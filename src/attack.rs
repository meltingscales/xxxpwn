use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use native_tls::TlsConnector;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use regex::Regex;

use crate::context::{AttackCtx, Config};

/// Encodes everything except unreserved URI characters; approximates urllib.quote_plus
const ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'\'');

pub fn encode_payload(payload: &str, config: &Config) -> String {
    let mut result = payload.to_string();
    if config.urlencode {
        result = utf8_percent_encode(&result, ENCODE_SET)
            .to_string()
            .replace("%20", "+");
    }
    if config.htmlencode {
        // Replicate Python's cgi.escape: &, <, >
        result = result
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
    }
    result
}

pub fn attack(inject: &str, ctx: &Arc<AttackCtx>) -> bool {
    let config = &ctx.config;
    let ci = if config.case_sensitive { "" } else { "(?i)" };

    // Replace $INJECT placeholder
    let inject_re = Regex::new(&format!(r"{}\$INJECT", ci)).unwrap();
    let mut request = inject_re
        .replacen(&config.inject_content, 1, inject)
        .to_string();

    // Update Host header
    let host_re = Regex::new(&format!(r"{}(Host:\s*\S*)", ci)).unwrap();
    if host_re.is_match(&request) {
        let replacement = format!("Host: {}", config.host);
        request = host_re.replacen(&request, 1, replacement.as_str()).to_string();
    }

    // Update Accept-Encoding to none
    let ae_re = Regex::new(&format!(r"{}(Accept-Encoding:\s*.*)", ci)).unwrap();
    if ae_re.is_match(&request) {
        request = ae_re
            .replacen(&request, 1, "Accept-Encoding: none")
            .to_string();
    }

    // Handle Connection header
    let conn_re = Regex::new(&format!(r"{}(Connection:\s*.*)", ci)).unwrap();
    if conn_re.is_match(&request) {
        request = conn_re
            .replacen(&request, 1, "Connection: close")
            .to_string();
    } else {
        // Insert Connection: close before the blank line separating headers from body
        if let Some(pos) = request.find("\r\n\r\n") {
            request.insert_str(pos, "\r\nConnection: close");
        } else if let Some(pos) = request.find("\n\n") {
            request.insert_str(pos, "\nConnection: close");
        }
    }

    // Update Content-Length if present
    let cl_re = Regex::new(&format!(r"{}Content-Length:", ci)).unwrap();
    if cl_re.is_match(&request) {
        let body_start = if let Some(p) = request.find("\r\n\r\n") {
            Some(p + 4)
        } else {
            request.find("\n\n").map(|p| p + 2)
        };
        if let Some(start) = body_start {
            let body_len = request.len() - start;
            let cl_re2 =
                Regex::new(&format!(r"{}(Content-Length:\s*[0-9]*)", ci)).unwrap();
            request = cl_re2
                .replacen(&request, 1, format!("Content-Length: {}", body_len).as_str())
                .to_string();
        }
    }

    const MAX_RETRIES: usize = 10;
    let mut retries = MAX_RETRIES;
    let response = loop {
        match make_request(&request, config) {
            Ok(resp) => break resp,
            Err(e) => {
                if retries == 0 {
                    eprintln!("### Max retries reached: {} ###", e);
                    return false;
                }
                eprintln!("### Connection Retry {} ###", retries);
                retries -= 1;
                thread::sleep(Duration::from_secs(1));
            }
        }
    };

    ctx.request_count.fetch_add(1, Ordering::Relaxed);

    let match_re = Regex::new(&format!("{}{}", ci, &config.match_pattern))
        .unwrap_or_else(|_| {
            Regex::new(&format!("{}{}", ci, regex::escape(&config.match_pattern))).unwrap()
        });
    let found = match_re.is_match(&response);

    if config.verbose_attack {
        println!(
            "### Request: ###\n{}\n### Reply: ###\n{}\n### Match: '{}' = {} ###\n",
            request, response, config.match_pattern, found
        );
    }

    found
}

fn make_request(
    request: &str,
    config: &Config,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", config.host, config.port);
    let stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let mut buf = Vec::new();

    if config.use_ssl {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let mut tls = connector.connect(&config.host, stream)?;
        tls.write_all(request.as_bytes())?;
        match tls.read_to_end(&mut buf) {
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock =>
            {}
            Err(_) if !buf.is_empty() => {}
            Err(e) => return Err(e.into()),
        }
    } else {
        let mut tcp = stream;
        tcp.write_all(request.as_bytes())?;
        match tcp.read_to_end(&mut buf) {
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock =>
            {}
            Err(_) if !buf.is_empty() => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(String::from_utf8_lossy(&buf).to_string())
}

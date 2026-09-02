use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

use serde_json::Value;

pub struct OracleArg {
    pub name: &'static str,
    pub value: Value,
}

/// Signal the start of a new test to the oracle server.
/// No-op when QUINT_ORACLE_URL is not set.
pub fn start_test(name: &str) {
    let Some(url) = env::var("QUINT_ORACLE_URL").ok() else {
        return;
    };
    let path = format!("/test/{}", percent_encode(name));
    http_send("POST", &url, &path, None);
}

/// Log a state-machine action to the oracle server.
/// No-op when QUINT_ORACLE_URL is not set.
pub fn log_action(action: &str, args: &[OracleArg]) {
    let Some(url) = env::var("QUINT_ORACLE_URL").ok() else {
        return;
    };
    let args_json: Vec<Value> = args
        .iter()
        .map(|a| serde_json::json!({"name": a.name, "value": a.value}))
        .collect();
    let body = serde_json::json!({"action": action, "arguments": args_json}).to_string();
    http_send("PUT", &url, "/log", Some(&body));
}

fn http_send(method: &str, base_url: &str, path: &str, body: Option<&str>) {
    let (host, port) = parse_host_port(base_url);
    let Ok(mut stream) = TcpStream::connect((&host[..], port)) else {
        return;
    };
    let body_bytes = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.0\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body_bytes}",
        body_bytes.len()
    );
    let _ = stream.write_all(req.as_bytes());
    // drain the response so the server considers the connection cleanly closed
    let mut buf = [0u8; 256];
    let _ = stream.read(&mut buf);
}

fn parse_host_port(url: &str) -> (String, u16) {
    let s = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("localhost:12345");
    match s.rsplit_once(':') {
        Some((host, port)) => (host.to_owned(), port.parse().unwrap_or(80)),
        None => (s.to_owned(), 80),
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

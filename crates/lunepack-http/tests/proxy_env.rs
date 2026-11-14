//! Proxy selection through the environment (M4-D14: an environment proxy wins everywhere).
//!
//! The environment of a running test process cannot be changed without `unsafe`, so each case
//! re-runs this binary as a child process whose environment is set on the `Command`; the parent's
//! environment is never touched. This test has its own `main` (see Cargo.toml).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::panic::catch_unwind;
use std::process::Command;
use std::thread;
use std::time::Duration;

use lunepack_core::{BlockingTransport, CancelToken, Request};
use lunepack_http::{UreqTransport, proxy_for_url};

const PROXY_VARS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--proxy-for") => {
            // The proxy a request to the URL would use, `none` for a direct connection.
            println!(
                "{}",
                proxy_for_url(&args[1]).unwrap_or_else(|| "none".to_owned())
            );
            return;
        }
        Some("--fetch") => {
            let request = Request {
                url: args[1].clone(),
                range: None,
                if_range: None,
            };
            match UreqTransport::new().get(&request, &CancelToken::new()) {
                Ok(mut response) => {
                    let mut body = String::new();
                    response.body.read_to_string(&mut body).expect("body");
                    println!("status={} body={body}", response.head.status);
                }
                Err(e) => println!("error={:?}", e.kind),
            }
            return;
        }
        _ => {}
    }

    let tests: &[(&str, fn())] = &[
        ("an_env_proxy_is_selected", env_proxy_is_selected),
        ("all_proxy_comes_before_https_proxy", all_proxy_first),
        ("no_proxy_bypasses_the_env_proxy", no_proxy_bypasses),
        (
            "a_request_goes_through_the_env_proxy",
            request_goes_through_proxy,
        ),
        ("without_env_there_is_no_proxy_on_linux", no_env_no_proxy),
    ];
    let mut failed = 0;
    for (name, test) in tests {
        match catch_unwind(*test) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed += 1;
            }
        }
    }
    println!(
        "\ntest result: {} passed; {failed} failed",
        tests.len() - failed
    );
    if failed > 0 {
        std::process::exit(1);
    }
}

/// A child of this binary with every proxy variable removed and `env` set.
fn child(env: &[(&str, &str)], args: &[&str]) -> String {
    let mut cmd = Command::new(std::env::current_exe().expect("current exe"));
    cmd.args(args);
    for var in PROXY_VARS {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("child");
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .trim()
        .to_owned()
}

const URL: &str = "https://updates.example.invalid/feed";

fn env_proxy_is_selected() {
    for var in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"] {
        let got = child(&[(var, "http://127.0.0.1:3128")], &["--proxy-for", URL]);
        assert_eq!(got, "127.0.0.1:3128", "{var}");
    }
}

fn all_proxy_first() {
    let got = child(
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:2222"),
            ("ALL_PROXY", "http://127.0.0.1:1111"),
        ],
        &["--proxy-for", URL],
    );
    assert_eq!(got, "127.0.0.1:1111");
}

fn no_proxy_bypasses() {
    let got = child(
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:3128"),
            ("NO_PROXY", "updates.example.invalid"),
        ],
        &["--proxy-for", URL],
    );
    assert_eq!(got, "none");
}

/// Reads up to the end of one request head; returns it.
fn read_head(stream: &mut std::net::TcpStream) -> String {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).expect("read");
        assert!(n > 0, "closed early");
        seen.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

/// A CONNECT proxy that records what it is asked for, tunnels nothing and answers the request
/// inside the tunnel itself with `200 ok`.
fn request_goes_through_proxy() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let connect = read_head(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .expect("write");
        let inner = read_head(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write");
        (
            connect.lines().next().unwrap_or_default().to_owned(),
            inner.lines().next().unwrap_or_default().to_owned(),
        )
    });
    let proxy = format!("http://127.0.0.1:{port}");
    // The host never resolves: only a proxy can answer.
    let got = child(
        &[("HTTP_PROXY", proxy.as_str())],
        &["--fetch", "http://updates.example.invalid/file.bin"],
    );
    assert_eq!(got, "status=200 body=ok");
    let (connect, inner) = server.join().expect("server");
    assert_eq!(
        connect, "CONNECT updates.example.invalid:80 HTTP/1.1",
        "the request must reach the proxy"
    );
    assert_eq!(inner, "GET /file.bin HTTP/1.1");
}

/// Linux has no system proxy source: without the environment there is none. (macOS and Windows
/// read the machine's own settings, which this test cannot know.)
fn no_env_no_proxy() {
    if cfg!(any(target_os = "macos", windows)) {
        return;
    }
    assert_eq!(child(&[], &["--proxy-for", URL]), "none");
}

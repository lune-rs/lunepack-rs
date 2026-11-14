//! Runner-side helper for the OS-trust and system-proxy CI job (M4 step 14): the P-N1 probe's
//! commands, with `fetch` going through the production `UreqTransport`. Output is `key=value`
//! lines; never request or file bodies. Not part of the library; it makes certificates and runs a
//! loopback TLS server and a CONNECT proxy for one job, then exits with the job.
//!
//! * `gen-certs <dir>`: a run-time root and leaf (rcgen). The root *certificate* goes to
//!   `<dir>/root.pem`; the root key is dropped in memory and never written anywhere.
//! * `serve-tls <dir> <port>`: a loopback TLS server presenting the leaf.
//! * `fetch <url>`: a GET through `UreqTransport` (platform verifier, system or environment
//!   proxy); prints `result=ok|error`, `status`, `body_len`, `kind`, `proxy_selected`.
//! * `proxy-serve <port> <logfile>`: a minimal logging CONNECT proxy on loopback.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lunepack_core::{BlockingTransport, CancelToken, Request};
use lunepack_http::{UreqTransport, proxy_for_url};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn short(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(160).collect()
}

fn cmd_gen_certs(dir: &str) -> Res<()> {
    fs::create_dir_all(dir)?;
    let now = OffsetDateTime::now_utc();
    let suffix = now.unix_timestamp();

    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("Lunepack Probe Root {suffix}"));
    root_params.distinguished_name = dn;
    root_params.not_before = now - TimeDuration::days(1);
    root_params.not_after = now + TimeDuration::days(30);
    let root_key = KeyPair::generate()?;
    let root_cert = root_params.self_signed(&root_key)?;
    fs::write(Path::new(dir).join("root.pem"), root_cert.pem())?;

    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    leaf_params.distinguished_name = dn;
    leaf_params.not_before = now - TimeDuration::days(1);
    leaf_params.not_after = now + TimeDuration::days(30);
    let leaf_key = KeyPair::generate()?;
    let issuer = Issuer::new(root_params, root_key); // the root key lives only in memory
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;
    fs::write(Path::new(dir).join("leaf.pem"), leaf_cert.pem())?;
    fs::write(Path::new(dir).join("leaf.key"), leaf_key.serialize_pem())?;
    println!("certs=written root_key_written=false");
    Ok(())
}

fn cmd_serve_tls(dir: &str, port: &str) -> Res<()> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(Path::new(dir).join("leaf.pem"))?
            .collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_file(Path::new(dir).join("leaf.key"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    );
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    println!("listening=127.0.0.1:{port}");
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        let Ok(tcp) = stream else { continue };
        let config = Arc::clone(&config);
        thread::spawn(move || {
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
            let Ok(conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 2048];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return, // handshake rejected or client gone
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let body = "lunepack-probe-ok";
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(reply.as_bytes());
            let _ = tls.flush();
        });
    }
    Ok(())
}

fn cmd_fetch(url: &str) -> Res<()> {
    println!(
        "proxy_selected={}",
        proxy_for_url(url).unwrap_or_else(|| "none".to_string())
    );
    let request = Request {
        url: url.to_string(),
        range: None,
        if_range: None,
    };
    match UreqTransport::new().get(&request, &CancelToken::new()) {
        Ok(response) => {
            let status = response.head.status;
            let mut body = Vec::new();
            match response.body.take(1 << 20).read_to_end(&mut body) {
                Ok(_) => {
                    println!("result=ok");
                    println!("status={status}");
                    println!("body_len={}", body.len());
                }
                Err(e) => {
                    println!("result=error");
                    println!("error={}", short(&e.to_string()));
                }
            }
        }
        Err(e) => {
            println!("result=error");
            println!("kind={:?}", e.kind);
            // The cause is the transport's own text; it names no URL (M4 step 1).
            let cause = std::error::Error::source(&e).map(ToString::to_string);
            println!("error={}", short(&cause.unwrap_or_else(|| e.to_string())));
        }
    }
    Ok(())
}

fn append_log(path: &str, line: &str) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 2048];
    let mut seen = Vec::new();
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
        if seen.len() > 16 * 1024 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&seen).into_owned())
}

fn tunnel(mut client: TcpStream, log: &str) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(15)));
    let Some(head) = read_head(&mut client) else {
        return;
    };
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method != "CONNECT" {
        append_log(log, "OTHER");
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    // Only loopback targets are ever tunnelled: this is a probe, not a proxy.
    let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
    if host != "127.0.0.1" && host != "localhost" {
        append_log(log, "REFUSED");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    append_log(log, &format!("CONNECT {target}"));
    let Ok(upstream) = TcpStream::connect(target) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let (Ok(mut c2), Ok(mut u2)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let (mut client, mut upstream) = (client, upstream);
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut u2);
        let _ = u2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

fn cmd_proxy_serve(port: &str, log: &str) -> Res<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    println!("listening=127.0.0.1:{port}");
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let log = log.to_string();
        thread::spawn(move || tunnel(stream, &log));
    }
    Ok(())
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["gen-certs", dir] => cmd_gen_certs(dir),
        ["serve-tls", dir, port] => cmd_serve_tls(dir, port),
        ["fetch", url] => cmd_fetch(url),
        ["proxy-serve", port, log] => cmd_proxy_serve(port, log),
        _ => {
            eprintln!("usage: os_trust gen-certs|serve-tls|fetch|proxy-serve ...");
            std::process::exit(2);
        }
    }
}

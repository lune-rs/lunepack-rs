//! The HTTP adapters against the core's transport contract (M4 step 8): `UreqTransport` over the
//! loopback server (the whole blocking suite), what it puts on the wire, its error mapping, the
//! TLS control (a certificate no store trusts must fail with `Tls`), and `DirSource` over a
//! temporary directory.
//!
//! `DirSource` runs the same blocking suite with the parts a directory has no meaning for switched
//! off (`TransportCaps`; each one is named where it is chosen), and keeps its own cases below.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lunepack_core::{
    BlockingTransport, ByteRange, CancelToken, Head, Request, TransportError, TransportErrorKind,
    Validator,
};
use lunepack_http::{DirSource, UreqOptions, UreqTransport};
use lunepack_testkit::{
    LoopbackServer, TransportCaps, TransportFixture, run_blocking_transport_suite,
    run_blocking_transport_suite_with,
};

fn get_all(
    transport: &dyn BlockingTransport,
    url: &str,
    range: Option<ByteRange>,
) -> Result<(Head, Vec<u8>), TransportError> {
    let request = Request {
        url: url.to_owned(),
        range,
        if_range: None,
    };
    let response = transport.get(&request, &CancelToken::new())?;
    let mut body = Vec::new();
    let mut reader = response.body;
    reader
        .read_to_end(&mut body)
        .map_err(|e| inner_transport_error(e, url))?;
    Ok((response.head, body))
}

/// The `TransportError` an adapter's body reader wrapped in its `io::Error`.
fn inner_transport_error(e: io::Error, url: &str) -> TransportError {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<TransportError>())
    {
        Some(inner) => TransportError::new(inner.kind, url, None),
        None => panic!("a body read failed with a plain I/O error: {e}"),
    }
}

// ---- UreqTransport ------------------------------------------------------------------------------

#[test]
fn ureq_transport_passes_the_blocking_suite_over_loopback() {
    let server = LoopbackServer::fixture().expect("loopback server");
    let transport = UreqTransport::new();
    run_blocking_transport_suite(&transport, &server.base_url(), &|| {
        server.origin().requests()
    });
}

/// A one-shot server that returns the raw request head it received.
fn capture_request_head() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let url = format!("http://{}/file.bin", listener.local_addr().expect("addr"));
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).expect("read");
            assert!(n > 0, "the client closed before the head ended");
            seen.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write");
        String::from_utf8(seen).expect("ascii head")
    });
    (url, handle)
}

fn header_names(head: &str) -> Vec<String> {
    let mut names: Vec<String> = head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    names.sort();
    names
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[test]
fn a_plain_request_sends_only_host_and_the_lunepack_user_agent() {
    let (url, handle) = capture_request_head();
    let (head, body) = get_all(&UreqTransport::new(), &url, None).expect("fetch");
    assert_eq!((head.status, body.as_slice()), (200, &b"ok"[..]));
    let sent = handle.join().expect("server");
    assert_eq!(header_names(&sent), ["host", "user-agent"], "{sent}");
    assert_eq!(header_value(&sent, "user-agent"), Some("lunepack"));
}

#[test]
fn a_range_request_adds_range_and_if_range_and_nothing_else() {
    let (url, handle) = capture_request_head();
    let request = Request {
        url,
        range: Some(ByteRange {
            first: 5,
            last: Some(9),
        }),
        if_range: Validator::from_etag(b"\"abc\""),
    };
    let response = UreqTransport::new()
        .get(&request, &CancelToken::new())
        .expect("fetch");
    assert_eq!(response.head.status, 200);
    let sent = handle.join().expect("server");
    assert_eq!(
        header_names(&sent),
        ["host", "if-range", "range", "user-agent"],
        "{sent}"
    );
    assert_eq!(header_value(&sent, "range"), Some("bytes=5-9"));
    assert_eq!(header_value(&sent, "if-range"), Some("\"abc\""));
}

#[test]
fn if_range_without_a_range_is_not_sent() {
    let (url, handle) = capture_request_head();
    let request = Request {
        url,
        range: None,
        if_range: Validator::from_etag(b"\"abc\""),
    };
    UreqTransport::new()
        .get(&request, &CancelToken::new())
        .expect("fetch");
    let sent = handle.join().expect("server");
    assert_eq!(header_names(&sent), ["host", "user-agent"], "{sent}");
}

#[test]
fn a_cancel_during_the_body_stops_the_next_read_with_cancelled() {
    let server = LoopbackServer::fixture().expect("loopback server");
    let cancel = CancelToken::new();
    let request = Request {
        url: server.url(TransportFixture::LARGE),
        range: None,
        if_range: None,
    };
    let mut response = UreqTransport::new().get(&request, &cancel).expect("get");
    let mut first = [0u8; 10];
    response.body.read_exact(&mut first).expect("first read");
    cancel.cancel();
    let error = response
        .body
        .read(&mut [0u8; 10])
        .expect_err("a read after cancel");
    let inner = error
        .get_ref()
        .and_then(|i| i.downcast_ref::<TransportError>())
        .expect("a wrapped TransportError");
    assert_eq!(inner.kind, TransportErrorKind::Cancelled);
    assert_ne!(
        error.kind(),
        io::ErrorKind::Interrupted,
        "read_to_end would retry Interrupted"
    );
}

#[test]
fn only_http_and_https_urls_are_supported() {
    for url in [
        "ftp://example.invalid/a",
        "file:///etc/hosts",
        "not a url",
        "",
    ] {
        let request = Request {
            url: url.to_owned(),
            range: None,
            if_range: None,
        };
        let error = UreqTransport::new()
            .get(&request, &CancelToken::new())
            .expect_err(url);
        assert_eq!(error.kind, TransportErrorKind::Unsupported, "{url}");
    }
}

#[test]
fn a_redirect_loop_fails_after_the_limit_with_protocol() {
    let server = LoopbackServer::fixture().expect("loopback server");
    server.origin().redirect("loop", "loop");
    let options = UreqOptions {
        max_redirects: 3,
        ..UreqOptions::default()
    };
    let error = get_all(
        &UreqTransport::with_options(&options),
        &server.url("loop"),
        None,
    )
    .expect_err("a loop");
    assert_eq!(error.kind, TransportErrorKind::Protocol);
    let hops = server
        .origin()
        .requests()
        .iter()
        .filter(|r| r.url.ends_with("/loop"))
        .count();
    assert_eq!(hops, 4, "the first request plus three redirects");
}

#[test]
fn a_refused_connection_is_connect_and_names_no_query_or_userinfo() {
    // Bind and drop to get a port nothing listens on.
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let url = format!("http://user:pw@127.0.0.1:{port}/a?token=s3cr3t");
    let error = get_all(&UreqTransport::new(), &url, None).expect_err("refused");
    assert_eq!(error.kind, TransportErrorKind::Connect, "{error}");
    let mut texts = vec![format!("{error}"), format!("{error:?}")];
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        texts.push(format!("{cause}"));
        texts.push(format!("{cause:?}"));
        source = cause.source();
    }
    for text in texts {
        assert!(
            !text.contains("s3cr3t") && !text.contains("user:pw") && !text.contains("pw@"),
            "a credential reached an error text: {text}"
        );
    }
}

#[test]
fn a_stalled_server_ends_at_the_read_timeout() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let url = format!("http://{}/a", listener.local_addr().expect("addr"));
    // Accept and say nothing; hold the socket until the client gives up.
    let holder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        thread::sleep(Duration::from_secs(3));
        drop(stream);
    });
    let options = UreqOptions {
        read_timeout: Duration::from_millis(300),
        ..UreqOptions::default()
    };
    let error = get_all(&UreqTransport::with_options(&options), &url, None).expect_err("stalled");
    assert_eq!(error.kind, TransportErrorKind::Timeout, "{error}");
    holder.join().expect("holder");
}

// ---- TLS control ------------------------------------------------------------------------------

/// A TLS server with a self-signed certificate that is in neither the OS store nor webpki-roots.
/// It handles connections until the listener is dropped with the thread.
fn untrusted_tls_server() -> (String, thread::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("self-signed certificate");
    let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
        .expect("private key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config"),
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let url = format!("https://{}/x", listener.local_addr().expect("addr"));
    let handle = thread::spawn(move || {
        // One connection is enough: the client must give up at the handshake. Serve a second in
        // case the client retries.
        for _ in 0..2 {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
            let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 1024];
            // A rejected handshake ends here with an error; a client that trusted the certificate
            // would send its request, which this server answers (and the test then fails).
            if let Ok(n) = tls.read(&mut buf)
                && n > 0
            {
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tls.flush();
            }
        }
    });
    (url, handle)
}

#[test]
fn a_certificate_no_store_trusts_fails_with_tls() {
    let (url, _handle) = untrusted_tls_server();
    let error = get_all(&UreqTransport::new(), &url, None).expect_err("an untrusted certificate");
    assert_eq!(
        error.kind,
        TransportErrorKind::Tls,
        "the control must fail as Tls: {error}; cause: {:?}",
        std::error::Error::source(&error).map(ToString::to_string)
    );
}

// ---- DirSource --------------------------------------------------------------------------------

fn dir_with_fixture() -> (tempfile::TempDir, DirSource, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    for name in [
        TransportFixture::EMPTY,
        TransportFixture::ONE_BYTE,
        TransportFixture::LARGE,
    ] {
        std::fs::write(
            dir.path().join(name),
            TransportFixture::bytes(name).expect("fixture"),
        )
        .expect("write");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        dir.path().join(TransportFixture::LARGE),
        dir.path().join(TransportFixture::ALIAS),
    )
    .expect("symlink");
    let source = DirSource::new(dir.path());
    let base = url::Url::from_directory_path(dir.path())
        .expect("directory url")
        .to_string();
    (dir, source, base)
}

#[test]
fn dir_source_passes_the_blocking_suite_with_the_http_only_parts_off() {
    let (_dir, source, base) = dir_with_fixture();
    run_blocking_transport_suite_with(
        &source,
        &base,
        &|| Vec::new(),
        TransportCaps {
            // A directory offers no ETag or Last-Modified, so there is nothing for If-Range to
            // compare (case 3).
            validators: false,
            // A file has one set of headers; a header twice needs a server (case 6).
            duplicate_headers: false,
            // The alias is a symlink to the large file, which DirSource follows (M4-D14); the
            // fixture creates it on Unix only (case 5).
            redirects: cfg!(unix),
            // There is no wire, so there is no request log (case 7).
            request_log: false,
        },
    );
}

fn range(first: u64, last: Option<u64>) -> Option<ByteRange> {
    Some(ByteRange { first, last })
}

fn header<'a>(head: &'a Head, name: &str) -> Option<&'a [u8]> {
    head.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}

#[test]
fn dir_source_serves_whole_files_with_their_exact_bytes() {
    let (_dir, source, base) = dir_with_fixture();
    for name in [
        TransportFixture::EMPTY,
        TransportFixture::ONE_BYTE,
        TransportFixture::LARGE,
    ] {
        let (head, body) = get_all(&source, &format!("{base}{name}"), None).expect(name);
        assert_eq!(head.status, 200, "{name}");
        assert_eq!(body, TransportFixture::bytes(name).unwrap(), "{name}");
        assert_eq!(
            header(&head, "content-length"),
            Some(body.len().to_string().as_bytes()),
            "{name}"
        );
        assert!(
            head.headers
                .iter()
                .all(|(n, _)| n != "etag" && n != "last-modified"),
            "a directory offers no validator: {head:?}"
        );
    }
}

#[test]
fn dir_source_answers_ranges_with_a_correct_content_range() {
    let (_dir, source, base) = dir_with_fixture();
    let large = TransportFixture::bytes(TransportFixture::LARGE).unwrap();
    let len = large.len() as u64;
    let url = format!("{base}{}", TransportFixture::LARGE);

    let (head, body) = get_all(&source, &url, range(0, Some(99))).expect("0-99");
    assert_eq!(head.status, 206);
    assert_eq!(body, &large[..100]);
    assert_eq!(
        header(&head, "content-range"),
        Some(format!("bytes 0-99/{len}").as_bytes())
    );

    let from = len - 1000;
    let (head, body) = get_all(&source, &url, range(from, None)).expect("open");
    assert_eq!(head.status, 206);
    assert_eq!(body, &large[from as usize..]);
    assert_eq!(
        header(&head, "content-range"),
        Some(format!("bytes {from}-{}/{len}", len - 1).as_bytes())
    );

    // A last byte past the end is clamped, as HTTP says.
    let (head, body) = get_all(&source, &url, range(len - 10, Some(len + 500))).expect("clamp");
    assert_eq!(head.status, 206);
    assert_eq!(body, &large[(len - 10) as usize..]);

    // Inner range.
    let (_, body) = get_all(&source, &url, range(1234, Some(1239))).expect("inner");
    assert_eq!(body, &large[1234..1240]);
}

#[test]
fn dir_source_range_passes_the_core_response_rules() {
    use lunepack_core::fetch::classify;
    use lunepack_core::{Outcome, ResponseInfo};
    let (_dir, source, base) = dir_with_fixture();
    let len = TransportFixture::LARGE_LEN as u64;
    let url = format!("{base}{}", TransportFixture::LARGE);
    let asked = range(10, Some(109));
    let (head, _) = get_all(&source, &url, asked).expect("range");
    let info = ResponseInfo::from_head(&head).expect("rules");
    assert_eq!(
        classify(asked, &info, len, 100),
        Ok(Outcome::Partial {
            first: 10,
            last: 109
        })
    );
}

#[test]
fn dir_source_unsatisfiable_ranges_are_416() {
    let (_dir, source, base) = dir_with_fixture();
    let len = TransportFixture::LARGE_LEN as u64;
    let url = format!("{base}{}", TransportFixture::LARGE);
    for asked in [range(len, None), range(len + 5, Some(len + 9))] {
        let (head, body) = get_all(&source, &url, asked).expect("416 is a head");
        assert_eq!(head.status, 416, "{asked:?}");
        assert!(body.is_empty());
        assert_eq!(
            header(&head, "content-range"),
            Some(format!("bytes */{len}").as_bytes())
        );
    }
    // Any range of an empty file is unsatisfiable.
    let empty = format!("{base}{}", TransportFixture::EMPTY);
    let (head, _) = get_all(&source, &empty, range(0, None)).expect("empty");
    assert_eq!(head.status, 416);
    // last < first is refused too.
    let (head, _) = get_all(&source, &url, range(50, Some(10))).expect("backwards");
    assert_eq!(head.status, 416);
}

#[test]
fn dir_source_missing_files_and_directories_are_404_heads() {
    let (dir, source, base) = dir_with_fixture();
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
    for name in [TransportFixture::MISSING, "sub", "sub/nothing.bin"] {
        let (head, body) = get_all(&source, &format!("{base}{name}"), None).expect(name);
        assert_eq!(head.status, 404, "{name}");
        assert!(body.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn dir_source_follows_a_symlink_inside_the_root() {
    let (_dir, source, base) = dir_with_fixture();
    let (head, body) =
        get_all(&source, &format!("{base}{}", TransportFixture::ALIAS), None).expect("alias");
    assert_eq!(head.status, 200);
    assert_eq!(
        body,
        TransportFixture::bytes(TransportFixture::LARGE).unwrap()
    );
}

#[test]
fn dir_source_refuses_paths_outside_its_root_and_other_schemes() {
    let (dir, source, base) = dir_with_fixture();
    let outside = tempfile::tempdir().expect("outside dir");
    std::fs::write(outside.path().join("secret.bin"), b"outside").expect("write");
    let outside_url = url::Url::from_file_path(outside.path().join("secret.bin"))
        .expect("url")
        .to_string();
    // A sibling directory whose name starts with the root's name is not under it.
    let sibling = format!("{}-sibling", dir.path().display());
    std::fs::create_dir_all(&sibling).expect("sibling");
    std::fs::write(format!("{sibling}/f.bin"), b"x").expect("write");
    let sibling_url = url::Url::from_file_path(format!("{sibling}/f.bin"))
        .expect("url")
        .to_string();

    let refused = [
        outside_url,
        sibling_url,
        // Dot segments (the URL parser removes plain ones; encoded ones decode to dots).
        format!("{base}../x.bin"),
        format!("{base}%2e%2e/x.bin"),
        format!("{base}sub/%2E%2E/%2e%2e/x.bin"),
        "http://127.0.0.1/a".to_owned(),
        "file://example.invalid/etc/hosts".to_owned(),
        "not a url".to_owned(),
    ];
    for url in &refused {
        let request = Request {
            url: url.clone(),
            range: None,
            if_range: None,
        };
        match source.get(&request, &CancelToken::new()) {
            Err(e) => assert_eq!(e.kind, TransportErrorKind::Unsupported, "{url}"),
            Ok(r) => panic!("{url}: served with status {}", r.head.status),
        }
    }
    std::fs::remove_dir_all(&sibling).expect("cleanup sibling");
}

#[test]
fn dir_source_cancel_before_get_and_during_the_body() {
    let (_dir, source, base) = dir_with_fixture();
    let url = format!("{base}{}", TransportFixture::LARGE);
    let request = Request {
        url,
        range: None,
        if_range: None,
    };
    let cancelled = CancelToken::new();
    cancelled.cancel();
    let error = source.get(&request, &cancelled).expect_err("cancelled");
    assert_eq!(error.kind, TransportErrorKind::Cancelled);

    let cancel = CancelToken::new();
    let mut response = source.get(&request, &cancel).expect("get");
    response
        .body
        .read_exact(&mut [0u8; 10])
        .expect("first read");
    cancel.cancel();
    let error = response
        .body
        .read(&mut [0u8; 10])
        .expect_err("after cancel");
    let inner = error
        .get_ref()
        .and_then(|i| i.downcast_ref::<TransportError>())
        .expect("a wrapped TransportError");
    assert_eq!(inner.kind, TransportErrorKind::Cancelled);
}

#[test]
fn dir_source_header_names_are_lowercase() {
    let (_dir, source, base) = dir_with_fixture();
    let (head, _) = get_all(
        &source,
        &format!("{base}{}", TransportFixture::LARGE),
        range(0, Some(9)),
    )
    .expect("range");
    assert!(
        head.headers
            .iter()
            .all(|(n, _)| *n == n.to_ascii_lowercase())
    );
}

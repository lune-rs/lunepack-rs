//! A loopback HTTP/1.1 server over a [`FakeOrigin`] (M4 step 2): the real-socket counterpart of
//! the in-memory fakes, for the adapters' contract tests and the facade's end-to-end tests.
//!
//! It binds only to `127.0.0.1`, answers `GET` with one response per connection (`Connection:
//! close`), serves what the origin holds (`Range`, `If-Range`, `ETag`, redirects, a `404` for
//! unknown paths) and injects the origin's [`crate::TransportFault`]s on the wire: a body whose
//! length differs from the file's has no `content-length` and ends when the connection closes, a
//! truncated or failing body closes the connection early, `SlowChunks` writes one byte per
//! segment. Dropping the server stops every thread (within 1 s, even with a stalled or endless
//! connection open).

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::transport::{FakeOrigin, Reply};

/// How long a blocked socket call waits before the thread looks at the stop flag again.
const TICK: Duration = Duration::from_millis(50);
/// A connection that sends no complete request head within this long is dropped.
const HEAD_DEADLINE: Duration = Duration::from_secs(10);
/// Longest request head accepted.
const MAX_HEAD: usize = 16 * 1024;

/// The server; stops on drop.
pub struct LoopbackServer {
    origin: FakeOrigin,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl LoopbackServer {
    /// Starts serving `origin` on `127.0.0.1:0`.
    pub fn start(origin: FakeOrigin) -> io::Result<LoopbackServer> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let accept = {
            let (origin, stop, connections) = (origin.clone(), stop.clone(), connections.clone());
            thread::Builder::new()
                .name("lunepack-loopback-accept".to_owned())
                .spawn(move || accept_loop(&listener, &origin, &stop, &connections))?
        };
        Ok(LoopbackServer {
            origin,
            addr,
            stop,
            accept: Some(accept),
            connections,
        })
    }

    /// Starts serving a fresh [`FakeOrigin::fixture`] origin.
    pub fn fixture() -> io::Result<LoopbackServer> {
        LoopbackServer::start(FakeOrigin::fixture())
    }

    /// The socket address (always `127.0.0.1`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`, no trailing slash.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The URL of `path`.
    pub fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url(), path.trim_start_matches('/'))
    }

    /// The origin being served (files, faults, the request log).
    pub fn origin(&self) -> &FakeOrigin {
        &self.origin
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking `accept`.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let handles = std::mem::take(
            &mut *self
                .connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for handle in handles {
            let _ = handle.join();
        }
    }
}

fn accept_loop(
    listener: &TcpListener,
    origin: &FakeOrigin,
    stop: &Arc<AtomicBool>,
    connections: &Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    for incoming in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = incoming else { continue };
        let (origin, stop) = (origin.clone(), stop.clone());
        let Ok(handle) = thread::Builder::new()
            .name("lunepack-loopback-conn".to_owned())
            .spawn(move || handle_connection(stream, &origin, &stop))
        else {
            continue;
        };
        let mut held = connections.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|h| !h.is_finished());
        held.push(handle);
    }
}

fn is_retry(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// The request head, or `None` when the client went away, sent too much, took too long or the
/// server is stopping.
fn read_head(stream: &mut TcpStream, stop: &AtomicBool) -> Option<Vec<u8>> {
    let deadline = Instant::now() + HEAD_DEADLINE;
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
            return None;
        }
        match stream.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => {
                head.extend_from_slice(&tmp[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Some(head);
                }
                if head.len() > MAX_HEAD {
                    return None;
                }
            }
            Err(e) if is_retry(e.kind()) => {}
            Err(_) => return None,
        }
    }
}

/// Writes all of `buf`; `false` when the peer is gone or the server is stopping.
fn write_all(stream: &mut TcpStream, mut buf: &[u8], stop: &AtomicBool) -> bool {
    while !buf.is_empty() {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        match stream.write(buf) {
            Ok(0) => return false,
            Ok(n) => buf = &buf[n..],
            Err(e) if is_retry(e.kind()) => {}
            Err(_) => return false,
        }
    }
    true
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        302 => "Found",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn header_of(lines: &[&str], name: &str) -> Option<String> {
    lines.iter().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_owned())
    })
}

fn handle_connection(mut stream: TcpStream, origin: &FakeOrigin, stop: &AtomicBool) {
    if stream.set_read_timeout(Some(TICK)).is_err()
        || stream.set_write_timeout(Some(TICK)).is_err()
        || stream.set_nodelay(true).is_err()
    {
        return;
    }
    let Some(raw) = read_head(&mut stream, stop) else {
        return;
    };
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let headers: Vec<&str> = lines.take_while(|l| !l.is_empty()).collect();
    let mut parts = request_line.split(' ');
    let (method, target) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or("/"),
    );

    let reply = if method == "GET" {
        origin.serve(
            target,
            header_of(&headers, "range").as_deref(),
            header_of(&headers, "if-range").as_deref(),
            header_of(&headers, "accept-encoding").as_deref(),
        )
    } else {
        Reply {
            status: 405,
            headers: vec![("Content-Length".to_owned(), b"0".to_vec())],
            body: Vec::new(),
            endless: false,
            error_after: None,
            chunk: 8192,
            pending_forever: false,
        }
    };

    let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).into_bytes();
    for (name, value) in &reply.headers {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    if !write_all(&mut stream, &head, stop) {
        return;
    }
    let mut body = reply.body_state(target);
    while let Ok(Some(chunk)) = body.next() {
        if !write_all(&mut stream, &chunk, stop) {
            return;
        }
    }
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

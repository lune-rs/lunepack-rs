//! In-memory transports with fault knobs (M4 step 2). One [`FakeOrigin`] plays the server: it holds
//! a file map, answers `Range` and `If-Range` the way an HTTP server does, logs every request and
//! injects the [`TransportFault`]s a test asks for. [`FakeTransport`] (async) and
//! [`FakeBlockingTransport`] (sync) serve it in memory, and [`crate::LoopbackServer`] serves the
//! same origin over a real socket, so one set of tests covers all three.
//!
//! The fakes follow the transport contract of `lunepack_core::transport`: they follow redirects,
//! lowercase header names, keep duplicate headers, never send `Accept-Encoding`, and report a
//! missing file as a `404` head.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Read};
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use lunepack_core::{
    BlockingResponse, BlockingTransport, Body, BoxFuture, ByteRange, CancelToken, Head, Request,
    Response, Transport, TransportError, TransportErrorKind,
};

/// Most redirect hops a fake follows.
const MAX_REDIRECTS: usize = 5;
/// The default body chunk size.
const CHUNK: usize = 8192;
/// The filler byte of [`TransportFault::ExtraBytes`] and [`TransportFault::Endless`].
const FILLER: u8 = 0xEE;
/// The `Last-Modified` value of every file.
const LAST_MODIFIED: &str = "Thu, 01 Jan 2026 00:00:00 GMT";

/// The base URL [`FakeTransport::fixture`] and [`FakeBlockingTransport::fixture`] serve.
pub const FAKE_BASE_URL: &str = "http://fake.invalid";

/// A fault the origin injects into the answers for files. One enum for the async fake, the sync
/// fake and the loopback server, so a test states a failure once. Faults apply to answers for
/// files (not to `404`s and not to redirect hops), and several can be active together.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportFault {
    /// Ignore `Range` and answer `200` with the full body.
    IgnoreRange,
    /// Answer a range with a `content-range` that names another total than the file's.
    WrongContentRange,
    /// Answer a range with `206` and no `content-range`.
    NoContentRange,
    /// The body ends after this many bytes; `content-length` still names the full length.
    TruncateAfter(u64),
    /// The body never ends (filler after the file), and `content-length` is dropped.
    Endless,
    /// The body has this many filler bytes more than the file, and `content-length` is dropped.
    ExtraBytes(u64),
    /// From the request with this zero-based number on, the file's `etag` is another one, so an
    /// `If-Range` that carries the old tag no longer matches.
    ChangeETagAfter(u64),
    /// Answer every file with this status and an empty body.
    Status(u16),
    /// Add `content-encoding: gzip` (the body stays as it is).
    GzipEncoded,
    /// Send the named header twice (with the value `1` when the answer has none).
    DuplicateHeader(&'static str),
    /// Deliver the body one byte per chunk.
    SlowChunks,
    /// The async fake's `next_chunk` never resolves. The sync fake and the loopback server ignore
    /// it.
    PendingForever,
    /// The body fails after this many bytes: an I/O error in the fakes, a closed connection over
    /// the loopback server.
    ErrorAfter(u64),
}

/// One request the origin saw (one per hop: a followed redirect logs two).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    /// The request target: path and query, as an HTTP request line carries it.
    pub url: String,
    /// The parsed `Range`, when it was `bytes=<first>-` or `bytes=<first>-<last>`.
    pub range: Option<ByteRange>,
    /// The `Range` header exactly as received.
    pub range_header: Option<String>,
    /// The `If-Range` header as received.
    pub if_range: Option<String>,
    /// The `Accept-Encoding` header as received; a conforming transport never sends one.
    pub accept_encoding: Option<String>,
}

#[derive(Clone)]
enum Entry {
    File {
        body: Vec<u8>,
        extra_headers: Vec<(String, Vec<u8>)>,
    },
    Redirect(String),
}

#[derive(Default)]
struct OriginState {
    entries: BTreeMap<String, Entry>,
    faults: Vec<TransportFault>,
    seen: Vec<SeenRequest>,
}

/// The server side of the fakes: files, answers, a request log and the active faults. Clones share
/// state.
#[derive(Clone, Default)]
pub struct FakeOrigin {
    inner: Arc<Mutex<OriginState>>,
}

/// What the origin answers: the status, the headers as a server writes them (names in their
/// written case), and how the body is delivered.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    pub(crate) body: Vec<u8>,
    pub(crate) endless: bool,
    pub(crate) error_after: Option<u64>,
    pub(crate) chunk: usize,
    pub(crate) pending_forever: bool,
}

impl Reply {
    fn plain(status: u16, headers: Vec<(String, Vec<u8>)>, body: Vec<u8>) -> Reply {
        Reply {
            status,
            headers,
            body,
            endless: false,
            error_after: None,
            chunk: CHUNK,
            pending_forever: false,
        }
    }

    pub(crate) fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// The head a transport reports: names lowercased, values and duplicates kept.
    fn head(&self) -> Head {
        Head {
            status: self.status,
            headers: self
                .headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
                .collect(),
        }
    }

    pub(crate) fn body_state(&self, url: &str) -> BodyState {
        BodyState {
            url: url.to_owned(),
            data: self.body.clone(),
            pos: 0,
            endless: self.endless,
            chunk: self.chunk.max(1),
            error_after: self.error_after,
            delivered: 0,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn key_of(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

/// The request target (path and query) of an absolute URL; `None` when it has no `scheme://`.
fn target_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let rest = rest.split('#').next().unwrap_or_default();
    Some(match rest.find('/') {
        Some(at) => rest[at..].to_owned(),
        None => "/".to_owned(),
    })
}

fn parse_range(text: &str) -> Option<ByteRange> {
    let spec = text.strip_prefix("bytes=")?;
    let (first, last) = spec.split_once('-')?;
    let first = first.parse().ok()?;
    let last = if last.is_empty() {
        None
    } else {
        Some(last.parse().ok()?)
    };
    Some(ByteRange { first, last })
}

fn etag_of(path: &str, changed: bool) -> String {
    let hash = path.bytes().fold(0x811c_9dc5u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    });
    format!("\"fx-{hash:08x}{}\"", if changed { "-changed" } else { "" })
}

impl FakeOrigin {
    /// An origin with no files.
    pub fn new() -> Self {
        FakeOrigin::default()
    }

    /// An origin serving [`TransportFixture`].
    pub fn fixture() -> Self {
        let origin = FakeOrigin::new();
        for name in [
            TransportFixture::EMPTY,
            TransportFixture::ONE_BYTE,
            TransportFixture::LARGE,
            TransportFixture::DUPLICATE,
        ] {
            origin.put(name, TransportFixture::bytes(name).unwrap_or_default());
        }
        origin.redirect(TransportFixture::ALIAS, TransportFixture::LARGE);
        origin.header(TransportFixture::DUPLICATE, "X-Dup", b"one");
        origin.header(TransportFixture::DUPLICATE, "X-Dup", b"two");
        origin.header(TransportFixture::DUPLICATE, "X-Mixed-Case", b"v");
        origin
    }

    /// Serves `body` at `path` (a leading `/` is optional).
    pub fn put(&self, path: &str, body: impl Into<Vec<u8>>) {
        lock(&self.inner).entries.insert(
            key_of(path),
            Entry::File {
                body: body.into(),
                extra_headers: Vec::new(),
            },
        );
    }

    /// Answers `path` with a `302` to `to` (a path on the same origin).
    pub fn redirect(&self, path: &str, to: &str) {
        lock(&self.inner)
            .entries
            .insert(key_of(path), Entry::Redirect(key_of(to)));
    }

    /// Adds a response header (name as written; duplicates allowed) to the file at `path`.
    ///
    /// # Panics
    ///
    /// Panics when `path` is not a file of this origin.
    pub fn header(&self, path: &str, name: &str, value: &[u8]) {
        match lock(&self.inner).entries.get_mut(&key_of(path)) {
            Some(Entry::File { extra_headers, .. }) => {
                extra_headers.push((name.to_owned(), value.to_vec()));
            }
            _ => panic!("{path} is not a file of this origin"),
        }
    }

    /// Replaces the active faults.
    pub fn set_faults(&self, faults: Vec<TransportFault>) {
        lock(&self.inner).faults = faults;
    }

    /// Adds an active fault.
    pub fn add_fault(&self, fault: TransportFault) {
        lock(&self.inner).faults.push(fault);
    }

    /// Every request seen so far, in order.
    pub fn requests(&self) -> Vec<SeenRequest> {
        lock(&self.inner).seen.clone()
    }

    /// Forgets the logged requests (the count behind [`TransportFault::ChangeETagAfter`] restarts).
    pub fn clear_requests(&self) {
        lock(&self.inner).seen.clear();
    }

    /// Answers one request (one hop). Logs it first.
    pub(crate) fn serve(
        &self,
        target: &str,
        range_header: Option<&str>,
        if_range: Option<&str>,
        accept_encoding: Option<&str>,
    ) -> Reply {
        let mut state = lock(&self.inner);
        let number = state.seen.len() as u64;
        state.seen.push(SeenRequest {
            url: target.to_owned(),
            range: range_header.and_then(parse_range),
            range_header: range_header.map(str::to_owned),
            if_range: if_range.map(str::to_owned),
            accept_encoding: accept_encoding.map(str::to_owned),
        });
        let path = target.split(['?', '#']).next().unwrap_or("/");
        let faults = state.faults.clone();
        match state.entries.get(path) {
            None => Reply::plain(
                404,
                vec![
                    ("Content-Type".to_owned(), b"text/plain".to_vec()),
                    ("Content-Length".to_owned(), b"9".to_vec()),
                ],
                b"not found".to_vec(),
            ),
            Some(Entry::Redirect(to)) => Reply::plain(
                302,
                vec![
                    ("Location".to_owned(), to.as_bytes().to_vec()),
                    ("Content-Length".to_owned(), b"0".to_vec()),
                ],
                Vec::new(),
            ),
            Some(Entry::File {
                body,
                extra_headers,
            }) => file_reply(
                path,
                body,
                extra_headers,
                range_header,
                if_range,
                number,
                &faults,
            ),
        }
    }

    /// Answers `request` the way a transport must: follows redirects, up to [`MAX_REDIRECTS`].
    pub(crate) fn get(&self, request: &Request) -> Result<Reply, TransportError> {
        let range = request.range.map(|r| r.header_value());
        let if_range = request
            .if_range
            .as_ref()
            .map(|v| v.header_value().to_owned());
        let Some(mut target) = target_of(&request.url) else {
            return Err(TransportError::new(
                TransportErrorKind::Unsupported,
                &request.url,
                Some("a fake serves only scheme://host/path URLs".into()),
            ));
        };
        for _ in 0..=MAX_REDIRECTS {
            let reply = self.serve(&target, range.as_deref(), if_range.as_deref(), None);
            if !matches!(reply.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(reply);
            }
            let location = reply
                .header("location")
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
            target = if location.contains("://") {
                target_of(&location).unwrap_or_default()
            } else {
                location
            };
        }
        Err(TransportError::new(
            TransportErrorKind::Unsupported,
            &request.url,
            Some("too many redirects".into()),
        ))
    }
}

fn file_reply(
    path: &str,
    full: &[u8],
    extra_headers: &[(String, Vec<u8>)],
    range_header: Option<&str>,
    if_range: Option<&str>,
    number: u64,
    faults: &[TransportFault],
) -> Reply {
    let has = |f: &TransportFault| faults.contains(f);
    let changed = faults
        .iter()
        .any(|f| matches!(f, TransportFault::ChangeETagAfter(n) if number >= *n));
    let etag = etag_of(path, changed);
    let total = full.len() as u64;

    if let Some(status) = faults.iter().find_map(|f| match f {
        TransportFault::Status(s) => Some(*s),
        _ => None,
    }) {
        return Reply::plain(
            status,
            vec![("Content-Length".to_owned(), b"0".to_vec())],
            Vec::new(),
        );
    }

    let mut headers: Vec<(String, Vec<u8>)> = vec![
        (
            "Content-Type".to_owned(),
            b"application/octet-stream".to_vec(),
        ),
        ("Accept-Ranges".to_owned(), b"bytes".to_vec()),
        ("ETag".to_owned(), etag.as_bytes().to_vec()),
        (
            "Last-Modified".to_owned(),
            LAST_MODIFIED.as_bytes().to_vec(),
        ),
    ];
    headers.extend(extra_headers.iter().cloned());

    // Does the range apply? Not when ignored, unparsable, or when `If-Range` names another version.
    let validator_ok = if_range.is_none_or(|v| v == etag || v == LAST_MODIFIED);
    let range = if has(&TransportFault::IgnoreRange) || !validator_ok {
        None
    } else {
        range_header.and_then(parse_range)
    };

    let (status, mut body) = match range {
        Some(r) if r.first >= total => {
            headers.push((
                "Content-Range".to_owned(),
                format!("bytes */{total}").into_bytes(),
            ));
            headers.push(("Content-Length".to_owned(), b"0".to_vec()));
            return Reply::plain(416, headers, Vec::new());
        }
        Some(r) => {
            let last = r.last.map_or(total - 1, |l| l.min(total - 1));
            if last < r.first {
                headers.push((
                    "Content-Range".to_owned(),
                    format!("bytes */{total}").into_bytes(),
                ));
                headers.push(("Content-Length".to_owned(), b"0".to_vec()));
                return Reply::plain(416, headers, Vec::new());
            }
            let shown_total = if has(&TransportFault::WrongContentRange) {
                total + 1
            } else {
                total
            };
            if !has(&TransportFault::NoContentRange) {
                headers.push((
                    "Content-Range".to_owned(),
                    format!("bytes {}-{last}/{shown_total}", r.first).into_bytes(),
                ));
            }
            let slice = full[r.first as usize..=last as usize].to_vec();
            (206, slice)
        }
        None => (200, full.to_vec()),
    };
    headers.push((
        "Content-Length".to_owned(),
        body.len().to_string().into_bytes(),
    ));

    let mut reply_flags = (false, None, CHUNK, false);
    for fault in faults {
        match fault {
            TransportFault::GzipEncoded => {
                headers.push(("Content-Encoding".to_owned(), b"gzip".to_vec()));
            }
            TransportFault::TruncateAfter(n) => {
                body.truncate(usize::try_from(*n).unwrap_or(usize::MAX));
            }
            TransportFault::ExtraBytes(n) => {
                headers.retain(|(h, _)| !h.eq_ignore_ascii_case("content-length"));
                let extra = usize::try_from(*n).unwrap_or(0);
                body.resize(body.len() + extra, FILLER);
            }
            TransportFault::Endless => {
                headers.retain(|(h, _)| !h.eq_ignore_ascii_case("content-length"));
                reply_flags.0 = true;
            }
            TransportFault::ErrorAfter(n) => reply_flags.1 = Some(*n),
            TransportFault::SlowChunks => reply_flags.2 = 1,
            TransportFault::PendingForever => reply_flags.3 = true,
            _ => {}
        }
    }
    for fault in faults {
        if let TransportFault::DuplicateHeader(name) = fault {
            match headers
                .iter()
                .position(|(h, _)| h.eq_ignore_ascii_case(name))
            {
                Some(at) => {
                    let copy = headers[at].clone();
                    headers.insert(at + 1, copy);
                }
                None => {
                    headers.push(((*name).to_owned(), b"1".to_vec()));
                    headers.push(((*name).to_owned(), b"1".to_vec()));
                }
            }
        }
    }
    Reply {
        status,
        headers,
        body,
        endless: reply_flags.0,
        error_after: reply_flags.1,
        chunk: reply_flags.2,
        pending_forever: reply_flags.3,
    }
}

/// The fixed file set the transport suites expect an origin to serve.
#[derive(Debug, Clone, Copy)]
pub struct TransportFixture;

impl TransportFixture {
    /// A 0-byte file.
    pub const EMPTY: &'static str = "empty.bin";
    /// A 1-byte file.
    pub const ONE_BYTE: &'static str = "one.bin";
    /// A 100 KiB file of deterministic bytes.
    pub const LARGE: &'static str = "large.bin";
    /// A `302` to [`TransportFixture::LARGE`].
    pub const ALIAS: &'static str = "alias.bin";
    /// A name that is not served (`404`).
    pub const MISSING: &'static str = "missing.bin";
    /// A small file whose answer carries `X-Dup: one`, `X-Dup: two` and `X-Mixed-Case: v`.
    pub const DUPLICATE: &'static str = "dup.bin";
    /// Size of [`TransportFixture::LARGE`].
    pub const LARGE_LEN: usize = 100 * 1024;

    /// The bytes of a fixture file (the alias has the large file's); `None` for other names.
    pub fn bytes(name: &str) -> Option<Vec<u8>> {
        match name {
            Self::EMPTY => Some(Vec::new()),
            Self::ONE_BYTE => Some(vec![0x41]),
            Self::LARGE | Self::ALIAS => Some(
                (0..Self::LARGE_LEN)
                    .map(|i| (i.wrapping_mul(131).wrapping_add(17) % 251) as u8)
                    .collect(),
            ),
            Self::DUPLICATE => Some(b"duplicate headers".to_vec()),
            _ => None,
        }
    }
}

// ---- body delivery ---------------------------------------------------------------------------------

/// The chunking, endless, early-error behaviour shared by the async and sync bodies.
pub(crate) struct BodyState {
    url: String,
    data: Vec<u8>,
    pos: usize,
    endless: bool,
    chunk: usize,
    error_after: Option<u64>,
    delivered: u64,
}

impl BodyState {
    /// The next non-empty chunk, `Ok(None)` at the end.
    pub(crate) fn next(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut want = self.chunk;
        if let Some(limit) = self.error_after {
            if self.delivered >= limit {
                return Err(TransportError::new(
                    TransportErrorKind::Io,
                    &self.url,
                    Some("fake: connection reset".into()),
                ));
            }
            want = want.min(usize::try_from(limit - self.delivered).unwrap_or(usize::MAX));
        }
        let out = if self.pos < self.data.len() {
            let end = (self.pos + want).min(self.data.len());
            let chunk = self.data[self.pos..end].to_vec();
            self.pos = end;
            chunk
        } else if self.endless {
            vec![FILLER; want.min(CHUNK)]
        } else {
            return Ok(None);
        };
        self.delivered += out.len() as u64;
        Ok(Some(out))
    }
}

struct FakeBody {
    state: BodyState,
    pending_forever: bool,
}

impl Body for FakeBody {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            if self.pending_forever {
                std::future::pending::<()>().await;
            }
            self.state.next()
        })
    }
}

/// The async fake. The future it returns resolves at once, except for
/// [`TransportFault::PendingForever`], which keeps `next_chunk` pending.
#[derive(Clone)]
pub struct FakeTransport {
    origin: FakeOrigin,
}

impl FakeTransport {
    /// A transport that talks to `origin`.
    pub fn new(origin: FakeOrigin) -> Self {
        FakeTransport { origin }
    }

    /// A transport over a fresh [`TransportFixture`] origin; its base URL is [`FAKE_BASE_URL`].
    pub fn fixture() -> Self {
        FakeTransport::new(FakeOrigin::fixture())
    }

    /// Adds an active fault.
    pub fn with_fault(self, fault: TransportFault) -> Self {
        self.origin.add_fault(fault);
        self
    }

    /// The origin it talks to (to change files and faults, or read the request log).
    pub fn origin(&self) -> &FakeOrigin {
        &self.origin
    }

    /// The requests the origin has seen.
    pub fn requests(&self) -> Vec<SeenRequest> {
        self.origin.requests()
    }
}

impl Transport for FakeTransport {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let origin = self.origin.clone();
        Box::pin(async move {
            let reply = origin.get(&request)?;
            Ok(Response {
                head: reply.head(),
                body: Box::new(FakeBody {
                    state: reply.body_state(&request.url),
                    pending_forever: reply.pending_forever,
                }),
            })
        })
    }
}

struct FakeBlockingBody {
    state: BodyState,
    cancel: CancelToken,
    url: String,
    current: Vec<u8>,
    offset: usize,
}

impl Read for FakeBlockingBody {
    /// Checks the cancel token before every read; a cancel is an `io::Error` whose source is a
    /// `TransportError` of kind `Cancelled`, and so is a [`TransportFault::ErrorAfter`] (kind `Io`).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.cancel.is_cancelled() {
            return Err(io::Error::other(TransportError::new(
                TransportErrorKind::Cancelled,
                &self.url,
                None,
            )));
        }
        if self.offset >= self.current.len() {
            match self.state.next().map_err(io::Error::other)? {
                Some(chunk) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.current.len() - self.offset);
        buf[..n].copy_from_slice(&self.current[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

/// The sync fake, with the same faults ([`TransportFault::PendingForever`] excepted).
#[derive(Clone)]
pub struct FakeBlockingTransport {
    origin: FakeOrigin,
}

impl FakeBlockingTransport {
    /// A transport that talks to `origin`.
    pub fn new(origin: FakeOrigin) -> Self {
        FakeBlockingTransport { origin }
    }

    /// A transport over a fresh [`TransportFixture`] origin; its base URL is [`FAKE_BASE_URL`].
    pub fn fixture() -> Self {
        FakeBlockingTransport::new(FakeOrigin::fixture())
    }

    /// Adds an active fault.
    pub fn with_fault(self, fault: TransportFault) -> Self {
        self.origin.add_fault(fault);
        self
    }

    /// The origin it talks to.
    pub fn origin(&self) -> &FakeOrigin {
        &self.origin
    }

    /// The requests the origin has seen.
    pub fn requests(&self) -> Vec<SeenRequest> {
        self.origin.requests()
    }
}

impl BlockingTransport for FakeBlockingTransport {
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError> {
        if cancel.is_cancelled() {
            return Err(TransportError::new(
                TransportErrorKind::Cancelled,
                &request.url,
                None,
            ));
        }
        let reply = self.origin.get(request)?;
        Ok(BlockingResponse {
            head: reply.head(),
            body: Box::new(FakeBlockingBody {
                state: reply.body_state(&request.url),
                cancel: cancel.clone(),
                url: request.url.clone(),
                current: Vec::new(),
                offset: 0,
            }),
        })
    }
}

// ---- a std-only block_on, private to the testkit -----------------------------------------------------

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Drives `future` to completion on the calling thread.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

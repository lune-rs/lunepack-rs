//! The transport traits and the plain types a transport speaks (M4-D1, C9).
//!
//! Two traits, one contract. [`Transport`] is the app-injectable async one (object-safe, boxed
//! `Send + 'static` futures, a chunk-stream body); [`BlockingTransport`] is the sync one the
//! default adapters implement. The facade turns the second into the first. Neither knows about
//! signed sizes or the pack: the response rules that depend on them are in [`crate::fetch`], so
//! every transport is held to the same rules.
//!
//! The transport contract, which every implementation must meet and the testkit's transport suites
//! check:
//!
//! - follow redirects and return the final response;
//! - send `Range` and `If-Range` exactly as the [`Request`] gives them, and nothing that changes
//!   the representation: never send `Accept-Encoding`, never decode a content coding;
//! - report every response header in [`Head::headers`], name ASCII-lowercased, value as raw bytes,
//!   duplicates and order kept;
//! - a missing resource is a [`Head`] with its status (404), not an error; errors are for failures
//!   to get a response at all;
//! - never put the request URL's userinfo or query into an error ([`TransportError`] holds only
//!   scheme and host).

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::io::Read;
use std::pin::Pin;

use crate::cancel::CancelToken;
use crate::error::Untrusted;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A byte range of a `GET`, as the `Range` header carries it. Both ends are inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteRange {
    /// First byte.
    pub first: u64,
    /// Last byte; `None` means "to the end".
    pub last: Option<u64>,
}

impl ByteRange {
    /// The `Range` header value: `bytes=<first>-` or `bytes=<first>-<last>`.
    pub fn header_value(&self) -> String {
        match self.last {
            Some(last) => format!("bytes={}-{last}", self.first),
            None => format!("bytes={}-", self.first),
        }
    }
}

/// A validator for `If-Range`: one the server can compare, and that is strong. A weak ETag cannot
/// be built with [`Validator::from_etag`]. The stored text is the header value as sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Validator {
    /// A strong entity tag, quotes included (`"abc"`).
    StrongETag(String),
    /// A `Last-Modified` value.
    LastModified(String),
}

impl Validator {
    /// A strong validator from an `ETag` header value. `None` for a weak tag (`W/"..."`) and for
    /// anything that is not `"` etagc* `"` (RFC 9110 8.8.3, ASCII only), so the text can never
    /// carry a line break into a request header.
    pub fn from_etag(value: &[u8]) -> Option<Validator> {
        if value.starts_with(b"W/") {
            return None;
        }
        let inner = value.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
        if !inner
            .iter()
            .all(|&b| b == 0x21 || (0x23..=0x7e).contains(&b))
        {
            return None;
        }
        Some(Validator::StrongETag(
            String::from_utf8(value.to_vec()).ok()?,
        ))
    }

    /// A validator from a `Last-Modified` header value: 1 to 64 printable ASCII bytes, so the
    /// text can never carry a line break into a request header.
    pub fn from_last_modified(value: &[u8]) -> Option<Validator> {
        if value.is_empty() || value.len() > 64 || !value.iter().all(|b| (0x20..=0x7e).contains(b))
        {
            return None;
        }
        Some(Validator::LastModified(
            String::from_utf8(value.to_vec()).ok()?,
        ))
    }

    /// The `If-Range` header value.
    pub fn header_value(&self) -> &str {
        match self {
            Validator::StrongETag(v) | Validator::LastModified(v) => v,
        }
    }
}

/// One `GET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The absolute URL.
    pub url: String,
    /// The `Range` to send, if any.
    pub range: Option<ByteRange>,
    /// The `If-Range` to send, if any (only meaningful with a range).
    pub if_range: Option<Validator>,
}

/// The status and headers of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The status code of the final response.
    pub status: u16,
    /// Every header: name ASCII-lowercased by the transport, value raw, duplicates and order kept.
    pub headers: Vec<(String, Vec<u8>)>,
}

impl Head {
    /// The values of the header `name` (compared ASCII case-insensitively), in order.
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// A response body read as a stream of chunks.
pub trait Body: Send {
    /// The next chunk; `Ok(None)` at the end of the body. A chunk is never empty.
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;
}

/// A response from a [`Transport`].
pub struct Response {
    /// Status and headers.
    pub head: Head,
    /// The body.
    pub body: Box<dyn Body>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// The async transport an app may inject (C9). Object-safe; the future is `'static` so the facade
/// can hold it without borrowing the transport.
pub trait Transport: Send + Sync {
    /// Sends `request` and returns the final response (see the module docs for the contract).
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>>;
}

/// A response from a [`BlockingTransport`].
pub struct BlockingResponse {
    /// Status and headers.
    pub head: Head,
    /// The body.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for BlockingResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingResponse")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// The sync transport the default adapters implement. The facade runs it on its own worker threads
/// and presents it as a [`Transport`].
pub trait BlockingTransport: Send + Sync {
    /// Sends `request` and returns the final response (see the module docs for the contract). The
    /// transport checks `cancel` before connecting and before every body read and then fails with
    /// [`TransportErrorKind::Cancelled`].
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError>;
}

/// What kind of failure a [`TransportError`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// No connection could be made (DNS, refused, unreachable).
    Connect,
    /// The TLS handshake or certificate check failed.
    Tls,
    /// A connect or read timed out.
    Timeout,
    /// The proxy refused or failed.
    Proxy,
    /// A read or write failed on an open connection.
    Io,
    /// The operation's [`CancelToken`] was cancelled.
    Cancelled,
    /// The peer's bytes broke the HTTP protocol.
    Protocol,
    /// The request needs something this transport does not do (a scheme, a redirect policy).
    Unsupported,
}

impl TransportErrorKind {
    /// A fixed lowercase description.
    pub const fn describe(self) -> &'static str {
        match self {
            TransportErrorKind::Connect => "connection failed",
            TransportErrorKind::Tls => "TLS failed",
            TransportErrorKind::Timeout => "timed out",
            TransportErrorKind::Proxy => "proxy failed",
            TransportErrorKind::Io => "I/O failed",
            TransportErrorKind::Cancelled => "cancelled",
            TransportErrorKind::Protocol => "protocol error",
            TransportErrorKind::Unsupported => "unsupported request",
        }
    }
}

/// A transport failed to produce a response (or a body chunk).
///
/// It names the request's scheme and host and nothing else of the URL: a query or userinfo may
/// carry a credential, so neither reaches `Display` or `Debug`. An adapter must not put the URL
/// into the [`source`](TransportError::source) it attaches either.
pub struct TransportError {
    /// The failure class.
    pub kind: TransportErrorKind,
    /// The underlying error, kept as the cause (hard rule 4).
    pub source: Option<Box<dyn StdError + Send + Sync>>,
    origin: String,
}

impl TransportError {
    /// An error of `kind` for a request to `url`; only the scheme and host of `url` are kept.
    pub fn new(
        kind: TransportErrorKind,
        url: &str,
        source: Option<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        TransportError {
            kind,
            source,
            origin: origin_of(url),
        }
    }

    /// The `scheme://host` the request went to.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport: {} ({})", self.kind.describe(), self.origin)
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The cause is not printed: an adapter's error may echo the URL.
        f.debug_struct("TransportError")
            .field("kind", &self.kind)
            .field("origin", &self.origin)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

impl StdError for TransportError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn StdError + 'static))
    }
}

/// `scheme://host` of `url`, with no userinfo, port, path, query or fragment; escaped and capped
/// like any untrusted text. A text that does not look like a URL becomes `<invalid url>`.
fn origin_of(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once(':') else {
        return "<invalid url>".to_owned();
    };
    let scheme_ok = scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok {
        return "<invalid url>".to_owned();
    }
    let host = match rest.strip_prefix("//") {
        Some(after) => {
            let authority = after
                .split(['/', '?', '#', '\\'])
                .next()
                .unwrap_or_default();
            let hostport = authority.rsplit('@').next().unwrap_or_default();
            if hostport.starts_with('[') {
                // An IPv6 literal: up to and including the closing bracket.
                hostport.find(']').map_or(hostport, |end| &hostport[..=end])
            } else {
                hostport.split(':').next().unwrap_or_default()
            }
        }
        // `file:/path` has no authority; any other scheme without `//` (`user:pw@host`) is not a
        // URL worth echoing.
        None if scheme.eq_ignore_ascii_case("file") => "",
        None => return "<invalid url>".to_owned(),
    };
    Untrusted::new(&format!("{}://{host}", scheme.to_ascii_lowercase())).to_string()
}

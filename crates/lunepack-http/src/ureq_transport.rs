//! [`UreqTransport`]: the default `http`/`https` transport (M4-D14).

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read};
use std::time::Duration;

use lunepack_core::{
    BlockingResponse, BlockingTransport, CancelToken, Head, Request, TransportError,
    TransportErrorKind,
};
use ureq::Agent;
use ureq::config::Config;
use ureq::tls::{RootCerts, TlsConfig};

use crate::proxy::{self, Selection};

/// Timeouts and the redirect limit of [`UreqTransport`] (M4-D14). There is no global timeout, so a
/// large download is never cut short while it makes progress.
#[derive(Debug, Clone)]
pub struct UreqOptions {
    /// Longest wait for a connection, TLS handshake included. Default 30 s.
    pub connect_timeout: Duration,
    /// Longest wait for one read from the socket. Default 30 s.
    pub read_timeout: Duration,
    /// Redirects followed before the request fails. Default 5.
    pub max_redirects: u32,
}

impl Default for UreqOptions {
    fn default() -> Self {
        UreqOptions {
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(30),
            max_redirects: 5,
        }
    }
}

/// The agent configuration, in one place: this is the only constructor, and it offers no way to
/// add a trust anchor. Roots are the platform verifier's; ureq's `rustls` feature links
/// `webpki-roots`, but nothing here selects `RootCerts::WebPki`.
pub(crate) fn agent_config(options: &UreqOptions) -> Config {
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    Agent::config_builder()
        .tls_config(tls)
        // A 404 is an answer, not an error (the core decides what a status means).
        .http_status_as_error(false)
        .max_redirects(options.max_redirects)
        // Exactly `User-Agent: lunepack` (no app id, version or install id; D24). An empty value
        // means "send no header" for the two below: no `Accept`, and never an `Accept-Encoding`,
        // even if another crate in the build turns ureq's gzip feature on.
        .user_agent("lunepack")
        .accept("")
        .accept_encoding("")
        .timeout_connect(Some(options.connect_timeout))
        .timeout_per_read(Some(options.read_timeout))
        .build()
}

/// The default transport for `http` and `https` URLs: ureq with rustls and the platform
/// verifier, redirects followed, system proxies per M4-D14, no content decoding.
///
/// A blocked read ends at the per-read timeout, not at cancellation (the socket cannot be woken;
/// documented risk). Cancellation is checked before connecting and before every body read.
pub struct UreqTransport {
    agent: Agent,
}

impl UreqTransport {
    /// A transport with the default [`UreqOptions`].
    pub fn new() -> Self {
        UreqTransport::with_options(&UreqOptions::default())
    }

    /// A transport with the given options.
    pub fn with_options(options: &UreqOptions) -> Self {
        UreqTransport {
            agent: Agent::new_with_config(agent_config(options)),
        }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport::new()
    }
}

impl fmt::Debug for UreqTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UreqTransport").finish_non_exhaustive()
    }
}

impl BlockingTransport for UreqTransport {
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError> {
        let fail = |kind: TransportErrorKind, source: Option<Box<dyn StdError + Send + Sync>>| {
            TransportError::new(kind, &request.url, source)
        };
        if cancel.is_cancelled() {
            return Err(fail(TransportErrorKind::Cancelled, None));
        }
        if !is_http_url(&request.url) {
            return Err(fail(
                TransportErrorKind::Unsupported,
                Some("only http and https URLs are supported".into()),
            ));
        }

        let mut builder = self.agent.get(&request.url);
        if let Some(range) = request.range {
            builder = builder.header("Range", range.header_value());
        }
        if let Some(validator) = &request.if_range {
            // Only with a range: `If-Range` alone means nothing.
            if request.range.is_some() {
                builder = builder.header("If-Range", validator.header_value());
            }
        }
        let result = match proxy::select(&request.url) {
            Selection::AgentDefault => builder.call(),
            Selection::Override(chosen) => builder.config().proxy(chosen).build().call(),
        };
        let response = result.map_err(|e| from_ureq(&e, &request.url))?;

        let (parts, body) = response.into_parts();
        let head = Head {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
        };
        Ok(BlockingResponse {
            head,
            body: Box::new(UreqBody {
                inner: body.into_reader(),
                cancel: cancel.clone(),
                url: request.url.clone(),
            }),
        })
    }
}

fn is_http_url(url: &str) -> bool {
    let lower = |prefix: &str| {
        url.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    lower("http://") || lower("https://")
}

/// The body: checks the token before every read, and turns every failure into an `io::Error` that
/// wraps a [`TransportError`] (the facade finds it again with `get_ref().downcast_ref`). The kind
/// is never `Interrupted`, which `read_to_end` would retry.
struct UreqBody {
    inner: ureq::BodyReader<'static>,
    cancel: CancelToken,
    url: String,
}

impl Read for UreqBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(wrap(TransportError::new(
                TransportErrorKind::Cancelled,
                &self.url,
                None,
            )));
        }
        self.inner.read(buf).map_err(|e| {
            let error = match e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<ureq::Error>())
            {
                Some(ureq_error) => from_ureq(ureq_error, &self.url),
                None => TransportError::new(
                    io_kind(&e),
                    &self.url,
                    Some(Box::new(io::Error::new(e.kind(), "body read failed"))),
                ),
            };
            wrap(error)
        })
    }
}

/// An `io::Error` carrying `error`, for `Read` implementations.
pub(crate) fn wrap(error: TransportError) -> io::Error {
    io::Error::other(error)
}

/// Whether `e` wraps a rustls error anywhere in its cause chain. ureq reports a failed handshake
/// (an untrusted certificate, an alert) as an `io::Error` around the rustls error.
fn is_tls_failure(e: &io::Error) -> bool {
    let mut cause: Option<&(dyn StdError + 'static)> = e.get_ref().map(|inner| inner as _);
    while let Some(c) = cause {
        if c.is::<rustls::Error>() {
            return true;
        }
        cause = c.source();
    }
    false
}

fn io_kind(e: &io::Error) -> TransportErrorKind {
    if is_tls_failure(e) {
        return TransportErrorKind::Tls;
    }
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TransportErrorKind::Timeout,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotConnected => {
            TransportErrorKind::Connect
        }
        _ => TransportErrorKind::Io,
    }
}

fn kind_of(e: &ureq::Error) -> TransportErrorKind {
    use ureq::Error as E;
    match e {
        E::Timeout(_) => TransportErrorKind::Timeout,
        E::Tls(_) | E::Pem(_) | E::Rustls(_) | E::TlsRequired => TransportErrorKind::Tls,
        E::ConnectProxyFailed(_) | E::InvalidProxyUrl => TransportErrorKind::Proxy,
        E::HostNotFound | E::ConnectionFailed => TransportErrorKind::Connect,
        E::Io(io_error) => io_kind(io_error),
        E::RequireHttpsOnly(_) => TransportErrorKind::Unsupported,
        _ => TransportErrorKind::Protocol,
    }
}

/// A [`TransportError`] for a ureq failure, with the ureq error kept as the source. The two
/// variants that carry the URL's text are replaced by a fixed message (the URL's query or userinfo
/// must not reach a log through the cause chain).
fn from_ureq(e: &ureq::Error, url: &str) -> TransportError {
    let kind = kind_of(e);
    let source: Box<dyn StdError + Send + Sync> = match e {
        ureq::Error::BadUri(_) => "the URL could not be parsed".into(),
        ureq::Error::RequireHttpsOnly(_) => "the URL is not https".into(),
        // `ureq::Error` is not `Clone`; rebuild the one shape that matters most, keep the rest as
        // text of the error (which names no URL).
        other => other.to_string().into(),
    };
    TransportError::new(kind, url, Some(source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ureq::config::AutoHeaderValue;

    #[test]
    fn the_agent_trusts_the_platform_verifier_and_nothing_else() {
        let config = agent_config(&UreqOptions::default());
        assert!(
            matches!(
                config.tls_config().root_certs(),
                RootCerts::PlatformVerifier
            ),
            "the production constructor must select the platform verifier"
        );
        assert!(
            !config.tls_config().disable_verification(),
            "certificate verification must stay on"
        );
    }

    #[test]
    fn the_agent_sends_no_accept_headers_and_a_bare_user_agent() {
        let config = agent_config(&UreqOptions::default());
        assert!(matches!(config.accept_encoding(), AutoHeaderValue::None));
        assert!(matches!(config.accept(), AutoHeaderValue::None));
        assert!(
            matches!(config.user_agent(), AutoHeaderValue::Provided(v) if v.as_str() == "lunepack")
        );
        assert!(!config.http_status_as_error());
        assert_eq!(config.max_redirects(), 5);
    }

    #[test]
    fn options_reach_the_agent() {
        let config = agent_config(&UreqOptions {
            connect_timeout: Duration::from_secs(7),
            read_timeout: Duration::from_secs(9),
            max_redirects: 2,
        });
        assert_eq!(config.max_redirects(), 2);
        assert_eq!(config.timeout_per_read(), Some(Duration::from_secs(9)));
        assert_eq!(
            config.timeouts().connect,
            Some(Duration::from_secs(7)),
            "connect timeout"
        );
        assert_eq!(config.timeouts().global, None, "no global timeout");
    }
}

//! Proxy selection (M4-D14).
//!
//! Order: an environment proxy (`ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` with `NO_PROXY`) wins
//! everywhere. Without one, Windows reads the WinINET user proxy (inside ureq's own default, the
//! `win-system-proxy` feature), macOS asks hyper-util's system matcher about each request URL, and
//! Linux uses the environment only. No PAC or WPAD (D23).
//!
//! ureq's default configuration already covers the environment and Windows, so the agent is built
//! with it and only macOS needs a per-request answer.

use ureq::http::Uri;

/// What to do about the proxy for one request.
pub(crate) enum Selection {
    /// Use the agent's own proxy setting (the environment, or the WinINET proxy on Windows).
    AgentDefault,
    /// Use exactly this proxy for the request; `None` connects directly.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Override(Option<ureq::Proxy>),
}

/// The proxy choice for a request to `url`. Evaluated per request: on macOS the system settings
/// are read each time, so a change of network settings applies to the next request.
pub(crate) fn select(url: &str) -> Selection {
    #[cfg(target_os = "macos")]
    {
        if ureq::Proxy::try_from_env().is_some() {
            return Selection::AgentDefault;
        }
        Selection::Override(mac_system_proxy(url))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = url;
        Selection::AgentDefault
    }
}

#[cfg(target_os = "macos")]
fn mac_system_proxy(url: &str) -> Option<ureq::Proxy> {
    let matcher = hyper_util::client::proxy::matcher::Matcher::from_system();
    let uri = url.parse::<http::Uri>().ok()?;
    let intercept = matcher.intercept(&uri)?;
    ureq::Proxy::new(&intercept.uri().to_string()).ok()
}

/// `host:port` of the proxy a request to `url` would use, or `None` for a direct connection. A
/// diagnostic for tests and the CI probe; it applies the same order as the transport does.
pub fn proxy_for_url(url: &str) -> Option<String> {
    let chosen = match select(url) {
        Selection::Override(proxy) => proxy,
        Selection::AgentDefault => {
            let proxy = ureq::Proxy::try_from_env()?;
            let uri = url.parse::<Uri>().ok()?;
            if proxy.is_no_proxy(&uri) {
                return None;
            }
            Some(proxy)
        }
    };
    chosen.map(|p| format!("{}:{}", p.host(), p.port()))
}

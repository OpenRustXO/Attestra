//! Outbound HTTP abstraction, so this crate runs on the host in tests and on Workers in
//! production.

use std::fmt;

/// A buffered outbound request.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Header values and bodies carry access tokens and integrity tokens, so `Debug` only
/// shows header names and the body length.
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A buffered response.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A transport-level failure (DNS, TLS, connection reset, ...).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("transport error: {0}")]
pub struct HttpError(pub String);

/// Sends HTTP requests. Implementations may return `!Send` futures (Workers is
/// single-threaded), hence a plain `async fn`.
#[allow(async_fn_in_trait)]
pub trait HttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;
}

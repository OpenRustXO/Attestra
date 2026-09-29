//! `ANY /p/{provider}/{*path}`: the attested API-key proxy.

use proxy_core::assertion::{self, ASSERTION_HEADER, TIMESTAMP_HEADER};
use proxy_core::{ProxyError, RequestPath, forwards_response_header};
use session::Platform;
use worker::{
    Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, ResponseBuilder,
    Url,
};

use super::ios;
use crate::config::Config;
use crate::durable::device_state::{self, CheckRequest, RateCheck, Refusal};
use crate::encoding::decode_base64;
use crate::error::ApiError;
use crate::http;
use crate::providers;
use crate::sessions::{self, Session};
use crate::time::now_secs;

pub async fn handle(
    req: &mut Request,
    env: &Env,
    config: &Config,
    provider_name: &str,
    raw_path: &str,
) -> Result<Response, ApiError> {
    let session = sessions::authenticate(req, env).await?;

    let registry = providers::registry().map_err(|e| ApiError::Internal(e.to_string()))?;
    let provider = registry.get(provider_name).ok_or(ApiError::NotFound)?;
    let path = RequestPath::parse(raw_path).map_err(forbidden)?;
    let method = req.method();
    provider
        .authorize(method.as_ref(), &path)
        .map_err(forbidden)?;

    let body = http::read_body(req, provider.max_body_bytes).await?;
    if !body.is_empty() && matches!(method, Method::Get | Method::Head) {
        return Err(ApiError::BadRequest(
            "GET and HEAD requests cannot have a body".into(),
        ));
    }
    let url = req.url()?;

    let counter = if provider.require_assertion && session.claims.plat == Platform::Ios {
        Some(verify_request_assertion(
            req,
            config,
            &session,
            method.as_ref(),
            &url,
            &body,
        )?)
    } else {
        None
    };
    let rate = provider.rate_limit.map(|limit| RateCheck {
        provider: provider.name.clone(),
        per_minute: limit.per_minute,
        per_day: limit.per_day,
    });
    if counter.is_some() || rate.is_some() {
        match device_state::check(env, &session.claims.sub, &CheckRequest { counter, rate }).await?
        {
            Ok(()) => {}
            Err(Refusal::CounterReplay) => {
                return Err(ApiError::AttestationInvalid(
                    "assertion counter replay".into(),
                ));
            }
            Err(Refusal::RateLimited { retry_after_secs }) => {
                return Err(ApiError::RateLimited { retry_after_secs });
            }
        }
    }

    let key = env
        .secret(&provider.secret)
        .map_err(|_| ApiError::Internal(format!("secret {} is not set", provider.secret)))?
        .to_string();
    let upstream_url = provider
        .upstream_url(&path, url.query(), &key)
        .map_err(|e| ApiError::Internal(format!("{}: {e}", provider.name)))?;

    let headers = Headers::new();
    for (name, value) in req.headers().entries() {
        if provider.forwards_request_header(&name) {
            headers.append(&name, &value)?;
        }
    }
    if let Some((name, value)) = provider
        .auth_header(&key)
        .map_err(|e| ApiError::Internal(format!("{}: {e}", provider.name)))?
    {
        headers.set(&name, &value)?;
    }

    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        // Never follow redirects with the key attached; hand them to the client instead.
        .with_redirect(RequestRedirect::Manual);
    if !body.is_empty() {
        init.with_body(Some(
            worker::js_sys::Uint8Array::from(body.as_slice()).into(),
        ));
    }
    let outbound = Request::new_with_init(&upstream_url, &init)?;
    let upstream = Fetch::Request(outbound)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("{}: {e}", provider.name)))?;
    stream_back(upstream, key.trim())
}

/// Returns the upstream response with its body streamed through untouched (SSE and chunked
/// responses keep flowing) and only safe headers copied.
fn stream_back(upstream: Response, key: &str) -> Result<Response, ApiError> {
    let status = upstream.status_code();
    let headers = Headers::new();
    for (name, value) in upstream.headers().entries() {
        // Also drop any header that echoes the key (e.g. a redirect `Location`).
        if forwards_response_header(&name) && !value.contains(key) {
            headers.append(&name, &value)?;
        }
    }
    let (_, body) = upstream.into_parts();
    Ok(ResponseBuilder::new()
        .with_status(status)
        .with_headers(headers)
        .body(body))
}

/// Verifies `X-Attestra-Assertion` over this exact request and returns its counter.
fn verify_request_assertion(
    req: &Request,
    config: &Config,
    session: &Session,
    method: &str,
    url: &Url,
    body: &[u8],
) -> Result<u32, ApiError> {
    let apple = config
        .apple
        .as_ref()
        .ok_or_else(|| ApiError::Internal("iOS session but iOS is not configured".into()))?;
    let header = |name: &str| -> Result<String, ApiError> {
        req.headers()
            .get(name)?
            .ok_or_else(|| ApiError::AttestationInvalid(format!("missing {name} header")))
    };
    let timestamp = assertion::check_timestamp(&header(TIMESTAMP_HEADER)?, now_secs())
        .map_err(|e| ApiError::AttestationInvalid(e.to_string()))?;
    let assertion_bytes = decode_base64(&header(ASSERTION_HEADER)?)
        .ok_or_else(|| ApiError::AttestationInvalid("assertion is not base64".into()))?;

    let client_data = assertion::client_data(method, &path_and_query(url), body, timestamp);
    let public_key = session
        .device
        .public_key
        .as_deref()
        .ok_or_else(|| ApiError::Internal("iOS device without public key".into()))?;
    let verified = ios::verifier(apple)?
        .verify_assertion(&assertion_bytes, &client_data, public_key)
        .map_err(ios::attestation_invalid)?;
    Ok(verified.counter)
}

/// `PATH` in the assertion client data: the percent-encoded path plus `?query` when the
/// query is non-empty, exactly as the runtime parsed the request URL.
fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) if !query.is_empty() => format!("{}?{query}", url.path()),
        _ => url.path().to_owned(),
    }
}

fn forbidden(err: ProxyError) -> ApiError {
    ApiError::Forbidden(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Must agree byte-for-byte with the Swift and Kotlin clients' `pathAndQuery`
    /// (see `RequestBuilderTests.testEncodesPathSegmentsAndQuery` in the Swift package).
    #[test]
    fn path_and_query_matches_the_clients() {
        let url = Url::parse(
            "https://attestra.example.dev/p/gemini/v1beta/models/gemini%20pro:generateContent?q=a%26b%3Dc%2Bd%20%27e%27&flag",
        )
        .unwrap();
        assert_eq!(
            path_and_query(&url),
            "/p/gemini/v1beta/models/gemini%20pro:generateContent?q=a%26b%3Dc%2Bd%20%27e%27&flag"
        );
        let bare = Url::parse("https://attestra.example.dev/p/x/?").unwrap();
        assert_eq!(path_and_query(&bare), "/p/x/");
    }
}

//! Play Integrity plumbing: a `fetch`-backed [`HttpClient`] and the per-isolate service
//! account (whose access-token cache therefore lives as long as the isolate).

use std::sync::OnceLock;

use attest_google::{GoogleAuth, HttpClient, HttpError, HttpRequest, HttpResponse};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use crate::error::ApiError;

const SERVICE_ACCOUNT_SECRET: &str = "GOOGLE_SERVICE_ACCOUNT_JSON";
/// Google API responses are small; anything larger is treated as an upstream failure.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

pub struct FetchClient;

impl HttpClient for FetchClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let transport = |e: worker::Error| HttpError(e.to_string());
        let headers = Headers::new();
        for (name, value) in &request.headers {
            headers.set(name, value).map_err(transport)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::from(request.method.to_owned()))
            .with_headers(headers)
            .with_body(Some(
                worker::js_sys::Uint8Array::from(request.body.as_slice()).into(),
            ));
        let outbound = Request::new_with_init(&request.url, &init).map_err(transport)?;
        let mut response = Fetch::Request(outbound).send().await.map_err(transport)?;
        let body = response.bytes().await.map_err(transport)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError("response too large".into()));
        }
        Ok(HttpResponse {
            status: response.status_code(),
            body,
        })
    }
}

/// The service account, parsed once per isolate.
pub fn auth(env: &Env) -> Result<&'static GoogleAuth, ApiError> {
    static AUTH: OnceLock<GoogleAuth> = OnceLock::new();
    if let Some(auth) = AUTH.get() {
        return Ok(auth);
    }
    let json = env
        .secret(SERVICE_ACCOUNT_SECRET)
        .map_err(|_| ApiError::Internal(format!("secret {SERVICE_ACCOUNT_SECRET} is not set")))?
        .to_string();
    let auth = GoogleAuth::from_service_account_json(&json)
        .map_err(|e| ApiError::Internal(format!("{SERVICE_ACCOUNT_SECRET}: {e}")))?;
    Ok(AUTH.get_or_init(|| auth))
}

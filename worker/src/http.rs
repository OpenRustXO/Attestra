//! JSON response helpers and bounded request-body reading.

use futures_util::StreamExt as _;
use serde::Serialize;
use serde::de::DeserializeOwned;
use worker::js_sys::Uint8Array;
use worker::wasm_bindgen::JsCast as _;
use worker::{Request, Response, console_debug, console_error};

use crate::error::ApiError;

/// Upper bound for the JSON bodies of the attestation endpoints. Attestation objects are
/// a few kilobytes; anything much larger is not a legitimate client.
pub const MAX_JSON_BODY_BYTES: usize = 64 * 1024;

/// Headers set on every JSON response. No CORS headers: only mobile clients call this API.
const JSON_HEADERS: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
];

pub fn json<T: Serialize>(status: u16, body: &T) -> Result<Response, ApiError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|e| ApiError::Internal(format!("serialize response: {e}")))?;
    Ok(build(status, bytes, &[])?)
}

/// Logs `err` server-side and renders the generic client-facing error body.
pub fn error_response(err: &ApiError) -> worker::Result<Response> {
    if err.is_server_fault() {
        console_error!("{err}");
    } else {
        console_debug!("{err}");
    }
    build(err.status(), err.body().into_bytes(), &err.headers())
}

fn build(status: u16, body: Vec<u8>, extra: &[(&str, String)]) -> worker::Result<Response> {
    let mut builder = Response::builder().with_status(status);
    for (name, value) in JSON_HEADERS {
        builder = builder.with_header(name, value)?;
    }
    for (name, value) in extra {
        builder = builder.with_header(name, value)?;
    }
    Ok(builder.fixed(body))
}

/// Reads the whole request body, failing with `payload_too_large` as soon as it exceeds
/// `limit` (checked against `Content-Length` first, then while streaming, so a chunked body
/// cannot bypass the cap).
pub async fn read_body(req: &mut Request, limit: u64) -> Result<Vec<u8>, ApiError> {
    if let Some(declared) = req.headers().get("content-length")? {
        let declared: u64 = declared
            .trim()
            .parse()
            .map_err(|_| ApiError::BadRequest("invalid content-length".into()))?;
        if declared > limit {
            return Err(ApiError::PayloadTooLarge);
        }
    }
    let Some(body) = req.inner().body() else {
        return Ok(Vec::new());
    };
    let mut stream = wasm_streams::ReadableStream::from_raw(body.unchecked_into()).into_stream();
    let mut buffer = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk: Uint8Array = chunk
            .map_err(|_| ApiError::BadRequest("request body stream failed".into()))?
            .dyn_into()
            .map_err(|_| ApiError::Internal("request body chunk is not bytes".into()))?;
        if buffer.len() as u64 + u64::from(chunk.length()) > limit {
            // Cancel rather than drop, so the runtime stops receiving the upload cleanly.
            let _ = stream.cancel().await;
            return Err(ApiError::PayloadTooLarge);
        }
        let start = buffer.len();
        buffer.resize(start + chunk.length() as usize, 0);
        chunk.copy_to(&mut buffer[start..]);
    }
    Ok(buffer)
}

pub async fn read_json<T: DeserializeOwned>(req: &mut Request) -> Result<T, ApiError> {
    let body = read_body(req, MAX_JSON_BODY_BYTES as u64).await?;
    serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {e}")))
}

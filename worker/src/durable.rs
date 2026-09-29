//! Durable Object classes bound in `wrangler.toml`, plus the worker-side helpers that call them.
//!
//! Objects are called over their `fetch` interface with small JSON bodies. The URL host is
//! irrelevant; only the path selects the operation.

pub mod challenge_store;
pub mod device_state;

pub use challenge_store::ChallengeStore;
pub use device_state::DeviceState;

use worker::{Env, Method, Request, RequestInit, Stub};

use crate::error::ApiError;

fn stub(env: &Env, binding: &str, name: &str) -> Result<Stub, ApiError> {
    Ok(env.durable_object(binding)?.get_by_name(name)?)
}

fn internal_request(path: &str, json_body: Option<String>) -> Result<Request, ApiError> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    if let Some(body) = json_body {
        init.with_body(Some(body.into()));
    }
    Ok(Request::new_with_init(
        &format!("https://durable-object{path}"),
        &init,
    )?)
}

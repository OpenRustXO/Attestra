//! Attestra: an attested API-key proxy for mobile apps, running as a Cloudflare Worker.
//!
//! The public modules (`challenge`, `config`, `encoding`, `error`, `providers`, `routes`) make
//! no runtime calls and are unit-tested on the host; the private modules are thin glue over
//! `worker` (D1, Durable Objects, fetch).

pub mod challenge;
pub mod config;
pub mod encoding;
pub mod error;
pub mod providers;
pub mod routes;

mod db;
mod durable;
mod google;
mod handlers;
mod http;
mod sessions;
mod time;

pub use durable::{ChallengeStore, DeviceState};

use worker::{Context, Env, Request, Response, event};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    match handlers::handle(req, &env).await {
        Ok(response) => Ok(response),
        Err(err) => http::error_response(&err),
    }
}

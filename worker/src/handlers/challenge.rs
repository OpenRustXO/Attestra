//! `POST /challenge`

use serde::Serialize;
use worker::{Env, Response};

use crate::challenge::Challenge;
use crate::config::Config;
use crate::durable::challenge_store;
use crate::error::ApiError;
use crate::http;
use crate::time::now_ms;

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    expires_at: u64,
}

pub async fn issue(env: &Env, config: &Config) -> Result<Response, ApiError> {
    let challenge = Challenge::random()?;
    let expires_at_ms = now_ms() + config.challenge_ttl_seconds * 1000;
    challenge_store::create(env, &challenge, expires_at_ms).await?;
    http::json(
        200,
        &ChallengeResponse {
            challenge: challenge.encode(),
            expires_at: expires_at_ms / 1000,
        },
    )
}

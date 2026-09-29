//! `POST /attest/ios` and `POST /assert/ios`

use attest_apple::{AppAttest, AppleError};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use session::Platform;
use worker::{Env, Request, Response};

use crate::challenge::Challenge;
use crate::config::{AppleConfig, Config};
use crate::db;
use crate::durable::{challenge_store, device_state};
use crate::encoding::{decode_field, decode_key_id};
use crate::error::ApiError;
use crate::http;
use crate::sessions;
use crate::time::now_secs;

#[derive(Deserialize)]
struct AttestRequest {
    key_id: String,
    attestation: String,
    challenge: String,
}

#[derive(Deserialize)]
struct AssertRequest {
    key_id: String,
    assertion: String,
    challenge: String,
}

pub fn verifier(apple: &AppleConfig) -> Result<AppAttest, ApiError> {
    AppAttest::new(apple.app_ids(), apple.allow_development)
        .map_err(|e| ApiError::Internal(format!("App Attest verifier: {e}")))
}

pub fn attestation_invalid(err: AppleError) -> ApiError {
    ApiError::AttestationInvalid(err.to_string())
}

/// Verifies a fresh App Attest key, registers the device and issues a session.
pub async fn attest(
    req: &mut Request,
    env: &Env,
    config: &Config,
    apple: &AppleConfig,
) -> Result<Response, ApiError> {
    let body: AttestRequest = http::read_json(req).await?;
    let challenge = Challenge::parse(&body.challenge)?;
    let key_id = decode_key_id(&body.key_id)?;
    let attestation = decode_field(&body.attestation, "attestation")?;

    // Consume first so a challenge is single-use even when verification fails.
    challenge_store::consume(env, &challenge).await?;

    let now = now_secs();
    let verified = verifier(apple)?
        .verify_attestation(&attestation, &key_id, challenge.as_bytes(), now)
        .map_err(attestation_invalid)?;

    let device_id = hex::encode(key_id);
    let environment = verified.environment.as_str();
    let revoked = db::register_ios(
        &db::database(env)?,
        &device_id,
        &STANDARD.encode(key_id),
        &verified.public_key,
        environment,
        now,
    )
    .await?;
    if revoked {
        return Err(ApiError::Forbidden("device revoked".into()));
    }
    sessions::issue(env, config, &device_id, Platform::Ios, environment)
}

/// Verifies an assertion from a registered key and issues a new session.
pub async fn assert(
    req: &mut Request,
    env: &Env,
    config: &Config,
    apple: &AppleConfig,
) -> Result<Response, ApiError> {
    let body: AssertRequest = http::read_json(req).await?;
    let challenge = Challenge::parse(&body.challenge)?;
    let key_id = decode_key_id(&body.key_id)?;
    let assertion = decode_field(&body.assertion, "assertion")?;

    challenge_store::consume(env, &challenge).await?;

    let device_id = hex::encode(key_id);
    let database = db::database(env)?;
    let device = db::find(&database, &device_id)
        .await?
        .filter(|d| d.platform == Platform::Ios.as_str())
        .ok_or_else(|| ApiError::AttestationInvalid("unknown key id".into()))?;
    if device.revoked {
        return Err(ApiError::Forbidden("device revoked".into()));
    }
    let public_key = device
        .public_key
        .as_deref()
        .ok_or_else(|| ApiError::Internal("iOS device without public key".into()))?;

    let verified = verifier(apple)?
        .verify_assertion(&assertion, challenge.as_bytes(), public_key)
        .map_err(attestation_invalid)?;
    let check = device_state::CheckRequest {
        counter: Some(verified.counter),
        rate: None,
    };
    if device_state::check(env, &device_id, &check).await?.is_err() {
        return Err(ApiError::AttestationInvalid(
            "assertion counter replay".into(),
        ));
    }

    db::touch(&database, &device_id, now_secs()).await?;
    sessions::issue(env, config, &device_id, Platform::Ios, &device.environment)
}

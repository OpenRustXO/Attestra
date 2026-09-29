//! `POST /attest/android`

use attest_google::{GoogleError, IntegrityRequest, PlayIntegrityPolicy};
use serde::Deserialize;
use session::Platform;
use worker::{Env, Request, Response};

use crate::challenge::Challenge;
use crate::config::{AndroidConfig, Config};
use crate::db;
use crate::durable::challenge_store;
use crate::encoding::is_canonical_uuid;
use crate::error::ApiError;
use crate::google::{self, FetchClient};
use crate::http;
use crate::sessions;
use crate::time::{now_ms, now_secs};

/// Standard API tokens are a few kilobytes.
const MAX_INTEGRITY_TOKEN_LEN: usize = 16 * 1024;

#[derive(Deserialize)]
struct AttestRequest {
    integrity_token: String,
    challenge: String,
    install_id: String,
    /// Required only when more than one package is configured.
    #[serde(default)]
    package_name: Option<String>,
}

pub async fn attest(
    req: &mut Request,
    env: &Env,
    config: &Config,
    android: &AndroidConfig,
) -> Result<Response, ApiError> {
    let body: AttestRequest = http::read_json(req).await?;
    let challenge = Challenge::parse(&body.challenge)?;
    if !is_canonical_uuid(&body.install_id) {
        return Err(ApiError::BadRequest(
            "install_id must be a lowercase UUID".into(),
        ));
    }
    if body.integrity_token.is_empty() || body.integrity_token.len() > MAX_INTEGRITY_TOKEN_LEN {
        return Err(ApiError::BadRequest("invalid integrity_token".into()));
    }
    let package_name = match (&body.package_name, android.package_names.as_slice()) {
        (Some(name), _) => name.as_str(),
        (None, [only]) => only.as_str(),
        (None, _) => {
            return Err(ApiError::BadRequest(
                "package_name is required when several packages are configured".into(),
            ));
        }
    };

    challenge_store::consume(env, &challenge).await?;

    let policy = PlayIntegrityPolicy {
        package_names: android.package_names.clone(),
        cert_sha256: android.cert_sha256.clone(),
        require_licensed: android.require_licensed,
    };
    let request = IntegrityRequest {
        package_name,
        integrity_token: &body.integrity_token,
        challenge: challenge.as_bytes(),
        install_id: &body.install_id,
    };
    let verified = attest_google::verify(
        &FetchClient,
        google::auth(env)?,
        &policy,
        &request,
        now_ms(),
    )
    .await
    .map_err(|err| match err {
        GoogleError::InvalidToken | GoogleError::Verdict(_) => {
            ApiError::AttestationInvalid(err.to_string())
        }
        GoogleError::Upstream(_) => ApiError::Upstream(err.to_string()),
        GoogleError::Config(_) => ApiError::Internal(err.to_string()),
    })?;

    let revoked =
        db::register_android(&db::database(env)?, &verified.device_id, now_secs()).await?;
    if revoked {
        return Err(ApiError::Forbidden("device revoked".into()));
    }
    sessions::issue(
        env,
        config,
        &verified.device_id,
        Platform::Android,
        "production",
    )
}

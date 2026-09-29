//! Session issuance and the bearer-token check used by the proxy.

use std::sync::OnceLock;

use serde::Serialize;
use session::{Claims, Platform, SessionKey};
use worker::{Env, Request, Response};

use crate::config::Config;
use crate::db::{self, Device};
use crate::error::ApiError;
use crate::http;
use crate::time::now_secs;

const SIGNING_KEY_SECRET: &str = "SESSION_SIGNING_KEY";

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: u64,
}

/// An authenticated request: verified claims plus the (non-revoked) device record.
#[derive(Debug)]
pub struct Session {
    pub claims: Claims,
    pub device: Device,
}

/// The signing key, parsed once per isolate.
fn signing_key(env: &Env) -> Result<&'static SessionKey, ApiError> {
    static KEY: OnceLock<SessionKey> = OnceLock::new();
    if let Some(key) = KEY.get() {
        return Ok(key);
    }
    let pem = env
        .secret(SIGNING_KEY_SECRET)
        .map_err(|_| ApiError::Internal(format!("secret {SIGNING_KEY_SECRET} is not set")))?
        .to_string();
    let key = SessionKey::from_pkcs8_pem(&pem)
        .map_err(|e| ApiError::Internal(format!("{SIGNING_KEY_SECRET}: {e}")))?;
    Ok(KEY.get_or_init(|| key))
}

/// Issues a session token and renders the `{ token, expires_at }` response.
pub fn issue(
    env: &Env,
    config: &Config,
    device_id: &str,
    platform: Platform,
    environment: &str,
) -> Result<Response, ApiError> {
    let mut jti = [0u8; 16];
    getrandom::fill(&mut jti).map_err(|e| ApiError::Internal(format!("getrandom: {e}")))?;
    let claims = Claims::new(
        device_id,
        platform,
        environment,
        now_secs(),
        config.session_ttl_seconds,
        jti,
    );
    let token = signing_key(env)?
        .issue(&claims)
        .map_err(|e| ApiError::Internal(format!("issue session: {e}")))?;
    http::json(
        200,
        &SessionResponse {
            token,
            expires_at: claims.exp,
        },
    )
}

/// Verifies `Authorization: Bearer <token>` and that the device exists and is not revoked
/// (revocation state is cached per isolate for up to 60 s).
pub async fn authenticate(req: &Request, env: &Env) -> Result<Session, ApiError> {
    let header = req
        .headers()
        .get("authorization")?
        .ok_or_else(|| ApiError::SessionInvalid("missing authorization header".into()))?;
    let token = bearer_token(&header)
        .ok_or_else(|| ApiError::SessionInvalid("not a bearer token".into()))?;
    let claims = signing_key(env)?
        .verify(token, now_secs())
        .map_err(|e| ApiError::SessionInvalid(e.to_string()))?;
    let device = db::find_cached(env, &claims.sub)
        .await?
        .ok_or_else(|| ApiError::SessionInvalid("unknown device".into()))?;
    if device.revoked {
        return Err(ApiError::SessionInvalid("device revoked".into()));
    }
    if device.platform != claims.plat.as_str() {
        return Err(ApiError::SessionInvalid("platform mismatch".into()));
    }
    Ok(Session { claims, device })
}

fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.trim().split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn parses_bearer_tokens() {
        assert_eq!(bearer_token("Bearer abc.def.ghi"), Some("abc.def.ghi"));
        assert_eq!(bearer_token("bearer  abc "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("abc"), None);
    }
}

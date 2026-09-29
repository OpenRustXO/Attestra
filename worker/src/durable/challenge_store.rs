//! `ChallengeStore`: single-use attestation challenges with a TTL.
//!
//! There is one object per challenge, named by the challenge itself. Issuance and consumption
//! therefore scale horizontally, each object is created close to the client that requested
//! it, and single use reduces to an atomic delete of one key. An alarm clears challenges that
//! are never consumed.

use serde::{Deserialize, Serialize};
use worker::{DurableObject, Env, Request, Response, Result, State, durable_object};

use super::{internal_request, stub};
use crate::challenge::Challenge;
use crate::error::ApiError;
use crate::time::now_ms;

pub const BINDING: &str = "CHALLENGE_STORE";
const EXPIRES_AT_KEY: &str = "expires_at_ms";

#[derive(Serialize, Deserialize)]
struct CreateRequest {
    expires_at_ms: u64,
}

#[durable_object(alarm)] // `alarm` also generates the `fetch` binding
pub struct ChallengeStore {
    state: State,
}

impl DurableObject for ChallengeStore {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let storage = self.state.storage();
        match req.path().as_str() {
            "/create" => {
                let CreateRequest { expires_at_ms } = req.json().await?;
                if storage.get::<u64>(EXPIRES_AT_KEY).await?.is_some() {
                    return Response::error("exists", 409);
                }
                storage.put(EXPIRES_AT_KEY, expires_at_ms).await?;
                let delay_ms = expires_at_ms.saturating_sub(now_ms());
                storage
                    .set_alarm(i64::try_from(delay_ms).unwrap_or(i64::MAX))
                    .await?;
                Ok(Response::empty()?.with_status(201))
            }
            "/consume" => {
                let expires_at_ms = storage.get::<u64>(EXPIRES_AT_KEY).await?;
                // `delete` reports whether the key existed, which makes consumption single-use
                // even if two requests race.
                let existed = storage.delete(EXPIRES_AT_KEY).await?;
                if existed {
                    storage.delete_alarm().await?;
                }
                match expires_at_ms {
                    Some(expires_at_ms) if existed && now_ms() < expires_at_ms => Response::empty(),
                    _ => Response::error("gone", 410),
                }
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        Response::empty()
    }
}

/// Registers a freshly generated challenge.
pub async fn create(
    env: &Env,
    challenge: &Challenge,
    expires_at_ms: u64,
) -> std::result::Result<(), ApiError> {
    let body = serde_json::to_string(&CreateRequest { expires_at_ms })
        .map_err(|e| ApiError::Internal(format!("encode challenge: {e}")))?;
    let response = stub(env, BINDING, &challenge.encode())?
        .fetch_with_request(internal_request("/create", Some(body))?)
        .await?;
    match response.status_code() {
        201 => Ok(()),
        status => Err(ApiError::Internal(format!(
            "challenge store create returned {status}"
        ))),
    }
}

/// Consumes a challenge. Fails with `challenge_invalid` if it is unknown, expired or used.
pub async fn consume(env: &Env, challenge: &Challenge) -> std::result::Result<(), ApiError> {
    let response = stub(env, BINDING, &challenge.encode())?
        .fetch_with_request(internal_request("/consume", None)?)
        .await?;
    match response.status_code() {
        200 => Ok(()),
        410 => Err(ApiError::ChallengeInvalid(
            "unknown, expired or already used".into(),
        )),
        status => Err(ApiError::Internal(format!(
            "challenge store consume returned {status}"
        ))),
    }
}

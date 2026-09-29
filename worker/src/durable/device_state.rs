//! `DeviceState`: per-device App Attest counter and rate-limit windows.
//!
//! One object per device id. A Durable Object processes one event at a time and its storage
//! writes commit together, so each `/check` (counter compare-and-set plus rate-limit
//! check-and-increment) is atomic.

use attest_apple::ensure_counter_advanced;
use proxy_core::{RateDecision, RateLimit, RateWindows};
use serde::{Deserialize, Serialize};
use worker::{DurableObject, Env, Request, Response, Result, State, durable_object};

use super::{internal_request, stub};
use crate::error::ApiError;
use crate::time::now_ms;

pub const BINDING: &str = "DEVICE_STATE";
const COUNTER_KEY: &str = "counter";
const STATUS_COUNTER_REPLAY: u16 = 409;
const STATUS_RATE_LIMITED: u16 = 429;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CheckRequest {
    /// A verified App Attest assertion counter that must exceed the stored one.
    #[serde(default)]
    pub counter: Option<u32>,
    #[serde(default)]
    pub rate: Option<RateCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateCheck {
    pub provider: String,
    pub per_minute: Option<u32>,
    pub per_day: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct RateLimited {
    retry_after_secs: u64,
}

/// Why a check was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    CounterReplay,
    RateLimited { retry_after_secs: u64 },
}

#[durable_object(fetch)]
pub struct DeviceState {
    state: State,
}

impl DurableObject for DeviceState {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if req.path() != "/check" {
            return Response::error("not found", 404);
        }
        let check: CheckRequest = req.json().await?;
        let storage = self.state.storage();

        // The counter is persisted even if the rate limit then refuses the request: the
        // assertion has been presented and must never be accepted again.
        if let Some(counter) = check.counter {
            let stored = storage.get::<u32>(COUNTER_KEY).await?.unwrap_or(0);
            if ensure_counter_advanced(stored, counter).is_err() {
                return Response::error("counter replay", STATUS_COUNTER_REPLAY);
            }
            storage.put(COUNTER_KEY, counter).await?;
        }

        if let Some(rate) = check.rate {
            let key = format!("rate:{}", rate.provider);
            let limit = RateLimit {
                per_minute: rate.per_minute,
                per_day: rate.per_day,
            };
            let windows = storage.get::<RateWindows>(&key).await?.unwrap_or_default();
            match windows.check(&limit, now_ms()) {
                RateDecision::Allowed(next) => storage.put(&key, next).await?,
                RateDecision::Limited { retry_after_secs } => {
                    return Ok(Response::from_json(&RateLimited { retry_after_secs })?
                        .with_status(STATUS_RATE_LIMITED));
                }
            }
        }

        Response::empty()
    }
}

/// Runs a counter and/or rate-limit check for `device_id`.
///
/// The outer `Result` carries infrastructure failures; the inner one a refusal.
pub async fn check(
    env: &Env,
    device_id: &str,
    request: &CheckRequest,
) -> std::result::Result<std::result::Result<(), Refusal>, ApiError> {
    let body = serde_json::to_string(request)
        .map_err(|e| ApiError::Internal(format!("encode device check: {e}")))?;
    let mut response = stub(env, BINDING, device_id)?
        .fetch_with_request(internal_request("/check", Some(body))?)
        .await?;
    match response.status_code() {
        200 => Ok(Ok(())),
        STATUS_COUNTER_REPLAY => Ok(Err(Refusal::CounterReplay)),
        STATUS_RATE_LIMITED => {
            let RateLimited { retry_after_secs } = response.json().await?;
            Ok(Err(Refusal::RateLimited { retry_after_secs }))
        }
        status => Err(ApiError::Internal(format!(
            "device state check returned {status}"
        ))),
    }
}

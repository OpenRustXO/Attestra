//! D1 access to the `devices` table, plus a short per-isolate cache for session checks.

use std::cell::RefCell;
use std::collections::HashMap;

use serde::Deserialize;
use worker::{D1Database, D1Type, Env};

use crate::error::ApiError;
use crate::time::now_ms;

pub const BINDING: &str = "DB";

/// How long a device lookup (revocation state, public key) is reused by an isolate.
const CACHE_TTL_MS: u64 = 60_000;
/// Bound on cached entries per isolate; the cache is simply cleared when it fills up.
const CACHE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub platform: String,
    pub public_key: Option<Vec<u8>>,
    pub environment: String,
    pub revoked: bool,
}

#[derive(Deserialize)]
struct DeviceRow {
    id: String,
    platform: String,
    public_key_hex: Option<String>,
    environment: String,
    revoked: f64,
}

#[derive(Deserialize)]
struct RevokedRow {
    revoked: f64,
}

pub fn database(env: &Env) -> Result<D1Database, ApiError> {
    Ok(env.d1(BINDING)?)
}

/// Unix seconds as a D1 number (D1's integer binding is only 32 bits wide).
fn timestamp(unix_secs: u64) -> D1Type<'static> {
    D1Type::Real(unix_secs as f64)
}

/// Registers (or refreshes) an iOS device. Returns whether the device is revoked.
pub async fn register_ios(
    db: &D1Database,
    id: &str,
    key_id_b64: &str,
    public_key: &[u8],
    environment: &str,
    now_secs: u64,
) -> Result<bool, ApiError> {
    let row: Option<RevokedRow> = db
        .prepare(
            "INSERT INTO devices (id, platform, key_id, public_key, environment, created_at, last_seen_at) \
             VALUES (?1, 'ios', ?2, ?3, ?4, ?5, ?5) \
             ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at \
             RETURNING revoked",
        )
        .bind_refs(&[
            D1Type::Text(id),
            D1Type::Text(key_id_b64),
            D1Type::Blob(public_key),
            D1Type::Text(environment),
            timestamp(now_secs),
        ])?
        .first(None)
        .await?;
    forget(id);
    revoked_flag(row)
}

/// Registers (or refreshes) an Android install. Returns whether the device is revoked.
pub async fn register_android(db: &D1Database, id: &str, now_secs: u64) -> Result<bool, ApiError> {
    let row: Option<RevokedRow> = db
        .prepare(
            "INSERT INTO devices (id, platform, environment, created_at, last_seen_at) \
             VALUES (?1, 'android', 'production', ?2, ?2) \
             ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at \
             RETURNING revoked",
        )
        .bind_refs(&[D1Type::Text(id), timestamp(now_secs)])?
        .first(None)
        .await?;
    forget(id);
    revoked_flag(row)
}

fn revoked_flag(row: Option<RevokedRow>) -> Result<bool, ApiError> {
    row.map(|r| r.revoked != 0.0)
        .ok_or_else(|| ApiError::Internal("device upsert returned no row".into()))
}

pub async fn touch(db: &D1Database, id: &str, now_secs: u64) -> Result<(), ApiError> {
    db.prepare("UPDATE devices SET last_seen_at = ?2 WHERE id = ?1")
        .bind_refs(&[D1Type::Text(id), timestamp(now_secs)])?
        .run()
        .await?;
    Ok(())
}

/// Reads a device straight from D1.
pub async fn find(db: &D1Database, id: &str) -> Result<Option<Device>, ApiError> {
    let row: Option<DeviceRow> = db
        .prepare(
            "SELECT id, platform, lower(hex(public_key)) AS public_key_hex, environment, revoked \
             FROM devices WHERE id = ?1",
        )
        .bind_refs(&[D1Type::Text(id)])?
        .first(None)
        .await?;
    row.map(|row| {
        let public_key = match row.public_key_hex.as_deref() {
            None | Some("") => None,
            Some(hex) => Some(
                hex::decode(hex)
                    .map_err(|e| ApiError::Internal(format!("stored public key: {e}")))?,
            ),
        };
        Ok(Device {
            id: row.id,
            platform: row.platform,
            public_key,
            environment: row.environment,
            revoked: row.revoked != 0.0,
        })
    })
    .transpose()
}

thread_local! {
    static CACHE: RefCell<HashMap<String, (u64, Device)>> = RefCell::new(HashMap::new());
}

/// Like [`find`], but reuses a found device for up to 60 s within this isolate. Used on the
/// hot path (every proxied request), so revocation takes effect within a minute. Unknown
/// devices are not cached, so a device that (re-)registers is recognized immediately.
pub async fn find_cached(env: &Env, id: &str) -> Result<Option<Device>, ApiError> {
    let now = now_ms();
    let cached = CACHE.with(|cache| {
        cache
            .borrow()
            .get(id)
            .filter(|(expires_at, _)| *expires_at > now)
            .map(|(_, device)| device.clone())
    });
    if let Some(device) = cached {
        return Ok(Some(device));
    }
    let device = find(&database(env)?, id).await?;
    if let Some(device) = &device {
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.len() >= CACHE_MAX_ENTRIES {
                cache.clear();
            }
            cache.insert(id.to_owned(), (now + CACHE_TTL_MS, device.clone()));
        });
    }
    Ok(device)
}

/// Drops a cached entry after this isolate changed the row.
fn forget(id: &str) {
    CACHE.with(|cache| {
        cache.borrow_mut().remove(id);
    });
}

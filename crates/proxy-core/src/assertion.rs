//! Per-request App Attest assertions for providers with `require_assertion = true`.
//!
//! The iOS client signs `clientData` = `METHOD\nPATH\nb64url(SHA256(body))\nunix_seconds`
//! and sends the assertion in `X-Attestra-Assertion` and the timestamp in
//! `X-Attestra-Timestamp`. `PATH` is the request path including the query string, exactly as
//! sent (percent-encoded), e.g. `/p/gmaps/maps/api/place/details/json?place_id=abc`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::ProxyError;

pub const ASSERTION_HEADER: &str = "x-attestra-assertion";
pub const TIMESTAMP_HEADER: &str = "x-attestra-timestamp";
/// Assertions older than this are rejected.
pub const MAX_ASSERTION_AGE_SECS: u64 = 60;
/// Tolerated clock skew for timestamps slightly in the future.
pub const MAX_ASSERTION_SKEW_SECS: u64 = 60;

/// Builds the bytes the client hashed into the assertion's `clientDataHash`.
pub fn client_data(method: &str, path_and_query: &str, body: &[u8], timestamp: u64) -> Vec<u8> {
    format!(
        "{method}\n{path_and_query}\n{}\n{timestamp}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(body))
    )
    .into_bytes()
}

/// Parses `X-Attestra-Timestamp` and checks it is fresh.
pub fn check_timestamp(header: &str, now_secs: u64) -> Result<u64, ProxyError> {
    let header = header.trim();
    if header.is_empty() || !header.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProxyError::Assertion("malformed timestamp"));
    }
    let timestamp: u64 = header
        .parse()
        .map_err(|_| ProxyError::Assertion("malformed timestamp"))?;
    if timestamp.saturating_add(MAX_ASSERTION_AGE_SECS) < now_secs {
        return Err(ProxyError::Assertion("timestamp too old"));
    }
    if timestamp > now_secs.saturating_add(MAX_ASSERTION_SKEW_SECS) {
        return Err(ProxyError::Assertion("timestamp in the future"));
    }
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data_layout() {
        let data = client_data(
            "POST",
            "/p/openai/v1/chat/completions?x=1",
            b"{}",
            1_750_000_000,
        );
        assert_eq!(
            String::from_utf8(data).unwrap(),
            format!(
                "POST\n/p/openai/v1/chat/completions?x=1\n{}\n1750000000",
                URL_SAFE_NO_PAD.encode(Sha256::digest(b"{}"))
            )
        );
        // Empty body: hash of the empty string.
        let data = client_data("GET", "/p/x/", b"", 1);
        assert!(
            String::from_utf8(data)
                .unwrap()
                .contains("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU")
        );
    }

    #[test]
    fn timestamp_window() {
        let now = 1_750_000_000;
        assert_eq!(check_timestamp("1750000000", now), Ok(now));
        assert_eq!(check_timestamp(" 1749999940 ", now), Ok(now - 60));
        assert_eq!(check_timestamp("1750000060", now), Ok(now + 60));
        assert_eq!(
            check_timestamp("1749999939", now),
            Err(ProxyError::Assertion("timestamp too old"))
        );
        assert_eq!(
            check_timestamp("1750000061", now),
            Err(ProxyError::Assertion("timestamp in the future"))
        );
        for bad in ["", "-1", "1e9", "0x10", "99999999999999999999999"] {
            assert!(check_timestamp(bad, now).is_err(), "{bad}");
        }
    }
}

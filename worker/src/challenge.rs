//! Attestation challenges: 32 random bytes, transported as unpadded base64url.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::ApiError;

pub const CHALLENGE_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge([u8; CHALLENGE_LEN]);

impl Challenge {
    pub fn random() -> Result<Self, ApiError> {
        let mut bytes = [0u8; CHALLENGE_LEN];
        getrandom::fill(&mut bytes).map_err(|e| ApiError::Internal(format!("getrandom: {e}")))?;
        Ok(Self(bytes))
    }

    /// Parses the client-supplied encoding. Only canonical unpadded base64url of exactly 32
    /// bytes is accepted.
    pub fn parse(encoded: &str) -> Result<Self, ApiError> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| <[u8; CHALLENGE_LEN]>::try_from(bytes.as_slice()).ok())
            .map(Self)
            .ok_or_else(|| ApiError::ChallengeInvalid("malformed challenge".into()))
    }

    pub fn as_bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.0
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_challenges_round_trip() {
        let a = Challenge::random().unwrap();
        let b = Challenge::random().unwrap();
        assert_ne!(a, b);
        let encoded = a.encode();
        assert_eq!(encoded.len(), 43);
        assert_eq!(Challenge::parse(&encoded).unwrap(), a);
    }

    #[test]
    fn rejects_malformed_challenges() {
        let valid = Challenge([0xff; CHALLENGE_LEN]).encode(); // all `_` in base64url
        for bad in [
            String::new(),
            "not base64!".to_owned(),
            format!("{valid}="),                       // padding
            valid.replace('_', "/").replace('-', "+"), // standard alphabet
            URL_SAFE_NO_PAD.encode([0u8; 31]),
            URL_SAFE_NO_PAD.encode([0u8; 33]),
        ] {
            let err = Challenge::parse(&bad).unwrap_err();
            assert_eq!(err.code(), "challenge_invalid", "{bad}");
        }
    }
}

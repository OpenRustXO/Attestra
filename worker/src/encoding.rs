//! Lenient base64 decoding for client-supplied blobs.
//!
//! iOS produces standard base64 (`Data.base64EncodedString()`), other clients often use
//! base64url; both alphabets are accepted, with or without padding.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD_INDIFFERENT, URL_SAFE_NO_PAD_INDIFFERENT};

use crate::error::ApiError;

pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    STANDARD_NO_PAD_INDIFFERENT
        .decode(input)
        .or_else(|_| URL_SAFE_NO_PAD_INDIFFERENT.decode(input))
        .ok()
}

/// Decodes a required base64 field, mapping failure to `bad_request`.
pub fn decode_field(input: &str, field: &'static str) -> Result<Vec<u8>, ApiError> {
    decode_base64(input).ok_or_else(|| ApiError::BadRequest(format!("{field} is not base64")))
}

/// Decodes an App Attest key id, which is always 32 bytes.
pub fn decode_key_id(input: &str) -> Result<[u8; 32], ApiError> {
    decode_field(input, "key_id")?
        .try_into()
        .map_err(|_| ApiError::BadRequest("key_id must be 32 bytes".into()))
}

/// Whether `input` is a canonical, lowercase, hyphenated UUID (what
/// `java.util.UUID.toString()` produces).
pub fn is_canonical_uuid(input: &str) -> bool {
    input.len() == 36
        && input.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    #[test]
    fn accepts_both_alphabets_and_padding() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        for encoded in [STANDARD.encode(&bytes), URL_SAFE_NO_PAD.encode(&bytes)] {
            assert_eq!(decode_base64(&encoded), Some(bytes.clone()), "{encoded}");
        }
        assert_eq!(decode_base64(" YQ== "), Some(b"a".to_vec()));
        assert_eq!(decode_base64("YQ"), Some(b"a".to_vec()));
        assert_eq!(decode_base64("not base64!"), None);
    }

    #[test]
    fn canonical_uuids() {
        assert!(is_canonical_uuid("6f46aaeb-3989-45db-8c24-6cc88a76e789"));
        for bad in [
            "",
            "6F46AAEB-3989-45DB-8C24-6CC88A76E789",
            "6f46aaeb398945db8c246cc88a76e789",
            "6f46aaeb-3989-45db-8c24-6cc88a76e78",
            "6f46aaeb-3989-45db-8c24-6cc88a76e7899",
            "6f46aaeb_3989_45db_8c24_6cc88a76e789",
            "{6f46aaeb-3989-45db-8c24-6cc88a76e78}",
            "gf46aaeb-3989-45db-8c24-6cc88a76e789",
        ] {
            assert!(!is_canonical_uuid(bad), "{bad}");
        }
    }

    #[test]
    fn key_ids_are_32_bytes() {
        let id = [9u8; 32];
        assert_eq!(decode_key_id(&STANDARD.encode(id)).unwrap(), id);
        assert_eq!(
            decode_key_id(&STANDARD.encode([9u8; 31]))
                .unwrap_err()
                .code(),
            "bad_request"
        );
        assert_eq!(decode_key_id("%%%").unwrap_err().code(), "bad_request");
    }
}

//! WebAuthn-style authenticator data as produced by App Attest.
//!
//! ```text
//! rpIdHash (32) | flags (1) | signCount (4, BE) | [aaguid (16) | credIdLen (2, BE) | credId | COSE key]
//! ```
//!
//! Real devices set the attested-credential-data flag (0x40) on assertions too, even though
//! assertions stop after the counter, so the optional part is parsed only when present.

use crate::AppleError;

const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

pub(crate) struct AuthenticatorData<'a> {
    pub rp_id_hash: [u8; 32],
    pub counter: u32,
    pub attested: Option<AttestedCredential<'a>>,
}

pub(crate) struct AttestedCredential<'a> {
    pub aaguid: [u8; 16],
    pub credential_id: &'a [u8],
}

pub(crate) fn parse(bytes: &[u8]) -> Result<AuthenticatorData<'_>, AppleError> {
    const MALFORMED: AppleError = AppleError::Malformed("authenticator data");

    let (rp_id_hash, rest) = bytes.split_first_chunk::<32>().ok_or(MALFORMED)?;
    let (&flags, rest) = rest.split_first().ok_or(MALFORMED)?;
    let (counter, rest) = rest.split_first_chunk::<4>().ok_or(MALFORMED)?;

    let attested = if flags & FLAG_ATTESTED_CREDENTIAL_DATA != 0 && !rest.is_empty() {
        let (aaguid, rest) = rest.split_first_chunk::<16>().ok_or(MALFORMED)?;
        let (id_len, rest) = rest.split_first_chunk::<2>().ok_or(MALFORMED)?;
        let (credential_id, public_key) = rest
            .split_at_checked(usize::from(u16::from_be_bytes(*id_len)))
            .ok_or(MALFORMED)?;
        if credential_id.is_empty() || public_key.is_empty() {
            return Err(MALFORMED);
        }
        Some(AttestedCredential {
            aaguid: *aaguid,
            credential_id,
        })
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash: *rp_id_hash,
        counter: u32::from_be_bytes(*counter),
        attested,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assertion_shape() {
        let mut bytes = vec![3u8; 32];
        bytes.push(0x00);
        bytes.extend(7u32.to_be_bytes());
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.rp_id_hash, [3u8; 32]);
        assert_eq!(parsed.counter, 7);
        assert!(parsed.attested.is_none());
    }

    #[test]
    fn parses_real_device_assertion_flags() {
        // Assertions from real devices carry flags = 0x40 but no credential data.
        let mut bytes = vec![3u8; 32];
        bytes.push(FLAG_ATTESTED_CREDENTIAL_DATA);
        bytes.extend(1u32.to_be_bytes());
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.counter, 1);
        assert!(parsed.attested.is_none());
    }

    #[test]
    fn parses_attested_credential() {
        let mut bytes = vec![3u8; 32];
        bytes.push(FLAG_ATTESTED_CREDENTIAL_DATA);
        bytes.extend(0u32.to_be_bytes());
        bytes.extend(*b"appattestdevelop");
        bytes.extend(4u16.to_be_bytes());
        bytes.extend([1, 2, 3, 4]);
        bytes.extend([0xa0]); // empty COSE map
        let parsed = parse(&bytes).unwrap();
        let cred = parsed.attested.unwrap();
        assert_eq!(&cred.aaguid, b"appattestdevelop");
        assert_eq!(cred.credential_id, &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_truncated_data() {
        let mut bytes = vec![3u8; 32];
        bytes.push(FLAG_ATTESTED_CREDENTIAL_DATA);
        bytes.extend(0u32.to_be_bytes());
        for len in [0, 31, 36] {
            assert!(parse(&bytes[..len.min(bytes.len())]).is_err(), "{len}");
        }
        // Partial credential data.
        bytes.extend([0u8; 10]);
        assert!(parse(&bytes).is_err());
        // Credential id longer than the remaining bytes.
        bytes.extend([0u8; 16]);
        bytes.extend(64u16.to_be_bytes());
        bytes.extend([1, 2, 3]);
        assert!(parse(&bytes).is_err());
    }
}

//! Attestation object verification, following Apple's "Validating Apps That Connect to Your
//! Server" steps.

use ciborium::Value;
use spki::ObjectIdentifier;

use crate::{AppAttest, AppleError, Environment, authdata, cbor, cert, ct_eq, der_lite, sha256};

const APPLE_NONCE_EXTENSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.2");
const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";

/// The result of a successful attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// The credential public key as an uncompressed SEC1 point (65 bytes).
    pub public_key: Vec<u8>,
    pub environment: Environment,
    /// Apple's App Attest receipt, usable later for fraud-risk metrics.
    pub receipt: Vec<u8>,
}

pub(crate) fn verify(
    verifier: &AppAttest,
    attestation: &[u8],
    key_id: &[u8],
    client_data: &[u8],
    now_unix: u64,
) -> Result<VerifiedAttestation, AppleError> {
    // 1. Decode `{ fmt, attStmt: { x5c, receipt }, authData }`.
    let object = cbor::decode_map(attestation)?;
    if cbor::get(&object, "fmt").and_then(Value::as_text) != Some("apple-appattest") {
        return Err(AppleError::UnsupportedFormat);
    }
    let statement = cbor::get(&object, "attStmt")
        .and_then(Value::as_map)
        .ok_or(AppleError::Malformed("attStmt"))?;
    let auth_data = cbor::get_bytes(&object, "authData", "authData")?;
    let receipt = cbor::get_bytes(statement, "receipt", "receipt")?;
    let x5c: Vec<&[u8]> = cbor::get(statement, "x5c")
        .and_then(Value::as_array)
        .ok_or(AppleError::Malformed("x5c"))?
        .iter()
        .map(|c| c.as_bytes().map(Vec::as_slice))
        .collect::<Option<_>>()
        .ok_or(AppleError::Malformed("x5c"))?;
    let [leaf_der, intermediate_der] = x5c.as_slice() else {
        return Err(AppleError::Chain("expected exactly two certificates"));
    };

    // 2. Verify leaf -> intermediate -> Apple root, including validity periods.
    let leaf = cert::parse(leaf_der)?;
    let intermediate = cert::parse(intermediate_der)?;
    let anchor = &verifier.anchor;
    anchor.check_validity(now_unix)?;
    intermediate.check_validity(now_unix)?;
    leaf.check_validity(now_unix)?;
    intermediate.verify_issued_by(anchor.subject(), anchor.key())?;
    if !intermediate.is_ca() {
        return Err(AppleError::Chain("intermediate is not a CA"));
    }
    leaf.verify_issued_by(intermediate.subject(), &intermediate.public_key()?)?;

    // 3. nonce = SHA256(authData || SHA256(clientData)) must equal the leaf's nonce extension.
    let client_data_hash = sha256(&[client_data]);
    let nonce = sha256(&[auth_data, &client_data_hash]);
    let certified_nonce = leaf
        .extension_value(APPLE_NONCE_EXTENSION)
        .and_then(der_lite::apple_nonce)
        .ok_or(AppleError::Malformed("nonce extension"))?;
    if !ct_eq(certified_nonce, &nonce) {
        return Err(AppleError::NonceMismatch);
    }

    // 4. The key id is SHA256 of the credential public key.
    let public_key = leaf.p256_point()?;
    if !ct_eq(&sha256(&[public_key]), key_id) {
        return Err(AppleError::KeyIdMismatch);
    }

    // 5. Authenticator data: App ID, zero counter, AAGUID and credential id.
    let auth = authdata::parse(auth_data)?;
    if !verifier.matches_app_id(&auth.rp_id_hash) {
        return Err(AppleError::RpIdMismatch);
    }
    if auth.counter != 0 {
        return Err(AppleError::NonZeroCounter);
    }
    let credential = auth
        .attested
        .ok_or(AppleError::Malformed("attested credential data"))?;
    let environment = if &credential.aaguid == AAGUID_PRODUCTION {
        Environment::Production
    } else if &credential.aaguid == AAGUID_DEVELOPMENT && verifier.allow_development {
        Environment::Development
    } else {
        return Err(AppleError::Aaguid);
    };
    if !ct_eq(credential.credential_id, key_id) {
        return Err(AppleError::CredentialIdMismatch);
    }

    Ok(VerifiedAttestation {
        public_key: public_key.to_vec(),
        environment,
        receipt: receipt.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{APP_ID, AttestationSpec, LeafIssuer, NOW, Pki};

    fn verifier(pki: &Pki, allow_development: bool) -> AppAttest {
        AppAttest::with_trust_anchor([APP_ID], allow_development, &pki.root_der).unwrap()
    }

    fn verify_spec(spec: &AttestationSpec) -> Result<VerifiedAttestation, AppleError> {
        let pki = Pki::new();
        let built = pki.attestation(spec);
        verifier(&pki, true).verify_attestation(
            &built.attestation,
            &built.key_id,
            &built.client_data,
            NOW,
        )
    }

    #[test]
    fn accepts_valid_attestation() {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec::default());
        let verified = verifier(&pki, false)
            .verify_attestation(&built.attestation, &built.key_id, &built.client_data, NOW)
            .unwrap();
        assert_eq!(verified.environment, Environment::Production);
        assert_eq!(verified.public_key, built.public_key);
        assert_eq!(verified.receipt, b"receipt");
    }

    #[test]
    fn development_aaguid_requires_opt_in() {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec {
            aaguid: *AAGUID_DEVELOPMENT,
            ..AttestationSpec::default()
        });
        let args = (
            &built.attestation[..],
            &built.key_id[..],
            &built.client_data[..],
            NOW,
        );
        assert_eq!(
            verifier(&pki, false).verify_attestation(args.0, args.1, args.2, args.3),
            Err(AppleError::Aaguid)
        );
        let verified = verifier(&pki, true)
            .verify_attestation(args.0, args.1, args.2, args.3)
            .unwrap();
        assert_eq!(verified.environment, Environment::Development);
    }

    #[test]
    fn rejects_wrong_aaguid() {
        let spec = AttestationSpec {
            aaguid: *b"notappattest\0\0\0\0",
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::Aaguid));
    }

    #[test]
    fn rejects_wrong_nonce() {
        let spec = AttestationSpec {
            nonce_override: Some([0x42; 32]),
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::NonceMismatch));
    }

    #[test]
    fn rejects_different_challenge() {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec::default());
        assert_eq!(
            verifier(&pki, true).verify_attestation(
                &built.attestation,
                &built.key_id,
                b"other challenge",
                NOW
            ),
            Err(AppleError::NonceMismatch)
        );
    }

    #[test]
    fn rejects_missing_nonce_extension() {
        let spec = AttestationSpec {
            include_nonce_extension: false,
            ..AttestationSpec::default()
        };
        assert_eq!(
            verify_spec(&spec),
            Err(AppleError::Malformed("nonce extension"))
        );
    }

    #[test]
    fn rejects_wrong_key_id() {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec::default());
        let mut key_id = built.key_id;
        key_id[0] ^= 1;
        assert_eq!(
            verifier(&pki, true).verify_attestation(
                &built.attestation,
                &key_id,
                &built.client_data,
                NOW
            ),
            Err(AppleError::KeyIdMismatch)
        );
    }

    #[test]
    fn rejects_wrong_rp_id() {
        let spec = AttestationSpec {
            app_id: "ABCDE12345.com.example.other".into(),
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::RpIdMismatch));
        let spec = AttestationSpec {
            app_id: "ZZZZZ99999.com.example.app".into(),
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::RpIdMismatch));
    }

    #[test]
    fn rejects_non_zero_counter() {
        let spec = AttestationSpec {
            counter: 1,
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::NonZeroCounter));
    }

    #[test]
    fn rejects_credential_id_mismatch() {
        let spec = AttestationSpec {
            credential_id_override: Some(vec![7; 32]),
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::CredentialIdMismatch));
    }

    #[test]
    fn rejects_leaf_signed_by_untrusted_key() {
        let spec = AttestationSpec {
            leaf_issuer: LeafIssuer::Stranger,
            ..AttestationSpec::default()
        };
        assert_eq!(
            verify_spec(&spec),
            Err(AppleError::Chain("bad certificate signature"))
        );
    }

    #[test]
    fn rejects_leaf_signed_directly_by_root() {
        // Correct issuer name, but signed with the root key instead of the intermediate's.
        let spec = AttestationSpec {
            leaf_issuer: LeafIssuer::RootKey,
            ..AttestationSpec::default()
        };
        assert_eq!(
            verify_spec(&spec),
            Err(AppleError::Chain("bad certificate signature"))
        );
    }

    #[test]
    fn rejects_chain_from_another_root() {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec::default());
        let other = Pki::with_seed(0x77);
        let verifier = AppAttest::with_trust_anchor([APP_ID], true, &other.root_der).unwrap();
        assert!(matches!(
            verifier.verify_attestation(&built.attestation, &built.key_id, &built.client_data, NOW),
            Err(AppleError::Chain(_))
        ));
    }

    #[test]
    fn rejects_intermediate_without_ca_flag() {
        let spec = AttestationSpec {
            intermediate_is_ca: false,
            ..AttestationSpec::default()
        };
        assert_eq!(
            verify_spec(&spec),
            Err(AppleError::Chain("intermediate is not a CA"))
        );
    }

    #[test]
    fn rejects_expired_or_future_certificates() {
        let spec = AttestationSpec {
            leaf_validity: (NOW - 10 * 86_400, NOW - 86_400),
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::CertificateValidity));
        let spec = AttestationSpec {
            leaf_validity: (NOW + 60, NOW + 86_400),
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::CertificateValidity));
    }

    #[test]
    fn rejects_wrong_format_and_shape() {
        let spec = AttestationSpec {
            fmt: "packed",
            ..AttestationSpec::default()
        };
        assert_eq!(verify_spec(&spec), Err(AppleError::UnsupportedFormat));
        let spec = AttestationSpec {
            chain_len: 1,
            ..AttestationSpec::default()
        };
        assert_eq!(
            verify_spec(&spec),
            Err(AppleError::Chain("expected exactly two certificates"))
        );
        let spec = AttestationSpec {
            chain_len: 3,
            ..AttestationSpec::default()
        };
        assert_eq!(
            verify_spec(&spec),
            Err(AppleError::Chain("expected exactly two certificates"))
        );

        let pki = Pki::new();
        let v = verifier(&pki, true);
        for garbage in [&b""[..], b"\xa0", b"\x80", b"not cbor at all"] {
            assert!(v.verify_attestation(garbage, &[0; 32], b"c", NOW).is_err());
        }
    }

    #[test]
    fn rejects_tampered_bytes() {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec::default());
        let v = verifier(&pki, true);
        // Flipping any single byte must never produce a successful verification.
        for i in (0..built.attestation.len()).step_by(7) {
            let mut tampered = built.attestation.clone();
            tampered[i] ^= 0x01;
            let result = v.verify_attestation(&tampered, &built.key_id, &built.client_data, NOW);
            if let Ok(verified) = result {
                // Only the opaque receipt may change without being detected.
                assert_eq!(verified.public_key, built.public_key, "byte {i}");
                assert_ne!(verified.receipt, b"receipt", "byte {i}");
            }
        }
    }
}

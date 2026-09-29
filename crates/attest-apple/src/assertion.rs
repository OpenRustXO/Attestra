//! Assertion verification.
//!
//! The Secure Enclave signs `nonce = SHA256(authenticatorData || clientDataHash)` as the
//! *message* of an ECDSA-P256-SHA256 signature, so the ECDSA digest is `SHA256(nonce)`. The
//! signature is therefore verified with the regular (hashing) verifier over `nonce`, not with a
//! prehash verifier. This matches every real-device assertion we have tested against.

use p256::ecdsa::signature::Verifier as _;

use crate::{AppAttest, AppleError, authdata, cbor, sha256};

/// The result of a successful assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The signed counter. The caller must require it to be greater than the stored counter.
    pub counter: u32,
}

pub(crate) fn verify(
    verifier: &AppAttest,
    assertion: &[u8],
    client_data: &[u8],
    public_key: &[u8],
) -> Result<VerifiedAssertion, AppleError> {
    let object = cbor::decode_map(assertion)?;
    let signature = cbor::get_bytes(&object, "signature", "signature")?;
    let auth_data = cbor::get_bytes(&object, "authenticatorData", "authenticatorData")?;

    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| AppleError::Malformed("stored public key"))?;
    let signature = p256::ecdsa::Signature::from_der(signature)
        .map_err(|_| AppleError::Signature)?
        .normalize_s();
    let client_data_hash = sha256(&[client_data]);
    let nonce = sha256(&[auth_data, &client_data_hash]);
    key.verify(&nonce, &signature)
        .map_err(|_| AppleError::Signature)?;

    let auth = authdata::parse(auth_data)?;
    if !verifier.matches_app_id(&auth.rp_id_hash) {
        return Err(AppleError::RpIdMismatch);
    }
    Ok(VerifiedAssertion {
        counter: auth.counter,
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    use super::*;
    use crate::ensure_counter_advanced;
    use crate::testutil::{APP_ID, AttestationSpec, NOW, Pki, assertion, auth_data};

    fn setup() -> (AppAttest, crate::testutil::Built) {
        let pki = Pki::new();
        let built = pki.attestation(&AttestationSpec::default());
        let verifier = AppAttest::with_trust_anchor([APP_ID], false, &pki.root_der).unwrap();
        verifier
            .verify_attestation(&built.attestation, &built.key_id, &built.client_data, NOW)
            .unwrap();
        (verifier, built)
    }

    #[test]
    fn accepts_valid_assertion() {
        let (verifier, built) = setup();
        let data = auth_data(APP_ID, 5, None);
        let a = assertion(&built.device_key, &data, b"GET\n/x\n...");
        let verified = verifier
            .verify_assertion(&a, b"GET\n/x\n...", &built.public_key)
            .unwrap();
        assert_eq!(verified.counter, 5);
        ensure_counter_advanced(4, verified.counter).unwrap();
    }

    #[test]
    fn counter_replay_is_detected() {
        let (verifier, built) = setup();
        let data = auth_data(APP_ID, 3, None);
        let a = assertion(&built.device_key, &data, b"payload");
        let verified = verifier
            .verify_assertion(&a, b"payload", &built.public_key)
            .unwrap();
        // Replaying the same assertion yields the same counter, which the stored counter
        // (updated after the first use) rejects.
        assert_eq!(
            ensure_counter_advanced(verified.counter, verified.counter),
            Err(AppleError::CounterReplay)
        );
        assert_eq!(
            ensure_counter_advanced(10, verified.counter),
            Err(AppleError::CounterReplay)
        );
    }

    #[test]
    fn rejects_other_client_data() {
        let (verifier, built) = setup();
        let a = assertion(&built.device_key, &auth_data(APP_ID, 1, None), b"payload");
        assert_eq!(
            verifier.verify_assertion(&a, b"tampered", &built.public_key),
            Err(AppleError::Signature)
        );
    }

    #[test]
    fn rejects_other_key() {
        let (verifier, built) = setup();
        let stranger = p256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap();
        let a = assertion(&stranger, &auth_data(APP_ID, 1, None), b"payload");
        assert_eq!(
            verifier.verify_assertion(&a, b"payload", &built.public_key),
            Err(AppleError::Signature)
        );
    }

    #[test]
    fn rejects_single_hash_signature() {
        // A signature whose ECDSA digest is the nonce itself (no second SHA-256) is not what
        // the Secure Enclave produces and must not verify.
        let (verifier, built) = setup();
        let data = auth_data(APP_ID, 1, None);
        let nonce = sha256(&[&data, &sha256(&[b"payload"])]);
        let sig: p256::ecdsa::Signature = built.device_key.sign_prehash(&nonce).unwrap();
        let a = crate::testutil::encode_assertion(&sig.to_der().to_bytes(), &data);
        assert_eq!(
            verifier.verify_assertion(&a, b"payload", &built.public_key),
            Err(AppleError::Signature)
        );
    }

    #[test]
    fn rejects_wrong_rp_id() {
        let (verifier, built) = setup();
        let data = auth_data("ABCDE12345.com.example.other", 1, None);
        let a = assertion(&built.device_key, &data, b"payload");
        assert_eq!(
            verifier.verify_assertion(&a, b"payload", &built.public_key),
            Err(AppleError::RpIdMismatch)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        let (verifier, built) = setup();
        assert!(
            verifier
                .verify_assertion(b"", b"p", &built.public_key)
                .is_err()
        );
        let a = crate::testutil::encode_assertion(b"not der", &auth_data(APP_ID, 1, None));
        assert_eq!(
            verifier.verify_assertion(&a, b"p", &built.public_key),
            Err(AppleError::Signature)
        );
        let good = assertion(&built.device_key, &auth_data(APP_ID, 1, None), b"p");
        assert_eq!(
            verifier.verify_assertion(&good, b"p", &[4; 65]),
            Err(AppleError::Malformed("stored public key"))
        );
    }
}

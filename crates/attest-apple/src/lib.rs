//! Apple App Attest verification.
//!
//! Verifies attestation objects (`fmt = "apple-appattest"`) against the embedded Apple App
//! Attestation Root CA and verifies per-request assertions against a previously registered
//! P-256 public key. This crate is runtime-agnostic: it has no dependency on `worker` and is
//! fully testable on the host. Callers pass the current time in, so verification is
//! deterministic.
//!
//! Replay protection for assertions needs durable state: [`AppAttest::verify_assertion`]
//! returns the signed counter and the caller must persist it atomically, accepting it only if
//! [`ensure_counter_advanced`] succeeds against the stored value.
#![forbid(unsafe_code)]

mod assertion;
mod attestation;
mod authdata;
mod cbor;
mod cert;
mod der_lite;
#[cfg(test)]
mod testutil;

use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

pub use assertion::VerifiedAssertion;
pub use attestation::VerifiedAttestation;
use cert::TrustAnchor;

/// Apple App Attestation Root CA (P-384, valid 2020-03-18 to 2045-03-15), as published at
/// <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>.
/// SHA-256 fingerprint `1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32`.
pub const APPLE_APP_ATTESTATION_ROOT_CA_PEM: &str =
    include_str!("../certs/apple_app_attestation_root_ca.pem");

/// The App Attest environment a key was created in, taken from the attestation AAGUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Production,
    Development,
}

impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }
}

/// Why verification failed. The detail is meant for server-side logs only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppleError {
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("unsupported attestation format")]
    UnsupportedFormat,
    #[error("certificate chain invalid: {0}")]
    Chain(&'static str),
    #[error("certificate expired or not yet valid")]
    CertificateValidity,
    #[error("nonce does not match the certificate")]
    NonceMismatch,
    #[error("key id does not match the credential public key")]
    KeyIdMismatch,
    #[error("rpIdHash does not match an allowed App ID")]
    RpIdMismatch,
    #[error("attestation counter is not zero")]
    NonZeroCounter,
    #[error("unexpected AAGUID (environment not allowed)")]
    Aaguid,
    #[error("credential id does not match the key id")]
    CredentialIdMismatch,
    #[error("signature verification failed")]
    Signature,
    #[error("assertion counter did not increase")]
    CounterReplay,
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// A configured App Attest verifier.
#[derive(Debug, Clone)]
pub struct AppAttest {
    app_id_hashes: Vec<[u8; 32]>,
    allow_development: bool,
    anchor: TrustAnchor,
}

impl AppAttest {
    /// Creates a verifier trusting the Apple App Attestation Root CA.
    ///
    /// `app_ids` are `<TEAM_ID>.<bundle_id>` strings; `allow_development` additionally
    /// accepts keys from the `appattestdevelop` environment.
    pub fn new<I, S>(app_ids: I, allow_development: bool) -> Result<Self, AppleError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        static APPLE_ROOT: OnceLock<Result<TrustAnchor, AppleError>> = OnceLock::new();
        let anchor = APPLE_ROOT
            .get_or_init(|| TrustAnchor::from_pem(APPLE_APP_ATTESTATION_ROOT_CA_PEM))
            .clone()?;
        Self::build(app_ids, allow_development, anchor)
    }

    /// Creates a verifier trusting `root_der` instead of the Apple root. Intended for tests.
    pub fn with_trust_anchor<I, S>(
        app_ids: I,
        allow_development: bool,
        root_der: &[u8],
    ) -> Result<Self, AppleError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::build(app_ids, allow_development, TrustAnchor::from_der(root_der)?)
    }

    fn build<I, S>(
        app_ids: I,
        allow_development: bool,
        anchor: TrustAnchor,
    ) -> Result<Self, AppleError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let app_id_hashes: Vec<[u8; 32]> = app_ids
            .into_iter()
            .map(|id| sha256(&[id.as_ref().as_bytes()]))
            .collect();
        if app_id_hashes.is_empty() {
            return Err(AppleError::Config("at least one App ID is required".into()));
        }
        Ok(Self {
            app_id_hashes,
            allow_development,
            anchor,
        })
    }

    /// Verifies an attestation object for `key_id` (raw bytes, i.e. SHA-256 of the public
    /// key). `client_data` is hashed with SHA-256 to form `clientDataHash`; pass the raw
    /// challenge bytes. `now_unix` is used for certificate validity checks.
    pub fn verify_attestation(
        &self,
        attestation: &[u8],
        key_id: &[u8],
        client_data: &[u8],
        now_unix: u64,
    ) -> Result<VerifiedAttestation, AppleError> {
        attestation::verify(self, attestation, key_id, client_data, now_unix)
    }

    /// Verifies an assertion made with the key whose uncompressed SEC1 public key is
    /// `public_key`. `client_data` is hashed with SHA-256 to form `clientDataHash`.
    ///
    /// The returned counter must still be checked against the stored counter with
    /// [`ensure_counter_advanced`] and persisted atomically by the caller.
    pub fn verify_assertion(
        &self,
        assertion: &[u8],
        client_data: &[u8],
        public_key: &[u8],
    ) -> Result<VerifiedAssertion, AppleError> {
        assertion::verify(self, assertion, client_data, public_key)
    }

    /// Constant-time check (across all configured App IDs) that `rp_id_hash` is allowed.
    fn matches_app_id(&self, rp_id_hash: &[u8; 32]) -> bool {
        self.app_id_hashes
            .iter()
            .fold(Choice::from(0), |acc, h| acc | h.ct_eq(rp_id_hash))
            .into()
    }
}

/// Assertion counters must strictly increase; anything else is a replay or a cloned key.
pub fn ensure_counter_advanced(stored: u32, received: u32) -> Result<(), AppleError> {
    if received > stored {
        Ok(())
    } else {
        Err(AppleError::CounterReplay)
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_root_is_embedded_and_self_signed() {
        let anchor = TrustAnchor::from_pem(APPLE_APP_ATTESTATION_ROOT_CA_PEM).unwrap();
        // Valid until 2045-03-15.
        anchor.check_validity(1_750_000_000).unwrap();
        anchor.check_validity(2_373_148_800).unwrap();
        assert_eq!(
            anchor.check_validity(2_373_148_801), // 2045-03-15T00:00:01Z
            Err(AppleError::CertificateValidity)
        );
        AppAttest::new(["ABCDE12345.com.example.app"], false).unwrap();
    }

    #[test]
    fn apple_root_fingerprint() {
        let der = x509_cert::der::pem::decode_vec(APPLE_APP_ATTESTATION_ROOT_CA_PEM.as_bytes())
            .unwrap()
            .1;
        let hex: String = sha256(&[&der]).iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(
            hex,
            "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932"
        );
    }

    #[test]
    fn requires_an_app_id() {
        let empty: [&str; 0] = [];
        assert!(matches!(
            AppAttest::new(empty, false),
            Err(AppleError::Config(_))
        ));
    }

    #[test]
    fn counter_must_strictly_increase() {
        ensure_counter_advanced(0, 1).unwrap();
        ensure_counter_advanced(41, 42).unwrap();
        assert_eq!(
            ensure_counter_advanced(5, 5),
            Err(AppleError::CounterReplay)
        );
        assert_eq!(
            ensure_counter_advanced(5, 4),
            Err(AppleError::CounterReplay)
        );
        assert_eq!(
            ensure_counter_advanced(u32::MAX, 0),
            Err(AppleError::CounterReplay)
        );
    }
}

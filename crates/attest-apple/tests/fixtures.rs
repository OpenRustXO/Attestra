//! Verifies real, device-captured App Attest objects against the Apple root.
//!
//! Every `*.json` file in `tests/fixtures/` is loaded; see `tests/fixtures/README.md` for the
//! format. To add a captured attestation, drop a new file in that directory.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use attest_apple::{AppAttest, AppleError, Environment};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub description: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    /// `<TEAM_ID>.<bundle_id>`
    pub app_id: String,
    /// `production` or `development`
    pub environment: String,
    /// Unix time inside the leaf certificate's validity window.
    pub verify_at: u64,
    /// Base64 attestation object.
    pub attestation: String,
    /// Base64 key id (SHA-256 of the public key).
    pub key_id: String,
    /// Base64 of the bytes hashed into `clientDataHash` (the challenge).
    pub client_data: String,
    #[serde(default)]
    pub assertion: Option<AssertionFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionFixture {
    /// Base64 assertion object made with the attested key.
    pub assertion: String,
    /// Base64 of the bytes hashed into the assertion's `clientDataHash`.
    pub client_data: String,
    pub counter: u32,
}

impl Fixture {
    fn bytes(field: &str) -> Vec<u8> {
        STANDARD
            .decode(field)
            .expect("fixture fields are standard base64")
    }

    fn expected_environment(&self) -> Environment {
        match self.environment.as_str() {
            "production" => Environment::Production,
            "development" => Environment::Development,
            other => panic!("{}: unknown environment `{other}`", self.description),
        }
    }

    fn verify(
        &self,
        app_ids: &[&str],
        allow_development: bool,
        now: u64,
    ) -> Result<Vec<u8>, AppleError> {
        let verifier = AppAttest::new(app_ids, allow_development)?;
        let verified = verifier.verify_attestation(
            &Self::bytes(&self.attestation),
            &Self::bytes(&self.key_id),
            &Self::bytes(&self.client_data),
            now,
        )?;
        assert_eq!(
            verified.environment,
            self.expected_environment(),
            "{}",
            self.description
        );
        Ok(verified.public_key)
    }
}

/// Loads every fixture in `dir`, sorted by file name.
pub fn load_fixtures(dir: &Path) -> Vec<(PathBuf, Fixture)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("fixture directory exists")
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("readable fixture");
            let fixture =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (path, fixture)
        })
        .collect()
}

fn fixtures() -> Vec<(PathBuf, Fixture)> {
    load_fixtures(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
}

#[test]
fn real_device_attestations_and_assertions_verify() {
    let fixtures = fixtures();
    assert!(!fixtures.is_empty(), "no fixtures found");
    for (path, fixture) in &fixtures {
        let public_key = fixture
            .verify(&[&fixture.app_id], true, fixture.verify_at)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));

        if let Some(assertion) = &fixture.assertion {
            let verifier = AppAttest::new([&fixture.app_id], true).unwrap();
            let verified = verifier
                .verify_assertion(
                    &Fixture::bytes(&assertion.assertion),
                    &Fixture::bytes(&assertion.client_data),
                    &public_key,
                )
                .unwrap_or_else(|e| panic!("{} (assertion): {e}", path.display()));
            assert_eq!(verified.counter, assertion.counter, "{}", path.display());
        }
    }
}

#[test]
fn real_device_attestations_reject_other_app_ids() {
    for (path, fixture) in fixtures() {
        assert_eq!(
            fixture.verify(&["ABCDE12345.com.example.app"], true, fixture.verify_at),
            Err(AppleError::RpIdMismatch),
            "{}",
            path.display()
        );
    }
}

#[test]
fn real_device_attestations_expire() {
    // Every leaf certificate has long expired, so verifying "now" must fail.
    for (path, fixture) in fixtures() {
        assert_eq!(
            fixture.verify(&[&fixture.app_id], true, 1_900_000_000),
            Err(AppleError::CertificateValidity),
            "{}",
            path.display()
        );
    }
}

#[test]
fn development_keys_need_opt_in() {
    for (path, fixture) in fixtures() {
        let result = fixture.verify(&[&fixture.app_id], false, fixture.verify_at);
        match fixture.expected_environment() {
            Environment::Production => assert!(result.is_ok(), "{}", path.display()),
            Environment::Development => {
                assert_eq!(result, Err(AppleError::Aaguid), "{}", path.display());
            }
        }
    }
}

#[test]
fn real_assertions_reject_tampered_client_data() {
    for (path, fixture) in fixtures() {
        let Some(assertion) = &fixture.assertion else {
            continue;
        };
        let public_key = fixture
            .verify(&[&fixture.app_id], true, fixture.verify_at)
            .unwrap();
        let verifier = AppAttest::new([&fixture.app_id], true).unwrap();
        let mut client_data = Fixture::bytes(&assertion.client_data);
        client_data.push(b'!');
        assert_eq!(
            verifier.verify_assertion(
                &Fixture::bytes(&assertion.assertion),
                &client_data,
                &public_key
            ),
            Err(AppleError::Signature),
            "{}",
            path.display()
        );
    }
}

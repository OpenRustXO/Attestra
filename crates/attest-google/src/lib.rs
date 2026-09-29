//! Google Play Integrity verification (Standard API).
//!
//! Flow: obtain an OAuth access token with a service-account JWT ([`GoogleAuth`]), decode the
//! integrity token with `decodeIntegrityToken`, then check the verdict against the expected
//! request hash, package, signing certificate and device integrity ([`verify`]). Outbound HTTP
//! goes through [`HttpClient`], so the crate has no dependency on `worker` and is fully
//! testable on the host.
//!
//! The app computes `requestHash = base64url(SHA256(challenge || install_id))` (unpadded) and
//! passes it to `StandardIntegrityTokenRequest`; [`request_hash`] recomputes it here.
#![forbid(unsafe_code)]

mod auth;
mod http;

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD_NO_PAD_INDIFFERENT, URL_SAFE_NO_PAD, URL_SAFE_NO_PAD_INDIFFERENT,
};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

pub use auth::{GoogleAuth, SCOPE, TOKEN_URL};
pub use http::{HttpClient, HttpError, HttpRequest, HttpResponse};

/// Integrity tokens older than this are rejected.
pub const MAX_TOKEN_AGE_MS: u64 = 120_000;
/// Tolerated clock skew for tokens stamped slightly in the future.
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const DECODE_URL: &str = "https://playintegrity.googleapis.com/v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GoogleError {
    /// Misconfiguration on our side (service account, package list, ...).
    #[error("configuration: {0}")]
    Config(String),
    /// Google could not be reached or answered unexpectedly.
    #[error("upstream: {0}")]
    Upstream(String),
    /// Google rejected the integrity token itself.
    #[error("integrity token rejected by Google")]
    InvalidToken,
    /// The decoded verdict does not meet our requirements.
    #[error("verdict: {0}")]
    Verdict(&'static str),
}

impl From<HttpError> for GoogleError {
    fn from(err: HttpError) -> Self {
        Self::Upstream(err.to_string())
    }
}

/// What a verdict must satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayIntegrityPolicy {
    pub package_names: Vec<String>,
    /// SHA-256 digests of the allowed app signing certificates.
    pub cert_sha256: Vec<[u8; 32]>,
    /// Require `accountDetails.appLicensingVerdict == "LICENSED"`.
    pub require_licensed: bool,
}

/// One attestation attempt from a device.
#[derive(Debug, Clone, Copy)]
pub struct IntegrityRequest<'a> {
    pub package_name: &'a str,
    pub integrity_token: &'a str,
    /// The raw challenge bytes.
    pub challenge: &'a [u8],
    pub install_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIntegrity {
    /// `hex(SHA256(package_name || install_id))`
    pub device_id: String,
    pub package_name: String,
}

/// `base64url(SHA256(challenge || install_id))`, unpadded.
pub fn request_hash(challenge: &[u8], install_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(install_id.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// `hex(SHA256(package_name || install_id))`
pub fn device_id(package_name: &str, install_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(package_name.as_bytes());
    hasher.update(install_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// Decodes the integrity token with Google and checks the verdict.
pub async fn verify<H: HttpClient>(
    http: &H,
    auth: &GoogleAuth,
    policy: &PlayIntegrityPolicy,
    request: &IntegrityRequest<'_>,
    now_ms: u64,
) -> Result<VerifiedIntegrity, GoogleError> {
    if !policy
        .package_names
        .iter()
        .any(|p| p == request.package_name)
    {
        return Err(GoogleError::Verdict("package name not allowed"));
    }
    let payload = decode_integrity_token(
        http,
        auth,
        request.package_name,
        request.integrity_token,
        now_ms / 1000,
    )
    .await?;
    check_verdict(&payload, policy, request, now_ms)?;
    Ok(VerifiedIntegrity {
        device_id: device_id(request.package_name, request.install_id),
        package_name: request.package_name.to_owned(),
    })
}

/// Calls `decodeIntegrityToken`, retrying once with a fresh access token on 401.
pub async fn decode_integrity_token<H: HttpClient>(
    http: &H,
    auth: &GoogleAuth,
    package_name: &str,
    integrity_token: &str,
    now_secs: u64,
) -> Result<TokenPayload, GoogleError> {
    let body = serde_json::to_vec(&serde_json::json!({ "integrity_token": integrity_token }))
        .map_err(|e| GoogleError::Config(format!("encode request: {e}")))?;
    let url = format!("{DECODE_URL}/{package_name}:decodeIntegrityToken");

    for attempt in 0..2 {
        let access_token = auth.access_token(http, now_secs).await?;
        let response = http
            .send(HttpRequest {
                method: "POST",
                url: url.clone(),
                headers: vec![
                    ("authorization".into(), format!("Bearer {access_token}")),
                    ("content-type".into(), "application/json".into()),
                ],
                body: body.clone(),
            })
            .await?;
        match response.status {
            200 => {
                let decoded: DecodeResponse = serde_json::from_slice(&response.body)
                    .map_err(|e| GoogleError::Upstream(format!("decode response: {e}")))?;
                return Ok(decoded.token_payload_external);
            }
            401 if attempt == 0 => auth.invalidate()?,
            400 => return Err(GoogleError::InvalidToken),
            status => {
                return Err(GoogleError::Upstream(format!(
                    "decodeIntegrityToken returned {status}"
                )));
            }
        }
    }
    Err(GoogleError::Upstream(
        "decodeIntegrityToken kept returning 401".into(),
    ))
}

/// Checks a decoded payload against the policy and the expected request.
pub fn check_verdict(
    payload: &TokenPayload,
    policy: &PlayIntegrityPolicy,
    request: &IntegrityRequest<'_>,
    now_ms: u64,
) -> Result<(), GoogleError> {
    let details = payload
        .request_details
        .as_ref()
        .ok_or(GoogleError::Verdict("missing requestDetails"))?;
    if details.request_package_name.as_deref() != Some(request.package_name) {
        return Err(GoogleError::Verdict("requestPackageName mismatch"));
    }
    let expected_hash = request_hash(request.challenge, request.install_id);
    let hash_matches = details
        .request_hash
        .as_deref()
        .is_some_and(|hash| bool::from(hash.as_bytes().ct_eq(expected_hash.as_bytes())));
    if !hash_matches {
        return Err(GoogleError::Verdict("requestHash mismatch"));
    }
    let timestamp = details
        .timestamp_millis
        .ok_or(GoogleError::Verdict("missing timestampMillis"))?;
    if timestamp.saturating_add(MAX_TOKEN_AGE_MS) < now_ms
        || timestamp > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
    {
        return Err(GoogleError::Verdict("token is stale"));
    }

    let app = payload
        .app_integrity
        .as_ref()
        .ok_or(GoogleError::Verdict("missing appIntegrity"))?;
    if app.app_recognition_verdict.as_deref() != Some("PLAY_RECOGNIZED") {
        return Err(GoogleError::Verdict("app not recognized by Play"));
    }
    if app
        .package_name
        .as_deref()
        .is_some_and(|p| p != request.package_name)
    {
        return Err(GoogleError::Verdict("appIntegrity.packageName mismatch"));
    }
    let digests = app.certificate_sha256_digest.as_deref().unwrap_or_default();
    let allowed_cert =
        digests
            .iter()
            .filter_map(|d| decode_digest(d))
            .fold(Choice::from(0), |acc, digest| {
                policy
                    .cert_sha256
                    .iter()
                    .fold(acc, |acc, allowed| acc | allowed.ct_eq(&digest))
            });
    if !bool::from(allowed_cert) {
        return Err(GoogleError::Verdict("signing certificate not allowed"));
    }

    let meets_device_integrity = payload
        .device_integrity
        .as_ref()
        .and_then(|d| d.device_recognition_verdict.as_deref())
        .is_some_and(|verdicts| verdicts.iter().any(|v| v == "MEETS_DEVICE_INTEGRITY"));
    if !meets_device_integrity {
        return Err(GoogleError::Verdict("device integrity not met"));
    }

    if policy.require_licensed {
        let licensed = payload
            .account_details
            .as_ref()
            .and_then(|a| a.app_licensing_verdict.as_deref())
            == Some("LICENSED");
        if !licensed {
            return Err(GoogleError::Verdict("app not licensed"));
        }
    }
    Ok(())
}

fn decode_digest(encoded: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD_INDIFFERENT
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD_INDIFFERENT.decode(encoded))
        .ok()?
        .try_into()
        .ok()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecodeResponse {
    token_payload_external: TokenPayload,
}

/// The decoded verdict (`tokenPayloadExternal`). Only the fields we check are modelled.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPayload {
    pub request_details: Option<RequestDetails>,
    pub app_integrity: Option<AppIntegrity>,
    pub device_integrity: Option<DeviceIntegrity>,
    pub account_details: Option<AccountDetails>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetails {
    pub request_package_name: Option<String>,
    pub request_hash: Option<String>,
    /// int64 fields are strings in proto3 JSON; numbers are accepted too.
    #[serde(default, deserialize_with = "int64")]
    pub timestamp_millis: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppIntegrity {
    pub app_recognition_verdict: Option<String>,
    pub package_name: Option<String>,
    pub certificate_sha256_digest: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIntegrity {
    pub device_recognition_verdict: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDetails {
    pub app_licensing_verdict: Option<String>,
}

fn int64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Int64 {
        Number(u64),
        Text(String),
    }
    match Option::<Int64>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Int64::Number(n)) => Ok(Some(n)),
        Some(Int64::Text(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::signature::Verifier as _;

    use super::*;

    const SERVICE_ACCOUNT: &str = include_str!("../testdata/service_account.json");
    const PACKAGE: &str = "com.example.app";
    const INSTALL_ID: &str = "6f46aaeb-3989-45db-8c24-6cc88a76e789";
    const CHALLENGE: &[u8] = &[7; 32];
    const NOW_MS: u64 = 1_750_000_000_000;
    const CERT: [u8; 32] = [0xab; 32];

    /// Polls a future that never actually waits (the mock client is synchronous).
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    #[derive(Default)]
    struct MockHttp {
        responses: RefCell<VecDeque<Result<HttpResponse, HttpError>>>,
        requests: RefCell<Vec<HttpRequest>>,
    }

    impl MockHttp {
        fn respond(&self, status: u16, body: serde_json::Value) -> &Self {
            self.responses.borrow_mut().push_back(Ok(HttpResponse {
                status,
                body: body.to_string().into_bytes(),
            }));
            self
        }

        fn fail(&self) -> &Self {
            self.responses
                .borrow_mut()
                .push_back(Err(HttpError("connection reset".into())));
            self
        }

        fn urls(&self) -> Vec<String> {
            self.requests
                .borrow()
                .iter()
                .map(|r| r.url.clone())
                .collect()
        }
    }

    impl HttpClient for MockHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            self.requests.borrow_mut().push(request);
            self.responses
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err(HttpError("no mock response queued".into())))
        }
    }

    fn auth() -> GoogleAuth {
        GoogleAuth::from_service_account_json(SERVICE_ACCOUNT).unwrap()
    }

    fn policy() -> PlayIntegrityPolicy {
        PlayIntegrityPolicy {
            package_names: vec![PACKAGE.into()],
            cert_sha256: vec![CERT],
            require_licensed: true,
        }
    }

    fn request() -> IntegrityRequest<'static> {
        IntegrityRequest {
            package_name: PACKAGE,
            integrity_token: "opaque-integrity-token",
            challenge: CHALLENGE,
            install_id: INSTALL_ID,
        }
    }

    fn good_payload() -> serde_json::Value {
        serde_json::json!({
            "requestDetails": {
                "requestPackageName": PACKAGE,
                "requestHash": request_hash(CHALLENGE, INSTALL_ID),
                "timestampMillis": (NOW_MS - 5_000).to_string(),
            },
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": PACKAGE,
                "certificateSha256Digest": [URL_SAFE_NO_PAD.encode(CERT)],
                "versionCode": "42",
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY"],
            },
            "accountDetails": { "appLicensingVerdict": "LICENSED" },
            "environmentDetails": { "playProtectVerdict": "NO_ISSUES" },
        })
    }

    fn token_response() -> serde_json::Value {
        serde_json::json!({ "access_token": "ya29.test", "expires_in": 3599, "token_type": "Bearer" })
    }

    fn payload(value: serde_json::Value) -> TokenPayload {
        serde_json::from_value(value).unwrap()
    }

    fn check(value: serde_json::Value) -> Result<(), GoogleError> {
        check_verdict(&payload(value), &policy(), &request(), NOW_MS)
    }

    fn with(
        mut value: serde_json::Value,
        pointer: &str,
        replacement: serde_json::Value,
    ) -> serde_json::Value {
        *value.pointer_mut(pointer).unwrap() = replacement;
        value
    }

    #[test]
    fn full_flow_succeeds_and_caches_the_access_token() {
        let http = MockHttp::default();
        http.respond(200, token_response())
            .respond(
                200,
                serde_json::json!({ "tokenPayloadExternal": good_payload() }),
            )
            .respond(
                200,
                serde_json::json!({ "tokenPayloadExternal": good_payload() }),
            );
        let auth = auth();

        let verified = block_on(verify(&http, &auth, &policy(), &request(), NOW_MS)).unwrap();
        assert_eq!(verified.device_id, device_id(PACKAGE, INSTALL_ID));
        assert_eq!(verified.device_id.len(), 64);
        // Second verification reuses the cached access token.
        block_on(verify(&http, &auth, &policy(), &request(), NOW_MS + 1_000)).unwrap();
        assert_eq!(
            http.urls(),
            [
                TOKEN_URL.to_owned(),
                format!("{DECODE_URL}/{PACKAGE}:decodeIntegrityToken"),
                format!("{DECODE_URL}/{PACKAGE}:decodeIntegrityToken"),
            ]
        );

        let requests = http.requests.borrow();
        let decode = &requests[1];
        assert_eq!(decode.method, "POST");
        assert!(
            decode
                .headers
                .contains(&("authorization".into(), "Bearer ya29.test".into()))
        );
        let body: serde_json::Value = serde_json::from_slice(&decode.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "integrity_token": "opaque-integrity-token" })
        );
        // Debug output never contains the access token or the integrity token.
        let debug = format!("{decode:?}");
        assert!(
            !debug.contains("ya29") && !debug.contains("opaque-integrity-token"),
            "{debug}"
        );
    }

    #[test]
    fn service_account_jwt_is_well_formed_and_verifiable() {
        let http = MockHttp::default();
        http.respond(200, token_response());
        let auth = auth();
        let now = NOW_MS / 1000;
        block_on(auth.access_token(&http, now)).unwrap();

        let request = http.requests.borrow()[0].clone();
        assert_eq!(request.url, TOKEN_URL);
        assert!(request.headers.contains(&(
            "content-type".into(),
            "application/x-www-form-urlencoded".into()
        )));
        let body = String::from_utf8(request.body).unwrap();
        let jwt = body
            .strip_prefix(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
            )
            .unwrap();

        let (input, signature) = jwt.rsplit_once('.').unwrap();
        let (header, claims) = input.split_once('.').unwrap();
        let json = |part: &str| -> serde_json::Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
        };
        assert_eq!(
            json(header),
            serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "0123456789abcdef0123456789abcdef01234567" })
        );
        assert_eq!(
            json(claims),
            serde_json::json!({
                "iss": "play-integrity@attestra-test.iam.gserviceaccount.com",
                "scope": SCOPE,
                "aud": TOKEN_URL,
                "iat": now,
                "exp": now + 3600,
            })
        );

        let account: serde_json::Value = serde_json::from_str(SERVICE_ACCOUNT).unwrap();
        let key =
            rsa::RsaPrivateKey::from_pkcs8_pem(account["private_key"].as_str().unwrap()).unwrap();
        let verifying = VerifyingKey::<Sha256>::new(key.to_public_key());
        let signature =
            Signature::try_from(URL_SAFE_NO_PAD.decode(signature).unwrap().as_slice()).unwrap();
        verifying.verify(input.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn access_token_is_refreshed_five_minutes_before_expiry() {
        let http = MockHttp::default();
        http.respond(
            200,
            serde_json::json!({ "access_token": "first", "expires_in": 3600 }),
        )
        .respond(
            200,
            serde_json::json!({ "access_token": "second", "expires_in": 3600 }),
        );
        let auth = auth();
        let t0 = 1_000_000;
        assert_eq!(block_on(auth.access_token(&http, t0)).unwrap(), "first");
        assert_eq!(
            block_on(auth.access_token(&http, t0 + 3299)).unwrap(),
            "first"
        );
        assert_eq!(
            block_on(auth.access_token(&http, t0 + 3300)).unwrap(),
            "second"
        );
        assert_eq!(http.requests.borrow().len(), 2);
    }

    #[test]
    fn retries_once_after_401() {
        let http = MockHttp::default();
        http.respond(
            200,
            serde_json::json!({ "access_token": "stale", "expires_in": 3600 }),
        )
        .respond(401, serde_json::json!({}))
        .respond(
            200,
            serde_json::json!({ "access_token": "fresh", "expires_in": 3600 }),
        )
        .respond(
            200,
            serde_json::json!({ "tokenPayloadExternal": good_payload() }),
        );
        block_on(verify(&http, &auth(), &policy(), &request(), NOW_MS)).unwrap();
        let requests = http.requests.borrow();
        assert_eq!(requests.len(), 4);
        assert!(
            requests[3]
                .headers
                .contains(&("authorization".into(), "Bearer fresh".into()))
        );
    }

    #[test]
    fn maps_upstream_failures() {
        let run = |http: &MockHttp| block_on(verify(http, &auth(), &policy(), &request(), NOW_MS));

        let http = MockHttp::default();
        http.fail();
        assert!(matches!(run(&http), Err(GoogleError::Upstream(_))));

        let http = MockHttp::default();
        http.respond(500, serde_json::json!({}));
        assert!(matches!(run(&http), Err(GoogleError::Upstream(_))));

        let http = MockHttp::default();
        http.respond(200, token_response())
            .respond(400, serde_json::json!({ "error": {} }));
        assert_eq!(run(&http), Err(GoogleError::InvalidToken));

        let http = MockHttp::default();
        http.respond(200, token_response())
            .respond(503, serde_json::json!({}));
        assert!(matches!(run(&http), Err(GoogleError::Upstream(_))));

        let http = MockHttp::default();
        http.respond(200, token_response())
            .respond(401, serde_json::json!({}))
            .respond(200, token_response())
            .respond(401, serde_json::json!({}));
        assert!(matches!(run(&http), Err(GoogleError::Upstream(_))));

        let http = MockHttp::default();
        http.respond(200, token_response())
            .respond(200, serde_json::json!({ "unexpected": true }));
        assert!(matches!(run(&http), Err(GoogleError::Upstream(_))));
    }

    #[test]
    fn rejects_unlisted_package_before_calling_google() {
        let http = MockHttp::default();
        let request = IntegrityRequest {
            package_name: "com.evil.app",
            ..request()
        };
        assert_eq!(
            block_on(verify(&http, &auth(), &policy(), &request, NOW_MS)),
            Err(GoogleError::Verdict("package name not allowed"))
        );
        assert!(http.requests.borrow().is_empty());
    }

    #[test]
    fn accepts_good_verdict_and_both_timestamp_encodings() {
        check(good_payload()).unwrap();
        check(with(
            good_payload(),
            "/requestDetails/timestampMillis",
            serde_json::json!(NOW_MS - 1),
        ))
        .unwrap();
    }

    #[test]
    fn rejects_each_failed_check() {
        let cases = [
            (
                "/requestDetails/requestPackageName",
                serde_json::json!("com.other.app"),
                "requestPackageName mismatch",
            ),
            (
                "/requestDetails/requestHash",
                serde_json::json!(request_hash(CHALLENGE, "other-install")),
                "requestHash mismatch",
            ),
            (
                "/requestDetails/requestHash",
                serde_json::json!(null),
                "requestHash mismatch",
            ),
            (
                "/requestDetails/timestampMillis",
                serde_json::json!((NOW_MS - MAX_TOKEN_AGE_MS - 1).to_string()),
                "token is stale",
            ),
            (
                "/requestDetails/timestampMillis",
                serde_json::json!((NOW_MS + MAX_CLOCK_SKEW_MS + 1).to_string()),
                "token is stale",
            ),
            (
                "/requestDetails/timestampMillis",
                serde_json::json!(null),
                "missing timestampMillis",
            ),
            (
                "/appIntegrity/appRecognitionVerdict",
                serde_json::json!("UNRECOGNIZED_VERSION"),
                "app not recognized by Play",
            ),
            (
                "/appIntegrity/appRecognitionVerdict",
                serde_json::json!("UNEVALUATED"),
                "app not recognized by Play",
            ),
            (
                "/appIntegrity/packageName",
                serde_json::json!("com.other.app"),
                "appIntegrity.packageName mismatch",
            ),
            (
                "/appIntegrity/certificateSha256Digest",
                serde_json::json!([URL_SAFE_NO_PAD.encode([0u8; 32])]),
                "signing certificate not allowed",
            ),
            (
                "/appIntegrity/certificateSha256Digest",
                serde_json::json!(["not-a-digest"]),
                "signing certificate not allowed",
            ),
            (
                "/appIntegrity/certificateSha256Digest",
                serde_json::json!([]),
                "signing certificate not allowed",
            ),
            (
                "/deviceIntegrity/deviceRecognitionVerdict",
                serde_json::json!(["MEETS_BASIC_INTEGRITY"]),
                "device integrity not met",
            ),
            (
                "/deviceIntegrity/deviceRecognitionVerdict",
                serde_json::json!([]),
                "device integrity not met",
            ),
            (
                "/accountDetails/appLicensingVerdict",
                serde_json::json!("UNLICENSED"),
                "app not licensed",
            ),
            (
                "/accountDetails/appLicensingVerdict",
                serde_json::json!("UNEVALUATED"),
                "app not licensed",
            ),
        ];
        for (pointer, value, reason) in cases {
            assert_eq!(
                check(with(good_payload(), pointer, value.clone())),
                Err(GoogleError::Verdict(reason)),
                "{pointer} = {value}"
            );
        }
        // Missing sections.
        for section in [
            "requestDetails",
            "appIntegrity",
            "deviceIntegrity",
            "accountDetails",
        ] {
            let mut value = good_payload();
            value.as_object_mut().unwrap().remove(section);
            assert!(check(value).is_err(), "{section}");
        }
    }

    #[test]
    fn licensing_check_is_configurable() {
        let unlicensed = payload(with(
            good_payload(),
            "/accountDetails/appLicensingVerdict",
            serde_json::json!("UNLICENSED"),
        ));
        let relaxed = PlayIntegrityPolicy {
            require_licensed: false,
            ..policy()
        };
        check_verdict(&unlicensed, &relaxed, &request(), NOW_MS).unwrap();
    }

    #[test]
    fn accepts_padded_standard_base64_digests() {
        use base64::engine::general_purpose::STANDARD;
        let value = with(
            good_payload(),
            "/appIntegrity/certificateSha256Digest",
            serde_json::json!(["unrelated", STANDARD.encode(CERT)]),
        );
        check(value).unwrap();
    }

    #[test]
    fn request_hash_and_device_id_vectors() {
        // Independently computed: SHA256(challenge || install_id).
        let mut expected = Sha256::new();
        expected.update([7u8; 32]);
        expected.update(INSTALL_ID.as_bytes());
        assert_eq!(
            request_hash(CHALLENGE, INSTALL_ID),
            URL_SAFE_NO_PAD.encode(expected.finalize())
        );
        assert_eq!(request_hash(CHALLENGE, INSTALL_ID).len(), 43);
        assert_ne!(
            device_id(PACKAGE, INSTALL_ID),
            device_id("com.other", INSTALL_ID)
        );
    }

    #[test]
    fn rejects_bad_service_accounts() {
        assert!(matches!(
            GoogleAuth::from_service_account_json("{}"),
            Err(GoogleError::Config(_))
        ));
        assert!(matches!(
            GoogleAuth::from_service_account_json(r#"{"client_email":"a","private_key":"nope"}"#),
            Err(GoogleError::Config(_))
        ));
        // Debug output never shows key material.
        let debug = format!("{:?}", auth());
        assert!(!debug.contains("PRIVATE"), "{debug}");
    }
}

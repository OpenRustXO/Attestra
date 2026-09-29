//! OAuth access tokens for the Play Integrity API via a service-account JWT (RFC 7523).

use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{GoogleError, HttpClient, HttpRequest};

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const SCOPE: &str = "https://www.googleapis.com/auth/playintegrity";
/// Cached tokens are replaced this long before they expire.
const REFRESH_MARGIN_SECS: u64 = 300;
const ASSERTION_TTL_SECS: u64 = 3600;

#[derive(Deserialize)]
struct ServiceAccountJson {
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'static str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Clone)]
struct CachedToken {
    value: String,
    refresh_at: u64,
}

/// A service account plus an in-memory access-token cache.
///
/// Meant to live for the whole isolate (e.g. in a `static`). The lock is never held across
/// an `await`; concurrent refreshes may both fetch a token, which is harmless.
pub struct GoogleAuth {
    client_email: String,
    key_id: Option<String>,
    signing_key: SigningKey<Sha256>,
    cache: Mutex<Option<CachedToken>>,
}

impl std::fmt::Debug for GoogleAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleAuth")
            .field("client_email", &self.client_email)
            .finish_non_exhaustive()
    }
}

impl GoogleAuth {
    /// Parses a service-account key file (the JSON downloaded from Google Cloud).
    pub fn from_service_account_json(json: &str) -> Result<Self, GoogleError> {
        let account: ServiceAccountJson = serde_json::from_str(json)
            .map_err(|e| GoogleError::Config(format!("service account JSON: {e}")))?;
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&account.private_key)
            .map_err(|e| GoogleError::Config(format!("service account private key: {e}")))?;
        Ok(Self {
            client_email: account.client_email,
            key_id: account.private_key_id,
            signing_key: SigningKey::<Sha256>::new(private_key),
            cache: Mutex::new(None),
        })
    }

    /// Builds the signed JWT assertion exchanged for an access token.
    pub fn signed_assertion(&self, now: u64) -> Result<String, GoogleError> {
        let header = JwtHeader {
            alg: "RS256",
            typ: "JWT",
            kid: self.key_id.as_deref(),
        };
        let claims = JwtClaims {
            iss: &self.client_email,
            scope: SCOPE,
            aud: TOKEN_URL,
            iat: now,
            exp: now + ASSERTION_TTL_SECS,
        };
        let encode = |json: serde_json::Result<Vec<u8>>| {
            json.map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
                .map_err(|e| GoogleError::Config(format!("encode JWT: {e}")))
        };
        let input = format!(
            "{}.{}",
            encode(serde_json::to_vec(&header))?,
            encode(serde_json::to_vec(&claims))?
        );
        let signature = self
            .signing_key
            .try_sign(input.as_bytes())
            .map_err(|e| GoogleError::Config(format!("sign JWT: {e}")))?;
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    /// Returns a cached access token, or fetches a new one.
    pub async fn access_token<H: HttpClient>(
        &self,
        http: &H,
        now: u64,
    ) -> Result<String, GoogleError> {
        if let Some(token) = self.cached(now)? {
            return Ok(token);
        }
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            self.signed_assertion(now)?
        );
        let response = http
            .send(HttpRequest {
                method: "POST",
                url: TOKEN_URL.into(),
                headers: vec![(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                body: body.into_bytes(),
            })
            .await?;
        if response.status != 200 {
            return Err(GoogleError::Upstream(format!(
                "token endpoint returned {}",
                response.status
            )));
        }
        let token: TokenResponse = serde_json::from_slice(&response.body)
            .map_err(|e| GoogleError::Upstream(format!("token response: {e}")))?;
        let refresh_at = now + token.expires_in.saturating_sub(REFRESH_MARGIN_SECS);
        *self.lock()? = Some(CachedToken {
            value: token.access_token.clone(),
            refresh_at,
        });
        Ok(token.access_token)
    }

    /// Drops the cached token (e.g. after the API rejected it).
    pub fn invalidate(&self) -> Result<(), GoogleError> {
        *self.lock()? = None;
        Ok(())
    }

    fn cached(&self, now: u64) -> Result<Option<String>, GoogleError> {
        Ok(self
            .lock()?
            .as_ref()
            .filter(|token| now < token.refresh_at)
            .map(|token| token.value.clone()))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<CachedToken>>, GoogleError> {
        self.cache
            .lock()
            .map_err(|_| GoogleError::Config("token cache poisoned".into()))
    }
}

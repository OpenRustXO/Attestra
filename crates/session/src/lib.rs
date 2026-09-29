//! Session tokens: ES256 JWTs issued after a successful attestation or assertion.
//!
//! Tokens are compact JWS with the header `{"alg":"ES256","typ":"JWT","kid":<thumbprint>}`,
//! where the key id is the RFC 7638 JWK thumbprint of the signing key's public key. The crate
//! is runtime-agnostic: callers supply the current time and the random `jti`.
#![forbid(unsafe_code)]

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Clock skew tolerated when checking `exp` and `iat`.
pub const DEFAULT_LEEWAY_SECS: u64 = 30;
/// Longest accepted session lifetime; guards against misconfigured TTLs.
pub const MAX_TTL_SECS: u64 = 86_400;
/// Tokens longer than this are rejected before any decoding.
const MAX_TOKEN_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }
}

/// Session claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// Device id.
    pub sub: String,
    pub plat: Platform,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    /// Attestation environment (`production` / `development`).
    pub env: String,
}

impl Claims {
    pub fn new(
        device_id: impl Into<String>,
        platform: Platform,
        environment: impl Into<String>,
        now: u64,
        ttl_secs: u64,
        jti: [u8; 16],
    ) -> Self {
        Self {
            sub: device_id.into(),
            plat: platform,
            iat: now,
            exp: now.saturating_add(ttl_secs),
            jti: URL_SAFE_NO_PAD.encode(jti),
            env: environment.into(),
        }
    }

    fn validate(&self, now: u64, leeway: u64) -> Result<(), SessionError> {
        let well_formed = !self.sub.is_empty()
            && self.sub.len() <= 128
            && !self.jti.is_empty()
            && self.jti.len() <= 64
            && self.env.len() <= 32
            && self.exp > self.iat
            && self.exp - self.iat <= MAX_TTL_SECS;
        if !well_formed {
            return Err(SessionError::Claims);
        }
        if now >= self.exp.saturating_add(leeway) {
            return Err(SessionError::Expired);
        }
        if self.iat > now.saturating_add(leeway) {
            return Err(SessionError::NotYetValid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("invalid signing key: {0}")]
    Key(String),
    #[error("malformed token")]
    Malformed,
    #[error("unexpected token header")]
    Header,
    #[error("bad token signature")]
    Signature,
    #[error("token expired")]
    Expired,
    #[error("token issued in the future")]
    NotYetValid,
    #[error("invalid token claims")]
    Claims,
    #[error("encoding failed: {0}")]
    Encode(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// The session signing key (P-256) and its verifying half.
pub struct SessionKey {
    signing: SigningKey,
    verifying: VerifyingKey,
    kid: String,
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SessionKey {
    /// Loads a PKCS#8 PEM private key. Literal `\n` sequences (common when a PEM is pasted
    /// into a single-line secret) are accepted.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, SessionError> {
        let pem = pem.trim().replace("\\n", "\n");
        let signing =
            SigningKey::from_pkcs8_pem(&pem).map_err(|e| SessionError::Key(e.to_string()))?;
        Ok(Self::from_signing_key(signing))
    }

    /// Builds a key from a raw 32-byte scalar.
    pub fn from_bytes(secret: &[u8]) -> Result<Self, SessionError> {
        let signing =
            SigningKey::from_slice(secret).map_err(|e| SessionError::Key(e.to_string()))?;
        Ok(Self::from_signing_key(signing))
    }

    fn from_signing_key(signing: SigningKey) -> Self {
        let verifying = *signing.verifying_key();
        let kid = jwk_thumbprint(&verifying);
        Self {
            signing,
            verifying,
            kid,
        }
    }

    /// RFC 7638 thumbprint of the public key, used as the JWT `kid`.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn issue(&self, claims: &Claims) -> Result<String, SessionError> {
        let header = Header {
            alg: "ES256".into(),
            typ: "JWT".into(),
            kid: self.kid.clone(),
        };
        let signing_input = format!("{}.{}", b64_json(&header)?, b64_json(claims)?);
        let signature: Signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    /// Verifies signature, header and claims with [`DEFAULT_LEEWAY_SECS`] of clock skew.
    pub fn verify(&self, token: &str, now: u64) -> Result<Claims, SessionError> {
        self.verify_with_leeway(token, now, DEFAULT_LEEWAY_SECS)
    }

    pub fn verify_with_leeway(
        &self,
        token: &str,
        now: u64,
        leeway: u64,
    ) -> Result<Claims, SessionError> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(SessionError::Malformed);
        }
        let mut parts = token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SessionError::Malformed);
        };
        let decode = |part: &str| {
            URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| SessionError::Malformed)
        };

        let header: Header =
            serde_json::from_slice(&decode(header_b64)?).map_err(|_| SessionError::Header)?;
        if header.alg != "ES256" || header.typ != "JWT" || header.kid != self.kid {
            return Err(SessionError::Header);
        }

        let signature =
            Signature::from_slice(&decode(signature_b64)?).map_err(|_| SessionError::Signature)?;
        let signing_input_len = header_b64.len() + 1 + claims_b64.len();
        let signing_input = token
            .get(..signing_input_len)
            .ok_or(SessionError::Malformed)?;
        self.verifying
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| SessionError::Signature)?;

        let claims: Claims =
            serde_json::from_slice(&decode(claims_b64)?).map_err(|_| SessionError::Claims)?;
        claims.validate(now, leeway)?;
        Ok(claims)
    }
}

/// `{"crv":"P-256","kty":"EC","x":..,"y":..}` hashed with SHA-256 (RFC 7638).
fn jwk_thumbprint(key: &VerifyingKey) -> String {
    let point = key.to_sec1_point(false);
    let coordinate = |c: Option<&[u8]>| URL_SAFE_NO_PAD.encode(c.unwrap_or_default());
    let jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        coordinate(point.x().map(|x| x.as_slice())),
        coordinate(point.y().map(|y| y.as_slice())),
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))
}

fn b64_json<T: Serialize>(value: &T) -> Result<String, SessionError> {
    serde_json::to_vec(value)
        .map(|json| URL_SAFE_NO_PAD.encode(json))
        .map_err(|e| SessionError::Encode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use p256::pkcs8::EncodePrivateKey as _;
    use p256::pkcs8::LineEnding;

    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn key() -> SessionKey {
        SessionKey::from_bytes(&[0x21; 32]).unwrap()
    }

    fn claims() -> Claims {
        Claims::new("device-1", Platform::Ios, "production", NOW, 900, [7; 16])
    }

    /// Re-signs arbitrary header/claims JSON with `key`.
    fn forge(key: &SessionKey, header: &str, claims: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature: Signature = key.signing.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn round_trip() {
        let key = key();
        let token = key.issue(&claims()).unwrap();
        assert_eq!(token.split('.').count(), 3);
        assert_eq!(key.verify(&token, NOW + 10).unwrap(), claims());
    }

    #[test]
    fn header_and_claims_shape() {
        let key = key();
        let token = key.issue(&claims()).unwrap();
        let mut parts = token.split('.');
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], key.kid());
        let body: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "sub": "device-1", "plat": "ios", "iat": NOW, "exp": NOW + 900,
                "jti": URL_SAFE_NO_PAD.encode([7u8; 16]), "env": "production"
            })
        );
    }

    #[test]
    fn loads_pkcs8_pem() {
        let signing = SigningKey::from_slice(&[0x21; 32]).unwrap();
        let pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let loaded = SessionKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(loaded.kid(), key().kid());
        // Single-line secret with escaped newlines.
        let escaped = pem.replace('\n', "\\n");
        assert_eq!(
            SessionKey::from_pkcs8_pem(&escaped).unwrap().kid(),
            key().kid()
        );
        assert!(matches!(
            SessionKey::from_pkcs8_pem("nope"),
            Err(SessionError::Key(_))
        ));
    }

    #[test]
    fn kid_is_rfc7638_thumbprint() {
        // RFC 7638 fixes member order and whitespace; recompute independently.
        let key = key();
        let point = key.verifying.to_sec1_point(false);
        let jwk = serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        // serde_json sorts keys alphabetically, which is the RFC 7638 order.
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.to_string()));
        assert_eq!(key.kid(), expected);
        assert_eq!(key.kid().len(), 43);
    }

    #[test]
    fn expiry_and_leeway() {
        let key = key();
        let token = key.issue(&claims()).unwrap();
        let exp = NOW + 900;
        key.verify(&token, exp - 1).unwrap();
        key.verify(&token, exp + DEFAULT_LEEWAY_SECS - 1).unwrap();
        assert_eq!(
            key.verify(&token, exp + DEFAULT_LEEWAY_SECS),
            Err(SessionError::Expired)
        );
        assert_eq!(
            key.verify_with_leeway(&token, exp, 0),
            Err(SessionError::Expired)
        );
        // Issued in the future beyond the leeway.
        assert_eq!(
            key.verify(&token, NOW - DEFAULT_LEEWAY_SECS - 1),
            Err(SessionError::NotYetValid)
        );
        key.verify(&token, NOW - DEFAULT_LEEWAY_SECS).unwrap();
    }

    #[test]
    fn rejects_tampering() {
        let key = key();
        let token = key.issue(&claims()).unwrap();
        let (input, signature) = token.rsplit_once('.').unwrap();

        // Swap in different claims under the original signature.
        let mut other = claims();
        other.sub = "device-2".into();
        let other_token = key.issue(&other).unwrap();
        let other_claims = other_token.split('.').nth(1).unwrap();
        let header = input.split('.').next().unwrap();
        assert_eq!(
            key.verify(&format!("{header}.{other_claims}.{signature}"), NOW),
            Err(SessionError::Signature)
        );

        // Flip a signature bit.
        let mut sig = URL_SAFE_NO_PAD.decode(signature).unwrap();
        sig[10] ^= 1;
        assert_eq!(
            key.verify(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)), NOW),
            Err(SessionError::Signature)
        );

        // A different key.
        let stranger = SessionKey::from_bytes(&[0x33; 32]).unwrap();
        assert_eq!(stranger.verify(&token, NOW), Err(SessionError::Header)); // kid differs
        let resigned = forge(
            &stranger,
            &format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{}"}}"#, key.kid()),
            &serde_json::to_string(&claims()).unwrap(),
        );
        assert_eq!(key.verify(&resigned, NOW), Err(SessionError::Signature));
    }

    #[test]
    fn rejects_other_algorithms_and_headers() {
        let key = key();
        let body = serde_json::to_string(&claims()).unwrap();
        for header in [
            format!(r#"{{"alg":"none","typ":"JWT","kid":"{}"}}"#, key.kid()),
            format!(r#"{{"alg":"HS256","typ":"JWT","kid":"{}"}}"#, key.kid()),
            format!(r#"{{"alg":"ES256","typ":"JWS","kid":"{}"}}"#, key.kid()),
            r#"{"alg":"ES256","typ":"JWT"}"#.to_owned(),
            format!(
                r#"{{"alg":"ES256","typ":"JWT","kid":"{}","jku":"https://x"}}"#,
                key.kid()
            ),
        ] {
            assert_eq!(
                key.verify(&forge(&key, &header, &body), NOW),
                Err(SessionError::Header),
                "{header}"
            );
        }
        // alg=none with an empty signature.
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(format!(
                r#"{{"alg":"none","typ":"JWT","kid":"{}"}}"#,
                key.kid()
            )),
            URL_SAFE_NO_PAD.encode(&body)
        );
        assert_eq!(key.verify(&none, NOW), Err(SessionError::Header));
    }

    #[test]
    fn rejects_bad_claims() {
        let key = key();
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{}"}}"#, key.kid());
        for body in [
            r#"{"sub":"d","plat":"windows","iat":1750000000,"exp":1750000900,"jti":"j","env":"production"}"#,
            r#"{"sub":"","plat":"ios","iat":1750000000,"exp":1750000900,"jti":"j","env":"production"}"#,
            r#"{"sub":"d","plat":"ios","iat":1750000000,"exp":1750000000,"jti":"j","env":"production"}"#,
            r#"{"sub":"d","plat":"ios","iat":1750000000,"exp":1760000000,"jti":"j","env":"production"}"#,
            r#"{"sub":"d","plat":"ios","iat":1750000000,"exp":1750000900,"env":"production"}"#,
            r#"{"sub":"d","plat":"ios","iat":1750000000,"exp":1750000900,"jti":"j","env":"production","admin":true}"#,
        ] {
            assert_eq!(
                key.verify(&forge(&key, &header, body), NOW),
                Err(SessionError::Claims),
                "{body}"
            );
        }
    }

    #[test]
    fn rejects_malformed_tokens() {
        let key = key();
        let token = key.issue(&claims()).unwrap();
        for bad in [
            String::new(),
            "a.b".to_owned(),
            "a.b.c.d".to_owned(),
            format!("{token}."),
            format!("{token}=="),
            token.replace('.', ".."),
            "x".repeat(MAX_TOKEN_LEN + 1),
        ] {
            assert!(key.verify(&bad, NOW).is_err(), "{bad}");
        }
    }
}

//! The API error type and its mapping to stable, client-facing error codes.

/// Error returned by request handlers.
///
/// The `Display` output carries internal detail and is only ever written to server-side logs.
/// Clients see nothing but [`ApiError::status`] and the body `{"error": "<code>"}`, so
/// verification failures never reveal which check failed.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("challenge invalid: {0}")]
    ChallengeInvalid(String),
    #[error("attestation invalid: {0}")]
    AttestationInvalid(String),
    #[error("session invalid: {0}")]
    SessionInvalid(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed { allow: &'static str },
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) | Self::ChallengeInvalid(_) => 400,
            Self::AttestationInvalid(_) | Self::SessionInvalid(_) => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed { .. } => 405,
            Self::PayloadTooLarge => 413,
            Self::RateLimited { .. } => 429,
            Self::Internal(_) => 500,
            Self::NotImplemented(_) => 501,
            Self::Upstream(_) => 502,
        }
    }

    /// Stable machine-readable code sent to clients.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::ChallengeInvalid(_) => "challenge_invalid",
            Self::AttestationInvalid(_) => "attestation_invalid",
            Self::SessionInvalid(_) => "session_invalid",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed { .. } => "method_not_allowed",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited { .. } => "rate_limited",
            Self::Upstream(_) => "upstream_error",
            Self::NotImplemented(_) => "not_implemented",
            Self::Internal(_) => "internal_error",
        }
    }

    /// Response body: `{"error":"<code>"}`.
    pub fn body(&self) -> String {
        serde_json::json!({ "error": self.code() }).to_string()
    }

    /// Headers that accompany this error (e.g. `Retry-After`, `Allow`).
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::RateLimited { retry_after_secs } => {
                vec![("retry-after", retry_after_secs.max(&1).to_string())]
            }
            Self::MethodNotAllowed { allow } => vec![("allow", (*allow).to_owned())],
            _ => Vec::new(),
        }
    }

    /// Server-side faults are logged at error level; everything else (client mistakes and
    /// verification failures) only at debug level.
    pub fn is_server_fault(&self) -> bool {
        self.status() >= 500
    }
}

impl From<worker::Error> for ApiError {
    fn from(err: worker::Error) -> Self {
        Self::Internal(format!("runtime: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<ApiError> {
        vec![
            ApiError::BadRequest("detail".into()),
            ApiError::ChallengeInvalid("detail".into()),
            ApiError::AttestationInvalid("detail".into()),
            ApiError::SessionInvalid("detail".into()),
            ApiError::Forbidden("detail".into()),
            ApiError::NotFound,
            ApiError::MethodNotAllowed { allow: "POST" },
            ApiError::PayloadTooLarge,
            ApiError::RateLimited {
                retry_after_secs: 7,
            },
            ApiError::Upstream("detail".into()),
            ApiError::NotImplemented("detail"),
            ApiError::Internal("detail".into()),
        ]
    }

    #[test]
    fn status_and_code_mapping() {
        let mapping: Vec<(u16, &str)> = all_variants()
            .iter()
            .map(|e| (e.status(), e.code()))
            .collect();
        assert_eq!(
            mapping,
            [
                (400, "bad_request"),
                (400, "challenge_invalid"),
                (401, "attestation_invalid"),
                (401, "session_invalid"),
                (403, "forbidden"),
                (404, "not_found"),
                (405, "method_not_allowed"),
                (413, "payload_too_large"),
                (429, "rate_limited"),
                (502, "upstream_error"),
                (501, "not_implemented"),
                (500, "internal_error"),
            ]
        );
    }

    #[test]
    fn body_never_leaks_detail() {
        for err in all_variants() {
            let body = err.body();
            assert!(!body.contains("detail"), "{body}");
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json, serde_json::json!({ "error": err.code() }));
            // ...while the log line keeps it.
            if !matches!(
                err,
                ApiError::NotFound
                    | ApiError::MethodNotAllowed { .. }
                    | ApiError::PayloadTooLarge
                    | ApiError::RateLimited { .. }
            ) {
                assert!(err.to_string().contains("detail"), "{err}");
            }
        }
    }

    #[test]
    fn extra_headers() {
        assert_eq!(
            ApiError::RateLimited {
                retry_after_secs: 30
            }
            .headers(),
            [("retry-after", "30".to_owned())]
        );
        // Never advertise `Retry-After: 0`.
        assert_eq!(
            ApiError::RateLimited {
                retry_after_secs: 0
            }
            .headers(),
            [("retry-after", "1".to_owned())]
        );
        assert_eq!(
            ApiError::MethodNotAllowed { allow: "POST" }.headers(),
            [("allow", "POST".to_owned())]
        );
        assert!(ApiError::NotFound.headers().is_empty());
    }

    #[test]
    fn server_faults() {
        let faults: Vec<&str> = all_variants()
            .iter()
            .filter(|e| e.is_server_fault())
            .map(ApiError::code)
            .collect();
        assert_eq!(
            faults,
            ["upstream_error", "not_implemented", "internal_error"]
        );
    }
}

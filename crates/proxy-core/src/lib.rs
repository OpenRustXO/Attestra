//! Generic API-key proxy core.
//!
//! Holds the provider registry (parsed from `providers.toml`), allowlist matching, the
//! request/response rewriting rules, per-(device, provider) rate-limit windows and the
//! per-request assertion format. Adding a provider is a configuration change only.
//! This crate is runtime-agnostic: it has no dependency on `worker`.
#![forbid(unsafe_code)]

pub mod assertion;
mod config;
mod path;
mod rate_limit;
mod rewrite;

pub use config::{
    AllowRule, AuthConfig, BaseUrl, ConfigError, DEFAULT_MAX_BODY_BYTES, KeyTemplate,
    MAX_BODY_BYTES_LIMIT, Method, PathPattern, PatternSegment, Provider, ProviderRegistry,
    RateLimit,
};
pub use path::{RequestPath, pattern_matches};
pub use rate_limit::{RateDecision, RateWindows};
pub use rewrite::forwards_response_header;

/// Why a proxied request was refused. The detail is for server-side logs only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid path: {0}")]
    InvalidPath(&'static str),
    #[error("{method} {path} is not in the allowlist")]
    NotAllowed { method: String, path: String },
    #[error("provider secret is empty or not printable ASCII")]
    InvalidSecret,
    #[error("assertion: {0}")]
    Assertion(&'static str),
}

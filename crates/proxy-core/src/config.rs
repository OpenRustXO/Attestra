//! `providers.toml` schema and validation.
//!
//! The file is deserialized into private `Raw*` structs and then validated into the public
//! types below, so every [`Provider`] handed to the proxy is known to be well-formed.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

/// Request-body cap applied when a provider does not set `max_body_bytes` (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Largest accepted `max_body_bytes` (100 MiB, the Workers request-body limit).
pub const MAX_BODY_BYTES_LIMIT: u64 = 100 * 1024 * 1024;

const KEY_PLACEHOLDER: &str = "{key}";

/// Headers that the proxy manages itself and that an auth config may therefore not target.
const RESERVED_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-attestra-assertion",
    "x-real-ip",
];
const RESERVED_HEADER_PREFIXES: &[&str] = &["cf-", "x-forwarded-"];

/// Error produced while loading `providers.toml`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("providers.toml: {0}")]
    Syntax(String),
    #[error("providers.toml: provider `{provider}`: {reason}")]
    Invalid { provider: String, reason: String },
}

impl ConfigError {
    fn invalid(provider: &str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            provider: provider.to_owned(),
            reason: reason.into(),
        }
    }
}

/// All configured providers, keyed by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderRegistry {
    providers: BTreeMap<String, Provider>,
}

impl ProviderRegistry {
    /// Parses and validates a `providers.toml` document.
    pub fn from_toml(src: &str) -> Result<Self, ConfigError> {
        let raw: RawFile = toml::from_str(src).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        let mut providers = BTreeMap::new();
        for (name, raw_provider) in raw.providers {
            let provider = Provider::from_raw(&name, raw_provider)?;
            providers.insert(name, provider);
        }
        Ok(Self { providers })
    }

    /// Fails if any provider names one of `reserved` as its secret, which would forward an
    /// internal secret (e.g. the session signing key) to a third party.
    pub fn ensure_secrets_not_reserved(&self, reserved: &[&str]) -> Result<(), ConfigError> {
        match self
            .providers
            .values()
            .find(|p| reserved.contains(&p.secret.as_str()))
        {
            Some(p) => Err(ConfigError::invalid(
                &p.name,
                format!("secret `{}` is reserved for internal use", p.secret),
            )),
            None => Ok(()),
        }
    }

    pub fn get(&self, name: &str) -> Option<&Provider> {
        self.providers.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Provider> {
        self.providers.values()
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

/// A validated upstream provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub name: String,
    pub base_url: BaseUrl,
    /// Name of the Worker secret holding the provider's API key.
    pub secret: String,
    pub auth: AuthConfig,
    pub allow: Vec<AllowRule>,
    pub rate_limit: Option<RateLimit>,
    pub max_body_bytes: u64,
    pub require_assertion: bool,
}

impl Provider {
    fn from_raw(name: &str, raw: RawProvider) -> Result<Self, ConfigError> {
        let invalid =
            |field: &str, reason: String| ConfigError::invalid(name, format!("{field}: {reason}"));

        validate_provider_name(name).map_err(|r| ConfigError::invalid(name, r))?;
        let base_url = BaseUrl::parse(&raw.base_url).map_err(|r| invalid("base_url", r))?;
        validate_secret_name(&raw.secret).map_err(|r| invalid("secret", r))?;
        let auth = AuthConfig::from_raw(raw.auth).map_err(|r| invalid("auth", r))?;

        if raw.allow.is_empty() {
            return Err(invalid("allow", "must contain at least one rule".into()));
        }
        let allow = raw
            .allow
            .into_iter()
            .map(AllowRule::from_raw)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|r| invalid("allow", r))?;

        let rate_limit = raw
            .rate_limit
            .map(RateLimit::from_raw)
            .transpose()
            .map_err(|r| invalid("rate_limit", r))?;

        let max_body_bytes = raw.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES);
        if max_body_bytes > MAX_BODY_BYTES_LIMIT {
            return Err(invalid(
                "max_body_bytes",
                format!("must not exceed {MAX_BODY_BYTES_LIMIT}"),
            ));
        }

        Ok(Self {
            name: name.to_owned(),
            base_url,
            secret: raw.secret,
            auth,
            allow,
            rate_limit,
            max_body_bytes,
            require_assertion: raw.require_assertion,
        })
    }
}

/// An `https` origin plus an optional path prefix, e.g. `https://api.example.com/v2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl {
    origin: String,
    path_prefix: String,
}

impl BaseUrl {
    pub fn parse(s: &str) -> Result<Self, String> {
        let rest = s
            .strip_prefix("https://")
            .ok_or_else(|| "must start with `https://`".to_owned())?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));

        if authority.contains('@') {
            return Err("must not contain credentials".into());
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        validate_host(host)?;
        if let Some(port) = port {
            match port.parse::<u16>() {
                Ok(p) if p > 0 && port.bytes().all(|b| b.is_ascii_digit()) => {}
                _ => return Err(format!("invalid port `{port}`")),
            }
        }

        let path_prefix = path.trim_end_matches('/');
        if !path_prefix.is_empty() {
            for segment in path_prefix.split('/').skip(1) {
                validate_literal_segment(segment)?;
            }
        }

        let mut origin = format!("https://{}", host.to_ascii_lowercase());
        if let Some(port) = port {
            origin.push(':');
            origin.push_str(port);
        }
        Ok(Self {
            origin,
            path_prefix: path_prefix.to_owned(),
        })
    }

    /// `https://host[:port]`, lowercased, without a trailing slash.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Path prefix without a trailing slash; empty when the base URL has no path.
    pub fn path_prefix(&self) -> &str {
        &self.path_prefix
    }
}

impl fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.origin, self.path_prefix)
    }
}

/// How the API key is attached to the upstream request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthConfig {
    /// `<name>: <format>` with `{key}` substituted.
    Header { name: String, format: KeyTemplate },
    /// `?<name>=<key>` appended to the query string.
    Query { name: String },
    /// `Authorization: Basic base64(<format>)` with `{key}` substituted.
    Basic { format: KeyTemplate },
}

impl AuthConfig {
    fn from_raw(raw: RawAuth) -> Result<Self, String> {
        match raw {
            RawAuth::Header { name, format } => Ok(Self::Header {
                name: validate_header_name(&name)?,
                format: KeyTemplate::parse(&format)?,
            }),
            RawAuth::Query { name } => {
                validate_query_name(&name)?;
                Ok(Self::Query { name })
            }
            RawAuth::Basic { format } => Ok(Self::Basic {
                format: KeyTemplate::parse(&format)?,
            }),
        }
    }

    /// The (lowercase) request header this auth scheme writes, if any.
    pub fn header_name(&self) -> Option<&str> {
        match self {
            Self::Header { name, .. } => Some(name),
            Self::Basic { .. } => Some("authorization"),
            Self::Query { .. } => None,
        }
    }

    /// The query parameter this auth scheme writes, if any.
    pub fn query_param(&self) -> Option<&str> {
        match self {
            Self::Query { name } => Some(name),
            Self::Header { .. } | Self::Basic { .. } => None,
        }
    }
}

/// A value template containing exactly one `{key}` placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTemplate {
    prefix: String,
    suffix: String,
}

impl KeyTemplate {
    pub fn parse(s: &str) -> Result<Self, String> {
        if !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err("format must be printable ASCII".into());
        }
        let (prefix, suffix) = s
            .split_once(KEY_PLACEHOLDER)
            .ok_or_else(|| "format must contain `{key}`".to_owned())?;
        if suffix.contains(KEY_PLACEHOLDER) {
            return Err("format must contain `{key}` exactly once".into());
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            suffix: suffix.to_owned(),
        })
    }

    pub fn render(&self, key: &str) -> String {
        let mut out = String::with_capacity(self.prefix.len() + key.len() + self.suffix.len());
        out.push_str(&self.prefix);
        out.push_str(key);
        out.push_str(&self.suffix);
        out
    }
}

/// One allowlist entry: an HTTP method and a path pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub method: Method,
    pub path: PathPattern,
}

impl AllowRule {
    fn from_raw(raw: RawAllow) -> Result<Self, String> {
        let method = Method::parse(&raw.method.to_ascii_uppercase())
            .ok_or_else(|| format!("unsupported method `{}`", raw.method))?;
        let path =
            PathPattern::parse(&raw.path).map_err(|r| format!("path `{}`: {r}", raw.path))?;
        Ok(Self { method, path })
    }
}

/// HTTP methods that may appear in an allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    /// Parses a canonical (uppercase) method name.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "OPTIONS" => Self::Options,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One segment of a [`PathPattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternSegment {
    /// Matches exactly this (unencoded) segment. An empty literal is only produced for a
    /// trailing slash.
    Literal(String),
    /// `*`: matches one or more whole path segments.
    Wildcard,
}

/// An allowlist path such as `/maps/api/place/*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    raw: String,
    segments: Vec<PatternSegment>,
}

impl PathPattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let rest = s
            .strip_prefix('/')
            .ok_or_else(|| "must start with `/`".to_owned())?;
        let mut segments = Vec::new();
        if !rest.is_empty() {
            let mut parts = rest.split('/').peekable();
            while let Some(part) = parts.next() {
                let is_last = parts.peek().is_none();
                segments.push(match part {
                    "" if is_last => PatternSegment::Literal(String::new()),
                    "" => return Err("must not contain empty segments".into()),
                    "*" => PatternSegment::Wildcard,
                    _ if part.contains('*') => {
                        return Err("`*` must be a whole path segment".into());
                    }
                    _ => {
                        validate_literal_segment(part)?;
                        PatternSegment::Literal(part.to_owned())
                    }
                });
            }
        }
        Ok(Self {
            raw: s.to_owned(),
            segments,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn segments(&self) -> &[PatternSegment] {
        &self.segments
    }
}

/// Per-(device, provider) request quotas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub per_minute: Option<u32>,
    pub per_day: Option<u32>,
}

impl RateLimit {
    fn from_raw(raw: RawRateLimit) -> Result<Self, String> {
        if raw.per_minute.is_none() && raw.per_day.is_none() {
            return Err("must set `per_minute` and/or `per_day`".into());
        }
        if raw.per_minute == Some(0) || raw.per_day == Some(0) {
            return Err("limits must be greater than zero".into());
        }
        Ok(Self {
            per_minute: raw.per_minute,
            per_day: raw.per_day,
        })
    }
}

// --- validation helpers ---------------------------------------------------------------------

fn validate_provider_name(name: &str) -> Result<(), String> {
    let mut bytes = name.bytes();
    let valid = name.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err("provider names must match [a-z0-9][a-z0-9_-]{0,63}".into())
    }
}

fn validate_secret_name(name: &str) -> Result<(), String> {
    let mut bytes = name.bytes();
    let valid = name.len() <= 128
        && bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(format!("`{name}` must match [A-Z][A-Z0-9_]*"))
    }
}

fn validate_host(host: &str) -> Result<(), String> {
    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if !host.is_empty() && host.len() <= 253 && host.split('.').all(valid_label) {
        Ok(())
    } else {
        Err(format!("invalid host `{host}`"))
    }
}

/// RFC 3986 `pchar` without percent-encoding and without `*` (reserved for globs).
fn is_plain_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()+,;=:@".contains(&b)
}

fn validate_literal_segment(segment: &str) -> Result<(), String> {
    if segment.is_empty() {
        return Err("must not contain empty segments".into());
    }
    if segment == "." || segment == ".." {
        return Err("must not contain `.` or `..` segments".into());
    }
    if !segment.bytes().all(is_plain_pchar) {
        return Err(format!(
            "segment `{segment}` contains unsupported characters"
        ));
    }
    Ok(())
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn validate_header_name(name: &str) -> Result<String, String> {
    if name.is_empty() || !name.bytes().all(is_token_char) {
        return Err(format!("invalid header name `{name}`"));
    }
    let lower = name.to_ascii_lowercase();
    if RESERVED_HEADERS.contains(&lower.as_str())
        || RESERVED_HEADER_PREFIXES
            .iter()
            .any(|p| lower.starts_with(p))
    {
        return Err(format!("header `{name}` is managed by the proxy"));
    }
    Ok(lower)
}

fn validate_query_name(name: &str) -> Result<(), String> {
    if !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        Ok(())
    } else {
        Err(format!("invalid query parameter name `{name}`"))
    }
}

// --- raw TOML shape -------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    providers: BTreeMap<String, RawProvider>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    base_url: String,
    secret: String,
    auth: RawAuth,
    allow: Vec<RawAllow>,
    #[serde(default)]
    rate_limit: Option<RawRateLimit>,
    #[serde(default)]
    max_body_bytes: Option<u64>,
    #[serde(default)]
    require_assertion: bool,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum RawAuth {
    Header {
        name: String,
        #[serde(default = "default_key_format")]
        format: String,
    },
    Query {
        name: String,
    },
    Basic {
        #[serde(default = "default_key_format")]
        format: String,
    },
}

fn default_key_format() -> String {
    KEY_PLACEHOLDER.to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllow {
    method: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimit {
    per_minute: Option<u32>,
    per_day: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_EXAMPLE: &str = r#"
        [providers.openai]
        base_url = "https://api.openai.com"
        secret = "OPENAI_API_KEY"
        auth = { kind = "header", name = "Authorization", format = "Bearer {key}" }
        allow = [ { method = "POST", path = "/v1/chat/completions" } ]
        rate_limit = { per_minute = 60, per_day = 2000 }
        max_body_bytes = 1048576
        require_assertion = false

        [providers.gmaps]
        base_url = "https://maps.googleapis.com"
        secret = "GMAPS_KEY"
        auth = { kind = "query", name = "key" }
        allow = [ { method = "GET", path = "/maps/api/place/*" } ]
    "#;

    /// Builds a single-provider document, overriding one line of a valid baseline.
    fn doc(override_line: &str) -> String {
        let mut lines = vec![
            ("base_url", r#"base_url = "https://api.example.com""#),
            ("secret", r#"secret = "EXAMPLE_KEY""#),
            ("auth", r#"auth = { kind = "header", name = "X-Api-Key" }"#),
            ("allow", r#"allow = [ { method = "GET", path = "/v1/*" } ]"#),
        ];
        let key = override_line.split('=').next().unwrap_or("").trim();
        match lines.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = override_line,
            None => lines.push((key, override_line)),
        }
        let body: Vec<&str> = lines.iter().map(|(_, l)| *l).collect();
        format!("[providers.example]\n{}\n", body.join("\n"))
    }

    fn parse_one(override_line: &str) -> Result<Provider, ConfigError> {
        let registry = ProviderRegistry::from_toml(&doc(override_line))?;
        Ok(registry.get("example").cloned().expect("provider present"))
    }

    fn assert_rejected(override_line: &str, needle: &str) {
        let err = parse_one(override_line)
            .expect_err(override_line)
            .to_string();
        assert!(
            err.contains(needle),
            "`{override_line}` -> `{err}` (expected `{needle}`)"
        );
    }

    #[test]
    fn parses_spec_example() {
        let registry = ProviderRegistry::from_toml(SPEC_EXAMPLE).unwrap();
        assert_eq!(registry.len(), 2);

        let openai = registry.get("openai").unwrap();
        assert_eq!(openai.base_url.origin(), "https://api.openai.com");
        assert_eq!(openai.base_url.path_prefix(), "");
        assert_eq!(openai.secret, "OPENAI_API_KEY");
        assert_eq!(openai.auth.header_name(), Some("authorization"));
        match &openai.auth {
            AuthConfig::Header { format, .. } => assert_eq!(format.render("sk-1"), "Bearer sk-1"),
            other => panic!("unexpected auth {other:?}"),
        }
        assert_eq!(openai.allow.len(), 1);
        assert_eq!(openai.allow[0].method, Method::Post);
        assert_eq!(openai.allow[0].path.as_str(), "/v1/chat/completions");
        assert_eq!(
            openai.rate_limit,
            Some(RateLimit {
                per_minute: Some(60),
                per_day: Some(2000)
            })
        );
        assert_eq!(openai.max_body_bytes, 1_048_576);
        assert!(!openai.require_assertion);

        let gmaps = registry.get("gmaps").unwrap();
        assert_eq!(gmaps.auth.query_param(), Some("key"));
        assert_eq!(gmaps.auth.header_name(), None);
        assert_eq!(
            gmaps.allow[0].path.segments(),
            &[
                PatternSegment::Literal("maps".into()),
                PatternSegment::Literal("api".into()),
                PatternSegment::Literal("place".into()),
                PatternSegment::Wildcard,
            ]
        );
        assert_eq!(gmaps.rate_limit, None);
        assert_eq!(gmaps.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn empty_document_is_an_empty_registry() {
        assert!(ProviderRegistry::from_toml("").unwrap().is_empty());
    }

    #[test]
    fn applies_defaults() {
        let p = parse_one(r#"auth = { kind = "header", name = "X-Api-Key" }"#).unwrap();
        match &p.auth {
            AuthConfig::Header { name, format } => {
                assert_eq!(name, "x-api-key");
                assert_eq!(format.render("k"), "k");
            }
            other => panic!("unexpected auth {other:?}"),
        }
        assert_eq!(p.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert!(!p.require_assertion);
    }

    #[test]
    fn basic_auth_formats() {
        let p = parse_one(r#"auth = { kind = "basic", format = "api:{key}" }"#).unwrap();
        assert_eq!(p.auth.header_name(), Some("authorization"));
        match &p.auth {
            AuthConfig::Basic { format } => assert_eq!(format.render("s3cret"), "api:s3cret"),
            other => panic!("unexpected auth {other:?}"),
        }
        let p = parse_one(r#"auth = { kind = "basic" }"#).unwrap();
        assert!(matches!(p.auth, AuthConfig::Basic { .. }));
    }

    #[test]
    fn base_url_normalization() {
        let p = parse_one(r#"base_url = "https://API.Example.com:8443/v2/""#).unwrap();
        assert_eq!(p.base_url.origin(), "https://api.example.com:8443");
        assert_eq!(p.base_url.path_prefix(), "/v2");
        assert_eq!(p.base_url.to_string(), "https://api.example.com:8443/v2");

        let p = parse_one(r#"base_url = "https://api.example.com/""#).unwrap();
        assert_eq!(p.base_url.path_prefix(), "");
    }

    #[test]
    fn method_is_case_insensitive_in_config() {
        let p = parse_one(r#"allow = [ { method = "delete", path = "/x" } ]"#).unwrap();
        assert_eq!(p.allow[0].method, Method::Delete);
    }

    #[test]
    fn path_pattern_shapes() {
        use PatternSegment::{Literal, Wildcard};
        let seg = |s: &str| PathPattern::parse(s).unwrap().segments().to_vec();
        assert_eq!(seg("/"), vec![]);
        assert_eq!(
            seg("/a/"),
            vec![Literal("a".into()), Literal(String::new())]
        );
        assert_eq!(
            seg("/v1/models/*/generate"),
            vec![
                Literal("v1".into()),
                Literal("models".into()),
                Wildcard,
                Literal("generate".into())
            ]
        );
        assert_eq!(
            seg("/v1beta/models/gemini:generateContent"),
            vec![
                Literal("v1beta".into()),
                Literal("models".into()),
                Literal("gemini:generateContent".into())
            ]
        );
    }

    #[test]
    fn rejects_invalid_toml_and_unknown_fields() {
        assert!(matches!(
            ProviderRegistry::from_toml("[providers.x"),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            ProviderRegistry::from_toml("[other]\na = 1"),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            ProviderRegistry::from_toml(&doc("unexpected = true")),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            ProviderRegistry::from_toml(&doc(r#"auth = { kind = "cookie", name = "k" }"#)),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            ProviderRegistry::from_toml(&doc(
                r#"auth = { kind = "query", name = "k", format = "{key}" }"#
            )),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            ProviderRegistry::from_toml(&doc(r#"rate_limit = { per_hour = 5 }"#)),
            Err(ConfigError::Syntax(_))
        ));
    }

    #[test]
    fn rejects_invalid_base_urls() {
        for (url, needle) in [
            ("http://api.example.com", "https://"),
            ("https://", "invalid host"),
            ("https://user:pw@api.example.com", "credentials"),
            ("https://api.example.com?x=1", "invalid host"),
            ("https://api.example.com/v1?x=1", "unsupported characters"),
            ("https://api.example.com/v1#frag", "unsupported characters"),
            ("https://api.example.com/a/../b", "`..`"),
            ("https://api.example.com/a%2Fb", "unsupported characters"),
            ("https://api.example.com//a", "empty segments"),
            ("https://api.example.com:0", "invalid port"),
            ("https://api.example.com:99999", "invalid port"),
            ("https://api.example.com:+80", "invalid port"),
            ("https://-bad.example.com", "invalid host"),
            ("https://bad..example.com", "invalid host"),
            ("https://[::1]", "invalid host"),
        ] {
            assert_rejected(&format!(r#"base_url = "{url}""#), needle);
        }
    }

    #[test]
    fn rejects_invalid_names() {
        let bad_name = "[providers.OpenAI]\nbase_url = \"https://a.b\"\nsecret = \"K\"\nauth = { kind = \"query\", name = \"k\" }\nallow = [ { method = \"GET\", path = \"/\" } ]\n";
        let err = ProviderRegistry::from_toml(bad_name)
            .unwrap_err()
            .to_string();
        assert!(err.contains("provider names must match"), "{err}");

        assert_rejected(r#"secret = "lowercase""#, "must match [A-Z]");
        assert_rejected(r#"secret = "1KEY""#, "must match [A-Z]");
        assert_rejected(r#"secret = """#, "must match [A-Z]");
    }

    #[test]
    fn rejects_invalid_auth() {
        for (auth, needle) in [
            (
                r#"{ kind = "header", name = "Authorization", format = "Bearer" }"#,
                "must contain `{key}`",
            ),
            (
                r#"{ kind = "header", name = "X-Key", format = "{key}{key}" }"#,
                "exactly once",
            ),
            (
                r#"{ kind = "header", name = "X-Key", format = "{key}\n" }"#,
                "printable ASCII",
            ),
            (
                r#"{ kind = "header", name = "Host" }"#,
                "managed by the proxy",
            ),
            (
                r#"{ kind = "header", name = "Cookie" }"#,
                "managed by the proxy",
            ),
            (
                r#"{ kind = "header", name = "CF-Connecting-IP" }"#,
                "managed by the proxy",
            ),
            (
                r#"{ kind = "header", name = "X-Forwarded-For" }"#,
                "managed by the proxy",
            ),
            (
                r#"{ kind = "header", name = "X-Attestra-Assertion" }"#,
                "managed by the proxy",
            ),
            (
                r#"{ kind = "header", name = "Bad Header" }"#,
                "invalid header name",
            ),
            (r#"{ kind = "header", name = "" }"#, "invalid header name"),
            (
                r#"{ kind = "query", name = "" }"#,
                "invalid query parameter",
            ),
            (
                r#"{ kind = "query", name = "a&b" }"#,
                "invalid query parameter",
            ),
            (
                r#"{ kind = "basic", format = "user:pass" }"#,
                "must contain `{key}`",
            ),
        ] {
            assert_rejected(&format!("auth = {auth}"), needle);
        }
    }

    #[test]
    fn rejects_invalid_allow_rules() {
        assert_rejected("allow = []", "at least one rule");
        for (rule, needle) in [
            (r#"{ method = "TRACE", path = "/x" }"#, "unsupported method"),
            (
                r#"{ method = "CONNECT", path = "/x" }"#,
                "unsupported method",
            ),
            (r#"{ method = "GET", path = "x" }"#, "must start with `/`"),
            (r#"{ method = "GET", path = "" }"#, "must start with `/`"),
            (r#"{ method = "GET", path = "/a//b" }"#, "empty segments"),
            (r#"{ method = "GET", path = "/a/../b" }"#, "`..`"),
            (r#"{ method = "GET", path = "/a/./b" }"#, "`..`"),
            (
                r#"{ method = "GET", path = "/a/b*" }"#,
                "whole path segment",
            ),
            (
                r#"{ method = "GET", path = "/a/**" }"#,
                "whole path segment",
            ),
            (
                r#"{ method = "GET", path = "/a/%2e%2e" }"#,
                "unsupported characters",
            ),
            (
                r#"{ method = "GET", path = "/a b" }"#,
                "unsupported characters",
            ),
            (
                r#"{ method = "GET", path = "/a?b=c" }"#,
                "unsupported characters",
            ),
        ] {
            assert_rejected(&format!("allow = [ {rule} ]"), needle);
        }
    }

    #[test]
    fn rejects_invalid_limits() {
        assert_rejected("rate_limit = {}", "per_minute");
        assert_rejected("rate_limit = { per_minute = 0 }", "greater than zero");
        assert_rejected(
            "rate_limit = { per_minute = 5, per_day = 0 }",
            "greater than zero",
        );
        assert_rejected(
            &format!("max_body_bytes = {}", MAX_BODY_BYTES_LIMIT + 1),
            "must not exceed",
        );
        let p = parse_one("max_body_bytes = 0").unwrap();
        assert_eq!(p.max_body_bytes, 0);
        let p = parse_one("rate_limit = { per_day = 10 }").unwrap();
        assert_eq!(
            p.rate_limit,
            Some(RateLimit {
                per_minute: None,
                per_day: Some(10)
            })
        );
    }

    #[test]
    fn reserved_secrets_are_rejected() {
        let registry =
            ProviderRegistry::from_toml(&doc(r#"secret = "SESSION_SIGNING_KEY""#)).unwrap();
        let err = registry
            .ensure_secrets_not_reserved(&["SESSION_SIGNING_KEY"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");

        let registry = ProviderRegistry::from_toml(SPEC_EXAMPLE).unwrap();
        registry
            .ensure_secrets_not_reserved(&["SESSION_SIGNING_KEY"])
            .unwrap();
    }
}

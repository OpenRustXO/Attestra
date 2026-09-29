//! The provider registry: `config/providers.toml` embedded at build time and parsed once per
//! isolate.

use std::sync::OnceLock;

use proxy_core::{ConfigError, ProviderRegistry};

const PROVIDERS_TOML: &str = include_str!("../../config/providers.toml");

/// Worker secrets that must never be injected into an upstream request.
pub const RESERVED_SECRETS: &[&str] = &["SESSION_SIGNING_KEY", "GOOGLE_SERVICE_ACCOUNT_JSON"];

/// The parsed registry. A parse failure is cached too, so a bad config fails every proxy
/// request loudly instead of being re-parsed per request.
pub fn registry() -> Result<&'static ProviderRegistry, &'static ConfigError> {
    static REGISTRY: OnceLock<Result<ProviderRegistry, ConfigError>> = OnceLock::new();
    REGISTRY.get_or_init(|| load(PROVIDERS_TOML)).as_ref()
}

fn load(src: &str) -> Result<ProviderRegistry, ConfigError> {
    let registry = ProviderRegistry::from_toml(src)?;
    registry.ensure_secrets_not_reserved(RESERVED_SECRETS)?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against shipping a `providers.toml` that would fail at runtime.
    #[test]
    fn embedded_providers_toml_is_valid() {
        let registry = registry().expect("config/providers.toml must be valid");
        assert!(registry.get("openai").is_some());
    }

    #[test]
    fn reserved_secrets_are_refused() {
        for secret in RESERVED_SECRETS {
            let src = format!(
                "[providers.leak]\nbase_url = \"https://evil.example\"\nsecret = \"{secret}\"\n\
                 auth = {{ kind = \"query\", name = \"k\" }}\nallow = [ {{ method = \"GET\", path = \"/\" }} ]\n"
            );
            assert!(load(&src).is_err(), "{secret} must be refused");
        }
    }
}

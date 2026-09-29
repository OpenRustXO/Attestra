//! Runtime configuration read from wrangler `[vars]`.
//!
//! Parsing is decoupled from the Workers `Env` through a lookup closure so it can be tested on
//! the host. A platform whose variables are all empty is disabled; a platform that is only
//! partially configured is a configuration error.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD_INDIFFERENT, URL_SAFE_NO_PAD_INDIFFERENT};

/// Names of the environment variables read by [`Config::from_lookup`].
pub mod vars {
    pub const APPLE_TEAM_ID: &str = "APPLE_TEAM_ID";
    pub const APPLE_BUNDLE_IDS: &str = "APPLE_BUNDLE_IDS";
    pub const APPLE_ALLOW_DEVELOPMENT: &str = "APPLE_ALLOW_DEVELOPMENT";
    pub const ANDROID_PACKAGE_NAMES: &str = "ANDROID_PACKAGE_NAMES";
    pub const ANDROID_CERT_SHA256: &str = "ANDROID_CERT_SHA256";
    pub const ANDROID_REQUIRE_LICENSED: &str = "ANDROID_REQUIRE_LICENSED";
    pub const SESSION_TTL_SECONDS: &str = "SESSION_TTL_SECONDS";
    pub const CHALLENGE_TTL_SECONDS: &str = "CHALLENGE_TTL_SECONDS";
}

pub const DEFAULT_SESSION_TTL_SECONDS: u64 = 900;
pub const DEFAULT_CHALLENGE_TTL_SECONDS: u64 = 120;
const SESSION_TTL_RANGE: std::ops::RangeInclusive<u64> = 60..=86_400;
const CHALLENGE_TTL_RANGE: std::ops::RangeInclusive<u64> = 10..=600;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{name} is required when {because} is set")]
    Missing {
        name: &'static str,
        because: &'static str,
    },
    #[error("{name} is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

fn invalid(name: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        name,
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `None` when iOS is not configured.
    pub apple: Option<AppleConfig>,
    /// `None` when Android is not configured.
    pub android: Option<AndroidConfig>,
    pub session_ttl_seconds: u64,
    pub challenge_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleConfig {
    pub team_id: String,
    pub bundle_ids: Vec<String>,
    /// Accept attestations from the `appattestdevelop` environment.
    pub allow_development: bool,
}

impl AppleConfig {
    /// App IDs (`<TEAM_ID>.<bundle_id>`); the App Attest rpIdHash is SHA-256 of one of these.
    pub fn app_ids(&self) -> impl Iterator<Item = String> + '_ {
        self.bundle_ids
            .iter()
            .map(move |bundle_id| format!("{}.{bundle_id}", self.team_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidConfig {
    pub package_names: Vec<String>,
    /// SHA-256 digests of the allowed app signing certificates.
    pub cert_sha256: Vec<[u8; 32]>,
    /// Require `accountDetails.appLicensingVerdict == "LICENSED"`.
    pub require_licensed: bool,
}

impl Config {
    /// Builds the configuration from a variable lookup (e.g. `Env::var`).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let apple = match (get(vars::APPLE_TEAM_ID), get(vars::APPLE_BUNDLE_IDS)) {
            (None, None) => None,
            (Some(_), None) => return Err(missing(vars::APPLE_BUNDLE_IDS, vars::APPLE_TEAM_ID)),
            (None, Some(_)) => return Err(missing(vars::APPLE_TEAM_ID, vars::APPLE_BUNDLE_IDS)),
            (Some(team_id), Some(bundle_ids)) => Some(AppleConfig {
                team_id: parse_team_id(&team_id)?,
                bundle_ids: parse_list(vars::APPLE_BUNDLE_IDS, &bundle_ids, parse_bundle_id)?,
                allow_development: parse_bool(
                    vars::APPLE_ALLOW_DEVELOPMENT,
                    get(vars::APPLE_ALLOW_DEVELOPMENT),
                    false,
                )?,
            }),
        };

        let android = match (
            get(vars::ANDROID_PACKAGE_NAMES),
            get(vars::ANDROID_CERT_SHA256),
        ) {
            (None, None) => None,
            (Some(_), None) => {
                return Err(missing(
                    vars::ANDROID_CERT_SHA256,
                    vars::ANDROID_PACKAGE_NAMES,
                ));
            }
            (None, Some(_)) => {
                return Err(missing(
                    vars::ANDROID_PACKAGE_NAMES,
                    vars::ANDROID_CERT_SHA256,
                ));
            }
            (Some(packages), Some(certs)) => Some(AndroidConfig {
                package_names: parse_list(
                    vars::ANDROID_PACKAGE_NAMES,
                    &packages,
                    parse_package_name,
                )?,
                cert_sha256: parse_list(vars::ANDROID_CERT_SHA256, &certs, parse_cert_digest)?,
                require_licensed: parse_bool(
                    vars::ANDROID_REQUIRE_LICENSED,
                    get(vars::ANDROID_REQUIRE_LICENSED),
                    true,
                )?,
            }),
        };

        Ok(Self {
            apple,
            android,
            session_ttl_seconds: parse_seconds(
                vars::SESSION_TTL_SECONDS,
                get(vars::SESSION_TTL_SECONDS),
                DEFAULT_SESSION_TTL_SECONDS,
                SESSION_TTL_RANGE,
            )?,
            challenge_ttl_seconds: parse_seconds(
                vars::CHALLENGE_TTL_SECONDS,
                get(vars::CHALLENGE_TTL_SECONDS),
                DEFAULT_CHALLENGE_TTL_SECONDS,
                CHALLENGE_TTL_RANGE,
            )?,
        })
    }
}

fn missing(name: &'static str, because: &'static str) -> ConfigError {
    ConfigError::Missing { name, because }
}

/// Parses a comma-separated list, ignoring blank entries and duplicates.
fn parse_list<T: PartialEq>(
    name: &'static str,
    raw: &str,
    parse_item: impl Fn(&str) -> Result<T, String>,
) -> Result<Vec<T>, ConfigError> {
    let mut items = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let item = parse_item(entry).map_err(|reason| invalid(name, reason))?;
        if !items.contains(&item) {
            items.push(item);
        }
    }
    if items.is_empty() {
        return Err(invalid(name, "list is empty"));
    }
    Ok(items)
}

fn parse_bool(name: &'static str, raw: Option<String>, default: bool) -> Result<bool, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(invalid(
            name,
            format!("expected true or false, got `{raw}`"),
        )),
    }
}

fn parse_seconds(
    name: &'static str,
    raw: Option<String>,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    match raw.parse::<u64>() {
        Ok(v) if range.contains(&v) => Ok(v),
        _ => Err(invalid(
            name,
            format!(
                "expected an integer between {} and {}, got `{raw}`",
                range.start(),
                range.end()
            ),
        )),
    }
}

fn parse_team_id(raw: &str) -> Result<String, ConfigError> {
    if raw.len() == 10
        && raw
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        Ok(raw.to_owned())
    } else {
        Err(invalid(
            vars::APPLE_TEAM_ID,
            "expected 10 uppercase letters or digits",
        ))
    }
}

fn parse_bundle_id(raw: &str) -> Result<String, String> {
    let valid = raw.len() <= 155
        && raw.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if valid {
        Ok(raw.to_owned())
    } else {
        Err(format!("`{raw}` is not a valid bundle identifier"))
    }
}

fn parse_package_name(raw: &str) -> Result<String, String> {
    let valid_segment = |part: &str| {
        part.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    if raw.len() <= 255 && raw.contains('.') && raw.split('.').all(valid_segment) {
        Ok(raw.to_owned())
    } else {
        Err(format!("`{raw}` is not a valid Android package name"))
    }
}

/// Accepts a SHA-256 digest as hex (optionally `:`-separated, as printed by `keytool`) or as
/// base64 / base64url (padding optional, as returned by Play Integrity).
fn parse_cert_digest(raw: &str) -> Result<[u8; 32], String> {
    let hex_digits: String = raw.chars().filter(|c| *c != ':').collect();
    let bytes = if hex_digits.len() == 64 && hex_digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(&hex_digits).map_err(|e| e.to_string())?
    } else {
        URL_SAFE_NO_PAD_INDIFFERENT
            .decode(raw)
            .or_else(|_| STANDARD_NO_PAD_INDIFFERENT.decode(raw))
            .map_err(|_| format!("`{raw}` is neither hex nor base64"))?
    };
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("`{raw}` is not a 32-byte SHA-256 digest"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const DIGEST_HEX: &str = "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc";

    fn digest() -> [u8; 32] {
        hex::decode(DIGEST_HEX).unwrap().try_into().unwrap()
    }

    fn full_env() -> HashMap<&'static str, String> {
        HashMap::from([
            (vars::APPLE_TEAM_ID, "ABCDE12345".to_owned()),
            (
                vars::APPLE_BUNDLE_IDS,
                "com.example.app, com.example.app.beta".to_owned(),
            ),
            (vars::APPLE_ALLOW_DEVELOPMENT, "true".to_owned()),
            (vars::ANDROID_PACKAGE_NAMES, "com.example.app".to_owned()),
            (vars::ANDROID_CERT_SHA256, DIGEST_HEX.to_owned()),
            (vars::ANDROID_REQUIRE_LICENSED, "false".to_owned()),
            (vars::SESSION_TTL_SECONDS, "600".to_owned()),
            (vars::CHALLENGE_TTL_SECONDS, "60".to_owned()),
        ])
    }

    fn parse(env: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| env.get(name).cloned())
    }

    fn parse_with(overrides: &[(&'static str, &str)]) -> Result<Config, ConfigError> {
        let mut env = full_env();
        for (k, v) in overrides {
            env.insert(k, (*v).to_owned());
        }
        parse(&env)
    }

    fn invalid_var(result: Result<Config, ConfigError>) -> &'static str {
        match result {
            Err(ConfigError::Invalid { name, .. }) => name,
            other => panic!("expected invalid config, got {other:?}"),
        }
    }

    #[test]
    fn parses_full_configuration() {
        let config = parse(&full_env()).unwrap();
        let apple = config.apple.unwrap();
        assert_eq!(apple.team_id, "ABCDE12345");
        assert_eq!(
            apple.bundle_ids,
            ["com.example.app", "com.example.app.beta"]
        );
        assert!(apple.allow_development);
        assert_eq!(
            apple.app_ids().collect::<Vec<_>>(),
            [
                "ABCDE12345.com.example.app",
                "ABCDE12345.com.example.app.beta"
            ]
        );

        let android = config.android.unwrap();
        assert_eq!(android.package_names, ["com.example.app"]);
        assert_eq!(android.cert_sha256, [digest()]);
        assert!(!android.require_licensed);

        assert_eq!(config.session_ttl_seconds, 600);
        assert_eq!(config.challenge_ttl_seconds, 60);
    }

    #[test]
    fn empty_environment_disables_platforms_and_uses_defaults() {
        let config = Config::from_lookup(|_| None).unwrap();
        assert_eq!(config.apple, None);
        assert_eq!(config.android, None);
        assert_eq!(config.session_ttl_seconds, DEFAULT_SESSION_TTL_SECONDS);
        assert_eq!(config.challenge_ttl_seconds, DEFAULT_CHALLENGE_TTL_SECONDS);

        // Blank values are treated as unset.
        let config = Config::from_lookup(|_| Some("  ".to_owned())).unwrap();
        assert_eq!(config.apple, None);
        assert_eq!(config.android, None);
    }

    #[test]
    fn optional_flags_have_secure_defaults() {
        let mut env = full_env();
        env.remove(vars::APPLE_ALLOW_DEVELOPMENT);
        env.remove(vars::ANDROID_REQUIRE_LICENSED);
        let config = parse(&env).unwrap();
        assert!(!config.apple.unwrap().allow_development);
        assert!(config.android.unwrap().require_licensed);
    }

    #[test]
    fn partially_configured_platform_is_an_error() {
        for (removed, expected) in [
            (vars::APPLE_BUNDLE_IDS, vars::APPLE_BUNDLE_IDS),
            (vars::APPLE_TEAM_ID, vars::APPLE_TEAM_ID),
            (vars::ANDROID_CERT_SHA256, vars::ANDROID_CERT_SHA256),
            (vars::ANDROID_PACKAGE_NAMES, vars::ANDROID_PACKAGE_NAMES),
        ] {
            let mut env = full_env();
            env.remove(removed);
            match parse(&env) {
                Err(ConfigError::Missing { name, .. }) => assert_eq!(name, expected),
                other => panic!("removing {removed}: {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_invalid_values() {
        for (var, value) in [
            (vars::APPLE_TEAM_ID, "abcde12345"),
            (vars::APPLE_TEAM_ID, "ABCDE1234"),
            (vars::APPLE_TEAM_ID, "<TEAM_ID>"),
            (vars::APPLE_BUNDLE_IDS, "com..example"),
            (vars::APPLE_BUNDLE_IDS, "com.example app"),
            (vars::APPLE_BUNDLE_IDS, ",,"),
            (vars::APPLE_ALLOW_DEVELOPMENT, "maybe"),
            (vars::ANDROID_PACKAGE_NAMES, "example"),
            (vars::ANDROID_PACKAGE_NAMES, "com.1example"),
            (vars::ANDROID_PACKAGE_NAMES, "com.example-app"),
            (vars::ANDROID_CERT_SHA256, "zz"),
            (vars::ANDROID_CERT_SHA256, "a40da80a"),
            (vars::ANDROID_REQUIRE_LICENSED, "on"),
            (vars::SESSION_TTL_SECONDS, "abc"),
            (vars::SESSION_TTL_SECONDS, "-1"),
            (vars::SESSION_TTL_SECONDS, "59"),
            (vars::SESSION_TTL_SECONDS, "86401"),
            (vars::CHALLENGE_TTL_SECONDS, "5"),
            (vars::CHALLENGE_TTL_SECONDS, "601"),
        ] {
            assert_eq!(
                invalid_var(parse_with(&[(var, value)])),
                var,
                "{var}={value}"
            );
        }
    }

    #[test]
    fn accepts_all_cert_digest_encodings() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        let colon_hex = digest()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        for encoded in [
            DIGEST_HEX.to_owned(),
            DIGEST_HEX.to_uppercase(),
            colon_hex,
            STANDARD.encode(digest()),
            URL_SAFE_NO_PAD.encode(digest()),
        ] {
            assert_eq!(parse_cert_digest(&encoded), Ok(digest()), "{encoded}");
        }
    }

    #[test]
    fn lists_are_trimmed_and_deduplicated() {
        let config = parse_with(&[
            (vars::APPLE_BUNDLE_IDS, " com.a.b ,com.a.b,, com.c.d "),
            (
                vars::ANDROID_CERT_SHA256,
                &format!("{DIGEST_HEX},{}", DIGEST_HEX.to_uppercase()),
            ),
        ])
        .unwrap();
        assert_eq!(config.apple.unwrap().bundle_ids, ["com.a.b", "com.c.d"]);
        assert_eq!(config.android.unwrap().cert_sha256.len(), 1);
    }
}

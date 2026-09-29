//! Request/response rewriting: header filtering, query handling and key injection.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::{AuthConfig, Provider, ProxyError, RequestPath};

/// Request headers never forwarded upstream (besides `cf-*`, `x-forwarded-*` and the
/// provider's own auth header).
const DROPPED_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "forwarded",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "true-client-ip",
    "upgrade",
    "x-attestra-assertion",
    "x-attestra-timestamp",
    "x-real-ip",
];
const DROPPED_REQUEST_PREFIXES: &[&str] = &["cf-", "x-forwarded-"];

/// Response headers never returned to the client. `content-length` is dropped because the
/// runtime may transparently decode and re-encode the streamed body.
const DROPPED_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "set-cookie",
    "set-cookie2",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

impl Provider {
    /// Whether a client request header may be forwarded to this provider.
    pub fn forwards_request_header(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        !(DROPPED_REQUEST_HEADERS.contains(&name.as_str())
            || DROPPED_REQUEST_PREFIXES.iter().any(|p| name.starts_with(p))
            || self.auth.header_name() == Some(name.as_str()))
    }

    /// The header carrying the API key, if the provider authenticates with a header.
    pub fn auth_header(&self, key: &str) -> Result<Option<(String, String)>, ProxyError> {
        let key = checked_key(key)?;
        Ok(match &self.auth {
            AuthConfig::Header { name, format } => Some((name.clone(), format.render(key))),
            AuthConfig::Basic { format } => Some((
                "authorization".to_owned(),
                format!("Basic {}", STANDARD.encode(format.render(key))),
            )),
            AuthConfig::Query { .. } => None,
        })
    }

    /// The full upstream URL: base URL + validated path + client query (minus any parameter
    /// colliding with the auth parameter) + the auth parameter for query auth.
    pub fn upstream_url(
        &self,
        path: &RequestPath,
        query: Option<&str>,
        key: &str,
    ) -> Result<String, ProxyError> {
        let key = checked_key(key)?;
        let reserved = self.auth.query_param();
        let mut params: Vec<String> = query
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
            .filter(|pair| {
                let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
                reserved.is_none_or(|reserved| !same_param(name, reserved))
            })
            .map(str::to_owned)
            .collect();
        if let AuthConfig::Query { name } = &self.auth {
            params.push(format!("{name}={}", percent_encode(key)));
        }

        let mut url = format!(
            "{}{}{}",
            self.base_url.origin(),
            self.base_url.path_prefix(),
            path.as_str()
        );
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        Ok(url)
    }
}

/// Whether a client response header may be returned to the client.
pub fn forwards_response_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !(DROPPED_RESPONSE_HEADERS.contains(&name.as_str()) || name.starts_with("access-control-"))
}

/// Compares a raw (possibly percent-encoded) query parameter name with the auth parameter,
/// case-insensitively, so `KEY=` or `%6Bey=` cannot smuggle a second key past the proxy.
fn same_param(raw_name: &str, reserved: &str) -> bool {
    let decoded = percent_decode_lossy(&raw_name.replace('+', " "));
    decoded.eq_ignore_ascii_case(reserved)
}

fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let escaped = (b == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(decoded) => {
                out.push(decoded);
                i += 3;
            }
            None => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Secrets are trimmed (a trailing newline sneaks in easily) and must be printable ASCII so
/// they cannot inject extra header lines.
fn checked_key(key: &str) -> Result<&str, ProxyError> {
    let key = key.trim();
    if key.is_empty() || !key.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(ProxyError::InvalidSecret);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderRegistry;

    fn provider(auth: &str, base_url: &str) -> Provider {
        let src = format!(
            "[providers.p]\nbase_url = \"{base_url}\"\nsecret = \"K\"\nauth = {auth}\nallow = [ {{ method = \"GET\", path = \"/*\" }} ]\n"
        );
        ProviderRegistry::from_toml(&src)
            .unwrap()
            .get("p")
            .unwrap()
            .clone()
    }

    fn path(p: &str) -> RequestPath {
        RequestPath::parse(p).unwrap()
    }

    #[test]
    fn strips_sensitive_request_headers() {
        let p = provider(
            r#"{ kind = "header", name = "X-Api-Key" }"#,
            "https://api.example.com",
        );
        for name in [
            "Authorization",
            "cookie",
            "Host",
            "CF-Connecting-IP",
            "cf-ipcountry",
            "X-Forwarded-For",
            "x-forwarded-proto",
            "X-Real-IP",
            "Forwarded",
            "True-Client-IP",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "X-Api-Key",
            "x-api-key",
            "X-Attestra-Assertion",
            "X-Attestra-Timestamp",
        ] {
            assert!(!p.forwards_request_header(name), "{name}");
        }
        for name in [
            "content-type",
            "accept",
            "user-agent",
            "openai-beta",
            "x-goog-api-client",
        ] {
            assert!(p.forwards_request_header(name), "{name}");
        }
    }

    #[test]
    fn injects_header_and_basic_auth() {
        let p = provider(
            r#"{ kind = "header", name = "Authorization", format = "Bearer {key}" }"#,
            "https://api.example.com",
        );
        assert_eq!(
            p.auth_header("sk-123\n").unwrap(),
            Some(("authorization".into(), "Bearer sk-123".into()))
        );
        let p = provider(
            r#"{ kind = "basic", format = "api:{key}" }"#,
            "https://api.example.com",
        );
        assert_eq!(
            p.auth_header("s3cret").unwrap(),
            Some((
                "authorization".into(),
                format!("Basic {}", STANDARD.encode("api:s3cret"))
            ))
        );
        let p = provider(
            r#"{ kind = "query", name = "key" }"#,
            "https://api.example.com",
        );
        assert_eq!(p.auth_header("k").unwrap(), None);
    }

    #[test]
    fn rejects_unusable_secrets() {
        let p = provider(
            r#"{ kind = "header", name = "X-Api-Key" }"#,
            "https://api.example.com",
        );
        for key in ["", "   ", "a\r\nX-Evil: 1", "tab\tinside", "caf\u{e9}"] {
            assert_eq!(
                p.auth_header(key),
                Err(ProxyError::InvalidSecret),
                "{key:?}"
            );
            assert_eq!(
                p.upstream_url(&path("/"), None, key),
                Err(ProxyError::InvalidSecret)
            );
        }
    }

    #[test]
    fn builds_upstream_urls() {
        let p = provider(
            r#"{ kind = "header", name = "X-Api-Key" }"#,
            "https://api.example.com/v2/",
        );
        assert_eq!(
            p.upstream_url(&path("/models/x"), Some("a=1&b=two"), "k")
                .unwrap(),
            "https://api.example.com/v2/models/x?a=1&b=two"
        );
        assert_eq!(
            p.upstream_url(&path("/"), None, "k").unwrap(),
            "https://api.example.com/v2/"
        );
        assert_eq!(
            p.upstream_url(&path("/x"), Some(""), "k").unwrap(),
            "https://api.example.com/v2/x"
        );
    }

    #[test]
    fn query_auth_replaces_client_supplied_key() {
        let p = provider(
            r#"{ kind = "query", name = "key" }"#,
            "https://maps.googleapis.com",
        );
        let url = p
            .upstream_url(
                &path("/maps/api/place/details/json"),
                Some("place_id=abc&key=evil&KEY=evil2&%6Bey=evil3&k%65y=evil4&keyword=ok&key"),
                "real key/+&",
            )
            .unwrap();
        assert_eq!(
            url,
            "https://maps.googleapis.com/maps/api/place/details/json?place_id=abc&keyword=ok&key=real%20key%2F%2B%26"
        );
        // Header auth leaves a `key` query parameter alone.
        let p = provider(
            r#"{ kind = "header", name = "X-Api-Key" }"#,
            "https://api.example.com",
        );
        assert_eq!(
            p.upstream_url(&path("/x"), Some("key=1"), "k").unwrap(),
            "https://api.example.com/x?key=1"
        );
    }

    #[test]
    fn filters_response_headers() {
        for name in [
            "Set-Cookie",
            "set-cookie2",
            "Transfer-Encoding",
            "Content-Length",
            "Access-Control-Allow-Origin",
        ] {
            assert!(!forwards_response_header(name), "{name}");
        }
        for name in [
            "content-type",
            "cache-control",
            "x-request-id",
            "content-encoding",
            "retry-after",
        ] {
            assert!(forwards_response_header(name), "{name}");
        }
    }
}

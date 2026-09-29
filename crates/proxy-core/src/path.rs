//! Request-path normalization and allowlist matching.

use crate::{Method, PatternSegment, Provider, ProxyError};

const MAX_PATH_LEN: usize = 2048;

/// A validated upstream path: safe to forward verbatim, with decoded segments for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPath {
    raw: String,
    segments: Vec<String>,
}

impl RequestPath {
    /// Validates a still percent-encoded path (as seen in the request URL).
    ///
    /// Traversal is rejected before anything else happens: `.`/`..` segments, empty segments,
    /// backslashes, control characters, and any percent-encoding that decodes to `/`, `\`,
    /// `.`, `%` or a control character (which also rules out double encoding such as
    /// `%252e`). Because nothing dangerous can hide behind an escape, the raw path is
    /// forwarded unchanged.
    pub fn parse(raw: &str) -> Result<Self, ProxyError> {
        let invalid = ProxyError::InvalidPath;
        if raw.len() > MAX_PATH_LEN {
            return Err(invalid("too long"));
        }
        let rest = raw
            .strip_prefix('/')
            .ok_or(invalid("must start with `/`"))?;
        if rest.is_empty() {
            return Ok(Self {
                raw: raw.to_owned(),
                segments: Vec::new(),
            });
        }

        let mut segments = Vec::new();
        let mut parts = rest.split('/').peekable();
        while let Some(part) = parts.next() {
            let is_last = parts.peek().is_none();
            if part.is_empty() && !is_last {
                return Err(invalid("empty segment"));
            }
            let decoded = decode_segment(part)?;
            if decoded == "." || decoded == ".." {
                return Err(invalid("dot segment"));
            }
            segments.push(decoded);
        }
        Ok(Self {
            raw: raw.to_owned(),
            segments,
        })
    }

    /// The path as received (percent-encoded), safe to forward.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Decoded segments; a trailing slash yields a final empty segment.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

fn decode_segment(segment: &str) -> Result<String, ProxyError> {
    let invalid = ProxyError::InvalidPath;
    let mut out = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = bytes.next().and_then(hex_value);
                let lo = bytes.next().and_then(hex_value);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(invalid("malformed percent-encoding"));
                };
                let decoded = hi << 4 | lo;
                if matches!(decoded, b'/' | b'\\' | b'.' | b'%') || decoded.is_ascii_control() {
                    return Err(invalid("forbidden percent-encoded character"));
                }
                out.push(decoded);
            }
            b'\\' => return Err(invalid("backslash")),
            b'?' | b'#' => return Err(invalid("unexpected delimiter")),
            _ if b.is_ascii_control() || !b.is_ascii() => {
                return Err(invalid("unencoded special character"));
            }
            _ => out.push(b),
        }
    }
    String::from_utf8(out).map_err(|_| invalid("segment is not UTF-8"))
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Whether `pattern` matches `path`; `*` matches one or more whole, non-empty segments.
pub fn pattern_matches(pattern: &[PatternSegment], path: &[String]) -> bool {
    // reachable[j]: the pattern prefix seen so far can consume exactly path[..j].
    let n = path.len();
    let mut reachable = vec![false; n + 1];
    reachable[0] = true;
    for segment in pattern {
        let mut next = vec![false; n + 1];
        for start in (0..n).filter(|&j| reachable[j]) {
            match segment {
                PatternSegment::Literal(literal) => {
                    if path[start] == *literal {
                        next[start + 1] = true;
                    }
                }
                PatternSegment::Wildcard => {
                    for end in start + 1..=n {
                        if path[end - 1].is_empty() {
                            break;
                        }
                        next[end] = true;
                    }
                }
            }
        }
        reachable = next;
    }
    reachable[n]
}

impl Provider {
    /// Checks the method and path against the allowlist.
    pub fn authorize(&self, method: &str, path: &RequestPath) -> Result<(), ProxyError> {
        let allowed = Method::parse(method).is_some_and(|method| {
            self.allow.iter().any(|rule| {
                rule.method == method && pattern_matches(rule.path.segments(), path.segments())
            })
        });
        if allowed {
            Ok(())
        } else {
            Err(ProxyError::NotAllowed {
                method: method.to_owned(),
                path: path.as_str().to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PathPattern, ProviderRegistry};

    fn segs(path: &str) -> Vec<String> {
        RequestPath::parse(path).unwrap().segments().to_vec()
    }

    fn matches(pattern: &str, path: &str) -> bool {
        pattern_matches(PathPattern::parse(pattern).unwrap().segments(), &segs(path))
    }

    #[test]
    fn parses_and_decodes_paths() {
        assert_eq!(segs("/"), Vec::<String>::new());
        assert_eq!(segs("/v1/chat/completions"), ["v1", "chat", "completions"]);
        assert_eq!(segs("/a/"), ["a", ""]);
        assert_eq!(
            segs("/models/gemini%3AgenerateContent"),
            ["models", "gemini:generateContent"]
        );
        assert_eq!(segs("/caf%C3%A9"), ["café"]);
        assert_eq!(RequestPath::parse("/a%20b").unwrap().as_str(), "/a%20b");
    }

    #[test]
    fn rejects_traversal_and_encoding_tricks() {
        for path in [
            "",
            "a/b",
            "/a/../b",
            "/..",
            "/a/./b",
            "/.",
            "/a//b",
            "//a",
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a/.%2e/b",
            "/a/%2e./b",
            "/a/%2e/b",
            "/a%2fb",
            "/a%2Fb",
            "/a%5cb",
            "/a\\b",
            "/a%00b",
            "/a%0ab",
            "/a%252e%252e/b",
            "/a%25",
            "/a%zz",
            "/a%2",
            "/a%",
            "/a?b",
            "/a#b",
            "/a\u{7f}",
            "/a\tb",
            "/é",
            "/a%ff",
        ] {
            assert!(
                RequestPath::parse(path).is_err(),
                "{path:?} should be rejected"
            );
        }
        assert!(RequestPath::parse(&format!("/{}", "a".repeat(MAX_PATH_LEN))).is_err());
    }

    #[test]
    fn literal_and_wildcard_matching() {
        assert!(matches("/v1/chat/completions", "/v1/chat/completions"));
        assert!(!matches("/v1/chat/completions", "/v1/chat/completions/"));
        assert!(!matches("/v1/chat/completions", "/v1/chat"));
        assert!(!matches("/v1/chat/completions", "/v1/chat/completions/x"));
        assert!(!matches("/v1/chat/completions", "/V1/chat/completions"));

        // `*` is one or more whole segments.
        assert!(matches(
            "/maps/api/place/*",
            "/maps/api/place/nearbysearch/json"
        ));
        assert!(matches("/maps/api/place/*", "/maps/api/place/details"));
        assert!(!matches("/maps/api/place/*", "/maps/api/place"));
        assert!(!matches("/maps/api/place/*", "/maps/api/place/"));
        assert!(!matches("/maps/api/place/*", "/maps/api/placex/details"));

        assert!(matches("/v1/models/*/generate", "/v1/models/a/generate"));
        assert!(matches(
            "/v1/models/*/generate",
            "/v1/models/a/b/c/generate"
        ));
        assert!(!matches("/v1/models/*/generate", "/v1/models/generate"));
        assert!(matches("/*/x/*", "/a/x/b"));
        assert!(matches("/*/x/*", "/a/x/x/x/b"));
        assert!(!matches("/*/x/*", "/a/x"));
        assert!(matches("/", "/"));
        assert!(!matches("/", "/a"));
        assert!(matches("/*", "/a/b/c"));
        assert!(!matches("/*", "/"));
    }

    #[test]
    fn many_wildcards_stay_fast() {
        let pattern = format!("/{}z", "*/".repeat(20));
        let path = format!("/{}", vec!["a"; 60].join("/"));
        assert!(!matches(&pattern, &path));
    }

    #[test]
    fn authorize_checks_method_and_path() {
        let registry = ProviderRegistry::from_toml(
            r#"
            [providers.p]
            base_url = "https://api.example.com"
            secret = "K"
            auth = { kind = "query", name = "key" }
            allow = [
                { method = "POST", path = "/v1/chat/completions" },
                { method = "GET", path = "/v1/models/*" },
            ]
            "#,
        )
        .unwrap();
        let p = registry.get("p").unwrap();
        let path = |s: &str| RequestPath::parse(s).unwrap();
        p.authorize("POST", &path("/v1/chat/completions")).unwrap();
        p.authorize("GET", &path("/v1/models/gpt")).unwrap();
        for (method, raw) in [
            ("GET", "/v1/chat/completions"),
            ("post", "/v1/chat/completions"),
            ("DELETE", "/v1/models/gpt"),
            ("GET", "/v1/models"),
            ("TRACE", "/v1/models/gpt"),
            ("POST", "/v1/embeddings"),
        ] {
            assert!(matches!(
                p.authorize(method, &path(raw)),
                Err(ProxyError::NotAllowed { .. })
            ));
        }
    }
}

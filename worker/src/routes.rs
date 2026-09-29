//! Maps `(method, path)` to a [`Route`].
//!
//! A hand-rolled matcher instead of `worker::Router` so that unmatched routes and wrong methods
//! produce the same JSON error bodies as every other failure. There is deliberately no
//! `OPTIONS` handling: CORS is disabled because only mobile clients call this API.

use crate::error::ApiError;

const PROXY_PREFIX: &str = "/p/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route<'a> {
    /// `POST /challenge`
    Challenge,
    /// `POST /attest/ios`
    AttestIos,
    /// `POST /assert/ios`
    AssertIos,
    /// `POST /attest/android`
    AttestAndroid,
    /// `ANY /p/{provider}/{*path}`. `path` keeps its leading `/` and is still
    /// percent-encoded; normalization and allowlisting happen in `proxy-core`.
    Proxy { provider: &'a str, path: &'a str },
}

pub fn resolve<'a>(method: &str, path: &'a str) -> Result<Route<'a>, ApiError> {
    let route = match path {
        "/challenge" => Route::Challenge,
        "/attest/ios" => Route::AttestIos,
        "/assert/ios" => Route::AssertIos,
        "/attest/android" => Route::AttestAndroid,
        _ => return resolve_proxy(path),
    };
    if method == "POST" {
        Ok(route)
    } else {
        Err(ApiError::MethodNotAllowed { allow: "POST" })
    }
}

fn resolve_proxy(path: &str) -> Result<Route<'_>, ApiError> {
    let rest = path.strip_prefix(PROXY_PREFIX).ok_or(ApiError::NotFound)?;
    let (provider, upstream_path) = rest.split_at(rest.find('/').ok_or(ApiError::NotFound)?);
    if provider.is_empty() {
        return Err(ApiError::NotFound);
    }
    Ok(Route::Proxy {
        provider,
        path: upstream_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(result: Result<Route<'_>, ApiError>) -> &'static str {
        match result {
            Ok(route) => panic!("unexpected route {route:?}"),
            Err(err) => err.code(),
        }
    }

    #[test]
    fn json_endpoints_require_post() {
        for (path, route) in [
            ("/challenge", Route::Challenge),
            ("/attest/ios", Route::AttestIos),
            ("/assert/ios", Route::AssertIos),
            ("/attest/android", Route::AttestAndroid),
        ] {
            assert_eq!(resolve("POST", path).unwrap(), route);
            for method in ["GET", "PUT", "DELETE", "OPTIONS", "HEAD"] {
                assert_eq!(
                    code(resolve(method, path)),
                    "method_not_allowed",
                    "{method} {path}"
                );
            }
        }
    }

    #[test]
    fn proxy_route_accepts_any_method() {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            assert_eq!(
                resolve(method, "/p/openai/v1/chat/completions").unwrap(),
                Route::Proxy {
                    provider: "openai",
                    path: "/v1/chat/completions"
                }
            );
        }
        assert_eq!(
            resolve("GET", "/p/gmaps/").unwrap(),
            Route::Proxy {
                provider: "gmaps",
                path: "/"
            }
        );
        // Encoded segments are passed through untouched for proxy-core to reject.
        assert_eq!(
            resolve("GET", "/p/x/a/%2e%2e/b").unwrap(),
            Route::Proxy {
                provider: "x",
                path: "/a/%2e%2e/b"
            }
        );
    }

    #[test]
    fn unknown_paths_are_not_found() {
        for path in [
            "/",
            "",
            "/v1/challenge",
            "/challenge/",
            "/challengex",
            "/Challenge",
            "/attest",
            "/p",
            "/p/",
            "/p/openai",
            "/p//v1/chat",
            "/v1/p/openai/v1/chat",
        ] {
            assert_eq!(code(resolve("POST", path)), "not_found", "{path}");
        }
    }
}

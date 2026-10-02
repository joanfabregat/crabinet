use axum::{
    body::Body,
    extract::OriginalUri,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use embedded::WebAssets;

// Release builds embed these files. Debug builds make rust-embed read them
// from web/dist at runtime, behind its own canonicalized-prefix check. The
// lint level must sit on a module because derive output does not inherit it.
#[allow(
    clippy::disallowed_methods,
    reason = "debug-only rust-embed reads of the build's own web/dist"
)]
mod embedded {
    use rust_embed::RustEmbed;

    #[derive(RustEmbed)]
    #[folder = "web/dist/"]
    #[include = "*.html"]
    #[include = "assets/*"]
    #[include = "crabinet.png"]
    #[include = "google-g.png"]
    pub(super) struct WebAssets;
}

const INDEX: &str = "index.html";

pub async fn serve(OriginalUri(uri): OriginalUri) -> Response {
    if uri.path().starts_with("/api/") || uri.path().starts_with("/health/") {
        return bare_status(StatusCode::NOT_FOUND);
    }

    let requested = uri.path().trim_start_matches('/');
    let is_asset = requested.starts_with("assets/")
        || requested == "crabinet.png"
        || requested == "google-g.png";
    let path = if requested.is_empty() {
        INDEX
    } else {
        requested
    };
    let (asset_path, file) = match WebAssets::get(path) {
        Some(file) => (path, file),
        None if !is_asset => match WebAssets::get(INDEX) {
            Some(file) => (INDEX, file),
            None => return bare_status(StatusCode::SERVICE_UNAVAILABLE),
        },
        None => return bare_status(StatusCode::NOT_FOUND),
    };

    let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
    let cache = cache_control(asset_path);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, cache)
        .header(header::CONTENT_SECURITY_POLICY, content_security_policy())
        .header("x-content-type-options", "nosniff")
        .body(Body::from(file.data.into_owned()))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal service error").into_response()
        })
}

/// An empty error answer that is neither cached nor content-sniffed.
fn bare_status(status: StatusCode) -> Response {
    let mut response = status.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Only Vite's content-hashed `assets/*` output may be cached immutably.
/// Unhashed files (the HTML shell and `web/public` icons) keep their URL
/// across releases, so browsers must revalidate them.
fn cache_control(asset_path: &str) -> &'static str {
    if asset_path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

pub fn has_index() -> bool {
    WebAssets::get(INDEX).is_some()
}

pub fn content_security_policy() -> HeaderValue {
    HeaderValue::from_static(
        "default-src 'self'; img-src 'self' https://lh3.googleusercontent.com https://www.gravatar.com; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_disables_objects_and_embedding() {
        let header = content_security_policy();
        let value = header.to_str().expect("static header");
        assert!(value.contains("object-src 'none'"));
        assert!(value.contains("frame-ancestors 'none'"));
        assert!(value.contains("img-src 'self' https://lh3.googleusercontent.com"));
        assert!(value.contains("https://www.gravatar.com"));
    }

    #[test]
    fn only_hashed_assets_are_immutable() {
        assert_eq!(
            cache_control("assets/index-3f2a1b.js"),
            "public, max-age=31536000, immutable"
        );
        for unhashed in [INDEX, "crabinet.png", "google-g.png"] {
            assert_eq!(cache_control(unhashed), "no-cache", "{unhashed}");
        }
    }

    #[test]
    fn crabinet_icon_is_embedded() {
        assert!(WebAssets::get("crabinet.png").is_some());
    }

    #[tokio::test]
    async fn google_icon_is_served_as_png() {
        let response = serve(OriginalUri("/google-g.png".parse().unwrap())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    }

    #[tokio::test]
    async fn missing_assets_are_not_cached_or_sniffed() {
        for path in ["/assets/missing.js", "/health/missing", "/api/missing"] {
            let response = serve(OriginalUri(path.parse().unwrap())).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }
}

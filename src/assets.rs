use axum::{
    body::Body,
    extract::OriginalUri,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist/"]
#[include = "*.html"]
#[include = "assets/*"]
#[include = "crabinet.png"]
#[include = "google-g.png"]
struct WebAssets;

const INDEX: &str = "index.html";

pub async fn serve(OriginalUri(uri): OriginalUri) -> Response {
    if uri.path().starts_with("/api/") || uri.path().starts_with("/health/") {
        return StatusCode::NOT_FOUND.into_response();
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
            None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        },
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
    let cache = if asset_path == INDEX {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };

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

pub fn has_index() -> bool {
    WebAssets::get(INDEX).is_some()
}

pub fn content_security_policy() -> HeaderValue {
    HeaderValue::from_static(
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'",
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
}

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
struct WebAssets;

const INDEX: &str = "index.html";

pub async fn serve(OriginalUri(uri): OriginalUri) -> Response {
    if uri.path().starts_with("/api/") || uri.path().starts_with("/health/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let requested = uri.path().trim_start_matches('/');
    let is_asset = requested.starts_with("assets/");
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
}

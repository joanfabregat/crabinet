//! Request extractors whose rejections use the standard JSON error envelope.
//!
//! Axum's own `Path`, `Query`, and `Json` rejections answer with plain-text
//! deserializer messages and none of the API's `Cache-Control: no-store` and
//! `X-Content-Type-Options: nosniff` headers. These wrappers map every
//! rejection to [`AppError`] instead, so a malformed request receives the
//! same generic body and headers as any other refused API call and never
//! echoes request-derived text.

use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Path, Query, Request},
    http::{StatusCode, request::Parts},
};
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// Path parameters; a rejection is `400 invalid_request`.
pub struct ApiPath<T>(pub T);

/// Query parameters; a rejection is `400 invalid_request`.
pub struct ApiQuery<T>(pub T);

/// A JSON body; an oversized body is `413 too_large` and any other
/// rejection, including a missing JSON content type, is `400 invalid_request`.
pub struct ApiJson<T>(pub T);

/// Maps an Axum rejection status to the public error without exposing its
/// message.
fn rejection_error(status: StatusCode) -> AppError {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::TooLarge
    } else if status.is_server_error() {
        AppError::Internal
    } else {
        AppError::InvalidRequest
    }
}

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|rejection| rejection_error(rejection.status()))
    }
}

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|rejection| rejection_error(rejection.status()))
    }
}

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| rejection_error(rejection.status()))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
        routing::post,
    };
    use serde::Deserialize;
    use tower::ServiceExt;

    use super::*;

    #[derive(Deserialize)]
    struct JsonBody {
        #[allow(dead_code)]
        path: String,
    }

    #[derive(Deserialize)]
    struct Params {
        #[allow(dead_code)]
        limit: Option<u32>,
    }

    async fn handler(
        ApiPath(_id): ApiPath<String>,
        ApiQuery(_query): ApiQuery<Params>,
        ApiJson(_body): ApiJson<JsonBody>,
    ) -> StatusCode {
        StatusCode::NO_CONTENT
    }

    fn app() -> Router {
        Router::new()
            .route("/items/{id}", post(handler))
            .layer(axum::extract::DefaultBodyLimit::max(64))
    }

    async fn send(uri: &str, content_type: Option<&str>, body: &str) -> axum::response::Response {
        let mut request = Request::post(uri);
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        app()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn malformed_requests_use_the_json_error_envelope() {
        let json = Some("application/json");
        let long = format!(r#"{{"path":"{}"}}"#, "x".repeat(128));
        let cases = [
            (
                "/items/a?limit=-1",
                json,
                r#"{"path":"a"}"#,
                400,
                "invalid_request",
            ),
            (
                "/items/%FF",
                json,
                r#"{"path":"a"}"#,
                400,
                "invalid_request",
            ),
            ("/items/a", json, r#"{"path":"#, 400, "invalid_request"),
            ("/items/a", json, r#"{"path":7}"#, 400, "invalid_request"),
            ("/items/a", None, r#"{"path":"a"}"#, 400, "invalid_request"),
            ("/items/a", json, long.as_str(), 413, "too_large"),
        ];
        for (uri, content_type, body, status, code) in cases {
            let response = send(uri, content_type, body).await;
            assert_eq!(response.status().as_u16(), status, "{uri} {body}");
            let headers = response.headers();
            assert_eq!(headers[header::CONTENT_TYPE], "application/json");
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers["x-content-type-options"], "nosniff");
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains(code), "{text}");
            let lower = text.to_ascii_lowercase();
            for leak in ["failed", "expected", "deserialize", "path", "%ff"] {
                assert!(!lower.contains(leak), "{text}");
            }
        }
        assert_eq!(
            send("/items/a?limit=3", json, r#"{"path":"a"}"#)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
}

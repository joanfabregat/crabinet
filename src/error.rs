use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication required")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error("service is not ready")]
    NotReady,
    #[error("request was invalid")]
    InvalidRequest,
    #[error("resource state changed")]
    Conflict,
    #[error("request exceeds a configured limit")]
    TooLarge,
    #[error("resource is not valid UTF-8 text")]
    UnsupportedMedia,
    #[error("internal service error")]
    Internal,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl AppError {
    fn public_parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "Resource not found"),
            Self::NotReady => (
                StatusCode::SERVICE_UNAVAILABLE,
                "not_ready",
                "Service is not ready",
            ),
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Request was invalid",
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "Resource state changed; restart the operation",
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "Request exceeds a configured limit",
            ),
            Self::UnsupportedMedia => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Resource is not supported as text",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal service error",
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.public_parts();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody { code, message },
            }),
        )
            .into_response();
        response.headers_mut().insert(
            "x-content-type-options",
            axum::http::HeaderValue::from_static("nosniff"),
        );
        response
    }
}

pub async fn api_not_found() -> AppError {
    AppError::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_errors_do_not_expose_internal_display_text() {
        let (_, code, message) = AppError::Internal.public_parts();
        assert_eq!(code, "internal_error");
        assert_eq!(message, "Internal service error");
    }
}

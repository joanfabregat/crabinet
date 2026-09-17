use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, HeaderValue, Request},
    middleware,
    routing::get,
};
use serde::Serialize;
use tower_http::{
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{assets, auth, browse, error, mutations, preview};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
pub struct AppState {
    ready: Arc<AtomicBool>,
    browse: Arc<browse::BrowseState>,
    preview_policy: preview::PreviewPolicy,
    auth: Option<auth::AuthService>,
    mutations: Arc<mutations::MutationState>,
}

impl AppState {
    pub fn new(ready: bool) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(ready)),
            browse: Arc::new(browse::BrowseState::disabled()),
            preview_policy: preview::PreviewPolicy::default(),
            auth: None,
            mutations: Arc::new(mutations::MutationState::default()),
        }
    }

    #[must_use]
    pub fn with_browse(mut self, browse: browse::BrowseState) -> Self {
        self.browse = Arc::new(browse);
        self
    }

    #[must_use]
    pub fn browse(&self) -> &browse::BrowseState {
        &self.browse
    }

    #[must_use]
    pub fn with_preview_policy(mut self, policy: preview::PreviewPolicy) -> Self {
        self.preview_policy = policy;
        self
    }

    #[must_use]
    pub fn with_mutations(mut self, mutations: mutations::MutationState) -> Self {
        self.mutations = Arc::new(mutations);
        self
    }

    #[must_use]
    pub const fn preview_policy(&self) -> preview::PreviewPolicy {
        self.preview_policy
    }

    pub fn with_auth(ready: bool, auth: auth::AuthService) -> Self {
        Self::new(ready).with_auth_service(auth)
    }

    #[must_use]
    pub fn with_auth_service(mut self, auth: auth::AuthService) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn auth(&self) -> Option<&auth::AuthService> {
        self.auth.as_ref()
    }

    #[must_use]
    pub fn mutations(&self) -> &mutations::MutationState {
        &self.mutations
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
struct SequenceRequestId;

impl MakeRequestId for SequenceRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let value = HeaderValue::from_str(&format!("req-{sequence:016x}"))
            .expect("hex request ID is a valid header");
        Some(RequestId::new(value))
    }
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn live() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> Result<Json<Health>, error::AppError> {
    if state.is_ready() {
        Ok(Json(Health { status: "ready" }))
    } else {
        Err(error::AppError::NotReady)
    }
}

pub fn router(state: AppState) -> Router {
    let reads = browse::router().merge(preview::router());
    let writes = mutations::router(state.mutations().http_body_limit());
    let (reads, writes) = if state.auth().is_some() {
        (
            reads.route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth::require_authentication,
            )),
            writes.route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth::require_state_change,
            )),
        )
    } else {
        // Isolated handler tests inject verified request extensions directly.
        // Without them, every protected extractor still fails closed.
        (reads, writes)
    };
    let api = Router::new()
        .merge(auth::router())
        .merge(reads)
        .merge(writes)
        .fallback(error::api_not_found);

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .nest("/api/v1", api)
        .route("/api/{*path}", get(error::api_not_found))
        .fallback(assets::serve)
        .with_state(state)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = request
                    .headers()
                    .get(&REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("missing");
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    request_id = %request_id
                )
            }),
        )
        .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER.clone()))
        .layer(SetRequestIdLayer::new(
            REQUEST_ID_HEADER.clone(),
            SequenceRequestId,
        ))
}

use axum::body::Body;

#[cfg(test)]
mod tests {
    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn liveness_is_independent_of_readiness() {
        let app = router(AppState::new(false));
        let live_response = app
            .clone()
            .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(live_response.status(), StatusCode::OK);

        let ready_response = app
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn unknown_api_never_returns_the_spa() {
        let response = router(AppState::new(true))
            .oneshot(Request::get("/api/v1/missing").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("not_found"));
    }

    #[tokio::test]
    async fn every_response_has_a_request_id() {
        let response = router(AppState::new(true))
            .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(response.headers().contains_key(&REQUEST_ID_HEADER));
    }
}

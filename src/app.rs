use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, HeaderValue, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tower_http::{
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{assets, auth, browse, error, mutations, oidc, preview, thumbnail};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
pub struct AppState {
    ready: Arc<AtomicBool>,
    browse: Arc<browse::BrowseState>,
    preview_policy: preview::PreviewPolicy,
    auth: Option<auth::AuthService>,
    oidc: Option<oidc::OidcService>,
    mutations: Arc<mutations::MutationState>,
    trash_retention_days: u16,
    thumbnails: Arc<thumbnail::ThumbnailService>,
}

impl AppState {
    pub fn new(ready: bool) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(ready)),
            browse: Arc::new(browse::BrowseState::disabled()),
            preview_policy: preview::PreviewPolicy::default(),
            auth: None,
            oidc: None,
            mutations: Arc::new(mutations::MutationState::default()),
            trash_retention_days: 30,
            thumbnails: Arc::new(thumbnail::ThumbnailService::default()),
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
    pub fn with_oidc_service(mut self, oidc: oidc::OidcService) -> Self {
        self.oidc = Some(oidc);
        self
    }

    pub fn oidc(&self) -> Option<&oidc::OidcService> {
        self.oidc.as_ref()
    }

    #[must_use]
    pub fn mutations(&self) -> &mutations::MutationState {
        &self.mutations
    }

    #[must_use]
    pub fn with_trash_retention_days(mut self, days: u16) -> Self {
        self.trash_retention_days = days;
        self
    }

    #[must_use]
    pub fn with_thumbnails(mut self, thumbnails: thumbnail::ThumbnailService) -> Self {
        self.thumbnails = Arc::new(thumbnails);
        self
    }

    #[must_use]
    pub fn thumbnails(&self) -> &Arc<thumbnail::ThumbnailService> {
        &self.thumbnails
    }

    #[must_use]
    pub const fn trash_retention_days(&self) -> u16 {
        self.trash_retention_days
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

/// Health answers are tiny JSON documents that must never be cached or
/// sniffed, matching every other API response.
fn health(status: StatusCode, value: &'static str) -> Response {
    let mut response = (status, Json(Health { status: value })).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn live() -> Response {
    health(StatusCode::OK, "ok")
}

async fn ready(State(state): State<AppState>) -> Result<Response, error::AppError> {
    if state.is_ready() {
        Ok(health(StatusCode::OK, "ready"))
    } else {
        Err(error::AppError::NotReady)
    }
}

/// The request ID is always generated here. A client-supplied `x-request-id`
/// is discarded so log lines cannot be forged into another request's trail.
async fn discard_client_request_id(mut request: Request<Body>) -> Request<Body> {
    request.headers_mut().remove(&REQUEST_ID_HEADER);
    request
}

pub fn router(state: AppState) -> Router {
    let reads = browse::router()
        .merge(preview::router())
        .merge(thumbnail::router())
        .merge(mutations::read_router());
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
        .merge(oidc::router())
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
        .layer(middleware::map_request(discard_client_request_id))
}

use axum::body::Body;

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "tests read the crate's own router sources and build synthetic fixtures in temporary directories"
)]
pub(crate) mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    };

    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        browse::{
            AuthenticatedIdentity, BrowseGate, BrowseLimits, BrowseState, ConfiguredShare,
            SubjectGate,
        },
        filesystem::{AccessLevel, GlobalPolicy, ShareFs, ShareGrant, ShareId},
        mutations::{CsrfVerified, MutationGate, MutationState},
    };

    /// Who may call a route.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Access {
        /// Reachable without a session: health, sign-in, and the API 404.
        Public,
        /// Requires a session but names no share.
        Session,
        /// Requires a session and the subject's grant for `{share_id}`.
        Share,
    }

    /// The proof a request must carry before the route changes any state.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Proof {
        /// A safe method: no origin or CSRF check.
        Safe,
        /// Same-origin headers only, for sign-in before a session exists.
        SameOrigin,
        /// Same-origin headers plus the session's CSRF token.
        Csrf,
    }

    /// The concurrency bound in front of a route's work (invariant 9).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Bound {
        Browse(BrowseGate),
        Mutation(MutationGate),
        /// Deliberately outside the request gates, for the stated reason.
        Exempt(&'static str),
    }

    /// A request body that gets past the route's extractors.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Sample {
        Empty,
        Json(&'static str),
        Text(&'static str),
        Multipart,
    }

    /// One `(method, path)` pair the assembled router serves, classified for
    /// the authorization, CSRF, and resource-limit route tests.
    #[derive(Debug)]
    pub(crate) struct Route {
        pub(crate) method: &'static str,
        pub(crate) path: &'static str,
        pub(crate) access: Access,
        pub(crate) proof: Proof,
        pub(crate) bound: Bound,
        /// Names the synthetic fixture files, so a granted request succeeds.
        pub(crate) query: &'static str,
        pub(crate) body: Sample,
    }

    impl Route {
        const fn new(
            method: &'static str,
            path: &'static str,
            access: Access,
            proof: Proof,
            bound: Bound,
        ) -> Self {
            Self {
                method,
                path,
                access,
                proof,
                bound,
                query: "",
                body: Sample::Empty,
            }
        }

        const fn query(mut self, query: &'static str) -> Self {
            self.query = query;
            self
        }

        const fn body(mut self, body: Sample) -> Self {
            self.body = body;
            self
        }
    }

    const AUTH_FLOW: Bound = Bound::Exempt(
        "authentication flow: login limiters and Argon2 slots, or the session store; no share work",
    );
    const NO_WORK: Bound = Bound::Exempt("constant response; no filesystem or session work");
    const SESSION_STORE: Bound =
        Bound::Exempt("session store lookups stay outside the request gates by design");
    const COMMIT_LOCK: Bound = Bound::Exempt(
        "serialized by the per-share commit lock, so one blocking thread per share at most",
    );
    const LISTINGS: Bound = Bound::Browse(BrowseGate::Listings);
    const BUFFERED_READS: Bound = Bound::Browse(BrowseGate::BufferedReads);
    const DOWNLOADS: Bound = Bound::Browse(BrowseGate::Downloads);
    const BLOCKING: Bound = Bound::Browse(BrowseGate::Blocking);

    /// The single authoritative list of routes. `route_inventory_matches_the_
    /// router_sources` fails when a router gains a route missing here, so a
    /// new route must be classified before it can ship.
    pub(crate) const ROUTES: &[Route] = {
        use Access::{Public, Session, Share};
        use Proof::{Csrf, Safe, SameOrigin};
        &[
            Route::new("GET", "/health/live", Public, Safe, NO_WORK),
            Route::new("GET", "/health/ready", Public, Safe, NO_WORK),
            Route::new("GET", "/api/{*path}", Public, Safe, NO_WORK),
            Route::new("GET", "/api/v1/auth/methods", Public, Safe, NO_WORK),
            Route::new("GET", "/api/v1/auth/oidc/start", Public, Safe, AUTH_FLOW),
            Route::new("GET", "/api/v1/auth/oidc/callback", Public, Safe, AUTH_FLOW),
            Route::new(
                "GET",
                "/api/v1/auth/oidc/disconnect",
                Public,
                Safe,
                AUTH_FLOW,
            ),
            Route::new("POST", "/api/v1/auth/login", Public, SameOrigin, AUTH_FLOW)
                .body(Sample::Json(r#"{"username":"nobody","password":"wrong"}"#)),
            Route::new(
                "POST",
                "/api/v1/auth/passkeys/login/start",
                Public,
                SameOrigin,
                AUTH_FLOW,
            )
            .body(Sample::Json("{}")),
            Route::new(
                "POST",
                "/api/v1/auth/passkeys/login/finish",
                Public,
                SameOrigin,
                AUTH_FLOW,
            )
            .body(Sample::Json("{}")),
            Route::new("GET", "/api/v1/session", Session, Safe, SESSION_STORE),
            Route::new("PUT", "/api/v1/preferences", Session, Csrf, SESSION_STORE)
                .body(Sample::Json(r#"{"defaultFolder":null}"#)),
            Route::new(
                "PUT",
                "/api/v1/preferences/display",
                Session,
                Csrf,
                SESSION_STORE,
            )
            .body(Sample::Json("{}")),
            Route::new("POST", "/api/v1/auth/logout", Session, Csrf, SESSION_STORE),
            Route::new("GET", "/api/v1/auth/passkeys", Session, Safe, SESSION_STORE),
            Route::new(
                "POST",
                "/api/v1/auth/passkeys/register/start",
                Session,
                Csrf,
                SESSION_STORE,
            )
            .body(Sample::Json(r#"{"name":"Laptop"}"#)),
            Route::new(
                "POST",
                "/api/v1/auth/passkeys/register/finish",
                Session,
                Csrf,
                SESSION_STORE,
            )
            .body(Sample::Json("{}")),
            Route::new(
                "PATCH",
                "/api/v1/auth/passkeys/{id}",
                Session,
                Csrf,
                SESSION_STORE,
            )
            .body(Sample::Json(r#"{"name":"Laptop"}"#)),
            Route::new(
                "DELETE",
                "/api/v1/auth/passkeys/{id}",
                Session,
                Csrf,
                SESSION_STORE,
            ),
            Route::new(
                "GET",
                "/api/v1/shares",
                Session,
                Safe,
                Bound::Exempt("answers from in-memory grants without filesystem work"),
            ),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/directory",
                Share,
                Safe,
                LISTINGS,
            ),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/events",
                Share,
                Safe,
                Bound::Browse(BrowseGate::Events),
            ),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/metadata",
                Share,
                Safe,
                BLOCKING,
            )
            .query("path=a.txt"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/text",
                Share,
                Safe,
                BUFFERED_READS,
            )
            .query("path=a.txt"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/download",
                Share,
                Safe,
                DOWNLOADS,
            )
            .query("path=a.txt"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/archive",
                Share,
                Safe,
                Bound::Browse(BrowseGate::Archives),
            )
            // A selection of two files, the most general request shape.
            .query("path=page.html&path=pixel.png"),
            // A cached size is served without the gate; each fixture is new,
            // so the first request walks.
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/folder-size",
                Share,
                Safe,
                Bound::Browse(BrowseGate::FolderSizes),
            ),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/preview",
                Share,
                Safe,
                BUFFERED_READS,
            )
            .query("path=a.txt"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/preview/html",
                Share,
                Safe,
                BUFFERED_READS,
            )
            .query("path=page.html"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/preview/html/rendered",
                Share,
                Safe,
                DOWNLOADS,
            )
            .query("path=page.html"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/preview/image",
                Share,
                Safe,
                DOWNLOADS,
            )
            .query("path=pixel.png"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/preview/svg",
                Share,
                Safe,
                DOWNLOADS,
            )
            .query("path=image.svg"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/thumbnail",
                Share,
                Safe,
                BUFFERED_READS,
            )
            .query("path=photo.png&size=256"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/open",
                Share,
                Safe,
                DOWNLOADS,
            )
            .query("path=a.txt"),
            Route::new(
                "GET",
                "/api/v1/shares/{share_id}/trash",
                Share,
                Safe,
                LISTINGS,
            ),
            Route::new(
                "POST",
                "/api/v1/shares/{share_id}/directories",
                Share,
                Csrf,
                COMMIT_LOCK,
            )
            .body(Sample::Json(r#"{"path":"new-folder"}"#)),
            Route::new(
                "POST",
                "/api/v1/shares/{share_id}/files",
                Share,
                Csrf,
                COMMIT_LOCK,
            )
            .body(Sample::Json(r#"{"path":"new.txt"}"#)),
            Route::new(
                "PUT",
                "/api/v1/shares/{share_id}/text",
                Share,
                Csrf,
                Bound::Mutation(MutationGate::TextSaves),
            )
            .query("path=a.txt")
            .body(Sample::Text("saved text")),
            Route::new(
                "POST",
                "/api/v1/shares/{share_id}/move",
                Share,
                Csrf,
                BLOCKING,
            )
            .body(Sample::Json(
                r#"{"source":"a.txt","destination":"moved.txt"}"#,
            )),
            Route::new(
                "DELETE",
                "/api/v1/shares/{share_id}/entry",
                Share,
                Csrf,
                BLOCKING,
            )
            .query("path=a.txt"),
            Route::new(
                "POST",
                "/api/v1/shares/{share_id}/trash/{item_id}/restore",
                Share,
                Csrf,
                COMMIT_LOCK,
            )
            .body(Sample::Json("{}")),
            Route::new(
                "POST",
                "/api/v1/shares/{share_id}/trash/empty",
                Share,
                Csrf,
                COMMIT_LOCK,
            ),
            Route::new(
                "DELETE",
                "/api/v1/shares/{share_id}/trash/{item_id}",
                Share,
                Csrf,
                COMMIT_LOCK,
            ),
            Route::new(
                "POST",
                "/api/v1/shares/{share_id}/uploads",
                Share,
                Csrf,
                Bound::Mutation(MutationGate::Uploads),
            )
            .body(Sample::Multipart),
        ]
    };

    /// Every request gate. Each must guard at least one route.
    const GATES: [Bound; 9] = [
        Bound::Browse(BrowseGate::Events),
        Bound::Browse(BrowseGate::Downloads),
        Bound::Browse(BrowseGate::Archives),
        Bound::Browse(BrowseGate::BufferedReads),
        Bound::Browse(BrowseGate::Listings),
        Bound::Browse(BrowseGate::Blocking),
        Bound::Browse(BrowseGate::FolderSizes),
        Bound::Mutation(MutationGate::Uploads),
        Bound::Mutation(MutationGate::TextSaves),
    ];

    const MULTIPART_BOUNDARY: &str = "crabinet-route-boundary";

    /// A request for `route` against `share_id`, with the route's sample
    /// query and body but no session, CSRF, or origin headers.
    pub(crate) fn sample_request(route: &Route, share_id: &str) -> Request<Body> {
        let path = route
            .path
            .replace("{share_id}", share_id)
            .replace("{item_id}", "0123456789abcdef0123456789abcdef")
            .replace("{id}", "credential")
            .replace("{*path}", "missing");
        let uri = if route.query.is_empty() {
            path
        } else {
            format!("{path}?{}", route.query)
        };
        let builder = Request::builder().method(route.method).uri(uri);
        match route.body {
            Sample::Empty => builder.body(Body::empty()),
            Sample::Json(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json)),
            Sample::Text(text) => builder
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(text)),
            Sample::Multipart => builder
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"),
                )
                .body(Body::from(format!(
                    "--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"files\"; \
                     filename=\"upload.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n\
                     uploaded\r\n--{MULTIPART_BOUNDARY}--\r\n"
                ))),
        }
        .expect("sample request")
    }

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

    #[tokio::test]
    async fn client_request_ids_are_replaced() {
        let response = router(AppState::new(true))
            .oneshot(
                Request::get("/health/live")
                    .header(&REQUEST_ID_HEADER, "forged-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let id = response.headers()[&REQUEST_ID_HEADER].to_str().unwrap();
        assert_ne!(id, "forged-id");
        assert!(id.starts_with("req-"), "{id}");
    }

    #[tokio::test]
    async fn health_responses_are_not_cached_or_sniffed() {
        for (ready, path) in [
            (true, "/health/live"),
            (true, "/health/ready"),
            (false, "/health/ready"),
            (true, "/health/missing"),
        ] {
            let response = router(AppState::new(ready))
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let headers = response.headers();
            assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{path}");
            assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{path}");
        }
    }

    /// Every Rust source file below `directory`.
    fn rust_sources(directory: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("source directory") {
            let entry = entry.expect("source entry");
            let path = entry.path();
            if entry.file_type().expect("source file type").is_dir() {
                rust_sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }

    /// The text of a source file before its unit-test module, where test
    /// routers are built.
    fn production_source(text: &str) -> &str {
        text.find("mod tests {")
            .map_or(text, |start| &text[..start])
    }

    /// The text up to the parenthesis closing an argument list whose opening
    /// parenthesis has just been consumed.
    fn call_arguments(text: &str) -> &str {
        let mut depth = 1_usize;
        for (index, character) in text.char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[..index];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced router call: {text}");
    }

    /// The HTTP methods of an Axum method router such as
    /// `patch(rename).delete(remove)`.
    fn router_methods(arguments: &str) -> Vec<&'static str> {
        let mut methods = Vec::new();
        for (name, method) in [
            ("get", "GET"),
            ("post", "POST"),
            ("put", "PUT"),
            ("patch", "PATCH"),
            ("delete", "DELETE"),
        ] {
            let call = format!("{name}(");
            for (start, _) in arguments.match_indices(&call) {
                let preceding = arguments[..start].chars().next_back();
                if !preceding
                    .is_some_and(|character| character.is_alphanumeric() || character == '_')
                {
                    methods.push(method);
                }
            }
        }
        methods
    }

    /// `(method, path)` for every `.route(...)` call in `source`.
    fn route_calls(source: &str) -> Vec<(&'static str, String)> {
        let mut routes = Vec::new();
        for (start, call) in source.match_indices(".route(") {
            let arguments = call_arguments(&source[start + call.len()..]);
            let path = arguments
                .split('"')
                .nth(1)
                .expect("route path string literal");
            let methods = router_methods(arguments);
            assert!(
                !methods.is_empty(),
                "unrecognized method router for {path}: {arguments}"
            );
            routes.extend(methods.into_iter().map(|method| (method, path.to_owned())));
        }
        routes
    }

    /// Axum cannot list a router's routes, so the inventory is checked
    /// against the router source instead: every `.route(` call outside a
    /// test module, in every file under `src/`. The application router's
    /// own routes are absolute and every other router is merged below
    /// `/api/v1`, its only nest.
    #[test]
    fn route_inventory_matches_the_router_sources() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_sources(&root, &mut files);
        let mut defined = BTreeSet::new();
        let mut nests = Vec::new();
        for file in &files {
            let text = fs::read_to_string(file).expect("router source");
            let production = production_source(&text);
            let relative = file.strip_prefix(&root).expect("source below src");
            for unsupported in [".route_service(", ".nest_service(", ".fallback_service("] {
                assert!(
                    !production.contains(unsupported),
                    "{} uses {unsupported}; classify its routes and teach this scan",
                    relative.display()
                );
            }
            nests.extend(
                production
                    .match_indices(".nest(")
                    .map(|(start, _)| format!("{}:{start}", relative.display())),
            );
            let prefix = if relative == Path::new("app.rs") {
                ""
            } else {
                "/api/v1"
            };
            for (method, path) in route_calls(production) {
                let route = (method.to_owned(), format!("{prefix}{path}"));
                assert!(defined.insert(route.clone()), "duplicate route {route:?}");
            }
        }
        assert_eq!(nests.len(), 1, "expected only the /api/v1 nest: {nests:?}");
        assert!(
            defined.len() > 30,
            "the scan found too few routes: {defined:?}"
        );

        let listed: BTreeSet<_> = ROUTES
            .iter()
            .map(|route| (route.method.to_owned(), route.path.to_owned()))
            .collect();
        assert_eq!(listed.len(), ROUTES.len(), "duplicate inventory entries");
        let unlisted: Vec<_> = defined.difference(&listed).collect();
        let stale: Vec<_> = listed.difference(&defined).collect();
        assert!(
            unlisted.is_empty() && stale.is_empty(),
            "classify new routes in app::tests::ROUTES: unlisted {unlisted:?}, stale {stale:?}"
        );
    }

    #[test]
    fn route_inventory_classifications_are_consistent() {
        for route in ROUTES {
            let label = format!("{} {}", route.method, route.path);
            // Only safe methods skip the origin check; every state change
            // carries proof, and every session-bound one a CSRF token.
            assert_eq!(route.method == "GET", route.proof == Proof::Safe, "{label}");
            if route.access != Access::Public && route.method != "GET" {
                assert_eq!(route.proof, Proof::Csrf, "{label}");
            }
            assert_eq!(
                route.path.contains("{share_id}"),
                route.access == Access::Share,
                "{label}"
            );
        }
        for gate in GATES {
            assert!(
                ROUTES.iter().any(|route| route.bound == gate),
                "{gate:?} guards no route"
            );
        }
    }

    /// A share with one file of each kind the gated routes read, behind a
    /// state whose gates the test can hold directly.
    struct GateFixture {
        root: TempDir,
        state: AppState,
        app: Router,
    }

    impl GateFixture {
        fn new() -> Self {
            let root = TempDir::new().expect("temporary share");
            let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
            png.extend_from_slice(&2_u32.to_be_bytes());
            png.extend_from_slice(&3_u32.to_be_bytes());
            fs::write(root.path().join("pixel.png"), png).expect("image fixture");
            fs::write(root.path().join("page.html"), b"<p>page</p>").expect("HTML fixture");
            fs::write(
                root.path().join("image.svg"),
                b"<svg xmlns='http://www.w3.org/2000/svg'/>",
            )
            .expect("SVG fixture");
            fs::write(
                root.path().join("photo.png"),
                crate::thumbnail::tests::png_fixture(4, 3, false),
            )
            .expect("decodable image fixture");
            let id = ShareId::new("documents").expect("share id");
            let share = ConfiguredShare::new(
                "Documents",
                ShareFs::open(id, root.path()).expect("open share"),
            )
            .expect("configured share");
            let browse = BrowseState::new(
                vec![share],
                BrowseLimits::default(),
                GlobalPolicy::default(),
                [0x5a; 32],
            )
            .expect("browse state");
            let state = AppState::new(true)
                .with_browse(browse)
                .with_mutations(MutationState::default());
            let app = router(state.clone());
            Self { root, state, app }
        }

        fn gate(&self, bound: Bound) -> &SubjectGate {
            match bound {
                Bound::Browse(gate) => self.state.browse().subject_gate(gate),
                Bound::Mutation(gate) => self.state.mutations().subject_gate(gate),
                Bound::Exempt(reason) => panic!("no gate: {reason}"),
            }
        }

        fn with_identity(request: Request<Body>, subject: &str) -> Request<Body> {
            let (mut parts, body) = request.into_parts();
            parts.extensions.insert(AuthenticatedIdentity::new(
                subject,
                vec![ShareGrant {
                    share_id: ShareId::new("documents").expect("share id"),
                    access: AccessLevel::ReadWrite,
                }],
            ));
            parts.extensions.insert(CsrfVerified(()));
            Request::from_parts(parts, body)
        }

        /// Restores the files a previous admitted request may have changed
        /// and returns the current validator of `a.txt`. A subject of its
        /// own reads it, so held subject leases do not refuse the lookup.
        async fn prepare(&self) -> String {
            fs::write(self.root.path().join("a.txt"), b"abcdef").expect("text fixture");
            for created in ["moved.txt", "upload.txt"] {
                let path = self.root.path().join(created);
                if fs::symlink_metadata(&path).is_ok() {
                    fs::remove_file(path).expect("remove a created file");
                }
            }
            let response = self
                .app
                .clone()
                .oneshot(Self::with_identity(
                    Request::get("/api/v1/shares/documents/metadata?path=a.txt")
                        .body(Body::empty())
                        .expect("metadata request"),
                    "fixture",
                ))
                .await
                .expect("metadata response");
            assert_eq!(response.status(), StatusCode::OK);
            response.headers()[header::ETAG]
                .to_str()
                .expect("ASCII validator")
                .to_owned()
        }

        async fn send(&self, route: &Route, subject: &str, validator: &str) -> Response {
            let mut request = sample_request(route, "documents");
            if route.method != "GET" {
                request.headers_mut().insert(
                    header::IF_MATCH,
                    HeaderValue::from_str(validator).expect("validator header"),
                );
            }
            self.app
                .clone()
                .oneshot(Self::with_identity(request, subject))
                .await
                .expect("router response")
        }
    }

    /// The event gate answers with the rate-limit code; every other gate
    /// answers `busy`. Both are `429` with `Retry-After`.
    fn refusal_code(bound: Bound) -> &'static str {
        if bound == Bound::Browse(BrowseGate::Events) {
            "rate_limited"
        } else {
            "busy"
        }
    }

    async fn assert_refused(response: Response, route: &Route, subject: &str) {
        let label = format!("{} {} as {subject}", route.method, route.path);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{label}");
        assert!(
            response.headers().contains_key(header::RETRY_AFTER),
            "{label}"
        );
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("refusal body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON refusal");
        assert_eq!(json["error"]["code"], refusal_code(route.bound), "{label}");
    }

    fn assert_admitted(response: &Response, route: &Route, subject: &str) {
        assert!(
            response.status().is_success(),
            "{} {} as {subject}: {}",
            route.method,
            route.path,
            response.status()
        );
    }

    /// Resource-limit registry (invariant 9): every route the inventory
    /// classifies as gated is refused with `429` while its gate is full,
    /// process-wide and for one subject, and is admitted again once the
    /// slots are released. With the inventory scan, a new route cannot ship
    /// without being placed behind a gate or explicitly exempted.
    #[tokio::test]
    async fn every_gated_route_refuses_when_its_gate_is_full_and_recovers() {
        let gated = ROUTES
            .iter()
            .filter(|route| !matches!(route.bound, Bound::Exempt(_)));
        for route in gated {
            // Process-wide: with every slot held, every subject is refused.
            let fixture = GateFixture::new();
            let validator = fixture.prepare().await;
            let process = Arc::clone(fixture.gate(route.bound).process_semaphore());
            let capacity = process.available_permits();
            let held = Arc::clone(&process)
                .acquire_many_owned(u32::try_from(capacity).expect("permit count"))
                .await
                .expect("process permits");
            for subject in ["alice", "bob"] {
                let response = fixture.send(route, subject, &validator).await;
                assert_refused(response, route, subject).await;
            }
            drop(held);
            let admitted = fixture.send(route, "alice", &validator).await;
            assert_admitted(&admitted, route, "alice");
            drop(admitted);
            assert_eq!(process.available_permits(), capacity, "{route:?}");

            // Per subject: one subject's full share refuses only that subject.
            let fixture = GateFixture::new();
            let gate = fixture.gate(route.bound);
            let held: Vec<_> = std::iter::from_fn(|| gate.try_acquire("alice")).collect();
            assert!(!held.is_empty(), "{route:?}");
            assert!(
                gate.process_semaphore().available_permits() > 0,
                "{route:?}: the per-subject cap must be below the process cap"
            );
            let validator = fixture.prepare().await;
            let refused = fixture.send(route, "alice", &validator).await;
            assert_refused(refused, route, "alice").await;
            let admitted = fixture.send(route, "bob", &validator).await;
            assert_admitted(&admitted, route, "bob");
            drop((admitted, held));
            let validator = fixture.prepare().await;
            let admitted = fixture.send(route, "alice", &validator).await;
            assert_admitted(&admitted, route, "alice");
        }
    }
}

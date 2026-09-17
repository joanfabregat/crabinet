//! Bounded, inert previews of untrusted files.
//!
//! This module deliberately does not turn uploaded Markdown or HTML into active
//! markup. Text, code, and Markdown are returned as JSON strings. The dedicated
//! HTML-source response uses `text/plain`, so even a new-tab navigation cannot
//! execute the file. A CSP sandbox and defense-in-depth response headers remain
//! attached to every preview response.

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};

use crate::{
    app::AppState,
    browse::AuthenticatedIdentity,
    error::AppError,
    filesystem::{AuthorizedShare, FsErrorCode, ShareId, VirtualPath},
};

/// A process-wide ceiling independent of operator configuration.
///
/// This keeps an accidentally permissive configuration from allowing one
/// preview to allocate an unbounded buffer. Operators may configure any lower
/// value.
pub const HARD_MAX_PREVIEW_BYTES: u64 = 16 * 1024 * 1024;

const PREVIEW_CSP: &str =
    "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'";
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), display-capture=(), \
    encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), \
    idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), \
    picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), \
    screen-wake-lock=(), serial=(), speaker-selection=(), usb=(), web-share=(), xr-spatial-tracking=()";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewKind {
    Code,
    HtmlSource,
    MarkdownSource,
    Text,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewDocument {
    pub kind: PreviewKind,
    pub source: String,
    pub language: Option<&'static str>,
    pub size: u64,
    /// V1 rejects oversized files rather than returning ambiguous partial text.
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreviewPolicy {
    max_bytes: u64,
}

impl PreviewPolicy {
    pub fn new(configured_max_bytes: u64) -> Result<Self, PreviewError> {
        if configured_max_bytes == 0 || configured_max_bytes > HARD_MAX_PREVIEW_BYTES {
            return Err(PreviewError::InvalidLimit);
        }
        Ok(Self {
            max_bytes: configured_max_bytes,
        })
    }

    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }
}

impl Default for PreviewPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreviewError {
    #[error("preview access denied")]
    AccessDenied,
    #[error("preview path is invalid")]
    InvalidPath,
    #[error("preview file was not found")]
    NotFound,
    #[error("preview file exceeds the configured limit")]
    TooLarge,
    #[error("preview file is not UTF-8 text")]
    InvalidUtf8,
    #[error("preview file appears to be binary")]
    Binary,
    #[error("preview file type is unsupported")]
    UnsupportedEntry,
    #[error("preview service is unavailable")]
    Unavailable,
    #[error("preview byte limit is invalid")]
    InvalidLimit,
}

impl PreviewError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AccessDenied => "not_found",
            Self::InvalidPath => "invalid_path",
            Self::NotFound => "not_found",
            Self::TooLarge => "preview_too_large",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::Binary => "binary_file",
            Self::UnsupportedEntry => "unsupported_entry",
            Self::Unavailable => "preview_unavailable",
            Self::InvalidLimit => "invalid_preview_limit",
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            // Do not disclose whether a share or entry exists to an unauthorized user.
            Self::AccessDenied | Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidPath => StatusCode::BAD_REQUEST,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InvalidUtf8 | Self::Binary | Self::UnsupportedEntry => {
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            }
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidLimit => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::AccessDenied | Self::NotFound => "Preview not found",
            Self::InvalidPath => "Preview path is invalid",
            Self::TooLarge => "File is too large to preview",
            Self::InvalidUtf8 => "File is not valid UTF-8 text",
            Self::Binary => "Binary files cannot be previewed",
            Self::UnsupportedEntry => "Entry cannot be previewed",
            Self::Unavailable => "Preview is temporarily unavailable",
            Self::InvalidLimit => "Preview service is unavailable",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewErrorBody {
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for PreviewError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status(),
            Json(PreviewErrorBody {
                code: self.code(),
                message: self.message(),
            }),
        )
            .into_response();
        apply_security_headers(response.headers_mut());
        response
    }
}

impl From<FsErrorCode> for PreviewError {
    fn from(value: FsErrorCode) -> Self {
        match value {
            FsErrorCode::AccessDenied => Self::AccessDenied,
            FsErrorCode::Conflict => Self::Unavailable,
            FsErrorCode::CrossDevice => Self::Unavailable,
            FsErrorCode::InvalidPath => Self::InvalidPath,
            FsErrorCode::NotFound => Self::NotFound,
            FsErrorCode::TooLarge => Self::TooLarge,
            FsErrorCode::UnsupportedEntry => Self::UnsupportedEntry,
            FsErrorCode::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PreviewQuery {
    path: Option<String>,
}

enum PreviewRequestError {
    Application(AppError),
    Preview(PreviewError),
}

impl From<AppError> for PreviewRequestError {
    fn from(error: AppError) -> Self {
        Self::Application(error)
    }
}

impl From<PreviewError> for PreviewRequestError {
    fn from(error: PreviewError) -> Self {
        Self::Preview(error)
    }
}

impl IntoResponse for PreviewRequestError {
    fn into_response(self) -> Response {
        match self {
            Self::Application(error) => error.into_response(),
            Self::Preview(error) => error.into_response(),
        }
    }
}

/// Authenticated preview routes, mounted below `/api/v1` by the application.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/shares/{share_id}/preview", get(preview_json))
        .route("/shares/{share_id}/preview/html", get(preview_html_source))
}

async fn preview_json(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<PreviewQuery>,
) -> Result<Response, PreviewRequestError> {
    let document = request_document(&state, &identity, &raw_share_id, query.path.as_deref())?;
    Ok(json_response(document))
}

async fn preview_html_source(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<PreviewQuery>,
) -> Result<Response, PreviewRequestError> {
    let document = request_document(&state, &identity, &raw_share_id, query.path.as_deref())?;
    html_source_response(document).map_err(Into::into)
}

fn request_document(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    raw_path: Option<&str>,
) -> Result<PreviewDocument, PreviewRequestError> {
    let share_id = ShareId::new(raw_share_id.to_owned()).map_err(|_| AppError::NotFound)?;
    let raw_path = raw_path.ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let authorized = state.browse().authorize(identity, &share_id)?;
    load(&authorized, &path, state.preview_policy()).map_err(Into::into)
}

/// Loads one complete text preview through an already-authorized capability.
///
/// Authorization is encoded in the input type: callers cannot pass a raw host
/// path or an unauthenticated `ShareFs`. HTTP handlers must construct a fresh
/// `AuthorizedShare` from the request identity before every call.
pub fn load(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
    policy: PreviewPolicy,
) -> Result<PreviewDocument, PreviewError> {
    let bytes = share
        .read_file(path, policy.max_bytes())
        .map_err(|error| PreviewError::from(error.code()))?;
    let size = bytes.len() as u64;
    let source = String::from_utf8(bytes).map_err(|_| PreviewError::InvalidUtf8)?;
    if contains_binary_control(&source) {
        return Err(PreviewError::Binary);
    }
    let (kind, language) = classify(path);
    Ok(PreviewDocument {
        kind,
        source,
        language,
        size,
        truncated: false,
    })
}

/// Returns a JSON preview for text, code, Markdown source, or HTML source.
///
/// `serde_json` escapes the source as data. The response content type and
/// `nosniff` prevent browsers from treating it as uploaded markup.
pub fn json_response(document: PreviewDocument) -> Response {
    let mut response = Json(document).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    apply_security_headers(response.headers_mut());
    response
}

/// Returns HTML file contents as inert source, never as an HTML document.
///
/// The fixed `text/plain` content type avoids parsing, script execution,
/// subresource fetching, forms, redirects, and storage access. The CSP sandbox
/// remains important defense in depth and applies when opened in a new tab.
pub fn html_source_response(document: PreviewDocument) -> Result<Response, PreviewError> {
    if document.kind != PreviewKind::HtmlSource {
        return Err(PreviewError::UnsupportedEntry);
    }
    let mut response = Response::new(Body::from(document.source));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    apply_security_headers(headers);
    Ok(response)
}

fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PREVIEW_CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
}

fn contains_binary_control(source: &str) -> bool {
    source.chars().any(|character| {
        (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
            || character == '\u{fffe}'
            || character == '\u{ffff}'
    })
}

pub(crate) fn classify(path: &VirtualPath) -> (PreviewKind, Option<&'static str>) {
    let extension = path
        .file_name()
        .and_then(|name| {
            name.as_str()
                .rsplit_once('.')
                .map(|(_, extension)| extension)
        })
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("html" | "htm" | "xhtml") => (PreviewKind::HtmlSource, Some("html")),
        Some("md" | "markdown" | "mdown" | "mkdn") => {
            (PreviewKind::MarkdownSource, Some("markdown"))
        }
        Some(extension) => match code_language(extension) {
            Some(language) => (PreviewKind::Code, Some(language)),
            None => (PreviewKind::Text, None),
        },
        None => (PreviewKind::Text, None),
    }
}

fn code_language(extension: &str) -> Option<&'static str> {
    Some(match extension {
        "bash" | "sh" | "zsh" => "shell",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" => "cpp",
        "css" => "css",
        "go" => "go",
        "java" => "java",
        "js" | "mjs" | "cjs" => "javascript",
        "json" => "json",
        "jsx" => "jsx",
        "kt" | "kts" => "kotlin",
        "lua" => "lua",
        "php" => "php",
        "py" => "python",
        "rb" => "ruby",
        "rs" => "rust",
        "sql" => "sql",
        "swift" => "swift",
        "toml" => "toml",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "tsx",
        "xml" | "svg" => "xml",
        "yaml" | "yml" => "yaml",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::Request,
    };
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        browse::{BrowseLimits, BrowseState, ConfiguredShare},
        filesystem::{AccessLevel, GlobalPolicy, ShareFs, ShareGrant, ShareId},
    };

    fn fixture(contents: &[u8], name: &str) -> (TempDir, ShareFs, ShareGrant, VirtualPath) {
        let temporary = TempDir::new().expect("temporary directory");
        fs::write(temporary.path().join(name), contents).expect("fixture file");
        let id = ShareId::new("documents").expect("share id");
        let share = ShareFs::open(id.clone(), temporary.path()).expect("share");
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadOnly,
        };
        let path = VirtualPath::parse(name).expect("path");
        (temporary, share, grant, path)
    }

    struct ApiFixture {
        _temporary: TempDir,
        app: Router,
        identity: AuthenticatedIdentity,
    }

    fn api_fixture(max_bytes: u64) -> ApiFixture {
        let temporary = TempDir::new().expect("temporary directory");
        fs::write(temporary.path().join("main.rs"), b"fn main() {}\n").unwrap();
        fs::write(
            temporary.path().join("hostile.html"),
            b"<script>fetch('https://attacker.invalid/')</script><form action=/api/v1/auth/logout>",
        )
        .unwrap();
        fs::write(temporary.path().join("large.txt"), vec![b'a'; 128]).unwrap();
        fs::write(temporary.path().join("binary.txt"), b"text\0binary").unwrap();

        let share_id = ShareId::new("documents").unwrap();
        let filesystem = ShareFs::open(share_id.clone(), temporary.path()).unwrap();
        let configured = ConfiguredShare::new("Documents", filesystem).unwrap();
        let browse = BrowseState::new(
            vec![configured],
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [7; 32],
        )
        .unwrap();
        let identity = AuthenticatedIdentity::new(
            "user-1",
            vec![ShareGrant {
                share_id,
                access: AccessLevel::ReadOnly,
            }],
        );
        let state = AppState::new(true)
            .with_browse(browse)
            .with_preview_policy(PreviewPolicy::new(max_bytes).unwrap());
        ApiFixture {
            _temporary: temporary,
            app: crate::app::router(state),
            identity,
        }
    }

    async fn send(
        app: &Router,
        identity: Option<&AuthenticatedIdentity>,
        mut request: Request<Body>,
    ) -> Response {
        if let Some(identity) = identity {
            request.extensions_mut().insert(identity.clone());
        }
        app.clone().oneshot(request).await.unwrap()
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn config_limit_must_be_positive_and_bounded() {
        assert_eq!(PreviewPolicy::new(0), Err(PreviewError::InvalidLimit));
        assert_eq!(
            PreviewPolicy::new(HARD_MAX_PREVIEW_BYTES + 1),
            Err(PreviewError::InvalidLimit)
        );
        assert_eq!(
            PreviewPolicy::new(HARD_MAX_PREVIEW_BYTES)
                .expect("limit")
                .max_bytes(),
            HARD_MAX_PREVIEW_BYTES
        );
    }

    #[test]
    fn exact_limit_is_allowed_and_one_extra_byte_is_rejected_before_reading() {
        let (_temporary, share, grant, path) = fixture(b"hello", "hello.txt");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(5).unwrap())
                .expect("preview")
                .source,
            "hello"
        );
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(4).unwrap()),
            Err(PreviewError::TooLarge)
        );
    }

    #[test]
    fn invalid_utf8_and_binary_controls_are_rejected() {
        let (_temporary, share, grant, path) = fixture(&[0xff, 0xfe], "bad.txt");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(32).unwrap()),
            Err(PreviewError::InvalidUtf8)
        );

        let (_temporary, share, grant, path) = fixture(b"prefix\0suffix", "binary.txt");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(32).unwrap()),
            Err(PreviewError::Binary)
        );
    }

    #[test]
    fn markdown_is_source_data_and_never_rendered_server_side() {
        let hostile = "# title\n<script>alert(document.cookie)</script>\n[x](javascript:alert(1))";
        let (_temporary, share, grant, path) = fixture(hostile.as_bytes(), "attack.md");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        let document = load(&authorized, &path, PreviewPolicy::new(4096).unwrap()).unwrap();
        assert_eq!(document.kind, PreviewKind::MarkdownSource);
        assert_eq!(document.source, hostile);
        assert_eq!(document.language, Some("markdown"));
        assert!(!document.truncated);
    }

    #[tokio::test]
    async fn hostile_html_is_served_verbatim_only_as_plain_text() {
        let hostile = concat!(
            "<script>top.location='https://attacker.invalid/'</script>",
            "<img src=https://attacker.invalid/beacon onerror=alert(1)>",
            "<form action=https://attacker.invalid/><input></form>",
            "<meta http-equiv=refresh content='0;url=https://attacker.invalid/'>",
            "<svg><script>open('https://attacker.invalid/')</script></svg>"
        );
        let (_temporary, share, grant, path) = fixture(hostile.as_bytes(), "attack.html");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        let document = load(&authorized, &path, PreviewPolicy::new(4096).unwrap()).unwrap();
        let response = html_source_response(document).expect("HTML source response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            PREVIEW_CSP
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "inline"
        );
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        assert_eq!(body.as_ref(), hostile.as_bytes());
    }

    #[test]
    fn html_endpoint_rejects_non_html_files() {
        let document = PreviewDocument {
            kind: PreviewKind::Text,
            source: "plain".into(),
            language: None,
            size: 5,
            truncated: false,
        };
        assert_eq!(
            html_source_response(document).expect_err("not HTML"),
            PreviewError::UnsupportedEntry
        );
    }

    #[test]
    fn code_hints_are_from_a_fixed_allowlist() {
        let rust = VirtualPath::parse("src/main.RS").unwrap();
        let unknown = VirtualPath::parse("payload.evil-language").unwrap();
        assert_eq!(classify(&rust), (PreviewKind::Code, Some("rust")));
        assert_eq!(classify(&unknown), (PreviewKind::Text, None));
    }

    #[test]
    fn filesystem_errors_keep_access_and_missing_non_disclosing() {
        assert_eq!(
            PreviewError::from(FsErrorCode::AccessDenied).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            PreviewError::from(FsErrorCode::NotFound).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            PreviewError::AccessDenied.message(),
            PreviewError::NotFound.message()
        );
    }

    #[tokio::test]
    async fn routes_require_authentication_and_authorize_every_request() {
        let fixture = api_fixture(4096);
        let uri = "/api/v1/shares/documents/preview?path=main.rs";
        let unauthenticated = send(
            &fixture.app,
            None,
            Request::get(uri).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let no_grants = AuthenticatedIdentity::new("user-2", vec![]);
        let ungranted = send(
            &fixture.app,
            Some(&no_grants),
            Request::get(uri).body(Body::empty()).unwrap(),
        )
        .await;
        let missing = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/missing/preview?path=main.rs")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(ungranted.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(ungranted).await, response_json(missing).await);
    }

    #[tokio::test]
    async fn code_route_returns_only_inert_bounded_json() {
        let fixture = api_fixture(4096);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview?path=main.rs")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            PREVIEW_CSP
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert!(response.headers().contains_key("x-request-id"));
        let value = response_json(response).await;
        assert_eq!(value["kind"], "code");
        assert_eq!(value["language"], "rust");
        assert_eq!(value["source"], "fn main() {}\n");
        assert_eq!(value["truncated"], false);
    }

    #[tokio::test]
    async fn html_route_is_plain_text_under_the_http_sandbox() {
        let fixture = api_fixture(4096);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview/html?path=hostile.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            PREVIEW_CSP
        );
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            bytes.as_ref(),
            b"<script>fetch('https://attacker.invalid/')</script><form action=/api/v1/auth/logout>"
        );
    }

    #[tokio::test]
    async fn route_rejects_ambiguous_paths_binary_input_and_oversized_files() {
        let fixture = api_fixture(32);
        for (uri, status, code) in [
            (
                "/api/v1/shares/documents/preview",
                StatusCode::BAD_REQUEST,
                "invalid_path",
            ),
            (
                "/api/v1/shares/documents/preview?path=..%2Fsecret",
                StatusCode::BAD_REQUEST,
                "invalid_path",
            ),
            (
                "/api/v1/shares/documents/preview?path=binary.txt",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "binary_file",
            ),
            (
                "/api/v1/shares/documents/preview?path=large.txt",
                StatusCode::PAYLOAD_TOO_LARGE,
                "preview_too_large",
            ),
        ] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(response.status(), status, "unexpected status for {uri}");
            assert_eq!(response_json(response).await["code"], code);
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_files_cannot_be_previewed() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().expect("temporary directory");
        let outside = TempDir::new().expect("outside directory");
        fs::write(outside.path().join("secret.txt"), b"secret").expect("secret");
        symlink(
            outside.path().join("secret.txt"),
            temporary.path().join("linked.txt"),
        )
        .expect("symlink");
        fs::write(temporary.path().join("inside.txt"), b"inside").expect("inside");
        fs::hard_link(
            temporary.path().join("inside.txt"),
            temporary.path().join("alias.txt"),
        )
        .expect("hard link");

        let id = ShareId::new("documents").unwrap();
        let share = ShareFs::open(id.clone(), temporary.path()).unwrap();
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadOnly,
        };
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        for name in ["linked.txt", "inside.txt", "alias.txt"] {
            assert_eq!(
                load(
                    &authorized,
                    &VirtualPath::parse(name).unwrap(),
                    PreviewPolicy::new(64).unwrap()
                ),
                Err(PreviewError::UnsupportedEntry),
                "linked entry {name:?} must be rejected"
            );
        }
    }
}

//! Bounded previews of untrusted files.
//!
//! This module deliberately does not turn uploaded Markdown or HTML into active
//! markup. Text, code, and Markdown are returned as JSON strings. The dedicated
//! HTML source remains available as `text/plain`. Rendered HTML is isolated in
//! a browser sandbox and served under a deny-by-default CSP. Image responses
//! are accepted only after their signatures match a supported media type.
//!
//! The inline open route serves a file in a new tab only when its bytes match
//! a type the browser displays without running script on this origin: raster
//! images, PDF, allowlisted audio and video containers, and UTF-8 text, which
//! is always `text/plain`. The type comes from the signature, never from the
//! filename or an uploaded `Content-Type`.

use std::io::{Read, Seek as _, SeekFrom};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;
use tokio_util::io::ReaderStream;

use crate::{
    app::AppState,
    browse::{AuthenticatedIdentity, StreamedFile, SubjectLease, run_blocking, stream_file},
    error::AppError,
    extract::{ApiPath, ApiQuery},
    filesystem::{AuthorizedShare, FsErrorCode, ShareId, VirtualPath},
};

/// A process-wide ceiling independent of operator configuration.
///
/// This keeps an accidentally permissive configuration from allowing one
/// preview to allocate an unbounded buffer. Operators may configure any lower
/// value. It bounds only previews that buffer the whole file (text, code,
/// Markdown, and HTML); streamed types are bounded by the download limit.
pub const HARD_MAX_PREVIEW_BYTES: u64 = 16 * 1024 * 1024;
/// The bounded prefix every preview and inline open reads to classify a file
/// by signature, and the prefix the open route checks for UTF-8 text.
const SIGNATURE_HEADER_BYTES: u64 = 64 * 1024;
/// Browsers accept `%PDF-` anywhere in the first kilobyte.
const PDF_SIGNATURE_WINDOW: usize = 1024;
const MAX_IMAGE_PIXELS: u64 = 100_000_000;
const IMAGE_STREAM_CHUNK_BYTES: usize = 64 * 1024;

const PREVIEW_CSP: &str = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
    base-uri 'none'; form-action 'none'; frame-ancestors 'self'; navigate-to 'none'";
const TEXT_PLAIN_UTF8: &str = "text/plain; charset=utf-8";
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), display-capture=(), \
    encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), \
    idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), \
    picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), \
    screen-wake-lock=(), serial=(), speaker-selection=(), usb=(), web-share=(), xr-spatial-tracking=()";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewKind {
    Audio,
    Code,
    HtmlSource,
    Image,
    MarkdownSource,
    Pdf,
    Text,
    Video,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewDocument {
    pub kind: PreviewKind,
    pub source: String,
    pub language: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    pub size: u64,
    /// V1 rejects oversized files rather than returning ambiguous partial text.
    pub truncated: bool,
    /// Whether the UI offers `/open` as a top-level new tab: images, PDF,
    /// and text-like kinds (served as `text/plain`). Audio and video stream
    /// from `/open` into the panel's media elements only.
    pub openable: bool,
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
            FsErrorCode::InvalidPath | FsErrorCode::TooDeep => Self::InvalidPath,
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
        .route(
            "/shares/{share_id}/preview/html/rendered",
            get(preview_html_rendered),
        )
        .route("/shares/{share_id}/preview/image", get(preview_image))
        .route("/shares/{share_id}/open", get(open_inline))
}

async fn preview_json(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<PreviewQuery>,
) -> Result<Response, PreviewRequestError> {
    let (document, _permit) =
        request_document(&state, &identity, &raw_share_id, query.path.as_deref()).await?;
    Ok(json_response(document))
}

async fn preview_html_source(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<PreviewQuery>,
) -> Result<Response, PreviewRequestError> {
    let (document, _permit) =
        request_document(&state, &identity, &raw_share_id, query.path.as_deref()).await?;
    html_source_response(document).map_err(Into::into)
}

async fn preview_html_rendered(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<PreviewQuery>,
    headers: HeaderMap,
) -> Result<Response, PreviewRequestError> {
    if !rendered_destination_allowed(&headers) {
        return Ok(frame_only_response());
    }
    let (document, _permit) =
        request_document(&state, &identity, &raw_share_id, query.path.as_deref()).await?;
    html_rendered_response(document).map_err(Into::into)
}

/// Rendered HTML is served only to frames.
///
/// A CSP sandbox blocks scripts, forms, and popups but not a top-level
/// document's own navigation, so a page opened directly in a tab could send
/// the reader elsewhere with a link or a meta refresh. Inside the UI's
/// empty-sandbox iframe it cannot. Browsers that report the request
/// destination therefore receive the document only for an `iframe`; clients
/// that omit `Sec-Fetch-Dest` keep the previous behavior under the same CSP.
fn rendered_destination_allowed(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-dest")
        .is_none_or(|destination| destination.as_bytes() == b"iframe")
}

/// The inert notice returned instead of rendered HTML outside a frame. It is
/// decided before authorization, so it discloses nothing about the file.
fn frame_only_response() -> Response {
    let mut response = (
        StatusCode::FORBIDDEN,
        "Rendered HTML previews open only inside Crabinet's sandboxed viewer.\n",
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    apply_security_headers(headers);
    response
}

async fn preview_image(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<PreviewQuery>,
) -> Result<Response, PreviewRequestError> {
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let raw_path = query.path.as_deref().ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let authorized = state.browse().authorize_owned(&identity, &share_id)?;
    let max_bytes = state.browse().max_download_bytes();
    // A streamed image holds an open file like a download, so it takes a
    // download slot before the file is opened. The lease travels with the
    // blocking open, so a cancelled request cannot release it early, and then
    // with the body stream, so the slot is released only when the stream ends
    // or is dropped.
    let lease = state.browse().acquire_download(&identity)?;
    let (opened, lease) =
        run_blocking(move || (open_image(&authorized.view(), &path, max_bytes), lease)).await?;
    let (file, image, size) = opened?;
    let stream = ReaderStream::with_capacity(
        tokio::fs::File::from_std(file).take(size),
        IMAGE_STREAM_CHUNK_BYTES,
    )
    .map(move |chunk| {
        let _lease = &lease;
        chunk
    });
    Ok(image_response(
        Body::from_stream(stream),
        image.mime_type,
        size,
    ))
}

/// Opens and signature-checks an image on a blocking thread, returning the
/// handle rewound to the start for streaming. A streamed image is bounded by
/// the download limit and the pixel cap, not by the buffered preview limit.
fn open_image(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
    max_bytes: u64,
) -> Result<(std::fs::File, ImageInfo, u64), PreviewError> {
    let opened = share
        .open_file(path)
        .map_err(|error| PreviewError::from(error.code()))?;
    let size = opened.len();
    if size > max_bytes {
        return Err(PreviewError::TooLarge);
    }
    let mut file = opened.into_std();
    let header = read_signature_header(&mut file, size)?;
    let image = validated_image(&header)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| PreviewError::Unavailable)?;
    Ok((file, image, size))
}

/// Serves a file in a new tab when its bytes match an inline allowlist.
///
/// Authorization and admission mirror `/preview/image`: a fresh grant
/// resolution, a validated virtual path, and a download slot held for the
/// body's lifetime. The response streams from the handle that was validated,
/// with the same validators, conditional requests, and single byte ranges as
/// downloads, so PDF viewers and media elements can seek.
async fn open_inline(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<PreviewQuery>,
    headers: HeaderMap,
) -> Result<Response, PreviewRequestError> {
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let raw_path = query.path.as_deref().ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let browse = state.browse();
    let authorized = browse.authorize_owned(&identity, &share_id)?;
    let max_bytes = browse.max_download_bytes();
    // The same slot discipline as `preview_image` and downloads.
    let lease = browse.acquire_download(&identity)?;
    let open_path = path.clone();
    let (opened, lease) = run_blocking(move || {
        (
            open_for_inline(&authorized.view(), &open_path, max_bytes),
            lease,
        )
    })
    .await?;
    let opened = opened?;
    let etag = browse.file_etag(
        &share_id,
        &path,
        opened.size,
        opened.modified,
        opened.file_id,
    );
    let content = opened.content;
    let file = StreamedFile {
        file: opened.file,
        total_len: opened.size,
        etag,
    };
    let mut response = stream_file(
        &headers,
        file,
        browse.stream_chunk_bytes(),
        lease,
        |response_headers| {
            response_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content.media_type()),
            );
            response_headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("inline"),
            );
            Ok(())
        },
    )
    .await?;
    // Every inline response, PDF included, keeps the sandboxed deny-by-default
    // policy: Chromium's and Firefox's PDF viewers render a top-level PDF
    // under it (see docs/previews.md), so no type needs an exception.
    apply_security_headers(response.headers_mut());
    Ok(response)
}

/// What the open route serves, decided from the file's bytes only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InlineContent {
    Media(StreamedMedia),
    /// UTF-8 text, including HTML, SVG, and XML source, always `text/plain`.
    Text,
}

impl InlineContent {
    const fn media_type(self) -> &'static str {
        match self {
            Self::Media(media) => media.mime_type(),
            Self::Text => TEXT_PLAIN_UTF8,
        }
    }
}

struct InlineFile {
    file: std::fs::File,
    size: u64,
    modified: Option<std::time::SystemTime>,
    file_id: u64,
    content: InlineContent,
}

/// Opens a file and classifies its bounded header on a blocking thread.
/// Anything outside the allowlist is refused with the preview error codes.
fn open_for_inline(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
    max_bytes: u64,
) -> Result<InlineFile, PreviewError> {
    let opened = share
        .open_file(path)
        .map_err(|error| PreviewError::from(error.code()))?;
    let size = opened.len();
    if size > max_bytes {
        return Err(PreviewError::TooLarge);
    }
    let modified = opened.modified();
    let file_id = opened.file_id();
    let mut file = opened.into_std();
    let header = read_signature_header(&mut file, size)?;
    let content = match classify_streamed(&header)? {
        Some(media) => InlineContent::Media(media),
        None => {
            check_text_prefix(&header, header_reached_end(&header))?;
            InlineContent::Text
        }
    };
    Ok(InlineFile {
        file,
        size,
        modified,
        file_id,
        content,
    })
}

async fn request_document(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    raw_path: Option<&str>,
) -> Result<(PreviewDocument, SubjectLease), PreviewRequestError> {
    let share_id = ShareId::new(raw_share_id.to_owned()).map_err(|_| AppError::NotFound)?;
    let raw_path = raw_path.ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let authorized = state.browse().authorize_owned(identity, &share_id)?;
    // Returned to the caller, which holds it while building the response
    // so every buffered copy of the document stays within the bound.
    let permit = state.browse().acquire_buffered_read(identity)?;
    let policy = state.preview_policy();
    // The permit travels with the blocking work, so a cancelled request does
    // not release it while the read is still running.
    let (document, permit) =
        run_blocking(move || (load(&authorized.view(), &path, policy), permit)).await?;
    Ok((document?, permit))
}

/// Loads one preview through an already-authorized capability.
///
/// Authorization is encoded in the input type: callers cannot pass a raw host
/// path or an unauthenticated `ShareFs`. HTTP handlers must construct a fresh
/// `AuthorizedShare` from the request identity before every call.
///
/// A bounded header is classified by signature first. Streamed types (raster
/// images, PDF, audio, and video) return metadata only and are not bound by
/// the preview limit, which applies only to the buffered text path.
pub fn load(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
    policy: PreviewPolicy,
) -> Result<PreviewDocument, PreviewError> {
    let opened = share
        .open_file(path)
        .map_err(|error| PreviewError::from(error.code()))?;
    let size = opened.len();
    let mut file = opened.into_std();
    let header = read_signature_header(&mut file, size)?;
    if let Some(media) = classify_streamed(&header)? {
        let (width, height) = match media {
            StreamedMedia::Image(image) => (image.width, image.height),
            _ => (None, None),
        };
        return Ok(PreviewDocument {
            kind: media.kind(),
            source: String::new(),
            language: None,
            mime_type: Some(media.mime_type()),
            width,
            height,
            size,
            truncated: false,
            openable: media.opens_in_tab(),
        });
    }
    if size > policy.max_bytes() {
        return Err(PreviewError::TooLarge);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| PreviewError::Unavailable)?;
    let mut bytes = Vec::with_capacity(size as usize);
    Read::by_ref(&mut file)
        .take(policy.max_bytes().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PreviewError::Unavailable)?;
    if bytes.len() as u64 > policy.max_bytes() {
        return Err(PreviewError::TooLarge);
    }
    let source = String::from_utf8(bytes).map_err(|_| PreviewError::InvalidUtf8)?;
    if contains_binary_control(&source) {
        return Err(PreviewError::Binary);
    }
    let (kind, language) = classify(path);
    Ok(PreviewDocument {
        kind,
        source,
        language,
        mime_type: None,
        width: None,
        height: None,
        size,
        truncated: false,
        // Served by `/open` as `text/plain`, whatever the extension says.
        openable: true,
    })
}

/// Reads at most [`SIGNATURE_HEADER_BYTES`] from the start of `file`. The
/// handle is left after the header; callers seek before reading again.
fn read_signature_header(file: &mut std::fs::File, size: u64) -> Result<Vec<u8>, PreviewError> {
    let mut header = Vec::with_capacity(size.min(SIGNATURE_HEADER_BYTES) as usize);
    Read::by_ref(file)
        .take(SIGNATURE_HEADER_BYTES)
        .read_to_end(&mut header)
        .map_err(|_| PreviewError::Unavailable)?;
    Ok(header)
}

/// A header shorter than the read bound ended at end of file, so a trailing
/// partial UTF-8 sequence is a real encoding error rather than a cut.
const fn header_reached_end(header: &[u8]) -> bool {
    (header.len() as u64) < SIGNATURE_HEADER_BYTES
}

/// Checks a bounded prefix with the same rules as text previews. When the
/// prefix was cut by the read bound, an incomplete trailing multibyte
/// character is tolerated; any other invalid sequence is not.
fn check_text_prefix(header: &[u8], at_end: bool) -> Result<(), PreviewError> {
    let text = match std::str::from_utf8(header) {
        Ok(text) => text,
        Err(error) if !at_end && error.error_len().is_none() => {
            std::str::from_utf8(&header[..error.valid_up_to()])
                .map_err(|_| PreviewError::InvalidUtf8)?
        }
        Err(_) => return Err(PreviewError::InvalidUtf8),
    };
    if contains_binary_control(text) {
        return Err(PreviewError::Binary);
    }
    Ok(())
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

/// Returns uploaded HTML as a sandboxed document for the UI's doubly-sandboxed
/// iframe. The response CSP forbids scripts, forms, same-origin access, network
/// requests, plugins, and storage capabilities wherever the document loads; the
/// route also refuses top-level loads from browsers that report one, because
/// only the iframe sandbox stops the document navigating its own tab.
pub fn html_rendered_response(document: PreviewDocument) -> Result<Response, PreviewError> {
    if document.kind != PreviewKind::HtmlSource {
        return Err(PreviewError::UnsupportedEntry);
    }
    let mut response = Response::new(Body::from(document.source));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    apply_security_headers(headers);
    Ok(response)
}

fn image_response(body: Body, mime_type: &'static str, size: u64) -> Response {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime_type));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    if let Ok(value) = HeaderValue::from_str(&size.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    apply_security_headers(headers);
    response
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ImageInfo {
    mime_type: &'static str,
    width: Option<u32>,
    height: Option<u32>,
}

fn classify_image(bytes: &[u8]) -> Option<ImageInfo> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 24 {
        let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        if width == 0 || height == 0 {
            return None;
        }
        return Some(ImageInfo {
            mime_type: "image/png",
            width: Some(width),
            height: Some(height),
        });
    }
    if (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) && bytes.len() >= 10 {
        return Some(ImageInfo {
            mime_type: "image/gif",
            width: Some(u16::from_le_bytes(bytes[6..8].try_into().ok()?) as u32),
            height: Some(u16::from_le_bytes(bytes[8..10].try_into().ok()?) as u32),
        });
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        let mut offset = 2;
        while offset + 9 < bytes.len() {
            if bytes[offset] != 0xff {
                offset += 1;
                continue;
            }
            let marker = bytes[offset + 1];
            if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
                return Some(ImageInfo {
                    mime_type: "image/jpeg",
                    height: Some(u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]) as u32),
                    width: Some(u16::from_be_bytes([bytes[offset + 7], bytes[offset + 8]]) as u32),
                });
            }
            if marker == 0xd9 || marker == 0xda {
                break;
            }
            let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            if length < 2 {
                break;
            }
            offset = offset.saturating_add(length + 2);
        }
        return Some(ImageInfo {
            mime_type: "image/jpeg",
            width: None,
            height: None,
        });
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        let (width, height) = if bytes.len() >= 30 && &bytes[12..16] == b"VP8X" {
            (
                Some(1 + u32::from_le_bytes([bytes[24], bytes[25], bytes[26], 0])),
                Some(1 + u32::from_le_bytes([bytes[27], bytes[28], bytes[29], 0])),
            )
        } else {
            (None, None)
        };
        return Some(ImageInfo {
            mime_type: "image/webp",
            width,
            height,
        });
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" && bytes[8..12].starts_with(b"avif") {
        return Some(ImageInfo {
            mime_type: "image/avif",
            width: None,
            height: None,
        });
    }
    None
}

fn validated_image(bytes: &[u8]) -> Result<ImageInfo, PreviewError> {
    let image = classify_image(bytes).ok_or(PreviewError::UnsupportedEntry)?;
    validate_image_dimensions(image)?;
    Ok(image)
}

fn validate_image_dimensions(image: ImageInfo) -> Result<(), PreviewError> {
    if let (Some(width), Some(height)) = (image.width, image.height) {
        let pixels = u64::from(width).saturating_mul(u64::from(height));
        if width == 0 || height == 0 || pixels > MAX_IMAGE_PIXELS {
            return Err(PreviewError::UnsupportedEntry);
        }
    }
    Ok(())
}

/// A type that streams from the file handle instead of being buffered, and
/// that `/open` serves with the media type below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamedMedia {
    Image(ImageInfo),
    Pdf,
    Audio(&'static str),
    Video(&'static str),
}

impl StreamedMedia {
    const fn kind(self) -> PreviewKind {
        match self {
            Self::Image(_) => PreviewKind::Image,
            Self::Pdf => PreviewKind::Pdf,
            Self::Audio(_) => PreviewKind::Audio,
            Self::Video(_) => PreviewKind::Video,
        }
    }

    const fn mime_type(self) -> &'static str {
        match self {
            Self::Image(image) => image.mime_type,
            Self::Pdf => "application/pdf",
            Self::Audio(mime_type) | Self::Video(mime_type) => mime_type,
        }
    }

    /// Whether a browser displays this type as a top-level document under
    /// the sandboxed preview CSP. Images and PDF do. A media document does
    /// not: Chromium's player refetches the URL from the sandbox's opaque
    /// origin, which CORS refuses, so audio and video play only in the
    /// panel's media elements and offer no new-tab action.
    const fn opens_in_tab(self) -> bool {
        matches!(self, Self::Image(_) | Self::Pdf)
    }
}

/// Classifies a bounded file header by signature only.
///
/// Raster images come first, so an AVIF `ftyp` is never served as video and
/// image polyglots keep their pixel cap. `Ok(None)` means the bytes match no
/// streamed type; the caller may then try the UTF-8 text rules.
fn classify_streamed(header: &[u8]) -> Result<Option<StreamedMedia>, PreviewError> {
    if let Some(image) = classify_image(header) {
        validate_image_dimensions(image)?;
        return Ok(Some(StreamedMedia::Image(image)));
    }
    if is_pdf(header) {
        return Ok(Some(StreamedMedia::Pdf));
    }
    Ok(classify_audio_video(header))
}

/// `%PDF-` at the start, or later in the first kilobyte as browsers accept.
///
/// A late marker counts only when the prefix is not clean UTF-8 text, so a
/// text file that merely mentions `%PDF-` near its start keeps opening as
/// inert `text/plain` instead of under the PDF viewer's relaxed policy.
fn is_pdf(header: &[u8]) -> bool {
    if header.starts_with(b"%PDF-") {
        return true;
    }
    let window = &header[..header.len().min(PDF_SIGNATURE_WINDOW)];
    window.windows(5).any(|candidate| candidate == b"%PDF-")
        && check_text_prefix(header, header_reached_end(header)).is_err()
}

fn classify_audio_video(header: &[u8]) -> Option<StreamedMedia> {
    if let Some(media) = classify_iso_bmff(header) {
        return Some(media);
    }
    if is_matroska(header) {
        // Browsers play WebM and the WebM-compatible subset of Matroska only
        // under the WebM type.
        return Some(StreamedMedia::Video("video/webm"));
    }
    if let Some(media) = classify_ogg(header) {
        return Some(media);
    }
    if header.len() >= 12 && header.starts_with(b"RIFF") && &header[8..12] == b"WAVE" {
        return Some(StreamedMedia::Audio("audio/wav"));
    }
    if is_flac(header) {
        return Some(StreamedMedia::Audio("audio/flac"));
    }
    if is_mp3(header) {
        return Some(StreamedMedia::Audio("audio/mpeg"));
    }
    None
}

/// MP4 major brands served as video. Anything else, including QuickTime,
/// 3GP, and every HEIF or AVIF image brand, gets no inline type.
const MP4_VIDEO_BRANDS: [&[u8; 4]; 11] = [
    b"isom", b"iso2", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42", b"avc1", b"dash", b"M4V ",
    b"MSNV",
];
/// MP4 major brands for audio-only files (`.m4a`, `.m4b`).
const MP4_AUDIO_BRANDS: [&[u8; 4]; 2] = [b"M4A ", b"M4B "];
/// Still-image and image-sequence brands that must never open as video.
const IMAGE_BRANDS: [&[u8; 4]; 11] = [
    b"avif", b"avis", b"mif1", b"mif2", b"msf1", b"miaf", b"heic", b"heix", b"heim", b"heis",
    b"hevc",
];

/// An ISO base media file must start with a complete `ftyp` box whose major
/// brand is allowlisted and whose compatible brands name no image format.
fn classify_iso_bmff(header: &[u8]) -> Option<StreamedMedia> {
    if header.len() < 16 || &header[4..8] != b"ftyp" {
        return None;
    }
    let size = usize::try_from(u32::from_be_bytes(header[0..4].try_into().ok()?)).ok()?;
    if size < 16 || size % 4 != 0 || size > header.len() {
        return None;
    }
    let major: &[u8; 4] = header[8..12].try_into().ok()?;
    let (compatible, _) = header[16..size].as_chunks::<4>();
    if std::iter::once(major)
        .chain(compatible)
        .any(|brand| IMAGE_BRANDS.contains(&brand))
    {
        return None;
    }
    if MP4_AUDIO_BRANDS.contains(&major) {
        return Some(StreamedMedia::Audio("audio/mp4"));
    }
    if MP4_VIDEO_BRANDS.contains(&major) {
        return Some(StreamedMedia::Video("video/mp4"));
    }
    None
}

/// The EBML magic followed, within the EBML header, by a `DocType` element
/// naming WebM or Matroska.
fn is_matroska(header: &[u8]) -> bool {
    if !header.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        return false;
    }
    let ebml = &header[4..header.len().min(64)];
    let contains = |needle: &[u8]| ebml.windows(needle.len()).any(|window| window == needle);
    contains(b"\x42\x82\x84webm") || contains(b"\x42\x82\x88matroska")
}

/// An Ogg page header (`OggS`, version 0). A Theora first packet is video;
/// every other first stream (Vorbis, Opus, FLAC) is audio.
fn classify_ogg(header: &[u8]) -> Option<StreamedMedia> {
    if header.len() < 27 || !header.starts_with(b"OggS") || header[4] != 0 {
        return None;
    }
    let packet = header.get(27 + usize::from(header[26])..)?;
    if packet.starts_with(b"\x80theora") {
        Some(StreamedMedia::Video("video/ogg"))
    } else {
        Some(StreamedMedia::Audio("audio/ogg"))
    }
}

/// `fLaC` followed by the mandatory 34-byte STREAMINFO metadata block.
fn is_flac(header: &[u8]) -> bool {
    header.len() >= 8
        && header.starts_with(b"fLaC")
        && header[4] & 0x7f == 0
        && header[5..8] == [0, 0, 34]
}

/// An ID3v2 tag header, or two consecutive MPEG-1/2/2.5 Layer III frames.
///
/// A single 11-bit frame sync is too weak on its own, so without an ID3 tag
/// the frame length computed from the first header must land on a second
/// valid header.
fn is_mp3(header: &[u8]) -> bool {
    if header.len() >= 10 && header.starts_with(b"ID3") {
        return matches!(header[3], 2..=4)
            && header[4] != 0xff
            && header[6..10].iter().all(|byte| byte & 0x80 == 0);
    }
    let Some(first) = mpeg_layer3_frame_len(header) else {
        return false;
    };
    header
        .get(first..)
        .and_then(mpeg_layer3_frame_len)
        .is_some()
}

fn mpeg_layer3_frame_len(header: &[u8]) -> Option<usize> {
    const V1_KBPS: [u32; 15] = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ];
    const V2_KBPS: [u32; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    if header.len() < 4 || header[0] != 0xff || header[1] & 0xe0 != 0xe0 {
        return None;
    }
    // Version: 0 = MPEG-2.5, 1 = reserved, 2 = MPEG-2, 3 = MPEG-1.
    let version = (header[1] >> 3) & 0b11;
    // Layer: 1 = Layer III. ADTS AAC uses 0 and is not MP3.
    let layer = (header[1] >> 1) & 0b11;
    let bitrate_index = usize::from(header[2] >> 4);
    let rate_index = usize::from((header[2] >> 2) & 0b11);
    if version == 1 || layer != 1 || bitrate_index == 0 || bitrate_index == 15 || rate_index == 3 {
        return None;
    }
    let padding = u32::from((header[2] >> 1) & 1);
    let (kbps, rates, coefficient) = match version {
        3 => (V1_KBPS[bitrate_index], [44_100, 48_000, 32_000], 144),
        2 => (V2_KBPS[bitrate_index], [22_050, 24_000, 16_000], 72),
        _ => (V2_KBPS[bitrate_index], [11_025, 12_000, 8_000], 72),
    };
    let length = coefficient * kbps * 1000 / rates[rate_index] + padding;
    usize::try_from(length).ok().filter(|length| *length >= 4)
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
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests build synthetic fixtures in temporary directories"
)]
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
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&2_u32.to_be_bytes());
        png.extend_from_slice(&3_u32.to_be_bytes());
        fs::write(temporary.path().join("pixel.png"), png).unwrap();

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
    fn exact_limit_is_allowed_and_one_extra_byte_is_rejected_for_buffered_text() {
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

    #[tokio::test]
    async fn rendered_html_is_doubly_sandboxed_and_network_dark() {
        let hostile =
            "<style>body{color:red}</style><script>fetch('https://attacker.invalid')</script>";
        let (_temporary, share, grant, path) = fixture(hostile.as_bytes(), "attack.html");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        let document = load(&authorized, &path, PreviewPolicy::new(4096).unwrap()).unwrap();
        let response = html_rendered_response(document).expect("rendered response");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let csp = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.starts_with("sandbox; default-src 'none'"));
        assert!(csp.contains("form-action 'none'"));
        assert!(csp.contains("navigate-to 'none'"));
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), hostile.as_bytes());
    }

    #[tokio::test]
    async fn unread_image_bodies_hold_a_download_slot_until_released() {
        use crate::browse::MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT;

        let fixture = api_fixture(4096);
        let image = |identity: &AuthenticatedIdentity| {
            let identity = identity.clone();
            let app = fixture.app.clone();
            async move {
                send(
                    &app,
                    Some(&identity),
                    Request::get("/api/v1/shares/documents/preview/image?path=pixel.png")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
            }
        };
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT {
            let response = image(&fixture.identity).await;
            assert_eq!(response.status(), StatusCode::OK);
            held.push(response);
        }
        // The handler has returned for every held response; only the unread
        // bodies keep the slots, which downloads share.
        let busy = image(&fixture.identity).await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response_json(busy).await["error"]["code"], "busy");
        let download = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=pixel.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(download.status(), StatusCode::TOO_MANY_REQUESTS);

        // Another subject is not affected by this subject's limit.
        let other = AuthenticatedIdentity::new(
            "user-2",
            vec![ShareGrant {
                share_id: ShareId::new("documents").unwrap(),
                access: AccessLevel::ReadOnly,
            }],
        );
        assert_eq!(image(&other).await.status(), StatusCode::OK);

        // Dropping an unread body releases its slot.
        drop(held.pop());
        let response = image(&fixture.identity).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            image(&fixture.identity).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Reading a body to completion releases its slot too.
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap().len(),
            24
        );
        assert_eq!(image(&fixture.identity).await.status(), StatusCode::OK);
        drop(held);
    }

    #[tokio::test]
    async fn raster_images_are_signature_validated_and_served_with_fixed_types() {
        let fixture = api_fixture(4096);
        let metadata = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview?path=pixel.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(metadata.status(), StatusCode::OK);
        let document = response_json(metadata).await;
        assert_eq!(document["kind"], "image");
        assert_eq!(document["mimeType"], "image/png");
        assert_eq!(document["width"], 2);
        assert_eq!(document["height"], 3);

        let image = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview/image?path=pixel.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(image.status(), StatusCode::OK);
        assert_eq!(
            image.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        assert_eq!(
            image.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(image.headers().get(header::CONTENT_LENGTH).unwrap(), "24");
        assert_eq!(
            to_bytes(image.into_body(), 4096).await.unwrap().as_ref(),
            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x02\0\0\0\x03"
        );
    }

    #[test]
    fn raster_dimensions_are_bounded_before_browser_decode() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&20_000_u32.to_be_bytes());
        png.extend_from_slice(&20_000_u32.to_be_bytes());
        assert_eq!(validated_image(&png), Err(PreviewError::UnsupportedEntry));
    }

    #[test]
    fn html_endpoint_rejects_non_html_files() {
        let document = PreviewDocument {
            kind: PreviewKind::Text,
            source: "plain".into(),
            language: None,
            mime_type: None,
            width: None,
            height: None,
            size: 5,
            truncated: false,
            openable: true,
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
    async fn rendered_route_serves_html_only_to_frames() {
        let fixture = api_fixture(4096);
        let uri = "/api/v1/shares/documents/preview/html/rendered?path=hostile.html";
        let request = |destination: Option<&str>| {
            let mut request = Request::get(uri);
            if let Some(destination) = destination {
                request = request.header("sec-fetch-dest", destination);
            }
            request.body(Body::empty()).unwrap()
        };

        // The UI's iframe, and clients that do not report a destination.
        for destination in [Some("iframe"), None] {
            let response = send(&fixture.app, Some(&fixture.identity), request(destination)).await;
            assert_eq!(response.status(), StatusCode::OK, "{destination:?}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/html; charset=utf-8"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_SECURITY_POLICY)
                    .unwrap(),
                PREVIEW_CSP
            );
        }

        // A top-level tab, a script fetch, or any other embedding gets an
        // inert notice instead of the uploaded document.
        for destination in ["document", "empty", "frame", "object", "embed"] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                request(Some(destination)),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{destination}");
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
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains("sandboxed viewer"), "{body}");
            assert!(!body.contains("<script"), "{body}");
        }

        // The destination check never stands in for authentication.
        let unauthenticated = send(&fixture.app, None, request(Some("document"))).await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
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

    fn pdf_bytes() -> Vec<u8> {
        let mut pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        pdf.extend_from_slice(&[b'x'; 200]);
        pdf
    }

    fn ftyp(major: &[u8; 4], compatible: &[&[u8; 4]]) -> Vec<u8> {
        let size = u32::try_from(16 + 4 * compatible.len()).unwrap();
        let mut bytes = size.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(major);
        bytes.extend_from_slice(&[0, 0, 2, 0]);
        for brand in compatible {
            bytes.extend_from_slice(*brand);
        }
        bytes.extend_from_slice(b"\0\0\0\x08free");
        bytes
    }

    /// Two MPEG-1 Layer III frames at 128 kbit/s and 44.1 kHz (417 bytes).
    fn mp3_frames() -> Vec<u8> {
        let mut frames = vec![0xff, 0xfb, 0x90, 0x00];
        frames.resize(417, 0);
        frames.extend_from_slice(&[0xff, 0xfb, 0x90, 0x00]);
        frames.resize(834, 0);
        frames
    }

    fn streamed(bytes: &[u8]) -> Option<(PreviewKind, &'static str)> {
        classify_streamed(bytes)
            .expect("no dimension error")
            .map(|media| (media.kind(), media.mime_type()))
    }

    #[test]
    fn streamed_types_are_classified_from_signatures_only() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&2_u32.to_be_bytes());
        png.extend_from_slice(&3_u32.to_be_bytes());
        assert_eq!(streamed(&png), Some((PreviewKind::Image, "image/png")));
        assert_eq!(
            streamed(&pdf_bytes()),
            Some((PreviewKind::Pdf, "application/pdf"))
        );
        // A plain-ASCII PDF is still a PDF when the marker comes first.
        assert_eq!(
            streamed(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"),
            Some((PreviewKind::Pdf, "application/pdf"))
        );
        // Browsers accept a binary prefix before the marker in the first KiB.
        let mut prefixed = vec![0_u8; 100];
        prefixed.extend_from_slice(&pdf_bytes());
        assert_eq!(
            streamed(&prefixed),
            Some((PreviewKind::Pdf, "application/pdf"))
        );

        assert_eq!(
            streamed(&ftyp(b"isom", &[b"isom", b"mp41"])),
            Some((PreviewKind::Video, "video/mp4"))
        );
        assert_eq!(
            streamed(&ftyp(b"M4A ", &[b"M4A ", b"mp42"])),
            Some((PreviewKind::Audio, "audio/mp4"))
        );
        assert_eq!(
            streamed(b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\x82\x84webm\x42\x87\x81\x04"),
            Some((PreviewKind::Video, "video/webm"))
        );
        assert_eq!(
            streamed(b"\x1a\x45\xdf\xa3\xa3\x42\x82\x88matroska\x42\x87\x81\x04"),
            Some((PreviewKind::Video, "video/webm"))
        );
        let mut vorbis = b"OggS\0\x02".to_vec();
        vorbis.resize(26, 0);
        vorbis.extend_from_slice(b"\x01\x1e\x01vorbis");
        assert_eq!(streamed(&vorbis), Some((PreviewKind::Audio, "audio/ogg")));
        let mut theora = b"OggS\0\x02".to_vec();
        theora.resize(26, 0);
        theora.extend_from_slice(b"\x01\x2a\x80theora");
        assert_eq!(streamed(&theora), Some((PreviewKind::Video, "video/ogg")));
        assert_eq!(
            streamed(b"RIFF\x24\0\0\0WAVEfmt "),
            Some((PreviewKind::Audio, "audio/wav"))
        );
        assert_eq!(
            streamed(b"fLaC\x80\0\0\x22\x10\0"),
            Some((PreviewKind::Audio, "audio/flac"))
        );
        assert_eq!(
            streamed(b"ID3\x04\0\0\0\0\x01\x00TIT2"),
            Some((PreviewKind::Audio, "audio/mpeg"))
        );
        assert_eq!(
            streamed(&mp3_frames()),
            Some((PreviewKind::Audio, "audio/mpeg"))
        );
    }

    #[test]
    fn hostile_and_ambiguous_signatures_get_no_streamed_type() {
        // AVIF stays an image; image brands never become video.
        assert_eq!(
            streamed(&ftyp(b"avif", &[b"avif", b"mif1"])),
            Some((PreviewKind::Image, "image/avif"))
        );
        for (major, compatible) in [
            (b"mif1", vec![b"avif"]),
            (b"isom", vec![b"avif"]),
            (b"mp42", vec![b"heic"]),
            (b"heic", vec![b"mif1"]),
            (b"qt  ", vec![b"qt  "]),
            (b"3gp4", vec![b"isom"]),
        ] {
            assert_eq!(
                streamed(&ftyp(major, &compatible)),
                None,
                "{}",
                String::from_utf8_lossy(major)
            );
        }
        // A truncated or oversized ftyp box is not trusted.
        let mut truncated = ftyp(b"isom", &[b"isom"]);
        truncated[3] = 0xf0;
        assert_eq!(streamed(&truncated), None);

        // Active documents and text are never a streamed type, whatever the
        // name says.
        for text in [
            &b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"[..],
            b"<!doctype html><script>alert(1)</script>",
            b"<?xml version='1.0'?><x/>",
            // A note that mentions the marker near its start stays text.
            b"Header: %PDF-1.7 is how a PDF starts.\n",
            // Text that starts like a tag without the binary fields.
            b"ID3 tags hold MP3 titles\n",
            b"OggS is the Ogg capture pattern\n",
            b"fLaC is FLAC's marker\n",
        ] {
            assert_eq!(streamed(text), None, "{}", String::from_utf8_lossy(text));
        }

        // A polyglot whose marker comes after the first KiB is not a PDF.
        let mut late = vec![0_u8; PDF_SIGNATURE_WINDOW];
        late.extend_from_slice(&pdf_bytes());
        assert_eq!(streamed(&late), None);

        // One MPEG frame sync without a following frame is too weak.
        assert_eq!(streamed(&mp3_frames()[..420]), None);
        // ADTS AAC (layer bits 00) and MPEG layer II are not MP3.
        let mut aac = mp3_frames();
        aac[1] = 0xf1;
        assert_eq!(streamed(&aac), None);
        // Wrong FLAC STREAMINFO length and non-zero Ogg version.
        assert_eq!(streamed(b"fLaC\x80\0\0\x21\x10\0"), None);
        assert_eq!(
            streamed(b"OggS\x01\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x1e"),
            None
        );
        // EBML without a WebM or Matroska DocType.
        assert_eq!(streamed(b"\x1a\x45\xdf\xa3\x9f\x42\x82\x84abcd"), None);
    }

    #[test]
    fn text_prefix_tolerates_only_a_cut_trailing_character() {
        let cut = "é".as_bytes();
        let mut prefix = b"abc".to_vec();
        prefix.push(cut[0]);
        assert_eq!(check_text_prefix(&prefix, false), Ok(()));
        assert_eq!(
            check_text_prefix(&prefix, true),
            Err(PreviewError::InvalidUtf8)
        );
        assert_eq!(
            check_text_prefix(b"ab\xffcd", false),
            Err(PreviewError::InvalidUtf8)
        );
        assert_eq!(
            check_text_prefix(b"ab\0cd", false),
            Err(PreviewError::Binary)
        );
    }

    #[test]
    fn preview_limit_bounds_only_buffered_text() {
        let mut large_pdf = pdf_bytes();
        large_pdf.resize(4096, b' ');
        let (_temporary, share, grant, path) = fixture(&large_pdf, "report.txt");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        // A PDF named .txt is a PDF, and its size is not the preview limit's.
        let document = load(&authorized, &path, PreviewPolicy::new(16).unwrap()).unwrap();
        assert_eq!(document.kind, PreviewKind::Pdf);
        assert_eq!(document.mime_type, Some("application/pdf"));
        assert_eq!(document.source, "");
        assert_eq!(document.size, 4096);
        assert!(document.openable);

        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>";
        let (_temporary, share, grant, path) = fixture(svg, "image.pdf");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        // SVG named .pdf is plain text and still bounded by the limit.
        let document = load(&authorized, &path, PreviewPolicy::new(4096).unwrap()).unwrap();
        assert_eq!(document.kind, PreviewKind::Text);
        assert!(document.openable);
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(16).unwrap()),
            Err(PreviewError::TooLarge)
        );
    }

    fn write_fixture(fixture: &ApiFixture, name: &str, contents: &[u8]) {
        fs::write(fixture._temporary.path().join(name), contents).unwrap();
    }

    async fn open(fixture: &ApiFixture, name: &str) -> Response {
        send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(format!("/api/v1/shares/documents/open?path={name}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    fn assert_preview_headers(response: &Response, label: &str) {
        let headers = response.headers();
        for (name, value) in [
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("cache-control", "no-store, private"),
            ("cross-origin-resource-policy", "same-origin"),
            ("x-frame-options", "SAMEORIGIN"),
            ("permissions-policy", PERMISSIONS_POLICY),
        ] {
            assert_eq!(headers.get(name).unwrap(), value, "{label}: {name}");
        }
    }

    #[tokio::test]
    async fn open_route_serves_signature_types_under_the_sandboxed_policy() {
        let fixture = api_fixture(32);
        write_fixture(&fixture, "report.pdf", &pdf_bytes());
        write_fixture(&fixture, "clip.mp4", &ftyp(b"isom", &[b"isom"]));
        write_fixture(&fixture, "song.mp3", &mp3_frames());
        write_fixture(
            &fixture,
            "vector.svg",
            b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        );
        write_fixture(&fixture, "fake.pdf", b"<html><script>alert(1)</script>");
        for (name, media_type, size) in [
            ("report.pdf", "application/pdf", "215"),
            ("clip.mp4", "video/mp4", "28"),
            ("song.mp3", "audio/mpeg", "834"),
            ("pixel.png", "image/png", "24"),
            // Text beyond the 32-byte preview limit still opens.
            ("large.txt", "text/plain; charset=utf-8", "128"),
            ("hostile.html", "text/plain; charset=utf-8", "84"),
            ("vector.svg", "text/plain; charset=utf-8", "71"),
            ("fake.pdf", "text/plain; charset=utf-8", "31"),
            ("main.rs", "text/plain; charset=utf-8", "13"),
        ] {
            let response = open(&fixture, name).await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            let headers = response.headers();
            assert_eq!(headers[header::CONTENT_TYPE], media_type, "{name}");
            assert_eq!(headers[header::CONTENT_DISPOSITION], "inline", "{name}");
            assert_eq!(headers[header::CONTENT_LENGTH], size, "{name}");
            assert_eq!(headers[header::ACCEPT_RANGES], "bytes", "{name}");
            assert!(headers.contains_key(header::ETAG), "{name}");
            // Every type, PDF included, keeps the sandboxed deny-by-default policy.
            assert_eq!(
                headers[header::CONTENT_SECURITY_POLICY],
                PREVIEW_CSP,
                "{name}"
            );
            assert_preview_headers(&response, name);
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(body.len().to_string(), size, "{name}");
        }
    }

    #[tokio::test]
    async fn open_route_refuses_binary_and_unrecognized_bytes() {
        let fixture = api_fixture(4096);
        write_fixture(&fixture, "movie.mov", &ftyp(b"qt  ", &[b"qt  "]));
        write_fixture(&fixture, "bad.txt", &[b'a', 0xff, 0xfe]);
        for (name, code) in [
            ("binary.txt", "binary_file"),
            ("movie.mov", "binary_file"),
            ("bad.txt", "invalid_utf8"),
        ] {
            let response = open(&fixture, name).await;
            assert_eq!(
                response.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{name}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_SECURITY_POLICY],
                PREVIEW_CSP
            );
            assert_eq!(response_json(response).await["code"], code, "{name}");
        }
    }

    #[tokio::test]
    async fn open_route_supports_ranges_and_conditional_requests() {
        let fixture = api_fixture(4096);
        write_fixture(&fixture, "report.pdf", &pdf_bytes());
        let full = open(&fixture, "report.pdf").await;
        // pdf.js switches to range requests only when the full response
        // advertises byte ranges with an exact, unencoded length.
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(full.headers()[header::ACCEPT_RANGES], "bytes");
        assert_eq!(full.headers()[header::CONTENT_LENGTH], "215");
        assert!(!full.headers().contains_key(header::CONTENT_ENCODING));
        let etag = full.headers()[header::ETAG].clone();
        let request = |range: Option<&str>, if_none_match: Option<&HeaderValue>| {
            let mut request = Request::get("/api/v1/shares/documents/open?path=report.pdf");
            if let Some(range) = range {
                request = request.header(header::RANGE, range);
            }
            if let Some(value) = if_none_match {
                request = request.header(header::IF_NONE_MATCH, value);
            }
            request.body(Body::empty()).unwrap()
        };

        let partial = send(
            &fixture.app,
            Some(&fixture.identity),
            request(Some("bytes=1-4"), None),
        )
        .await;
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.headers()[header::CONTENT_RANGE], "bytes 1-4/215");
        assert_eq!(partial.headers()[header::CONTENT_LENGTH], "4");
        assert_eq!(partial.headers()[header::ACCEPT_RANGES], "bytes");
        assert!(!partial.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(partial.headers()[header::CONTENT_TYPE], "application/pdf");
        assert_eq!(
            partial.headers()[header::CONTENT_SECURITY_POLICY],
            PREVIEW_CSP
        );
        assert_preview_headers(&partial, "partial");
        assert_eq!(
            to_bytes(partial.into_body(), 64).await.unwrap().as_ref(),
            b"PDF-"
        );

        let not_modified = send(
            &fixture.app,
            Some(&fixture.identity),
            request(None, Some(&etag)),
        )
        .await;
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_preview_headers(&not_modified, "not modified");

        let unsatisfiable = send(
            &fixture.app,
            Some(&fixture.identity),
            request(Some("bytes=999-"), None),
        )
        .await;
        assert_eq!(unsatisfiable.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            unsatisfiable.headers()[header::CONTENT_RANGE],
            "bytes */215"
        );
        // Error bodies keep the sandboxed policy too.
        assert_eq!(
            unsatisfiable.headers()[header::CONTENT_SECURITY_POLICY],
            PREVIEW_CSP
        );
        assert_preview_headers(&unsatisfiable, "unsatisfiable");
    }

    #[tokio::test]
    async fn open_route_is_authenticated_and_non_disclosing() {
        let fixture = api_fixture(4096);
        let uri = "/api/v1/shares/documents/open?path=main.rs";
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
        let missing_share = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/missing/open?path=main.rs")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(ungranted.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing_share.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(ungranted).await,
            response_json(missing_share).await
        );

        let missing_file = open(&fixture, "absent.pdf").await;
        assert_eq!(missing_file.status(), StatusCode::NOT_FOUND);
        let traversal = open(&fixture, "..%2Fsecret").await;
        assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn preview_json_reports_streamed_kinds_without_the_preview_limit() {
        let fixture = api_fixture(32);
        write_fixture(&fixture, "report.pdf", &pdf_bytes());
        write_fixture(&fixture, "song.mp3", &mp3_frames());
        write_fixture(
            &fixture,
            "clip.webm",
            b"\x1a\x45\xdf\xa3\x9f\x42\x82\x84webm",
        );
        for (name, kind, mime_type, openable) in [
            ("report.pdf", "pdf", "application/pdf", true),
            // Media plays in the panel, not as a sandboxed top-level tab.
            ("song.mp3", "audio", "audio/mpeg", false),
            ("clip.webm", "video", "video/webm", false),
        ] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get(format!("/api/v1/shares/documents/preview?path={name}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            let document = response_json(response).await;
            assert_eq!(document["kind"], kind, "{name}");
            assert_eq!(document["mimeType"], mime_type, "{name}");
            assert_eq!(document["source"], "", "{name}");
            assert_eq!(document["openable"], openable, "{name}");
        }
        let text = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview?path=main.rs")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response_json(text).await["openable"], true);
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

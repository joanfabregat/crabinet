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
//! images, PDF, allowlisted audio and video containers, a content-detected SVG
//! document within the render limit (as `image/svg+xml` under the sandboxed
//! CSP, which runs no script), and UTF-8 text, which is always `text/plain`.
//! The type comes from the bytes, never from the filename or an uploaded
//! `Content-Type`.

use std::io::{BufReader, Read, Seek as _, SeekFrom};

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
/// The default largest HTML file rendered and SVG shown as an image. Both
/// stream from the file handle, so this bounds the work a reader's browser is
/// handed, not server memory.
pub const DEFAULT_MAX_RENDER_BYTES: u64 = 32 * 1024 * 1024;
/// The render limit's ceiling, the download size cap that bounds every
/// streamed response.
pub const HARD_MAX_RENDER_BYTES: u64 = 1024 * 1024 * 1024;
/// The bounded prefix every preview and inline open reads to classify a file
/// by signature, and the prefix the open route checks for UTF-8 text.
const SIGNATURE_HEADER_BYTES: u64 = 64 * 1024;
/// Browsers accept `%PDF-` anywhere in the first kilobyte.
const PDF_SIGNATURE_WINDOW: usize = 1024;
pub(crate) const MAX_IMAGE_PIXELS: u64 = 100_000_000;
const IMAGE_STREAM_CHUNK_BYTES: usize = 64 * 1024;
/// The largest head returned for a text-like file above the preview limit
/// (and never more than that limit). It is a prefix of the signature header,
/// so a head needs no read beyond it.
const HEAD_MAX_BYTES: usize = 64 * 1024;
/// The most lines a head shows.
const HEAD_MAX_LINES: usize = 1000;
/// How much of a GIF the animation check walks looking for a second frame.
/// A GIF whose first frame alone is larger is treated as a still image.
const GIF_ANIMATION_SCAN_BYTES: u64 = 8 * 1024 * 1024;
const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";
const SVG_MIME_TYPE: &str = "image/svg+xml";

const PREVIEW_CSP: &str = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
    base-uri 'none'; form-action 'none'; frame-ancestors 'self'; navigate-to 'none'";
const TEXT_PLAIN_UTF8: &str = "text/plain; charset=utf-8";
const HTML_UTF8: &str = "text/html; charset=utf-8";
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
    /// A TIFF-based camera RAW file, shown only through its thumbnail.
    Raw,
    /// An SVG document, detected from its content, within the render limit:
    /// its source (a head above the preview limit) plus an image view of the
    /// whole file from `/preview/svg`.
    Svg,
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
    /// The whole file's size, also when `source` is only its head.
    pub size: u64,
    /// A text-like file above the preview limit returns only its head (see
    /// [`text_head_len`]) with `truncated: true`; `shown_bytes` and
    /// `shown_lines` then describe that head. A file within the limit is
    /// returned whole with `truncated: false` and neither field.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shown_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shown_lines: Option<u64>,
    /// Whether the UI offers `/open` as a top-level new tab: images, PDF,
    /// SVG (served as a sandboxed image), and text-like kinds (served as
    /// `text/plain`). Audio and video stream from `/open` into the panel's
    /// media elements only.
    pub openable: bool,
    /// Whether `/preview/html/rendered` renders this file: an `html_source`
    /// document, whole or a head, whose file is within the render limit.
    pub renderable: bool,
    /// Whether the panel shows this file through `/thumbnail`: PNG and JPEG
    /// images, still GIF and WebP images, and RAW files with an embedded
    /// JPEG preview. An animated GIF or WebP is `false`, so the panel shows
    /// the original and the animation plays; a thumbnail would be its first
    /// frame only.
    pub thumbnailable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreviewPolicy {
    max_bytes: u64,
    max_render_bytes: u64,
}

impl PreviewPolicy {
    /// A policy with the given buffered preview limit and the default
    /// render limit, or the preview limit when that is larger.
    pub fn new(configured_max_bytes: u64) -> Result<Self, PreviewError> {
        if configured_max_bytes == 0 || configured_max_bytes > HARD_MAX_PREVIEW_BYTES {
            return Err(PreviewError::InvalidLimit);
        }
        Ok(Self {
            max_bytes: configured_max_bytes,
            max_render_bytes: DEFAULT_MAX_RENDER_BYTES.max(configured_max_bytes),
        })
    }

    /// Sets the largest HTML file rendered and the largest SVG shown as an
    /// image. It is never below the preview limit, since every whole
    /// document renders, and never above [`HARD_MAX_RENDER_BYTES`].
    pub fn with_max_render_bytes(
        self,
        configured_max_render_bytes: u64,
    ) -> Result<Self, PreviewError> {
        if configured_max_render_bytes < self.max_bytes
            || configured_max_render_bytes > HARD_MAX_RENDER_BYTES
        {
            return Err(PreviewError::InvalidLimit);
        }
        Ok(Self {
            max_render_bytes: configured_max_render_bytes,
            ..self
        })
    }

    /// Lowers the render limit to `cap` when that is smaller.
    #[must_use]
    const fn with_render_cap(self, cap: u64) -> Self {
        Self {
            max_render_bytes: if cap < self.max_render_bytes {
                cap
            } else {
                self.max_render_bytes
            },
            ..self
        }
    }

    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    #[must_use]
    pub const fn max_render_bytes(self) -> u64 {
        self.max_render_bytes
    }
}

impl Default for PreviewPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_render_bytes: DEFAULT_MAX_RENDER_BYTES,
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
    #[error("thumbnail size is not one of the fixed sizes")]
    InvalidThumbnailSize,
    #[error("image is too large to thumbnail")]
    ThumbnailTooLarge,
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
            Self::InvalidThumbnailSize => "invalid_thumbnail_size",
            Self::ThumbnailTooLarge => "thumbnail_too_large",
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            // Do not disclose whether a share or entry exists to an unauthorized user.
            Self::AccessDenied | Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidPath | Self::InvalidThumbnailSize => StatusCode::BAD_REQUEST,
            Self::TooLarge | Self::ThumbnailTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
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
            Self::InvalidThumbnailSize => "Thumbnail size is not supported",
            Self::ThumbnailTooLarge => "Image is too large to thumbnail",
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

pub(crate) enum PreviewRequestError {
    Application(AppError),
    Preview(PreviewError),
    /// A complete response built elsewhere, such as a busy refusal with a
    /// route-specific `Retry-After`.
    Response(Box<Response>),
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
            Self::Response(response) => *response,
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
        .route("/shares/{share_id}/preview/svg", get(preview_svg))
        .route("/shares/{share_id}/open", get(open_inline))
}

/// Serves a whole SVG document as `image/svg+xml` for the panel's `<img>`.
///
/// The file must be UTF-8 text whose 64 KiB header is an SVG document (see
/// [`is_svg_document`]), and it must be within the render limit; a larger one
/// is refused rather than drawn from a partial document. The exact bytes
/// stream from the handle that was classified, under a download slot like
/// `/preview/image`, so memory is bounded by the chunk size, not the file.
async fn preview_svg(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<PreviewQuery>,
) -> Result<Response, PreviewRequestError> {
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let raw_path = query.path.as_deref().ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let browse = state.browse();
    let authorized = browse.authorize_owned(&identity, &share_id)?;
    let max_bytes = render_limit(&state);
    // The same slot discipline as `preview_image`: taken before the open,
    // moved through the blocking work, and then held by the body stream.
    let lease = browse.acquire_download(&identity)?;
    let (opened, lease) = run_blocking(move || {
        (
            open_streamed_text(&authorized.view(), &path).and_then(|mut text| {
                if !text.svg {
                    return Err(PreviewError::UnsupportedEntry);
                }
                if text.size > max_bytes {
                    return Err(PreviewError::TooLarge);
                }
                text.file
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| PreviewError::Unavailable)?;
                Ok(text)
            }),
            lease,
        )
    })
    .await?;
    let opened = opened?;
    let stream = ReaderStream::with_capacity(
        tokio::fs::File::from_std(opened.file).take(opened.size),
        IMAGE_STREAM_CHUNK_BYTES,
    )
    .map(move |chunk| {
        let _lease = &lease;
        chunk
    });
    Ok(image_response(
        Body::from_stream(stream),
        SVG_MIME_TYPE,
        opened.size,
    ))
}

/// The configured policy with its render limit kept within the download size
/// cap every streamed response shares, so the JSON preview and the streaming
/// routes agree on what renders.
fn effective_policy(state: &AppState) -> PreviewPolicy {
    state
        .preview_policy()
        .with_render_cap(state.browse().max_download_bytes())
}

/// The largest HTML file rendered and SVG shown as an image.
fn render_limit(state: &AppState) -> u64 {
    effective_policy(state).max_render_bytes()
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

/// Serves uploaded HTML as a sandboxed document for the UI's doubly-sandboxed
/// iframe. The response CSP forbids scripts, forms, same-origin access, network
/// requests, plugins, and storage capabilities wherever the document loads; the
/// route also refuses top-level loads from browsers that report one, because
/// only the iframe sandbox stops the document navigating its own tab.
///
/// The file streams whole from the validated handle, with the validators,
/// conditional requests, and single byte ranges of `/open`, so a document up
/// to the render limit costs the server a chunk of memory, not its size. A
/// larger file is `413`: a head is never rendered.
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
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let raw_path = query.path.as_deref().ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let browse = state.browse();
    let authorized = browse.authorize_owned(&identity, &share_id)?;
    let max_bytes = render_limit(&state);
    // The document streams in chunks like `/open`, so it takes a download
    // slot, held by the body, rather than a buffered-read permit.
    let lease = browse.acquire_download(&identity)?;
    let open_path = path.clone();
    let (opened, lease) = run_blocking(move || {
        (
            open_rendered_html(&authorized.view(), &open_path, max_bytes),
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
            response_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(HTML_UTF8));
            response_headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("inline"),
            );
            Ok(())
        },
    )
    .await?;
    apply_security_headers(response.headers_mut());
    Ok(response)
}

/// Opens an HTML file for rendering on a blocking thread.
///
/// The checks are the buffered preview's, on the same 64 KiB header: a
/// streamed signature, binary content, or invalid UTF-8 is `415`, as is a
/// file whose extension is not HTML or whose content is an SVG document. Only
/// then is a file above `max_bytes` refused with `413`. A document is never
/// rendered from its head: within the limit it streams whole.
fn open_rendered_html(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
    max_bytes: u64,
) -> Result<StreamedText, PreviewError> {
    let text = open_streamed_text(share, path)?;
    if classify(path).0 != PreviewKind::HtmlSource || text.svg {
        return Err(PreviewError::UnsupportedEntry);
    }
    if text.size > max_bytes {
        return Err(PreviewError::TooLarge);
    }
    Ok(text)
}

/// A text file opened to stream whole, classified from its header.
struct StreamedText {
    file: std::fs::File,
    size: u64,
    modified: Option<std::time::SystemTime>,
    file_id: u64,
    /// Whether the header is an SVG document.
    svg: bool,
}

/// Opens a file and applies the text-preview rules to its bounded header: a
/// streamed signature is unsupported, and binary controls or invalid UTF-8
/// (other than a character cut by the header bound) are refused. Bytes after
/// the header are not inspected; a browser decodes them as UTF-8, and an
/// invalid sequence there becomes U+FFFD (HTML) or a parse error (SVG).
fn open_streamed_text(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
) -> Result<StreamedText, PreviewError> {
    let opened = share
        .open_file(path)
        .map_err(|error| PreviewError::from(error.code()))?;
    let size = opened.len();
    let modified = opened.modified();
    let file_id = opened.file_id();
    let mut file = opened.into_std();
    let header = read_signature_header(&mut file, size)?;
    if classify_streamed(&header)?.is_some() {
        return Err(PreviewError::UnsupportedEntry);
    }
    let svg = is_svg_document(check_text_prefix(&header, header_reached_end(&header))?);
    Ok(StreamedText {
        file,
        size,
        modified,
        file_id,
        svg,
    })
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
    let max_svg_bytes = render_limit(&state);
    // The same slot discipline as `preview_image` and downloads.
    let lease = browse.acquire_download(&identity)?;
    let open_path = path.clone();
    let (opened, lease) = run_blocking(move || {
        (
            open_for_inline(&authorized.view(), &open_path, max_bytes, max_svg_bytes),
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
    // Every inline response, PDF and SVG included, keeps the sandboxed
    // deny-by-default policy: Chromium's and Firefox's PDF viewers render a
    // top-level PDF under it, and it keeps a top-level SVG from running
    // script, loading resources, or submitting forms (see docs/previews.md),
    // so no type needs an exception.
    apply_security_headers(response.headers_mut());
    Ok(response)
}

/// What the open route serves, decided from the file's bytes only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InlineContent {
    Media(StreamedMedia),
    /// An SVG document within the render limit, `image/svg+xml`.
    Svg,
    /// UTF-8 text, including HTML, XML, and SVG above the render limit,
    /// always `text/plain`.
    Text,
}

impl InlineContent {
    const fn media_type(self) -> &'static str {
        match self {
            Self::Media(media) => media.mime_type(),
            Self::Svg => SVG_MIME_TYPE,
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
///
/// UTF-8 text whose header is an SVG document is served as an image only up
/// to `max_svg_bytes`, the render limit, like the panel's image view; a
/// larger SVG opens as `text/plain` source.
fn open_for_inline(
    share: &AuthorizedShare<'_>,
    path: &VirtualPath,
    max_bytes: u64,
    max_svg_bytes: u64,
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
            let text = check_text_prefix(&header, header_reached_end(&header))?;
            if size <= max_svg_bytes && is_svg_document(text) {
                InlineContent::Svg
            } else {
                InlineContent::Text
            }
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
    let policy = effective_policy(state);
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
///
/// Text is checked for invalid UTF-8 and binary controls on the header before
/// its size is considered, so an unrecognized binary file of any size is
/// `415`, not `413`. A text-like file within the limit is returned whole; a
/// larger one returns only its head (see [`text_head_len`]), cut from the
/// header already read, so no more than [`HEAD_MAX_BYTES`] of it is buffered
/// whatever its size.
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
        // AVIF and HEIF (including HEIC) are served as the original only: no
        // permissively licensed pure-Rust decoder exists, and only some
        // browsers decode them. An animated GIF or WebP is served as the
        // original too, because its thumbnail would be a still first frame.
        let thumbnailable = match media {
            StreamedMedia::Image(ImageInfo {
                mime_type: "image/png" | "image/jpeg",
                ..
            }) => true,
            StreamedMedia::Image(ImageInfo {
                mime_type: "image/webp",
                ..
            }) => !webp_is_animated(&header),
            StreamedMedia::Image(ImageInfo {
                mime_type: "image/gif",
                ..
            }) => {
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| PreviewError::Unavailable)?;
                !gif_is_animated(Read::by_ref(&mut file))
            }
            _ => false,
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
            shown_bytes: None,
            shown_lines: None,
            openable: media.opens_in_tab(),
            renderable: false,
            thumbnailable,
        });
    }
    // A TIFF-based RAW container is shown through its embedded JPEG preview
    // only: it is never served by `/open` and has no media type. The walk is
    // bounded (see `thumbnail::tiff`) and reads only directory entries and
    // the candidates' JPEG headers.
    if crate::thumbnail::tiff::is_tiff(&header)
        && size <= crate::thumbnail::decode::MAX_SOURCE_BYTES
        && let Ok(Some(_)) = crate::thumbnail::decode::raw_preview(&mut file, size)
    {
        return Ok(PreviewDocument {
            kind: PreviewKind::Raw,
            source: String::new(),
            language: None,
            mime_type: None,
            width: None,
            height: None,
            size,
            truncated: false,
            shown_bytes: None,
            shown_lines: None,
            openable: false,
            renderable: false,
            thumbnailable: true,
        });
    }
    // Binary and invalid UTF-8 are decided on the header before the size, so
    // an unrecognized binary file is never reported as too large to preview.
    let header_text = check_text_prefix(&header, header_reached_end(&header))?;
    let (path_kind, path_language) = classify(path);
    let renderable =
        |kind: PreviewKind| kind == PreviewKind::HtmlSource && size <= policy.max_render_bytes();
    if size > policy.max_bytes() {
        // The head is a prefix of the header that was just validated, so it
        // is valid UTF-8 without binary controls once cut on a character
        // boundary. Nothing beyond the header is read.
        let window = usize::try_from(policy.max_bytes())
            .unwrap_or(usize::MAX)
            .min(HEAD_MAX_BYTES)
            .min(header.len());
        let head = &header[..text_head_len(&header[..window])];
        let source = std::str::from_utf8(head)
            .map_err(|_| PreviewError::InvalidUtf8)?
            .to_owned();
        let shown_lines = line_count(&source);
        // The image view streams the whole document from `/preview/svg`, so
        // an SVG within the render limit keeps its kind and shows its head as
        // source. A larger one previews as source only.
        let (kind, language) = if size <= policy.max_render_bytes() && is_svg_document(header_text)
        {
            (PreviewKind::Svg, Some("xml"))
        } else {
            (path_kind, path_language)
        };
        return Ok(PreviewDocument {
            kind,
            language,
            mime_type: None,
            width: None,
            height: None,
            size,
            truncated: true,
            shown_bytes: Some(source.len() as u64),
            shown_lines: Some(shown_lines),
            source,
            // `/open` serves the whole file as `text/plain` within the
            // download limit, or an SVG as a sandboxed image.
            openable: true,
            // The full-window viewer streams the whole document; the panel
            // shows the head as source only.
            renderable: renderable(kind),
            thumbnailable: false,
        });
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
    // SVG is recognized from the content alone, never from the extension.
    let (kind, language) = if is_svg_document(&source) {
        (PreviewKind::Svg, Some("xml"))
    } else {
        (path_kind, path_language)
    };
    Ok(PreviewDocument {
        kind,
        source,
        language,
        mime_type: None,
        width: None,
        height: None,
        size,
        truncated: false,
        shown_bytes: None,
        shown_lines: None,
        // Served by `/open` as `text/plain`, whatever the extension says, or
        // for SVG as a sandboxed image.
        openable: true,
        renderable: renderable(kind),
        thumbnailable: false,
    })
}

/// The length of the head shown for a text-like file above the preview
/// limit, given the first `window` bytes of that file.
///
/// The head ends after the 1,000th line feed when the window holds that many;
/// otherwise after the window's last line feed; and when the window holds no
/// line feed at all (one long line), at the last UTF-8 character boundary
/// within it. A CRLF line ends at its `\n`, so the pair is never split.
fn text_head_len(window: &[u8]) -> usize {
    if let Some(index) = window
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .map(|(index, _)| index)
        .nth(HEAD_MAX_LINES - 1)
    {
        return index + 1;
    }
    if let Some(index) = window.iter().rposition(|byte| *byte == b'\n') {
        return index + 1;
    }
    match std::str::from_utf8(window) {
        Ok(_) => window.len(),
        Err(error) => error.valid_up_to(),
    }
}

/// Lines in `text`, counting a final line without a line feed.
fn line_count(text: &str) -> u64 {
    let feeds = text.bytes().filter(|byte| *byte == b'\n').count() as u64;
    if text.is_empty() || text.ends_with('\n') {
        feeds
    } else {
        feeds + 1
    }
}

/// Whether a WebP header declares an animation: the VP8X animation flag, or
/// an `ANIM` or `ANMF` chunk among the chunks within the header.
fn webp_is_animated(header: &[u8]) -> bool {
    const VP8X_ANIMATION_FLAG: u8 = 0x02;
    if header.len() >= 21 && &header[12..16] == b"VP8X" && header[20] & VP8X_ANIMATION_FLAG != 0 {
        return true;
    }
    let mut offset = 12_usize;
    while let Some(chunk) = header.get(offset..offset + 8) {
        if &chunk[..4] == b"ANIM" || &chunk[..4] == b"ANMF" {
            return true;
        }
        let Ok(length) =
            usize::try_from(u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]))
        else {
            return false;
        };
        // Chunk payloads are padded to an even length.
        offset = match offset
            .checked_add(8)
            .and_then(|end| end.checked_add(length))
            .and_then(|end| end.checked_add(length & 1))
        {
            Some(next) => next,
            None => return false,
        };
    }
    false
}

/// Whether a GIF holds a second image, walking its blocks from the start.
///
/// The walk reads at most [`GIF_ANIMATION_SCAN_BYTES`] and skips image data
/// and extensions sub-block by sub-block, so its work is bounded whatever the
/// file says. A malformed stream, or one whose second image starts beyond the
/// bound, is reported as still: its thumbnail is then its first frame, as
/// before.
fn gif_is_animated(reader: impl Read) -> bool {
    gif_image_count(reader, 2) >= 2
}

fn gif_image_count(reader: impl Read, stop_at: usize) -> usize {
    fn skip(reader: &mut impl Read, length: u64) -> Option<()> {
        let copied =
            std::io::copy(&mut Read::by_ref(reader).take(length), &mut std::io::sink()).ok()?;
        (copied == length).then_some(())
    }
    fn skip_sub_blocks(reader: &mut impl Read) -> Option<()> {
        loop {
            let mut length = [0_u8];
            reader.read_exact(&mut length).ok()?;
            if length[0] == 0 {
                return Some(());
            }
            skip(reader, u64::from(length[0]))?;
        }
    }
    let mut reader = BufReader::with_capacity(
        IMAGE_STREAM_CHUNK_BYTES,
        reader.take(GIF_ANIMATION_SCAN_BYTES),
    );
    let mut images = 0;
    let mut screen = [0_u8; 13];
    if reader.read_exact(&mut screen).is_err()
        || !(screen.starts_with(b"GIF87a") || screen.starts_with(b"GIF89a"))
    {
        return images;
    }
    let color_table = |packed: u8| {
        if packed & 0x80 == 0 {
            0
        } else {
            3_u64 << ((packed & 0x07) + 1)
        }
    };
    if skip(&mut reader, color_table(screen[10])).is_none() {
        return images;
    }
    while images < stop_at {
        let mut introducer = [0_u8];
        if reader.read_exact(&mut introducer).is_err() {
            break;
        }
        let step = match introducer[0] {
            // Image descriptor, optional local color table, LZW code size,
            // then the image data sub-blocks.
            0x2c => {
                images += 1;
                if images >= stop_at {
                    break;
                }
                let mut descriptor = [0_u8; 9];
                reader.read_exact(&mut descriptor).ok().and_then(|()| {
                    skip(&mut reader, color_table(descriptor[8]))?;
                    skip(&mut reader, 1)?;
                    skip_sub_blocks(&mut reader)
                })
            }
            // Extension: a label, then sub-blocks.
            0x21 => skip(&mut reader, 1).and_then(|()| skip_sub_blocks(&mut reader)),
            // Trailer, or anything that is not a GIF block.
            _ => None,
        };
        if step.is_none() {
            break;
        }
    }
    images
}

/// Whether `text` is an SVG document: after an optional byte-order mark, XML
/// declaration, comments, white space, and a `<!DOCTYPE svg …>` without an
/// internal subset, the first element is an unprefixed `<svg>` whose start
/// tag declares the SVG namespace as its default namespace (`xmlns` exactly
/// `http://www.w3.org/2000/svg`). Anything else, including another processing
/// instruction such as `xml-stylesheet`, a prefixed root, or a start tag cut
/// by the header bound, is not SVG and stays text. Only the first 64 KiB are
/// examined.
fn is_svg_document(text: &str) -> bool {
    fn after<'a>(rest: &'a str, terminator: &str) -> Option<&'a str> {
        rest.find(terminator)
            .map(|index| &rest[index + terminator.len()..])
    }
    fn is_xml_space(character: char) -> bool {
        matches!(character, ' ' | '\t' | '\r' | '\n')
    }
    let mut end = text.len().min(SIGNATURE_HEADER_BYTES as usize);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let text = &text[..end];
    let mut rest = text.strip_prefix('\u{feff}').unwrap_or(text);
    if let Some(declaration) = rest.strip_prefix("<?xml") {
        if !declaration.starts_with(is_xml_space) {
            return false;
        }
        let Some(next) = after(declaration, "?>") else {
            return false;
        };
        rest = next;
    }
    let mut seen_doctype = false;
    loop {
        rest = rest.trim_start_matches(is_xml_space);
        if let Some(comment) = rest.strip_prefix("<!--") {
            let Some(next) = after(comment, "-->") else {
                return false;
            };
            rest = next;
        } else if let Some(doctype) = rest.strip_prefix("<!DOCTYPE") {
            let Some(close) = doctype.find('>') else {
                return false;
            };
            let declaration = &doctype[..close];
            // One doctype naming `svg`, and no internal subset, which could
            // declare entities.
            if seen_doctype
                || declaration.contains('[')
                || !declaration.starts_with(is_xml_space)
                || declaration
                    .trim_start_matches(is_xml_space)
                    .split(is_xml_space)
                    .next()
                    != Some("svg")
            {
                return false;
            }
            seen_doctype = true;
            rest = &doctype[close + 1..];
        } else {
            break;
        }
    }
    let Some(mut tag) = rest.strip_prefix("<svg") else {
        return false;
    };
    if !tag.starts_with(|character: char| is_xml_space(character) || matches!(character, '>' | '/'))
    {
        return false;
    }
    let mut svg_namespace = false;
    loop {
        tag = tag.trim_start_matches(is_xml_space);
        if tag.starts_with('>') || tag.starts_with("/>") {
            return svg_namespace;
        }
        let name_end = tag
            .find(|character: char| is_xml_space(character) || matches!(character, '=' | '>' | '/'))
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        let Some(value) = tag[name_end..]
            .trim_start_matches(is_xml_space)
            .strip_prefix('=')
        else {
            return false;
        };
        let value = value.trim_start_matches(is_xml_space);
        let Some(quote) = value
            .chars()
            .next()
            .filter(|quote| matches!(quote, '"' | '\''))
        else {
            return false;
        };
        let value = &value[1..];
        let Some(close) = value.find(quote) else {
            return false;
        };
        if name.is_empty() {
            return false;
        }
        if name == "xmlns" {
            if &value[..close] != SVG_NAMESPACE {
                return false;
            }
            svg_namespace = true;
        }
        tag = &value[close + 1..];
    }
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
/// character is tolerated; any other invalid sequence is not. Returns the
/// valid text, without such a cut character.
fn check_text_prefix(header: &[u8], at_end: bool) -> Result<&str, PreviewError> {
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
    Ok(text)
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
///
/// It serves only a whole buffered document: a file above the preview limit
/// is `413`, and the panel shows its head from the JSON preview instead.
pub fn html_source_response(document: PreviewDocument) -> Result<Response, PreviewError> {
    if document.kind != PreviewKind::HtmlSource {
        return Err(PreviewError::UnsupportedEntry);
    }
    if document.truncated {
        return Err(PreviewError::TooLarge);
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
    if let Some(mime_type) = classify_heif(bytes) {
        return Some(ImageInfo {
            mime_type,
            width: None,
            height: None,
        });
    }
    None
}

/// AVIF brands. A file naming one is AVIF whatever else it lists, because an
/// AVIF file is also a HEIF (`mif1`/`msf1`) file.
const AVIF_BRANDS: [&[u8; 4]; 2] = [b"avif", b"avis"];
/// HEVC-coded HEIF brands: still images (`heic`, `heix`), their multi-view
/// and scalable variants (`heim`, `heis`), and image sequences (`hevc`,
/// `hevx`). All are served as `image/heic`.
const HEIC_BRANDS: [&[u8; 4]; 6] = [b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx"];
/// Generic HEIF structural brands, served as `image/heif` when no AVIF or
/// HEVC brand says more.
const HEIF_BRANDS: [&[u8; 4]; 4] = [b"mif1", b"mif2", b"msf1", b"miaf"];

/// AVIF, HEIC, or another HEIF image, from the brands of a leading `ftyp`
/// box. None of them is decoded on the server: they are served as the
/// original for the browser to decode. A major brand `avif` is AVIF even in a
/// box that is not complete within the header, as it always has been; every
/// other match needs a complete `ftyp` box.
fn classify_heif(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 12 || &bytes[4..8] != b"ftyp" {
        return None;
    }
    if bytes[8..12].starts_with(b"avif") {
        return Some("image/avif");
    }
    let brands = ftyp_brands(bytes)?;
    let names = |list: &[&[u8; 4]]| brands.clone().any(|brand| list.contains(&brand));
    if names(&AVIF_BRANDS) {
        Some("image/avif")
    } else if names(&HEIC_BRANDS) {
        Some("image/heic")
    } else if names(&HEIF_BRANDS) {
        Some("image/heif")
    } else {
        None
    }
}

/// The major and compatible brands of a complete leading `ftyp` box.
fn ftyp_brands(header: &[u8]) -> Option<impl Iterator<Item = &[u8; 4]> + Clone> {
    if header.len() < 16 || &header[4..8] != b"ftyp" {
        return None;
    }
    let size = usize::try_from(u32::from_be_bytes(header[0..4].try_into().ok()?)).ok()?;
    if size < 16 || size % 4 != 0 || size > header.len() {
        return None;
    }
    let major: &[u8; 4] = header[8..12].try_into().ok()?;
    let (compatible, _) = header[16..size].as_chunks::<4>();
    Some(std::iter::once(major).chain(compatible))
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
/// Raster images come first, so an AVIF or HEIF `ftyp` is never served as
/// video and image polyglots keep their pixel cap. `Ok(None)` means the bytes
/// match no streamed type; the caller may then try the UTF-8 text rules.
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
/// [`classify_image`] claims these first; this list keeps the MP4 rules safe
/// on their own.
const IMAGE_BRANDS: [&[u8; 4]; 12] = [
    b"avif", b"avis", b"mif1", b"mif2", b"msf1", b"miaf", b"heic", b"heix", b"heim", b"heis",
    b"hevc", b"hevx",
];

/// An ISO base media file must start with a complete `ftyp` box whose major
/// brand is allowlisted and whose compatible brands name no image format.
fn classify_iso_bmff(header: &[u8]) -> Option<StreamedMedia> {
    let mut brands = ftyp_brands(header)?;
    if brands.clone().any(|brand| IMAGE_BRANDS.contains(&brand)) {
        return None;
    }
    let major = brands.next()?;
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

pub(crate) fn apply_security_headers(headers: &mut HeaderMap) {
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
        api_fixture_with(PreviewPolicy::new(max_bytes).unwrap())
    }

    fn api_fixture_with(policy: PreviewPolicy) -> ApiFixture {
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
            .with_preview_policy(policy);
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
    fn render_limit_is_at_least_the_preview_limit_and_at_most_the_download_cap() {
        let policy = PreviewPolicy::new(1024).unwrap();
        assert_eq!(policy.max_render_bytes(), DEFAULT_MAX_RENDER_BYTES);
        assert_eq!(
            PreviewPolicy::new(HARD_MAX_PREVIEW_BYTES)
                .unwrap()
                .max_render_bytes(),
            DEFAULT_MAX_RENDER_BYTES
        );
        assert_eq!(
            policy.with_max_render_bytes(1023),
            Err(PreviewError::InvalidLimit)
        );
        assert_eq!(
            policy.with_max_render_bytes(HARD_MAX_RENDER_BYTES + 1),
            Err(PreviewError::InvalidLimit)
        );
        assert_eq!(
            policy
                .with_max_render_bytes(1024)
                .unwrap()
                .max_render_bytes(),
            1024
        );
        assert_eq!(
            policy
                .with_max_render_bytes(HARD_MAX_RENDER_BYTES)
                .unwrap()
                .max_render_bytes(),
            HARD_MAX_RENDER_BYTES
        );
        // The ceiling is the download cap every streamed response shares.
        assert_eq!(
            HARD_MAX_RENDER_BYTES,
            BrowseLimits::default().max_download_bytes
        );
        assert_eq!(policy.with_render_cap(4096).max_render_bytes(), 4096);
    }

    #[test]
    fn exact_limit_is_whole_and_one_extra_byte_returns_a_head() {
        let (_temporary, share, grant, path) = fixture(b"hel\nlo", "hello.txt");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        let whole = load(&authorized, &path, PreviewPolicy::new(6).unwrap()).expect("preview");
        assert_eq!(whole.source, "hel\nlo");
        assert!(!whole.truncated);
        assert_eq!((whole.shown_bytes, whole.shown_lines), (None, None));
        let serialized = serde_json::to_value(&whole).unwrap();
        assert!(serialized.get("shownBytes").is_none());
        assert!(serialized.get("shownLines").is_none());

        let head = load(&authorized, &path, PreviewPolicy::new(5).unwrap()).expect("head");
        assert_eq!(head.source, "hel\n");
        assert!(head.truncated);
        assert_eq!(head.size, 6);
        assert_eq!((head.shown_bytes, head.shown_lines), (Some(4), Some(1)));
        assert!(head.openable);
        let serialized = serde_json::to_value(&head).unwrap();
        assert_eq!(serialized["shownBytes"], 4);
        assert_eq!(serialized["shownLines"], 1);
        assert_eq!(serialized["size"], 6);
    }

    fn head_of(contents: &[u8], name: &str, limit: u64) -> PreviewDocument {
        let (_temporary, share, grant, path) = fixture(contents, name);
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        load(&authorized, &path, PreviewPolicy::new(limit).unwrap()).expect("preview")
    }

    #[test]
    fn head_stops_at_one_thousand_lines_when_they_come_first() {
        let line = "0123456789\n";
        let contents = line.repeat(10_000);
        let document = head_of(contents.as_bytes(), "log.txt", HEAD_MAX_BYTES as u64);
        assert!(document.truncated);
        assert!(document.source == line.repeat(HEAD_MAX_LINES));
        assert_eq!(document.shown_lines, Some(1000));
        assert_eq!(document.shown_bytes, Some(11_000));
        assert_eq!(document.size, 110_000);
    }

    #[test]
    fn head_stops_at_the_last_line_feed_within_the_byte_window() {
        // 700 lines of 100 bytes: the 64 KiB window ends inside line 656.
        let line = format!("{}\n", "x".repeat(99));
        let contents = line.repeat(700);
        let document = head_of(contents.as_bytes(), "wide.txt", HEAD_MAX_BYTES as u64);
        assert!(document.truncated);
        let lines = HEAD_MAX_BYTES / 100;
        assert_eq!(document.source, line.repeat(lines));
        assert_eq!(document.shown_lines, Some(lines as u64));
        assert_eq!(document.shown_bytes, Some((lines * 100) as u64));

        // The window is never larger than the configured limit.
        let document = head_of(contents.as_bytes(), "wide.txt", 250);
        assert_eq!(document.source, line.repeat(2));
        assert_eq!(document.shown_lines, Some(2));
    }

    #[test]
    fn head_of_one_long_line_ends_on_a_character_boundary() {
        // ASCII: exactly the window.
        let document = head_of(&vec![b'a'; 200_000], "one-line.json", 4096);
        assert_eq!(document.source.len(), 4096);
        assert_eq!(document.shown_lines, Some(1));

        // A three-byte character straddles the 64 KiB window: it is dropped
        // whole, never split.
        let mut contents = vec![b'a'; HEAD_MAX_BYTES - 1];
        contents.extend_from_slice("€".as_bytes());
        contents.extend_from_slice(&vec![b'b'; 1000]);
        let document = head_of(&contents, "one-line.txt", HEAD_MAX_BYTES as u64);
        assert_eq!(document.source.len(), HEAD_MAX_BYTES - 1);
        assert!(document.source.bytes().all(|byte| byte == b'a'));
        assert_eq!(document.shown_bytes, Some((HEAD_MAX_BYTES - 1) as u64));
        assert_eq!(document.shown_lines, Some(1));
    }

    #[test]
    fn head_keeps_crlf_pairs_whole() {
        let contents = "line one\r\nline two\r\nline three\r\n".repeat(100);
        let document = head_of(contents.as_bytes(), "dos.txt", 25);
        assert_eq!(document.source, "line one\r\nline two\r\n");
        assert_eq!(document.shown_lines, Some(2));
        // A window ending between `\r` and `\n` keeps only complete lines.
        let document = head_of(contents.as_bytes(), "dos.txt", 19);
        assert_eq!(document.source, "line one\r\n");
        assert_eq!(document.shown_lines, Some(1));
    }

    #[test]
    fn head_of_a_huge_file_is_bounded_by_the_window() {
        let temporary = TempDir::new().expect("temporary directory");
        let file = fs::File::create(temporary.path().join("huge.log")).unwrap();
        // Sparse: 1 GiB of NUL bytes after a text start. Only the header is
        // read, so the NULs beyond it are never seen and nothing near the
        // file's size is allocated.
        file.set_len(1 << 30).unwrap();
        {
            use std::io::Write as _;
            let mut file = file;
            file.write_all("entry\n".repeat(20_000).as_bytes()).unwrap();
        }
        let id = ShareId::new("documents").unwrap();
        let share = ShareFs::open(id.clone(), temporary.path()).unwrap();
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadOnly,
        };
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let document = load(
            &authorized,
            &VirtualPath::parse("huge.log").unwrap(),
            PreviewPolicy::new(HARD_MAX_PREVIEW_BYTES).unwrap(),
        )
        .unwrap();
        assert!(document.truncated);
        assert_eq!(document.size, 1 << 30);
        assert_eq!(document.source, "entry\n".repeat(HEAD_MAX_LINES));
        assert!(document.source.capacity() <= HEAD_MAX_BYTES);
    }

    #[test]
    fn oversized_binary_is_unsupported_not_too_large() {
        // A QuickTime ISO-BMFF file has no streamed type and is binary.
        let mut movie = 24_u32.to_be_bytes().to_vec();
        movie.extend_from_slice(b"ftypqt  \0\0\0\0qt  qt  ");
        movie.resize(4096, 0);
        let (_temporary, share, grant, path) = fixture(&movie, "movie.mov");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(64).unwrap()),
            Err(PreviewError::Binary)
        );
        // Invalid UTF-8 without controls is reported as such, also above
        // the limit.
        let mut latin1 = b"caf\xe9 ".repeat(100);
        latin1.push(b'\n');
        let (_temporary, share, grant, path) = fixture(&latin1, "latin1.txt");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        assert_eq!(
            load(&authorized, &path, PreviewPolicy::new(64).unwrap()),
            Err(PreviewError::InvalidUtf8)
        );
    }

    #[test]
    fn truncated_markdown_and_html_return_their_head_as_source() {
        let markdown = "# Title\n\nparagraph\n".repeat(100);
        let document = head_of(markdown.as_bytes(), "notes.md", 64);
        assert_eq!(document.kind, PreviewKind::MarkdownSource);
        assert!(document.truncated);
        assert_eq!(document.source, "# Title\n\nparagraph\n".repeat(3));

        let html = "<p>hello</p>\n".repeat(100);
        let document = head_of(html.as_bytes(), "page.html", 64);
        assert_eq!(document.kind, PreviewKind::HtmlSource);
        assert!(document.truncated);
        assert_eq!(document.source, "<p>hello</p>\n".repeat(4));
        // The rendered endpoint streams the whole file within the render
        // limit, but the source endpoint never serves a head.
        assert!(document.renderable);
        assert_eq!(
            html_source_response(document).expect_err("truncated source"),
            PreviewError::TooLarge
        );
        let (_temporary, share, grant, path) = fixture(html.as_bytes(), "page.html");
        let authorized = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .expect("authorized");
        let policy = PreviewPolicy::new(64).unwrap();
        let at_limit = policy.with_max_render_bytes(html.len() as u64).unwrap();
        assert!(load(&authorized, &path, at_limit).unwrap().renderable);
        let below = policy.with_max_render_bytes(html.len() as u64 - 1).unwrap();
        let document = load(&authorized, &path, below).unwrap();
        assert_eq!(document.kind, PreviewKind::HtmlSource);
        assert!(!document.renderable);
        // Nothing but HTML renders.
        assert!(!head_of(markdown.as_bytes(), "notes.md", 4096).renderable);
        assert!(head_of(html.as_bytes(), "page.html", 4096).renderable);
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
        let fixture = api_fixture(4096);
        write_fixture(&fixture, "attack.html", hostile.as_bytes());
        let response = rendered(&fixture, "attack.html", &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
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

    /// Requests the rendered endpoint as the UI's iframe does.
    async fn rendered(fixture: &ApiFixture, name: &str, extra: &[(&str, &str)]) -> Response {
        let mut request = Request::get(format!(
            "/api/v1/shares/documents/preview/html/rendered?path={name}"
        ))
        .header("sec-fetch-dest", "iframe");
        for (header_name, value) in extra {
            request = request.header(*header_name, *value);
        }
        send(
            &fixture.app,
            Some(&fixture.identity),
            request.body(Body::empty()).unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn rendered_route_streams_documents_up_to_the_render_limit() {
        let fixture = api_fixture_with(
            PreviewPolicy::new(64)
                .unwrap()
                .with_max_render_bytes(4096)
                .unwrap(),
        );
        let small = "\u{feff}<p>small</p>\n";
        // Above the preview limit, within the render limit.
        let large = format!("<!doctype html>\n{}", "<p>\u{e9}t\u{e9}</p>\n".repeat(200));
        assert!(large.len() > 64 && large.len() <= 4096);
        write_fixture(&fixture, "small.html", small.as_bytes());
        write_fixture(&fixture, "large.html", large.as_bytes());
        write_fixture(&fixture, "huge.html", "<p>x</p>\n".repeat(600).as_bytes());

        let small_response = rendered(&fixture, "small.html", &[]).await;
        let large_response = rendered(&fixture, "large.html", &[]).await;
        for (response, body) in [(&small_response, small), (&large_response, large.as_str())] {
            assert_eq!(response.status(), StatusCode::OK);
            let headers = response.headers();
            assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
            assert_eq!(headers[header::CONTENT_DISPOSITION], "inline");
            assert_eq!(headers[header::CONTENT_SECURITY_POLICY], PREVIEW_CSP);
            assert_eq!(headers[header::CONTENT_LENGTH], body.len().to_string());
            assert_eq!(headers[header::ACCEPT_RANGES], "bytes");
            assert!(headers.contains_key(header::ETAG));
            assert_preview_headers(response, "rendered");
        }
        // Whatever the size, the same headers, and only their values differ
        // where the file does.
        let names = |response: &Response| {
            let mut names = response
                .headers()
                .keys()
                .map(|name| name.as_str().to_owned())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        assert_eq!(names(&small_response), names(&large_response));
        for name in [
            header::CONTENT_TYPE,
            header::CONTENT_DISPOSITION,
            header::CONTENT_SECURITY_POLICY,
            header::CACHE_CONTROL,
        ] {
            assert_eq!(
                small_response.headers()[&name],
                large_response.headers()[&name]
            );
        }
        // The exact bytes, a byte-order mark included.
        let etag = large_response.headers()[header::ETAG].clone();
        assert_eq!(
            to_bytes(small_response.into_body(), 4096)
                .await
                .unwrap()
                .as_ref(),
            small.as_bytes()
        );
        assert_eq!(
            to_bytes(large_response.into_body(), 8192)
                .await
                .unwrap()
                .as_ref(),
            large.as_bytes()
        );

        // Conditional requests and ranges behave as on `/open`.
        let unchanged = rendered(
            &fixture,
            "large.html",
            &[("if-none-match", etag.to_str().unwrap())],
        )
        .await;
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            unchanged.headers()[header::CONTENT_SECURITY_POLICY],
            PREVIEW_CSP
        );
        let partial = rendered(&fixture, "large.html", &[("range", "bytes=0-14")]).await;
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            partial.headers()[header::CONTENT_RANGE],
            format!("bytes 0-14/{}", large.len())
        );
        assert_eq!(
            partial.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(
            partial.headers()[header::CONTENT_SECURITY_POLICY],
            PREVIEW_CSP
        );
        assert_eq!(
            to_bytes(partial.into_body(), 4096).await.unwrap().as_ref(),
            b"<!doctype html>"
        );

        // The JSON preview says which documents render.
        for (name, renderable) in [
            ("small.html", true),
            ("large.html", true),
            ("huge.html", false),
        ] {
            let document = response_json(
                send(
                    &fixture.app,
                    Some(&fixture.identity),
                    Request::get(format!("/api/v1/shares/documents/preview?path={name}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await,
            )
            .await;
            assert_eq!(document["kind"], "html_source", "{name}");
            assert_eq!(document["renderable"], renderable, "{name}");
        }

        // Above the render limit, and for anything but HTML text, the
        // checks and refusals are those of the buffered route.
        write_fixture(
            &fixture,
            "binary.html",
            &[b"<p>".as_slice(), &[0; 200]].concat(),
        );
        write_fixture(&fixture, "latin1.html", &b"<p>caf\xe9</p>\n".repeat(20));
        write_fixture(&fixture, "drawing.html", SVG.as_bytes());
        write_fixture(&fixture, "page.txt", b"<p>text</p>");
        for (name, status, code) in [
            (
                "huge.html",
                StatusCode::PAYLOAD_TOO_LARGE,
                "preview_too_large",
            ),
            (
                "binary.html",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "binary_file",
            ),
            (
                "latin1.html",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_utf8",
            ),
            (
                "drawing.html",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_entry",
            ),
            (
                "page.txt",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_entry",
            ),
            (
                "pixel.png",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_entry",
            ),
            ("absent.html", StatusCode::NOT_FOUND, "not_found"),
        ] {
            let response = rendered(&fixture, name, &[]).await;
            assert_eq!(response.status(), status, "{name}");
            assert_eq!(
                response.headers()[header::CONTENT_SECURITY_POLICY],
                PREVIEW_CSP,
                "{name}"
            );
            assert_eq!(response_json(response).await["code"], code, "{name}");
        }
    }

    #[tokio::test]
    async fn unread_rendered_bodies_hold_a_download_slot_not_a_buffered_permit() {
        use crate::browse::MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT;

        let fixture = api_fixture(4096);
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT {
            let response = rendered(&fixture, "hostile.html", &[]).await;
            assert_eq!(response.status(), StatusCode::OK);
            held.push(response);
        }
        let busy = rendered(&fixture, "hostile.html", &[]).await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        // Buffered previews are admitted separately.
        let preview = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview?path=hostile.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(preview.status(), StatusCode::OK);
        drop(held.pop());
        assert_eq!(
            rendered(&fixture, "hostile.html", &[]).await.status(),
            StatusCode::OK
        );
        drop(held);
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
            shown_bytes: None,
            shown_lines: None,
            openable: true,
            renderable: false,
            thumbnailable: false,
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
            // An unrecognized binary file above the limit is unsupported,
            // not too large.
            (
                "/api/v1/shares/documents/preview?path=large.bin",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "binary_file",
            ),
            (
                "/api/v1/shares/documents/preview?path=large-latin1.txt",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_utf8",
            ),
        ] {
            write_fixture(&fixture, "large.bin", &[0x7f, 0x01, 0x02, 0x03].repeat(64));
            write_fixture(&fixture, "large-latin1.txt", &b"na\xefve ".repeat(64));
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

    #[tokio::test]
    async fn oversized_text_previews_return_their_head_and_stay_openable() {
        let fixture = api_fixture(32);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview?path=large.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let document = response_json(response).await;
        assert_eq!(document["kind"], "text");
        assert_eq!(document["truncated"], true);
        assert_eq!(document["source"], "a".repeat(32));
        assert_eq!(document["size"], 128);
        assert_eq!(document["shownBytes"], 32);
        assert_eq!(document["shownLines"], 1);
        assert_eq!(document["openable"], true);
        // The whole file still opens as text.
        let opened = open(&fixture, "large.txt").await;
        assert_eq!(opened.status(), StatusCode::OK);
        assert_eq!(
            opened.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(to_bytes(opened.into_body(), 4096).await.unwrap().len(), 128);

        // The HTML source endpoint refuses a head instead of serving it; the
        // rendered endpoint streams the whole document within the render
        // limit.
        let long = "<p>x</p>\n".repeat(10);
        write_fixture(&fixture, "long.html", long.as_bytes());
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview/html?path=long.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response_json(response).await["code"], "preview_too_large");
        let response = rendered(&fixture, "long.html", &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap().as_ref(),
            long.as_bytes()
        );
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
        // AVIF and HEIF stay images; image brands never become video. An AVIF
        // brand wins over the HEIF brands every AVIF file also lists, and an
        // HEVC brand over the generic HEIF ones.
        for (major, compatible, media_type) in [
            (b"avif", vec![b"avif", b"mif1"], "image/avif"),
            (b"mif1", vec![b"avif"], "image/avif"),
            (b"mif1", vec![b"mif1", b"miaf", b"avif"], "image/avif"),
            (b"msf1", vec![b"avis", b"msf1"], "image/avif"),
            (b"isom", vec![b"avif"], "image/avif"),
            (b"heic", vec![b"mif1", b"heic"], "image/heic"),
            (b"heix", vec![b"mif1", b"heix"], "image/heic"),
            (b"mif1", vec![b"mif1", b"heic"], "image/heic"),
            (b"msf1", vec![b"msf1", b"hevc"], "image/heic"),
            (b"hevx", vec![b"msf1"], "image/heic"),
            (b"heim", vec![b"mif1"], "image/heic"),
            (b"mp42", vec![b"heic"], "image/heic"),
            (b"mif1", vec![b"mif1", b"miaf"], "image/heif"),
            (b"msf1", vec![b"msf1"], "image/heif"),
        ] {
            assert_eq!(
                streamed(&ftyp(major, &compatible)),
                Some((PreviewKind::Image, media_type)),
                "{} {compatible:?}",
                String::from_utf8_lossy(major)
            );
        }
        for (major, compatible) in [
            (b"qt  ", vec![b"qt  "]),
            (b"3gp4", vec![b"isom"]),
            (b"crx ", vec![b"crx "]),
        ] {
            assert_eq!(
                streamed(&ftyp(major, &compatible)),
                None,
                "{}",
                String::from_utf8_lossy(major)
            );
        }
        // A truncated or oversized ftyp box is not trusted, for HEIF either.
        let mut truncated = ftyp(b"isom", &[b"isom"]);
        truncated[3] = 0xf0;
        assert_eq!(streamed(&truncated), None);
        let mut truncated = ftyp(b"heic", &[b"mif1", b"heic"]);
        truncated[3] = 0xf0;
        assert_eq!(streamed(&truncated), None);
        let mut unaligned = ftyp(b"mif1", &[b"heic"]);
        unaligned[3] = 18;
        assert_eq!(streamed(&unaligned), None);

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

    /// A 2×2 GIF with `frames` images, each `data_blocks` sub-blocks of 255
    /// bytes long, and a Netscape looping extension when animated.
    fn gif(frames: usize, data_blocks: usize) -> Vec<u8> {
        let mut bytes = b"GIF89a\x02\x00\x02\x00\x80\x00\x00".to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        if frames > 1 {
            bytes.extend_from_slice(b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00");
        }
        for _ in 0..frames {
            // Graphic control extension, then an image with a local table.
            bytes.extend_from_slice(b"\x21\xf9\x04\x00\x0a\x00\x00\x00");
            bytes.extend_from_slice(b"\x2c\0\0\0\0\x02\0\x02\0\x80");
            bytes.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
            bytes.push(2);
            for _ in 0..data_blocks {
                bytes.push(255);
                bytes.extend_from_slice(&[0x2c; 255]);
            }
            bytes.extend_from_slice(b"\x02\x4c\x01\x00");
        }
        bytes.push(0x3b);
        bytes
    }

    fn webp(chunks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut body = b"WEBP".to_vec();
        for (name, payload) in chunks {
            body.extend_from_slice(*name);
            body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
            body.extend_from_slice(payload);
            if payload.len() % 2 == 1 {
                body.push(0);
            }
        }
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    fn vp8x(flags: u8) -> Vec<u8> {
        // Flags, three reserved bytes, then a 2×2 canvas (stored minus one).
        vec![flags, 0, 0, 0, 1, 0, 0, 1, 0, 0]
    }

    #[test]
    fn animated_gif_and_webp_are_detected_from_their_bytes() {
        assert!(!gif_is_animated(&gif(1, 0)[..]));
        assert!(gif_is_animated(&gif(2, 0)[..]));
        // A second frame after a large first one is still found, and a
        // looping extension alone does not make an animation.
        assert!(gif_is_animated(&gif(2, 2000)[..]));
        let mut looping_still = gif(1, 0);
        looping_still.splice(19..19, *b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00");
        assert!(!gif_is_animated(&looping_still[..]));
        // Malformed or cut streams are still images.
        let animated = gif(2, 0);
        assert!(!gif_is_animated(&animated[..40]));
        assert!(!gif_is_animated(&b"GIF89a"[..]));
        let mut corrupt = gif(2, 0);
        corrupt[19] = 0x99;
        assert!(!gif_is_animated(&corrupt[..]));
        // The walk stops at its byte bound: a second frame beyond it is not
        // looked for.
        let blocks = usize::try_from(GIF_ANIMATION_SCAN_BYTES / 256).unwrap() + 1;
        assert!(!gif_is_animated(&gif(2, blocks)[..]));

        let still = webp(&[(b"VP8L", vec![0x2f, 0x01, 0x40, 0x00, 0x00])]);
        assert!(!webp_is_animated(&still));
        let alpha = webp(&[(b"VP8X", vp8x(0x10)), (b"VP8L", vec![0x2f, 0, 0, 0, 0])]);
        assert!(!webp_is_animated(&alpha));
        let flagged = webp(&[(b"VP8X", vp8x(0x02)), (b"ANIM", vec![0; 6])]);
        assert!(webp_is_animated(&flagged));
        // An ANIM or ANMF chunk counts even without the flag.
        let unflagged = webp(&[(b"VP8X", vp8x(0)), (b"ANIM", vec![0; 6])]);
        assert!(webp_is_animated(&unflagged));
        let frame_only = webp(&[(b"VP8X", vp8x(0)), (b"ANMF", vec![0; 17])]);
        assert!(webp_is_animated(&frame_only));
        // A hostile chunk length ends the walk instead of overflowing.
        let mut hostile = webp(&[(b"VP8X", vp8x(0)), (b"EXIF", vec![0; 3])]);
        let length_at = 12 + 8 + 10 + 4;
        hostile[length_at..length_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!webp_is_animated(&hostile));
    }

    #[tokio::test]
    async fn animated_images_are_not_thumbnailable_so_the_original_plays() {
        let fixture = api_fixture(32);
        write_fixture(&fixture, "still.gif", &gif(1, 0));
        write_fixture(&fixture, "animated.gif", &gif(3, 1));
        write_fixture(
            &fixture,
            "still.webp",
            &webp(&[(b"VP8X", vp8x(0x10)), (b"VP8L", vec![0x2f, 0, 0, 0, 0])]),
        );
        write_fixture(
            &fixture,
            "animated.webp",
            &webp(&[(b"VP8X", vp8x(0x02)), (b"ANIM", vec![0; 6])]),
        );
        for (name, mime_type, thumbnailable) in [
            ("still.gif", "image/gif", true),
            ("animated.gif", "image/gif", false),
            ("still.webp", "image/webp", true),
            ("animated.webp", "image/webp", false),
            ("pixel.png", "image/png", true),
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
            assert_eq!(document["kind"], "image", "{name}");
            assert_eq!(document["mimeType"], mime_type, "{name}");
            assert_eq!(document["thumbnailable"], thumbnailable, "{name}");
            assert_eq!(document["openable"], true, "{name}");
            // The original is served either way, under the pixel cap.
            let original = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get(format!(
                    "/api/v1/shares/documents/preview/image?path={name}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await;
            assert_eq!(original.status(), StatusCode::OK, "{name}");
            assert_eq!(original.headers()[header::CONTENT_TYPE], mime_type);
        }
    }

    const SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"2\" height=\"2\"/>";

    #[test]
    fn svg_is_recognized_only_from_a_strict_root_element() {
        for svg in [
            SVG,
            "<svg xmlns='http://www.w3.org/2000/svg'><rect/></svg>",
            "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- drawn -->\n<svg\n  xmlns:xlink=\"http://www.w3.org/1999/xlink\"\n  xmlns = \"http://www.w3.org/2000/svg\" >",
            "<?xml version='1.0'?><!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\"><svg xmlns='http://www.w3.org/2000/svg'/>",
            "<svg viewBox='0 0 1 1' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        ] {
            assert!(is_svg_document(svg), "{svg}");
        }
        for text in [
            "",
            "plain text mentioning <svg xmlns='http://www.w3.org/2000/svg'>",
            // No namespace, the wrong namespace, or only a prefixed one.
            "<svg><rect/></svg>",
            "<svg xmlns='http://www.w3.org/2000/svg/'/>",
            "<svg xmlns='HTTP://WWW.W3.ORG/2000/SVG'/>",
            "<svg xmlns:svg='http://www.w3.org/2000/svg'/>",
            "<svg:svg xmlns:svg='http://www.w3.org/2000/svg'/>",
            "<svg xmlns='http://www.w3.org/2000/svg' xmlns='urn:x'/>",
            "<svg xmlns='http&#58;//www.w3.org/2000/svg'/>",
            // Another root, including HTML that embeds SVG.
            "<svgx xmlns='http://www.w3.org/2000/svg'/>",
            "<html><svg xmlns='http://www.w3.org/2000/svg'/></html>",
            "<!doctype html><svg xmlns='http://www.w3.org/2000/svg'/>",
            // Processing instructions, internal subsets, other doctypes.
            "<?xml-stylesheet href='https://attacker.invalid/x.css'?><svg xmlns='http://www.w3.org/2000/svg'/>",
            "<!DOCTYPE svg [<!ENTITY x 'y'>]><svg xmlns='http://www.w3.org/2000/svg'/>",
            "<!DOCTYPE html><svg xmlns='http://www.w3.org/2000/svg'/>",
            "<?xml version='1.0'?><?xml version='1.0'?><svg xmlns='http://www.w3.org/2000/svg'/>",
            " <?xml version='1.0'?><svg xmlns='http://www.w3.org/2000/svg'/>",
            // Unterminated comments, declarations, and start tags.
            "<!-- <svg xmlns='http://www.w3.org/2000/svg'/>",
            "<?xml version='1.0' <svg xmlns='http://www.w3.org/2000/svg'/>",
            "<svg xmlns='http://www.w3.org/2000/svg'",
            "<svg xmlns='http://www.w3.org/2000/svg",
            "<svg xmlns=http://www.w3.org/2000/svg>",
            "<svg width xmlns='http://www.w3.org/2000/svg'>",
        ] {
            assert!(!is_svg_document(text), "{text}");
        }
        // The root must start within the first 64 KiB.
        let late = format!("<!--{}-->{SVG}", " ".repeat(HEAD_MAX_BYTES));
        assert!(!is_svg_document(&late));
    }

    #[tokio::test]
    async fn svg_image_route_serves_only_whole_svg_documents() {
        let fixture = api_fixture_with(
            PreviewPolicy::new(4096)
                .unwrap()
                .with_max_render_bytes(16 * 1024)
                .unwrap(),
        );
        let hostile = concat!(
            "<?xml version=\"1.0\"?>\n",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\">",
            "<script>fetch('https://attacker.invalid/')</script>",
            "<image href=\"https://attacker.invalid/beacon.png\"/>",
            "<foreignObject><form xmlns=\"http://www.w3.org/1999/xhtml\" ",
            "action=\"https://attacker.invalid/\"><button>go</button></form></foreignObject>",
            "</svg>\n"
        );
        // Content decides: an SVG named .txt is an SVG, and SVG markup in a
        // `.svg` file without the namespace is not.
        write_fixture(&fixture, "drawing.txt", hostile.as_bytes());
        write_fixture(&fixture, "plain.svg", b"<svg><rect/></svg>");
        write_fixture(
            &fixture,
            "large.svg",
            format!(
                "{}>\n{}</svg>\n",
                &SVG[..SVG.len() - 2],
                "<rect/>\n".repeat(1000)
            )
            .as_bytes(),
        );
        let huge = format!(
            "{}>\n{}</svg>\n",
            &SVG[..SVG.len() - 2],
            "<rect/>\n".repeat(3000)
        );
        write_fixture(&fixture, "huge.svg", huge.as_bytes());

        let get = |uri: String| {
            let app = fixture.app.clone();
            let identity = fixture.identity.clone();
            async move {
                send(
                    &app,
                    Some(&identity),
                    Request::get(uri).body(Body::empty()).unwrap(),
                )
                .await
            }
        };
        let document =
            response_json(get("/api/v1/shares/documents/preview?path=drawing.txt".into()).await)
                .await;
        assert_eq!(document["kind"], "svg");
        assert_eq!(document["language"], "xml");
        assert_eq!(document["source"], hostile);
        assert_eq!(document["openable"], true);
        assert_eq!(document["thumbnailable"], false);
        assert_eq!(document["truncated"], false);

        let image = get("/api/v1/shares/documents/preview/svg?path=drawing.txt".into()).await;
        assert_eq!(image.status(), StatusCode::OK);
        assert_eq!(image.headers()[header::CONTENT_TYPE], "image/svg+xml");
        assert_eq!(image.headers()[header::CONTENT_DISPOSITION], "inline");
        assert_eq!(
            image.headers()[header::CONTENT_LENGTH],
            hostile.len().to_string()
        );
        assert_eq!(
            image.headers()[header::CONTENT_SECURITY_POLICY],
            PREVIEW_CSP
        );
        assert_preview_headers(&image, "svg image");
        assert_eq!(
            to_bytes(image.into_body(), 8192).await.unwrap().as_ref(),
            hostile.as_bytes()
        );

        let plain =
            response_json(get("/api/v1/shares/documents/preview?path=plain.svg".into()).await)
                .await;
        assert_eq!(plain["kind"], "code");
        assert_eq!(plain["language"], "xml");
        for (name, status, code) in [
            (
                "plain.svg",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_entry",
            ),
            (
                "main.rs",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_entry",
            ),
            (
                "pixel.png",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_entry",
            ),
            (
                "binary.txt",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "binary_file",
            ),
            // Above the render limit the image is refused, never drawn from
            // a head.
            (
                "huge.svg",
                StatusCode::PAYLOAD_TOO_LARGE,
                "preview_too_large",
            ),
            ("absent.svg", StatusCode::NOT_FOUND, "not_found"),
        ] {
            let response = get(format!("/api/v1/shares/documents/preview/svg?path={name}")).await;
            assert_eq!(response.status(), status, "{name}");
            assert_eq!(
                response.headers()[header::CONTENT_SECURITY_POLICY],
                PREVIEW_CSP,
                "{name}"
            );
            assert_eq!(response_json(response).await["code"], code, "{name}");
        }
        // Above the preview limit and within the render limit, the preview
        // is an SVG head and the image streams the whole file.
        let large_svg = format!(
            "{}>\n{}</svg>\n",
            &SVG[..SVG.len() - 2],
            "<rect/>\n".repeat(1000)
        );
        let large =
            response_json(get("/api/v1/shares/documents/preview?path=large.svg".into()).await)
                .await;
        assert_eq!(large["kind"], "svg");
        assert_eq!(large["language"], "xml");
        assert_eq!(large["truncated"], true);
        assert_eq!(large["renderable"], false);
        assert!(large["shownBytes"].as_u64().unwrap() <= 4096);
        let image = get("/api/v1/shares/documents/preview/svg?path=large.svg".into()).await;
        assert_eq!(image.status(), StatusCode::OK);
        assert_eq!(image.headers()[header::CONTENT_TYPE], "image/svg+xml");
        assert_eq!(
            image.headers()[header::CONTENT_LENGTH],
            large_svg.len().to_string()
        );
        assert_eq!(
            image.headers()[header::CONTENT_SECURITY_POLICY],
            PREVIEW_CSP
        );
        assert_preview_headers(&image, "large svg image");
        assert_eq!(
            to_bytes(image.into_body(), 64 * 1024)
                .await
                .unwrap()
                .as_ref(),
            large_svg.as_bytes()
        );
        let huge =
            response_json(get("/api/v1/shares/documents/preview?path=huge.svg".into()).await).await;
        assert_eq!(huge["kind"], "code");
        assert_eq!(huge["truncated"], true);

        // The route is authenticated and non-disclosing like the others.
        let unauthenticated = send(
            &fixture.app,
            None,
            Request::get("/api/v1/shares/documents/preview/svg?path=drawing.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let ungranted = send(
            &fixture.app,
            Some(&AuthenticatedIdentity::new("user-2", vec![])),
            Request::get("/api/v1/shares/documents/preview/svg?path=drawing.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(ungranted.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn open_route_serves_svg_as_a_sandboxed_image_within_the_render_limit() {
        let fixture = api_fixture_with(
            PreviewPolicy::new(4096)
                .unwrap()
                .with_max_render_bytes(16 * 1024)
                .unwrap(),
        );
        write_fixture(
            &fixture,
            "huge.svg",
            format!(
                "{}>\n{}</svg>\n",
                &SVG[..SVG.len() - 2],
                "<rect/>\n".repeat(3000)
            )
            .as_bytes(),
        );
        write_fixture(&fixture, "vector.svg", SVG.as_bytes());
        write_fixture(&fixture, "vector.txt", SVG.as_bytes());
        write_fixture(&fixture, "plain.svg", b"<svg><rect/></svg>");
        write_fixture(
            &fixture,
            "large.svg",
            format!(
                "{}>\n{}</svg>\n",
                &SVG[..SVG.len() - 2],
                "<rect/>\n".repeat(1000)
            )
            .as_bytes(),
        );
        for (name, media_type) in [
            ("vector.svg", "image/svg+xml"),
            ("vector.txt", "image/svg+xml"),
            ("plain.svg", "text/plain; charset=utf-8"),
            // Above the preview limit, within the render limit.
            ("large.svg", "image/svg+xml"),
            ("huge.svg", "text/plain; charset=utf-8"),
        ] {
            let response = open(&fixture, name).await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                media_type,
                "{name}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_SECURITY_POLICY],
                PREVIEW_CSP,
                "{name}"
            );
            assert_eq!(response.headers()[header::CONTENT_DISPOSITION], "inline");
            assert_preview_headers(&response, name);
        }
    }

    #[test]
    fn text_prefix_tolerates_only_a_cut_trailing_character() {
        let cut = "é".as_bytes();
        let mut prefix = b"abc".to_vec();
        prefix.push(cut[0]);
        assert_eq!(check_text_prefix(&prefix, false), Ok("abc"));
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
        // SVG named .pdf is never a streamed type. Within the preview limit
        // it is recognized from its content; above it, only its head is
        // returned, still an SVG while the file is within the render limit
        // and text beyond it.
        let document = load(&authorized, &path, PreviewPolicy::new(4096).unwrap()).unwrap();
        assert_eq!(document.kind, PreviewKind::Svg);
        assert_eq!(document.language, Some("xml"));
        assert!(document.openable);
        assert!(!document.renderable);
        let head = load(&authorized, &path, PreviewPolicy::new(16).unwrap()).unwrap();
        assert_eq!(head.kind, PreviewKind::Svg);
        assert_eq!(head.language, Some("xml"));
        assert!(head.truncated);
        assert_eq!(head.source, "<svg xmlns='http");
        let small_render = PreviewPolicy::new(16)
            .unwrap()
            .with_max_render_bytes(svg.len() as u64 - 1)
            .unwrap();
        let head = load(&authorized, &path, small_render).unwrap();
        assert_eq!(head.kind, PreviewKind::Text);
        assert!(head.truncated);
        assert_eq!(head.source, "<svg xmlns='http");
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
        // The 71-byte SVG is above the 64-byte render limit, so it is text.
        let fixture = api_fixture_with(
            PreviewPolicy::new(32)
                .unwrap()
                .with_max_render_bytes(64)
                .unwrap(),
        );
        write_fixture(&fixture, "report.pdf", &pdf_bytes());
        write_fixture(&fixture, "clip.mp4", &ftyp(b"isom", &[b"isom"]));
        write_fixture(&fixture, "photo.heic", &ftyp(b"heic", &[b"mif1", b"heic"]));
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
            // Decoded by the browser's image decoder, like AVIF.
            ("photo.heic", "image/heic", "32"),
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

//! Capability-scoped mutation and streaming-upload HTTP APIs.
//!
//! Authentication middleware must insert both [`AuthenticatedIdentity`] and
//! [`CsrfVerified`] request extensions. The latter is deliberately not inferred
//! from a header here: only the session layer has enough context to validate a
//! token. All endpoints therefore fail closed when that layer is absent.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, FromRequestParts, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, Semaphore},
};

use crate::{
    app::AppState,
    browse::AuthenticatedIdentity,
    error::AppError,
    filesystem::{
        AuthorizedShare, EntryMetadata, EntryName, FsError, FsErrorCode, PendingWrite, ShareId,
        VirtualPath,
    },
};

const ABSOLUTE_FILE_UPLOAD_LIMIT: usize = 1_073_741_824;
const MAX_MULTIPART_OVERHEAD: usize = 1_048_576;
const MULTIPART_OVERHEAD_PER_FILE: usize = 8_192;
const MULTIPART_FIXED_OVERHEAD: usize = 4_096;
const MAX_METADATA_BODY_BYTES: usize = 16_384;
const QUOTA_SCAN_ENTRY_LIMIT: usize = 1_000_000;

#[derive(Clone, Copy, Debug)]
pub struct MutationLimits {
    pub max_request_bytes: u64,
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub max_text_bytes: usize,
    pub max_concurrent_uploads: usize,
    pub max_share_bytes: Option<u64>,
}

impl Default for MutationLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 268_435_456,
            max_file_bytes: 268_435_456,
            max_files: 32,
            max_text_bytes: 1_048_576,
            max_concurrent_uploads: 4,
            max_share_bytes: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MutationStateError {
    #[error("mutation limits must be non-zero and internally consistent")]
    InvalidLimits,
}

pub struct MutationState {
    limits: MutationLimits,
    upload_gate: Arc<Semaphore>,
    commit_lock: Arc<Mutex<()>>,
}

impl MutationState {
    pub fn new(limits: MutationLimits) -> Result<Self, MutationStateError> {
        if limits.max_request_bytes == 0
            || limits.max_file_bytes == 0
            || limits.max_file_bytes > limits.max_request_bytes
            || limits.max_files == 0
            || limits.max_text_bytes == 0
            || limits.max_text_bytes as u64 > limits.max_file_bytes
            || limits.max_concurrent_uploads == 0
            || limits.max_share_bytes == Some(0)
        {
            return Err(MutationStateError::InvalidLimits);
        }
        Ok(Self {
            limits,
            upload_gate: Arc::new(Semaphore::new(limits.max_concurrent_uploads)),
            commit_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Builds conservative v1 limits from the immutable configured upload cap.
    /// Multipart framing receives only a small, bounded allowance above it.
    pub fn from_max_upload_bytes(max_upload_bytes: u64) -> Result<Self, MutationStateError> {
        if max_upload_bytes > ABSOLUTE_FILE_UPLOAD_LIMIT as u64 {
            return Err(MutationStateError::InvalidLimits);
        }
        let mut limits = MutationLimits::default();
        limits.max_request_bytes = max_upload_bytes;
        limits.max_file_bytes = max_upload_bytes;
        limits.max_text_bytes = limits
            .max_text_bytes
            .min(usize::try_from(max_upload_bytes).unwrap_or(usize::MAX));
        Self::new(limits)
    }

    #[must_use]
    pub fn http_body_limit(&self) -> usize {
        let payload_limit = usize::try_from(self.limits.max_request_bytes)
            .expect("validated upload limit fits in usize");
        let overhead = self
            .limits
            .max_files
            .saturating_mul(MULTIPART_OVERHEAD_PER_FILE)
            .saturating_add(MULTIPART_FIXED_OVERHEAD)
            .min(MAX_MULTIPART_OVERHEAD);
        payload_limit.saturating_add(overhead)
    }
}

impl Default for MutationState {
    fn default() -> Self {
        Self::new(MutationLimits::default()).expect("default mutation limits are valid")
    }
}

/// Proof that the authentication/session layer validated CSRF protection.
#[derive(Clone, Copy, Debug)]
pub struct CsrfVerified(pub(crate) ());

impl<S> FromRequestParts<S> for CsrfVerified
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .copied()
            .ok_or(AppError::Forbidden)
    }
}

pub fn router(http_body_limit: usize) -> Router<AppState> {
    Router::new()
        .route("/shares/{share_id}/directories", post(create_directory))
        .route("/shares/{share_id}/files", post(create_file))
        .route("/shares/{share_id}/text", put(save_text))
        .route("/shares/{share_id}/move", post(move_entry))
        .route("/shares/{share_id}/entry", delete(delete_entry))
        .route(
            "/shares/{share_id}/uploads",
            post(upload_files).layer(DefaultBodyLimit::max(http_body_limit)),
        )
}

#[derive(Deserialize)]
struct PathBody {
    path: String,
}

#[derive(Deserialize)]
struct MoveBody {
    source: String,
    destination: String,
}

#[derive(Deserialize)]
struct PathQuery {
    path: Option<String>,
}

#[derive(Deserialize)]
struct UploadQuery {
    path: Option<String>,
    #[serde(default)]
    replace: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationResponse {
    share_id: String,
    path: String,
    outcome: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadResponse {
    share_id: String,
    outcomes: Vec<UploadOutcome>,
}

#[derive(Serialize)]
struct UploadOutcome {
    path: String,
    outcome: &'static str,
}

struct StagedUpload {
    path: VirtualPath,
    pending: PendingWrite,
    expected: Option<EntryMetadata>,
    size: u64,
}

async fn create_directory(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Json(body): Json<PathBody>,
) -> Result<Response, AppError> {
    reject_oversized_metadata(&body.path)?;
    let (share_id, path, authorized) =
        authorize_write(&state, &identity, &raw_share_id, &body.path)?;
    let result = {
        let _commit = state.mutations().commit_lock.lock().await;
        authorized.create_directory(&path)
    };
    finish_mutation(
        &identity,
        &share_id,
        &path,
        "create_directory",
        result,
        StatusCode::CREATED,
    )
}

async fn create_file(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Json(body): Json<PathBody>,
) -> Result<Response, AppError> {
    reject_oversized_metadata(&body.path)?;
    let (share_id, path, authorized) =
        authorize_write(&state, &identity, &raw_share_id, &body.path)?;
    let result = {
        let _commit = state.mutations().commit_lock.lock().await;
        ensure_quota(&authorized, state.mutations().limits, 0, 0)?;
        let pending = authorized
            .begin_write(&path)
            .map_err(map_mutation_fs_error)?;
        pending.publish_new()
    };
    finish_mutation(
        &identity,
        &share_id,
        &path,
        "create_file",
        result,
        StatusCode::CREATED,
    )
}

async fn save_text(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Query(query): Query<PathQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let raw_path = query.path.as_deref().ok_or(AppError::InvalidRequest)?;
    let (share_id, path, authorized) = authorize_write(&state, &identity, &raw_share_id, raw_path)?;
    let bytes = to_bytes(
        body,
        state.mutations().limits.max_text_bytes.saturating_add(1),
    )
    .await
    .map_err(|_| AppError::TooLarge)?;
    if bytes.len() > state.mutations().limits.max_text_bytes {
        return Err(AppError::TooLarge);
    }
    std::str::from_utf8(&bytes).map_err(|_| AppError::UnsupportedMedia)?;

    let current = authorized.metadata(&path).map_err(map_mutation_fs_error)?;
    require_if_match(&state, &share_id, &path, current, &headers)?;
    let pending = authorized
        .begin_write(&path)
        .map_err(map_mutation_fs_error)?;
    let mut writer = tokio::fs::File::from_std(pending.writer().map_err(map_mutation_fs_error)?);
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| AppError::Internal)?;
    writer.flush().await.map_err(|_| AppError::Internal)?;
    writer.sync_all().await.map_err(|_| AppError::Internal)?;
    drop(writer);
    let result = {
        let _commit = state.mutations().commit_lock.lock().await;
        ensure_quota(
            &authorized,
            state.mutations().limits,
            bytes.len() as u64,
            current.size,
        )?;
        pending.publish_replacement(current)
    };
    finish_mutation(
        &identity,
        &share_id,
        &path,
        "save_text",
        result,
        StatusCode::OK,
    )
}

async fn move_entry(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MoveBody>,
) -> Result<Response, AppError> {
    reject_oversized_metadata(&body.source)?;
    reject_oversized_metadata(&body.destination)?;
    let share_id = parse_share_id(&raw_share_id)?;
    let source = VirtualPath::parse(&body.source).map_err(map_mutation_fs_error)?;
    let destination = VirtualPath::parse(&body.destination).map_err(map_mutation_fs_error)?;
    let authorized = state.browse().authorize(&identity, &share_id)?;
    let current = authorized
        .metadata(&source)
        .map_err(map_mutation_fs_error)?;
    require_if_match(&state, &share_id, &source, current, &headers)?;
    let result = {
        let _commit = state.mutations().commit_lock.lock().await;
        authorized.move_entry(&source, &destination, current)
    };
    finish_mutation(
        &identity,
        &share_id,
        &destination,
        "move",
        result,
        StatusCode::OK,
    )
}

async fn delete_entry(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Query(query): Query<PathQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let raw_path = query.path.as_deref().ok_or(AppError::InvalidRequest)?;
    let (share_id, path, authorized) = authorize_write(&state, &identity, &raw_share_id, raw_path)?;
    let current = authorized.metadata(&path).map_err(map_mutation_fs_error)?;
    require_if_match(&state, &share_id, &path, current, &headers)?;
    let result = {
        let _commit = state.mutations().commit_lock.lock().await;
        authorized.delete_entry(&path, current)
    };
    finish_mutation(
        &identity,
        &share_id,
        &path,
        "delete",
        result,
        StatusCode::OK,
    )
}

async fn upload_files(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let _permit = state
        .mutations()
        .upload_gate
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)?;
    let share_id = parse_share_id(&raw_share_id)?;
    let authorized = state.browse().authorize(&identity, &share_id)?;
    let directory = parse_optional_path(query.path.as_deref())?;
    let mut total_bytes = 0_u64;
    let mut file_count = 0_usize;
    let mut staged = Vec::new();

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::InvalidRequest)?
    {
        file_count += 1;
        if file_count > state.mutations().limits.max_files {
            audit_rejected(&identity, &share_id, "upload", "file_count_limit");
            return Err(AppError::TooLarge);
        }
        let filename = field
            .file_name()
            .ok_or(AppError::InvalidRequest)?
            .to_owned();
        let name = EntryName::new(filename).map_err(map_mutation_fs_error)?;
        let path = directory.join(name);
        let expected = if query.replace {
            let current = authorized.metadata(&path).map_err(map_mutation_fs_error)?;
            let part_match = field
                .headers()
                .get(header::IF_MATCH)
                .or_else(|| headers.get(header::IF_MATCH));
            require_if_match_value(&state, &share_id, &path, current, part_match)?;
            Some(current)
        } else {
            None
        };
        let pending = authorized
            .begin_write(&path)
            .map_err(map_mutation_fs_error)?;
        let mut writer =
            tokio::fs::File::from_std(pending.writer().map_err(map_mutation_fs_error)?);
        let mut file_bytes = 0_u64;
        while let Some(chunk) = field.chunk().await.map_err(|_| AppError::InvalidRequest)? {
            let chunk_len = u64::try_from(chunk.len()).map_err(|_| AppError::TooLarge)?;
            file_bytes = file_bytes
                .checked_add(chunk_len)
                .ok_or(AppError::TooLarge)?;
            total_bytes = total_bytes
                .checked_add(chunk_len)
                .ok_or(AppError::TooLarge)?;
            if file_bytes > state.mutations().limits.max_file_bytes
                || total_bytes > state.mutations().limits.max_request_bytes
            {
                audit_rejected(&identity, &share_id, "upload", "byte_limit");
                return Err(AppError::TooLarge);
            }
            writer
                .write_all(&chunk)
                .await
                .map_err(|_| AppError::Internal)?;
        }
        writer.flush().await.map_err(|_| AppError::Internal)?;
        writer.sync_all().await.map_err(|_| AppError::Internal)?;
        drop(writer);
        staged.push(StagedUpload {
            path,
            pending,
            expected,
            size: file_bytes,
        });
    }
    if staged.is_empty() {
        return Err(AppError::InvalidRequest);
    }

    let mut outcomes = Vec::with_capacity(staged.len());
    for upload in staged {
        let path = upload.path;
        let is_replacement = upload.expected.is_some();
        let publish = {
            let _commit = state.mutations().commit_lock.lock().await;
            match ensure_quota(
                &authorized,
                state.mutations().limits,
                upload.size,
                upload.expected.map_or(0, |metadata| metadata.size),
            ) {
                Ok(()) => match upload.expected {
                    Some(expected) => upload
                        .pending
                        .publish_replacement(expected)
                        .map_err(map_mutation_fs_error),
                    None => upload.pending.publish_new().map_err(map_mutation_fs_error),
                },
                Err(error) => Err(error),
            }
        };
        match publish {
            Ok(()) => {
                tracing::info!(
                    audit = true,
                    subject = identity.subject(),
                    share_id = share_id.as_str(),
                    operation = "upload",
                    path = %path,
                    outcome = "success"
                );
                outcomes.push(UploadOutcome {
                    path: path.to_string(),
                    outcome: if is_replacement {
                        "replaced"
                    } else {
                        "created"
                    },
                });
            }
            Err(AppError::Conflict) => {
                audit_rejected(&identity, &share_id, "upload", "conflict");
                outcomes.push(UploadOutcome {
                    path: path.to_string(),
                    outcome: "conflict",
                });
            }
            Err(AppError::TooLarge) => {
                audit_rejected(&identity, &share_id, "upload", "quota");
                outcomes.push(UploadOutcome {
                    path: path.to_string(),
                    outcome: "quota_exceeded",
                });
            }
            Err(_) => {
                audit_rejected(&identity, &share_id, "upload", "internal_error");
                outcomes.push(UploadOutcome {
                    path: path.to_string(),
                    outcome: "error",
                });
            }
        }
    }
    Ok(inert_json(
        StatusCode::MULTI_STATUS,
        UploadResponse {
            share_id: share_id.to_string(),
            outcomes,
        },
    ))
}

fn authorize_write<'state>(
    state: &'state AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    raw_path: &str,
) -> Result<(ShareId, VirtualPath, AuthorizedShare<'state>), AppError> {
    let share_id = parse_share_id(raw_share_id)?;
    let path = VirtualPath::parse(raw_path).map_err(map_mutation_fs_error)?;
    let authorized = state.browse().authorize(identity, &share_id)?;
    Ok((share_id, path, authorized))
}

fn parse_share_id(raw: &str) -> Result<ShareId, AppError> {
    ShareId::new(raw.to_owned()).map_err(|_| AppError::NotFound)
}

fn parse_optional_path(raw: Option<&str>) -> Result<VirtualPath, AppError> {
    match raw {
        None | Some("") => Ok(VirtualPath::root()),
        Some(path) => VirtualPath::parse(path).map_err(map_mutation_fs_error),
    }
}

fn reject_oversized_metadata(value: &str) -> Result<(), AppError> {
    (value.len() <= MAX_METADATA_BODY_BYTES)
        .then_some(())
        .ok_or(AppError::TooLarge)
}

fn require_if_match(
    state: &AppState,
    share_id: &ShareId,
    path: &VirtualPath,
    metadata: EntryMetadata,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    require_if_match_value(
        state,
        share_id,
        path,
        metadata,
        headers.get(header::IF_MATCH),
    )
}

fn require_if_match_value(
    state: &AppState,
    share_id: &ShareId,
    path: &VirtualPath,
    metadata: EntryMetadata,
    supplied: Option<&axum::http::HeaderValue>,
) -> Result<(), AppError> {
    let supplied = supplied
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Conflict)?;
    let expected = state.browse().version_tag(share_id, path, metadata);
    if supplied == expected {
        Ok(())
    } else {
        Err(AppError::Conflict)
    }
}

fn ensure_quota(
    authorized: &AuthorizedShare<'_>,
    limits: MutationLimits,
    incoming: u64,
    replacing: u64,
) -> Result<(), AppError> {
    let Some(limit) = limits.max_share_bytes else {
        return Ok(());
    };
    let usage = authorized
        .usage_bounded(QUOTA_SCAN_ENTRY_LIMIT, limit.saturating_add(replacing))
        .map_err(map_mutation_fs_error)?;
    let projected = usage
        .saturating_sub(replacing)
        .checked_add(incoming)
        .ok_or(AppError::TooLarge)?;
    (projected <= limit).then_some(()).ok_or(AppError::TooLarge)
}

fn finish_mutation(
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    path: &VirtualPath,
    operation: &'static str,
    result: Result<(), FsError>,
    status: StatusCode,
) -> Result<Response, AppError> {
    match result {
        Ok(()) => {
            tracing::info!(
                audit = true,
                subject = identity.subject(),
                share_id = share_id.as_str(),
                operation,
                path = %path,
                outcome = "success"
            );
            Ok(inert_json(
                status,
                MutationResponse {
                    share_id: share_id.to_string(),
                    path: path.to_string(),
                    outcome: "success",
                },
            ))
        }
        Err(error) => {
            audit_rejected(identity, share_id, operation, fs_reason(error.code()));
            Err(map_mutation_fs_error(error))
        }
    }
}

fn audit_rejected(
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    operation: &'static str,
    reason: &'static str,
) {
    tracing::warn!(
        audit = true,
        subject = identity.subject(),
        share_id = share_id.as_str(),
        operation,
        outcome = "rejected",
        reason
    );
}

fn fs_reason(code: FsErrorCode) -> &'static str {
    match code {
        FsErrorCode::AccessDenied => "access_denied",
        FsErrorCode::Conflict => "conflict",
        FsErrorCode::InvalidPath => "invalid_path",
        FsErrorCode::NotFound => "not_found",
        FsErrorCode::TooLarge => "too_large",
        FsErrorCode::UnsupportedEntry => "unsupported_entry",
        FsErrorCode::Unavailable => "unavailable",
    }
}

fn map_mutation_fs_error(error: FsError) -> AppError {
    match error.code() {
        FsErrorCode::AccessDenied => AppError::Forbidden,
        FsErrorCode::Conflict => AppError::Conflict,
        FsErrorCode::InvalidPath => AppError::InvalidRequest,
        FsErrorCode::TooLarge => AppError::TooLarge,
        FsErrorCode::Unavailable => AppError::Internal,
        FsErrorCode::NotFound | FsErrorCode::UnsupportedEntry => AppError::NotFound,
    }
}

fn inert_json(status: StatusCode, value: impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use serde_json::json;
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        app,
        browse::{BrowseLimits, BrowseState, ConfiguredShare},
        filesystem::{AccessLevel, GlobalPolicy, ShareFs, ShareGrant},
    };

    struct Fixture {
        root: TempDir,
        app: Router,
        identity: AuthenticatedIdentity,
    }

    fn fixture(access: AccessLevel, global_read_only: bool, limits: MutationLimits) -> Fixture {
        let root = TempDir::new().expect("temporary share");
        fs::write(root.path().join("existing.txt"), b"original").expect("fixture file");
        fs::create_dir(root.path().join("nonempty")).expect("fixture directory");
        fs::write(root.path().join("nonempty/child.txt"), b"child").expect("fixture child");
        let share_id = ShareId::new("documents").expect("share id");
        let grant = ShareGrant {
            share_id: share_id.clone(),
            access,
        };
        let filesystem = ShareFs::open(share_id, root.path()).expect("share filesystem");
        let configured = ConfiguredShare::new("Documents", filesystem).expect("configured share");
        let browse = BrowseState::new(
            vec![configured],
            BrowseLimits::default(),
            GlobalPolicy {
                read_only: global_read_only,
            },
            [0x5a; 32],
        )
        .expect("browse state");
        let mutations = MutationState::new(limits).expect("mutation state");
        let app = app::router(
            AppState::new(true)
                .with_browse(browse)
                .with_mutations(mutations),
        );
        Fixture {
            root,
            app,
            identity: AuthenticatedIdentity::new("user-1", vec![grant]),
        }
    }

    async fn send(
        app: &Router,
        identity: Option<&AuthenticatedIdentity>,
        csrf: bool,
        request: Request<Body>,
    ) -> Response {
        let (mut parts, body) = request.into_parts();
        if let Some(identity) = identity {
            parts.extensions.insert(identity.clone());
        }
        if csrf {
            parts.extensions.insert(CsrfVerified(()));
        }
        app.clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .expect("router response")
    }

    fn json_request(method: &str, uri: &str, value: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .expect("request")
    }

    async fn metadata_etag(fixture: &Fixture, path: &str) -> String {
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            false,
            Request::get(format!("/api/v1/shares/documents/metadata?path={path}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::ETAG)
            .expect("etag")
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn multipart_body(boundary: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, contents) in files {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(contents);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    #[tokio::test]
    async fn mutations_fail_closed_without_identity_or_csrf_proof() {
        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        let request = || {
            json_request(
                "POST",
                "/api/v1/shares/documents/files",
                json!({"path":"new.txt"}),
            )
        };
        assert_eq!(
            send(&fixture.app, None, true, request()).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&fixture.app, Some(&fixture.identity), false, request())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert!(!fixture.root.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn read_only_grants_and_global_policy_block_every_write() {
        for (access, global_read_only) in [
            (AccessLevel::ReadOnly, false),
            (AccessLevel::ReadWrite, true),
        ] {
            let fixture = fixture(access, global_read_only, MutationLimits::default());
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                true,
                json_request(
                    "POST",
                    "/api/v1/shares/documents/directories",
                    json!({"path":"blocked"}),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!fixture.root.path().join("blocked").exists());
        }
    }

    #[tokio::test]
    async fn create_operations_are_no_replace_and_accept_normalized_unicode() {
        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        for (route, path) in [("directories", "café"), ("files", "café/日本語.txt")] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                true,
                json_request(
                    "POST",
                    &format!("/api/v1/shares/documents/{route}"),
                    json!({"path":path}),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        let duplicate = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            json_request(
                "POST",
                "/api/v1/shares/documents/files",
                json!({"path":"café/日本語.txt"}),
            ),
        )
        .await;
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        let traversal = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            json_request(
                "POST",
                "/api/v1/shares/documents/files",
                json!({"path":"../escape"}),
            ),
        )
        .await;
        assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn text_save_is_bounded_utf8_and_preconditioned() {
        let limits = MutationLimits {
            max_text_bytes: 8,
            ..MutationLimits::default()
        };
        let fixture = fixture(AccessLevel::ReadWrite, false, limits);
        let etag = metadata_etag(&fixture, "existing.txt").await;
        let request = |etag: &str, body: &'static [u8]| {
            Request::put("/api/v1/shares/documents/text?path=existing.txt")
                .header(header::IF_MATCH, etag)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(body))
                .unwrap()
        };
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            request(&etag, b"updated"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            fs::read(fixture.root.path().join("existing.txt")).unwrap(),
            b"updated"
        );

        let stale = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            request(&etag, b"stale"),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let invalid = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            request(&metadata_etag(&fixture, "existing.txt").await, &[0xff]),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let oversized = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            request(&metadata_etag(&fixture, "existing.txt").await, b"123456789"),
        )
        .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            fs::read(fixture.root.path().join("existing.txt")).unwrap(),
            b"updated"
        );
    }

    #[tokio::test]
    async fn move_and_delete_require_current_validators_and_never_recurse() {
        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        let etag = metadata_etag(&fixture, "existing.txt").await;
        let moved = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            json_request(
                "POST",
                "/api/v1/shares/documents/move",
                json!({"source":"existing.txt","destination":"renamed.txt"}),
            )
            .map(|body| body),
        )
        .await;
        // Missing If-Match is always a deterministic conflict.
        assert_eq!(moved.status(), StatusCode::CONFLICT);
        let moved = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/move")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, etag)
                .body(Body::from(
                    json!({"source":"existing.txt","destination":"renamed.txt"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(moved.status(), StatusCode::OK);
        assert!(fixture.root.path().join("renamed.txt").exists());

        let directory_etag = metadata_etag(&fixture, "nonempty").await;
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::delete("/api/v1/shares/documents/entry?path=nonempty")
                .header(header::IF_MATCH, directory_etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(fixture.root.path().join("nonempty/child.txt").exists());
    }

    #[tokio::test]
    async fn multipart_upload_reports_per_file_conflicts_and_cleans_oversize_temps() {
        let limits = MutationLimits {
            max_request_bytes: 12,
            max_file_bytes: 8,
            max_files: 3,
            max_text_bytes: 8,
            ..MutationLimits::default()
        };
        let fixture = fixture(AccessLevel::ReadWrite, false, limits);
        let boundary = "index-test-boundary";
        let body = multipart_body(boundary, &[("one.txt", b"one"), ("existing.txt", b"two")]);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        assert_eq!(
            fs::read(fixture.root.path().join("one.txt")).unwrap(),
            b"one"
        );
        assert_eq!(
            fs::read(fixture.root.path().join("existing.txt")).unwrap(),
            b"original"
        );

        let oversized = multipart_body(boundary, &[("large.txt", b"123456789")]);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!fixture.root.path().join("large.txt").exists());
        assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".index-tmp-")
        }));

        let truncated = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"truncated.txt\"\r\n\r\npartial"
        );
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(truncated))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!fixture.root.path().join("truncated.txt").exists());
        assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".index-tmp-")
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_and_hardlink_targets_are_never_mutated() {
        use std::os::unix::fs::symlink;

        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        let outside = TempDir::new().expect("outside");
        fs::write(outside.path().join("secret"), b"secret").expect("outside file");
        symlink(
            outside.path().join("secret"),
            fixture.root.path().join("link"),
        )
        .expect("symlink fixture");
        fs::hard_link(
            outside.path().join("secret"),
            fixture.root.path().join("alias"),
        )
        .expect("hardlink fixture");
        for path in ["link", "alias"] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                true,
                Request::delete(format!("/api/v1/shares/documents/entry?path={path}"))
                    .header(header::IF_MATCH, "W/\"attacker\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");
    }
}

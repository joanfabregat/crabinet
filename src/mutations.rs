//! Capability-scoped mutation and streaming-upload HTTP APIs.
//!
//! Authentication middleware must insert both [`AuthenticatedIdentity`] and
//! [`CsrfVerified`] request extensions. The latter is deliberately not inferred
//! from a header here: only the session layer has enough context to validate a
//! token. All endpoints therefore fail closed when that layer is absent.
//!
//! Filesystem work runs on Tokio's blocking pool. Each capability-scoped
//! operation receives an owned, freshly authorized share handle, and commits
//! are serialized per share rather than process-wide.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, FromRequestParts, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::OwnedMutexGuard, time::timeout};

use crate::{
    app::AppState,
    browse::{AuthenticatedIdentity, SubjectGate, run_blocking},
    error::AppError,
    filesystem::{
        AccessLevel, AuthorizedShare, EntryMetadata, EntryName, FsError, FsErrorCode,
        OwnedAuthorizedShare, PendingWrite, ShareId, VirtualPath,
    },
};

const ABSOLUTE_FILE_UPLOAD_LIMIT: usize = 1_073_741_824;
const MAX_MULTIPART_OVERHEAD: usize = 1_048_576;
const MULTIPART_OVERHEAD_PER_FILE: usize = 8_192;
const MULTIPART_FIXED_OVERHEAD: usize = 4_096;
const MAX_METADATA_BODY_BYTES: usize = 16_384;
const QUOTA_SCAN_ENTRY_LIMIT: usize = 1_000_000;
/// A multipart upload that delivers no new part or chunk for this long is
/// aborted, releasing its upload slot and unpublished staging files.
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Process-wide upload cap plus a per-subject cap of one less (at least
    /// one), so a single user cannot hold every upload slot. The default of
    /// four leaves each user three, matching the browser client's three
    /// parallel uploads in `web/src/operations.tsx`.
    upload_gate: SubjectGate,
    /// One commit lock per share. Quota checks and publication are atomic
    /// within a share; unrelated shares never wait on each other's fsyncs.
    /// Entries are created only for shares that passed authorization, so the
    /// map is bounded by the configured share count.
    commit_locks: Mutex<HashMap<ShareId, Arc<tokio::sync::Mutex<()>>>>,
    upload_idle_timeout: Duration,
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
            upload_gate: SubjectGate::new(
                limits.max_concurrent_uploads,
                (limits.max_concurrent_uploads - 1).max(1),
            ),
            commit_locks: Mutex::new(HashMap::new()),
            upload_idle_timeout: UPLOAD_IDLE_TIMEOUT,
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

    #[cfg(test)]
    fn with_upload_idle_timeout(mut self, idle: Duration) -> Self {
        self.upload_idle_timeout = idle;
        self
    }

    async fn commit_lock(&self, share_id: &ShareId) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self
                .commit_locks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            Arc::clone(locks.entry(share_id.clone()).or_default())
        };
        lock.lock_owned().await
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

/// A rejected mutation and its stable audit reason. Every handler returns
/// its failures through [`audited`], so no rejection path skips the audit
/// event that `docs/mutations.md` promises.
struct Rejection {
    error: AppError,
    reason: &'static str,
}

impl Rejection {
    const fn new(error: AppError, reason: &'static str) -> Self {
        Self { error, reason }
    }
}

impl From<AppError> for Rejection {
    fn from(error: AppError) -> Self {
        let reason = app_reason(&error);
        Self { error, reason }
    }
}

impl From<FsError> for Rejection {
    fn from(error: FsError) -> Self {
        Self {
            reason: fs_reason(error.code()),
            error: map_mutation_fs_error(error),
        }
    }
}

type MutationResult<T> = Result<T, Rejection>;

async fn create_directory(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Json(body): Json<PathBody>,
) -> Result<Response, AppError> {
    let result = create_directory_inner(&state, &identity, &raw_share_id, body).await;
    audited(&identity, &raw_share_id, "create_directory", result)
}

async fn create_directory_inner(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    body: PathBody,
) -> MutationResult<Response> {
    reject_oversized_metadata(&body.path)?;
    let (share_id, path, authorized) = authorize_write(state, identity, raw_share_id, &body.path)?;
    ensure_creatable(&path)?;
    let commit = state.mutations().commit_lock(&share_id).await;
    let target = path.clone();
    let result = run_blocking(move || {
        let _commit = commit;
        authorized
            .view()
            .create_directory(&target)
            .map_err(Rejection::from)
    })
    .await?;
    finish_mutation(
        identity,
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
    let result = create_file_inner(&state, &identity, &raw_share_id, body).await;
    audited(&identity, &raw_share_id, "create_file", result)
}

async fn create_file_inner(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    body: PathBody,
) -> MutationResult<Response> {
    reject_oversized_metadata(&body.path)?;
    let (share_id, path, authorized) = authorize_write(state, identity, raw_share_id, &body.path)?;
    ensure_creatable(&path)?;
    let limits = state.mutations().limits;
    let commit = state.mutations().commit_lock(&share_id).await;
    let target = path.clone();
    let result = run_blocking(move || {
        let _commit = commit;
        let share = authorized.view();
        ensure_quota(&share, limits, 0, 0)?;
        let pending = share.begin_write(&target)?;
        pending.publish_new().map_err(Rejection::from)
    })
    .await?;
    finish_mutation(
        identity,
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
    let result = save_text_inner(&state, &identity, &raw_share_id, query, &headers, body).await;
    audited(&identity, &raw_share_id, "save_text", result)
}

async fn save_text_inner(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    query: PathQuery,
    headers: &HeaderMap,
    body: Body,
) -> MutationResult<Response> {
    let raw_path = query.path.as_deref().ok_or(AppError::InvalidRequest)?;
    let (share_id, path, authorized) = authorize_write(state, identity, raw_share_id, raw_path)?;
    let limits = state.mutations().limits;
    let bytes = to_bytes(body, limits.max_text_bytes.saturating_add(1))
        .await
        .map_err(|_| AppError::TooLarge)?;
    if bytes.len() > limits.max_text_bytes {
        return Err(AppError::TooLarge.into());
    }
    std::str::from_utf8(&bytes).map_err(|_| AppError::UnsupportedMedia)?;

    let current = current_metadata(&authorized, &path).await?;
    require_if_match(state, &share_id, &path, current, headers)?;
    let pending = stage_write(&authorized, &path).await?;
    let mut writer = tokio::fs::File::from_std(pending.writer()?);
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| AppError::Internal)?;
    writer.flush().await.map_err(|_| AppError::Internal)?;
    writer.sync_all().await.map_err(|_| AppError::Internal)?;
    drop(writer);
    let size = bytes.len() as u64;
    let commit = state.mutations().commit_lock(&share_id).await;
    let result = run_blocking(move || {
        let _commit = commit;
        ensure_quota(&authorized.view(), limits, size, current.size)?;
        pending
            .publish_replacement(current)
            .map_err(Rejection::from)
    })
    .await?;
    finish_mutation(
        identity,
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
    let result = move_entry_inner(&state, &identity, &raw_share_id, &headers, body).await;
    audited(&identity, &raw_share_id, "move", result)
}

async fn move_entry_inner(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    headers: &HeaderMap,
    body: MoveBody,
) -> MutationResult<Response> {
    reject_oversized_metadata(&body.source)?;
    reject_oversized_metadata(&body.destination)?;
    let share_id = parse_share_id(raw_share_id)?;
    let source = VirtualPath::parse(&body.source)?;
    let destination = VirtualPath::parse(&body.destination)?;
    let authorized = state.browse().authorize_owned(identity, &share_id)?;
    require_write_access(authorized.access())?;
    // Moving an existing entry to another directory under its current name
    // is allowed; choosing a new name must satisfy the creation policy.
    if destination.file_name() != source.file_name() {
        ensure_creatable(&destination)?;
    }
    let current = current_metadata(&authorized, &source).await?;
    require_if_match(state, &share_id, &source, current, headers)?;
    let commit = state.mutations().commit_lock(&share_id).await;
    let (from, to) = (source, destination.clone());
    let result = run_blocking(move || {
        let _commit = commit;
        authorized
            .view()
            .move_entry(&from, &to, current)
            .map_err(Rejection::from)
    })
    .await?;
    finish_mutation(
        identity,
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
    let result = delete_entry_inner(&state, &identity, &raw_share_id, query, &headers).await;
    audited(&identity, &raw_share_id, "delete", result)
}

async fn delete_entry_inner(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    query: PathQuery,
    headers: &HeaderMap,
) -> MutationResult<Response> {
    let raw_path = query.path.as_deref().ok_or(AppError::InvalidRequest)?;
    let (share_id, path, authorized) = authorize_write(state, identity, raw_share_id, raw_path)?;
    let current = current_metadata(&authorized, &path).await?;
    require_if_match(state, &share_id, &path, current, headers)?;
    let commit = state.mutations().commit_lock(&share_id).await;
    let target = path.clone();
    let result = run_blocking(move || {
        let _commit = commit;
        authorized
            .view()
            .delete_entry(&target, current)
            .map_err(Rejection::from)
    })
    .await?;
    finish_mutation(identity, &share_id, &path, "delete", result, StatusCode::OK)
}

async fn upload_files(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    _csrf: CsrfVerified,
    Path(raw_share_id): Path<String>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, AppError> {
    let result =
        upload_files_inner(&state, &identity, &raw_share_id, query, &headers, multipart).await;
    audited(&identity, &raw_share_id, "upload", result)
}

async fn upload_files_inner(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    query: UploadQuery,
    headers: &HeaderMap,
    mut multipart: Multipart,
) -> MutationResult<Response> {
    let share_id = parse_share_id(raw_share_id)?;
    let authorized = state.browse().authorize_owned(identity, &share_id)?;
    require_write_access(authorized.access())?;
    let directory = parse_optional_path(query.path.as_deref())?;
    let _permit = state
        .mutations()
        .upload_gate
        .try_acquire(identity.subject())
        .ok_or(AppError::Busy)?;
    let limits = state.mutations().limits;
    let idle = state.mutations().upload_idle_timeout;
    let mut total_bytes = 0_u64;
    let mut file_count = 0_usize;
    let mut staged = Vec::new();

    while let Some(mut field) = timeout(idle, multipart.next_field())
        .await
        .map_err(|_| idle_timeout())?
        .map_err(|_| AppError::InvalidRequest)?
    {
        file_count += 1;
        if file_count > limits.max_files {
            return Err(Rejection::new(AppError::TooLarge, "file_count_limit"));
        }
        let filename = field
            .file_name()
            .ok_or(AppError::InvalidRequest)?
            .to_owned();
        let name = EntryName::new(filename)?;
        if !query.replace {
            name.ensure_creatable()?;
        }
        let path = directory.join(name);
        let expected = if query.replace {
            let current = current_metadata(&authorized, &path).await?;
            let part_match = field
                .headers()
                .get(header::IF_MATCH)
                .or_else(|| headers.get(header::IF_MATCH));
            require_if_match_value(state, &share_id, &path, current, part_match)?;
            Some(current)
        } else {
            None
        };
        let pending = stage_write(&authorized, &path).await?;
        // `tokio::fs::File` performs each write and the final sync on the
        // blocking pool, so a slow disk never stalls the runtime.
        let mut writer = tokio::fs::File::from_std(pending.writer()?);
        let mut file_bytes = 0_u64;
        while let Some(chunk) = timeout(idle, field.chunk())
            .await
            .map_err(|_| idle_timeout())?
            .map_err(|_| AppError::InvalidRequest)?
        {
            let chunk_len = u64::try_from(chunk.len()).map_err(|_| AppError::TooLarge)?;
            file_bytes = file_bytes
                .checked_add(chunk_len)
                .ok_or(AppError::TooLarge)?;
            total_bytes = total_bytes
                .checked_add(chunk_len)
                .ok_or(AppError::TooLarge)?;
            if file_bytes > limits.max_file_bytes || total_bytes > limits.max_request_bytes {
                return Err(Rejection::new(AppError::TooLarge, "byte_limit"));
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
        return Err(Rejection::new(AppError::InvalidRequest, "no_files"));
    }

    let mut outcomes = Vec::with_capacity(staged.len());
    for upload in staged {
        let path = upload.path;
        let is_replacement = upload.expected.is_some();
        let commit = state.mutations().commit_lock(&share_id).await;
        let share = authorized.clone();
        let publish = run_blocking(move || {
            let _commit = commit;
            ensure_quota(
                &share.view(),
                limits,
                upload.size,
                upload.expected.map_or(0, |metadata| metadata.size),
            )?;
            match upload.expected {
                Some(expected) => upload.pending.publish_replacement(expected),
                None => upload.pending.publish_new(),
            }
            .map_err(Rejection::from)
        })
        .await
        .unwrap_or_else(|error| Err(error.into()));
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
            Err(rejection) => {
                let outcome = match rejection.error {
                    AppError::Conflict => "conflict",
                    AppError::TooLarge => "quota_exceeded",
                    _ => "error",
                };
                audit_rejected(identity, share_id.as_str(), "upload", rejection.reason);
                outcomes.push(UploadOutcome {
                    path: path.to_string(),
                    outcome,
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

fn idle_timeout() -> Rejection {
    Rejection::new(AppError::InvalidRequest, "idle_timeout")
}

fn authorize_write(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    raw_path: &str,
) -> MutationResult<(ShareId, VirtualPath, OwnedAuthorizedShare)> {
    let share_id = parse_share_id(raw_share_id)?;
    let path = VirtualPath::parse(raw_path)?;
    let authorized = state.browse().authorize_owned(identity, &share_id)?;
    require_write_access(authorized.access())?;
    Ok((share_id, path, authorized))
}

fn require_write_access(access: AccessLevel) -> Result<(), AppError> {
    (access == AccessLevel::ReadWrite)
        .then_some(())
        .ok_or(AppError::Forbidden)
}

/// Applies the new-name policy to the final component a mutation creates.
fn ensure_creatable(path: &VirtualPath) -> MutationResult<()> {
    match path.file_name() {
        Some(name) => name.ensure_creatable().map_err(Rejection::from),
        None => Err(AppError::InvalidRequest.into()),
    }
}

async fn current_metadata(
    authorized: &OwnedAuthorizedShare,
    path: &VirtualPath,
) -> MutationResult<EntryMetadata> {
    let (share, path) = (authorized.clone(), path.clone());
    Ok(run_blocking(move || share.view().metadata(&path)).await??)
}

/// Creates a private staging file on the blocking pool. If the request is
/// cancelled meanwhile, the returned guard is dropped and removes the file.
async fn stage_write(
    authorized: &OwnedAuthorizedShare,
    path: &VirtualPath,
) -> MutationResult<PendingWrite> {
    let (share, path) = (authorized.clone(), path.clone());
    Ok(run_blocking(move || share.view().begin_write(&path)).await??)
}

fn parse_share_id(raw: &str) -> Result<ShareId, AppError> {
    ShareId::new(raw.to_owned()).map_err(|_| AppError::NotFound)
}

fn parse_optional_path(raw: Option<&str>) -> MutationResult<VirtualPath> {
    match raw {
        None | Some("") => Ok(VirtualPath::root()),
        Some(path) => Ok(VirtualPath::parse(path)?),
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
) -> MutationResult<()> {
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
) -> MutationResult<()> {
    let stale = || Rejection::new(AppError::Conflict, "stale_validator");
    let supplied = supplied
        .and_then(|value| value.to_str().ok())
        .ok_or_else(stale)?;
    let expected = state.browse().version_tag(share_id, path, metadata);
    if supplied == expected {
        Ok(())
    } else {
        Err(stale())
    }
}

/// Runs on the blocking pool with the share's commit lock held.
fn ensure_quota(
    authorized: &AuthorizedShare<'_>,
    limits: MutationLimits,
    incoming: u64,
    replacing: u64,
) -> MutationResult<()> {
    let Some(limit) = limits.max_share_bytes else {
        return Ok(());
    };
    let exceeded = || Rejection::new(AppError::TooLarge, "quota");
    let usage =
        match authorized.usage_bounded(QUOTA_SCAN_ENTRY_LIMIT, limit.saturating_add(replacing)) {
            Ok(usage) => usage,
            Err(error) if error.code() == FsErrorCode::TooLarge => return Err(exceeded()),
            Err(error) => return Err(error.into()),
        };
    let projected = usage
        .saturating_sub(replacing)
        .checked_add(incoming)
        .ok_or_else(exceeded)?;
    (projected <= limit).then_some(()).ok_or_else(exceeded)
}

fn finish_mutation(
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    path: &VirtualPath,
    operation: &'static str,
    result: MutationResult<()>,
    status: StatusCode,
) -> MutationResult<Response> {
    result?;
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

/// Emits the rejection audit event for any failed mutation, then returns
/// the public error.
fn audited(
    identity: &AuthenticatedIdentity,
    raw_share_id: &str,
    operation: &'static str,
    result: MutationResult<Response>,
) -> Result<Response, AppError> {
    result.map_err(|rejection| {
        // Only a syntactically valid share ID is logged verbatim.
        let share_id = if ShareId::new(raw_share_id.to_owned()).is_ok() {
            raw_share_id
        } else {
            "invalid"
        };
        audit_rejected(identity, share_id, operation, rejection.reason);
        rejection.error
    })
}

fn audit_rejected(
    identity: &AuthenticatedIdentity,
    share_id: &str,
    operation: &'static str,
    reason: &'static str,
) {
    tracing::warn!(
        audit = true,
        subject = identity.subject(),
        share_id,
        operation,
        outcome = "rejected",
        reason
    );
}

fn app_reason(error: &AppError) -> &'static str {
    match error {
        AppError::Forbidden => "access_denied",
        AppError::NotFound => "not_found",
        AppError::InvalidRequest => "invalid_request",
        AppError::Conflict => "conflict",
        AppError::TooLarge => "too_large",
        AppError::Busy | AppError::TooManyRequests => "busy",
        AppError::UnsupportedMedia => "unsupported_media",
        AppError::Unauthorized
        | AppError::AuthenticationFailed
        | AppError::ReauthenticationRequired => "unauthenticated",
        AppError::NotReady | AppError::Internal => "internal_error",
    }
}

fn fs_reason(code: FsErrorCode) -> &'static str {
    match code {
        FsErrorCode::AccessDenied => "access_denied",
        FsErrorCode::Conflict => "conflict",
        FsErrorCode::CrossDevice => "cross_device",
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
        FsErrorCode::CrossDevice => AppError::InvalidRequest,
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
        body::{Body, Bytes},
        http::{Request, StatusCode, header},
    };
    use futures_util::{StreamExt as _, stream};
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::sync::Semaphore;
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
        upload_gate: Arc<Semaphore>,
    }

    fn fixture(access: AccessLevel, global_read_only: bool, limits: MutationLimits) -> Fixture {
        fixture_with_state(
            access,
            global_read_only,
            MutationState::new(limits).expect("mutation state"),
        )
    }

    fn fixture_with_state(
        access: AccessLevel,
        global_read_only: bool,
        mutations: MutationState,
    ) -> Fixture {
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
        let upload_gate = Arc::clone(mutations.upload_gate.process_semaphore());
        let app = app::router(
            AppState::new(true)
                .with_browse(browse)
                .with_mutations(mutations),
        );
        Fixture {
            root,
            app,
            identity: AuthenticatedIdentity::new("user-1", vec![grant]),
            upload_gate,
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
    async fn read_only_grant_blocks_every_mutation_route_without_side_effects() {
        let fixture = fixture(AccessLevel::ReadOnly, false, MutationLimits::default());
        let boundary = "read-only-boundary";
        let requests = vec![
            json_request(
                "POST",
                "/api/v1/shares/documents/directories",
                json!({"path":"blocked-directory"}),
            ),
            json_request(
                "POST",
                "/api/v1/shares/documents/files",
                json!({"path":"blocked-file.txt"}),
            ),
            Request::put("/api/v1/shares/documents/text?path=existing.txt")
                .header(header::IF_MATCH, "W/\"attacker\"")
                .body(Body::from("replacement"))
                .unwrap(),
            Request::post("/api/v1/shares/documents/move")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "W/\"attacker\"")
                .body(Body::from(
                    json!({"source":"existing.txt","destination":"moved.txt"}).to_string(),
                ))
                .unwrap(),
            Request::delete("/api/v1/shares/documents/entry?path=existing.txt")
                .header(header::IF_MATCH, "W/\"attacker\"")
                .body(Body::empty())
                .unwrap(),
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    &[("blocked-upload.txt", b"blocked")],
                )))
                .unwrap(),
        ];

        for request in requests {
            let response = send(&fixture.app, Some(&fixture.identity), true, request).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        assert_eq!(
            fs::read(fixture.root.path().join("existing.txt")).unwrap(),
            b"original"
        );
        assert!(!fixture.root.path().join("blocked-directory").exists());
        assert!(!fixture.root.path().join("blocked-file.txt").exists());
        assert!(!fixture.root.path().join("blocked-upload.txt").exists());
        assert!(!fixture.root.path().join("moved.txt").exists());
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

        let too_many = multipart_body(
            boundary,
            &[
                ("a.txt", b"a"),
                ("b.txt", b"b"),
                ("c.txt", b"c"),
                ("d.txt", b"d"),
            ],
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
                .body(Body::from(too_many))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        for name in ["a.txt", "b.txt", "c.txt", "d.txt"] {
            assert!(!fixture.root.path().join(name).exists());
        }
        assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".index-tmp-")
        }));
    }

    #[tokio::test]
    async fn interrupted_upload_stream_removes_unpublished_temporary_file() {
        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        let boundary = "interrupted-boundary";
        let prefix = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"cancelled.txt\"\r\nContent-Type: application/octet-stream\r\n\r\npartial"
        );
        let interrupted = stream::iter([
            Ok::<_, std::io::Error>(Bytes::from(prefix)),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "synthetic client disconnect",
            )),
        ]);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from_stream(interrupted))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!fixture.root.path().join("cancelled.txt").exists());
        assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".index-tmp-")
        }));
    }

    #[tokio::test]
    async fn upload_concurrency_is_bounded_and_busy_requests_leave_no_temps() {
        let limits = MutationLimits {
            max_concurrent_uploads: 1,
            ..MutationLimits::default()
        };
        let fixture = fixture(AccessLevel::ReadWrite, false, limits);
        let held = Arc::clone(&fixture.upload_gate)
            .acquire_owned()
            .await
            .expect("upload permit");
        let boundary = "concurrency-boundary";
        let request = || {
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    &[("bounded.txt", b"complete")],
                )))
                .unwrap()
        };
        let busy = send(&fixture.app, Some(&fixture.identity), true, request()).await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(busy.headers()[header::RETRY_AFTER], "60");
        assert!(!fixture.root.path().join("bounded.txt").exists());
        assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".index-tmp-")
        }));

        drop(held);
        let accepted = send(&fixture.app, Some(&fixture.identity), true, request()).await;
        assert_eq!(accepted.status(), StatusCode::MULTI_STATUS);
        assert_eq!(
            fs::read(fixture.root.path().join("bounded.txt")).unwrap(),
            b"complete"
        );
    }

    #[tokio::test]
    async fn upload_authorization_precedes_the_global_busy_signal() {
        let limits = MutationLimits {
            max_concurrent_uploads: 1,
            ..MutationLimits::default()
        };
        let fixture = fixture(AccessLevel::ReadOnly, false, limits);
        let _held = Arc::clone(&fixture.upload_gate)
            .acquire_owned()
            .await
            .expect("upload permit");
        let boundary = "authorization-boundary";
        let request = |share: &str| {
            Request::post(format!("/api/v1/shares/{share}/uploads"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    &[("blocked.txt", b"blocked")],
                )))
                .unwrap()
        };

        let read_only = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            request("documents"),
        )
        .await;
        assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

        let ungranted = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            request("ungranted"),
        )
        .await;
        assert_eq!(ungranted.status(), StatusCode::NOT_FOUND);
        assert!(!fixture.root.path().join("blocked.txt").exists());
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

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    impl CapturedLogs {
        fn take(&self) -> String {
            let bytes = std::mem::take(&mut *self.0.lock().expect("log buffer"));
            String::from_utf8(bytes).expect("UTF-8 logs")
        }
    }

    #[tokio::test]
    async fn every_rejected_mutation_emits_an_audit_event() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        let cases = [
            (
                Request::delete("/api/v1/shares/documents/entry?path=existing.txt")
                    .header(header::IF_MATCH, "W/\"stale\"")
                    .body(Body::empty())
                    .unwrap(),
                StatusCode::CONFLICT,
                "stale_validator",
            ),
            (
                json_request(
                    "POST",
                    "/api/v1/shares/documents/files",
                    json!({"path":"../escape"}),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_path",
            ),
            (
                Request::post("/api/v1/shares/documents/move")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, "W/\"stale\"")
                    .body(Body::from(
                        json!({"source":"missing.txt","destination":"moved.txt"}).to_string(),
                    ))
                    .unwrap(),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                json_request(
                    "POST",
                    "/api/v1/shares/documents/files",
                    json!({"path":"existing.txt"}),
                ),
                StatusCode::CONFLICT,
                "conflict",
            ),
            (
                json_request(
                    "POST",
                    "/api/v1/shares/unknown/directories",
                    json!({"path":"folder"}),
                ),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
        ];
        for (request, status, reason) in cases {
            let response = send(&fixture.app, Some(&fixture.identity), true, request).await;
            assert_eq!(response.status(), status, "{reason}");
            let emitted = logs.take();
            assert!(emitted.contains("rejected"), "no audit event: {emitted}");
            assert!(emitted.contains(reason), "missing {reason}: {emitted}");
        }
    }

    #[tokio::test]
    async fn new_names_reject_spoofing_characters_but_existing_names_stay_usable() {
        let fixture = fixture(AccessLevel::ReadWrite, false, MutationLimits::default());
        let spoofed = "invoice\u{202e}fdp.exe";
        fs::write(fixture.root.path().join("zero\u{200b}width.txt"), b"legacy")
            .expect("existing spoofing name");
        for (route, path) in [("files", spoofed), ("directories", "line\u{2028}break")] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                true,
                json_request(
                    "POST",
                    &format!("/api/v1/shares/documents/{route}"),
                    json!({ "path": path }),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{route}");
        }

        let etag = metadata_etag(&fixture, "existing.txt").await;
        let rename = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/move")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag)
                .body(Body::from(
                    json!({"source":"existing.txt","destination": spoofed}).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(rename.status(), StatusCode::BAD_REQUEST);
        assert!(fixture.root.path().join("existing.txt").exists());

        // An existing entry keeps its name when moved to another directory.
        let legacy_etag = metadata_etag(&fixture, "zero%E2%80%8Bwidth.txt").await;
        let moved = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/move")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, legacy_etag)
                .body(Body::from(
                    json!({
                        "source": "zero\u{200b}width.txt",
                        "destination": "nonempty/zero\u{200b}width.txt"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(moved.status(), StatusCode::OK);
        assert!(
            fixture
                .root
                .path()
                .join("nonempty/zero\u{200b}width.txt")
                .exists()
        );

        let boundary = "spoof-boundary";
        let upload = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body(
                    boundary,
                    &[(spoofed, b"payload")],
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(upload.status(), StatusCode::BAD_REQUEST);
        assert!(!fixture.root.path().join(spoofed).exists());
    }

    #[tokio::test]
    async fn stalled_uploads_time_out_and_release_their_slot() {
        let limits = MutationLimits {
            max_concurrent_uploads: 1,
            ..MutationLimits::default()
        };
        let mutations = MutationState::new(limits)
            .expect("mutation state")
            .with_upload_idle_timeout(Duration::from_millis(100));
        let fixture = fixture_with_state(AccessLevel::ReadWrite, false, mutations);
        let boundary = "stalled-boundary";
        let prefix = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"stalled.txt\"\r\nContent-Type: application/octet-stream\r\n\r\npartial"
        );
        let stalled = stream::iter([Ok::<_, std::io::Error>(Bytes::from(prefix))])
            .chain(stream::pending::<Result<Bytes, std::io::Error>>());
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            true,
            Request::post("/api/v1/shares/documents/uploads")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from_stream(stalled))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(fixture.upload_gate.available_permits(), 1);
        assert!(!fixture.root.path().join("stalled.txt").exists());
        let staging = fixture.root.path().join(".index-staging");
        assert!(fs::read_dir(staging).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".index-tmp-")
        }));
    }

    #[test]
    fn one_subject_cannot_take_every_upload_slot() {
        let state = MutationState::new(MutationLimits::default()).expect("mutation state");
        let first = state.upload_gate.try_acquire("alice").expect("first slot");
        let second = state.upload_gate.try_acquire("alice").expect("second slot");
        let third = state.upload_gate.try_acquire("alice").expect("third slot");
        assert!(state.upload_gate.try_acquire("alice").is_none());
        let other = state.upload_gate.try_acquire("bob").expect("other user");
        assert!(state.upload_gate.try_acquire("bob").is_none());
        drop((first, second, third, other));

        let single = MutationState::new(MutationLimits {
            max_concurrent_uploads: 1,
            ..MutationLimits::default()
        })
        .expect("mutation state");
        assert!(single.upload_gate.try_acquire("alice").is_some());
    }

    #[tokio::test]
    async fn commit_locks_are_per_share() {
        let state = MutationState::default();
        let documents = ShareId::new("documents").expect("id");
        let photos = ShareId::new("photos").expect("id");
        let held = state.commit_lock(&documents).await;
        tokio::time::timeout(Duration::from_secs(1), state.commit_lock(&photos))
            .await
            .expect("another share is not blocked");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.commit_lock(&documents))
                .await
                .is_err()
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), state.commit_lock(&documents))
            .await
            .expect("released lock is available");
    }
}

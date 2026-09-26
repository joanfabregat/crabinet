//! Authenticated, authorization-aware read APIs for configured shares.
//!
//! Authentication middleware must insert an [`AuthenticatedIdentity`] in the
//! request extensions. There is deliberately no header, cookie, or development
//! fallback in this module: production requests fail closed until the real
//! authentication layer has verified a session.

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    io::SeekFrom,
    mem::MaybeUninit,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::stream;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Duration, Instant, sleep},
};
use tokio_util::io::ReaderStream;

use crate::{
    app::AppState,
    error::AppError,
    filesystem::{
        AccessLevel, AuthorizedShare, DirectoryEntry, EntryKind, EntryMetadata, FsError,
        FsErrorCode, GlobalPolicy, ShareFs, ShareGrant, ShareId, VirtualPath,
    },
};

type HmacSha256 = Hmac<Sha256>;
const CURSOR_VERSION: u8 = 1;
const CURSOR_BYTES: usize = 1 + 8 + 32 + 32;
const MAX_EVENT_CONNECTIONS: usize = 64;
const MAX_EVENT_CONNECTIONS_PER_SUBJECT: usize = 4;

#[derive(Clone, Debug)]
pub struct AuthenticatedIdentity {
    subject: Arc<str>,
    grants: Arc<[ShareGrant]>,
}

impl AuthenticatedIdentity {
    #[must_use]
    pub fn new(subject: impl Into<Arc<str>>, grants: Vec<ShareGrant>) -> Self {
        Self {
            subject: subject.into(),
            grants: grants.into(),
        }
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn grant_for(&self, share_id: &ShareId) -> Option<&ShareGrant> {
        self.grants.iter().find(|grant| &grant.share_id == share_id)
    }
}

impl<S> FromRequestParts<S> for AuthenticatedIdentity
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BrowseLimits {
    pub default_page_size: usize,
    pub max_page_size: usize,
    pub max_directory_entries: usize,
    pub max_text_bytes: u64,
    pub max_download_bytes: u64,
    pub stream_chunk_bytes: usize,
}

impl Default for BrowseLimits {
    fn default() -> Self {
        Self {
            default_page_size: 100,
            max_page_size: 200,
            max_directory_entries: 10_000,
            max_text_bytes: 1_048_576,
            max_download_bytes: 1_073_741_824,
            stream_chunk_bytes: 65_536,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BrowseStateError {
    #[error("duplicate share identifier")]
    DuplicateShare,
    #[error("cursor key must be a non-zero 32-byte secret")]
    InvalidCursorKey,
    #[error("browse limits must be non-zero and internally consistent")]
    InvalidLimits,
    #[error("configured share display name is invalid")]
    InvalidDisplayName,
}

pub struct ConfiguredShare {
    name: Arc<str>,
    filesystem: ShareFs,
}

impl ConfiguredShare {
    pub fn new(name: impl Into<Arc<str>>, filesystem: ShareFs) -> Result<Self, BrowseStateError> {
        let name = name.into();
        if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(BrowseStateError::InvalidDisplayName);
        }
        Ok(Self { name, filesystem })
    }

    #[must_use]
    pub fn id(&self) -> &ShareId {
        self.filesystem.id()
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub struct BrowseState {
    shares: HashMap<ShareId, Arc<ConfiguredShare>>,
    limits: BrowseLimits,
    policy: GlobalPolicy,
    cursor_key: [u8; 32],
    event_gate: DirectoryEventGate,
}

struct DirectoryEventGate {
    process: Arc<Semaphore>,
    subjects: Arc<Mutex<HashMap<Arc<str>, usize>>>,
    per_subject: usize,
}

struct DirectoryEventLease {
    _process: OwnedSemaphorePermit,
    subject: Arc<str>,
    subjects: Arc<Mutex<HashMap<Arc<str>, usize>>>,
}

impl DirectoryEventGate {
    fn new(process: usize, per_subject: usize) -> Self {
        Self {
            process: Arc::new(Semaphore::new(process)),
            subjects: Arc::new(Mutex::new(HashMap::new())),
            per_subject,
        }
    }

    fn try_acquire(&self, subject: &str) -> Result<DirectoryEventLease, AppError> {
        let process = self
            .process
            .clone()
            .try_acquire_owned()
            .map_err(|_| AppError::TooManyRequests)?;
        let subject: Arc<str> = Arc::from(subject);
        let mut subjects = self.subjects.lock().map_err(|_| AppError::Internal)?;
        let active = subjects.entry(subject.clone()).or_default();
        if *active >= self.per_subject {
            return Err(AppError::TooManyRequests);
        }
        *active += 1;
        drop(subjects);
        Ok(DirectoryEventLease {
            _process: process,
            subject,
            subjects: self.subjects.clone(),
        })
    }
}

impl Drop for DirectoryEventLease {
    fn drop(&mut self) {
        let Ok(mut subjects) = self.subjects.lock() else {
            return;
        };
        if let Some(active) = subjects.get_mut(&self.subject) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                subjects.remove(&self.subject);
            }
        }
    }
}

impl BrowseState {
    pub fn new(
        shares: Vec<ConfiguredShare>,
        limits: BrowseLimits,
        policy: GlobalPolicy,
        cursor_key: [u8; 32],
    ) -> Result<Self, BrowseStateError> {
        if cursor_key.iter().all(|byte| *byte == 0) {
            return Err(BrowseStateError::InvalidCursorKey);
        }
        if limits.default_page_size == 0
            || limits.max_page_size == 0
            || limits.default_page_size > limits.max_page_size
            || limits.max_directory_entries < limits.max_page_size
            || limits.max_text_bytes == 0
            || limits.max_download_bytes == 0
            || limits.stream_chunk_bytes == 0
        {
            return Err(BrowseStateError::InvalidLimits);
        }

        let mut by_id = HashMap::with_capacity(shares.len());
        for share in shares {
            let id = share.id().clone();
            if by_id.insert(id, Arc::new(share)).is_some() {
                return Err(BrowseStateError::DuplicateShare);
            }
        }
        Ok(Self {
            shares: by_id,
            limits,
            policy,
            cursor_key,
            event_gate: DirectoryEventGate::new(
                MAX_EVENT_CONNECTIONS,
                MAX_EVENT_CONNECTIONS_PER_SUBJECT,
            ),
        })
    }

    pub(crate) fn disabled() -> Self {
        Self {
            shares: HashMap::new(),
            limits: BrowseLimits::default(),
            policy: GlobalPolicy::default(),
            cursor_key: [0; 32],
            event_gate: DirectoryEventGate::new(
                MAX_EVENT_CONNECTIONS,
                MAX_EVENT_CONNECTIONS_PER_SUBJECT,
            ),
        }
    }

    pub fn authorize<'state>(
        &'state self,
        identity: &AuthenticatedIdentity,
        share_id: &ShareId,
    ) -> Result<AuthorizedShare<'state>, AppError> {
        let share = self.shares.get(share_id).ok_or(AppError::NotFound)?;
        share
            .filesystem
            .authorize(identity.grant_for(share_id), self.policy)
            .map_err(non_disclosing_fs_error)
    }

    fn acquire_event_connection(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<DirectoryEventLease, AppError> {
        self.event_gate.try_acquire(identity.subject())
    }

    /// Builds the same opaque validator returned by the metadata/read APIs.
    /// Mutation handlers use it for `If-Match` without learning host paths.
    #[must_use]
    pub(crate) fn version_tag(
        &self,
        share_id: &ShareId,
        path: &VirtualPath,
        metadata: EntryMetadata,
    ) -> String {
        entry_etag(&self.cursor_key, share_id, path, metadata)
    }

    fn authorized<'state>(
        &'state self,
        identity: &AuthenticatedIdentity,
        raw_share_id: &str,
    ) -> Result<(&'state ConfiguredShare, AuthorizedShare<'state>), AppError> {
        let share_id = ShareId::new(raw_share_id.to_owned()).map_err(|_| AppError::NotFound)?;
        let share = self.shares.get(&share_id).ok_or(AppError::NotFound)?;
        let authorized = self.authorize(identity, &share_id)?;
        Ok((share.as_ref(), authorized))
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/shares", get(discover_shares))
        .route("/shares/{share_id}/directory", get(list_directory))
        .route("/shares/{share_id}/events", get(directory_events))
        .route("/shares/{share_id}/metadata", get(read_metadata))
        .route("/shares/{share_id}/text", get(read_text))
        .route("/shares/{share_id}/download", get(download))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShareSummary {
    id: String,
    name: String,
    access: ApiAccess,
}

#[derive(Clone, Copy, Serialize)]
enum ApiAccess {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "read-write")]
    ReadWrite,
}

impl From<AccessLevel> for ApiAccess {
    fn from(access: AccessLevel) -> Self {
        match access {
            AccessLevel::ReadOnly => Self::Read,
            AccessLevel::ReadWrite => Self::ReadWrite,
        }
    }
}

#[derive(Serialize)]
struct ShareList {
    shares: Vec<ShareSummary>,
}

async fn discover_shares(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let mut visible = BTreeMap::<String, (String, AccessLevel)>::new();
    for (share_id, share) in &browse.shares {
        let Some(grant) = identity.grant_for(share_id) else {
            continue;
        };
        let Ok(authorized) = share.filesystem.authorize(Some(grant), browse.policy) else {
            continue;
        };
        visible
            .entry(share_id.as_str().to_owned())
            .or_insert_with(|| (share.name().to_owned(), authorized.access()));
    }
    Ok(inert_json(ShareList {
        shares: visible
            .into_iter()
            .map(|(id, (name, access))| ShareSummary {
                id,
                name,
                access: access.into(),
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
struct DirectoryQuery {
    path: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(rename = "showHidden")]
    show_hidden: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryPage {
    share_id: String,
    path: String,
    entries: Vec<EntryResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryResponse {
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

async fn list_directory(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<DirectoryQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let (share, authorized) = browse.authorized(&identity, &raw_share_id)?;
    let path = parse_query_path(query.path.as_deref())?;
    let limit = query.limit.unwrap_or(browse.limits.default_page_size);
    if limit == 0 || limit > browse.limits.max_page_size {
        return Err(AppError::InvalidRequest);
    }

    let mut entries = authorized
        .list_bounded(&path, browse.limits.max_directory_entries)
        .map_err(map_fs_error)?;
    if query.show_hidden == Some(false) {
        entries.retain(|entry| !entry.name.as_str().starts_with('.'));
    }
    entries.sort_by(|left, right| {
        entry_kind_order(left.kind)
            .cmp(&entry_kind_order(right.kind))
            .then_with(|| left.name.cmp(&right.name))
    });
    let fingerprint = listing_fingerprint(&entries);
    let offset = match query.cursor.as_deref() {
        Some(cursor) => decode_cursor(
            cursor,
            &browse.cursor_key,
            &identity,
            share.id(),
            &path,
            authorized.access(),
            &fingerprint,
        )?,
        None => 0,
    };
    if offset > entries.len() {
        return Err(AppError::Conflict);
    }
    let end = offset.saturating_add(limit).min(entries.len());
    let next_cursor = (end < entries.len()).then(|| {
        encode_cursor(
            &browse.cursor_key,
            &identity,
            share.id(),
            &path,
            authorized.access(),
            end,
            &fingerprint,
        )
    });
    let entries = entries[offset..end].iter().map(entry_response).collect();

    Ok(inert_json(DirectoryPage {
        share_id: share.id().as_str().to_owned(),
        path: path.to_string(),
        entries,
        next_cursor,
    }))
}

/// Sends event-driven invalidation hints for one explicitly selected
/// directory. Each connection is bounded to five minutes, then browsers
/// reconnect through authentication middleware. No directory contents are
/// scanned by the event stream.
async fn directory_events(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<DirectoryQuery>,
) -> Result<Response, AppError> {
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let path = parse_query_path(query.path.as_deref())?;
    let authorized = state.browse().authorize(&identity, &share_id)?;
    let lease = state.browse().acquire_event_connection(&identity)?;
    let watcher = authorized.watch_directory(&path).map_err(map_fs_error)?;
    let deadline = Instant::now() + Duration::from_secs(5 * 60);

    let events = stream::unfold(
        (watcher, deadline, lease),
        |(watcher, deadline, lease)| async move {
            loop {
                if Instant::now() >= deadline {
                    return None;
                }
                sleep(Duration::from_millis(250)).await;
                let mut buffer = [MaybeUninit::uninit(); 4096];
                match rustix::fs::inotify::Reader::new(&watcher, &mut buffer).next() {
                    Ok(_) => {
                        return Some((
                            Ok::<Event, Infallible>(
                                Event::default().event("invalidate").data("{}"),
                            ),
                            (watcher, deadline, lease),
                        ));
                    }
                    Err(rustix::io::Errno::AGAIN) => {}
                    Err(_) => {
                        return Some((
                            Ok::<Event, Infallible>(Event::default().event("resync").data("{}")),
                            (watcher, Instant::now(), lease),
                        ));
                    }
                }
            }
        },
    );

    let mut response = Sse::new(events)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    Ok(response)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataResponse {
    share_id: String,
    path: String,
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessed_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at_ms: Option<u64>,
    etag: String,
}

async fn read_metadata(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<FileQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let (share, authorized) = browse.authorized(&identity, &raw_share_id)?;
    let path = VirtualPath::parse(&query.path).map_err(map_fs_error)?;
    let metadata = authorized.metadata(&path).map_err(map_fs_error)?;
    let name = path
        .components()
        .last()
        .ok_or(AppError::InvalidRequest)?
        .as_str();
    let etag = entry_etag(&browse.cursor_key, share.id(), &path, metadata);
    let mut response = inert_json(MetadataResponse {
        share_id: share.id().as_str().to_owned(),
        path: path.to_string(),
        name: name.to_owned(),
        kind: kind_name(metadata.kind),
        size: (metadata.kind == EntryKind::File).then_some(metadata.size),
        accessed_at_ms: system_time_millis(metadata.accessed),
        created_at_ms: system_time_millis(metadata.created),
        etag: etag.clone(),
    });
    response
        .headers_mut()
        .insert(header::ETAG, header_value(&etag)?);
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct FileQuery {
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TextResponse {
    share_id: String,
    path: String,
    text: String,
    size: u64,
    mime_type: String,
    etag: String,
}

async fn read_text(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<FileQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let (share, authorized) = browse.authorized(&identity, &raw_share_id)?;
    let path = VirtualPath::parse(&query.path).map_err(map_fs_error)?;
    let bytes = authorized
        .read_file(&path, browse.limits.max_text_bytes)
        .map_err(map_fs_error)?;
    let size = bytes.len() as u64;
    let text = String::from_utf8(bytes).map_err(|_| AppError::UnsupportedMedia)?;
    let mime_type = mime_for_path(&path);
    let etag = content_etag(text.as_bytes());
    let mut response = Json(TextResponse {
        share_id: share.id().as_str().to_owned(),
        path: path.to_string(),
        text,
        size,
        mime_type,
        etag: etag.clone(),
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::ETAG, header_value(&etag)?);
    add_inert_headers(response.headers_mut());
    Ok(response)
}

async fn download(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let (share, authorized) = browse.authorized(&identity, &raw_share_id)?;
    let path = VirtualPath::parse(&query.path).map_err(map_fs_error)?;
    let opened = authorized.open_file(&path).map_err(map_fs_error)?;
    let total_len = opened.len();
    if total_len > browse.limits.max_download_bytes {
        return Err(AppError::TooLarge);
    }
    let etag = metadata_etag(
        &browse.cursor_key,
        share.id(),
        &path,
        total_len,
        opened.modified(),
        opened.file_id(),
        EntryKind::File,
    );
    let mime = mime_for_path(&path);
    let filename = path
        .components()
        .last()
        .ok_or(AppError::InvalidRequest)?
        .as_str();

    if if_none_match(headers.get(header::IF_NONE_MATCH), &etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        add_file_headers(response.headers_mut(), &etag, &mime, filename)?;
        return Ok(response);
    }

    let requested_range = if if_range_allows(headers.get(header::IF_RANGE), &etag) {
        match headers.get(header::RANGE) {
            Some(value) => {
                let Some(range) = parse_range(value, total_len) else {
                    return range_not_satisfiable(total_len);
                };
                Some(range)
            }
            None => None,
        }
    } else {
        None
    };

    let (status, start, response_len) = match requested_range {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        None => (StatusCode::OK, 0, total_len),
    };
    let mut file = tokio::fs::File::from_std(opened.into_std());
    if start != 0 {
        file.seek(SeekFrom::Start(start))
            .await
            .map_err(|_| AppError::Internal)?;
    }
    let stream =
        ReaderStream::with_capacity(file.take(response_len), browse.limits.stream_chunk_bytes);
    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(stream))
        .map_err(|_| AppError::Internal)?;
    add_file_headers(response.headers_mut(), &etag, &mime, filename)?;
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header_value(&response_len.to_string())?,
    );
    if let Some((start, end)) = requested_range {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes {start}-{end}/{total_len}"))?,
        );
    }
    Ok(response)
}

fn parse_query_path(raw: Option<&str>) -> Result<VirtualPath, AppError> {
    match raw {
        None | Some("") => Ok(VirtualPath::root()),
        Some(path) => VirtualPath::parse(path).map_err(map_fs_error),
    }
}

fn entry_kind_order(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Directory => 0,
        EntryKind::File => 1,
    }
}

fn entry_response(entry: &DirectoryEntry) -> EntryResponse {
    EntryResponse {
        name: entry.name.as_str().to_owned(),
        kind: kind_name(entry.kind),
        size: (entry.kind == EntryKind::File).then_some(entry.size),
    }
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Directory => "directory",
        EntryKind::File => "file",
    }
}

fn listing_fingerprint(entries: &[DirectoryEntry]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hash.update([entry_kind_order(entry.kind)]);
        hash.update((entry.name.as_str().len() as u64).to_be_bytes());
        hash.update(entry.name.as_str().as_bytes());
        hash.update(entry.size.to_be_bytes());
        hash.update(entry.file_id.to_be_bytes());
        update_time_digest(&mut hash, entry.modified);
    }
    hash.finalize().into()
}

fn encode_cursor(
    key: &[u8; 32],
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    path: &VirtualPath,
    access: AccessLevel,
    offset: usize,
    fingerprint: &[u8; 32],
) -> String {
    let offset = u64::try_from(offset).expect("directory entry limit fits in u64");
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.push(CURSOR_VERSION);
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes.extend_from_slice(fingerprint);
    let tag = cursor_tag(key, identity, share_id, path, access, offset, fingerprint);
    bytes.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_cursor(
    encoded: &str,
    key: &[u8; 32],
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    path: &VirtualPath,
    access: AccessLevel,
    current_fingerprint: &[u8; 32],
) -> Result<usize, AppError> {
    if encoded.len() > 128 {
        return Err(AppError::Conflict);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::Conflict)?;
    if bytes.len() != CURSOR_BYTES || bytes[0] != CURSOR_VERSION {
        return Err(AppError::Conflict);
    }
    let offset = u64::from_be_bytes(bytes[1..9].try_into().map_err(|_| AppError::Conflict)?);
    let fingerprint: [u8; 32] = bytes[9..41].try_into().map_err(|_| AppError::Conflict)?;
    if &fingerprint != current_fingerprint {
        return Err(AppError::Conflict);
    }
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    update_cursor_mac(
        &mut mac,
        identity,
        share_id,
        path,
        access,
        offset,
        &fingerprint,
    );
    mac.verify_slice(&bytes[41..])
        .map_err(|_| AppError::Conflict)?;
    usize::try_from(offset).map_err(|_| AppError::Conflict)
}

fn cursor_tag(
    key: &[u8; 32],
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    path: &VirtualPath,
    access: AccessLevel,
    offset: u64,
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    update_cursor_mac(
        &mut mac,
        identity,
        share_id,
        path,
        access,
        offset,
        fingerprint,
    );
    mac.finalize().into_bytes().into()
}

fn update_cursor_mac(
    mac: &mut HmacSha256,
    identity: &AuthenticatedIdentity,
    share_id: &ShareId,
    path: &VirtualPath,
    access: AccessLevel,
    offset: u64,
    fingerprint: &[u8; 32],
) {
    update_framed(mac, identity.subject().as_bytes());
    update_framed(mac, share_id.as_str().as_bytes());
    update_framed(mac, path.to_string().as_bytes());
    mac.update(&[match access {
        AccessLevel::ReadOnly => 0,
        AccessLevel::ReadWrite => 1,
    }]);
    mac.update(&offset.to_be_bytes());
    mac.update(fingerprint);
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn content_etag(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("\"{}\"", hex(&digest))
}

fn metadata_etag(
    key: &[u8; 32],
    share_id: &ShareId,
    path: &VirtualPath,
    len: u64,
    modified: Option<SystemTime>,
    file_id: u64,
    kind: EntryKind,
) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    update_framed(&mut mac, share_id.as_str().as_bytes());
    update_framed(&mut mac, path.to_string().as_bytes());
    mac.update(&len.to_be_bytes());
    mac.update(&file_id.to_be_bytes());
    mac.update(&[entry_kind_order(kind)]);
    update_time_mac(&mut mac, modified);
    format!("W/\"{}\"", hex(&mac.finalize().into_bytes()))
}

fn entry_etag(
    key: &[u8; 32],
    share_id: &ShareId,
    path: &VirtualPath,
    metadata: EntryMetadata,
) -> String {
    metadata_etag(
        key,
        share_id,
        path,
        metadata.size,
        metadata.modified,
        metadata.file_id,
        metadata.kind,
    )
}

fn update_time_digest(hash: &mut Sha256, time: Option<SystemTime>) {
    match time.and_then(|time| time.duration_since(UNIX_EPOCH).ok()) {
        Some(duration) => {
            hash.update([1]);
            hash.update(duration.as_secs().to_be_bytes());
            hash.update(duration.subsec_nanos().to_be_bytes());
        }
        None => hash.update([0]),
    }
}

fn system_time_millis(time: Option<SystemTime>) -> Option<u64> {
    time.and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn update_time_mac(mac: &mut HmacSha256, time: Option<SystemTime>) {
    match time.and_then(|time| time.duration_since(UNIX_EPOCH).ok()) {
        Some(duration) => {
            mac.update(&[1]);
            mac.update(&duration.as_secs().to_be_bytes());
            mac.update(&duration.subsec_nanos().to_be_bytes());
        }
        None => mac.update(&[0]),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn if_none_match(value: Option<&HeaderValue>, etag: &str) -> bool {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let etag = etag.strip_prefix("W/").unwrap_or(etag);
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

fn if_range_allows(value: Option<&HeaderValue>, etag: &str) -> bool {
    value.is_none()
        || (!etag.starts_with("W/")
            && value.is_some_and(|value| value.as_bytes() == etag.as_bytes()))
}

fn parse_range(value: &HeaderValue, total_len: u64) -> Option<(u64, u64)> {
    let value = value.to_str().ok()?.strip_prefix("bytes=")?;
    if value.contains(',') || total_len == 0 {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?;
        if suffix == 0 {
            return None;
        }
        let length = suffix.min(total_len);
        return Some((total_len - length, total_len - 1));
    }
    let start = start.parse::<u64>().ok()?;
    if start >= total_len {
        return None;
    }
    let end = if end.is_empty() {
        total_len - 1
    } else {
        end.parse::<u64>().ok()?.min(total_len - 1)
    };
    (start <= end).then_some((start, end))
}

fn mime_for_path(path: &VirtualPath) -> String {
    mime_guess::from_path(path.to_string())
        .first_or_octet_stream()
        .to_string()
}

pub(crate) fn content_disposition(filename: &str) -> Result<HeaderValue, AppError> {
    let fallback: String = filename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let mut encoded = String::with_capacity(filename.len() * 3);
    for byte in filename.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_') {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    header_value(&format!(
        "attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"
    ))
}

fn add_inert_headers(headers: &mut HeaderMap) {
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
}

fn inert_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    add_inert_headers(response.headers_mut());
    response
}

fn add_file_headers(
    headers: &mut HeaderMap,
    etag: &str,
    mime: &str,
    filename: &str,
) -> Result<(), AppError> {
    headers.insert(header::CONTENT_TYPE, header_value(mime)?);
    headers.insert(header::CONTENT_DISPOSITION, content_disposition(filename)?);
    headers.insert(header::ETAG, header_value(etag)?);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    add_inert_headers(headers);
    Ok(())
}

fn range_not_satisfiable(total_len: u64) -> Result<Response, AppError> {
    let mut response = AppError::InvalidRequest.into_response();
    *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    response.headers_mut().insert(
        header::CONTENT_RANGE,
        header_value(&format!("bytes */{total_len}"))?,
    );
    add_inert_headers(response.headers_mut());
    Ok(response)
}

fn header_value(value: &str) -> Result<HeaderValue, AppError> {
    HeaderValue::from_str(value).map_err(|_| AppError::Internal)
}

fn non_disclosing_fs_error(error: FsError) -> AppError {
    match error.code() {
        FsErrorCode::TooLarge => AppError::TooLarge,
        FsErrorCode::Unavailable => AppError::Internal,
        FsErrorCode::InvalidPath => AppError::InvalidRequest,
        FsErrorCode::AccessDenied
        | FsErrorCode::Conflict
        | FsErrorCode::CrossDevice
        | FsErrorCode::NotFound
        | FsErrorCode::UnsupportedEntry => AppError::NotFound,
    }
}

fn map_fs_error(error: FsError) -> AppError {
    non_disclosing_fs_error(error)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use proptest::prelude::*;
    use serde_json::Value;
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        app,
        filesystem::{EntryName, ShareId},
    };

    struct Fixture {
        _root: TempDir,
        app: Router,
        identity: AuthenticatedIdentity,
        grant: ShareGrant,
    }

    fn fixture(limits: BrowseLimits) -> Fixture {
        fixture_with_policy(limits, GlobalPolicy::default())
    }

    fn fixture_with_policy(limits: BrowseLimits, policy: GlobalPolicy) -> Fixture {
        let root = TempDir::new().expect("temporary share");
        fs::create_dir(root.path().join("a-directory")).expect("directory fixture");
        fs::write(root.path().join("a.txt"), b"abcdef").expect("text fixture");
        fs::write(
            root.path().join("page.html"),
            b"<script>window.evil=true</script>",
        )
        .expect("HTML fixture");
        fs::write(root.path().join("invalid.txt"), [0xff, 0xfe]).expect("binary fixture");
        let id = ShareId::new("documents").expect("share id");
        let share = ShareFs::open(id.clone(), root.path()).expect("open share");
        let share = ConfiguredShare::new("Documents", share).expect("configured share");
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadWrite,
        };
        let browse =
            BrowseState::new(vec![share], limits, policy, [0x5a; 32]).expect("browse state");
        let app = app::router(AppState::new(true).with_browse(browse));
        let identity = AuthenticatedIdentity::new("user-1", vec![grant.clone()]);
        Fixture {
            _root: root,
            app,
            identity,
            grant,
        }
    }

    async fn send(
        app: &Router,
        identity: Option<&AuthenticatedIdentity>,
        request: Request<Body>,
    ) -> Response {
        let (mut parts, body) = request.into_parts();
        if let Some(identity) = identity {
            parts.extensions.insert(identity.clone());
        }
        app.clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .expect("router response")
    }

    async fn json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("JSON response")
    }

    #[test]
    fn configured_share_construction_does_not_repeat_startup_recovery() {
        let root = TempDir::new().expect("temporary share");
        let interrupted = root
            .path()
            .join(".index-tmp-00000000000000000000000000000000");
        fs::write(&interrupted, b"incomplete").expect("interrupted write fixture");
        let filesystem = ShareFs::open(ShareId::new("documents").expect("share id"), root.path())
            .expect("open share");

        ConfiguredShare::new("Documents", filesystem).expect("configured share");

        assert!(interrupted.exists());
    }

    #[tokio::test]
    async fn browse_routes_fail_closed_without_authenticated_extension() {
        let fixture = fixture(BrowseLimits::default());
        let response = send(
            &fixture.app,
            None,
            Request::get("/api/v1/shares").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn discovery_returns_only_configured_grants_with_effective_access() {
        let mut fixture = fixture(BrowseLimits::default());
        fixture.identity = AuthenticatedIdentity::new(
            "user-1",
            vec![
                fixture.grant.clone(),
                ShareGrant {
                    share_id: ShareId::new("not-configured").unwrap(),
                    access: AccessLevel::ReadWrite,
                },
            ],
        );
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = json(response).await;
        assert_eq!(value["shares"].as_array().unwrap().len(), 1);
        assert_eq!(value["shares"][0]["id"], "documents");
        assert_eq!(value["shares"][0]["name"], "Documents");
        assert_eq!(value["shares"][0]["access"], "read-write");

        let read_only =
            fixture_with_policy(BrowseLimits::default(), GlobalPolicy { read_only: true });
        let response = send(
            &read_only.app,
            Some(&read_only.identity),
            Request::get("/api/v1/shares").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(json(response).await["shares"][0]["access"], "read");
    }

    #[tokio::test]
    async fn missing_and_ungranted_shares_are_equally_non_disclosing() {
        let fixture = fixture(BrowseLimits::default());
        let no_grants = AuthenticatedIdentity::new("user-2", vec![]);
        for (identity, uri) in [
            (&fixture.identity, "/api/v1/shares/missing/directory?path="),
            (&no_grants, "/api/v1/shares/documents/directory?path="),
        ] {
            let response = send(
                &fixture.app,
                Some(identity),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(json(response).await["error"]["code"], "not_found");
        }
    }

    #[tokio::test]
    async fn listing_is_folder_first_deterministic_and_paginated() {
        let fixture = fixture(BrowseLimits::default());
        let first = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?path=&limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let first = json(first).await;
        assert_eq!(first["shareId"], "documents");
        assert_eq!(first["path"], "");
        assert_eq!(first["entries"][0]["name"], "a-directory");
        assert_eq!(first["entries"][0]["kind"], "directory");
        assert!(first["entries"][0].get("size").is_none());
        assert_eq!(first["entries"][1]["name"], "a.txt");
        let cursor = first["nextCursor"].as_str().expect("next cursor");

        let second = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(format!(
                "/api/v1/shares/documents/directory?path=&limit=2&cursor={cursor}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
        let second = json(second).await;
        assert_eq!(second["entries"][0]["name"], "invalid.txt");
        assert_eq!(second["entries"][1]["name"], "page.html");
        assert!(second.get("nextCursor").is_none());
    }

    #[tokio::test]
    async fn hidden_entries_are_filtered_before_pagination_but_remain_accessible() {
        let fixture = fixture(BrowseLimits::default());
        fs::create_dir(fixture._root.path().join(".private")).expect("hidden directory fixture");
        fs::write(fixture._root.path().join(".secret.txt"), b"hidden")
            .expect("hidden file fixture");

        let unfiltered = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?path=&limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(json(unfiltered).await["entries"][0]["name"], ".private");

        let filtered = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?path=&limit=2&showHidden=false")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let first = json(filtered).await;
        assert_eq!(first["entries"][0]["name"], "a-directory");
        assert_eq!(first["entries"][1]["name"], "a.txt");
        let cursor = first["nextCursor"].as_str().expect("next cursor");

        let next = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(format!(
                "/api/v1/shares/documents/directory?path=&limit=2&showHidden=false&cursor={cursor}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        let next = json(next).await;
        assert_eq!(next["entries"][0]["name"], "invalid.txt");
        assert_eq!(next["entries"][1]["name"], "page.html");
        assert!(next.get("nextCursor").is_none());

        let preview = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/preview?path=.secret.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(preview.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn listings_cover_empty_unicode_and_large_directories() {
        let fixture = fixture(BrowseLimits::default());
        fs::create_dir(fixture._root.path().join("empty")).expect("empty directory");
        fs::create_dir(fixture._root.path().join("équipe")).expect("Unicode directory");
        fs::write(fixture._root.path().join("東京.md"), b"Tokyo").expect("Unicode file");
        let large = fixture._root.path().join("large");
        fs::create_dir(&large).expect("large directory");
        for index in 0..205 {
            fs::write(large.join(format!("entry-{index:03}.txt")), b"x")
                .expect("large directory entry");
        }

        let empty = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?path=empty")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let empty = json(empty).await;
        assert_eq!(empty["entries"].as_array().unwrap().len(), 0);
        assert!(empty.get("nextCursor").is_none());

        let root = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?limit=100")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let root = json(root).await;
        let names = root["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(names.contains(&"équipe"));
        assert!(names.contains(&"東京.md"));
        let first_file = root["entries"]
            .as_array()
            .unwrap()
            .iter()
            .position(|entry| entry["kind"] == "file")
            .expect("file entry");
        assert!(
            root["entries"].as_array().unwrap()[..first_file]
                .iter()
                .all(|entry| entry["kind"] == "directory")
        );

        let first = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?path=large&limit=200")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let first = json(first).await;
        assert_eq!(first["entries"].as_array().unwrap().len(), 200);
        assert_eq!(first["entries"][0]["name"], "entry-000.txt");
        assert_eq!(first["entries"][199]["name"], "entry-199.txt");
        let cursor = first["nextCursor"].as_str().expect("large cursor");
        let second = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(format!(
                "/api/v1/shares/documents/directory?path=large&limit=200&cursor={cursor}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        let second = json(second).await;
        assert_eq!(second["entries"].as_array().unwrap().len(), 5);
        assert_eq!(second["entries"][4]["name"], "entry-204.txt");
    }

    #[tokio::test]
    async fn cursors_reject_tampering_cross_user_replay_and_directory_changes() {
        let fixture = fixture(BrowseLimits::default());
        let first = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let cursor = json(first).await["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();
        let mut tampered = cursor.clone().into_bytes();
        let final_byte = tampered.last_mut().expect("non-empty cursor");
        *final_byte = if *final_byte == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        let other = AuthenticatedIdentity::new("user-2", vec![fixture.grant.clone()]);
        let downgraded = AuthenticatedIdentity::new(
            "user-1",
            vec![ShareGrant {
                share_id: fixture.grant.share_id.clone(),
                access: AccessLevel::ReadOnly,
            }],
        );

        for (identity, cursor) in [
            (&fixture.identity, tampered.as_str()),
            (&other, cursor.as_str()),
            (&downgraded, cursor.as_str()),
        ] {
            let response = send(
                &fixture.app,
                Some(identity),
                Request::get(format!(
                    "/api/v1/shares/documents/directory?limit=1&cursor={cursor}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        fs::write(fixture._root.path().join("new.txt"), b"new").expect("directory mutation");
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(format!(
                "/api/v1/shares/documents/directory?limit=1&cursor={cursor}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn metadata_is_authorized_handle_based_and_change_sensitive() {
        let fixture = fixture(BrowseLimits::default());
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/metadata?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let header_etag = response.headers()[header::ETAG].clone();
        let value = json(response).await;
        assert_eq!(value["shareId"], "documents");
        assert_eq!(value["path"], "a.txt");
        assert_eq!(value["name"], "a.txt");
        assert_eq!(value["kind"], "file");
        assert_eq!(value["size"], 6);
        assert_eq!(value["etag"], header_etag.to_str().unwrap());
        assert!(value.get("modifiedAt").is_none());
        for timestamp in ["accessedAtMs", "createdAtMs"] {
            if let Some(timestamp) = value.get(timestamp) {
                assert!(timestamp.as_u64().is_some());
            }
        }

        let directory = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/metadata?path=a-directory")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let directory = json(directory).await;
        assert_eq!(directory["kind"], "directory");
        assert!(directory.get("size").is_none());

        let replacement = fixture._root.path().join("replacement.txt");
        fs::write(&replacement, b"replacement").expect("replacement file");
        fs::rename(&replacement, fixture._root.path().join("a.txt")).expect("atomic replacement");
        let changed = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/metadata?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let changed = json(changed).await;
        assert_ne!(changed["etag"], value["etag"]);

        let no_grant = AuthenticatedIdentity::new("user-2", vec![]);
        let denied = send(
            &fixture.app,
            Some(&no_grant),
            Request::get("/api/v1/shares/documents/metadata?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn text_reads_are_utf8_json_and_strictly_capped() {
        let fixture = fixture(BrowseLimits::default());
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/text?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-content-type-options"],
            HeaderValue::from_static("nosniff")
        );
        assert_eq!(json(response).await["text"], "abcdef");

        let invalid = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/text?path=invalid.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let limits = BrowseLimits {
            max_text_bytes: 5,
            ..BrowseLimits::default()
        };
        let capped = fixture_with_request(limits, "/api/v1/shares/documents/text?path=a.txt").await;
        assert_eq!(capped.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn downloads_support_ranges_and_conditional_requests() {
        let fixture = fixture(BrowseLimits::default());
        let full = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(full.headers()[header::CONTENT_LENGTH], "6");
        assert_eq!(full.headers()[header::ACCEPT_RANGES], "bytes");
        let etag = full.headers()[header::ETAG].clone();
        assert_eq!(
            to_bytes(full.into_body(), 64).await.unwrap().as_ref(),
            b"abcdef"
        );

        let partial = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=a.txt")
                .header(header::RANGE, "bytes=2-4")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.headers()[header::CONTENT_RANGE], "bytes 2-4/6");
        assert_eq!(partial.headers()[header::CONTENT_LENGTH], "3");
        assert_eq!(
            to_bytes(partial.into_body(), 64).await.unwrap().as_ref(),
            b"cde"
        );

        let not_modified = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=a.txt")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        let if_range = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=a.txt")
                .header(header::RANGE, "bytes=2-4")
                .header(header::IF_RANGE, "W/\"weak-validator\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(if_range.status(), StatusCode::OK);
        assert_eq!(if_range.headers()[header::CONTENT_LENGTH], "6");
        assert_eq!(
            to_bytes(if_range.into_body(), 64).await.unwrap().as_ref(),
            b"abcdef"
        );

        let invalid = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=a.txt")
                .header(header::RANGE, "bytes=99-100")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(invalid.headers()[header::CONTENT_RANGE], "bytes */6");
    }

    #[tokio::test]
    async fn empty_and_atomically_replaced_downloads_are_consistent() {
        let fixture = fixture(BrowseLimits::default());
        fs::write(fixture._root.path().join("empty.bin"), []).expect("empty file");
        let empty = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=empty.bin")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(empty.status(), StatusCode::OK);
        assert_eq!(empty.headers()[header::CONTENT_LENGTH], "0");
        assert!(to_bytes(empty.into_body(), 1).await.unwrap().is_empty());

        let empty_range = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=empty.bin")
                .header(header::RANGE, "bytes=0-")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(empty_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(empty_range.headers()[header::CONTENT_RANGE], "bytes */0");

        fs::write(fixture._root.path().join("changing.txt"), b"original").expect("original file");
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=changing.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        fs::write(fixture._root.path().join("replacement.txt"), b"new-data")
            .expect("replacement file");
        fs::rename(
            fixture._root.path().join("replacement.txt"),
            fixture._root.path().join("changing.txt"),
        )
        .expect("atomic replacement");
        assert_eq!(
            to_bytes(response.into_body(), 64).await.unwrap().as_ref(),
            b"original"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_a_download_body_closes_the_stream_file() {
        let fixture = fixture(BrowseLimits::default());
        let path = fixture._root.path().join("cancel.bin");
        fs::write(&path, vec![0x5a; 2 * 1024 * 1024]).expect("large file");
        assert_eq!(open_descriptors_for(&path), 0);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=cancel.bin")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(open_descriptors_for(&path), 1);
        drop(response);
        assert_eq!(open_descriptors_for(&path), 0);
    }

    #[cfg(target_os = "linux")]
    fn open_descriptors_for(path: &std::path::Path) -> usize {
        fs::read_dir("/proc/self/fd")
            .expect("process descriptors")
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .filter(|target| target == path)
            .count()
    }

    #[tokio::test]
    async fn raw_html_is_always_an_attachment_with_inert_headers() {
        let fixture = fixture(BrowseLimits::default());
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/download?path=page.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .starts_with("attachment;")
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; sandbox"
        );
    }

    #[tokio::test]
    async fn traversal_links_and_oversized_resources_fail_without_disclosure() {
        let fixture = fixture(BrowseLimits::default());
        let traversal = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/text?path=..%2Fsecret.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);

        #[cfg(unix)]
        {
            use std::{os::unix::fs::symlink, os::unix::net::UnixListener};
            let outside = TempDir::new().expect("outside");
            fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
            symlink(
                outside.path().join("secret.txt"),
                fixture._root.path().join("link.txt"),
            )
            .unwrap();
            let _socket =
                UnixListener::bind(fixture._root.path().join("socket")).expect("socket fixture");
            for uri in [
                "/api/v1/shares/documents/download?path=link.txt",
                "/api/v1/shares/documents/text?path=link.txt",
                "/api/v1/shares/documents/metadata?path=link.txt",
                "/api/v1/shares/documents/download?path=socket",
                "/api/v1/shares/documents/text?path=socket",
                "/api/v1/shares/documents/metadata?path=socket",
            ] {
                let response = send(
                    &fixture.app,
                    Some(&fixture.identity),
                    Request::get(uri).body(Body::empty()).unwrap(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            }
            let listing = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get("/api/v1/shares/documents/directory")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(listing.status(), StatusCode::OK);
        }

        let directory_limits = BrowseLimits {
            default_page_size: 1,
            max_page_size: 2,
            max_directory_entries: 2,
            ..BrowseLimits::default()
        };
        let too_many = fixture_with_request(
            directory_limits,
            "/api/v1/shares/documents/directory?limit=1",
        )
        .await;
        assert_eq!(too_many.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let download_limits = BrowseLimits {
            max_download_bytes: 5,
            ..BrowseLimits::default()
        };
        let too_large = fixture_with_request(
            download_limits,
            "/api/v1/shares/documents/download?path=a.txt",
        )
        .await;
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    async fn fixture_with_request(limits: BrowseLimits, uri: &str) -> Response {
        let fixture = fixture(limits);
        send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(uri).body(Body::empty()).unwrap(),
        )
        .await
    }

    #[test]
    fn byte_range_parser_accepts_single_standard_forms_only() {
        assert_eq!(
            parse_range(&HeaderValue::from_static("bytes=2-4"), 6),
            Some((2, 4))
        );
        assert_eq!(
            parse_range(&HeaderValue::from_static("bytes=2-"), 6),
            Some((2, 5))
        );
        assert_eq!(
            parse_range(&HeaderValue::from_static("bytes=-2"), 6),
            Some((4, 5))
        );
        assert_eq!(
            parse_range(&HeaderValue::from_static("bytes=2-99"), 6),
            Some((2, 5))
        );
        for invalid in [
            "bytes=6-",
            "bytes=4-2",
            "bytes=0-1,3-4",
            "items=0-1",
            "bytes=-0",
        ] {
            assert_eq!(
                parse_range(&HeaderValue::from_str(invalid).unwrap(), 6),
                None
            );
        }
    }

    proptest! {
        #[test]
        fn download_filenames_always_produce_header_safe_content_disposition(
            candidate in any::<String>()
        ) {
            if let Ok(name) = EntryName::new(candidate) {
                let value = content_disposition(name.as_str()).expect("valid header");
                let rendered = value.to_str().expect("ASCII header value");
                prop_assert!(rendered.starts_with("attachment; filename=\""));
                prop_assert!(rendered.contains("; filename*=UTF-8''"));
                prop_assert!(!rendered.contains(['\r', '\n']));
            }
        }
    }

    #[test]
    fn state_rejects_zero_secrets_and_inconsistent_limits() {
        assert!(matches!(
            BrowseState::new(
                vec![],
                BrowseLimits::default(),
                GlobalPolicy::default(),
                [0; 32],
            ),
            Err(BrowseStateError::InvalidCursorKey)
        ));
        assert!(matches!(
            BrowseState::new(
                vec![],
                BrowseLimits {
                    default_page_size: 201,
                    ..BrowseLimits::default()
                },
                GlobalPolicy::default(),
                [1; 32],
            ),
            Err(BrowseStateError::InvalidLimits)
        ));
    }
}
#[test]
fn directory_event_connections_are_bounded_and_released() {
    let gate = DirectoryEventGate::new(2, 1);
    let alice = gate.try_acquire("alice").expect("first user lease");
    assert!(matches!(
        gate.try_acquire("alice"),
        Err(AppError::TooManyRequests)
    ));
    let bob = gate.try_acquire("bob").expect("second process lease");
    assert!(matches!(
        gate.try_acquire("charlie"),
        Err(AppError::TooManyRequests)
    ));
    drop(alice);
    let alice = gate.try_acquire("alice").expect("released user lease");
    drop((alice, bob));
    assert!(gate.try_acquire("charlie").is_ok());
}

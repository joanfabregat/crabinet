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
    extract::{FromRequestParts, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{StreamExt as _, stream};
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
    auth::AuthService,
    error::AppError,
    extract::{ApiPath, ApiQuery},
    filesystem::{
        AccessLevel, ArchiveLimits, AuthorizedShare, DirectoryEntry, EntryKind, EntryMetadata,
        FsError, FsErrorCode, GlobalPolicy, OwnedAuthorizedShare, ShareFs, ShareGrant, ShareId,
        VirtualPath,
    },
    zip::{Crc32, ZipPlan, ZipSource},
};

type HmacSha256 = Hmac<Sha256>;
const CURSOR_VERSION: u8 = 1;
const CURSOR_BYTES: usize = 1 + 8 + 32 + 32;
const MAX_EVENT_CONNECTIONS: usize = 64;
const MAX_EVENT_CONNECTIONS_PER_SUBJECT: usize = 4;
/// Event streams end after this lifetime so the browser reconnects through
/// the authentication middleware, which re-validates the session and grants.
const EVENT_STREAM_LIFETIME: Duration = Duration::from_secs(60);
/// Reconnect delay hint sent to `EventSource` clients.
const EVENT_STREAM_RETRY: Duration = Duration::from_secs(1);
/// How often an open event stream re-checks its session, matching the
/// keep-alive interval, so a sign-out or revocation ends it within this time
/// instead of at [`EVENT_STREAM_LIFETIME`].
#[cfg(not(test))]
const EVENT_SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(15);
#[cfg(test)]
const EVENT_SESSION_CHECK_INTERVAL: Duration = Duration::from_millis(250);
/// Concurrent requests that buffer a whole file in memory (text reads and
/// previews). Each can hold several copies of up to the 16 MiB preview cap.
const MAX_CONCURRENT_BUFFERED_READS: usize = 4;
/// Buffered reads per authenticated subject, so one user cannot hold every
/// buffered-read slot.
const MAX_CONCURRENT_BUFFERED_READS_PER_SUBJECT: usize = 2;
/// Concurrent directory scans, each of up to `max_directory_entries` stats.
const MAX_CONCURRENT_LISTINGS: usize = 16;
/// Directory and trash scans per authenticated subject.
const MAX_CONCURRENT_LISTINGS_PER_SUBJECT: usize = 8;
/// Request-path filesystem work that no dedicated gate already bounds:
/// metadata lookups and the pre-commit stat of a move or delete. Each holds a Tokio blocking-pool thread (512 by default) while
/// a slow disk or network filesystem answers, so this cap keeps such requests
/// from occupying the pool. Session lookups are deliberately not counted, so
/// signing in and out stays available while it is saturated.
const MAX_CONCURRENT_BLOCKING_REQUESTS: usize = 64;
/// Ungated blocking requests per authenticated subject.
const MAX_CONCURRENT_BLOCKING_REQUESTS_PER_SUBJECT: usize = 16;
/// Concurrent streaming downloads across the process, counting streamed
/// image previews and inline opens. Each holds an open file descriptor
/// until its response body completes or is dropped.
const MAX_CONCURRENT_DOWNLOADS: usize = 64;
/// Concurrent streaming downloads per authenticated subject: enough for a few
/// parallel downloads plus a media player's overlapping range requests, while
/// one user cannot hold every process slot.
pub(crate) const MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT: usize = 8;
/// Concurrent folder archives across the process. Each keeps its walk, at
/// most `max_archive_entries` entries and [`MAX_ARCHIVE_NAME_BYTES`] of
/// names, in memory until its response body completes or is dropped.
const MAX_CONCURRENT_ARCHIVES: usize = 4;
/// Folder archives per authenticated subject.
const MAX_CONCURRENT_ARCHIVES_PER_SUBJECT: usize = 2;
/// Total length of the relative paths in one folder archive. While its
/// layout is built, an archive holds these names twice, the second copy
/// prefixed with the folder name (at most 256 bytes per entry), so with
/// [`MAX_CONCURRENT_ARCHIVES`] name memory peaks at about 42 MiB.
const MAX_ARCHIVE_NAME_BYTES: usize = 4 * 1024 * 1024;

/// Runs synchronous filesystem work on Tokio's blocking pool so slow disks
/// or network filesystems never stall the async worker threads.
pub(crate) async fn run_blocking<T, F>(work: F) -> Result<T, AppError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| AppError::Internal)
}

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
    /// Largest single-file download, and largest sum of file sizes in one
    /// folder archive.
    pub max_download_bytes: u64,
    /// Directory entries one folder archive may scan, including omitted ones.
    pub max_archive_entries: usize,
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
            max_archive_entries: 10_000,
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
    filesystem: Arc<ShareFs>,
}

impl ConfiguredShare {
    pub fn new(name: impl Into<Arc<str>>, filesystem: ShareFs) -> Result<Self, BrowseStateError> {
        let name = name.into();
        if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(BrowseStateError::InvalidDisplayName);
        }
        Ok(Self {
            name,
            filesystem: Arc::new(filesystem),
        })
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
    event_gate: SubjectGate,
    download_gate: SubjectGate,
    archive_gate: SubjectGate,
    buffered_read_gate: SubjectGate,
    listing_gate: SubjectGate,
    blocking_gate: SubjectGate,
}

/// A process-wide concurrency cap combined with a per-subject cap, so one
/// authenticated user cannot take every process slot.
pub(crate) struct SubjectGate {
    process: Arc<Semaphore>,
    subjects: Arc<Mutex<HashMap<Arc<str>, usize>>>,
    per_subject: usize,
}

/// Names the gates of [`BrowseState`] for tests that hold them directly.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BrowseGate {
    Events,
    Downloads,
    Archives,
    BufferedReads,
    Listings,
    Blocking,
}

pub(crate) struct SubjectLease {
    _process: OwnedSemaphorePermit,
    subject: Arc<str>,
    subjects: Arc<Mutex<HashMap<Arc<str>, usize>>>,
}

impl SubjectGate {
    pub(crate) fn new(process: usize, per_subject: usize) -> Self {
        Self {
            process: Arc::new(Semaphore::new(process)),
            subjects: Arc::new(Mutex::new(HashMap::new())),
            per_subject,
        }
    }

    /// Returns `None` when either the process or the subject cap is reached.
    pub(crate) fn try_acquire(&self, subject: &str) -> Option<SubjectLease> {
        let process = self.process.clone().try_acquire_owned().ok()?;
        let subject: Arc<str> = Arc::from(subject);
        let mut subjects = self.subjects.lock().ok()?;
        let active = subjects.entry(subject.clone()).or_default();
        if *active >= self.per_subject {
            return None;
        }
        *active += 1;
        drop(subjects);
        Some(SubjectLease {
            _process: process,
            subject,
            subjects: self.subjects.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn process_semaphore(&self) -> &Arc<Semaphore> {
        &self.process
    }
}

impl Drop for SubjectLease {
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
    pub fn trash_gc_targets(&self) -> Vec<(ShareId, Arc<ShareFs>)> {
        self.shares
            .iter()
            .map(|(id, share)| (id.clone(), Arc::clone(&share.filesystem)))
            .collect()
    }

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
            || limits.max_archive_entries == 0
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
        Ok(Self::with_gates(by_id, limits, policy, cursor_key))
    }

    pub(crate) fn disabled() -> Self {
        Self::with_gates(
            HashMap::new(),
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [0; 32],
        )
    }

    fn with_gates(
        shares: HashMap<ShareId, Arc<ConfiguredShare>>,
        limits: BrowseLimits,
        policy: GlobalPolicy,
        cursor_key: [u8; 32],
    ) -> Self {
        Self {
            shares,
            limits,
            policy,
            cursor_key,
            event_gate: SubjectGate::new(MAX_EVENT_CONNECTIONS, MAX_EVENT_CONNECTIONS_PER_SUBJECT),
            download_gate: SubjectGate::new(
                MAX_CONCURRENT_DOWNLOADS,
                MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT,
            ),
            archive_gate: SubjectGate::new(
                MAX_CONCURRENT_ARCHIVES,
                MAX_CONCURRENT_ARCHIVES_PER_SUBJECT,
            ),
            buffered_read_gate: SubjectGate::new(
                MAX_CONCURRENT_BUFFERED_READS,
                MAX_CONCURRENT_BUFFERED_READS_PER_SUBJECT,
            ),
            listing_gate: SubjectGate::new(
                MAX_CONCURRENT_LISTINGS,
                MAX_CONCURRENT_LISTINGS_PER_SUBJECT,
            ),
            blocking_gate: SubjectGate::new(
                MAX_CONCURRENT_BLOCKING_REQUESTS,
                MAX_CONCURRENT_BLOCKING_REQUESTS_PER_SUBJECT,
            ),
        }
    }

    /// Owned variant of [`Self::authorize`] for work moved to the blocking
    /// pool. The grant check is identical and runs for every request.
    pub(crate) fn authorize_owned(
        &self,
        identity: &AuthenticatedIdentity,
        share_id: &ShareId,
    ) -> Result<OwnedAuthorizedShare, AppError> {
        let share = self.shares.get(share_id).ok_or(AppError::NotFound)?;
        share
            .filesystem
            .authorize_owned(identity.grant_for(share_id), self.policy)
            .map_err(non_disclosing_fs_error)
    }

    fn authorized_owned(
        &self,
        identity: &AuthenticatedIdentity,
        raw_share_id: &str,
    ) -> Result<OwnedAuthorizedShare, AppError> {
        let share_id = ShareId::new(raw_share_id.to_owned()).map_err(|_| AppError::NotFound)?;
        self.authorize_owned(identity, &share_id)
    }

    /// Admits one request that buffers a complete file in memory.
    pub(crate) fn acquire_buffered_read(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<SubjectLease, AppError> {
        self.buffered_read_gate
            .try_acquire(identity.subject())
            .ok_or(AppError::Busy)
    }

    /// Admits one request-path blocking filesystem call that no dedicated
    /// gate bounds. The lease must move into the blocking closure so a
    /// cancelled request cannot release it while the work still runs.
    pub(crate) fn acquire_blocking(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<SubjectLease, AppError> {
        self.blocking_gate
            .try_acquire(identity.subject())
            .ok_or(AppError::Busy)
    }

    /// Admits one streaming download. The lease must travel with the response
    /// body so the slot is released only when the stream ends or is dropped.
    pub(crate) fn acquire_download(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<SubjectLease, AppError> {
        self.download_gate
            .try_acquire(identity.subject())
            .ok_or(AppError::Busy)
    }

    /// Admits one folder archive, from its walk to the end of its stream.
    fn acquire_archive(&self, identity: &AuthenticatedIdentity) -> Result<SubjectLease, AppError> {
        self.archive_gate
            .try_acquire(identity.subject())
            .ok_or(AppError::Busy)
    }

    /// Admits one directory or trash scan.
    pub(crate) fn acquire_listing(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<SubjectLease, AppError> {
        self.listing_gate
            .try_acquire(identity.subject())
            .ok_or(AppError::Busy)
    }

    #[cfg(test)]
    pub(crate) fn buffered_read_gate(&self) -> &Arc<Semaphore> {
        self.buffered_read_gate.process_semaphore()
    }

    #[cfg(test)]
    pub(crate) fn listing_gate(&self) -> &Arc<Semaphore> {
        self.listing_gate.process_semaphore()
    }

    #[cfg(test)]
    pub(crate) fn blocking_gate(&self) -> &Arc<Semaphore> {
        self.blocking_gate.process_semaphore()
    }

    /// Each gate this state owns, for the route-level resource registry.
    #[cfg(test)]
    pub(crate) fn subject_gate(&self, gate: BrowseGate) -> &SubjectGate {
        match gate {
            BrowseGate::Events => &self.event_gate,
            BrowseGate::Downloads => &self.download_gate,
            BrowseGate::Archives => &self.archive_gate,
            BrowseGate::BufferedReads => &self.buffered_read_gate,
            BrowseGate::Listings => &self.listing_gate,
            BrowseGate::Blocking => &self.blocking_gate,
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
    ) -> Result<SubjectLease, AppError> {
        self.event_gate
            .try_acquire(identity.subject())
            .ok_or(AppError::TooManyRequests)
    }

    /// The HMAC key for opaque cursors. Other cursor formats must frame a
    /// distinct domain label first so they never verify as directory cursors.
    pub(crate) fn cursor_key(&self) -> &[u8; 32] {
        &self.cursor_key
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

    /// The validator downloads and inline opens send for an opened file.
    #[must_use]
    pub(crate) fn file_etag(
        &self,
        share_id: &ShareId,
        path: &VirtualPath,
        len: u64,
        modified: Option<SystemTime>,
        file_id: u64,
    ) -> String {
        metadata_etag(
            &self.cursor_key,
            share_id,
            path,
            len,
            modified,
            file_id,
            EntryKind::File,
        )
    }

    /// Streamed responses share the download size cap and chunk size.
    #[must_use]
    pub(crate) const fn max_download_bytes(&self) -> u64 {
        self.limits.max_download_bytes
    }

    #[must_use]
    pub(crate) const fn stream_chunk_bytes(&self) -> usize {
        self.limits.stream_chunk_bytes
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
        .route("/shares/{share_id}/archive", get(download_archive))
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
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_at_ms: Option<u64>,
}

async fn list_directory(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<DirectoryQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let authorized = browse.authorized_owned(&identity, &raw_share_id)?;
    let share_id = authorized.share_id().clone();
    let access = authorized.access();
    let path = parse_query_path(query.path.as_deref())?;
    let limit = query.limit.unwrap_or(browse.limits.default_page_size);
    if limit == 0 || limit > browse.limits.max_page_size {
        return Err(AppError::InvalidRequest);
    }

    let permit = browse.acquire_listing(&identity)?;
    let max_entries = browse.limits.max_directory_entries;
    let listing_path = path.clone();
    let mut entries = run_blocking(move || {
        let _permit = permit;
        authorized.view().list_bounded(&listing_path, max_entries)
    })
    .await?
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
            &share_id,
            &path,
            access,
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
            &share_id,
            &path,
            access,
            end,
            &fingerprint,
        )
    });
    let entries = entries[offset..end].iter().map(entry_response).collect();

    Ok(inert_json(DirectoryPage {
        share_id: share_id.as_str().to_owned(),
        path: path.to_string(),
        entries,
        next_cursor,
    }))
}

struct EventStreamState {
    watcher: rustix::fd::OwnedFd,
    deadline: Instant,
    /// Held for the life of the stream to keep its event-connection slot.
    _lease: SubjectLease,
    session: Option<SessionCheck>,
}

struct SessionCheck {
    auth: AuthService,
    cookies: HeaderMap,
    next_check: Instant,
}

/// Sends event-driven invalidation hints for one explicitly selected
/// directory. Authorization is checked when the stream opens, so each
/// connection is bounded to [`EVENT_STREAM_LIFETIME`]; browsers then
/// reconnect through authentication middleware, which re-validates the
/// session and grants. Grants are immutable configuration, so in between the
/// stream only re-checks that its session is still valid, every
/// [`EVENT_SESSION_CHECK_INTERVAL`], and ends once it is signed out, expired,
/// or revoked. No directory contents are scanned by the event stream.
async fn directory_events(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<DirectoryQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let path = parse_query_path(query.path.as_deref())?;
    let authorized = state.browse().authorize_owned(&identity, &share_id)?;
    let lease = state.browse().acquire_event_connection(&identity)?;
    let watcher = run_blocking(move || authorized.view().watch_directory(&path))
        .await?
        .map_err(map_fs_error)?;
    let now = Instant::now();
    // Only the session cookie is retained for the periodic re-check. Without
    // an authentication service (isolated handler tests), there is no
    // session to re-check.
    let session = state.auth().cloned().map(|auth| {
        let mut cookies = HeaderMap::new();
        for value in headers.get_all(header::COOKIE) {
            cookies.append(header::COOKIE, value.clone());
        }
        SessionCheck {
            auth,
            cookies,
            next_check: now + EVENT_SESSION_CHECK_INTERVAL,
        }
    });
    let stream_state = EventStreamState {
        watcher,
        deadline: now + EVENT_STREAM_LIFETIME,
        _lease: lease,
        session,
    };

    // A retry-only event sets the browser's reconnect delay without
    // dispatching anything to the page.
    let retry_hint =
        stream::once(async { Ok::<Event, Infallible>(Event::default().retry(EVENT_STREAM_RETRY)) });
    let events = stream::unfold(stream_state, |mut stream_state| async move {
        loop {
            if Instant::now() >= stream_state.deadline {
                return None;
            }
            sleep(Duration::from_millis(250)).await;
            if let Some(session) = stream_state.session.as_mut()
                && Instant::now() >= session.next_check
            {
                if !session.auth.session_is_active(&session.cookies).await {
                    return None;
                }
                session.next_check = Instant::now() + EVENT_SESSION_CHECK_INTERVAL;
            }
            let mut buffer = [MaybeUninit::uninit(); 4096];
            match rustix::fs::inotify::Reader::new(&stream_state.watcher, &mut buffer).next() {
                Ok(_) => {
                    return Some((
                        Ok::<Event, Infallible>(Event::default().event("invalidate").data("{}")),
                        stream_state,
                    ));
                }
                Err(rustix::io::Errno::AGAIN) => {}
                Err(_) => {
                    stream_state.deadline = Instant::now();
                    return Some((
                        Ok::<Event, Infallible>(Event::default().event("resync").data("{}")),
                        stream_state,
                    ));
                }
            }
        }
    });

    let mut response = Sse::new(retry_hint.chain(events))
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
    modified_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessed_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at_ms: Option<u64>,
    etag: String,
}

async fn read_metadata(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<FileQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let authorized = browse.authorized_owned(&identity, &raw_share_id)?;
    let share_id = authorized.share_id().clone();
    let path = VirtualPath::parse(&query.path).map_err(map_fs_error)?;
    let metadata_path = path.clone();
    let lease = browse.acquire_blocking(&identity)?;
    let metadata = run_blocking(move || {
        let _lease = lease;
        authorized.view().metadata(&metadata_path)
    })
    .await?
    .map_err(map_fs_error)?;
    let name = path
        .components()
        .last()
        .ok_or(AppError::InvalidRequest)?
        .as_str();
    let etag = entry_etag(&browse.cursor_key, &share_id, &path, metadata);
    let mut response = inert_json(MetadataResponse {
        share_id: share_id.as_str().to_owned(),
        path: path.to_string(),
        name: name.to_owned(),
        kind: kind_name(metadata.kind),
        size: (metadata.kind == EntryKind::File).then_some(metadata.size),
        modified_at_ms: system_time_millis(metadata.modified),
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
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<FileQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let authorized = browse.authorized_owned(&identity, &raw_share_id)?;
    let share_id = authorized.share_id().clone();
    let path = VirtualPath::parse(&query.path).map_err(map_fs_error)?;
    // The permit travels with the blocking read, so a cancelled request cannot
    // release it early, and is held until the response body is built.
    let permit = browse.acquire_buffered_read(&identity)?;
    let max_bytes = browse.limits.max_text_bytes;
    let read_path = path.clone();
    let (bytes, _permit) =
        run_blocking(move || (authorized.view().read_file(&read_path, max_bytes), permit)).await?;
    let bytes = bytes.map_err(map_fs_error)?;
    let size = bytes.len() as u64;
    let text = String::from_utf8(bytes).map_err(|_| AppError::UnsupportedMedia)?;
    let mime_type = mime_for_path(&path);
    let etag = content_etag(text.as_bytes());
    let mut response = Json(TextResponse {
        share_id: share_id.as_str().to_owned(),
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
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<FileQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let authorized = browse.authorized_owned(&identity, &raw_share_id)?;
    let share_id = authorized.share_id().clone();
    let path = VirtualPath::parse(&query.path).map_err(map_fs_error)?;
    // Taken before the file is opened so a rejected request never holds a
    // descriptor; the lease moves into the body stream below.
    let lease = browse.acquire_download(&identity)?;
    let open_path = path.clone();
    let opened = run_blocking(move || authorized.view().open_file(&open_path))
        .await?
        .map_err(map_fs_error)?;
    let total_len = opened.len();
    if total_len > browse.limits.max_download_bytes {
        return Err(AppError::TooLarge);
    }
    let etag = browse.file_etag(
        &share_id,
        &path,
        total_len,
        opened.modified(),
        opened.file_id(),
    );
    let mime = download_mime(mime_for_path(&path));
    let filename = path
        .components()
        .last()
        .ok_or(AppError::InvalidRequest)?
        .as_str();
    let file = StreamedFile {
        file: opened.into_std(),
        total_len,
        etag,
    };
    stream_file(
        &headers,
        file,
        browse.limits.stream_chunk_bytes,
        lease,
        |response_headers| add_file_headers(response_headers, &mime, filename),
    )
    .await
}

/// A validated regular-file handle and its validator, ready for
/// [`stream_file`].
pub(crate) struct StreamedFile {
    pub(crate) file: std::fs::File,
    pub(crate) total_len: u64,
    pub(crate) etag: String,
}

/// Streams an already-opened, already-validated file with the conditional
/// (`If-None-Match`, `If-Range`) and single-range handling downloads use.
///
/// `representation` adds the route's own type, disposition, and security
/// headers to `200`, `206`, and `304` responses; this function adds `ETag`,
/// `Accept-Ranges`, `Content-Length`, and `Content-Range`. A `416` carries
/// only the inert JSON error headers. The lease travels with the body
/// stream, so the slot is released only when the body completes or is
/// dropped.
pub(crate) async fn stream_file(
    request_headers: &HeaderMap,
    file: StreamedFile,
    chunk_bytes: usize,
    lease: SubjectLease,
    representation: impl FnOnce(&mut HeaderMap) -> Result<(), AppError>,
) -> Result<Response, AppError> {
    let StreamedFile {
        file,
        total_len,
        etag,
    } = file;
    if if_none_match(request_headers.get(header::IF_NONE_MATCH), &etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        representation(response.headers_mut())?;
        add_validator_headers(response.headers_mut(), &etag)?;
        return Ok(response);
    }

    let requested_range = if if_range_allows(request_headers.get(header::IF_RANGE), &etag) {
        match request_headers
            .get(header::RANGE)
            .map(|value| parse_range(value, total_len))
        {
            Some(RangeRequest::Satisfiable(start, end)) => Some((start, end)),
            Some(RangeRequest::Unsatisfiable) => return range_not_satisfiable(total_len),
            // RFC 9110 section 14.2: an invalid or unsupported (including
            // multi-range) header is ignored and the full content is sent.
            Some(RangeRequest::Ignore) | None => None,
        }
    } else {
        None
    };

    let (status, start, response_len) = match requested_range {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        None => (StatusCode::OK, 0, total_len),
    };
    let mut file = tokio::fs::File::from_std(file);
    // Always seek: the caller may have read a signature header first.
    file.seek(SeekFrom::Start(start))
        .await
        .map_err(|_| AppError::Internal)?;
    let stream =
        ReaderStream::with_capacity(file.take(response_len), chunk_bytes).map(move |chunk| {
            // The stream owns the lease, so the download slot is released
            // with the file handle when the body completes or is dropped.
            let _lease = &lease;
            chunk
        });
    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(stream))
        .map_err(|_| AppError::Internal)?;
    representation(response.headers_mut())?;
    add_validator_headers(response.headers_mut(), &etag)?;
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

#[derive(Debug, Deserialize)]
struct ArchiveQuery {
    path: Option<String>,
}

/// Streams a folder as a store-only ZIP archive. The whole folder is walked
/// and checked against the archive limits before the response starts, so a
/// refusal is an ordinary error response and an admitted archive carries its
/// exact `Content-Length`. If the folder changes while it streams, the body
/// ends with an error, so the client sees a failed transfer rather than a
/// complete-looking archive.
async fn download_archive(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<ArchiveQuery>,
) -> Result<Response, AppError> {
    let browse = state.browse();
    let authorized = browse.authorized_owned(&identity, &raw_share_id)?;
    let folder = parse_query_path(query.path.as_deref())?;
    // The lease travels into the walk and then the body stream, so the slot
    // is released only when the archive is complete or dropped.
    let lease = Arc::new(browse.acquire_archive(&identity)?);
    let limits = ArchiveLimits {
        max_entries: browse.limits.max_archive_entries,
        max_bytes: browse.limits.max_download_bytes,
        max_name_bytes: MAX_ARCHIVE_NAME_BYTES,
    };
    let walk_share = authorized.clone();
    let walk_folder = folder.clone();
    let walk_lease = Arc::clone(&lease);
    let tree = run_blocking(move || {
        let _lease = walk_lease;
        walk_share.view().archive_items(&walk_folder, limits)
    })
    .await?
    .map_err(map_fs_error)?;

    let root_name = folder
        .file_name()
        .map_or_else(|| authorized.share_id().as_str(), |name| name.as_str())
        .to_owned();
    let mut sources = Vec::with_capacity(tree.items.len() + 1);
    sources.push(ZipSource {
        name: root_name.clone(),
        size: None,
        modified: tree.modified,
    });
    sources.extend(tree.items.into_iter().map(|item| ZipSource {
        name: format!("{root_name}/{}", item.relative),
        size: (item.kind == EntryKind::File).then_some(item.size),
        modified: item.modified,
    }));
    let plan = ZipPlan::new(sources).ok_or(AppError::TooLarge)?;
    let content_length = plan.len();
    let archive = ArchiveStream {
        share: authorized,
        folder,
        prefix_len: root_name.len() + 1,
        plan,
        state: ArchiveState::Entry(0),
        sent: 0,
        chunk_bytes: browse.limits.stream_chunk_bytes,
        lease,
    };
    let stream = stream::try_unfold(archive, |mut archive| async move {
        match archive.next_chunk().await {
            Ok(chunk) => Ok(chunk.map(|chunk| (chunk, archive))),
            Err(error) => {
                tracing::warn!(
                    share_id = archive.share.share_id().as_str(),
                    "folder archive aborted while streaming"
                );
                Err(error)
            }
        }
    });
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from_stream(stream))
        .map_err(|_| AppError::Internal)?;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(&format!("{root_name}.zip"))?,
    );
    headers.insert(
        header::CONTENT_LENGTH,
        header_value(&content_length.to_string())?,
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    add_inert_headers(headers);
    Ok(response)
}

/// The position of an [`ArchiveStream`] in its archive.
enum ArchiveState {
    /// The local header of this entry is next.
    Entry(usize),
    /// Streaming a file's bytes.
    File {
        index: usize,
        file: tokio::fs::File,
        remaining: u64,
        crc: Crc32,
    },
    /// The central directory header of this entry is next.
    Central(usize),
    Done,
}

/// Produces a planned archive chunk by chunk, opening one file at a time.
/// Dropping it closes the open file and releases the archive slot.
struct ArchiveStream {
    share: OwnedAuthorizedShare,
    folder: VirtualPath,
    /// Length of the archive's root name and its slash, stripped from an
    /// entry name to recover the entry's path relative to `folder`.
    prefix_len: usize,
    plan: ZipPlan,
    state: ArchiveState,
    sent: u64,
    chunk_bytes: usize,
    lease: Arc<SubjectLease>,
}

impl ArchiveStream {
    /// Returns the next chunk of about `chunk_bytes`, or `None` once the
    /// whole planned length has been produced.
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut out = Vec::with_capacity(self.chunk_bytes);
        while out.len() < self.chunk_bytes {
            match std::mem::replace(&mut self.state, ArchiveState::Done) {
                ArchiveState::Entry(index) if index == self.plan.entry_count() => {
                    self.state = ArchiveState::Central(0);
                }
                ArchiveState::Entry(index) => {
                    self.plan.write_local_header(index, &mut out);
                    self.state = match self.plan.entry_size(index) {
                        None => ArchiveState::Entry(index + 1),
                        Some(size) => ArchiveState::File {
                            index,
                            file: self.open(index, size).await?,
                            remaining: size,
                            crc: Crc32::new(),
                        },
                    };
                }
                ArchiveState::File {
                    index,
                    crc,
                    remaining: 0,
                    file,
                } => {
                    // A file that grew past its planned size has changed.
                    let mut probe = file.take(1);
                    if probe.read(&mut [0]).await? != 0 {
                        return Err(archive_changed());
                    }
                    self.plan
                        .write_data_descriptor(index, crc.finish(), &mut out);
                    self.state = ArchiveState::Entry(index + 1);
                }
                ArchiveState::File {
                    index,
                    mut file,
                    remaining,
                    mut crc,
                } => {
                    let start = out.len();
                    let wanted = u64::try_from(self.chunk_bytes - start)
                        .unwrap_or(u64::MAX)
                        .min(remaining);
                    out.resize(start + wanted as usize, 0);
                    let read = file.read(&mut out[start..]).await?;
                    out.truncate(start + read);
                    if read == 0 {
                        return Err(archive_changed());
                    }
                    crc.update(&out[start..]);
                    self.state = ArchiveState::File {
                        index,
                        file,
                        remaining: remaining - read as u64,
                        crc,
                    };
                }
                ArchiveState::Central(index) if index == self.plan.entry_count() => {
                    self.plan.write_end(&mut out);
                }
                ArchiveState::Central(index) => {
                    self.plan.write_central_header(index, &mut out);
                    self.state = ArchiveState::Central(index + 1);
                }
                ArchiveState::Done => break,
            }
        }
        self.sent += out.len() as u64;
        if self.sent > self.plan.len() || (out.is_empty() && self.sent != self.plan.len()) {
            return Err(std::io::Error::other(
                "archive length differs from its plan",
            ));
        }
        Ok((!out.is_empty()).then_some(out))
    }

    /// Reopens file entry `index` through the share capability, exactly as a
    /// single-file download would, and checks it still has its planned size.
    async fn open(&self, index: usize, size: u64) -> std::io::Result<tokio::fs::File> {
        let relative = &self.plan.entry_name(index)[self.prefix_len..];
        let path = if self.folder.is_root() {
            VirtualPath::parse(relative)
        } else {
            VirtualPath::parse(&format!("{}/{relative}", self.folder))
        }
        .map_err(|_| archive_changed())?;
        let share = self.share.clone();
        let lease = Arc::clone(&self.lease);
        let opened = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            share.view().open_file(&path)
        })
        .await
        .map_err(std::io::Error::other)?
        .map_err(|_| archive_changed())?;
        if opened.len() != size {
            return Err(archive_changed());
        }
        Ok(tokio::fs::File::from_std(opened.into_std()))
    }
}

fn archive_changed() -> std::io::Error {
    std::io::Error::other("an archived entry changed while streaming")
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
        modified_at_ms: system_time_millis(entry.modified),
    }
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Directory => "directory",
        EntryKind::File => "file",
    }
}

/// Fingerprints only the page structure: entry kind, name, and identity.
/// Size and modification time are deliberately excluded so a file being
/// written does not invalidate every later page of its directory.
fn listing_fingerprint(entries: &[DirectoryEntry]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hash.update([entry_kind_order(entry.kind)]);
        hash.update((entry.name.as_str().len() as u64).to_be_bytes());
        hash.update(entry.name.as_str().as_bytes());
        hash.update(entry.file_id.to_be_bytes());
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

pub(crate) fn if_none_match(value: Option<&HeaderValue>, etag: &str) -> bool {
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

#[derive(Debug, Eq, PartialEq)]
enum RangeRequest {
    /// Syntactically invalid, multi-range, or another unit: serve `200`.
    Ignore,
    /// Valid but outside the representation: serve `416`.
    Unsatisfiable,
    /// One inclusive byte range within the representation.
    Satisfiable(u64, u64),
}

fn parse_range(value: &HeaderValue, total_len: u64) -> RangeRequest {
    let Some(spec) = value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("bytes="))
    else {
        return RangeRequest::Ignore;
    };
    // Multiple ranges are unsupported; RFC 9110 permits ignoring the header.
    let Some((start, end)) = spec.split_once('-').filter(|_| !spec.contains(',')) else {
        return RangeRequest::Ignore;
    };
    if start.is_empty() {
        let Some(suffix) = parse_range_number(end) else {
            return RangeRequest::Ignore;
        };
        if suffix == 0 {
            return RangeRequest::Unsatisfiable;
        }
        if total_len == 0 {
            // A non-zero suffix of an empty representation is the whole,
            // empty representation.
            return RangeRequest::Ignore;
        }
        let length = suffix.min(total_len);
        return RangeRequest::Satisfiable(total_len - length, total_len - 1);
    }
    let Some(start) = parse_range_number(start) else {
        return RangeRequest::Ignore;
    };
    let end = if end.is_empty() {
        None
    } else {
        match parse_range_number(end) {
            Some(end) if end >= start => Some(end),
            _ => return RangeRequest::Ignore,
        }
    };
    if start >= total_len {
        return RangeRequest::Unsatisfiable;
    }
    RangeRequest::Satisfiable(
        start,
        end.map_or(total_len - 1, |end| end.min(total_len - 1)),
    )
}

/// `1*DIGIT` only: `u64::from_str` would also accept a leading `+`.
fn parse_range_number(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn mime_for_path(path: &VirtualPath) -> String {
    mime_guess::from_path(path.to_string())
        .first_or_octet_stream()
        .to_string()
}

/// Downloads never carry a type a browser would run or apply as a
/// subresource. `Content-Disposition: attachment` does not stop
/// `<script src>` or `<link rel=stylesheet>` from loading a same-origin
/// download, so with `nosniff` this keeps `script-src 'self'` and
/// `style-src 'self'` from covering user files.
fn download_mime(mime: String) -> String {
    let essence = mime
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let executable = ["javascript", "ecmascript", "jscript", "livescript"]
        .iter()
        .any(|name| essence.contains(name))
        || essence == "text/css"
        || essence == "application/wasm";
    if executable {
        "application/octet-stream".to_owned()
    } else {
        mime
    }
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
    // `no-store` keeps authenticated bodies out of the browser disk cache
    // after logout. ETags still support explicit conditional requests.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
}

fn inert_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    add_inert_headers(response.headers_mut());
    response
}

fn add_validator_headers(headers: &mut HeaderMap, etag: &str) -> Result<(), AppError> {
    headers.insert(header::ETAG, header_value(etag)?);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    Ok(())
}

fn add_file_headers(headers: &mut HeaderMap, mime: &str, filename: &str) -> Result<(), AppError> {
    headers.insert(header::CONTENT_TYPE, header_value(mime)?);
    headers.insert(header::CONTENT_DISPOSITION, content_disposition(filename)?);
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
        FsErrorCode::TooDeep => AppError::PathTooDeep,
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
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests build synthetic fixtures in temporary directories"
)]
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
        for entry in first["entries"].as_array().expect("entries") {
            assert!(entry["modifiedAtMs"].as_u64().is_some());
        }
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
        for timestamp in ["modifiedAtMs", "accessedAtMs", "createdAtMs"] {
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
    async fn metadata_reports_modification_time_in_epoch_milliseconds() {
        let fixture = fixture(BrowseLimits::default());
        let set_modified = |time: SystemTime| {
            fs::File::options()
                .write(true)
                .open(fixture._root.path().join("a.txt"))
                .and_then(|file| file.set_modified(time))
                .expect("modification time fixture");
        };
        let modified = UNIX_EPOCH + std::time::Duration::from_millis(1_789_599_600_123);
        set_modified(modified);
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/metadata?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = json(response).await;
        assert_eq!(value["modifiedAtMs"], 1_789_599_600_123_u64);

        set_modified(modified + std::time::Duration::from_secs(60));
        let touched = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/metadata?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let touched = json(touched).await;
        assert_eq!(touched["modifiedAtMs"], 1_789_599_660_123_u64);
        assert_ne!(touched["etag"], value["etag"]);
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

    async fn archive(app: &Router, identity: &AuthenticatedIdentity, query: &str) -> Response {
        send(
            app,
            Some(identity),
            Request::get(format!("/api/v1/shares/documents/archive{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn archive_names(response: Response) -> Vec<(String, Option<Vec<u8>>)> {
        assert_eq!(response.status(), StatusCode::OK);
        let length: usize = response.headers()[header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("archive body");
        assert_eq!(bytes.len(), length, "Content-Length is exact");
        crate::zip::verify::read_archive(&bytes)
            .into_iter()
            .map(|entry| (entry.name, entry.data))
            .collect()
    }

    #[tokio::test]
    async fn folder_archives_stream_the_walked_tree_with_an_exact_length() {
        let fixture = fixture(BrowseLimits::default());
        let root = fixture._root.path();
        fs::create_dir(root.join("a-directory/inner")).expect("nested directory");
        // Larger than one stream chunk, so the file spans several reads.
        let large = vec![7_u8; 200_000];
        fs::write(root.join("a-directory/inner/b.bin"), &large).expect("large file");
        fs::write(root.join("a-directory/c.txt"), b"see").expect("small file");

        let response = archive(&fixture.app, &fixture.identity, "?path=a-directory").await;
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "application/zip");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"a-directory.zip\"; filename*=UTF-8''a-directory.zip"
        );
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; sandbox"
        );
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store, private");
        assert!(!headers.contains_key(header::ACCEPT_RANGES));
        assert_eq!(
            archive_names(response).await,
            [
                ("a-directory/".to_owned(), None),
                ("a-directory/c.txt".to_owned(), Some(b"see".to_vec())),
                ("a-directory/inner/".to_owned(), None),
                ("a-directory/inner/b.bin".to_owned(), Some(large)),
            ]
        );

        // The share root is named after the share and omits internal entries.
        let response = archive(&fixture.app, &fixture.identity, "").await;
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"documents.zip\"; filename*=UTF-8''documents.zip"
        );
        let names: Vec<_> = archive_names(response)
            .await
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            [
                "documents/",
                "documents/a-directory/",
                "documents/a-directory/c.txt",
                "documents/a-directory/inner/",
                "documents/a-directory/inner/b.bin",
                "documents/a.txt",
                "documents/invalid.txt",
                "documents/page.html",
            ]
        );

        // A read-only grant may archive.
        let reader = AuthenticatedIdentity::new(
            "reader",
            vec![ShareGrant {
                share_id: fixture.grant.share_id.clone(),
                access: AccessLevel::ReadOnly,
            }],
        );
        let response = archive(&fixture.app, &reader, "?path=a-directory%2Finner").await;
        assert_eq!(archive_names(response).await.len(), 2);
    }

    #[tokio::test]
    async fn folder_archives_refuse_before_streaming() {
        // Six, thirty-three, and two bytes of files at the root.
        let fixture = fixture(BrowseLimits {
            max_download_bytes: 40,
            ..BrowseLimits::default()
        });
        for (query, status, code) in [
            ("", StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            ("?path=a.txt", StatusCode::NOT_FOUND, "not_found"),
            ("?path=missing", StatusCode::NOT_FOUND, "not_found"),
            (
                "?path=..%2Fescape",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
        ] {
            let response = archive(&fixture.app, &fixture.identity, query).await;
            assert_eq!(response.status(), status, "{query}");
            assert_eq!(json(response).await["error"]["code"], code, "{query}");
        }
        let response = archive(&fixture.app, &fixture.identity, "?path=a-directory").await;
        assert_eq!(archive_names(response).await.len(), 1, "an empty folder");

        let stranger = AuthenticatedIdentity::new("stranger", Vec::new());
        let response = archive(&fixture.app, &stranger, "?path=a-directory").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Four visible root entries exceed three.
        let few_entries = fixture_with_policy(
            BrowseLimits {
                max_archive_entries: 3,
                ..BrowseLimits::default()
            },
            GlobalPolicy::default(),
        );
        let response = archive(&few_entries.app, &few_entries.identity, "").await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn folder_archives_abort_when_an_entry_changes_while_streaming() {
        let fixture = fixture(BrowseLimits::default());
        let folder = fixture._root.path().join("a-directory");
        // Same size as the archived file, so only the no-follow open rejects it.
        let outside = TempDir::new().expect("outside");
        fs::write(outside.path().join("secret"), b"WXYZ").expect("outside file");
        for change in ["resize", "remove", "replace with a link"] {
            fs::write(folder.join("entry.txt"), b"1234").expect("archived file");
            let response = archive(&fixture.app, &fixture.identity, "?path=a-directory").await;
            assert_eq!(response.status(), StatusCode::OK);
            match change {
                "resize" => fs::write(folder.join("entry.txt"), b"123456789").expect("resize"),
                "remove" => fs::remove_file(folder.join("entry.txt")).expect("remove"),
                _ => {
                    fs::remove_file(folder.join("entry.txt")).expect("remove");
                    std::os::unix::fs::symlink(
                        outside.path().join("secret"),
                        folder.join("entry.txt"),
                    )
                    .expect("link");
                }
            }
            assert!(
                to_bytes(response.into_body(), usize::MAX).await.is_err(),
                "{change}"
            );
            let _ = fs::remove_file(folder.join("entry.txt"));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_an_archive_body_closes_its_file_and_releases_its_slot() {
        use futures_util::StreamExt as _;

        let fixture = fixture(BrowseLimits::default());
        let path = fixture._root.path().join("a-directory/large.bin");
        fs::write(&path, vec![0x5a; 2 * 1024 * 1024]).expect("large file");
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_ARCHIVES_PER_SUBJECT {
            let response = archive(&fixture.app, &fixture.identity, "?path=a-directory").await;
            assert_eq!(response.status(), StatusCode::OK);
            held.push(response);
        }
        let busy = archive(&fixture.app, &fixture.identity, "?path=a-directory").await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);

        let mut stream = held.pop().unwrap().into_body().into_data_stream();
        stream
            .next()
            .await
            .expect("first chunk")
            .expect("archive bytes");
        assert_eq!(open_descriptors_for(&path), 1);
        drop(stream);
        assert_eq!(open_descriptors_for(&path), 0);
        let response = archive(&fixture.app, &fixture.identity, "?path=a-directory").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn download_a_txt(app: &Router, identity: &AuthenticatedIdentity) -> Response {
        send(
            app,
            Some(identity),
            Request::get("/api/v1/shares/documents/download?path=a.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn assert_download_busy(app: &Router, identity: &AuthenticatedIdentity) {
        let busy = download_a_txt(app, identity).await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(busy.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(json(busy).await["error"]["code"], "busy");
    }

    #[tokio::test]
    async fn unread_download_bodies_hold_a_per_subject_slot_until_released() {
        let fixture = fixture(BrowseLimits::default());
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT {
            let response = download_a_txt(&fixture.app, &fixture.identity).await;
            assert_eq!(response.status(), StatusCode::OK);
            held.push(response);
        }
        // The handler has returned for every held response; only the unread
        // bodies keep the slots.
        assert_download_busy(&fixture.app, &fixture.identity).await;

        // Another subject is not affected by this subject's limit.
        let other = AuthenticatedIdentity::new("user-2", vec![fixture.grant.clone()]);
        let response = download_a_txt(&fixture.app, &other).await;
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);

        // Dropping an unread body releases its slot.
        drop(held.pop());
        let response = download_a_txt(&fixture.app, &fixture.identity).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_download_busy(&fixture.app, &fixture.identity).await;

        // Reading a body to completion releases its slot too.
        assert_eq!(
            to_bytes(response.into_body(), 64).await.unwrap().as_ref(),
            b"abcdef"
        );
        let response = download_a_txt(&fixture.app, &fixture.identity).await;
        assert_eq!(response.status(), StatusCode::OK);
        drop((held, response));
    }

    #[tokio::test]
    async fn download_slots_are_bounded_across_the_process() {
        let fixture = fixture(BrowseLimits::default());
        let subjects = MAX_CONCURRENT_DOWNLOADS.div_ceil(MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT);
        let mut held = Vec::new();
        for subject in 0..subjects {
            let identity = AuthenticatedIdentity::new(
                format!("holder-{subject}"),
                vec![fixture.grant.clone()],
            );
            for _ in 0..MAX_CONCURRENT_DOWNLOADS_PER_SUBJECT {
                if held.len() == MAX_CONCURRENT_DOWNLOADS {
                    break;
                }
                let response = download_a_txt(&fixture.app, &identity).await;
                assert_eq!(response.status(), StatusCode::OK);
                held.push(response);
            }
        }
        // A fresh subject under its own limit is still refused by the
        // process-wide limit.
        let fresh = AuthenticatedIdentity::new("fresh", vec![fixture.grant.clone()]);
        assert_download_busy(&fixture.app, &fresh).await;

        drop(held.pop());
        let response = download_a_txt(&fixture.app, &fresh).await;
        assert_eq!(response.status(), StatusCode::OK);
        drop((held, response));
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
    async fn downloads_never_carry_a_script_or_stylesheet_type() {
        let fixture = fixture(BrowseLimits::default());
        for (name, expected) in [
            ("evil.js", "application/octet-stream"),
            ("evil.mjs", "application/octet-stream"),
            ("evil.css", "application/octet-stream"),
            ("evil.wasm", "application/octet-stream"),
            ("a.txt", "text/plain"),
        ] {
            fs::write(fixture._root.path().join(name), b"window.evil=true")
                .unwrap_or_else(|_| panic!("{name} fixture"));
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get(format!("/api/v1/shares/documents/download?path={name}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], expected, "{name}");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        }
    }

    #[test]
    fn download_mime_neutralizes_every_executable_subresource_type() {
        for executable in [
            "text/javascript",
            "application/javascript; charset=utf-8",
            "application/x-ecmascript",
            "text/JScript",
            "text/livescript",
            "text/css",
            "application/wasm",
        ] {
            assert_eq!(
                download_mime(executable.to_owned()),
                "application/octet-stream",
                "{executable}"
            );
        }
        for inert in ["text/plain", "text/html", "image/png", "application/json"] {
            assert_eq!(download_mime(inert.to_owned()), inert);
        }
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
        for (value, start, end) in [
            ("bytes=2-4", 2, 4),
            ("bytes=2-", 2, 5),
            ("bytes=-2", 4, 5),
            ("bytes=-99", 0, 5),
            ("bytes=2-99", 2, 5),
        ] {
            assert_eq!(
                parse_range(&HeaderValue::from_static(value), 6),
                RangeRequest::Satisfiable(start, end),
                "{value}"
            );
        }
        for unsatisfiable in ["bytes=6-", "bytes=99-100", "bytes=-0"] {
            assert_eq!(
                parse_range(&HeaderValue::from_static(unsatisfiable), 6),
                RangeRequest::Unsatisfiable,
                "{unsatisfiable}"
            );
        }
        for ignored in [
            "bytes=4-2",
            "bytes=0-1,3-4",
            "items=0-1",
            "bytes=+1-2",
            "bytes=1-+2",
            "bytes=-+2",
            "bytes= 1-2",
            "bytes=1",
            "bytes=a-b",
            "bytes=99999999999999999999999-",
        ] {
            assert_eq!(
                parse_range(&HeaderValue::from_static(ignored), 6),
                RangeRequest::Ignore,
                "{ignored}"
            );
        }
        assert_eq!(
            parse_range(&HeaderValue::from_static("bytes=0-"), 0),
            RangeRequest::Unsatisfiable
        );
        assert_eq!(
            parse_range(&HeaderValue::from_static("bytes=-5"), 0),
            RangeRequest::Ignore
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn event_streams_announce_a_fast_reconnect_and_have_a_bounded_lifetime() {
        assert!(EVENT_STREAM_LIFETIME <= Duration::from_secs(60));
        let fixture = fixture(BrowseLimits::default());
        let response = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/events?path=")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        let first = body.next().await.expect("first frame").expect("frame");
        assert_eq!(first.as_ref(), b"retry: 1000\n\n");
    }

    #[tokio::test]
    async fn invalid_and_multi_ranges_are_ignored_with_a_full_response() {
        let fixture = fixture(BrowseLimits::default());
        for range in ["bytes=5-3", "bytes=0-1,3-4", "bytes=+1-2", "bytes=garbage"] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get("/api/v1/shares/documents/download?path=a.txt")
                    .header(header::RANGE, range)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{range}");
            assert!(response.headers().get(header::CONTENT_RANGE).is_none());
            assert_eq!(
                to_bytes(response.into_body(), 64).await.unwrap().as_ref(),
                b"abcdef"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_read_responses_are_never_stored() {
        let fixture = fixture(BrowseLimits::default());
        for uri in [
            "/api/v1/shares",
            "/api/v1/shares/documents/directory",
            "/api/v1/shares/documents/metadata?path=a.txt",
            "/api/v1/shares/documents/text?path=a.txt",
            "/api/v1/shares/documents/download?path=a.txt",
        ] {
            let response = send(
                &fixture.app,
                Some(&fixture.identity),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "no-store, private",
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn pagination_survives_content_changes_but_not_structural_changes() {
        let fixture = fixture(BrowseLimits::default());
        let first = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get("/api/v1/shares/documents/directory?limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let cursor = json(first).await["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();
        // An in-place write changes size and mtime but not structure.
        fs::write(
            fixture._root.path().join("page.html"),
            b"growing file contents",
        )
        .expect("in-place write");
        let second = send(
            &fixture.app,
            Some(&fixture.identity),
            Request::get(format!(
                "/api/v1/shares/documents/directory?limit=2&cursor={cursor}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn trash_listing_is_concurrency_bounded() {
        let root = TempDir::new().expect("temporary share");
        let id = ShareId::new("documents").expect("share id");
        let share = ConfiguredShare::new(
            "Documents",
            ShareFs::open(id.clone(), root.path()).expect("open share"),
        )
        .expect("configured share");
        let browse = BrowseState::new(
            vec![share],
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [0x5a; 32],
        )
        .expect("browse state");
        let listings = Arc::clone(browse.listing_gate());
        let app = app::router(AppState::new(true).with_browse(browse));
        // Read-only users can list the trash, so the scan must be bounded
        // without relying on the write grant.
        let identity = AuthenticatedIdentity::new(
            "user-1",
            vec![ShareGrant {
                share_id: id,
                access: AccessLevel::ReadOnly,
            }],
        );
        let uri = "/api/v1/shares/documents/trash";

        let held_listings = Arc::clone(&listings)
            .acquire_many_owned(MAX_CONCURRENT_LISTINGS as u32)
            .await
            .expect("listing permits");
        let busy = send(
            &app,
            Some(&identity),
            Request::get(uri).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json(busy).await["error"]["code"], "busy");

        drop(held_listings);
        let accepted = send(
            &app,
            Some(&identity),
            Request::get(uri).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(listings.available_permits(), MAX_CONCURRENT_LISTINGS);
    }

    #[tokio::test]
    async fn buffered_reads_and_listings_are_concurrency_bounded() {
        let root = TempDir::new().expect("temporary share");
        fs::write(root.path().join("a.txt"), b"abcdef").expect("text fixture");
        let id = ShareId::new("documents").expect("share id");
        let share = ConfiguredShare::new(
            "Documents",
            ShareFs::open(id.clone(), root.path()).expect("open share"),
        )
        .expect("configured share");
        let browse = BrowseState::new(
            vec![share],
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [0x5a; 32],
        )
        .expect("browse state");
        let reads = Arc::clone(browse.buffered_read_gate());
        let listings = Arc::clone(browse.listing_gate());
        let app = app::router(AppState::new(true).with_browse(browse));
        let identity = AuthenticatedIdentity::new(
            "user-1",
            vec![ShareGrant {
                share_id: id,
                access: AccessLevel::ReadOnly,
            }],
        );

        let held_reads = reads
            .acquire_many_owned(MAX_CONCURRENT_BUFFERED_READS as u32)
            .await
            .expect("read permits");
        let held_listings = listings
            .acquire_many_owned(MAX_CONCURRENT_LISTINGS as u32)
            .await
            .expect("listing permits");
        for uri in [
            "/api/v1/shares/documents/text?path=a.txt",
            "/api/v1/shares/documents/preview?path=a.txt",
            "/api/v1/shares/documents/directory",
        ] {
            let busy = send(
                &app,
                Some(&identity),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS, "{uri}");
            assert_eq!(json(busy).await["error"]["code"], "busy");
        }
        drop((held_reads, held_listings));
        for uri in [
            "/api/v1/shares/documents/text?path=a.txt",
            "/api/v1/shares/documents/preview?path=a.txt",
            "/api/v1/shares/documents/directory",
        ] {
            let accepted = send(
                &app,
                Some(&identity),
                Request::get(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(accepted.status(), StatusCode::OK, "{uri}");
        }
    }

    /// A router and the state behind it, so a test can hold gate leases.
    fn gated_fixture() -> (TempDir, AppState, Router, ShareGrant) {
        let root = TempDir::new().expect("temporary share");
        fs::write(root.path().join("a.txt"), b"abcdef").expect("text fixture");
        let id = ShareId::new("documents").expect("share id");
        let share = ConfiguredShare::new(
            "Documents",
            ShareFs::open(id.clone(), root.path()).expect("open share"),
        )
        .expect("configured share");
        let browse = BrowseState::new(
            vec![share],
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [0x5a; 32],
        )
        .expect("browse state");
        let state = AppState::new(true).with_browse(browse);
        let app = app::router(state.clone());
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadOnly,
        };
        (root, state, app, grant)
    }

    async fn get_status(app: &Router, identity: &AuthenticatedIdentity, uri: &str) -> StatusCode {
        send(
            app,
            Some(identity),
            Request::get(uri).body(Body::empty()).unwrap(),
        )
        .await
        .status()
    }

    #[tokio::test]
    async fn listing_and_buffered_read_gates_cap_each_subject() {
        let (_root, state, app, grant) = gated_fixture();
        let alice = AuthenticatedIdentity::new("alice", vec![grant.clone()]);
        let bob = AuthenticatedIdentity::new("bob", vec![grant]);
        let browse = state.browse();
        let cases: [(&SubjectGate, usize, &[&str]); 2] = [
            (
                &browse.listing_gate,
                MAX_CONCURRENT_LISTINGS_PER_SUBJECT,
                &[
                    "/api/v1/shares/documents/directory",
                    "/api/v1/shares/documents/trash",
                ],
            ),
            (
                &browse.buffered_read_gate,
                MAX_CONCURRENT_BUFFERED_READS_PER_SUBJECT,
                &[
                    "/api/v1/shares/documents/text?path=a.txt",
                    "/api/v1/shares/documents/preview?path=a.txt",
                ],
            ),
        ];
        for (gate, per_subject, uris) in cases {
            let held: Vec<_> = (0..per_subject)
                .map(|_| gate.try_acquire("alice").expect("subject lease"))
                .collect();
            // The process still has free slots, yet this subject is refused.
            assert!(gate.process_semaphore().available_permits() > 0);
            for uri in uris {
                assert_eq!(
                    get_status(&app, &alice, uri).await,
                    StatusCode::TOO_MANY_REQUESTS,
                    "{uri}"
                );
                assert_eq!(get_status(&app, &bob, uri).await, StatusCode::OK, "{uri}");
            }
            drop(held);
            for uri in uris {
                assert_eq!(get_status(&app, &alice, uri).await, StatusCode::OK, "{uri}");
            }
        }
    }

    #[tokio::test]
    async fn ungated_blocking_requests_share_a_bounded_gate() {
        let (_root, state, app, grant) = gated_fixture();
        let alice = AuthenticatedIdentity::new("alice", vec![grant.clone()]);
        let bob = AuthenticatedIdentity::new("bob", vec![grant]);
        let uris = ["/api/v1/shares/documents/metadata?path=a.txt"];

        // Process-wide: every slot held refuses every subject.
        let held = Arc::clone(state.browse().blocking_gate())
            .acquire_many_owned(MAX_CONCURRENT_BLOCKING_REQUESTS as u32)
            .await
            .expect("blocking permits");
        let busy = send(
            &app,
            Some(&alice),
            Request::get(uris[0]).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(busy.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(json(busy).await["error"]["code"], "busy");
        drop(held);
        assert_eq!(get_status(&app, &alice, uris[0]).await, StatusCode::OK);
        assert_eq!(
            state.browse().blocking_gate().available_permits(),
            MAX_CONCURRENT_BLOCKING_REQUESTS
        );

        // Per subject: one user's slots do not refuse another user.
        let held: Vec<_> = (0..MAX_CONCURRENT_BLOCKING_REQUESTS_PER_SUBJECT)
            .map(|_| {
                state
                    .browse()
                    .blocking_gate
                    .try_acquire("alice")
                    .expect("subject lease")
            })
            .collect();
        assert_eq!(
            get_status(&app, &alice, uris[0]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(get_status(&app, &bob, uris[0]).await, StatusCode::OK);
        drop(held);
        assert_eq!(get_status(&app, &alice, uris[0]).await, StatusCode::OK);
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
    let gate = SubjectGate::new(2, 1);
    let alice = gate.try_acquire("alice").expect("first user lease");
    assert!(gate.try_acquire("alice").is_none());
    // A rejected per-subject attempt must not leak a process permit.
    assert_eq!(gate.process_semaphore().available_permits(), 1);
    let bob = gate.try_acquire("bob").expect("second process lease");
    assert!(gate.try_acquire("charlie").is_none());
    drop(alice);
    let alice = gate.try_acquire("alice").expect("released user lease");
    drop((alice, bob));
    assert!(gate.try_acquire("charlie").is_some());
}

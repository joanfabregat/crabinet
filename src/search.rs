//! Rebuildable, bounded metadata index. All share I/O uses existing capabilities.
use crate::{
    app::AppState,
    browse::{AuthenticatedIdentity, BrowseState, SubjectGate},
    config::Config,
    error::AppError,
    extract::ApiQuery,
    filesystem::{
        DirectoryEntry, EntryKind, FsErrorCode, MAX_PATH_DEPTH, OwnedAuthorizedShare, ShareId,
        VirtualPath,
    },
};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use rusqlite::{Connection, OpenFlags, params, types::Value};
use rustix::fs::inotify::{self, ReadFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use unicode_normalization::UnicodeNormalization;

const APPLICATION_ID: i64 = 0x4352_5348;
/// Older layouts are dropped and rebuilt; newer ones are refused.
const SCHEMA_VERSION: i64 = 2;
const MAX_ENTRIES: i64 = 200_000;
const MAX_OFFSET: usize = 10_000;
const MAX_WATCHES: usize = 4096;
const MAX_PENDING: usize = 4096;
const MAX_LISTING: usize = 10_000;
/// Work done for one share before the worker moves to the next; an
/// unfinished pass resumes where it stopped.
const WORK_SLICE: Duration = Duration::from_secs(2);
const RECONCILE: Duration = Duration::from_secs(300);
/// Change notifications are applied once a share has been quiet this long,
/// or at the latest this long after the first one, so a busy folder still
/// refreshes without being rescanned on every write.
const EVENT_QUIET: Duration = Duration::from_secs(2);
const EVENT_MAX_DELAY: Duration = Duration::from_secs(10);
/// Minimum time between full passes that mutations request on a share whose
/// directories are not all watched.
const FULL_PASS_GAP: Duration = Duration::from_secs(30);
/// One read connection per process-wide search slot, so queries never wait
/// for the indexer or for each other.
const READERS: usize = 4;
const MAX_QUERY_BYTES: usize = 1024;

struct IndexedShare {
    view: OwnedAuthorizedShare,
    /// Set by mutations; a full pass follows only when watches cannot cover the share.
    invalidated: AtomicBool,
    complete: AtomicBool,
    indexing: AtomicBool,
    polling: AtomicBool,
    work: Mutex<ShareWork>,
}

/// Indexer state for one share, used only by the background worker.
#[derive(Default)]
struct ShareWork {
    /// Directories to list, and whether to descend into all of their
    /// subdirectories. Targeted refreshes descend only into new ones.
    pending: VecDeque<(VirtualPath, bool)>,
    /// Finishing `pending` completes a pass over the whole share.
    full_pass: bool,
    full_requested: bool,
    last_full_pass: Option<Instant>,
    /// The last finished full pass, or later work, hit a bound or an unreadable directory.
    incomplete: bool,
    /// The same, for the full pass in progress.
    pass_incomplete: bool,
    indexed_once: bool,
    /// The pass in progress is the periodic check of an index believed current.
    reconciling: bool,
    unwatched: bool,
    dirty: HashSet<VirtualPath>,
    first_event: Option<Instant>,
    last_event: Option<Instant>,
    watcher: Option<rustix::fd::OwnedFd>,
    watches: HashMap<i32, VirtualPath>,
    watched: HashMap<VirtualPath, i32>,
}

struct Writer {
    connection: Connection,
    total: i64,
}

pub struct SearchService {
    writer: Mutex<Writer>,
    readers: Vec<Mutex<Connection>>,
    shares: HashMap<String, IndexedShare>,
    gate: SubjectGate,
    stop: AtomicBool,
    slice: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum SearchInitError {
    #[error("cannot initialize the private search index")]
    Io(#[from] std::io::Error),
    #[error("cannot initialize the search index schema")]
    Sqlite(#[from] rusqlite::Error),
}

impl SearchService {
    pub fn open(config: &Config, browse: &BrowseState) -> Result<Arc<Self>, SearchInitError> {
        let path = config.server().search_index_path();
        let connection = open_private_database(path)?;
        let shares = config
            .shares()
            .iter()
            .filter(|s| s.search_enabled())
            .filter_map(|s| {
                let view = browse
                    .configured_shares()
                    .find(|b| b.id().as_str() == s.id())?
                    .index_view();
                // Root changes must discard old names even when the share ID stays the same.
                let mut digest = Sha256::new();
                digest.update(s.root().as_os_str().as_encoded_bytes());
                digest.update(view.view().root_identity());
                let fingerprint = digest
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                Some((s.id().to_owned(), fingerprint, view))
            })
            .collect();
        let service = Self::initialize(connection, shares, || open_reader(path))?;
        Ok(Arc::new(service))
    }

    fn initialize(
        mut connection: Connection,
        shares: Vec<(String, String, OwnedAuthorizedShare)>,
        reader: impl Fn() -> rusqlite::Result<Connection>,
    ) -> Result<Self, rusqlite::Error> {
        connection.busy_timeout(Duration::from_millis(250))?;
        let application: i64 = connection.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let tables: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0),
        )?;
        if (application == 0 && tables != 0)
            || (application != 0 && (application != APPLICATION_ID || version > SCHEMA_VERSION))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if application == APPLICATION_ID && version < SCHEMA_VERSION {
            // The index is disposable, so an older layout is rebuilt rather than migrated.
            connection.execute_batch(
                "DROP TABLE IF EXISTS names; DROP TABLE IF EXISTS entries; DROP TABLE IF EXISTS roots;",
            )?;
        }
        let page_size: i64 = connection.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        connection.pragma_update(None, "max_page_count", (256 * 1024 * 1024) / page_size)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
            PRAGMA cache_size=-2048; PRAGMA journal_size_limit=4194304;
            CREATE TABLE IF NOT EXISTS roots (share TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, share TEXT NOT NULL REFERENCES roots(share) ON DELETE CASCADE,
                path TEXT NOT NULL, parent TEXT NOT NULL, name TEXT NOT NULL, normalized TEXT NOT NULL, kind TEXT NOT NULL,
                category TEXT NOT NULL, extension TEXT NOT NULL, size INTEGER, modified INTEGER,
                UNIQUE(share,path));
            CREATE INDEX IF NOT EXISTS entries_scope ON entries(share,parent);
            CREATE VIRTUAL TABLE IF NOT EXISTS names USING fts5(normalized, content='entries', content_rowid='id', tokenize='trigram');
            CREATE TRIGGER IF NOT EXISTS entries_insert AFTER INSERT ON entries BEGIN
                INSERT INTO names(rowid,normalized) VALUES(new.id,new.normalized); END;
            CREATE TRIGGER IF NOT EXISTS entries_delete AFTER DELETE ON entries BEGIN
                INSERT INTO names(names,rowid,normalized) VALUES('delete',old.id,old.normalized); END;
            CREATE TRIGGER IF NOT EXISTS entries_name AFTER UPDATE OF normalized ON entries WHEN old.normalized != new.normalized BEGIN
                INSERT INTO names(names,rowid,normalized) VALUES('delete',old.id,old.normalized);
                INSERT INTO names(rowid,normalized) VALUES(new.id,new.normalized); END;")?;
        let transaction = connection.transaction()?;
        let existing = transaction
            .prepare("SELECT share,fingerprint FROM roots")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        for (id, fingerprint) in existing {
            if !shares.iter().any(|(s, f, _)| s == &id && f == &fingerprint) {
                transaction.execute("DELETE FROM roots WHERE share=?", [&id])?;
            }
        }
        for (id, fingerprint, _) in &shares {
            transaction.execute(
                "INSERT OR IGNORE INTO roots VALUES(?,?)",
                params![id, fingerprint],
            )?;
        }
        transaction.commit()?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let total = connection.query_row("SELECT count(*) FROM entries", [], |r| r.get(0))?;
        let readers = (0..READERS)
            .map(|_| {
                let reader = reader()?;
                reader.busy_timeout(Duration::from_millis(250))?;
                reader.execute_batch("PRAGMA query_only=ON; PRAGMA cache_size=-512;")?;
                Ok(Mutex::new(reader))
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Self {
            writer: Mutex::new(Writer { connection, total }),
            readers,
            shares: shares
                .into_iter()
                .map(|(id, _, view)| {
                    (
                        id,
                        IndexedShare {
                            view,
                            invalidated: AtomicBool::new(false),
                            complete: AtomicBool::new(false),
                            indexing: AtomicBool::new(true),
                            polling: AtomicBool::new(true),
                            work: Mutex::new(ShareWork::default()),
                        },
                    )
                })
                .collect(),
            gate: SubjectGate::new(READERS, 2),
            stop: AtomicBool::new(false),
            slice: WORK_SLICE,
        })
    }

    pub fn invalidate(&self, id: &ShareId) {
        if let Some(share) = self.shares.get(id.as_str()) {
            share.invalidated.store(true, Ordering::Release);
            // Report indexing until the worker has taken in the mutation's
            // notifications, so a search sent right after it keeps polling.
            share.indexing.store(true, Ordering::Release);
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// One background worker. Each share gets a bounded slice of work per
    /// round; watches are hints, and periodic passes repair missed events.
    pub async fn run(self: Arc<Self>) {
        let ids: Vec<String> = self.shares.keys().cloned().collect();
        let allowance = MAX_WATCHES / ids.len().max(1);
        while !self.stop.load(Ordering::Acquire) {
            let mut busy = false;
            for id in &ids {
                if self.stop.load(Ordering::Acquire) {
                    return;
                }
                let service = Arc::clone(&self);
                let step_id = id.clone();
                match tokio::task::spawn_blocking(move || service.step(&step_id, allowance)).await {
                    Ok(Ok(more)) => busy |= more,
                    _ => tracing::warn!(
                        share_id = id,
                        "search indexing failed; retaining previous entries for reconciliation"
                    ),
                }
            }
            let pause = if busy {
                Duration::from_millis(50)
            } else {
                Duration::from_secs(1)
            };
            tokio::time::sleep(pause).await;
        }
    }

    /// Advances one share's indexing by at most one work slice. Returns
    /// whether queued work remains.
    fn step(&self, id: &str, watch_allowance: usize) -> Result<bool, rusqlite::Error> {
        let Some(share) = self.shares.get(id) else {
            return Ok(false);
        };
        let mut work = share
            .work
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let result = self.advance(id, share, &mut work, watch_allowance);
        if result.is_err() {
            // Abandon the pass; the next periodic pass retries without spinning on the failure.
            work.pending.clear();
            work.full_pass = false;
            work.reconciling = false;
            work.indexed_once = true;
            work.incomplete = true;
            share.complete.store(false, Ordering::Release);
            if let Ok(mut writer) = self.writer.lock()
                && let Ok(total) =
                    writer
                        .connection
                        .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            {
                writer.total = total;
            }
        }
        // The periodic check of a current index is not reported as indexing.
        let indexing = !work.indexed_once
            || (!work.pending.is_empty() && !work.reconciling)
            || !work.dirty.is_empty()
            || work.full_requested
            // A mutation that landed after this step drained its events.
            || share.invalidated.load(Ordering::Acquire);
        share.indexing.store(indexing, Ordering::Release);
        result.map(|()| !work.pending.is_empty())
    }

    fn advance(
        &self,
        id: &str,
        share: &IndexedShare,
        work: &mut ShareWork,
        watch_allowance: usize,
    ) -> Result<(), rusqlite::Error> {
        Self::drain_events(work);
        if share.invalidated.swap(false, Ordering::AcqRel) && share.polling.load(Ordering::Acquire)
        {
            work.full_requested = true;
        }
        if !work.full_pass {
            let since = work.last_full_pass.map(|at| at.elapsed());
            let due = since.is_none_or(|elapsed| elapsed >= RECONCILE);
            let requested =
                work.full_requested && since.is_none_or(|elapsed| elapsed >= FULL_PASS_GAP);
            if due || requested {
                if work.watcher.is_none() {
                    work.watcher = inotify::init(
                        inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK,
                    )
                    .ok();
                }
                // A full pass lists every directory, so it covers pending notifications.
                work.full_pass = true;
                work.full_requested = false;
                work.last_full_pass = Some(Instant::now());
                work.pass_incomplete = false;
                work.reconciling = due && !requested && work.indexed_once;
                work.unwatched = work.watcher.is_none();
                work.pending.clear();
                work.pending.push_back((VirtualPath::root(), true));
                work.dirty.clear();
                work.first_event = None;
                work.last_event = None;
            }
        }
        if work.pending.is_empty() && !work.dirty.is_empty() {
            let quiet = work
                .last_event
                .is_some_and(|at| at.elapsed() >= EVENT_QUIET);
            let overdue = work
                .first_event
                .is_some_and(|at| at.elapsed() >= EVENT_MAX_DELAY);
            if quiet || overdue {
                work.pending
                    .extend(work.dirty.drain().map(|path| (path, false)));
                work.first_event = None;
                work.last_event = None;
            }
        }
        let started = Instant::now();
        let mut hit = false;
        while let Some((path, recursive)) = work.pending.pop_front() {
            if self.stop.load(Ordering::Acquire) {
                work.pending.push_front((path, recursive));
                return Ok(());
            }
            Self::watch(share, work, &path, watch_allowance);
            match share.view.view().list_bounded(&path, MAX_LISTING) {
                Ok(entries) => {
                    let (directories, capped) = self.reconcile(id, &path, &entries)?;
                    hit |= capped;
                    for (directory, new) in directories {
                        if !(recursive || new) {
                            continue;
                        }
                        if work.pending.len() >= MAX_PENDING {
                            hit = true;
                        } else {
                            work.pending.push_back((directory, true));
                        }
                    }
                }
                // Removed since it was queued; its parent's refresh prunes it.
                Err(error) if error.code() == FsErrorCode::NotFound => {}
                // Unreadable or oversized directories keep their previous entries.
                Err(_) => hit = true,
            }
            if started.elapsed() >= self.slice {
                break;
            }
        }
        if !work.full_pass {
            work.incomplete |= hit;
        } else if work.pending.is_empty() {
            work.full_pass = false;
            work.reconciling = false;
            work.indexed_once = true;
            work.incomplete = work.pass_incomplete || hit;
            share.polling.store(work.unwatched, Ordering::Release);
            self.writer
                .lock()
                .map_err(|_| rusqlite::Error::InvalidQuery)?
                .connection
                .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
        } else {
            work.pass_incomplete |= hit;
        }
        share
            .complete
            .store(work.indexed_once && !work.incomplete, Ordering::Release);
        Ok(())
    }

    /// Turns pending inotify events into directories to refresh. Any event in
    /// a watched directory marks that directory; overflow requests a full pass.
    fn drain_events(work: &mut ShareWork) {
        let Some(watcher) = &work.watcher else {
            return;
        };
        let mut events = Vec::new();
        let mut overflow = false;
        {
            let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 8192];
            let mut reader = inotify::Reader::new(watcher, &mut buffer);
            // Drain everything: events left in the buffer would be lost.
            loop {
                match reader.next() {
                    Ok(event) => events.push((event.wd(), event.events())),
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(_) => {
                        overflow = true;
                        break;
                    }
                }
            }
        }
        for (wd, flags) in events {
            if flags.intersects(ReadFlags::QUEUE_OVERFLOW | ReadFlags::UNMOUNT) {
                overflow = true;
            } else if flags.contains(ReadFlags::IGNORED) {
                if let Some(path) = work.watches.remove(&wd)
                    && work.watched.get(&path) == Some(&wd)
                {
                    work.watched.remove(&path);
                }
            } else if let Some(path) = work.watches.get(&wd) {
                // A watched directory that moved or vanished changes its parent's listing.
                let target = if flags.intersects(ReadFlags::DELETE_SELF | ReadFlags::MOVE_SELF) {
                    path.split_parent().map(|(parent, _)| parent)
                } else {
                    Some(path.clone())
                };
                if let Some(target) = target {
                    work.dirty.insert(target);
                    let now = Instant::now();
                    work.first_event.get_or_insert(now);
                    work.last_event = Some(now);
                }
            }
        }
        if overflow {
            work.full_requested = true;
        }
    }

    fn watch(share: &IndexedShare, work: &mut ShareWork, path: &VirtualPath, allowance: usize) {
        let Some(watcher) = &work.watcher else {
            work.unwatched = true;
            return;
        };
        if !work.watched.contains_key(path) && work.watched.len() >= allowance {
            work.unwatched = true;
            return;
        }
        match share.view.view().watch_index_directory(watcher, path) {
            Ok(wd) => {
                // The kernel keeps one descriptor per directory, so a moved
                // directory keeps its descriptor under the new path.
                if let Some(old) = work.watches.insert(wd, path.clone())
                    && &old != path
                {
                    work.watched.remove(&old);
                }
                if let Some(old) = work.watched.insert(path.clone(), wd)
                    && old != wd
                {
                    work.watches.remove(&old);
                }
            }
            Err(_) => work.unwatched = true,
        }
    }

    /// Makes the index match one directory listing: new names are inserted,
    /// changed metadata is updated, and vanished names are removed with
    /// their descendants. Unchanged rows are not written. Returns the
    /// subdirectories, marking those not indexed before, and whether a bound
    /// left part of the listing out.
    fn reconcile(
        &self,
        id: &str,
        parent: &VirtualPath,
        entries: &[DirectoryEntry],
    ) -> Result<(Vec<(VirtualPath, bool)>, bool), rusqlite::Error> {
        type Row = (String, Option<i64>, Option<i64>);
        let parent_text = parent.to_string();
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let Writer { connection, total } = &mut *writer;
        let mut count = *total;
        let mut directories = Vec::new();
        let mut capped = false;
        let transaction = connection.transaction()?;
        {
            let mut existing = transaction
                .prepare("SELECT name,kind,size,modified FROM entries WHERE share=? AND parent=?")?
                .query_map(params![id, parent_text], |r| {
                    Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?)))
                })?
                .collect::<Result<HashMap<String, Row>, _>>()?;
            let mut insert = transaction.prepare(
                "INSERT INTO entries(share,path,parent,name,normalized,kind,category,extension,size,modified)
                VALUES(?,?,?,?,?,?,?,?,?,?)",
            )?;
            let mut update = transaction.prepare(
                "UPDATE entries SET kind=?,category=?,size=?,modified=? WHERE share=? AND path=?",
            )?;
            let mut remove = transaction.prepare("DELETE FROM entries WHERE share=? AND path=?")?;
            // "/" sorts immediately before "0", so the descendants of a path
            // are exactly the paths in ["path/", "path0").
            let mut remove_below =
                transaction.prepare("DELETE FROM entries WHERE share=? AND path>=? AND path<?")?;
            let mut descendants = |path: &str| -> Result<i64, rusqlite::Error> {
                let removed =
                    remove_below.execute(params![id, format!("{path}/"), format!("{path}0")])?;
                Ok(i64::try_from(removed).unwrap_or(i64::MAX))
            };
            for entry in entries {
                let path = parent.join(entry.name.clone());
                if path.depth() > MAX_PATH_DEPTH {
                    capped = true;
                    continue;
                }
                let directory = entry.kind == EntryKind::Directory;
                let kind = if directory { "directory" } else { "file" };
                let size = if directory {
                    None
                } else {
                    i64::try_from(entry.size).ok()
                };
                let modified = unix_seconds(entry.modified);
                let normalized = normalize(entry.name.as_str());
                let extension = extension(&normalized);
                let category = category(&extension, directory);
                let path_text = path.to_string();
                let new = match existing.remove(entry.name.as_str()) {
                    Some((old_kind, old_size, old_modified)) => {
                        if old_kind != kind {
                            if old_kind == "directory" {
                                count -= descendants(&path_text)?;
                            }
                        } else if old_size == size && old_modified == modified {
                            if directory {
                                directories.push((path, false));
                            }
                            continue;
                        }
                        update.execute(params![kind, category, size, modified, id, path_text])?;
                        old_kind != kind
                    }
                    None if count < MAX_ENTRIES => {
                        insert.execute(params![
                            id,
                            path_text,
                            parent_text,
                            entry.name.as_str(),
                            normalized,
                            kind,
                            category,
                            extension,
                            size,
                            modified
                        ])?;
                        count += 1;
                        true
                    }
                    None => {
                        capped = true;
                        continue;
                    }
                };
                if directory {
                    directories.push((path, new));
                }
            }
            for (name, (kind, _, _)) in existing {
                let path = if parent_text.is_empty() {
                    name
                } else {
                    format!("{parent_text}/{name}")
                };
                count -= i64::try_from(remove.execute(params![id, path])?).unwrap_or(i64::MAX);
                if kind == "directory" {
                    count -= descendants(&path)?;
                }
            }
        }
        transaction.commit()?;
        *total = count;
        Ok((directories, capped))
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: opens operator-configured private search state outside all shares"
)]
fn open_private_database(path: &Path) -> Result<Connection, SearchInitError> {
    for sibling in crate::config::sqlite_paths(path).iter().skip(1) {
        // nosemgrep: crabinet-ambient-filesystem-path
        match std::fs::symlink_metadata(sibling) {
            Ok(metadata)
                if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "search sidecars must be private regular files without aliases",
                )
                .into());
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // nosemgrep: crabinet-ambient-filesystem-path
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "search index must be an owner-only regular file without aliases",
        )
        .into());
    }
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

/// Opens a query connection to the index the writer has already validated
/// and created. It never creates the file.
fn open_reader(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
}

/// Indexed names and query terms compare in lowercase NFC. Crabinet lists
/// only NFC names, but typed or pasted queries may arrive decomposed.
fn normalize(value: &str) -> String {
    value
        .nfc()
        .collect::<String>()
        .to_lowercase()
        .nfc()
        .collect()
}

fn unix_seconds(time: Option<SystemTime>) -> Option<i64> {
    time?
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|t| i64::try_from(t.as_secs()).ok())
}

fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map_or(String::new(), |(_, ext)| ext.to_owned())
}

fn category(ext: &str, directory: bool) -> &'static str {
    if directory {
        return "folder";
    }
    match ext {
        "pdf" => "pdf",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "avif" | "heic" | "heif" | "dng"
        | "nef" | "cr2" | "tiff" | "tif" => "image",
        "mp4" | "webm" | "mov" | "mkv" | "avi" | "m4v" => "video",
        "mp3" | "wav" | "ogg" | "flac" | "m4a" | "aac" | "opus" => "audio",
        "txt" | "md" | "markdown" | "rst" | "doc" | "docx" | "odt" | "rtf" | "xls" | "xlsx"
        | "ods" | "ppt" | "pptx" | "odp" => "document",
        "rs" | "js" | "ts" | "tsx" | "jsx" | "py" | "php" | "rb" | "go" | "c" | "cpp" | "h"
        | "html" | "css" | "json" | "yaml" | "yml" | "toml" | "sh" | "sql" | "xml" | "java"
        | "swift" | "kt" => "code",
        _ => "other",
    }
}

#[derive(Default, Debug)]
struct SearchQuery {
    terms: Vec<String>,
    types: Vec<String>,
    extensions: Vec<String>,
    sizes: Vec<(&'static str, i64)>,
    dates: Vec<(&'static str, i64)>,
}

impl SearchQuery {
    fn parse(raw: &str) -> Result<Self, AppError> {
        if raw.len() > MAX_QUERY_BYTES || raw.chars().any(char::is_control) {
            return Err(AppError::InvalidRequest);
        }
        let mut tokens = Vec::new();
        let mut token = String::new();
        let mut quoted = false;
        let mut literal = false;
        for c in raw.chars() {
            if c == '"' {
                if token.is_empty() {
                    literal = true;
                }
                quoted = !quoted;
            } else if c.is_whitespace() && !quoted {
                if !token.is_empty() {
                    tokens.push((std::mem::take(&mut token), literal));
                    literal = false;
                }
            } else {
                token.push(c);
            }
        }
        if quoted {
            return Err(AppError::InvalidRequest);
        }
        if !token.is_empty() {
            tokens.push((token, literal));
        }
        if tokens.len() > 32 {
            return Err(AppError::InvalidRequest);
        }
        let mut query = Self::default();
        for (token, literal) in tokens {
            let token = normalize(&token);
            if literal {
                query.terms.push(token);
                continue;
            }
            if let Some(value) = token.strip_prefix("type:") {
                if ![
                    "pdf", "image", "video", "audio", "document", "code", "folder", "other", "file",
                ]
                .contains(&value)
                {
                    return Err(AppError::InvalidRequest);
                }
                query.types.push(value.to_owned());
            } else if let Some(value) = token.strip_prefix("ext:") {
                if value.is_empty()
                    || value.len() > 32
                    || !value.chars().all(|c| c.is_ascii_alphanumeric())
                {
                    return Err(AppError::InvalidRequest);
                }
                query.extensions.push(value.to_owned());
            } else if let Some(value) = token.strip_prefix("size:") {
                let (operator, value) = comparison(value);
                let split = value
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(value.len());
                let number = value[..split]
                    .parse::<i64>()
                    .map_err(|_| AppError::InvalidRequest)?;
                let multiplier = match &value[split..] {
                    "" | "b" => 1,
                    "kb" => 1000,
                    "mb" => 1_000_000,
                    "gb" => 1_000_000_000,
                    "kib" => 1024,
                    "mib" => 1024 * 1024,
                    "gib" => 1024 * 1024 * 1024,
                    _ => return Err(AppError::InvalidRequest),
                };
                query.sizes.push((
                    operator,
                    number
                        .checked_mul(multiplier)
                        .ok_or(AppError::InvalidRequest)?,
                ));
            } else if let Some(value) = token.strip_prefix("modified:") {
                let (operator, value) = comparison(value);
                let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
                    .map_err(|_| AppError::Internal)?;
                let date =
                    time::Date::parse(value, &format).map_err(|_| AppError::InvalidRequest)?;
                query
                    .dates
                    .push((operator, date.midnight().assume_utc().unix_timestamp()));
            } else {
                if token.contains(':') {
                    return Err(AppError::InvalidRequest);
                }
                query.terms.push(token);
            }
        }
        Ok(query)
    }
}

fn comparison(value: &str) -> (&'static str, &str) {
    for operator in [">=", "<=", ">", "<", "="] {
        if let Some(rest) = value.strip_prefix(operator) {
            return (operator, rest);
        }
    }
    ("=", value)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestQuery {
    #[serde(default)]
    q: String,
    share: Option<String>,
    #[serde(default)]
    path: String,
    #[serde(default)]
    show_hidden: bool,
    limit: Option<usize>,
    offset: Option<usize>,
    #[serde(default)]
    count: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchEntry {
    share_id: String,
    path: String,
    name: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchPage {
    entries: Vec<SearchEntry>,
    indexing: bool,
    incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_offset: Option<usize>,
    /// Pages of indexed candidates, up to the page at the largest offset;
    /// only when the request asks for a count.
    #[serde(skip_serializing_if = "Option::is_none")]
    page_count: Option<usize>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/search", get(search))
}

async fn search(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiQuery(request): ApiQuery<RequestQuery>,
) -> Result<Response, AppError> {
    let service = state.search().ok_or(AppError::FeatureDisabled)?.clone();
    let limit = request.limit.unwrap_or(8);
    let offset = request.offset.unwrap_or(0);
    if !(1..=100).contains(&limit)
        || offset > MAX_OFFSET
        || (request.share.is_none() && !request.path.is_empty())
    {
        return Err(AppError::InvalidRequest);
    }
    let path = if request.path.is_empty() {
        VirtualPath::root()
    } else {
        VirtualPath::parse(&request.path).map_err(|_| AppError::InvalidRequest)?
    };
    let query = SearchQuery::parse(&request.q)?;
    let mut allowed = HashMap::new();
    for configured in state.browse().configured_shares() {
        if request
            .share
            .as_ref()
            .is_some_and(|s| s != configured.id().as_str())
        {
            continue;
        }
        if let Ok(view) = state.browse().authorize_owned(&identity, configured.id())
            && service.shares.contains_key(configured.id().as_str())
        {
            allowed.insert(configured.id().to_string(), view);
        }
    }
    if request.share.is_some() && allowed.is_empty() {
        return Err(AppError::NotFound);
    }
    let lease = service
        .gate
        .try_acquire(identity.subject())
        .ok_or(AppError::Busy)?;
    let result = crate::browse::run_blocking(move || {
        let _lease = lease;
        service.query(
            &allowed,
            &path,
            &query,
            request.show_hidden,
            Paging {
                limit,
                offset,
                count: request.count,
            },
        )
    })
    .await??;
    let mut response = Json(result).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, private"),
    );
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

/// One page of results, and whether to count the pages of candidates.
struct Paging {
    limit: usize,
    offset: usize,
    count: bool,
}

impl SearchService {
    fn query(
        &self,
        allowed: &HashMap<String, OwnedAuthorizedShare>,
        path: &VirtualPath,
        query: &SearchQuery,
        hidden: bool,
        Paging {
            limit,
            offset,
            count,
        }: Paging,
    ) -> Result<SearchPage, AppError> {
        let indexing = allowed.keys().any(|id| {
            let share = &self.shares[id];
            share.indexing.load(Ordering::Acquire)
                || (share.invalidated.load(Ordering::Acquire)
                    && share.polling.load(Ordering::Acquire))
        });
        let incomplete = allowed
            .keys()
            .any(|id| !self.shares[id].complete.load(Ordering::Acquire));
        let mut page = SearchPage {
            entries: Vec::new(),
            indexing,
            incomplete,
            next_offset: None,
            page_count: None,
        };
        if allowed.is_empty() {
            return Ok(page);
        }
        if allowed.len() > 1024 {
            return Err(AppError::TooLarge);
        }
        // The filter is shared by the page query and the optional count.
        let mut sql = String::from("FROM entries e WHERE e.share IN (");
        let mut values: Vec<Value> = Vec::new();
        for id in allowed.keys() {
            if !values.is_empty() {
                sql.push(',');
            }
            sql.push('?');
            values.push(id.clone().into());
        }
        sql.push(')');
        if !path.to_string().is_empty() {
            // A range on the (share, path) index: "/" sorts immediately before "0".
            sql.push_str(" AND e.path>=? AND e.path<?");
            values.push(format!("{path}/").into());
            values.push(format!("{path}0").into());
        }
        if !hidden {
            sql.push_str(" AND e.path NOT GLOB '.*' AND e.path NOT GLOB '*/.*'");
        }
        for term in &query.terms {
            if term.chars().count() >= 3 {
                sql.push_str(" AND e.id IN (SELECT rowid FROM names WHERE names MATCH ?)");
                values.push(format!("\"{}\"", term.replace('"', "\"\"")).into());
            } else {
                sql.push_str(" AND instr(e.normalized,?)>0");
                values.push(term.clone().into());
            }
        }
        if !query.types.is_empty() {
            sql.push_str(" AND (");
            for (i, category) in query.types.iter().enumerate() {
                if i != 0 {
                    sql.push_str(" OR ");
                }
                if category == "file" {
                    sql.push_str("e.kind='file'");
                } else {
                    sql.push_str("e.category=?");
                    values.push(category.clone().into());
                }
            }
            sql.push(')');
        }
        if !query.extensions.is_empty() {
            sql.push_str(" AND e.extension IN (");
            for (i, ext) in query.extensions.iter().enumerate() {
                if i != 0 {
                    sql.push(',');
                }
                sql.push('?');
                values.push(ext.clone().into());
            }
            sql.push(')');
        }
        for (column, filters) in [("size", &query.sizes), ("modified", &query.dates)] {
            for (operator, value) in filters {
                sql.push_str(&format!(" AND e.{column}{operator}?"));
                values.push((*value).into());
            }
        }
        // Counting stops at the page holding the largest offset, so the count
        // costs at most one more bounded scan of the matches.
        let count = count.then(|| {
            let mut values = values.clone();
            values.push(((MAX_OFFSET + limit) as i64).into());
            (
                format!("SELECT count(*) FROM (SELECT 1 {sql} LIMIT ?)"),
                values,
            )
        });
        let needle = query.terms.join(" ");
        let sql = format!(
            "SELECT e.share,e.path,e.name,e.kind,e.size,e.modified {sql} ORDER BY CASE WHEN e.normalized=? THEN 0 WHEN instr(e.normalized,?)=1 THEN 1 ELSE 2 END,e.normalized,e.share,e.path LIMIT ? OFFSET ?"
        );
        values.extend([
            needle.clone().into(),
            needle.into(),
            ((limit + 1) as i64).into(),
            (offset as i64).into(),
        ]);
        // The gate admits at most READERS searches, so a free reader exists
        // unless a caller bypassed it.
        let connection = self
            .readers
            .iter()
            .find_map(|reader| match reader.try_lock() {
                Ok(connection) => Some(connection),
                Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => None,
            })
            .ok_or(AppError::Busy)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        connection
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(|_| AppError::Internal)?;
        type Candidate = (String, String, String, String, Option<i64>, Option<i64>);
        let candidates = (|| -> Result<(Vec<Candidate>, Option<usize>), rusqlite::Error> {
            let candidates = connection
                .prepare(&sql)?
                .query_map(rusqlite::params_from_iter(values), |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;
            let total = match count {
                Some((sql, values)) => Some(connection.query_row(
                    &sql,
                    rusqlite::params_from_iter(values),
                    |r| r.get::<_, i64>(0),
                )?),
                None => None,
            };
            Ok((
                candidates,
                total.map(|total| usize::try_from(total).unwrap_or(0)),
            ))
        })();
        connection
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|_| AppError::Internal)?;
        let (candidates, total) = candidates.map_err(query_error)?;
        drop(connection);
        // Only the first page is validated; the rest only says that more
        // pages exist, up to the largest offset a request may ask for.
        if candidates.len() > limit && offset + limit <= MAX_OFFSET {
            page.next_offset = Some(offset + limit);
        }
        // Like pages, the count is of indexed candidates, not validated matches.
        page.page_count = total.map(|total| total.div_ceil(limit).max(1));
        for (id, path, name, kind, _, _) in candidates.into_iter().take(limit) {
            let Ok(virtual_path) = VirtualPath::parse(&path) else {
                continue;
            };
            let Ok(metadata) = allowed[&id].view().metadata(&virtual_path) else {
                continue;
            };
            if (metadata.kind == EntryKind::Directory) != (kind == "directory") {
                continue;
            }
            // Recheck size/date filters against live metadata; indexed candidates are hints.
            let size = if metadata.kind == EntryKind::File {
                Some(metadata.size)
            } else {
                None
            };
            let modified = unix_seconds(metadata.modified);
            if !query.sizes.iter().all(|(op, n)| {
                size.and_then(|s| i64::try_from(s).ok())
                    .is_some_and(|s| compare(s, op, *n))
            }) || !query
                .dates
                .iter()
                .all(|(op, n)| modified.is_some_and(|s| compare(s, op, *n)))
            {
                continue;
            }
            page.entries.push(SearchEntry {
                share_id: id,
                path,
                name,
                kind,
                size,
                modified: modified
                    .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
                    .and_then(|t| {
                        t.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    }),
            });
        }
        Ok(page)
    }
}

fn compare(value: i64, operator: &str, target: i64) -> bool {
    match operator {
        ">" => value > target,
        ">=" => value >= target,
        "<" => value < target,
        "<=" => value <= target,
        _ => value == target,
    }
}

/// The one-second budget interrupts a query, which is load; anything else is
/// a fault and is logged without query details.
fn query_error(error: rusqlite::Error) -> AppError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted) {
        AppError::Busy
    } else {
        tracing::error!("search index query failed");
        AppError::Internal
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "tests create synthetic filesystem fixtures"
)]
mod tests {
    use super::*;
    use crate::{
        app,
        browse::{BrowseLimits, ConfiguredShare},
        filesystem::{AccessLevel, GlobalPolicy, ShareFs, ShareGrant},
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use std::{fs, os::unix::fs::symlink};
    use tower::ServiceExt;

    struct Fixture {
        _directory: tempfile::TempDir,
        root: std::path::PathBuf,
        service: Arc<SearchService>,
        state: AppState,
        identity: AuthenticatedIdentity,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_slice(WORK_SLICE)
        }
        fn with_slice(slice: Duration) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("documents");
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("reports")).unwrap();
            fs::write(root.join("reports/invoice.pdf"), vec![0_u8; 12_000]).unwrap();
            fs::write(root.join("invoice.txt"), b"text").unwrap();
            fs::write(root.join(".hidden.pdf"), b"hidden").unwrap();
            fs::write(root.join("résumé.pdf"), b"unicode").unwrap();
            let other = directory.path().join("private");
            fs::create_dir(&other).unwrap();
            fs::write(other.join("secret.pdf"), b"private").unwrap();
            let configured = vec![
                ConfiguredShare::new(
                    "Documents",
                    ShareFs::open(ShareId::new("documents").unwrap(), &root).unwrap(),
                )
                .unwrap(),
                ConfiguredShare::new(
                    "Private",
                    ShareFs::open(ShareId::new("private").unwrap(), &other).unwrap(),
                )
                .unwrap(),
            ];
            let views = configured
                .iter()
                .map(|s| (s.id().to_string(), s.id().to_string(), s.index_view()))
                .collect();
            let index = directory.path().join("search.sqlite3");
            let mut service =
                SearchService::initialize(open_private_database(&index).unwrap(), views, || {
                    open_reader(&index)
                })
                .unwrap();
            service.slice = slice;
            let service = Arc::new(service);
            let browse = BrowseState::new(
                configured,
                BrowseLimits::default(),
                GlobalPolicy::default(),
                [42; 32],
            )
            .unwrap();
            let identity = AuthenticatedIdentity::new(
                "reader",
                vec![ShareGrant {
                    share_id: ShareId::new("documents").unwrap(),
                    access: AccessLevel::ReadOnly,
                }],
            );
            let state = AppState::new(true)
                .with_browse(browse)
                .with_search(service.clone());
            let fixture = Self {
                _directory: directory,
                root,
                service,
                state,
                identity,
            };
            fixture.settle("documents");
            fixture.settle("private");
            fixture
        }
        /// Runs the worker for one share until no queued work remains.
        fn settle(&self, id: &str) {
            while self.service.step(id, 32).unwrap() {}
        }
        /// Applies pending change notifications without waiting for them to settle.
        fn notify(&self, id: &str) {
            {
                let mut work = self.service.shares[id].work.lock().unwrap();
                SearchService::drain_events(&mut work);
                let past = Instant::now() - EVENT_MAX_DELAY;
                if work.first_event.is_some() {
                    work.first_event = Some(past);
                }
            }
            self.settle(id);
        }
        fn full_pass(&self, id: &str) {
            self.service.shares[id].work.lock().unwrap().last_full_pass = None;
            self.settle(id);
        }
        fn changes(&self) -> i64 {
            self.service
                .writer
                .lock()
                .unwrap()
                .connection
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap()
        }
        async fn request(&self, query: &str, identity: bool) -> (StatusCode, serde_json::Value) {
            let mut request = Request::get(format!("/api/v1/search?{query}"))
                .body(Body::empty())
                .unwrap();
            if identity {
                request.extensions_mut().insert(self.identity.clone());
            }
            let response = app::router(self.state.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert!(
                response.headers()["cache-control"]
                    .to_str()
                    .unwrap()
                    .contains("no-store")
            );
            let status = response.status();
            (
                status,
                serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap())
                    .unwrap(),
            )
        }
        async fn names(&self, query: &str) -> Vec<String> {
            let (status, result) = self.request(query, true).await;
            assert_eq!(status, StatusCode::OK, "{result}");
            result["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["path"].as_str().unwrap().to_owned())
                .collect()
        }
    }

    #[test]
    fn parses_filters_and_rejects_invalid_or_unbounded_queries() {
        let query = SearchQuery::parse("\"annual report\" type:pdf type:image size:>=10kb size:<1mib modified:>=2026-01-01 ext:pdf").unwrap();
        assert_eq!(query.terms, vec!["annual report"]);
        assert_eq!(query.sizes, vec![(">=", 10000), ("<", 1048576)]);
        for invalid in [
            "size:>bad",
            "size:>999999999999999999gb",
            "type:nope",
            "ext:",
            "modified:2026-99-01",
            "\"unfinished",
            "unknown:filter",
        ] {
            assert!(SearchQuery::parse(invalid).is_err(), "{invalid}");
        }
        assert!(SearchQuery::parse(&"a".repeat(1025)).is_err());
    }

    #[tokio::test]
    async fn search_enforces_grants_filters_scope_hidden_and_short_unicode_queries() {
        let fixture = Fixture::new();
        let (status, result) = fixture
            .request("q=invoice%20type:pdf%20size:%3E10kb", true)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["entries"].as_array().unwrap().len(), 1);
        assert_eq!(result["entries"][0]["path"], "reports/invoice.pdf");
        assert_eq!(result["indexing"], false);
        assert_eq!(result["incomplete"], false);
        assert_eq!(
            fixture
                .names("q=type:pdf&share=documents&path=reports")
                .await,
            ["reports/invoice.pdf"]
        );
        // The folder scope covers descendants only, not siblings sharing its prefix.
        fs::create_dir(fixture.root.join("reports-old")).unwrap();
        fs::write(fixture.root.join("reports-old/invoice.pdf"), b"old").unwrap();
        fixture.full_pass("documents");
        assert_eq!(
            fixture
                .names("q=invoice&share=documents&path=reports")
                .await,
            ["reports/invoice.pdf"]
        );
        let (_, result) = fixture.request("q=&showHidden=true", true).await;
        assert!(!result.to_string().contains("secret.pdf"));
        assert!(result.to_string().contains(".hidden.pdf"));
        assert_eq!(fixture.names("q=R%C3%89S").await, ["résumé.pdf"]);
        // A decomposed query (e + combining acute accent) matches the NFC name.
        assert_eq!(fixture.names("q=re%CC%81sume%CC%81").await, ["résumé.pdf"]);
        assert_eq!(fixture.names("q=in").await.len(), 3);
        assert_eq!(
            fixture.request("share=private", true).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            fixture.request("share=missing", true).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            fixture.request("q=invoice", false).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            fixture.request("q=size:bad", true).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            fixture.request("limit=101", true).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            fixture.request("path=reports", true).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn stale_links_aliases_and_internal_entries_never_escape_through_search() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.root.join("reports/invoice.pdf")).unwrap();
        symlink(
            "../../private/secret.pdf",
            fixture.root.join("reports/invoice.pdf"),
        )
        .unwrap();
        fs::hard_link(
            fixture.root.join("invoice.txt"),
            fixture.root.join("alias.txt"),
        )
        .unwrap();
        let (_, result) = fixture.request("q=invoice", true).await;
        assert!(result["entries"].as_array().unwrap().is_empty());
        fixture.full_pass("documents");
        let (_, result) = fixture.request("q=&showHidden=true", true).await;
        assert!(!result.to_string().contains(".crabinet"));
        assert!(!result.to_string().contains("alias.txt"));
    }

    #[tokio::test]
    async fn notifications_refresh_only_changed_directories_after_they_settle() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("new.pdf"), b"new").unwrap();
        // Unsettled notifications wait, and the share reports indexing meanwhile.
        fixture.settle("documents");
        assert!(fixture.names("q=new").await.is_empty());
        assert_eq!(fixture.request("q=new", true).await.1["indexing"], true);
        fixture.notify("documents");
        assert_eq!(fixture.names("q=new").await, ["new.pdf"]);
        assert_eq!(fixture.request("q=new", true).await.1["indexing"], false);

        fs::rename(
            fixture.root.join("new.pdf"),
            fixture.root.join("renamed.pdf"),
        )
        .unwrap();
        // A folder created with contents is indexed recursively.
        fs::create_dir_all(fixture.root.join("drop/inner")).unwrap();
        fs::write(fixture.root.join("drop/inner/deep.pdf"), b"deep").unwrap();
        // Removing a folder removes everything that was indexed beneath it.
        fs::remove_dir_all(fixture.root.join("reports")).unwrap();
        fixture.notify("documents");
        assert!(fixture.names("q=new").await.is_empty());
        assert_eq!(fixture.names("q=renamed").await, ["renamed.pdf"]);
        assert_eq!(fixture.names("q=deep").await, ["drop/inner/deep.pdf"]);
        assert_eq!(fixture.names("q=invoice").await, ["invoice.txt"]);

        // A file changed inside a subfolder refreshes that folder only.
        fs::write(fixture.root.join("drop/inner/deep.pdf"), vec![0_u8; 20_000]).unwrap();
        fixture.notify("documents");
        assert_eq!(
            fixture.names("q=deep%20size:%3E10kb").await,
            ["drop/inner/deep.pdf"]
        );
    }

    #[tokio::test]
    async fn unchanged_entries_are_not_rewritten_and_mutations_rely_on_watches() {
        let fixture = Fixture::new();
        let before = fixture.changes();
        fixture.full_pass("documents");
        assert_eq!(fixture.changes(), before);
        // A fully watched share leaves mutations to its notifications, and
        // reports indexing only until the worker has taken them in.
        fixture
            .service
            .invalidate(&ShareId::new("documents").unwrap());
        assert_eq!(fixture.request("q=x", true).await.1["indexing"], true);
        fixture.settle("documents");
        assert_eq!(fixture.request("q=x", true).await.1["indexing"], false);
        assert!(
            !fixture.service.shares["documents"]
                .work
                .lock()
                .unwrap()
                .full_requested
        );
        // Without complete watches, a mutation schedules a full pass.
        fixture.service.shares["documents"]
            .polling
            .store(true, Ordering::Release);
        fixture
            .service
            .invalidate(&ShareId::new("documents").unwrap());
        assert_eq!(fixture.request("q=x", true).await.1["indexing"], true);
    }

    #[tokio::test]
    async fn an_interrupted_pass_resumes_and_prunes_what_it_visited() {
        let fixture = Fixture::with_slice(Duration::ZERO);
        fs::remove_file(fixture.root.join("invoice.txt")).unwrap();
        fs::create_dir_all(fixture.root.join("a/b/c")).unwrap();
        fs::write(fixture.root.join("a/b/c/leaf.pdf"), b"leaf").unwrap();
        fixture.service.shares["documents"]
            .work
            .lock()
            .unwrap()
            .last_full_pass = None;
        // A zero slice lists one directory per step: the root first.
        assert!(fixture.service.step("documents", 32).unwrap());
        assert_eq!(fixture.names("q=invoice").await, ["reports/invoice.pdf"]);
        assert!(fixture.names("q=leaf").await.is_empty());
        // A periodic pass over a current index is not reported as indexing.
        assert_eq!(fixture.request("q=x", true).await.1["indexing"], false);
        fixture.settle("documents");
        assert_eq!(fixture.names("q=leaf").await, ["a/b/c/leaf.pdf"]);
        assert_eq!(fixture.request("q=x", true).await.1["incomplete"], false);
    }

    #[tokio::test]
    #[expect(
        clippy::await_holding_lock,
        reason = "holds the indexer's connection to prove queries do not need it"
    )]
    async fn queries_do_not_wait_for_the_indexer_and_overload_is_explicit() {
        let fixture = Fixture::new();
        let writer = fixture.service.writer.lock().unwrap();
        assert_eq!(fixture.names("q=invoice").await.len(), 2);
        drop(writer);
        let (_, result) = fixture.request("q=&limit=1", true).await;
        assert_eq!(result["nextOffset"], 1);
        // Only a request for a count gets a page count, of indexed candidates.
        assert!(result.get("pageCount").is_none());
        let (_, all) = fixture.request("q=&limit=100&showHidden=true", true).await;
        let total = all["entries"].as_array().unwrap().len();
        let (_, result) = fixture
            .request("q=&limit=2&showHidden=true&count=true", true)
            .await;
        assert_eq!(result["pageCount"], total.div_ceil(2));
        let (_, result) = fixture.request("q=nothing&count=true", true).await;
        assert_eq!(result["pageCount"], 1);
        let (_, result) = fixture.request("q=&limit=1&offset=10000", true).await;
        assert!(result.get("nextOffset").is_none());
        fixture.service.shares["documents"]
            .complete
            .store(false, Ordering::Release);
        assert_eq!(
            fixture.request("q=invoice", true).await.1["incomplete"],
            true
        );
        let _one = fixture.service.gate.try_acquire("reader").unwrap();
        let _two = fixture.service.gate.try_acquire("reader").unwrap();
        assert_eq!(
            fixture.request("q=invoice", true).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn index_schema_is_reusable_rebuilds_old_layouts_and_refuses_unrelated_databases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("search.sqlite3");
        let open = || {
            SearchService::initialize(open_private_database(&path).unwrap(), vec![], || {
                open_reader(&path)
            })
        };
        drop(open().unwrap());
        assert!(open().is_ok());
        let old = open_private_database(&path).unwrap();
        old.execute_batch(
            "PRAGMA user_version=1; ALTER TABLE entries ADD COLUMN generation INTEGER;",
        )
        .unwrap();
        drop(old);
        drop(open().unwrap());
        let rebuilt = open_private_database(&path).unwrap();
        let columns: i64 = rebuilt
            .query_row(
                "SELECT count(*) FROM pragma_table_info('entries') WHERE name='generation'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(columns, 0);
        let unrelated = Connection::open_in_memory().unwrap();
        unrelated
            .execute("CREATE TABLE account (id INTEGER)", [])
            .unwrap();
        assert!(SearchService::initialize(unrelated, vec![], Connection::open_in_memory).is_err());
        let newer = Connection::open_in_memory().unwrap();
        newer
            .execute_batch("PRAGMA application_id=1129468744; PRAGMA user_version=3;")
            .unwrap();
        assert!(SearchService::initialize(newer, vec![], Connection::open_in_memory).is_err());
    }

    #[test]
    fn private_database_refuses_symlinks_aliases_and_public_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("search.sqlite3");
        drop(open_private_database(&path).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open_private_database(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = directory.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(open_private_database(&alias).is_err());
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(open_private_database(&link).is_err());
    }
}

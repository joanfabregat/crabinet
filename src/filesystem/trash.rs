//! Private, capability-scoped Trash storage.

use std::{
    io::{Read, Write},
    mem::MaybeUninit,
    time::{Duration, SystemTime},
};

use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AuthorizedShare, DIRECTORY_QUOTA_BYTES, EntryKind, EntryMetadata, FsError, FsErrorCode,
    FsResult, MAX_PATH_DEPTH, ShareFs, UsageError, UsageScan, VirtualPath,
    assert_no_external_alias, classify_metadata, ensure_same_device, ensure_subtree_within, map_io,
    measure_directory, metadata_in_parent_raw, random_internal_name, secure_file_options,
    sync_after_commit, sync_directory,
};

const CONTAINER: &str = ".crabinet";
const TRASH: &str = "trash";
const MAX_SIDECAR_BYTES: u64 = 8192;
const SIDECAR_SCHEMA_VERSION: u8 = 1;
/// A Trash payload sits one level below the share root when restored there,
/// so walks inside a payload start at this virtual depth.
const PAYLOAD_DEPTH: usize = 1;

/// Where a Trash listing page ends: the last item's deletion time and ID in
/// listing order (newest first, then by ID).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrashPosition {
    pub deleted_at: String,
    pub id: String,
}

/// One page of a Trash listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrashPage {
    pub items: Vec<TrashEntry>,
    /// Whether further items follow the last one in `items`.
    pub has_more: bool,
    /// Items left out because their sidecar or payload was unreadable,
    /// inconsistent, or removed while the listing ran.
    pub skipped: usize,
}

/// The result of one bounded Trash collection batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrashGcBatch {
    /// Items whose payload and sidecar are now gone.
    pub purged: usize,
    /// Whether this batch reached the end of the Trash directory, so the
    /// current sweep is complete.
    pub finished: bool,
}

fn listing_order(left: &TrashEntry, right: &TrashEntry) -> std::cmp::Ordering {
    right
        .deleted_at
        .cmp(&left.deleted_at)
        .then_with(|| left.id.cmp(&right.id))
}

/// Whether `entry` comes strictly after `position` in listing order.
fn is_after(entry: &TrashEntry, position: &TrashPosition) -> bool {
    position
        .deleted_at
        .cmp(&entry.deleted_at)
        .then_with(|| entry.id.cmp(&position.id))
        == std::cmp::Ordering::Greater
}

/// A published Trash item. Time fields are UTC RFC 3339 strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrashEntry {
    pub id: String,
    pub original_path: VirtualPath,
    pub kind: EntryKind,
    pub deleted_at: String,
    pub deleted_by: String,
    pub expires_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Pending,
    Live,
    Purging,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Sidecar {
    schema_version: u8,
    id: String,
    original_path: String,
    kind: String,
    deleted_at: String,
    deleted_by: String,
    expires_at: String,
    state: State,
}

impl Sidecar {
    fn entry(&self) -> FsResult<TrashEntry> {
        Ok(TrashEntry {
            id: self.id.clone(),
            original_path: VirtualPath::parse_stored(&self.original_path)?,
            kind: match self.kind.as_str() {
                "file" => EntryKind::File,
                "directory" => EntryKind::Directory,
                _ => return Err(FsError::new(FsErrorCode::Unavailable)),
            },
            deleted_at: self.deleted_at.clone(),
            deleted_by: self.deleted_by.clone(),
            expires_at: self.expires_at.clone(),
        })
    }
}

pub(super) fn open_trash_directory(root: &Dir) -> FsResult<Dir> {
    let container = open_private_directory(root, CONTAINER)?;
    open_private_directory(&container, TRASH)
}

pub(super) fn open_existing_trash_directory(root: &Dir) -> FsResult<Option<Dir>> {
    let container = match root.open_dir_nofollow(CONTAINER) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_io(error)),
    };
    match container.open_dir_nofollow(TRASH) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(map_io(error)),
    }
}

/// Read one bounded batch from an independent directory descriptor. Linux
/// directory cookies let the next GC pass continue without rescanning a
/// potentially large prefix. EOF resets the cursor for the next sweep.
fn gc_batch(trash: &Dir, cookie: &mut u64, max_entries: usize) -> FsResult<Vec<String>> {
    let descriptor = rustix::fs::openat(
        trash,
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| map_io(error.into()))?;
    if *cookie != 0 && rustix::fs::seek(&descriptor, rustix::fs::SeekFrom::Start(*cookie)).is_err()
    {
        *cookie = 0;
    }
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let mut reader = rustix::fs::RawDir::new(&descriptor, &mut buffer);
    let mut names = Vec::with_capacity(max_entries.min(256));
    while names.len() < max_entries {
        let Some(entry) = reader.next() else {
            *cookie = 0;
            break;
        };
        let entry = entry.map_err(|error| map_io(error.into()))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
        *cookie = entry.next_entry_cookie();
        if matches!(name, "." | "..") {
            continue;
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn open_private_directory(parent: &Dir, name: &str) -> FsResult<Dir> {
    let created = match rustix::fs::mkdirat(parent, name, rustix::fs::Mode::RWXU) {
        Ok(()) => true,
        Err(error) if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {
            false
        }
        Err(error) => return Err(map_io(error.into())),
    };
    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| map_io(error.into()))?;
    rustix::fs::fchmod(&descriptor, rustix::fs::Mode::RWXU)
        .map_err(|error| map_io(error.into()))?;
    let child = parent.open_dir_nofollow(name).map_err(map_io)?;
    if created {
        sync_directory(&child)?;
        sync_directory(parent)?;
    }
    Ok(child)
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sidecar_name(id: &str) -> String {
    format!("{id}.json")
}

fn write_sidecar(trash: &Dir, sidecar: &Sidecar, replace: bool) -> FsResult<()> {
    let bytes = serde_json::to_vec(sidecar).map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
    if bytes.len() as u64 > MAX_SIDECAR_BYTES {
        return Err(FsError::new(FsErrorCode::TooLarge));
    }
    let temp = random_internal_name(".tmp-")?;
    let mut options = secure_file_options();
    options.write(true).create_new(true);
    let mut file = trash.open_with(&temp, &options).map_err(map_io)?;
    let result = (|| {
        file.write_all(&bytes).map_err(map_io)?;
        file.sync_all().map_err(map_io)?;
        let flags = if replace {
            rustix::fs::RenameFlags::empty()
        } else {
            rustix::fs::RenameFlags::NOREPLACE
        };
        rustix::fs::renameat_with(trash, &temp, trash, sidecar_name(&sidecar.id), flags)
            .map_err(|error| map_io(error.into()))?;
        sync_after_commit(trash);
        Ok(())
    })();
    if result.is_err() {
        let _ = trash.remove_file(&temp);
    }
    result
}

fn read_sidecar(trash: &Dir, id: &str) -> FsResult<Sidecar> {
    if !valid_id(id) {
        return Err(FsError::new(FsErrorCode::InvalidPath));
    }
    let mut options = secure_file_options();
    options.read(true);
    let mut file = trash
        .open_with(sidecar_name(id), &options)
        .map_err(map_io)?;
    let meta = file.metadata().map_err(map_io)?;
    if !meta.is_file() || meta.len() > MAX_SIDECAR_BYTES {
        return Err(FsError::new(FsErrorCode::Unavailable));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_SIDECAR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    let sidecar: Sidecar =
        serde_json::from_slice(&bytes).map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
    if sidecar.id != id {
        return Err(FsError::new(FsErrorCode::Unavailable));
    }
    if sidecar.schema_version != SIDECAR_SCHEMA_VERSION {
        return Err(FsError::new(FsErrorCode::Unavailable));
    }
    sidecar.entry()?;
    OffsetDateTime::parse(&sidecar.expires_at, &Rfc3339)
        .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
    Ok(sidecar)
}

fn payload_metadata(trash: &Dir, id: &str) -> FsResult<EntryMetadata> {
    metadata_in_parent_raw(trash, id)
}

/// Reads one sidecar for a listing. `None` means the item is skipped and
/// counted; `Some(None)` means it is not published (pending or purging).
fn listable_item(trash: &Dir, id: &str) -> Option<Option<TrashEntry>> {
    let sidecar = match read_sidecar(trash, id) {
        Ok(sidecar) => sidecar,
        // Restored or purged between reading the directory and the sidecar.
        Err(error) if error.code() == FsErrorCode::NotFound => return None,
        Err(_) => {
            tracing::warn!(
                trash_id = id,
                "skipping a Trash item whose sidecar is unreadable"
            );
            return None;
        }
    };
    if sidecar.state != State::Live {
        return Some(None);
    }
    let Ok(entry) = sidecar.entry() else {
        tracing::warn!(
            trash_id = id,
            "skipping a Trash item whose sidecar is unreadable"
        );
        return None;
    };
    // A cursor carries the deletion time, so only well-formed times are listed.
    if OffsetDateTime::parse(&entry.deleted_at, &Rfc3339).is_err() {
        tracing::warn!(
            trash_id = id,
            "skipping a Trash item with an invalid deletion time"
        );
        return None;
    }
    match payload_metadata(trash, id) {
        Ok(payload) if payload.kind == entry.kind => Some(Some(entry)),
        Ok(_) => {
            tracing::warn!(
                trash_id = id,
                "skipping a Trash item whose payload kind does not match its sidecar"
            );
            None
        }
        Err(error) if error.code() == FsErrorCode::NotFound => {
            // Either a restore is between moving the payload and removing
            // the sidecar, or the payload is gone.
            tracing::warn!(
                trash_id = id,
                "skipping a Trash item whose payload is missing"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                trash_id = id,
                "skipping a Trash item whose payload is unreadable"
            );
            None
        }
    }
}

fn format_time(time: SystemTime) -> FsResult<String> {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| FsError::new(FsErrorCode::Unavailable))?
        .as_secs();
    let timestamp = OffsetDateTime::from_unix_timestamp(
        i64::try_from(seconds).map_err(|_| FsError::new(FsErrorCode::Unavailable))?,
    )
    .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
    timestamp
        .format(&Rfc3339)
        .map_err(|_| FsError::new(FsErrorCode::Unavailable))
}

impl AuthorizedShare<'_> {
    /// Moves a file or nonempty directory into Trash under a random opaque ID.
    pub fn move_to_trash(
        &self,
        path: &VirtualPath,
        expected: EntryMetadata,
        deleted_by: &str,
        retention_days: u16,
    ) -> FsResult<TrashEntry> {
        self.require_write()?;
        if deleted_by.is_empty()
            || deleted_by.len() > 256
            || deleted_by.chars().any(char::is_control)
            || retention_days == 0
        {
            return Err(FsError::new(FsErrorCode::InvalidPath));
        }
        let current = self.metadata(path)?;
        if !current.matches_validator(&expected) {
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        let trash = self
            .share
            .trash
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?;
        // A tree already nested deeper than the limit could be trashed but
        // never measured, restored or purged, so it is refused before
        // anything changes, with the same bounded walk a deeper move uses.
        if current.kind == EntryKind::Directory {
            let directory = self.share.open_directory(&path.0)?;
            ensure_subtree_within(
                &directory,
                MAX_PATH_DEPTH.saturating_sub(path.depth()),
                &mut 0,
            )?;
        }
        let (parent, name) = self.share.open_parent(path)?;
        ensure_same_device(trash, &parent)?;
        let now = SystemTime::now();
        let expires = now
            .checked_add(Duration::from_secs(u64::from(retention_days) * 86400))
            .ok_or_else(|| FsError::new(FsErrorCode::Unavailable))?;
        for _ in 0..16 {
            let id = random_internal_name("")?;
            if trash.exists(&id) || trash.exists(sidecar_name(&id)) {
                continue;
            }
            let mut sidecar = Sidecar {
                schema_version: SIDECAR_SCHEMA_VERSION,
                id,
                original_path: path.to_string(),
                kind: match expected.kind {
                    EntryKind::File => "file",
                    EntryKind::Directory => "directory",
                }
                .into(),
                deleted_at: format_time(now)?,
                deleted_by: deleted_by.into(),
                expires_at: format_time(expires)?,
                state: State::Pending,
            };
            match write_sidecar(trash, &sidecar, false) {
                Err(error) if error.code() == FsErrorCode::Conflict => continue,
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            if let Err(error) = rustix::fs::renameat_with(
                &parent,
                name.as_str(),
                trash,
                &sidecar.id,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                trash
                    .remove_file(sidecar_name(&sidecar.id))
                    .map_err(map_io)?;
                sync_after_commit(trash);
                return Err(map_io(error.into()));
            }
            let moved = payload_metadata(trash, &sidecar.id)?;
            if !moved.matches_validator(&expected) {
                if rustix::fs::renameat_with(
                    trash,
                    &sidecar.id,
                    &parent,
                    name.as_str(),
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .is_err()
                {
                    tracing::error!(
                        operation = "trash",
                        "validation failed and Trash rollback failed; pending item retained for recovery"
                    );
                    return Err(FsError::new(FsErrorCode::Unavailable));
                }
                trash
                    .remove_file(sidecar_name(&sidecar.id))
                    .map_err(map_io)?;
                return Err(FsError::new(FsErrorCode::Conflict));
            }
            sync_after_commit(&parent);
            sync_after_commit(trash);
            sidecar.state = State::Live;
            write_sidecar(trash, &sidecar, true)?;
            return sidecar.entry();
        }
        Err(FsError::new(FsErrorCode::Unavailable))
    }

    /// Lists every published item, newest first. Unreadable items are skipped.
    pub fn list_trash(&self, max_entries: usize) -> FsResult<Vec<TrashEntry>> {
        self.list_trash_page(max_entries, None, usize::MAX)
            .map(|page| page.items)
    }

    /// Lists up to `limit` published items after `after`, newest first.
    ///
    /// Every page reads at most `max_entries` Trash directory entries, but
    /// keeps only about twice `limit` items in memory. An item whose sidecar
    /// is corrupt or from an unknown schema, whose payload is missing or of
    /// the wrong kind, or that a concurrent restore or purge removed, is
    /// skipped and counted rather than failing the listing; a warning names
    /// only its opaque ID.
    pub fn list_trash_page(
        &self,
        max_entries: usize,
        after: Option<&TrashPosition>,
        limit: usize,
    ) -> FsResult<TrashPage> {
        let Some(trash) = &self.share.trash else {
            return Ok(TrashPage {
                items: Vec::new(),
                has_more: false,
                skipped: 0,
            });
        };
        let keep = limit.saturating_add(1);
        let compact_at = keep.saturating_mul(2).max(64);
        let mut items = Vec::with_capacity(keep.min(256));
        let mut scanned = 0_usize;
        let mut skipped = 0_usize;
        for entry in trash.entries().map_err(map_io)? {
            scanned += 1;
            if scanned > max_entries {
                return Err(FsError::new(FsErrorCode::TooLarge));
            }
            // Internal names are ASCII; any other name is not an item.
            let Ok(name) = entry.map_err(map_io)?.file_name().into_string() else {
                continue;
            };
            let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id)) else {
                continue;
            };
            let Some(item) = listable_item(trash, id) else {
                skipped += 1;
                continue;
            };
            let Some(item) = item else {
                continue;
            };
            if after.is_some_and(|position| !is_after(&item, position)) {
                continue;
            }
            items.push(item);
            if items.len() >= compact_at {
                items.sort_by(listing_order);
                items.truncate(keep);
            }
        }
        items.sort_by(listing_order);
        let has_more = items.len() > limit;
        items.truncate(limit);
        Ok(TrashPage {
            items,
            has_more,
            skipped,
        })
    }

    pub fn restore_trash(
        &self,
        id: &str,
        destination: Option<&VirtualPath>,
    ) -> FsResult<VirtualPath> {
        self.require_write()?;
        let trash = self
            .share
            .trash
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?;
        let sidecar = read_sidecar(trash, id)?;
        if sidecar.state != State::Live {
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        let entry = sidecar.entry()?;
        let target = destination.cloned().unwrap_or(entry.original_path);
        if destination.is_some() {
            target
                .file_name()
                .ok_or_else(|| FsError::new(FsErrorCode::InvalidPath))?
                .ensure_creatable()?;
        }
        let before = payload_metadata(trash, id)?;
        if before.kind != entry.kind {
            return Err(FsError::new(FsErrorCode::Unavailable));
        }
        // An original location recorded before the depth limit may be too
        // deep, and a restored directory's entries must stay within it too.
        if target.depth() > MAX_PATH_DEPTH {
            return Err(FsError::new(FsErrorCode::TooDeep));
        }
        if entry.kind == EntryKind::Directory {
            let payload = trash.open_dir_nofollow(id).map_err(map_io)?;
            ensure_subtree_within(&payload, MAX_PATH_DEPTH - target.depth(), &mut 0)?;
        }
        let (parent, name) = self.share.open_parent(&target)?;
        ensure_same_device(trash, &parent)?;
        rustix::fs::renameat_with(
            trash,
            id,
            &parent,
            name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_io(error.into()))?;
        if !metadata_in_parent_raw(&parent, name.as_str())
            .is_ok_and(|after| after.matches_validator(&before))
        {
            if rustix::fs::renameat_with(
                &parent,
                name.as_str(),
                trash,
                id,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .is_err()
            {
                tracing::error!(
                    operation = "restore",
                    "validation failed and rollback failed; metadata retained for recovery"
                );
                return Err(FsError::new(FsErrorCode::Unavailable));
            }
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        sync_after_commit(&parent);
        sync_after_commit(trash);
        trash.remove_file(sidecar_name(id)).map_err(map_io)?;
        sync_after_commit(trash);
        Ok(target)
    }

    pub fn purge_trash(&self, id: &str, max_entries: usize) -> FsResult<usize> {
        self.require_write()?;
        let trash = self
            .share
            .trash
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?;
        purge(trash, id, max_entries)
    }

    /// Runs one bounded batch of emptying the whole Trash: picks up to
    /// `max_entries` items and removes at most that many payload entries.
    /// Published and already purging items are removed; items still being
    /// moved in are left alone. An item that cannot be read or removed is
    /// logged by its opaque ID, counted in [`TrashEmptyBatch::failed`] and
    /// passed over for the rest of `sweep`, so one bad item cannot stall
    /// the others.
    ///
    /// Each batch reads the Trash directory from its start rather than
    /// resuming at a saved position: some filesystems reorganize a
    /// directory, and invalidate saved positions, as entries are removed.
    /// Removed items are gone, so every batch still makes progress, and
    /// [`TrashEmptyBatch::finished`] means a complete read found nothing
    /// left to remove.
    pub fn empty_trash_batch(
        &self,
        sweep: &mut TrashSweep,
        max_entries: usize,
    ) -> FsResult<TrashEmptyBatch> {
        let max_entries = max_entries.max(1);
        self.require_write()?;
        let trash = self
            .share
            .trash
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?;
        let mut candidates = Vec::new();
        let mut reached_end = true;
        let mut scanned = 0_usize;
        for entry in trash.entries().map_err(map_io)? {
            if candidates.len() >= max_entries {
                reached_end = false;
                break;
            }
            scanned += 1;
            if scanned > MAX_EMPTY_SCAN_ENTRIES {
                return Err(FsError::new(FsErrorCode::TooLarge));
            }
            // Internal names are ASCII; any other name is not an item.
            let Ok(name) = entry.map_err(map_io)?.file_name().into_string() else {
                continue;
            };
            if let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id))
                && !sweep.passed_over.contains(id)
            {
                candidates.push(id.to_owned());
            }
        }
        let mut batch = TrashEmptyBatch::default();
        let mut removed = 0;
        let mut handled_all = true;
        for id in candidates {
            if removed >= max_entries {
                handled_all = false;
                break;
            }
            let sidecar = match read_sidecar(trash, &id) {
                Ok(sidecar) => sidecar,
                Err(error) if error.code() == FsErrorCode::NotFound => continue,
                Err(_) => {
                    tracing::warn!(
                        trash_id = id.as_str(),
                        "emptying Trash skipped an item whose sidecar is unreadable"
                    );
                    batch.failed += 1;
                    sweep.passed_over.insert(id);
                    continue;
                }
            };
            if sidecar.state == State::Pending {
                sweep.passed_over.insert(id);
                continue;
            }
            match purge(trash, &id, max_entries - removed) {
                Ok(count) => {
                    removed += count;
                    if trash.exists(sidecar_name(&id)) {
                        // A large item ran out of this batch's budget; the
                        // next batch finds it again and continues.
                        handled_all = false;
                        break;
                    }
                    batch.purged += 1;
                }
                Err(error) => {
                    if error.code() == FsErrorCode::TooDeep {
                        tracing::error!(
                            trash_id = id.as_str(),
                            max_depth = MAX_PATH_DEPTH,
                            "emptying Trash cannot remove an item nested deeper than the folder depth limit; an operator must remove it"
                        );
                    } else {
                        tracing::warn!(
                            trash_id = id.as_str(),
                            "emptying Trash could not remove an item"
                        );
                    }
                    batch.failed += 1;
                    sweep.passed_over.insert(id);
                }
            }
        }
        batch.finished = reached_end && handled_all;
        Ok(batch)
    }
}

/// Trash directory entries one Empty Trash batch may read before it gives
/// up; it matches the bound on other subtree walks.
const MAX_EMPTY_SCAN_ENTRIES: usize = 1_000_000;

/// The state of one Empty Trash request across its batches.
#[derive(Debug, Default)]
pub struct TrashSweep {
    /// Items left in Trash for the rest of the request: unreadable,
    /// unremovable, or still being moved in.
    passed_over: std::collections::HashSet<String>,
}

/// The result of one bounded Empty Trash batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrashEmptyBatch {
    /// Items whose payload and sidecar are now gone.
    pub purged: usize,
    /// Items that could not be read or removed and were passed over.
    pub failed: usize,
    /// Whether a complete read of Trash found nothing left to remove.
    pub finished: bool,
}

fn purge(trash: &Dir, id: &str, max_entries: usize) -> FsResult<usize> {
    let mut sidecar = read_sidecar(trash, id)?;
    if sidecar.state == State::Pending {
        return Err(FsError::new(FsErrorCode::Conflict));
    }
    if sidecar.state != State::Purging {
        sidecar.state = State::Purging;
        write_sidecar(trash, &sidecar, true)?;
    }
    let mut count = 0;
    let payload = match payload_metadata(trash, id) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.code() == FsErrorCode::NotFound => None,
        Err(error) => return Err(error),
    };
    if let Some(meta) = payload {
        match meta.kind {
            EntryKind::File => {
                if max_entries == 0 {
                    return Err(FsError::new(FsErrorCode::TooLarge));
                }
                trash.remove_file(id).map_err(map_io)?;
                count += 1;
            }
            EntryKind::Directory => {
                let child = trash.open_dir_nofollow(id).map_err(map_io)?;
                if !remove_tree(&child, &mut count, max_entries, PAYLOAD_DEPTH)?
                    || count >= max_entries
                {
                    return Ok(count);
                }
                trash.remove_dir(id).map_err(map_io)?;
                count += 1;
            }
        }
        sync_after_commit(trash);
    }
    trash.remove_file(sidecar_name(id)).map_err(map_io)?;
    sync_after_commit(trash);
    Ok(count)
}

/// Removes the entries of `dir`, whose own virtual depth is `depth`, without
/// following links. An entry below [`MAX_PATH_DEPTH`] stops the removal with
/// [`FsErrorCode::TooDeep`] so recursion stays bounded; an operator must
/// remove such a tree.
fn remove_tree(dir: &Dir, count: &mut usize, max: usize, depth: usize) -> FsResult<bool> {
    for entry in dir.entries().map_err(map_io)? {
        if *count >= max {
            return Ok(false);
        }
        if depth >= MAX_PATH_DEPTH {
            return Err(FsError::new(FsErrorCode::TooDeep));
        }
        let entry = entry.map_err(map_io)?;
        let name = entry.file_name();
        let kind = entry.file_type().map_err(map_io)?;
        if kind.is_dir() {
            let child = dir.open_dir_nofollow(&name).map_err(map_io)?;
            if !remove_tree(&child, count, max, depth + 1)? {
                return Ok(false);
            }
            if *count >= max {
                return Ok(false);
            }
            dir.remove_dir(&name).map_err(map_io)?;
        } else {
            dir.remove_file(&name).map_err(map_io)?;
        }
        *count += 1;
    }
    sync_after_commit(dir);
    Ok(true)
}

impl ShareFs {
    /// Reconciles bounded interrupted moves and purges at startup.
    pub fn recover_trash(&self, max_entries: usize) -> FsResult<usize> {
        if self.staging.is_none() {
            return Ok(0);
        }
        let Some(trash) = &self.trash else {
            return Ok(0);
        };
        let mut work = 0;
        let mut changed = 0;
        for entry in trash.entries().map_err(map_io)? {
            work += 1;
            if work > max_entries {
                return Err(FsError::new(FsErrorCode::TooLarge));
            }
            let name = entry
                .map_err(map_io)?
                .file_name()
                .into_string()
                .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
            if name.strip_prefix(".tmp-").is_some_and(valid_id) {
                let mut options = secure_file_options();
                options.read(true);
                let file = trash.open_with(&name, &options).map_err(map_io)?;
                if !file.metadata().map_err(map_io)?.is_file() {
                    return Err(FsError::new(FsErrorCode::UnsupportedEntry));
                }
                trash.remove_file(&name).map_err(map_io)?;
                sync_after_commit(trash);
                changed += 1;
                continue;
            }
            if valid_id(&name) {
                if !trash.exists(sidecar_name(&name)) {
                    return Err(FsError::new(FsErrorCode::Unavailable));
                }
                continue;
            }
            let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id)) else {
                return Err(FsError::new(FsErrorCode::Unavailable));
            };
            let mut sidecar = read_sidecar(trash, id)?;
            match sidecar.state {
                State::Pending => match payload_metadata(trash, id) {
                    Ok(payload) if payload.kind == sidecar.entry()?.kind => {
                        sidecar.state = State::Live;
                        write_sidecar(trash, &sidecar, true)?;
                        changed += 1;
                    }
                    Ok(_) => return Err(FsError::new(FsErrorCode::Unavailable)),
                    Err(error) if error.code() == FsErrorCode::NotFound => {
                        trash.remove_file(sidecar_name(id)).map_err(map_io)?;
                        sync_after_commit(trash);
                        changed += 1;
                    }
                    Err(error) => return Err(error),
                },
                State::Purging => {
                    if work == max_entries {
                        break;
                    }
                    work += purge(trash, id, max_entries - work)?;
                    changed += 1;
                }
                State::Live if matches!(payload_metadata(trash, id), Err(error) if error.code() == FsErrorCode::NotFound) =>
                {
                    trash.remove_file(sidecar_name(id)).map_err(map_io)?;
                    sync_after_commit(trash);
                    changed += 1;
                }
                State::Live => {}
            }
        }
        Ok(changed)
    }

    /// Removes expired items using their stored deadline, reading at most
    /// `max_entries` Trash directory names and removing at most that many
    /// payload entries. Successive batches continue where the previous one
    /// stopped; [`TrashGcBatch::finished`] reports the end of a sweep. An
    /// item that cannot be read or removed is logged by its opaque ID and
    /// left for a later sweep instead of stopping the batch.
    pub fn gc_expired_trash(&self, now: SystemTime, max_entries: usize) -> FsResult<TrashGcBatch> {
        let done = TrashGcBatch {
            purged: 0,
            finished: true,
        };
        if self.staging.is_none() {
            return Ok(done);
        }
        let Some(trash) = &self.trash else {
            return Ok(done);
        };
        let now = OffsetDateTime::parse(&format_time(now)?, &Rfc3339)
            .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
        let mut cookie = self
            .gc_cookie
            .lock()
            .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
        let names = gc_batch(trash, &mut cookie, max_entries)?;
        let finished = *cookie == 0;
        let mut removed = 0;
        let mut purged = 0;
        for name in names {
            if removed >= max_entries {
                break;
            }
            if valid_id(&name) || name.strip_prefix(".tmp-").is_some_and(valid_id) {
                continue;
            }
            let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id)) else {
                tracing::warn!(
                    "Trash holds an entry that is not a Trash item; it is left in place"
                );
                continue;
            };
            let sidecar = match read_sidecar(trash, id) {
                Ok(sidecar) => sidecar,
                Err(error) if error.code() == FsErrorCode::NotFound => continue,
                Err(_) => {
                    tracing::warn!(
                        trash_id = id,
                        "Trash cleanup skipped an item whose sidecar is unreadable"
                    );
                    continue;
                }
            };
            let expired = OffsetDateTime::parse(&sidecar.expires_at, &Rfc3339)
                .is_ok_and(|expires| expires <= now);
            if sidecar.state == State::Purging || (sidecar.state == State::Live && expired) {
                match purge(trash, id, max_entries - removed) {
                    Ok(count) => removed += count,
                    Err(error) if error.code() == FsErrorCode::TooDeep => {
                        tracing::error!(
                            trash_id = id,
                            max_depth = MAX_PATH_DEPTH,
                            "Trash cleanup cannot remove an item nested deeper than the folder depth limit; an operator must remove it"
                        );
                        continue;
                    }
                    Err(_) => {
                        tracing::warn!(
                            trash_id = id,
                            "Trash cleanup could not remove an item; it will be retried"
                        );
                        continue;
                    }
                }
                if !trash.exists(sidecar_name(id)) {
                    purged += 1;
                }
            }
        }
        Ok(TrashGcBatch { purged, finished })
    }
}

pub(super) fn measure_trash(trash: &Dir, scan: &mut UsageScan) -> Result<(), UsageError> {
    for entry in trash.entries().map_err(map_io)? {
        scan.visit()?;
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| FsError::new(FsErrorCode::UnsupportedEntry))?;
        if !valid_id(&name) {
            continue;
        }
        let meta = entry.metadata().map_err(map_io)?;
        let kind = classify_metadata(&meta)?;
        assert_no_external_alias(&meta, kind)?;
        match kind {
            EntryKind::File => scan.charge(meta.len())?,
            EntryKind::Directory => {
                scan.charge(DIRECTORY_QUOTA_BYTES)?;
                let child = trash.open_dir_nofollow(&name).map_err(map_io)?;
                measure_directory(&child, scan, PAYLOAD_DEPTH)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::filesystem::{AccessLevel, GlobalPolicy, ShareGrant, ShareId};

    fn setup() -> (TempDir, ShareFs, ShareGrant) {
        let temp = TempDir::new().unwrap();
        let id = ShareId::new("documents").unwrap();
        let share = ShareFs::open(id.clone(), temp.path()).unwrap();
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadWrite,
        };
        (temp, share, grant)
    }

    #[test]
    fn nonempty_directory_round_trip_and_quota() {
        let (temp, share, grant) = setup();
        fs::create_dir(temp.path().join("photos")).unwrap();
        fs::write(temp.path().join("photos/image.jpg"), b"picture").unwrap();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let path = VirtualPath::parse("photos").unwrap();
        let expected = view.metadata(&path).unwrap();
        let item = view.move_to_trash(&path, expected, "user-1", 30).unwrap();
        assert_eq!(item.original_path, path);
        assert_eq!(item.kind, EntryKind::Directory);
        assert!(item.expires_at.ends_with('Z'));
        assert!(!temp.path().join("photos").exists());
        assert_eq!(
            view.usage_bounded(100, 1 << 20).unwrap(),
            7 + DIRECTORY_QUOTA_BYTES
        );
        assert_eq!(view.list_trash(100).unwrap(), vec![item.clone()]);
        assert_eq!(view.restore_trash(&item.id, None).unwrap(), path);
        assert_eq!(
            fs::read(temp.path().join("photos/image.jpg")).unwrap(),
            b"picture"
        );
        assert!(view.list_trash(100).unwrap().is_empty());
        assert_eq!(
            view.usage_bounded(100, 1 << 20).unwrap(),
            7 + DIRECTORY_QUOTA_BYTES
        );
    }

    #[test]
    fn restore_never_replaces_and_read_only_can_list() {
        let (temp, share, grant) = setup();
        fs::write(temp.path().join("a"), b"old").unwrap();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let path = VirtualPath::parse("a").unwrap();
        let item = view
            .move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 30)
            .unwrap();
        fs::write(temp.path().join("a"), b"new").unwrap();
        assert_eq!(
            view.restore_trash(&item.id, None).unwrap_err().code(),
            FsErrorCode::Conflict
        );
        assert_eq!(fs::read(temp.path().join("a")).unwrap(), b"new");
        let read_only =
            ShareFs::open_read_only(ShareId::new("documents").unwrap(), temp.path()).unwrap();
        assert_eq!(
            read_only
                .authorize(Some(&grant), GlobalPolicy::default())
                .unwrap()
                .list_trash(100)
                .unwrap(),
            vec![item]
        );
    }

    #[test]
    fn repeated_unicode_name_uses_distinct_versioned_sidecars() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let name = format!("résumé-{}.txt", "x".repeat(180));
        let path = VirtualPath::parse(&name).unwrap();
        fs::write(temp.path().join(&name), b"first").unwrap();
        let first = view
            .move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 30)
            .unwrap();
        fs::write(temp.path().join(&name), b"second").unwrap();
        let second = view
            .move_to_trash(&path, view.metadata(&path).unwrap(), "user-2", 30)
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(view.list_trash(100).unwrap().len(), 2);
        let sidecar = fs::read(
            temp.path()
                .join(CONTAINER)
                .join(TRASH)
                .join(sidecar_name(&first.id)),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&sidecar).unwrap()["schemaVersion"],
            SIDECAR_SCHEMA_VERSION
        );
        view.restore_trash(&first.id, None).unwrap();
        assert_eq!(fs::read(temp.path().join(&name)).unwrap(), b"first");
        assert_eq!(
            view.restore_trash(&second.id, None).unwrap_err().code(),
            FsErrorCode::Conflict
        );
        let alternate = VirtualPath::parse("recovered.txt").unwrap();
        view.restore_trash(&second.id, Some(&alternate)).unwrap();
        assert_eq!(
            fs::read(temp.path().join("recovered.txt")).unwrap(),
            b"second"
        );
    }

    #[test]
    fn unknown_sidecar_schema_fails_closed() {
        let (_temp, share, _grant) = setup();
        let trash = share.trash.as_ref().unwrap();
        let sidecar = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION + 1,
            id: "b".repeat(32),
            original_path: "source".into(),
            kind: "file".into(),
            deleted_at: "2020-01-01T00:00:00Z".into(),
            deleted_by: "user-1".into(),
            expires_at: "2020-02-01T00:00:00Z".into(),
            state: State::Pending,
        };
        write_sidecar(trash, &sidecar, false).unwrap();
        assert_eq!(
            share.recover_trash(100).unwrap_err().code(),
            FsErrorCode::Unavailable
        );
    }

    #[test]
    fn pending_recovery_and_expired_gc() {
        let (temp, share, grant) = setup();
        let trash = share.trash.as_ref().unwrap();
        let id = "a".repeat(32);
        let sidecar = Sidecar {
            schema_version: SIDECAR_SCHEMA_VERSION,
            id: id.clone(),
            original_path: "source".into(),
            kind: "file".into(),
            deleted_at: "2020-01-01T00:00:00Z".into(),
            deleted_by: "user-1".into(),
            expires_at: "2020-02-01T00:00:00Z".into(),
            state: State::Pending,
        };
        write_sidecar(trash, &sidecar, false).unwrap();
        fs::write(temp.path().join(CONTAINER).join(TRASH).join(&id), b"old").unwrap();
        assert_eq!(share.recover_trash(100).unwrap(), 1);
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        assert_eq!(view.list_trash(100).unwrap().len(), 1);
        assert_eq!(
            share
                .gc_expired_trash(SystemTime::now(), 100)
                .unwrap()
                .purged,
            1
        );
        assert!(view.list_trash(100).unwrap().is_empty());
        assert!(!temp.path().join(CONTAINER).join(TRASH).join(id).exists());
    }

    #[test]
    fn gc_cursor_reaches_items_after_the_first_batch() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        for index in 0..12 {
            let name = format!("file-{index}");
            fs::write(temp.path().join(&name), b"x").unwrap();
            let path = VirtualPath::parse(&name).unwrap();
            view.move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 1)
                .unwrap();
        }
        let after_retention = SystemTime::now() + Duration::from_secs(2 * 86400);
        for _ in 0..40 {
            share.gc_expired_trash(after_retention, 3).unwrap();
            if view.list_trash(100).unwrap().is_empty() {
                break;
            }
        }
        assert!(view.list_trash(100).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_purge_resumes_and_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;

        let (temp, share, grant) = setup();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret"), b"safe").unwrap();
        fs::create_dir(temp.path().join("folder")).unwrap();
        for index in 0..4 {
            fs::write(temp.path().join("folder").join(format!("{index}")), b"x").unwrap();
        }
        symlink(outside.path(), temp.path().join("folder/link")).unwrap();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let path = VirtualPath::parse("folder").unwrap();
        let item = view
            .move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 30)
            .unwrap();
        assert_eq!(view.purge_trash(&item.id, 2).unwrap(), 2);
        assert!(view.list_trash(100).unwrap().is_empty());
        for _ in 0..5 {
            let _ = view.purge_trash(&item.id, 2);
        }
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"safe");
        assert!(
            !temp
                .path()
                .join(CONTAINER)
                .join(TRASH)
                .join(&item.id)
                .exists()
        );
    }

    fn trash_file(view: &AuthorizedShare<'_>, temp: &TempDir, name: &str) -> TrashEntry {
        fs::write(temp.path().join(name), name.as_bytes()).unwrap();
        let path = VirtualPath::parse(name).unwrap();
        view.move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 30)
            .unwrap()
    }

    fn trash_path(temp: &TempDir, name: &str) -> std::path::PathBuf {
        temp.path().join(CONTAINER).join(TRASH).join(name)
    }

    fn deep_path(levels: usize) -> String {
        (0..levels)
            .map(|level| format!("d{level}"))
            .collect::<Vec<_>>()
            .join("/")
    }

    #[test]
    fn listing_skips_corrupt_orphaned_and_mismatched_items() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let corrupt = trash_file(&view, &temp, "corrupt.txt");
        let orphaned = trash_file(&view, &temp, "orphaned.txt");
        let mismatched = trash_file(&view, &temp, "mismatched.txt");
        let healthy = trash_file(&view, &temp, "healthy.txt");
        fs::write(trash_path(&temp, &sidecar_name(&corrupt.id)), b"{not json").unwrap();
        fs::remove_file(trash_path(&temp, &orphaned.id)).unwrap();
        fs::remove_file(trash_path(&temp, &mismatched.id)).unwrap();
        fs::create_dir(trash_path(&temp, &mismatched.id)).unwrap();

        let page = view.list_trash_page(100, None, 100).unwrap();
        assert_eq!(page.items, vec![healthy]);
        assert_eq!(page.skipped, 3);
        assert!(!page.has_more);
        // Skipped items stay in place for an operator or a later purge.
        assert!(trash_path(&temp, &sidecar_name(&corrupt.id)).exists());
    }

    #[test]
    fn listing_pages_in_a_stable_order_that_survives_concurrent_changes() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        for index in 0..5 {
            trash_file(&view, &temp, &format!("file-{index}.txt"));
        }
        let everything = view.list_trash(100).unwrap();
        assert_eq!(everything.len(), 5);

        let first = view.list_trash_page(100, None, 2).unwrap();
        assert_eq!(first.items, everything[..2]);
        assert!(first.has_more);
        let position = |entry: &TrashEntry| TrashPosition {
            deleted_at: entry.deleted_at.clone(),
            id: entry.id.clone(),
        };
        // An item on a later page is restored meanwhile; paging continues.
        view.restore_trash(&everything[3].id, None).unwrap();
        let second = view
            .list_trash_page(100, Some(&position(&first.items[1])), 2)
            .unwrap();
        assert_eq!(
            second.items,
            vec![everything[2].clone(), everything[4].clone()]
        );
        assert!(!second.has_more);
        let end = view
            .list_trash_page(100, Some(&position(&second.items[1])), 2)
            .unwrap();
        assert!(end.items.is_empty());
        assert!(!end.has_more);
        // The entry bound still applies to each page.
        assert_eq!(
            view.list_trash_page(3, None, 2).unwrap_err().code(),
            FsErrorCode::TooLarge
        );
    }

    #[test]
    fn restore_rejects_a_subtree_that_would_exceed_the_depth_limit() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        fs::create_dir_all(temp.path().join("folder/a")).unwrap();
        fs::write(temp.path().join("folder/a/b.txt"), b"b").unwrap();
        let path = VirtualPath::parse("folder").unwrap();
        let item = view
            .move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 30)
            .unwrap();
        // `folder` at depth 63 would put b.txt at depth 65.
        fs::create_dir_all(temp.path().join(deep_path(MAX_PATH_DEPTH - 2))).unwrap();
        let too_deep =
            VirtualPath::parse(&format!("{}/folder", deep_path(MAX_PATH_DEPTH - 2))).unwrap();
        assert_eq!(
            view.restore_trash(&item.id, Some(&too_deep))
                .unwrap_err()
                .code(),
            FsErrorCode::TooDeep
        );
        assert!(trash_path(&temp, &item.id).join("a/b.txt").exists());
        assert_eq!(view.list_trash(100).unwrap(), vec![item.clone()]);
        let fits =
            VirtualPath::parse(&format!("{}/folder", deep_path(MAX_PATH_DEPTH - 3))).unwrap();
        view.restore_trash(&item.id, Some(&fits)).unwrap();
        assert!(
            temp.path()
                .join(deep_path(MAX_PATH_DEPTH - 3))
                .join("folder/a/b.txt")
                .exists()
        );
    }

    #[test]
    fn an_item_recorded_deeper_than_the_limit_stays_listed_but_cannot_return_there() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let item = trash_file(&view, &temp, "deep.txt");
        let trash = share.trash.as_ref().unwrap();
        let mut sidecar = read_sidecar(trash, &item.id).unwrap();
        sidecar.original_path = format!("{}/deep.txt", deep_path(MAX_PATH_DEPTH + 5));
        write_sidecar(trash, &sidecar, true).unwrap();
        let listed = view.list_trash(100).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].original_path.depth(), MAX_PATH_DEPTH + 6);
        assert_eq!(
            view.restore_trash(&item.id, None).unwrap_err().code(),
            FsErrorCode::TooDeep
        );
        let elsewhere = VirtualPath::parse("restored.txt").unwrap();
        view.restore_trash(&item.id, Some(&elsewhere)).unwrap();
        assert_eq!(
            fs::read(temp.path().join("restored.txt")).unwrap(),
            b"deep.txt"
        );
    }

    #[test]
    fn trashing_a_tree_deeper_than_the_limit_is_refused_without_changes() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        // `fits` holds entries down to exactly the limit; `deep`, created out
        // of band, holds one more level.
        fs::create_dir_all(temp.path().join("fits").join(deep_path(MAX_PATH_DEPTH - 1))).unwrap();
        fs::create_dir_all(temp.path().join("deep").join(deep_path(MAX_PATH_DEPTH))).unwrap();
        let deep = VirtualPath::parse("deep").unwrap();
        assert_eq!(
            view.move_to_trash(&deep, view.metadata(&deep).unwrap(), "user-1", 30)
                .unwrap_err()
                .code(),
            FsErrorCode::TooDeep
        );
        assert!(
            temp.path()
                .join("deep")
                .join(deep_path(MAX_PATH_DEPTH))
                .exists()
        );
        let fits = VirtualPath::parse("fits").unwrap();
        let item = view
            .move_to_trash(&fits, view.metadata(&fits).unwrap(), "user-1", 30)
            .unwrap();
        // Only the accepted item reached Trash: its payload and sidecar.
        assert_eq!(view.list_trash(100).unwrap(), vec![item]);
        assert_eq!(
            fs::read_dir(temp.path().join(".crabinet/trash"))
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn a_payload_deeper_than_the_limit_fails_measurement_and_purge_distinctly() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        fs::create_dir(temp.path().join("deep")).unwrap();
        let path = VirtualPath::parse("deep").unwrap();
        let item = view
            .move_to_trash(&path, view.metadata(&path).unwrap(), "user-1", 30)
            .unwrap();
        // Grown out of band inside Trash, as an older version allowed.
        fs::create_dir_all(trash_path(&temp, &item.id).join(deep_path(MAX_PATH_DEPTH + 5)))
            .unwrap();
        assert_eq!(
            view.usage_bounded(10_000, u64::MAX),
            Err(UsageError::TooDeep)
        );
        assert_eq!(
            view.purge_trash(&item.id, 10_000).unwrap_err().code(),
            FsErrorCode::TooDeep
        );
        // Collection logs the item and carries on with the rest of Trash.
        let after_retention = SystemTime::now() + Duration::from_secs(31 * 86400);
        let batch = share.gc_expired_trash(after_retention, 100).unwrap();
        assert_eq!(batch.purged, 0);
        assert!(batch.finished);
        // Emptying Trash passes over it too, and reports it as failed.
        let batch = view
            .empty_trash_batch(&mut TrashSweep::default(), 10_000)
            .unwrap();
        assert_eq!(
            batch,
            TrashEmptyBatch {
                purged: 0,
                failed: 1,
                finished: true,
            }
        );
    }

    #[test]
    fn emptying_trash_continues_large_items_and_many_names_across_batches() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        fs::create_dir(temp.path().join("folder")).unwrap();
        for index in 0..12 {
            fs::write(temp.path().join(format!("folder/{index}.txt")), b"x").unwrap();
        }
        let folder = VirtualPath::parse("folder").unwrap();
        view.move_to_trash(&folder, view.metadata(&folder).unwrap(), "user-1", 30)
            .unwrap();
        for index in 0..9 {
            trash_file(&view, &temp, &format!("file-{index}.txt"));
        }
        let mut sweep = TrashSweep::default();
        let mut purged = 0;
        let mut batches = 0;
        loop {
            let batch = view.empty_trash_batch(&mut sweep, 4).unwrap();
            assert_eq!(batch.failed, 0);
            purged += batch.purged;
            batches += 1;
            if batch.finished {
                break;
            }
            assert!(batches < 100, "the pass never finished");
        }
        // Removing at most four entries per batch, the 13-entry folder alone
        // needs four batches.
        assert!(batches > 3, "only {batches} batches");
        assert_eq!(purged, 10);
        assert_eq!(view.list_trash(100).unwrap(), Vec::new());
        assert_eq!(
            fs::read_dir(temp.path().join(".crabinet/trash"))
                .unwrap()
                .count(),
            0
        );
        // A read-only view cannot empty Trash.
        let read_only = ShareGrant {
            access: AccessLevel::ReadOnly,
            ..grant
        };
        let view = share
            .authorize(Some(&read_only), GlobalPolicy::default())
            .unwrap();
        assert_eq!(
            view.empty_trash_batch(&mut TrashSweep::default(), 4)
                .unwrap_err()
                .code(),
            FsErrorCode::AccessDenied
        );
    }

    #[test]
    fn gc_reports_when_a_sweep_finishes() {
        let (temp, share, grant) = setup();
        let view = share
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        for index in 0..4 {
            trash_file(&view, &temp, &format!("file-{index}.txt"));
        }
        let after_retention = SystemTime::now() + Duration::from_secs(31 * 86400);
        // Two names cannot cover eight, so the first batch leaves the sweep
        // open. Entries renamed during a sweep can be reached only by the
        // next one, depending on the filesystem's directory order.
        let first = share.gc_expired_trash(after_retention, 2).unwrap();
        assert!(!first.finished);
        let mut purged = first.purged;
        let mut finished = false;
        for _ in 0..40 {
            let batch = share.gc_expired_trash(after_retention, 2).unwrap();
            purged += batch.purged;
            finished |= batch.finished;
            if purged == 4 && finished {
                break;
            }
        }
        assert_eq!(purged, 4);
        assert!(finished);
        assert!(view.list_trash(100).unwrap().is_empty());
    }
}

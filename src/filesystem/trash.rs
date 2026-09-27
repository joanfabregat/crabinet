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
    AuthorizedShare, EntryKind, EntryMetadata, FsError, FsErrorCode, FsResult, ShareFs,
    VirtualPath, assert_no_external_alias, classify_metadata, ensure_same_device, map_io,
    measure_directory, metadata_in_parent_raw, random_internal_name, secure_file_options,
    sync_after_commit, sync_directory,
};

const CONTAINER: &str = ".crabinet";
const TRASH: &str = "trash";
const MAX_SIDECAR_BYTES: u64 = 8192;
const MAX_DEPTH: usize = 256;

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
            original_path: VirtualPath::parse(&self.original_path)?,
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
    sidecar.entry()?;
    OffsetDateTime::parse(&sidecar.expires_at, &Rfc3339)
        .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
    Ok(sidecar)
}

fn payload_metadata(trash: &Dir, id: &str) -> FsResult<EntryMetadata> {
    metadata_in_parent_raw(trash, id)
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

    pub fn list_trash(&self, max_entries: usize) -> FsResult<Vec<TrashEntry>> {
        let Some(trash) = &self.share.trash else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        let mut scanned = 0;
        for entry in trash.entries().map_err(map_io)? {
            scanned += 1;
            if scanned > max_entries {
                return Err(FsError::new(FsErrorCode::TooLarge));
            }
            let name = entry
                .map_err(map_io)?
                .file_name()
                .into_string()
                .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let sidecar = read_sidecar(trash, id)?;
            if sidecar.state == State::Live {
                let payload = payload_metadata(trash, id)?;
                if payload.kind != sidecar.entry()?.kind {
                    return Err(FsError::new(FsErrorCode::Unavailable));
                }
                entries.push(sidecar.entry()?);
            }
        }
        entries.sort_by(|a, b| {
            b.deleted_at
                .cmp(&a.deleted_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(entries)
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
                if !remove_tree(&child, &mut count, max_entries, 0)? || count >= max_entries {
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

fn remove_tree(dir: &Dir, count: &mut usize, max: usize, depth: usize) -> FsResult<bool> {
    if depth > MAX_DEPTH {
        return Err(FsError::new(FsErrorCode::TooLarge));
    }
    for entry in dir.entries().map_err(map_io)? {
        if *count >= max {
            return Ok(false);
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

    /// Removes expired items using their stored deadline, with a bounded visit count.
    pub fn gc_expired_trash(&self, now: SystemTime, max_entries: usize) -> FsResult<usize> {
        if self.staging.is_none() {
            return Ok(0);
        }
        let Some(trash) = &self.trash else {
            return Ok(0);
        };
        let now = OffsetDateTime::parse(&format_time(now)?, &Rfc3339)
            .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
        let mut cookie = self
            .gc_cookie
            .lock()
            .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
        let names = gc_batch(trash, &mut cookie, max_entries)?;
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
                return Err(FsError::new(FsErrorCode::Unavailable));
            };
            let sidecar = read_sidecar(trash, id)?;
            let expired = OffsetDateTime::parse(&sidecar.expires_at, &Rfc3339)
                .map_err(|_| FsError::new(FsErrorCode::Unavailable))?
                <= now;
            if sidecar.state == State::Purging || (sidecar.state == State::Live && expired) {
                removed += purge(trash, id, max_entries - removed)?;
                if !trash.exists(sidecar_name(id)) {
                    purged += 1;
                }
            }
        }
        Ok(purged)
    }
}

pub(super) fn measure_trash(
    trash: &Dir,
    entries: &mut usize,
    max_entries: usize,
    bytes: &mut u64,
    max_bytes: u64,
) -> FsResult<()> {
    for entry in trash.entries().map_err(map_io)? {
        *entries += 1;
        if *entries > max_entries {
            return Err(FsError::new(FsErrorCode::TooLarge));
        }
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
            EntryKind::File => {
                *bytes = bytes
                    .checked_add(meta.len())
                    .ok_or_else(|| FsError::new(FsErrorCode::TooLarge))?;
                if *bytes > max_bytes {
                    return Err(FsError::new(FsErrorCode::TooLarge));
                }
            }
            EntryKind::Directory => {
                let child = trash.open_dir_nofollow(&name).map_err(map_io)?;
                measure_directory(&child, entries, max_entries, bytes, max_bytes, 0)?;
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
        assert_eq!(view.usage_bounded(100, 100).unwrap(), 7);
        assert_eq!(view.list_trash(100).unwrap(), vec![item.clone()]);
        assert_eq!(view.restore_trash(&item.id, None).unwrap(), path);
        assert_eq!(
            fs::read(temp.path().join("photos/image.jpg")).unwrap(),
            b"picture"
        );
        assert!(view.list_trash(100).unwrap().is_empty());
        assert_eq!(view.usage_bounded(100, 100).unwrap(), 7);
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
    fn pending_recovery_and_expired_gc() {
        let (temp, share, grant) = setup();
        let trash = share.trash.as_ref().unwrap();
        let id = "a".repeat(32);
        let sidecar = Sidecar {
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
        assert_eq!(share.gc_expired_trash(SystemTime::now(), 100).unwrap(), 1);
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
}

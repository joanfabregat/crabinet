//! Capability-scoped filesystem access.
//!
//! Ambient paths are accepted exactly once, while constructing a [`ShareFs`]
//! from operator-trusted configuration. Every request-time operation walks
//! validated components from that already-open directory handle. Symlinks are
//! never followed: intermediate directories use `open_dir_nofollow`, and final
//! files use a no-follow open option before their opened handle is inspected.

use std::{
    fmt,
    io::{Read, Write},
    path::Path,
    time::SystemTime,
};

use cap_fs_ext::MetadataExt as _;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions},
};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_VIRTUAL_PATH_BYTES: usize = 4096;
const MAX_SHARE_ID_BYTES: usize = 64;
const INTERNAL_STAGING_DIRECTORY: &str = ".index-staging";
const INTERNAL_TEMP_PREFIX: &str = ".index-tmp-";

pub type FsResult<T> = Result<T, FsError>;

/// A stable, non-disclosing category suitable for API error mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsErrorCode {
    AccessDenied,
    Conflict,
    CrossDevice,
    InvalidPath,
    NotFound,
    TooLarge,
    UnsupportedEntry,
    Unavailable,
}

/// A filesystem error that intentionally contains no host path or OS detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsError {
    code: FsErrorCode,
}

impl FsError {
    #[must_use]
    pub const fn code(&self) -> FsErrorCode {
        self.code
    }

    const fn new(code: FsErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.code {
            FsErrorCode::AccessDenied => "access denied",
            FsErrorCode::Conflict => "entry already exists or changed",
            FsErrorCode::CrossDevice => "destination crosses a filesystem boundary",
            FsErrorCode::InvalidPath => "invalid virtual path",
            FsErrorCode::NotFound => "entry not found",
            FsErrorCode::TooLarge => "entry exceeds the configured limit",
            FsErrorCode::UnsupportedEntry => "unsupported filesystem entry",
            FsErrorCode::Unavailable => "filesystem operation unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FsError {}

/// Stable configuration identifier for a mounted share.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ShareId(String);

impl ShareId {
    pub fn new(value: impl Into<String>) -> FsResult<Self> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_SHARE_ID_BYTES
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && value != "."
            && value != "..";
        valid
            .then_some(Self(value))
            .ok_or_else(|| FsError::new(FsErrorCode::InvalidPath))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ShareId {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// One validated filename component.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntryName(String);

impl EntryName {
    pub fn new(value: impl Into<String>) -> FsResult<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_COMPONENT_BYTES
            || matches!(value.as_str(), "." | "..")
            || value.contains(['/', '\\', '\0'])
            || value.chars().any(char::is_control)
            || value.ends_with(['.', ' '])
            || contains_percent_escape(&value)
            || !value.nfc().eq(value.chars())
            || is_windows_device_name(&value)
            || value == INTERNAL_STAGING_DIRECTORY
            || value.starts_with(INTERNAL_TEMP_PREFIX)
        {
            return Err(FsError::new(FsErrorCode::InvalidPath));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated, slash-separated path relative to a share.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VirtualPath(Vec<EntryName>);

impl VirtualPath {
    /// The explicit share root. Empty user-provided path strings remain invalid.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    pub fn parse(value: &str) -> FsResult<Self> {
        if value.is_empty() || value.len() > MAX_VIRTUAL_PATH_BYTES {
            return Err(FsError::new(FsErrorCode::InvalidPath));
        }
        let components = value
            .split('/')
            .map(|component| EntryName::new(component.to_owned()))
            .collect::<FsResult<Vec<_>>>()?;
        Ok(Self(components))
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn components(&self) -> impl ExactSizeIterator<Item = &EntryName> {
        self.0.iter()
    }

    /// Returns the final validated component, or `None` for the explicit share root.
    #[must_use]
    pub fn file_name(&self) -> Option<&EntryName> {
        self.0.last()
    }

    fn split_file(&self) -> FsResult<(&[EntryName], &EntryName)> {
        self.0
            .split_last()
            .map(|(name, parents)| (parents, name))
            .ok_or_else(|| FsError::new(FsErrorCode::InvalidPath))
    }

    #[must_use]
    pub fn join(&self, name: EntryName) -> Self {
        let mut components = self.0.clone();
        components.push(name);
        Self(components)
    }

    #[must_use]
    pub fn starts_with(&self, other: &Self) -> bool {
        self.0.starts_with(&other.0)
    }
}

impl fmt::Display for VirtualPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, component) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("/")?;
            }
            formatter.write_str(component.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareGrant {
    pub share_id: ShareId,
    pub access: AccessLevel,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GlobalPolicy {
    pub read_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: EntryName,
    pub kind: EntryKind,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub(crate) file_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryMetadata {
    pub kind: EntryKind,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub created: Option<SystemTime>,
    pub(crate) file_id: u64,
}

impl EntryMetadata {
    fn matches_validator(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.size == other.size
            && self.modified == other.modified
            && self.file_id == other.file_id
    }
}

/// A newly-created private staging file. Dropping it before publication removes
/// the temporary name, including when an async request is cancelled.
pub struct PendingWrite {
    staging: Dir,
    destination_parent: Dir,
    temporary_name: String,
    destination_name: EntryName,
    file: File,
    published: bool,
}

impl PendingWrite {
    /// Returns a cloned standard handle suitable for `tokio::fs::File`.
    pub fn writer(&self) -> FsResult<std::fs::File> {
        self.file.try_clone().map(File::into_std).map_err(map_io)
    }

    pub fn publish_new(mut self) -> FsResult<()> {
        validate_regular_handle(&self.file)?;
        let expected = raw_file_metadata(&self.file)?;
        self.file.sync_all().map_err(map_io)?;
        rustix::fs::renameat_with(
            &self.staging,
            &self.temporary_name,
            &self.destination_parent,
            self.destination_name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_io(std::io::Error::from(error)))?;
        if !metadata_in_parent_raw(&self.destination_parent, self.destination_name.as_str())
            .is_ok_and(|current| current.matches_validator(&expected))
        {
            let _ = self
                .destination_parent
                .remove_file(self.destination_name.as_str());
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        self.published = true;
        sync_directory(&self.staging)?;
        sync_directory(&self.destination_parent)
    }

    pub fn publish_replacement(mut self, expected: EntryMetadata) -> FsResult<()> {
        validate_regular_handle(&self.file)?;
        let replacement = raw_file_metadata(&self.file)?;
        self.file.sync_all().map_err(map_io)?;
        let current = metadata_in_parent(&self.destination_parent, &self.destination_name)?;
        if !current.matches_validator(&expected) || current.kind != EntryKind::File {
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        rustix::fs::renameat_with(
            &self.staging,
            &self.temporary_name,
            &self.destination_parent,
            self.destination_name.as_str(),
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(|error| map_io(std::io::Error::from(error)))?;
        let valid_exchange =
            metadata_in_parent_raw(&self.destination_parent, self.destination_name.as_str())
                .is_ok_and(|current| current.matches_validator(&replacement))
                && metadata_in_parent_raw(&self.staging, &self.temporary_name)
                    .is_ok_and(|current| current.matches_validator(&expected));
        if !valid_exchange {
            rustix::fs::renameat_with(
                &self.staging,
                &self.temporary_name,
                &self.destination_parent,
                self.destination_name.as_str(),
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        if let Err(error) = self.staging.remove_file(&self.temporary_name) {
            let rollback = rustix::fs::renameat_with(
                &self.staging,
                &self.temporary_name,
                &self.destination_parent,
                self.destination_name.as_str(),
                rustix::fs::RenameFlags::EXCHANGE,
            );
            return if rollback.is_err() {
                self.published = true;
                Err(FsError::new(FsErrorCode::Unavailable))
            } else {
                Err(map_io(error))
            };
        }
        self.published = true;
        sync_directory(&self.staging)?;
        sync_directory(&self.destination_parent)
    }
}

impl Drop for PendingWrite {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.staging.remove_file(&self.temporary_name);
        }
    }
}

/// A validated regular-file handle whose authority is limited to one share.
///
/// The API layer owns this handle while streaming. Dropping a response body
/// closes the handle, so client cancellation does not leave background reads.
pub struct OpenedFile {
    file: File,
    len: u64,
    modified: Option<SystemTime>,
    file_id: u64,
}

impl OpenedFile {
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn modified(&self) -> Option<SystemTime> {
        self.modified
    }

    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.file_id
    }

    #[must_use]
    pub fn into_std(self) -> std::fs::File {
        self.file.into_std()
    }
}

/// An open capability for exactly one configured share root.
pub struct ShareFs {
    id: ShareId,
    root: Dir,
    staging: Option<Dir>,
}

impl ShareFs {
    /// Opens an operator-trusted absolute directory without following a symlink
    /// in the root's final component. Ambient authority is discarded afterward.
    pub fn open(id: ShareId, trusted_root: &Path) -> FsResult<Self> {
        Self::open_with_writes(id, trusted_root, true)
    }

    /// Opens a share without creating writable staging state. Any write grant
    /// presented to this instance is reduced to read-only access.
    pub fn open_read_only(id: ShareId, trusted_root: &Path) -> FsResult<Self> {
        Self::open_with_writes(id, trusted_root, false)
    }

    fn open_with_writes(id: ShareId, trusted_root: &Path, writable: bool) -> FsResult<Self> {
        if !trusted_root.is_absolute() {
            return Err(FsError::new(FsErrorCode::InvalidPath));
        }

        let root = match (trusted_root.parent(), trusted_root.file_name()) {
            (Some(parent), Some(name)) => {
                let parent = Dir::open_ambient_dir(parent, ambient_authority()).map_err(map_io)?;
                parent.open_dir_nofollow(name).map_err(map_io)?
            }
            _ => Dir::open_ambient_dir(trusted_root, ambient_authority()).map_err(map_io)?,
        };

        if !root.dir_metadata().map_err(map_io)?.is_dir() {
            return Err(FsError::new(FsErrorCode::UnsupportedEntry));
        }
        let staging = writable
            .then(|| open_staging_directory(&root))
            .transpose()?;
        Ok(Self { id, root, staging })
    }

    #[must_use]
    pub fn id(&self) -> &ShareId {
        &self.id
    }

    /// Produces the only object that exposes request-time filesystem methods.
    /// Missing and wrong-share grants use the same denial.
    pub fn authorize<'share>(
        &'share self,
        grant: Option<&ShareGrant>,
        policy: GlobalPolicy,
    ) -> FsResult<AuthorizedShare<'share>> {
        let grant = grant
            .filter(|grant| grant.share_id == self.id)
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?;
        let access = if policy.read_only || self.staging.is_none() {
            AccessLevel::ReadOnly
        } else {
            grant.access
        };
        Ok(AuthorizedShare {
            share: self,
            access,
        })
    }

    fn open_directory(&self, components: &[EntryName]) -> FsResult<Dir> {
        let mut current = self.root.try_clone().map_err(map_io)?;
        for component in components {
            current = current
                .open_dir_nofollow(component.as_str())
                .map_err(map_io)?;
        }
        Ok(current)
    }

    fn open_parent<'path>(&self, path: &'path VirtualPath) -> FsResult<(Dir, &'path EntryName)> {
        let (parents, name) = path.split_file()?;
        Ok((self.open_directory(parents)?, name))
    }

    /// Removes reserved regular files left in the private staging directory by
    /// a terminated process. User content is never traversed.
    pub fn recover_staging_files(&self, max_entries: usize) -> FsResult<usize> {
        self.staging.as_ref().map_or(Ok(0), |staging| {
            recover_staging_directory(staging, max_entries)
        })
    }
}

/// An authorization-bound view of one share. Cross-share moves are impossible
/// by construction: operations never accept another `ShareFs` or ambient path.
pub struct AuthorizedShare<'share> {
    share: &'share ShareFs,
    access: AccessLevel,
}

impl AuthorizedShare<'_> {
    #[must_use]
    pub const fn access(&self) -> AccessLevel {
        self.access
    }

    pub fn list(&self, path: &VirtualPath) -> FsResult<Vec<DirectoryEntry>> {
        self.list_bounded(path, usize::MAX)
    }

    /// Creates a non-recursive kernel watch for one already-authorized
    /// directory without revealing or reconstructing its ambient host path.
    #[cfg(target_os = "linux")]
    pub(crate) fn watch_directory(&self, path: &VirtualPath) -> FsResult<rustix::fd::OwnedFd> {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        use rustix::fs::inotify::{self, CreateFlags, WatchFlags};

        let directory = self.share.open_directory(&path.0)?;
        let watcher = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)
            .map_err(|error| map_io(error.into()))?;
        let capability_path = format!("/proc/self/fd/{}", directory.as_fd().as_raw_fd());
        inotify::add_watch(
            &watcher,
            capability_path,
            WatchFlags::ATTRIB
                | WatchFlags::CLOSE_WRITE
                | WatchFlags::CREATE
                | WatchFlags::DELETE
                | WatchFlags::DELETE_SELF
                | WatchFlags::MOVE_SELF
                | WatchFlags::MOVED_FROM
                | WatchFlags::MOVED_TO
                | WatchFlags::ONLYDIR,
        )
        .map_err(|error| map_io(error.into()))?;
        Ok(watcher)
    }

    /// Lists at most `max_entries` from a directory. The implementation reads
    /// one additional entry so it can reject an oversized directory without
    /// allocating proportionally to attacker-controlled directory contents.
    pub fn list_bounded(
        &self,
        path: &VirtualPath,
        max_entries: usize,
    ) -> FsResult<Vec<DirectoryEntry>> {
        let directory = self.share.open_directory(&path.0)?;
        let mut result = Vec::with_capacity(max_entries.min(256));
        for (scanned, entry) in directory.entries().map_err(map_io)?.enumerate() {
            if scanned == max_entries {
                return Err(FsError::new(FsErrorCode::TooLarge));
            }
            let entry = entry.map_err(map_io)?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if is_internal_name(&name) {
                continue;
            }
            let Ok(name) = EntryName::new(name) else {
                continue;
            };
            let metadata = entry.metadata().map_err(map_io)?;
            let kind = match classify_metadata(&metadata) {
                Ok(kind) => kind,
                Err(error) if error.code() == FsErrorCode::UnsupportedEntry => continue,
                Err(error) => return Err(error),
            };
            if let Err(error) = assert_no_external_alias(&metadata, kind) {
                if error.code() == FsErrorCode::UnsupportedEntry {
                    continue;
                }
                return Err(error);
            }
            result.push(DirectoryEntry {
                name,
                kind,
                size: metadata.len(),
                modified: metadata.modified().ok().map(|time| time.into_std()),
                file_id: metadata_identity(&metadata),
            });
        }
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }

    pub fn open_file(&self, path: &VirtualPath) -> FsResult<OpenedFile> {
        let file = self.open_regular_file(path, false)?;
        let metadata = file.metadata().map_err(map_io)?;
        Ok(OpenedFile {
            file,
            len: metadata.len(),
            modified: metadata.modified().ok().map(|time| time.into_std()),
            file_id: metadata_identity(&metadata),
        })
    }

    /// Reads metadata from an opened no-follow handle rather than trusting a
    /// path-based pre-check. Files and directories are the only accepted kinds.
    pub fn metadata(&self, path: &VirtualPath) -> FsResult<EntryMetadata> {
        match self.open_regular_file(path, false) {
            Ok(file) => {
                let metadata = file.metadata().map_err(map_io)?;
                Ok(entry_metadata(&metadata, EntryKind::File))
            }
            Err(error) if error.code() == FsErrorCode::UnsupportedEntry => {
                let (parent, name) = self.share.open_parent(path)?;
                let directory = parent.open_dir_nofollow(name.as_str()).map_err(map_io)?;
                let metadata = directory.dir_metadata().map_err(map_io)?;
                let kind = classify_metadata(&metadata)?;
                if kind != EntryKind::Directory {
                    return Err(FsError::new(FsErrorCode::UnsupportedEntry));
                }
                Ok(entry_metadata(&metadata, kind))
            }
            Err(error) => Err(error),
        }
    }

    pub fn read_file(&self, path: &VirtualPath, max_bytes: u64) -> FsResult<Vec<u8>> {
        let mut file = self.open_regular_file(path, false)?;
        let metadata = file.metadata().map_err(map_io)?;
        if metadata.len() > max_bytes {
            return Err(FsError::new(FsErrorCode::TooLarge));
        }
        let take_limit = max_bytes.saturating_add(1);
        let mut bytes = Vec::with_capacity(metadata.len().min(max_bytes) as usize);
        Read::by_ref(&mut file)
            .take(take_limit)
            .read_to_end(&mut bytes)
            .map_err(map_io)?;
        if bytes.len() as u64 > max_bytes {
            return Err(FsError::new(FsErrorCode::TooLarge));
        }
        Ok(bytes)
    }

    pub fn create_file(&self, path: &VirtualPath, contents: &[u8]) -> FsResult<()> {
        let pending = self.begin_write(path)?;
        pending.writer()?.write_all(contents).map_err(map_io)?;
        pending.publish_new()
    }

    pub fn create_directory(&self, path: &VirtualPath) -> FsResult<()> {
        self.require_write()?;
        let (parent, name) = self.share.open_parent(path)?;
        parent.create_dir(name.as_str()).map_err(map_io)?;
        // Re-open without following so a concurrently substituted link is never accepted.
        parent.open_dir_nofollow(name.as_str()).map_err(map_io)?;
        sync_directory(&parent)
    }

    pub fn begin_write(&self, path: &VirtualPath) -> FsResult<PendingWrite> {
        self.require_write()?;
        let (destination_parent, destination_name) = self.share.open_parent(path)?;
        let staging = self
            .share
            .staging
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?
            .try_clone()
            .map_err(map_io)?;
        ensure_same_device(&staging, &destination_parent)?;
        for _ in 0..16 {
            let temporary_name = random_temporary_name()?;
            let mut options = secure_file_options();
            options.read(true).write(true).create_new(true);
            match staging.open_with(&temporary_name, &options) {
                Ok(file) => {
                    validate_regular_handle(&file)?;
                    return Ok(PendingWrite {
                        staging,
                        destination_parent,
                        temporary_name,
                        destination_name: destination_name.clone(),
                        file,
                        published: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_io(error)),
            }
        }
        Err(FsError::new(FsErrorCode::Unavailable))
    }

    pub fn move_entry(
        &self,
        source: &VirtualPath,
        destination: &VirtualPath,
        expected: EntryMetadata,
    ) -> FsResult<()> {
        self.require_write()?;
        if source == destination {
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        let current = self.metadata(source)?;
        if !current.matches_validator(&expected) {
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        if current.kind == EntryKind::Directory && destination.starts_with(source) {
            return Err(FsError::new(FsErrorCode::InvalidPath));
        }
        let (source_parent, source_name) = self.share.open_parent(source)?;
        let (destination_parent, destination_name) = self.share.open_parent(destination)?;
        rustix::fs::renameat_with(
            &source_parent,
            source_name.as_str(),
            &destination_parent,
            destination_name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_io(std::io::Error::from(error)))?;

        match metadata_in_parent(&destination_parent, destination_name) {
            Ok(moved) if moved.matches_validator(&expected) => {
                sync_directory(&source_parent)?;
                sync_directory(&destination_parent)
            }
            validation => {
                let rollback = rustix::fs::renameat_with(
                    &destination_parent,
                    destination_name.as_str(),
                    &source_parent,
                    source_name.as_str(),
                    rustix::fs::RenameFlags::NOREPLACE,
                );
                if rollback.is_err() {
                    return Err(FsError::new(FsErrorCode::Unavailable));
                }
                validation.and_then(|_| Err(FsError::new(FsErrorCode::Conflict)))
            }
        }
    }

    pub fn delete_entry(&self, path: &VirtualPath, expected: EntryMetadata) -> FsResult<()> {
        self.require_write()?;
        let current = self.metadata(path)?;
        if !current.matches_validator(&expected) {
            return Err(FsError::new(FsErrorCode::Conflict));
        }
        let (parent, name) = self.share.open_parent(path)?;
        let staging = self
            .share
            .staging
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?;
        ensure_same_device(staging, &parent)?;
        let staged_name = random_temporary_name()?;
        rustix::fs::renameat_with(
            &parent,
            name.as_str(),
            staging,
            &staged_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_io(std::io::Error::from(error)))?;
        let staged = metadata_in_parent_raw(staging, &staged_name);
        if staged.as_ref().is_err()
            || staged
                .as_ref()
                .is_ok_and(|value| !value.matches_validator(&expected))
        {
            let rollback = rustix::fs::renameat_with(
                staging,
                &staged_name,
                &parent,
                name.as_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            );
            return if rollback.is_err() {
                Err(FsError::new(FsErrorCode::Unavailable))
            } else {
                Err(FsError::new(FsErrorCode::Conflict))
            };
        }
        let removal = match expected.kind {
            EntryKind::File => staging.remove_file(&staged_name),
            EntryKind::Directory => staging.remove_dir(&staged_name),
        };
        if let Err(error) = removal {
            let rollback = rustix::fs::renameat_with(
                staging,
                &staged_name,
                &parent,
                name.as_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            );
            return if rollback.is_err() {
                Err(FsError::new(FsErrorCode::Unavailable))
            } else {
                Err(map_io(error))
            };
        }
        sync_directory(staging)?;
        sync_directory(&parent)
    }

    pub fn usage_bounded(&self, max_entries: usize, max_bytes: u64) -> FsResult<u64> {
        let mut entries = 0_usize;
        let mut bytes = 0_u64;
        measure_directory(
            &self.share.root,
            &mut entries,
            max_entries,
            &mut bytes,
            max_bytes,
            0,
        )?;
        Ok(bytes)
    }

    fn open_regular_file(&self, path: &VirtualPath, write: bool) -> FsResult<File> {
        let (parent, name) = self.share.open_parent(path)?;
        let mut options = secure_file_options();
        options.read(!write).write(write);
        let file = parent.open_with(name.as_str(), &options).map_err(map_io)?;
        validate_regular_handle(&file)?;
        Ok(file)
    }

    fn require_write(&self) -> FsResult<()> {
        (self.access == AccessLevel::ReadWrite)
            .then_some(())
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))
    }
}

fn metadata_in_parent(parent: &Dir, name: &EntryName) -> FsResult<EntryMetadata> {
    metadata_in_parent_raw(parent, name.as_str())
}

fn metadata_in_parent_raw(parent: &Dir, name: &str) -> FsResult<EntryMetadata> {
    let mut options = secure_file_options();
    options.read(true);
    match parent.open_with(name, &options) {
        Ok(file) => {
            // Linux permits opening a directory with O_RDONLY. Preserve that
            // classification here: this helper validates both staged files and
            // staged directories after a same-parent rename.
            let metadata = file.metadata().map_err(map_io)?;
            let kind = classify_metadata(&metadata)?;
            assert_no_external_alias(&metadata, kind)?;
            Ok(entry_metadata(&metadata, kind))
        }
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(6) | Some(19) | Some(21) | Some(40)
            ) =>
        {
            let directory = parent.open_dir_nofollow(name).map_err(map_io)?;
            let metadata = directory.dir_metadata().map_err(map_io)?;
            let kind = classify_metadata(&metadata)?;
            (kind == EntryKind::Directory)
                .then(|| entry_metadata(&metadata, kind))
                .ok_or_else(|| FsError::new(FsErrorCode::UnsupportedEntry))
        }
        Err(error) => Err(map_io(error)),
    }
}

fn raw_file_metadata(file: &File) -> FsResult<EntryMetadata> {
    let metadata = file.metadata().map_err(map_io)?;
    let kind = classify_metadata(&metadata)?;
    (kind == EntryKind::File)
        .then(|| entry_metadata(&metadata, kind))
        .ok_or_else(|| FsError::new(FsErrorCode::UnsupportedEntry))
}

fn open_staging_directory(root: &Dir) -> FsResult<Dir> {
    let created =
        match rustix::fs::mkdirat(root, INTERNAL_STAGING_DIRECTORY, rustix::fs::Mode::RWXU) {
            Ok(()) => true,
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists =>
            {
                false
            }
            Err(error) => return Err(map_io(std::io::Error::from(error))),
        };
    let descriptor = rustix::fs::openat(
        root,
        INTERNAL_STAGING_DIRECTORY,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| map_io(std::io::Error::from(error)))?;
    rustix::fs::fchmod(&descriptor, rustix::fs::Mode::RWXU)
        .map_err(|error| map_io(std::io::Error::from(error)))?;
    let staging = root
        .open_dir_nofollow(INTERNAL_STAGING_DIRECTORY)
        .map_err(map_io)?;
    if !staging.dir_metadata().map_err(map_io)?.is_dir() {
        return Err(FsError::new(FsErrorCode::UnsupportedEntry));
    }
    if created {
        sync_directory(&staging)?;
        sync_directory(root)?;
    }
    Ok(staging)
}

fn ensure_same_device(staging: &Dir, destination: &Dir) -> FsResult<()> {
    let staging_device = staging.dir_metadata().map_err(map_io)?.dev();
    let destination_device = destination.dir_metadata().map_err(map_io)?.dev();
    (staging_device == destination_device)
        .then_some(())
        .ok_or_else(|| FsError::new(FsErrorCode::CrossDevice))
}

fn recover_staging_directory(staging: &Dir, max_entries: usize) -> FsResult<usize> {
    let mut visited = 0_usize;
    let mut recoverable = Vec::with_capacity(max_entries.min(256));
    for entry in staging.entries().map_err(map_io)? {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| FsError::new(FsErrorCode::TooLarge))?;
        if visited > max_entries {
            return Err(FsError::new(FsErrorCode::TooLarge));
        }
        let entry = entry.map_err(map_io)?;
        let Ok(name) = entry.file_name().into_string() else {
            // A non-UTF-8 name cannot match the reserved ASCII namespace.
            continue;
        };
        let file_type = entry.file_type().map_err(map_io)?;
        if !is_internal_temp_name(&name) || !file_type.is_file() {
            // Never follow or remove malformed names, symlinks, directories,
            // or special entries, even inside the private staging directory.
            continue;
        }
        recoverable.push(name);
    }
    for name in &recoverable {
        staging.remove_file(name).map_err(map_io)?;
    }
    if !recoverable.is_empty() {
        sync_directory(staging)?;
    }
    Ok(recoverable.len())
}

fn measure_directory(
    directory: &Dir,
    entries: &mut usize,
    max_entries: usize,
    bytes: &mut u64,
    max_bytes: u64,
    depth: usize,
) -> FsResult<()> {
    if depth > 256 {
        return Err(FsError::new(FsErrorCode::TooLarge));
    }
    for entry in directory.entries().map_err(map_io)? {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| FsError::new(FsErrorCode::TooLarge))?;
        if *entries > max_entries {
            return Err(FsError::new(FsErrorCode::TooLarge));
        }
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| FsError::new(FsErrorCode::UnsupportedEntry))?;
        if is_internal_name(&name) {
            continue;
        }
        let metadata = entry.metadata().map_err(map_io)?;
        let kind = classify_metadata(&metadata)?;
        assert_no_external_alias(&metadata, kind)?;
        match kind {
            EntryKind::Directory => {
                let child = directory.open_dir_nofollow(&name).map_err(map_io)?;
                measure_directory(&child, entries, max_entries, bytes, max_bytes, depth + 1)?;
            }
            EntryKind::File => {
                *bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| FsError::new(FsErrorCode::TooLarge))?;
                if *bytes > max_bytes {
                    return Err(FsError::new(FsErrorCode::TooLarge));
                }
            }
        }
    }
    Ok(())
}

fn random_temporary_name() -> FsResult<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| FsError::new(FsErrorCode::Unavailable))?;
    let mut name = String::with_capacity(INTERNAL_TEMP_PREFIX.len() + bytes.len() * 2);
    name.push_str(INTERNAL_TEMP_PREFIX);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(name)
}

fn is_internal_temp_name(name: &str) -> bool {
    name.strip_prefix(INTERNAL_TEMP_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn is_internal_name(name: &str) -> bool {
    name == INTERNAL_STAGING_DIRECTORY || is_internal_temp_name(name)
}

fn sync_directory(directory: &Dir) -> FsResult<()> {
    let descriptor = rustix::fs::openat(
        directory,
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| map_io(std::io::Error::from(error)))?;
    match rustix::fs::fsync(descriptor) {
        Ok(()) => Ok(()),
        // Some container/overlay filesystems do not implement directory
        // fsync. File contents are still synced before publication.
        Err(error) if std::io::Error::from(error).kind() == std::io::ErrorKind::InvalidInput => {
            Ok(())
        }
        Err(error) => Err(map_io(std::io::Error::from(error))),
    }
}

fn secure_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.follow(FollowSymlinks::No).nonblock(true);
    options
}

fn validate_regular_handle(file: &File) -> FsResult<()> {
    let metadata = file.metadata().map_err(map_io)?;
    let kind = classify_metadata(&metadata)?;
    if kind != EntryKind::File {
        return Err(FsError::new(FsErrorCode::UnsupportedEntry));
    }
    assert_no_external_alias(&metadata, kind)
}

fn classify_metadata(metadata: &cap_std::fs::Metadata) -> FsResult<EntryKind> {
    if metadata.is_file() {
        Ok(EntryKind::File)
    } else if metadata.is_dir() {
        Ok(EntryKind::Directory)
    } else {
        Err(FsError::new(FsErrorCode::UnsupportedEntry))
    }
}

fn entry_metadata(metadata: &cap_std::fs::Metadata, kind: EntryKind) -> EntryMetadata {
    EntryMetadata {
        kind,
        size: metadata.len(),
        modified: metadata.modified().ok().map(|time| time.into_std()),
        accessed: metadata.accessed().ok().map(|time| time.into_std()),
        created: metadata.created().ok().map(|time| time.into_std()),
        file_id: metadata_identity(metadata),
    }
}

#[cfg(unix)]
fn metadata_identity(metadata: &cap_std::fs::Metadata) -> u64 {
    metadata.ino()
}

#[cfg(not(unix))]
fn metadata_identity(_metadata: &cap_std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn assert_no_external_alias(metadata: &cap_std::fs::Metadata, kind: EntryKind) -> FsResult<()> {
    if kind == EntryKind::File && metadata.nlink() != 1 {
        return Err(FsError::new(FsErrorCode::UnsupportedEntry));
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_no_external_alias(_metadata: &cap_std::fs::Metadata, _kind: EntryKind) -> FsResult<()> {
    // Production v1 is Linux-only. Other targets retain capability and
    // no-follow enforcement but cannot make the hard-link alias guarantee.
    Err(FsError::new(FsErrorCode::UnsupportedEntry))
}

fn contains_percent_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

fn is_windows_device_name(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or(value).to_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = stem.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let suffix: String = chars.collect();
    matches!(prefix.as_str(), "COM" | "LPT")
        && suffix.chars().count() == 1
        && suffix
            .chars()
            .all(|character| character.is_ascii_digit() || "⁰¹²³⁴⁵⁶⁷⁸⁹".contains(character))
}

fn map_io(error: std::io::Error) -> FsError {
    use std::io::ErrorKind;
    // Linux returns ELOOP (40) when O_NOFOLLOW rejects a final symbolic link,
    // and ENXIO/ENODEV (6/19) when opening some special files. Treat those as
    // unsupported entries rather than operational failures so the HTTP
    // boundary can use the same non-disclosing response as missing and
    // unauthorized paths. Linux is the explicitly supported v1 target.
    let code = if matches!(error.raw_os_error(), Some(6) | Some(19) | Some(40)) {
        FsErrorCode::UnsupportedEntry
    } else {
        match error.kind() {
            ErrorKind::NotFound | ErrorKind::NotADirectory => FsErrorCode::NotFound,
            ErrorKind::AlreadyExists | ErrorKind::DirectoryNotEmpty => FsErrorCode::Conflict,
            ErrorKind::InvalidInput | ErrorKind::InvalidFilename => FsErrorCode::InvalidPath,
            ErrorKind::PermissionDenied => FsErrorCode::AccessDenied,
            _ => FsErrorCode::Unavailable,
        }
    };
    FsError::new(code)
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, thread};

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;

    fn fixture() -> (TempDir, ShareFs, ShareGrant, ShareGrant) {
        let temporary = TempDir::new().expect("temporary directory");
        fs::write(temporary.path().join("hello.txt"), b"hello").expect("fixture file");
        fs::create_dir(temporary.path().join("nested")).expect("fixture directory");
        fs::write(temporary.path().join("nested/inside.txt"), b"inside")
            .expect("nested fixture file");
        let id = ShareId::new("documents").expect("valid share id");
        let share = ShareFs::open(id.clone(), temporary.path()).expect("open share");
        let read = ShareGrant {
            share_id: id.clone(),
            access: AccessLevel::ReadOnly,
        };
        let write = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadWrite,
        };
        (temporary, share, read, write)
    }

    #[test]
    fn path_parser_rejects_ambiguous_or_escaping_input() {
        let invalid = [
            "",
            "/etc/passwd",
            "etc/",
            "one//two",
            ".",
            "..",
            "one/../two",
            r"one\two",
            "file%2fname",
            "file%2Ename",
            "nul",
            "COM1.txt",
            "LPT¹",
            "trailing.",
            "trailing ",
            "control\nname",
            "e\u{301}.txt",
        ];
        for value in invalid {
            assert_eq!(
                VirtualPath::parse(value).expect_err(value).code(),
                FsErrorCode::InvalidPath,
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn path_parser_preserves_linux_names_normalized_unicode_and_literal_percent() {
        let path =
            VirtualPath::parse("日本語/café/report: 100%done.txt").expect("valid Unicode path");
        assert_eq!(path.to_string(), "日本語/café/report: 100%done.txt");
    }

    #[test]
    fn path_length_properties_hold_at_boundaries() {
        for length in [1, 2, 63, 254, 255] {
            let value = "a".repeat(length);
            assert!(EntryName::new(value).is_ok());
        }
        for length in [0, 256, 1024, 4097] {
            let value = "a".repeat(length);
            assert!(EntryName::new(value).is_err());
        }
        let too_long = format!("{}/{}", "a".repeat(2048), "b".repeat(2048));
        assert_eq!(
            VirtualPath::parse(&too_long)
                .expect_err("path is too long")
                .code(),
            FsErrorCode::InvalidPath
        );
    }

    #[test]
    fn authorization_matrix_is_exhaustive() {
        let (_temporary, share, read, write) = fixture();
        let wrong = ShareGrant {
            share_id: ShareId::new("other").expect("valid id"),
            access: AccessLevel::ReadWrite,
        };
        let cases = [
            (None, false, None),
            (None, true, None),
            (Some(&wrong), false, None),
            (Some(&wrong), true, None),
            (Some(&read), false, Some(AccessLevel::ReadOnly)),
            (Some(&read), true, Some(AccessLevel::ReadOnly)),
            (Some(&write), false, Some(AccessLevel::ReadWrite)),
            (Some(&write), true, Some(AccessLevel::ReadOnly)),
        ];
        for (grant, global_read_only, expected) in cases {
            let result = share.authorize(
                grant,
                GlobalPolicy {
                    read_only: global_read_only,
                },
            );
            match expected {
                Some(access) => assert_eq!(result.expect("authorized").access(), access),
                None => assert_eq!(
                    result.err().expect("denied").code(),
                    FsErrorCode::AccessDenied
                ),
            }
        }
    }

    #[test]
    fn read_only_and_global_read_only_block_mutations() {
        let (_temporary, share, read, write) = fixture();
        let path = VirtualPath::parse("new.txt").expect("valid path");
        let read_only = share
            .authorize(Some(&read), GlobalPolicy::default())
            .expect("read access");
        assert_eq!(
            read_only
                .create_file(&path, b"no")
                .expect_err("read only")
                .code(),
            FsErrorCode::AccessDenied
        );
        let globally_read_only = share
            .authorize(Some(&write), GlobalPolicy { read_only: true })
            .expect("read access");
        assert_eq!(
            globally_read_only
                .create_file(&path, b"no")
                .expect_err("global read only")
                .code(),
            FsErrorCode::AccessDenied
        );
    }

    #[test]
    fn basic_operations_are_directory_relative() {
        let (_temporary, share, _read, write) = fixture();
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        assert_eq!(
            authorized
                .read_file(&VirtualPath::parse("hello.txt").expect("path"), 5)
                .expect("read"),
            b"hello"
        );
        assert_eq!(
            authorized
                .read_file(&VirtualPath::parse("hello.txt").expect("path"), 4)
                .expect_err("bounded read")
                .code(),
            FsErrorCode::TooLarge
        );
        authorized
            .create_directory(&VirtualPath::parse("created").expect("path"))
            .expect("create directory");
        authorized
            .create_file(
                &VirtualPath::parse("created/file.txt").expect("path"),
                b"first",
            )
            .expect("create file");
        let listing = authorized
            .list(&VirtualPath::parse("created").expect("path"))
            .expect("list");
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].name.as_str(), "file.txt");
        assert_eq!(listing[0].kind, EntryKind::File);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_roots_are_rejected() {
        use std::os::unix::fs::symlink;

        let outside = TempDir::new().expect("outside directory");
        let link_parent = TempDir::new().expect("link parent");
        symlink(outside.path(), link_parent.path().join("root-link")).expect("root symlink");
        assert!(
            ShareFs::open(
                ShareId::new("linked").expect("id"),
                &link_parent.path().join("root-link")
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn nested_symlinks_and_special_files_are_rejected_without_poisoning_listing() {
        use std::{os::unix::fs::symlink, os::unix::net::UnixListener};

        let (temporary, share, read, _write) = fixture();
        let outside = TempDir::new().expect("outside");
        fs::write(outside.path().join("secret.txt"), b"secret").expect("secret");
        symlink(outside.path(), temporary.path().join("escape")).expect("symlink");
        let _socket = UnixListener::bind(temporary.path().join("socket")).expect("socket");
        let authorized = share
            .authorize(Some(&read), GlobalPolicy::default())
            .expect("authorized");
        for path in ["escape/secret.txt", "escape", "socket"] {
            let path = VirtualPath::parse(path).expect("valid virtual path");
            assert!(authorized.read_file(&path, 1024).is_err());
        }
        let listing = authorized
            .list(&VirtualPath::root())
            .expect("unsupported entries are omitted");
        assert!(listing.iter().all(|entry| entry.name.as_str() != "escape"));
        assert!(listing.iter().all(|entry| entry.name.as_str() != "socket"));
    }

    #[cfg(unix)]
    #[test]
    fn final_component_link_race_never_reads_outside() {
        use std::os::unix::fs::symlink;

        let (temporary, share, read, _write) = fixture();
        let outside = TempDir::new().expect("outside");
        fs::write(outside.path().join("secret.txt"), b"secret").expect("secret");
        let raced = temporary.path().join("raced.txt");
        fs::write(&raced, b"inside").expect("inside");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let attacker_stop = Arc::clone(&stop);
        let target = outside.path().join("secret.txt");
        let attacker = thread::spawn(move || {
            while !attacker_stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = fs::remove_file(&raced);
                let _ = symlink(&target, &raced);
                let _ = fs::remove_file(&raced);
                let _ = fs::write(&raced, b"inside");
            }
        });
        let authorized = share
            .authorize(Some(&read), GlobalPolicy::default())
            .expect("authorized");
        let path = VirtualPath::parse("raced.txt").expect("path");
        for _ in 0..2_000 {
            if let Ok(bytes) = authorized.read_file(&path, 32) {
                assert_ne!(bytes, b"secret");
                assert!(b"inside".starts_with(&bytes));
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        attacker.join().expect("attacker thread");
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_aliases_are_rejected() {
        let (temporary, share, read, _write) = fixture();
        fs::hard_link(
            temporary.path().join("hello.txt"),
            temporary.path().join("alias.txt"),
        )
        .expect("hard link");
        let authorized = share
            .authorize(Some(&read), GlobalPolicy::default())
            .expect("authorized");
        assert_eq!(
            authorized
                .read_file(&VirtualPath::parse("alias.txt").expect("path"), 32)
                .expect_err("alias rejected")
                .code(),
            FsErrorCode::UnsupportedEntry
        );
    }

    #[test]
    fn overlapping_shares_do_not_share_authority() {
        let root = TempDir::new().expect("root");
        fs::create_dir(root.path().join("child")).expect("child");
        fs::write(root.path().join("root.txt"), b"root").expect("root file");
        fs::write(root.path().join("child/child.txt"), b"child").expect("child file");
        let root_id = ShareId::new("root").expect("id");
        let child_id = ShareId::new("child").expect("id");
        let root_share = ShareFs::open(root_id.clone(), root.path()).expect("root share");
        let child_share =
            ShareFs::open(child_id.clone(), &root.path().join("child")).expect("child share");
        let root_grant = ShareGrant {
            share_id: root_id,
            access: AccessLevel::ReadWrite,
        };
        assert_eq!(
            child_share
                .authorize(Some(&root_grant), GlobalPolicy::default())
                .err()
                .expect("wrong share denied")
                .code(),
            FsErrorCode::AccessDenied
        );
        let root_access = root_share
            .authorize(Some(&root_grant), GlobalPolicy::default())
            .expect("root access");
        assert_eq!(
            root_access
                .read_file(&VirtualPath::parse("child/child.txt").expect("path"), 32)
                .expect("overlap is explicitly in root share"),
            b"child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_names_are_omitted_without_lossy_conversion() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let (temporary, share, read, _write) = fixture();
        fs::write(
            temporary.path().join(OsString::from_vec(vec![0xff, b'x'])),
            b"invalid",
        )
        .expect("invalid UTF-8 fixture");
        let authorized = share
            .authorize(Some(&read), GlobalPolicy::default())
            .expect("authorized");
        let listing = authorized
            .list(&VirtualPath::root())
            .expect("invalid UTF-8 entry omitted");
        let names = listing
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["hello.txt", "nested"]);
    }

    #[test]
    fn pending_writes_publish_atomically_and_clean_up_on_drop() {
        let (temporary, share, _read, write) = fixture();
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let created = VirtualPath::parse("created.txt").expect("path");
        let pending = authorized.begin_write(&created).expect("temporary file");
        let mut writer = pending.writer().expect("cloned writer");
        writer.write_all(b"complete").expect("write temporary");
        writer.sync_all().expect("sync temporary");
        drop(writer);
        assert!(!temporary.path().join("created.txt").exists());
        pending.publish_new().expect("atomic publish");
        assert_eq!(
            fs::read(temporary.path().join("created.txt")).unwrap(),
            b"complete"
        );

        let abandoned = authorized
            .begin_write(&VirtualPath::parse("abandoned.txt").expect("path"))
            .expect("temporary file");
        let mut writer = abandoned.writer().expect("cloned writer");
        writer.write_all(b"partial").expect("partial write");
        drop(writer);
        drop(abandoned);
        assert!(!temporary.path().join("abandoned.txt").exists());
        assert!(
            fs::read_dir(temporary.path().join(INTERNAL_STAGING_DIRECTORY))
                .unwrap()
                .all(|entry| !is_internal_temp_name(&entry.unwrap().file_name().to_string_lossy()))
        );
    }

    #[test]
    fn replacement_requires_unchanged_metadata_and_conflicts_preserve_target() {
        let (temporary, share, _read, write) = fixture();
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let path = VirtualPath::parse("hello.txt").expect("path");
        let expected = authorized.metadata(&path).expect("metadata");
        let pending = authorized.begin_write(&path).expect("temporary file");
        pending
            .writer()
            .expect("writer")
            .write_all(b"replacement")
            .expect("write replacement");
        fs::write(temporary.path().join("hello.txt"), b"changed concurrently")
            .expect("concurrent change");
        assert_eq!(
            pending
                .publish_replacement(expected)
                .expect_err("stale precondition")
                .code(),
            FsErrorCode::Conflict
        );
        assert_eq!(
            fs::read(temporary.path().join("hello.txt")).unwrap(),
            b"changed concurrently"
        );
    }

    #[test]
    fn moves_are_no_replace_and_deletes_are_non_recursive() {
        let (temporary, share, _read, write) = fixture();
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let source = VirtualPath::parse("hello.txt").expect("path");
        let occupied = VirtualPath::parse("nested/inside.txt").expect("path");
        let expected = authorized.metadata(&source).expect("metadata");
        let mut timestamp_only_change = expected;
        timestamp_only_change.accessed = Some(SystemTime::UNIX_EPOCH);
        timestamp_only_change.created =
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1));
        assert!(timestamp_only_change.matches_validator(&expected));
        assert_eq!(
            authorized
                .move_entry(&source, &occupied, expected)
                .expect_err("no overwrite")
                .code(),
            FsErrorCode::Conflict
        );
        assert_eq!(
            fs::read(temporary.path().join("hello.txt")).unwrap(),
            b"hello"
        );

        let destination = VirtualPath::parse("moved.txt").expect("path");
        authorized
            .move_entry(&source, &destination, expected)
            .expect("move");
        assert!(!temporary.path().join("hello.txt").exists());
        assert_eq!(
            fs::read(temporary.path().join("moved.txt")).unwrap(),
            b"hello"
        );

        let directory = VirtualPath::parse("nested").expect("path");
        let directory_metadata = authorized.metadata(&directory).expect("metadata");
        assert_eq!(
            authorized
                .delete_entry(&directory, directory_metadata)
                .expect_err("non-empty delete")
                .code(),
            FsErrorCode::Conflict
        );
        assert!(temporary.path().join("nested/inside.txt").exists());

        fs::create_dir(temporary.path().join("empty")).expect("empty directory");
        let empty = VirtualPath::parse("empty").expect("path");
        let empty_metadata = authorized.metadata(&empty).expect("metadata");
        authorized
            .delete_entry(&empty, empty_metadata)
            .expect("empty directory delete");
        assert!(!temporary.path().join("empty").exists());
    }

    #[test]
    fn directory_cannot_move_into_itself_and_usage_is_bounded() {
        let (_temporary, share, _read, write) = fixture();
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let source = VirtualPath::parse("nested").expect("path");
        let destination = VirtualPath::parse("nested/child").expect("path");
        let expected = authorized.metadata(&source).expect("metadata");
        assert_eq!(
            authorized
                .move_entry(&source, &destination, expected)
                .expect_err("self move")
                .code(),
            FsErrorCode::InvalidPath
        );
        assert_eq!(authorized.usage_bounded(10, 1024).expect("usage"), 11);
        assert_eq!(
            authorized
                .usage_bounded(1, 1024)
                .expect_err("entry limit")
                .code(),
            FsErrorCode::TooLarge
        );
    }

    #[test]
    fn startup_recovery_scans_only_private_staging() {
        let temporary = TempDir::new().expect("temporary directory");
        let stale = format!("{INTERNAL_TEMP_PREFIX}{}", "a".repeat(32));
        let user_stale = format!("{INTERNAL_TEMP_PREFIX}{}", "b".repeat(32));
        fs::create_dir(temporary.path().join("deep")).expect("user directory");
        fs::write(temporary.path().join(&user_stale), b"user data").expect("user temp-like file");
        fs::write(
            temporary.path().join("deep").join(&user_stale),
            b"nested user data",
        )
        .expect("nested user temp-like file");
        fs::write(temporary.path().join("keep.txt"), b"keep").expect("regular file");
        let share = ShareFs::open(ShareId::new("documents").expect("id"), temporary.path())
            .expect("open share");
        let staging = temporary.path().join(INTERNAL_STAGING_DIRECTORY);
        fs::write(staging.join(&stale), b"partial").expect("stale staged file");

        assert_eq!(share.recover_staging_files(10).expect("recover"), 1);

        assert!(!staging.join(stale).exists());
        assert!(temporary.path().join(&user_stale).exists());
        assert!(temporary.path().join("deep").join(user_stale).exists());
        assert!(temporary.path().join("keep.txt").exists());
    }

    #[test]
    fn staging_recovery_is_bounded_before_removing_anything() {
        let temporary = TempDir::new().expect("temporary directory");
        let share = ShareFs::open(ShareId::new("documents").expect("id"), temporary.path())
            .expect("open share");
        let staging = temporary.path().join(INTERNAL_STAGING_DIRECTORY);
        let first = format!("{INTERNAL_TEMP_PREFIX}{}", "a".repeat(32));
        let second = format!("{INTERNAL_TEMP_PREFIX}{}", "b".repeat(32));
        fs::write(staging.join(&first), b"first").expect("first staged file");
        fs::write(staging.join(&second), b"second").expect("second staged file");

        assert_eq!(
            share
                .recover_staging_files(1)
                .expect_err("staging bound")
                .code(),
            FsErrorCode::TooLarge
        );
        assert!(staging.join(first).exists());
        assert!(staging.join(second).exists());
    }

    #[test]
    fn read_only_shares_create_no_staging_and_reduce_write_grants() {
        let temporary = TempDir::new().expect("temporary directory");
        let id = ShareId::new("documents").expect("id");
        let share = ShareFs::open_read_only(id.clone(), temporary.path()).expect("read-only share");
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadWrite,
        };

        assert!(!temporary.path().join(INTERNAL_STAGING_DIRECTORY).exists());
        assert_eq!(
            share
                .authorize(Some(&grant), GlobalPolicy::default())
                .expect("authorized")
                .access(),
            AccessLevel::ReadOnly
        );
        assert_eq!(share.recover_staging_files(0).expect("no recovery"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn writable_staging_is_private_and_reserved_from_virtual_paths() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TempDir::new().expect("temporary directory");
        ShareFs::open(ShareId::new("documents").expect("id"), temporary.path())
            .expect("open share");
        let metadata = fs::metadata(temporary.path().join(INTERNAL_STAGING_DIRECTORY))
            .expect("staging metadata");

        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            EntryName::new(INTERNAL_STAGING_DIRECTORY)
                .expect_err("reserved staging name")
                .code(),
            FsErrorCode::InvalidPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_recovery_ignores_links_special_files_and_non_utf8_names() {
        use std::{
            ffi::OsString,
            os::unix::{ffi::OsStringExt, fs::symlink, net::UnixListener},
        };

        let temporary = TempDir::new().expect("temporary directory");
        let outside = TempDir::new().expect("outside directory");
        let stale = format!("{INTERNAL_TEMP_PREFIX}{}", "a".repeat(32));
        let reserved_link = format!("{INTERNAL_TEMP_PREFIX}{}", "b".repeat(32));
        let reserved_directory = format!("{INTERNAL_TEMP_PREFIX}{}", "c".repeat(32));
        fs::write(outside.path().join("secret"), b"secret").expect("outside file");
        let share = ShareFs::open(ShareId::new("documents").expect("id"), temporary.path())
            .expect("open share");
        let staging = temporary.path().join(INTERNAL_STAGING_DIRECTORY);
        fs::write(staging.join(&stale), b"partial").expect("stale temp");
        symlink(outside.path().join("secret"), staging.join(&reserved_link))
            .expect("reserved symlink");
        fs::create_dir(staging.join(&reserved_directory)).expect("reserved directory");
        symlink(outside.path(), staging.join("directory-link")).expect("directory symlink");
        let _socket = UnixListener::bind(staging.join("socket")).expect("socket");
        let non_utf8 = OsString::from_vec(vec![0xff, b'x']);
        fs::write(staging.join(&non_utf8), b"legacy").expect("non-UTF-8 file");

        assert_eq!(share.recover_staging_files(20).expect("recover"), 1);
        assert!(!staging.join(stale).exists());
        assert!(staging.join(reserved_link).is_symlink());
        assert!(staging.join(reserved_directory).is_dir());
        assert!(staging.join("directory-link").is_symlink());
        assert!(staging.join("socket").exists());
        assert!(staging.join(non_utf8).exists());
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");
    }

    #[cfg(unix)]
    #[test]
    fn temporary_source_substitution_cannot_publish_a_symlink() {
        use std::os::unix::fs::symlink;

        let (temporary, share, _read, write) = fixture();
        let outside = TempDir::new().expect("outside directory");
        fs::write(outside.path().join("secret"), b"secret").expect("outside file");
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let destination = VirtualPath::parse("published.txt").expect("path");
        let pending = authorized
            .begin_write(&destination)
            .expect("temporary file");
        let temporary_name = pending.temporary_name.clone();
        let staging = temporary.path().join(INTERNAL_STAGING_DIRECTORY);
        fs::remove_file(staging.join(&temporary_name)).expect("unlink temp name");
        symlink(outside.path().join("secret"), staging.join(&temporary_name))
            .expect("replace temp with symlink");
        assert!(matches!(
            pending
                .publish_new()
                .expect_err("substitution rejected")
                .code(),
            FsErrorCode::Conflict | FsErrorCode::UnsupportedEntry
        ));
        assert!(!temporary.path().join("published.txt").exists());
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");
    }

    #[cfg(unix)]
    #[test]
    fn source_and_destination_symlink_races_never_follow_outside_share() {
        use std::os::unix::fs::symlink;

        let (temporary, share, _read, write) = fixture();
        let outside = TempDir::new().expect("outside directory");
        fs::write(outside.path().join("secret"), b"secret").expect("outside file");
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let source = VirtualPath::parse("hello.txt").expect("source");
        let destination = VirtualPath::parse("destination.txt").expect("destination");
        let expected = authorized.metadata(&source).expect("metadata");
        fs::remove_file(temporary.path().join("hello.txt")).expect("remove source");
        symlink(
            outside.path().join("secret"),
            temporary.path().join("hello.txt"),
        )
        .expect("source symlink");
        assert!(
            authorized
                .move_entry(&source, &destination, expected)
                .is_err()
        );
        assert!(!temporary.path().join("destination.txt").exists());
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");

        let delete_path = VirtualPath::parse("delete.txt").expect("delete path");
        fs::write(temporary.path().join("delete.txt"), b"delete").expect("delete fixture");
        let delete_expected = authorized.metadata(&delete_path).expect("metadata");
        fs::remove_file(temporary.path().join("delete.txt")).expect("remove delete source");
        symlink(
            outside.path().join("secret"),
            temporary.path().join("delete.txt"),
        )
        .expect("delete symlink");
        assert!(
            authorized
                .delete_entry(&delete_path, delete_expected)
                .is_err()
        );
        assert!(
            temporary
                .path()
                .join("delete.txt")
                .symlink_metadata()
                .is_ok()
        );
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");
    }

    #[test]
    fn concurrent_new_publications_have_one_deterministic_winner() {
        let (temporary, share, _read, write) = fixture();
        let authorized = share
            .authorize(Some(&write), GlobalPolicy::default())
            .expect("write access");
        let path = VirtualPath::parse("winner.txt").expect("path");
        let first = authorized.begin_write(&path).expect("first temp");
        first
            .writer()
            .expect("first writer")
            .write_all(b"first")
            .expect("first write");
        let second = authorized.begin_write(&path).expect("second temp");
        second
            .writer()
            .expect("second writer")
            .write_all(b"second")
            .expect("second write");
        first.publish_new().expect("first wins");
        assert_eq!(
            second.publish_new().expect_err("second conflicts").code(),
            FsErrorCode::Conflict
        );
        assert_eq!(
            fs::read(temporary.path().join("winner.txt")).unwrap(),
            b"first"
        );
    }

    proptest! {
        #[test]
        fn valid_component_sequences_round_trip(
            raw_components in proptest::collection::vec("[a-z]{1,32}", 1..16)
        ) {
            prop_assume!(raw_components
                .iter()
                .all(|component| EntryName::new(component.clone()).is_ok()));
            let encoded = raw_components.join("/");
            let parsed = VirtualPath::parse(&encoded).expect("generated valid path");
            let decoded = parsed
                .components()
                .map(EntryName::as_str)
                .collect::<Vec<_>>();
            prop_assert_eq!(decoded, raw_components);
            prop_assert_eq!(parsed.to_string(), encoded);
        }

        #[test]
        fn separators_and_percent_triplets_are_always_rejected(
            prefix in "[a-z]{1,24}",
            suffix in "[a-z]{1,24}",
            high in prop::sample::select(vec![b'0', b'2', b'9', b'a', b'A', b'f', b'F']),
            low in prop::sample::select(vec![b'0', b'2', b'9', b'a', b'A', b'f', b'F']),
        ) {
            for candidate in [
                format!("{prefix}\\{suffix}"),
                format!("{prefix}//{suffix}"),
                format!("{prefix}/../{suffix}"),
                format!("{prefix}%{}{}{suffix}", high as char, low as char),
            ] {
                prop_assert!(VirtualPath::parse(&candidate).is_err(), "accepted {candidate:?}");
            }
        }

        #[test]
        fn accepted_entry_names_satisfy_the_public_grammar(value in any::<String>()) {
            if let Ok(name) = EntryName::new(value.clone()) {
                prop_assert!(!name.as_str().is_empty());
                prop_assert!(name.as_str().len() <= MAX_COMPONENT_BYTES);
                prop_assert!(!name.as_str().contains(['/', '\\', '\0']));
                prop_assert!(!contains_percent_escape(name.as_str()));
                prop_assert!(name.as_str().nfc().eq(name.as_str().chars()));
                prop_assert_eq!(
                    VirtualPath::parse(name.as_str())
                        .expect("accepted entry is a valid one-component path")
                        .to_string(),
                    value
                );
            }
        }

        #[test]
        fn authorization_obeys_grant_and_global_read_only_properties(
            grant_kind in 0_u8..4,
            global_read_only in any::<bool>(),
        ) {
            let temporary = TempDir::new().expect("temporary directory");
            let id = ShareId::new("documents").expect("valid id");
            let share = ShareFs::open(id.clone(), temporary.path()).expect("open share");
            let grant = match grant_kind {
                0 => None,
                1 => Some(ShareGrant { share_id: id, access: AccessLevel::ReadOnly }),
                2 => Some(ShareGrant { share_id: id, access: AccessLevel::ReadWrite }),
                _ => Some(ShareGrant {
                    share_id: ShareId::new("another-share").expect("valid other id"),
                    access: AccessLevel::ReadWrite,
                }),
            };
            let result = share.authorize(
                grant.as_ref(),
                GlobalPolicy { read_only: global_read_only },
            );
            match (grant_kind, global_read_only) {
                (0 | 3, _) => prop_assert_eq!(
                    result.err().expect("missing grant denied").code(),
                    FsErrorCode::AccessDenied
                ),
                (1, _) | (_, true) => {
                    prop_assert_eq!(result.expect("read access").access(), AccessLevel::ReadOnly)
                }
                _ => prop_assert_eq!(
                    result.expect("write access").access(),
                    AccessLevel::ReadWrite
                ),
            }
        }
    }
}

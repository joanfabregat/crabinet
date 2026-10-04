//! An operator-configured private state directory, such as the thumbnail
//! cache.
//!
//! The ambient path is accepted once, at startup, and the directory is then
//! used only through its capability handle. Entries are flat regular files
//! whose names the caller chooses from a fixed alphabet; nothing here follows
//! a symbolic link or descends into a subdirectory.

use std::{
    io::{Read, Write},
    path::Path,
    time::SystemTime,
};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions, OpenOptionsExt as _, PermissionsExt as _},
};

/// One regular file found while scanning a private directory.
#[derive(Clone, Debug)]
pub struct PrivateEntry {
    pub name: String,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

/// Why a private directory could not be opened at startup.
#[derive(Debug, thiserror::Error)]
pub enum PrivateDirError {
    #[error("the path must be absolute and name a directory")]
    InvalidPath,
    #[error("the parent directory is missing or unreadable")]
    MissingParent,
    #[error("the path is a symbolic link or not a directory")]
    NotADirectory,
    #[error(
        "the directory is accessible by group or other users; run `chmod 700` on it as its owner"
    )]
    Shared,
    #[error("the directory cannot be created or opened: {0}")]
    Io(std::io::Error),
}

/// A capability for one flat, owner-only directory.
pub struct PrivateDir {
    dir: Dir,
}

impl PrivateDir {
    /// Opens `trusted_path`, creating it with mode `0700` when it is missing.
    ///
    /// An existing directory must not be a symbolic link and must already be
    /// owner-only: its permissions are checked, never changed, so pointing
    /// the setting at a shared directory refuses startup instead of quietly
    /// tightening someone else's permissions.
    pub fn open_or_create(trusted_path: &Path) -> Result<Self, PrivateDirError> {
        let (Some(parent), Some(name)) = (trusted_path.parent(), trusted_path.file_name()) else {
            return Err(PrivateDirError::InvalidPath);
        };
        if !trusted_path.is_absolute() {
            return Err(PrivateDirError::InvalidPath);
        }
        let parent = Dir::open_ambient_dir(parent, ambient_authority())
            .map_err(|_| PrivateDirError::MissingParent)?;
        match rustix::fs::mkdirat(&parent, name, rustix::fs::Mode::RWXU) {
            Ok(()) => {}
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PrivateDirError::Io(error.into())),
        }
        let metadata = parent.symlink_metadata(name).map_err(PrivateDirError::Io)?;
        if !metadata.is_dir() {
            return Err(PrivateDirError::NotADirectory);
        }
        let dir = parent
            .open_dir_nofollow(name)
            .map_err(|_| PrivateDirError::NotADirectory)?;
        let metadata = dir.dir_metadata().map_err(PrivateDirError::Io)?;
        if !metadata.is_dir() {
            return Err(PrivateDirError::NotADirectory);
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(PrivateDirError::Shared);
        }
        Ok(Self { dir })
    }

    /// Lists at most `max_entries` regular files. Other entry kinds are
    /// skipped and never followed.
    pub fn list(&self, max_entries: usize) -> std::io::Result<Vec<PrivateEntry>> {
        let mut found = Vec::new();
        for entry in self.dir.entries()? {
            if found.len() >= max_entries {
                break;
            }
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(metadata) = self.dir.symlink_metadata(&name) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            found.push(PrivateEntry {
                name,
                len: metadata.len(),
                modified: metadata
                    .modified()
                    .ok()
                    .map(cap_std::time::SystemTime::into_std),
            });
        }
        Ok(found)
    }

    /// Reads a regular file of at most `max_len` bytes. `Ok(None)` means it
    /// is missing; a larger file, a link, or a special file is an error.
    pub fn read(&self, name: &str, max_len: u64) -> std::io::Result<Option<Vec<u8>>> {
        check_name(name)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = match self.dir.open_with(name, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > max_len {
            return Err(std::io::Error::other("private entry is not a bounded file"));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.take(max_len.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max_len {
            return Err(std::io::Error::other(
                "private entry grew while it was read",
            ));
        }
        Ok(Some(bytes))
    }

    /// Writes `bytes` to `temporary` with mode `0600`, syncs it, and renames
    /// it over `name`, so a reader sees either the old entry or the complete
    /// new one. The temporary file is removed if any step fails.
    pub fn write_atomic(&self, temporary: &str, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        check_name(temporary)?;
        check_name(name)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .follow(FollowSymlinks::No);
        let result = self
            .dir
            .open_with(temporary, &options)
            .and_then(|mut file| {
                file.write_all(bytes)?;
                file.sync_data()?;
                drop(file);
                self.dir.rename(temporary, &self.dir, name)
            });
        if result.is_err() {
            let _ = self.dir.remove_file(temporary);
        }
        result
    }

    /// Removes a regular file; a missing entry is not an error.
    pub fn remove(&self, name: &str) -> std::io::Result<()> {
        check_name(name)?;
        match self.dir.remove_file(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

/// Entry names are single components; the capability already refuses an
/// escape, and this keeps a malformed name from reaching the filesystem.
fn check_name(name: &str) -> std::io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use super::*;

    #[test]
    fn creates_owner_only_and_refuses_shared_or_linked_directories() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("cache");
        let private = PrivateDir::open_or_create(&path).expect("created");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        private
            .write_atomic(".tmp-a", "entry.jpg", b"jpeg")
            .expect("write");
        assert_eq!(
            private.read("entry.jpg", 16).expect("read"),
            Some(b"jpeg".to_vec())
        );
        let file_mode = fs::metadata(path.join("entry.jpg"))
            .expect("entry metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600);
        assert!(private.read("entry.jpg", 3).is_err(), "bounded read");
        assert_eq!(private.read("missing.jpg", 16).expect("missing"), None);
        assert!(private.read("../escape", 16).is_err());
        assert_eq!(private.list(8).expect("list").len(), 1);
        private.remove("entry.jpg").expect("remove");
        private.remove("entry.jpg").expect("remove twice");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).expect("chmod");
        assert!(matches!(
            PrivateDir::open_or_create(&path),
            Err(PrivateDirError::Shared)
        ));

        let target = temporary.path().join("target");
        fs::create_dir(&target).expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(matches!(
            PrivateDir::open_or_create(&link),
            Err(PrivateDirError::NotADirectory)
        ));
        assert!(matches!(
            PrivateDir::open_or_create(&temporary.path().join("absent/cache")),
            Err(PrivateDirError::MissingParent)
        ));
    }
}

//! The on-disk thumbnail cache.
//!
//! Entries are flat files named by the hex cache key and the media type's
//! extension, written atomically with owner-only permissions in a private
//! directory. The key is a keyed hash of the share, virtual path, requested
//! size, and source identity (see [`super::cache_key`]), so names reveal
//! nothing about paths and are never derived from user input. The index of
//! sizes lives in memory and is rebuilt by a bounded scan at startup;
//! eviction removes the oldest entries until the total and the entry count
//! are under their limits. Callers authorize every request before they
//! look an entry up.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Mutex,
    time::SystemTime,
};

use crate::filesystem::{PrivateDir, PrivateDirError};

/// Entries the in-memory index tracks; the oldest are evicted beyond it.
const MAX_ENTRIES: usize = 65_536;
/// Directory entries a startup scan inspects.
const MAX_SCAN_ENTRIES: usize = 2 * MAX_ENTRIES;
/// A cached file larger than this is never written or served.
pub(crate) const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const TEMPORARY_PREFIX: &str = ".tmp-";

pub(crate) type CacheKey = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MediaKind {
    Jpeg,
    Png,
}

impl MediaKind {
    const fn extension(self) -> &'static str {
        match self {
            Self::Jpeg => "jpg",
            Self::Png => "png",
        }
    }

    pub(crate) const fn media_type(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
        }
    }

    pub(crate) fn from_media_type(media_type: &str) -> Option<Self> {
        match media_type {
            "image/jpeg" => Some(Self::Jpeg),
            "image/png" => Some(Self::Png),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    len: u64,
    sequence: u64,
    kind: MediaKind,
}

#[derive(Default)]
struct Index {
    entries: HashMap<CacheKey, Entry>,
    order: BTreeMap<u64, CacheKey>,
    total: u64,
    next_sequence: u64,
}

impl Index {
    fn insert(&mut self, key: CacheKey, len: u64, kind: MediaKind) {
        self.remove(&key);
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.entries.insert(
            key,
            Entry {
                len,
                sequence,
                kind,
            },
        );
        self.order.insert(sequence, key);
        self.total += len;
    }

    fn remove(&mut self, key: &CacheKey) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        self.order.remove(&entry.sequence);
        self.total -= entry.len;
        Some(entry)
    }

    /// Removes the oldest entries until both limits hold.
    fn evict(&mut self, max_bytes: u64) -> Vec<(CacheKey, MediaKind)> {
        let mut evicted = Vec::new();
        while self.total > max_bytes || self.entries.len() > MAX_ENTRIES {
            let Some((_, key)) = self.order.pop_first() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&key) {
                self.total -= entry.len;
                evicted.push((key, entry.kind));
            }
        }
        evicted
    }
}

pub struct ThumbnailCache {
    dir: PrivateDir,
    max_bytes: u64,
    index: Mutex<Index>,
}

#[derive(Debug, thiserror::Error)]
pub enum ThumbnailCacheError {
    #[error("thumbnail cache directory: {0}")]
    Directory(#[from] PrivateDirError),
    #[error("cannot scan the thumbnail cache directory: {0}")]
    Scan(std::io::Error),
}

fn file_name(key: &CacheKey, kind: MediaKind) -> String {
    let mut name = String::with_capacity(68);
    for byte in key {
        name.push_str(&format!("{byte:02x}"));
    }
    name.push('.');
    name.push_str(kind.extension());
    name
}

fn parse_name(name: &str) -> Option<(CacheKey, MediaKind)> {
    let (hex, extension) = name.split_once('.')?;
    let kind = match extension {
        "jpg" => MediaKind::Jpeg,
        "png" => MediaKind::Png,
        _ => return None,
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some((key, kind))
}

impl ThumbnailCache {
    /// Opens or creates the private cache directory and rebuilds the index
    /// from at most [`MAX_SCAN_ENTRIES`] files, oldest first. Leftover
    /// temporary files and empty or oversized entries are removed; files
    /// with any other name are left alone and ignored.
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self, ThumbnailCacheError> {
        let dir = PrivateDir::open_or_create(path)?;
        let mut found: Vec<(Option<SystemTime>, CacheKey, u64, MediaKind)> = Vec::new();
        for entry in dir
            .list(MAX_SCAN_ENTRIES)
            .map_err(ThumbnailCacheError::Scan)?
        {
            if entry.name.starts_with(TEMPORARY_PREFIX) {
                let _ = dir.remove(&entry.name);
                continue;
            }
            let Some((key, kind)) = parse_name(&entry.name) else {
                continue;
            };
            if entry.len == 0 || entry.len > MAX_ENTRY_BYTES {
                let _ = dir.remove(&entry.name);
                continue;
            }
            found.push((entry.modified, key, entry.len, kind));
        }
        found.sort_by_key(|(modified, ..)| *modified);
        let mut index = Index::default();
        for (_, key, len, kind) in found {
            index.insert(key, len, kind);
        }
        for (key, kind) in index.evict(max_bytes) {
            let _ = dir.remove(&file_name(&key, kind));
        }
        Ok(Self {
            dir,
            max_bytes,
            index: Mutex::new(index),
        })
    }

    /// Returns a cached thumbnail, or `None` on a miss. A file that vanished
    /// or became unreadable is dropped from the index and reported as a miss.
    pub(crate) fn get(&self, key: &CacheKey) -> Option<(Vec<u8>, MediaKind)> {
        let kind = self.index.lock().ok()?.entries.get(key)?.kind;
        match self.dir.read(&file_name(key, kind), MAX_ENTRY_BYTES) {
            Ok(Some(bytes)) if !bytes.is_empty() => Some((bytes, kind)),
            _ => {
                if let Ok(mut index) = self.index.lock() {
                    index.remove(key);
                }
                None
            }
        }
    }

    /// Stores a thumbnail and evicts the oldest entries beyond the limits.
    /// Failures are logged and otherwise ignored: the cache is optional.
    pub(crate) fn put(&self, key: &CacheKey, kind: MediaKind, bytes: &[u8]) {
        let len = bytes.len() as u64;
        if len == 0 || len > MAX_ENTRY_BYTES || len > self.max_bytes {
            return;
        }
        let mut random = [0_u8; 8];
        if getrandom::fill(&mut random).is_err() {
            return;
        }
        let mut temporary = String::from(TEMPORARY_PREFIX);
        for byte in random {
            temporary.push_str(&format!("{byte:02x}"));
        }
        if let Err(error) = self
            .dir
            .write_atomic(&temporary, &file_name(key, kind), bytes)
        {
            tracing::warn!(%error, "cannot write a thumbnail cache entry");
            return;
        }
        let evicted = match self.index.lock() {
            Ok(mut index) => {
                index.insert(*key, len, kind);
                index.evict(self.max_bytes)
            }
            Err(_) => return,
        };
        for (key, kind) in evicted {
            let _ = self.dir.remove(&file_name(&key, kind));
        }
    }

    #[cfg(test)]
    pub(crate) fn totals(&self) -> (usize, u64) {
        let index = self.index.lock().expect("index");
        (index.entries.len(), index.total)
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests inspect a temporary cache directory"
)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn evicts_oldest_first_and_rebuilds_from_disk() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("thumbnails");
        let cache = ThumbnailCache::open(&path, 10).expect("cache");
        cache.put(&[1; 32], MediaKind::Jpeg, b"aaaa");
        cache.put(&[2; 32], MediaKind::Png, b"bbbb");
        assert_eq!(
            cache.get(&[1; 32]),
            Some((b"aaaa".to_vec(), MediaKind::Jpeg))
        );
        // A third entry exceeds 10 bytes, so the oldest goes.
        cache.put(&[3; 32], MediaKind::Jpeg, b"cccc");
        assert_eq!(cache.get(&[1; 32]), None);
        assert!(cache.get(&[2; 32]).is_some());
        assert_eq!(cache.totals(), (2, 8));
        assert!(!path.join(file_name(&[1; 32], MediaKind::Jpeg)).exists());
        // An entry larger than the whole cache is not stored.
        cache.put(&[4; 32], MediaKind::Jpeg, &[0; 11]);
        assert_eq!(cache.get(&[4; 32]), None);

        // Leftovers and foreign names at startup.
        fs::write(path.join(".tmp-0011"), b"partial").expect("temporary");
        fs::write(path.join("notes.txt"), b"keep").expect("foreign");
        fs::write(path.join(file_name(&[5; 32], MediaKind::Png)), b"").expect("empty");
        drop(cache);
        let reopened = ThumbnailCache::open(&path, 4).expect("reopened");
        assert_eq!(
            reopened.totals().0,
            1,
            "rebuilt and evicted to the new limit"
        );
        assert!(!path.join(".tmp-0011").exists());
        assert!(path.join("notes.txt").exists());
        assert!(!path.join(file_name(&[5; 32], MediaKind::Png)).exists());

        // A vanished file is a miss and leaves the index.
        let survivor = if reopened.get(&[3; 32]).is_some() {
            [3; 32]
        } else {
            [2; 32]
        };
        for kind in [MediaKind::Jpeg, MediaKind::Png] {
            let _ = fs::remove_file(path.join(file_name(&survivor, kind)));
        }
        assert_eq!(reopened.get(&survivor), None);
        assert_eq!(reopened.totals(), (0, 0));
    }

    #[test]
    fn names_round_trip_and_reject_anything_else() {
        let key = [0xab; 32];
        assert_eq!(
            parse_name(&file_name(&key, MediaKind::Png)),
            Some((key, MediaKind::Png))
        );
        assert_eq!(parse_name("ab.jpg"), None);
        assert_eq!(parse_name(&format!("{}.gif", "a".repeat(64))), None);
        assert_eq!(parse_name(&format!("{}.jpg", "A".repeat(64))), None);
    }
}

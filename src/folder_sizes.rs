//! A short-lived, bounded cache of folder sizes.
//!
//! A folder's size takes a walk of everything beneath it, so results are kept
//! for [`FOLDER_SIZE_TTL`] and shared by every user granted the share; each
//! request is still authorized before the cache is consulted. Directory
//! modification times cannot validate an entry, because a change deep inside
//! a folder does not touch the folder itself. Instead, entries expire, and a
//! successful mutation or a directory event stream that observes a change
//! invalidates the affected folder, its ancestors, and everything beneath it.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use crate::filesystem::{FolderSize, ShareId, VirtualPath};

/// How long a computed size is served without walking the folder again.
pub(crate) const FOLDER_SIZE_TTL: Duration = Duration::from_secs(60);
/// Cached sizes across all shares. A key is at most one 4 KiB virtual path,
/// so the cache holds at most about 12 MiB even with maximal paths.
pub(crate) const MAX_CACHED_FOLDER_SIZES: usize = 2_048;

pub(crate) struct FolderSizeCache {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

struct Inner {
    entries: HashMap<(ShareId, VirtualPath), Cached>,
    /// Advanced by every invalidation, so a walk that an invalidation
    /// overtook does not store its possibly stale result.
    generation: u64,
}

struct Cached {
    size: FolderSize,
    stored: Instant,
}

/// The cache generation when a walk started; see [`FolderSizeCache::insert`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Generation(u64);

impl Default for FolderSizeCache {
    fn default() -> Self {
        Self::new(FOLDER_SIZE_TTL, MAX_CACHED_FOLDER_SIZES)
    }
}

impl FolderSizeCache {
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                generation: 0,
            }),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// The cached size, if one was stored within the TTL.
    pub(crate) fn get(&self, share_id: &ShareId, path: &VirtualPath) -> Option<FolderSize> {
        self.get_at(share_id, path, Instant::now())
    }

    fn get_at(&self, share_id: &ShareId, path: &VirtualPath, now: Instant) -> Option<FolderSize> {
        let mut inner = self.lock();
        let key = (share_id.clone(), path.clone());
        let cached = inner.entries.get(&key)?;
        if now.saturating_duration_since(cached.stored) < self.ttl {
            return Some(cached.size);
        }
        inner.entries.remove(&key);
        None
    }

    /// Taken before a walk starts and passed back to [`Self::insert`].
    pub(crate) fn generation(&self) -> Generation {
        Generation(self.lock().generation)
    }

    /// Stores a walk's result unless an invalidation happened since `started`.
    pub(crate) fn insert(
        &self,
        share_id: &ShareId,
        path: &VirtualPath,
        size: FolderSize,
        started: Generation,
    ) {
        self.insert_at(share_id, path, size, started, Instant::now());
    }

    fn insert_at(
        &self,
        share_id: &ShareId,
        path: &VirtualPath,
        size: FolderSize,
        started: Generation,
        now: Instant,
    ) {
        let mut inner = self.lock();
        if inner.generation != started.0 {
            return;
        }
        let key = (share_id.clone(), path.clone());
        if !inner.entries.contains_key(&key) && inner.entries.len() >= self.capacity {
            let ttl = self.ttl;
            inner
                .entries
                .retain(|_, cached| now.saturating_duration_since(cached.stored) < ttl);
            if inner.entries.len() >= self.capacity {
                let oldest = inner
                    .entries
                    .iter()
                    .min_by_key(|(_, cached)| cached.stored)
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    inner.entries.remove(&oldest);
                }
            }
        }
        inner.entries.insert(key, Cached { size, stored: now });
    }

    /// Forgets `path`, every folder containing it, and everything beneath it:
    /// a change at `path` alters the size of each ancestor, and an entry
    /// replaced at `path` makes every size beneath it unknown.
    pub(crate) fn invalidate(&self, share_id: &ShareId, path: &VirtualPath) {
        let mut inner = self.lock();
        inner.generation = inner.generation.wrapping_add(1);
        inner.entries.retain(|(cached_share, cached_path), _| {
            cached_share != share_id
                || !(path.starts_with(cached_path) || cached_path.starts_with(path))
        });
    }

    /// Forgets every size in one share.
    pub(crate) fn invalidate_share(&self, share_id: &ShareId) {
        self.invalidate(share_id, &VirtualPath::root());
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Every update leaves the map consistent, so a panic elsewhere while
        // the lock was held cannot leave a half-written entry.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(id: &str) -> ShareId {
        ShareId::new(id).expect("share id")
    }

    fn path(value: &str) -> VirtualPath {
        if value.is_empty() {
            VirtualPath::root()
        } else {
            VirtualPath::parse(value).expect("virtual path")
        }
    }

    const fn size(bytes: u64) -> FolderSize {
        FolderSize {
            bytes,
            complete: true,
        }
    }

    #[test]
    fn sizes_are_served_until_the_ttl_expires() {
        let cache = FolderSizeCache::new(Duration::from_secs(60), 16);
        let start = Instant::now();
        let docs = share("docs");
        cache.insert_at(&docs, &path("a"), size(5), cache.generation(), start);
        assert_eq!(
            cache.get_at(&docs, &path("a"), start + Duration::from_secs(59)),
            Some(size(5))
        );
        assert_eq!(cache.get_at(&share("other"), &path("a"), start), None);
        assert_eq!(
            cache.get_at(&docs, &path("a"), start + Duration::from_secs(60)),
            None
        );
        assert_eq!(cache.len(), 0, "an expired entry is removed when read");
    }

    #[test]
    fn invalidation_covers_ancestors_and_descendants_but_not_siblings() {
        let cache = FolderSizeCache::default();
        let docs = share("docs");
        let other = share("other");
        for value in ["", "a", "a/b", "a/b/c", "a/x", "b"] {
            cache.insert(&docs, &path(value), size(1), cache.generation());
        }
        cache.insert(&other, &path("a/b"), size(1), cache.generation());

        cache.invalidate(&docs, &path("a/b"));
        for gone in ["", "a", "a/b", "a/b/c"] {
            assert_eq!(cache.get(&docs, &path(gone)), None, "{gone:?} is stale");
        }
        for kept in ["a/x", "b"] {
            assert_eq!(cache.get(&docs, &path(kept)), Some(size(1)), "{kept:?}");
        }
        assert_eq!(cache.get(&other, &path("a/b")), Some(size(1)));

        cache.invalidate_share(&docs);
        assert_eq!(cache.get(&docs, &path("b")), None);
        assert_eq!(cache.get(&other, &path("a/b")), Some(size(1)));
    }

    #[test]
    fn a_walk_overtaken_by_an_invalidation_is_not_stored() {
        let cache = FolderSizeCache::default();
        let docs = share("docs");
        let started = cache.generation();
        cache.invalidate(&docs, &path("elsewhere"));
        cache.insert(&docs, &path("a"), size(1), started);
        assert_eq!(cache.get(&docs, &path("a")), None);
        cache.insert(&docs, &path("a"), size(2), cache.generation());
        assert_eq!(cache.get(&docs, &path("a")), Some(size(2)));
    }

    #[test]
    fn the_entry_count_is_bounded_by_evicting_the_oldest() {
        let cache = FolderSizeCache::new(Duration::from_secs(60), 3);
        let start = Instant::now();
        let docs = share("docs");
        for (offset, name) in ["a", "b", "c", "d"].into_iter().enumerate() {
            let at = start + Duration::from_secs(offset as u64);
            cache.insert_at(&docs, &path(name), size(1), cache.generation(), at);
        }
        assert_eq!(cache.len(), 3);
        let now = start + Duration::from_secs(4);
        assert_eq!(cache.get_at(&docs, &path("a"), now), None, "oldest evicted");
        for kept in ["b", "c", "d"] {
            assert_eq!(cache.get_at(&docs, &path(kept), now), Some(size(1)));
        }
        // Replacing an existing key never evicts another.
        cache.insert_at(&docs, &path("d"), size(2), cache.generation(), now);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get_at(&docs, &path("b"), now), Some(size(1)));
    }
}

//! Private extraction trees. All paths are validated and walked without links.
use super::*;

pub(super) const TREE_PREFIX: &str = ".index-arc-";
pub(super) fn is_tree_name(name: &str) -> bool {
    name.strip_prefix(TREE_PREFIX).is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub(crate) struct PendingTree {
    staging: Dir,
    root: Dir,
    parent: Dir,
    temporary: String,
    destination: EntryName,
    published: bool,
}

impl AuthorizedShare<'_> {
    pub(crate) fn begin_tree(&self, path: &VirtualPath) -> FsResult<PendingTree> {
        self.require_write()?;
        let (parent, destination) = self.share.open_parent(path)?;
        destination.ensure_creatable()?;
        let staging = self
            .share
            .staging
            .as_ref()
            .ok_or_else(|| FsError::new(FsErrorCode::AccessDenied))?
            .try_clone()
            .map_err(map_io)?;
        ensure_same_device(&staging, &parent)?;
        for _ in 0..16 {
            let temporary = random_temporary_name()?.replacen(INTERNAL_TEMP_PREFIX, TREE_PREFIX, 1);
            match rustix::fs::mkdirat(&staging, temporary.as_str(), rustix::fs::Mode::RWXU) {
                Ok(()) => {
                    let root = staging.open_dir_nofollow(&temporary).map_err(map_io)?;
                    return Ok(PendingTree {
                        staging,
                        root,
                        parent,
                        temporary,
                        destination: destination.clone(),
                        published: false,
                    });
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(map_io(error.into())),
            }
        }
        Err(FsError::new(FsErrorCode::Unavailable))
    }
}

impl PendingTree {
    fn parent(&self, path: &VirtualPath) -> FsResult<(Dir, EntryName)> {
        let (parent, name) = path
            .split_parent()
            .ok_or_else(|| FsError::new(FsErrorCode::InvalidPath))?;
        let mut dir = self.root.try_clone().map_err(map_io)?;
        for component in parent.components() {
            dir = dir.open_dir_nofollow(component.as_str()).map_err(map_io)?;
        }
        Ok((dir, name.clone()))
    }

    pub(crate) fn directory(&self, path: &VirtualPath) -> FsResult<()> {
        let (parent, name) = self.parent(path)?;
        parent.create_dir(name.as_str()).map_err(map_io)?;
        parent.open_dir_nofollow(name.as_str()).map_err(map_io)?;
        Ok(())
    }

    pub(crate) fn file(&self, path: &VirtualPath) -> FsResult<std::fs::File> {
        let (parent, name) = self.parent(path)?;
        let mut options = secure_file_options();
        options.write(true).create_new(true);
        let file = parent.open_with(name.as_str(), &options).map_err(map_io)?;
        validate_regular_handle(&file)?;
        Ok(file.into_std())
    }

    pub(crate) fn publish(mut self) -> FsResult<()> {
        sync_directory(&self.root)?;
        rustix::fs::renameat_with(
            &self.staging,
            self.temporary.as_str(),
            &self.parent,
            self.destination.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_io(error.into()))?;
        self.published = true;
        sync_after_commit(&self.staging);
        sync_after_commit(&self.parent);
        Ok(())
    }
}

pub(super) fn clean_tree(
    staging: &Dir,
    name: &str,
    count: &mut usize,
    max: usize,
) -> FsResult<bool> {
    let root = staging.open_dir_nofollow(name).map_err(map_io)?;
    if trash::remove_tree(&root, count, max, 0)? {
        staging.remove_dir(name).map_err(map_io)?;
        return Ok(true);
    }
    Ok(false)
}

impl Drop for PendingTree {
    fn drop(&mut self) {
        let mut count = 0;
        if !self.published
            && !matches!(
                clean_tree(&self.staging, &self.temporary, &mut count, 10_001),
                Ok(true)
            )
        {
            tracing::warn!(
                "interrupted archive tree kept in private staging for bounded startup cleanup"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn interrupted_tree_recovery_is_bounded_and_never_follows_links() {
        let root = TempDir::new().unwrap();
        let id = ShareId::new("archive").unwrap();
        let fs = ShareFs::open(id.clone(), root.path()).unwrap();
        let grant = ShareGrant {
            share_id: id,
            access: AccessLevel::ReadWrite,
        };
        let share = fs.authorize(Some(&grant), GlobalPolicy::default()).unwrap();
        let tree = share
            .begin_tree(&VirtualPath::parse("output").unwrap())
            .unwrap();
        let name = tree.temporary.clone();
        tree.directory(&VirtualPath::parse("nested").unwrap())
            .unwrap();
        tree.file(&VirtualPath::parse("nested/file").unwrap())
            .unwrap()
            .write_all(b"temporary")
            .unwrap();
        let staging = fs.staging.as_ref().unwrap();
        // Simulate a host-created link in interrupted staging: remove only
        // the link, never its target, during recovery.
        staging
            .symlink("../../outside", format!("{name}/link"))
            .unwrap();
        assert!(fs.recover_staging_files(2).is_err());
        assert_eq!(fs.recover_staging_files(20).unwrap(), 1);
        assert!(staging.symlink_metadata(&name).is_err());
        // Mark the test guard completed after recovery to avoid a second cleanup.
        let mut tree = tree;
        tree.published = true;
    }
}

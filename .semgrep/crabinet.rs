// Rule tests for crabinet-ambient-filesystem-path. Run with:
// semgrep scan --test --config .semgrep/ .semgrep/
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

fn ambient(path: &Path, request: &str) -> std::io::Result<()> {
    // ruleid: crabinet-ambient-filesystem-path
    let _ = std::fs::read(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = fs::read_to_string(request)?;
    // ruleid: crabinet-ambient-filesystem-path
    fs::write(path, b"data")?;
    // ruleid: crabinet-ambient-filesystem-path
    fs::remove_dir_all(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = fs::canonicalize(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = File::open(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = std::fs::File::create(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = File::options().read(true).open(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = OpenOptions::new().write(true).open(path)?;
    // ruleid: crabinet-ambient-filesystem-path
    std::os::unix::fs::symlink(path, request)?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = path.exists();
    // ruleid: crabinet-ambient-filesystem-path
    let _ = path.canonicalize()?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = Path::new(request).read_dir()?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
    Ok(())
}

async fn ambient_async(path: &Path) -> std::io::Result<()> {
    // ruleid: crabinet-ambient-filesystem-path
    let _ = tokio::fs::read(path).await?;
    // ruleid: crabinet-ambient-filesystem-path
    let _ = tokio::fs::File::open(path).await?;
    // ruleid: crabinet-ambient-filesystem-path
    tokio::fs::rename(path, path).await?;
    Ok(())
}

fn capability_handles(file: std::fs::File) -> std::io::Result<()> {
    // ok: crabinet-ambient-filesystem-path
    let _ = tokio::fs::File::from_std(file.try_clone()?);
    // ok: crabinet-ambient-filesystem-path
    let _ = file.metadata()?;
    // ok: crabinet-ambient-filesystem-path
    let _ = rustix::fs::inotify::Reader::new(&file, &mut []);
    Ok(())
}

fn startup_only(path: &Path) -> std::io::Result<Vec<u8>> {
    // Operator configuration is trusted at startup.
    // nosemgrep: crabinet-ambient-filesystem-path
    fs::read(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn fixtures_may_use_ambient_paths() {
        let directory = tempfile::TempDir::new().unwrap();
        // ok: crabinet-ambient-filesystem-path
        fs::write(directory.path().join("fixture.txt"), b"fixture").unwrap();
        // ok: crabinet-ambient-filesystem-path
        assert!(directory.path().join("fixture.txt").exists());
    }
}

mod helpers {
    use std::fs;

    pub fn not_a_test_module(path: &std::path::Path) {
        // ruleid: crabinet-ambient-filesystem-path
        let _ = fs::read(path);
    }
}

// ruleid: crabinet-share-handler-without-identity
async fn unauthenticated_listing(
    State(state): State<AppState>,
    Path(raw_share_id): Path<String>,
) -> Result<Response, AppError> {
    todo!()
}

// ruleid: crabinet-share-handler-without-identity
async fn unauthenticated_restore(
    Path((raw_share_id, item_id)): Path<(String, String)>,
    Json(body): Json<RestoreRequest>,
) -> Response {
    todo!()
}

// ok: crabinet-share-handler-without-identity
async fn authenticated_listing(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    Path(raw_share_id): Path<String>,
) -> Result<Response, AppError> {
    todo!()
}

// ok: crabinet-share-handler-without-identity
async fn authenticated_trash(
    Path((raw_share_id, item_id)): Path<(String, String)>,
    identity: AuthenticatedIdentity,
) -> Response {
    todo!()
}

// ruleid: crabinet-share-handler-without-identity
async fn unauthenticated_api_path_listing(
    State(state): State<AppState>,
    ApiPath(raw_share_id): ApiPath<String>,
) -> Result<Response, AppError> {
    todo!()
}

// ok: crabinet-share-handler-without-identity
async fn authenticated_api_path_restore(
    identity: AuthenticatedIdentity,
    ApiPath((raw_share_id, item_id)): ApiPath<(String, String)>,
) -> Response {
    todo!()
}

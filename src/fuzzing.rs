//! Narrow entry points for out-of-process fuzz harnesses.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    body::Body,
    http::{Request, header},
};
use tower::ServiceExt;

use crate::{
    app::{self, AppState},
    browse::{AuthenticatedIdentity, BrowseLimits, BrowseState, ConfiguredShare},
    filesystem::{AccessLevel, EntryName, GlobalPolicy, ShareFs, ShareGrant, ShareId, VirtualPath},
    mutations::{CsrfVerified, MutationLimits, MutationState},
};

static FUZZ_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub fn config_toml(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        crate::config::fuzz_config_text(text);
    }
}

pub fn phc_policy(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        crate::config::fuzz_password_hash_policy(text);
    }
}

pub fn virtual_path(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = VirtualPath::parse(text);
    }
}

pub fn markdown_classification(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(path) = VirtualPath::parse(text)
    {
        let _ = crate::preview::classify(&path);
    }
}

pub fn content_disposition(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(name) = EntryName::new(text.to_owned())
    {
        let _ = crate::browse::content_disposition(name.as_str());
    }
}

pub fn multipart(data: &[u8]) {
    let root = FuzzRoot::new();
    let share_id = ShareId::new("fuzz").expect("static share ID");
    let grant = ShareGrant {
        share_id: share_id.clone(),
        access: AccessLevel::ReadWrite,
    };
    let filesystem = ShareFs::open(share_id, &root.0).expect("synthetic share");
    let configured = ConfiguredShare::new("Fuzz", filesystem).expect("synthetic share config");
    let browse = BrowseState::new(
        vec![configured],
        BrowseLimits::default(),
        GlobalPolicy::default(),
        [0x5a; 32],
    )
    .expect("browse state");
    let limits = MutationLimits {
        max_request_bytes: 65_536,
        max_file_bytes: 65_536,
        max_files: 8,
        max_text_bytes: 65_536,
        max_concurrent_uploads: 1,
        max_share_bytes: Some(131_072),
    };
    let mutations = MutationState::new(limits).expect("mutation state");
    let app = app::router(
        AppState::new(true)
            .with_browse(browse)
            .with_mutations(mutations),
    );
    let mut request = Request::post("/api/v1/shares/fuzz/uploads")
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=index-fuzz-boundary",
        )
        .body(Body::from(data.to_vec()))
        .expect("fuzz request");
    request
        .extensions_mut()
        .insert(AuthenticatedIdentity::new("fuzzer", vec![grant]));
    request.extensions_mut().insert(CsrfVerified(()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime");
    let _ = runtime.block_on(app.oneshot(request));
}

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Self {
        let sequence = FUZZ_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("index-fuzz-{}-{sequence:016x}", std::process::id()));
        std::fs::create_dir(&path).expect("unique synthetic fuzz root");
        Self(path)
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

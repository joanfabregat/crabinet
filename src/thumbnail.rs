//! Server-side image thumbnails within a decode memory budget.
//!
//! `GET /api/v1/shares/{shareId}/thumbnail?path=…&size=…` authorizes like
//! every preview route, then serves a downscaled, re-encoded copy of a PNG,
//! JPEG, GIF, or WebP image, or of the largest JPEG preview embedded in a
//! TIFF-based RAW container. Formats are recognized from bytes only.
//!
//! Decoded pixels, not file size, determine memory, so every decode first
//! reserves its estimated peak from one process-wide budget
//! (`max_image_decode_memory`). A request that cannot get its reservation
//! within [`BUDGET_WAIT`] answers `429 busy`, and one whose estimate alone
//! exceeds the budget answers `413 thumbnail_too_large`. The reservation
//! moves into the blocking decode, so it is released when the work ends,
//! fails, or panics, never while it still runs.
//!
//! Results are cached on disk under a keyed hash of the share, path, size,
//! and source identity. The cache is consulted only after the request's
//! grant has been resolved again, so an entry is never served across shares
//! or after a grant is revoked.

mod cache;
pub(crate) mod decode;
pub(crate) mod tiff;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use cache::{CacheKey, MediaKind};
pub use cache::{ThumbnailCache, ThumbnailCacheError};
use decode::{Plan, ThumbnailError};

use crate::{
    app::AppState,
    browse::{AuthenticatedIdentity, if_none_match, run_blocking},
    error::AppError,
    extract::{ApiPath, ApiQuery},
    filesystem::{ShareId, VirtualPath},
    preview::{PreviewError, PreviewRequestError, apply_security_headers},
};

/// The long-edge sizes a client may request. Anything else is `400`.
pub const SIZES: [u32; 2] = [256, 1600];
/// The default `max_image_decode_memory`.
pub const DEFAULT_MAX_DECODE_MEMORY: u64 = 128 * 1024 * 1024;
/// The ceiling for `max_image_decode_memory`. One image at the pixel cap
/// (100 megapixels) needs at most about 1 GiB on its worst decode path
/// (progressive JPEG coefficients plus planes, or a WebP frame and canvas),
/// so 4 GiB admits several such decodes; more would only let one process
/// claim memory a small server does not have. It also keeps the budget,
/// counted in KiB permits, within a `u32`.
pub const HARD_MAX_DECODE_MEMORY: u64 = 4 * 1024 * 1024 * 1024;
/// The default `max_thumbnail_cache_size`.
pub const DEFAULT_MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;
/// The ceiling for `max_thumbnail_cache_size`.
pub const HARD_MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Budget permits are KiB, so a reservation rounds up to whole KiB.
const BUDGET_UNIT: u64 = 1024;
/// How long a request waits for its memory reservation before `429`.
const BUDGET_WAIT: Duration = Duration::from_secs(2);
/// How long a request waits for an identical in-flight thumbnail before
/// `429`. Waiting holds no memory reservation.
const IN_FLIGHT_WAIT: Duration = Duration::from_secs(15);
/// `Retry-After` for a busy thumbnail: the budget frees as decodes finish.
const BUSY_RETRY_AFTER: &str = "2";
/// Distinguishes the cache key from every other HMAC under the same key.
const KEY_DOMAIN: &[u8] = b"crabinet:thumbnail:v1\0";

#[derive(Debug, thiserror::Error)]
pub enum ThumbnailConfigError {
    #[error("max_image_decode_memory must be greater than zero and at most 4 GiB")]
    InvalidBudget,
}

/// A held share of the decode memory budget. Dropping it, on success,
/// error, or unwinding, returns the bytes to the budget.
pub(crate) struct MemoryReservation {
    _permit: OwnedSemaphorePermit,
}

type InFlight = Arc<tokio::sync::Mutex<()>>;

/// The process-wide decode budget, the optional disk cache, and the key
/// that names cache entries and validators.
pub struct ThumbnailService {
    budget: Arc<Semaphore>,
    capacity: u64,
    cache: Option<ThumbnailCache>,
    key: [u8; 32],
    in_flight: Mutex<HashMap<CacheKey, InFlight>>,
    budget_wait: Duration,
    #[cfg(test)]
    renders: std::sync::atomic::AtomicUsize,
}

impl ThumbnailService {
    /// `max_decode_memory` bytes of budget, an optional cache, and the
    /// secret key for cache names and `ETag`s.
    pub fn new(
        max_decode_memory: u64,
        cache: Option<ThumbnailCache>,
        key: [u8; 32],
    ) -> Result<Self, ThumbnailConfigError> {
        if !(BUDGET_UNIT..=HARD_MAX_DECODE_MEMORY).contains(&max_decode_memory) {
            return Err(ThumbnailConfigError::InvalidBudget);
        }
        let units = usize::try_from(max_decode_memory / BUDGET_UNIT)
            .map_err(|_| ThumbnailConfigError::InvalidBudget)?;
        Ok(Self {
            budget: Arc::new(Semaphore::new(units)),
            capacity: (max_decode_memory / BUDGET_UNIT) * BUDGET_UNIT,
            cache,
            key,
            in_flight: Mutex::new(HashMap::new()),
            budget_wait: BUDGET_WAIT,
            #[cfg(test)]
            renders: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Whether an estimate can ever be admitted.
    fn fits(&self, estimate: u64) -> bool {
        estimate <= self.capacity
    }

    /// Reserves `bytes` of the budget, waiting at most the configured time.
    async fn reserve(&self, bytes: u64) -> Result<MemoryReservation, ThumbnailError> {
        if !self.fits(bytes) {
            return Err(ThumbnailError::TooLarge);
        }
        let units = u32::try_from(bytes.div_ceil(BUDGET_UNIT).max(1))
            .map_err(|_| ThumbnailError::TooLarge)?;
        match tokio::time::timeout(
            self.budget_wait,
            Arc::clone(&self.budget).acquire_many_owned(units),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(MemoryReservation { _permit: permit }),
            _ => Err(ThumbnailError::Unavailable),
        }
    }

    /// The single-flight lock for one cache key.
    fn in_flight(&self, key: &CacheKey) -> Option<InFlight> {
        let mut map = self.in_flight.lock().ok()?;
        Some(Arc::clone(map.entry(*key).or_default()))
    }

    /// Drops the single-flight entry once no other request holds it.
    fn release_in_flight(&self, key: &CacheKey, lock: InFlight) {
        if let Ok(mut map) = self.in_flight.lock()
            && Arc::strong_count(&lock) <= 2
        {
            map.remove(key);
        }
    }

    fn cache_key(
        &self,
        share_id: &ShareId,
        path: &VirtualPath,
        size: u32,
        source: &SourceIdentity,
    ) -> CacheKey {
        cache_key(&self.key, share_id, path, size, source)
    }

    #[cfg(test)]
    pub(crate) fn with_budget_wait(mut self, wait: Duration) -> Self {
        self.budget_wait = wait;
        self
    }

    #[cfg(test)]
    pub(crate) fn render_count(&self) -> usize {
        self.renders.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn available_budget(&self) -> u64 {
        self.budget.available_permits() as u64 * BUDGET_UNIT
    }

    #[cfg(test)]
    pub(crate) fn cache(&self) -> Option<&ThumbnailCache> {
        self.cache.as_ref()
    }
}

impl Default for ThumbnailService {
    /// The default budget without a disk cache, for tests and handlers that
    /// are not wired to configuration.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DECODE_MEMORY, None, [0x5c; 32]).expect("default budget is valid")
    }
}

/// What identifies one version of a source file.
pub(crate) struct SourceIdentity {
    len: u64,
    modified: Option<SystemTime>,
    file_id: u64,
}

/// HMAC-SHA-256 over the share, path, requested size, and source identity.
/// Keyed, so entry names and validators reveal nothing about paths; any
/// change to the file's length, modification time, or inode changes it.
fn cache_key(
    key: &[u8; 32],
    share_id: &ShareId,
    path: &VirtualPath,
    size: u32,
    source: &SourceIdentity,
) -> CacheKey {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(KEY_DOMAIN);
    for value in [share_id.as_str().as_bytes(), path.to_string().as_bytes()] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    mac.update(&size.to_be_bytes());
    mac.update(&source.len.to_be_bytes());
    mac.update(&source.file_id.to_be_bytes());
    match source
        .modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
    {
        Some(duration) => {
            mac.update(&[1]);
            mac.update(&duration.as_secs().to_be_bytes());
            mac.update(&duration.subsec_nanos().to_be_bytes());
        }
        None => mac.update(&[0]),
    }
    mac.finalize().into_bytes().into()
}

fn etag(key: &CacheKey) -> String {
    let mut value = String::with_capacity(36);
    value.push_str("\"t");
    for byte in &key[..16] {
        value.push_str(&format!("{byte:02x}"));
    }
    value.push('"');
    value
}

#[derive(Debug, Deserialize)]
struct ThumbnailQuery {
    path: Option<String>,
    size: Option<String>,
}

/// Authenticated thumbnail route, mounted below `/api/v1`.
pub fn router() -> Router<AppState> {
    Router::new().route("/shares/{share_id}/thumbnail", get(thumbnail))
}

/// Unsupported and undecodable images are `415`, so the UI can fall back to
/// the original; anything over a size bound is `413 thumbnail_too_large`.
const fn preview_error(error: ThumbnailError) -> PreviewError {
    match error {
        ThumbnailError::Unsupported | ThumbnailError::Corrupt => PreviewError::UnsupportedEntry,
        ThumbnailError::TooLarge => PreviewError::ThumbnailTooLarge,
        ThumbnailError::Unavailable => PreviewError::Unavailable,
    }
}

impl From<ThumbnailError> for PreviewRequestError {
    fn from(error: ThumbnailError) -> Self {
        Self::Preview(preview_error(error))
    }
}

/// A `429 busy` whose `Retry-After` matches the short budget wait.
fn busy() -> PreviewRequestError {
    PreviewRequestError::Response(Box::new({
        let mut response = AppError::Busy.into_response();
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(BUSY_RETRY_AFTER),
        );
        apply_security_headers(response.headers_mut());
        response
    }))
}

/// What the blocking preparation found.
enum Prepared {
    NotModified,
    Hit(Vec<u8>, MediaKind),
    Miss {
        file: std::fs::File,
        plan: Plan,
        cacheable: bool,
    },
}

async fn thumbnail(
    State(state): State<AppState>,
    identity: AuthenticatedIdentity,
    ApiPath(raw_share_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<ThumbnailQuery>,
    headers: HeaderMap,
) -> Result<Response, PreviewRequestError> {
    let share_id = ShareId::new(raw_share_id).map_err(|_| AppError::NotFound)?;
    let raw_path = query.path.as_deref().ok_or(PreviewError::InvalidPath)?;
    let path = VirtualPath::parse(raw_path).map_err(|error| PreviewError::from(error.code()))?;
    let size = query
        .size
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| SIZES.contains(value))
        .ok_or(PreviewError::InvalidThumbnailSize)?;
    // Authorization comes first: nothing below, the cache included, is
    // reached without a fresh grant resolution for this request.
    let authorized = state.browse().authorize_owned(&identity, &share_id)?;
    let lease = state.browse().acquire_buffered_read(&identity)?;
    let service = Arc::clone(state.thumbnails());

    let prepare_service = Arc::clone(&service);
    let prepare_path = path.clone();
    let prepare_share = share_id.clone();
    let condition = headers.get(header::IF_NONE_MATCH).cloned();
    let (prepared, lease) = run_blocking(move || {
        let result = (|| -> Result<(Prepared, CacheKey), PreviewError> {
            // Missing and unauthorized entries keep the non-disclosing 404.
            let opened = authorized
                .view()
                .open_file(&prepare_path)
                .map_err(|error| PreviewError::from(error.code()))?;
            let source = SourceIdentity {
                len: opened.len(),
                modified: opened.modified(),
                file_id: opened.file_id(),
            };
            let key = prepare_service.cache_key(&prepare_share, &prepare_path, size, &source);
            if if_none_match(condition.as_ref(), &etag(&key)) {
                return Ok((Prepared::NotModified, key));
            }
            if source.len > decode::MAX_SOURCE_BYTES {
                return Err(preview_error(ThumbnailError::TooLarge));
            }
            let cacheable = source.modified.is_some();
            if cacheable
                && let Some((bytes, kind)) = prepare_service
                    .cache
                    .as_ref()
                    .and_then(|cache| cache.get(&key))
            {
                return Ok((Prepared::Hit(bytes, kind), key));
            }
            let mut file = opened.into_std();
            let plan = decode::plan(&mut file, source.len, size).map_err(preview_error)?;
            Ok((
                Prepared::Miss {
                    file,
                    plan,
                    cacheable,
                },
                key,
            ))
        })();
        (result, lease)
    })
    .await?;
    let (prepared, key) = prepared?;
    let etag = etag(&key);

    let (bytes, kind) = match prepared {
        Prepared::NotModified => return Ok(not_modified(&etag)),
        Prepared::Hit(bytes, kind) => (bytes, kind),
        Prepared::Miss {
            file,
            plan,
            cacheable,
        } => {
            if !service.fits(plan.estimate) {
                return Err(ThumbnailError::TooLarge.into());
            }
            render_miss(&service, key, file, plan, cacheable, lease).await?
        }
    };
    Ok(thumbnail_response(bytes, kind, &etag))
}

/// Decodes a cache miss under a memory reservation, once per key at a time.
async fn render_miss(
    service: &Arc<ThumbnailService>,
    key: CacheKey,
    file: std::fs::File,
    plan: Plan,
    cacheable: bool,
    lease: crate::browse::SubjectLease,
) -> Result<(Vec<u8>, MediaKind), PreviewRequestError> {
    let use_cache = cacheable && service.cache.is_some();
    // Identical concurrent requests wait for the first one, then read its
    // cache entry, instead of decoding the same image twice.
    let flight = if use_cache {
        service.in_flight(&key)
    } else {
        None
    };
    let guard = match &flight {
        Some(lock) => Some(
            tokio::time::timeout(IN_FLIGHT_WAIT, Arc::clone(lock).lock_owned())
                .await
                .map_err(|_| busy())?,
        ),
        None => None,
    };
    let result = render_locked(service, key, file, plan, use_cache, lease).await;
    drop(guard);
    if let Some(lock) = flight {
        service.release_in_flight(&key, lock);
    }
    result
}

async fn render_locked(
    service: &Arc<ThumbnailService>,
    key: CacheKey,
    file: std::fs::File,
    plan: Plan,
    use_cache: bool,
    lease: crate::browse::SubjectLease,
) -> Result<(Vec<u8>, MediaKind), PreviewRequestError> {
    if use_cache {
        let lookup = Arc::clone(service);
        if let Some(hit) =
            run_blocking(move || lookup.cache.as_ref().and_then(|cache| cache.get(&key))).await?
        {
            return Ok(hit);
        }
    }
    let reservation = match service.reserve(plan.estimate).await {
        Ok(reservation) => reservation,
        Err(ThumbnailError::Unavailable) => return Err(busy()),
        Err(error) => return Err(error.into()),
    };
    let worker = Arc::clone(service);
    // The reservation and the request's slot travel with the blocking work,
    // so a cancelled request cannot release them while the decode runs.
    let (rendered, _reservation, _lease) = run_blocking(move || {
        #[cfg(test)]
        worker
            .renders
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let rendered = decode::render(file, &plan).and_then(|encoded| {
            let kind =
                MediaKind::from_media_type(encoded.media_type).ok_or(ThumbnailError::Corrupt)?;
            if use_cache && let Some(cache) = worker.cache.as_ref() {
                cache.put(&key, kind, &encoded.bytes);
            }
            Ok((encoded.bytes, kind))
        });
        (rendered, reservation, lease)
    })
    .await?;
    Ok(rendered?)
}

fn thumbnail_response(bytes: Vec<u8>, kind: MediaKind, etag: &str) -> Response {
    let length = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(kind.media_type()),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    apply_security_headers(headers);
    response
}

fn not_modified(etag: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    apply_security_headers(headers);
    response
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "unit tests build synthetic fixtures in temporary directories"
)]
pub(crate) mod tests {
    use std::fs;

    use axum::{body::to_bytes, http::Request};
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        browse::{BrowseLimits, BrowseState, ConfiguredShare},
        filesystem::{AccessLevel, GlobalPolicy, ShareFs, ShareGrant},
        thumbnail::tiff::tests::TiffBuilder,
    };

    /// A PNG of `width × height` pixels, translucent when `alpha` is set.
    pub(crate) fn png_fixture(width: u32, height: u32, alpha: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("PNG header");
        let mut pixels = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let opacity = if alpha && x == 0 { 0 } else { 255 };
                pixels.extend_from_slice(&[(x * 40) as u8, (y * 40) as u8, 120, opacity]);
            }
        }
        writer.write_image_data(&pixels).expect("PNG data");
        writer.finish().expect("PNG end");
        bytes
    }

    /// A baseline JPEG whose left half is red and right half blue, with an
    /// EXIF orientation tag when one is given.
    pub(crate) fn jpeg_fixture(width: u32, height: u32, orientation: Option<u8>) -> Vec<u8> {
        let mut rgba = Vec::new();
        for _ in 0..height {
            for x in 0..width {
                let pixel = if x < width / 2 {
                    [230, 20, 20, 255]
                } else {
                    [20, 20, 230, 255]
                };
                rgba.extend_from_slice(&pixel);
            }
        }
        let jpeg = decode::encode_jpeg(&rgba, width, height).expect("JPEG fixture");
        let Some(orientation) = orientation else {
            return jpeg;
        };
        let mut exif = b"Exif\0\0MM\0*\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0".to_vec();
        exif.extend_from_slice(&[orientation, 0, 0, 0, 0, 0, 0]);
        let mut with_exif = jpeg[..2].to_vec();
        with_exif.extend_from_slice(&[0xff, 0xe1]);
        with_exif.extend_from_slice(&u16::try_from(exif.len() + 2).unwrap().to_be_bytes());
        with_exif.extend_from_slice(&exif);
        with_exif.extend_from_slice(&jpeg[2..]);
        with_exif
    }

    /// A little-endian DNG-like TIFF whose SubIFD holds `preview` and whose
    /// IFD0 carries `orientation` and a small thumbnail preview.
    pub(crate) fn raw_fixture(preview: &[u8], orientation: u32) -> Vec<u8> {
        let small = jpeg_fixture(8, 8, None);
        let mut tiff = TiffBuilder::new();
        let small_at = tiff.blob(&small);
        let large_at = tiff.blob(preview);
        let sub = tiff.ifd(
            &[
                (0x00fe, 4, 1, 1),
                (0x0103, 3, 1, 7),
                (0x0106, 3, 1, 6),
                (0x0111, 4, 1, large_at),
                (0x0117, 4, 1, u32::try_from(preview.len()).unwrap()),
            ],
            0,
        );
        let ifd0 = tiff.ifd(
            &[
                (0x0112, 3, 1, orientation),
                (0x014a, 4, 1, sub),
                (0x0201, 4, 1, small_at),
                (0x0202, 4, 1, u32::try_from(small.len()).unwrap()),
            ],
            0,
        );
        tiff.set_first_ifd(ifd0);
        tiff.bytes
    }

    struct Fixture {
        _roots: Vec<TempDir>,
        _cache: TempDir,
        app: axum::Router,
        state: AppState,
        identity: AuthenticatedIdentity,
        root: std::path::PathBuf,
    }

    fn grant(share: &str) -> ShareGrant {
        ShareGrant {
            share_id: ShareId::new(share).unwrap(),
            access: AccessLevel::ReadOnly,
        }
    }

    fn fixture_with(budget: u64, cache_bytes: Option<u64>, wait: Duration) -> Fixture {
        let mut roots = Vec::new();
        let mut shares = Vec::new();
        for id in ["documents", "other"] {
            let root = TempDir::new().unwrap();
            fs::write(root.path().join("photo.png"), png_fixture(40, 30, false)).unwrap();
            shares.push(
                ConfiguredShare::new(
                    id,
                    ShareFs::open(ShareId::new(id).unwrap(), root.path()).unwrap(),
                )
                .unwrap(),
            );
            roots.push(root);
        }
        let root = roots[0].path().to_path_buf();
        let cache_dir = TempDir::new().unwrap();
        let cache = cache_bytes.map(|bytes| {
            ThumbnailCache::open(&cache_dir.path().join("thumbnails"), bytes).unwrap()
        });
        let browse = BrowseState::new(
            shares,
            BrowseLimits::default(),
            GlobalPolicy::default(),
            [7; 32],
        )
        .unwrap();
        let service = ThumbnailService::new(budget, cache, [9; 32])
            .unwrap()
            .with_budget_wait(wait);
        let state = AppState::new(true)
            .with_browse(browse)
            .with_thumbnails(service);
        Fixture {
            _roots: roots,
            _cache: cache_dir,
            app: crate::app::router(state.clone()),
            state,
            identity: AuthenticatedIdentity::new(
                "user-1",
                vec![grant("documents"), grant("other")],
            ),
            root,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(
            DEFAULT_MAX_DECODE_MEMORY,
            Some(DEFAULT_MAX_CACHE_BYTES),
            Duration::from_millis(50),
        )
    }

    impl Fixture {
        fn write(&self, name: &str, bytes: &[u8]) {
            fs::write(self.root.join(name), bytes).unwrap();
        }

        fn service(&self) -> &ThumbnailService {
            self.state.thumbnails()
        }

        async fn get_as(
            &self,
            identity: Option<&AuthenticatedIdentity>,
            uri: &str,
            if_none_match: Option<&str>,
        ) -> Response {
            let mut request = Request::get(uri);
            if let Some(value) = if_none_match {
                request = request.header(header::IF_NONE_MATCH, value);
            }
            let mut request = request.body(Body::empty()).unwrap();
            if let Some(identity) = identity {
                request.extensions_mut().insert(identity.clone());
            }
            self.app.clone().oneshot(request).await.unwrap()
        }

        async fn get(&self, uri: &str) -> Response {
            self.get_as(Some(&self.identity), uri, None).await
        }
    }

    async fn json(response: Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap()
    }

    async fn body(response: Response) -> Vec<u8> {
        to_bytes(response.into_body(), 64 << 20)
            .await
            .unwrap()
            .to_vec()
    }

    fn jpeg_size(bytes: &[u8]) -> (u32, u32) {
        let header =
            decode::jpeg_header(&mut std::io::Cursor::new(bytes), 0, bytes.len() as u64).unwrap();
        (header.width, header.height)
    }

    fn decode_jpeg(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
        let mut decoder = jpeg_decoder::Decoder::new(std::io::Cursor::new(bytes));
        let pixels = decoder.decode().unwrap();
        let info = decoder.info().unwrap();
        (u32::from(info.width), u32::from(info.height), pixels)
    }

    #[tokio::test]
    async fn serves_a_downscaled_jpeg_with_preview_headers_and_a_validator() {
        let fixture = fixture();
        fixture.write("wide.jpg", &jpeg_fixture(3200, 800, None));
        let response = fixture
            .get("/api/v1/shares/documents/thumbnail?path=wide.jpg&size=1600")
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(headers[header::CONTENT_TYPE], "image/jpeg");
        assert_eq!(headers[header::CONTENT_DISPOSITION], "inline");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store, private");
        assert!(
            headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .starts_with("sandbox; default-src 'none'")
        );
        let etag = headers[header::ETAG].to_str().unwrap().to_owned();
        let bytes = body(response).await;
        assert_eq!(jpeg_size(&bytes), (1600, 400));
        assert!(
            !bytes.windows(4).any(|window| window == b"Exif"),
            "no metadata"
        );

        let small = fixture
            .get("/api/v1/shares/documents/thumbnail?path=wide.jpg&size=256")
            .await;
        assert_eq!(jpeg_size(&body(small).await), (256, 64));

        // Never upscaled.
        let tiny = fixture
            .get("/api/v1/shares/documents/thumbnail?path=photo.png&size=1600")
            .await;
        assert_eq!(jpeg_size(&body(tiny).await), (40, 30));

        let not_modified = fixture
            .get_as(
                Some(&fixture.identity),
                "/api/v1/shares/documents/thumbnail?path=wide.jpg&size=1600",
                Some(&etag),
            )
            .await;
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers()[header::ETAG], etag.as_str());
        assert_eq!(
            not_modified.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
    }

    #[tokio::test]
    async fn applies_exif_orientation_and_strips_metadata() {
        let fixture = fixture();
        // Left half red; orientation 6 rotates it clockwise onto the top.
        fixture.write("rotated.jpg", &jpeg_fixture(64, 32, Some(6)));
        let response = fixture
            .get("/api/v1/shares/documents/thumbnail?path=rotated.jpg&size=256")
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (width, height, pixels) = decode_jpeg(&body(response).await);
        assert_eq!((width, height), (32, 64));
        let top = &pixels[(4 * 32 + 16) * 3..(4 * 32 + 16) * 3 + 3];
        let bottom = &pixels[(60 * 32 + 16) * 3..(60 * 32 + 16) * 3 + 3];
        assert!(top[0] > 150 && top[2] < 100, "top is red: {top:?}");
        assert!(
            bottom[2] > 150 && bottom[0] < 100,
            "bottom is blue: {bottom:?}"
        );
    }

    #[tokio::test]
    async fn translucent_images_become_lossless_png() {
        let fixture = fixture();
        fixture.write("alpha.png", &png_fixture(20, 10, true));
        let response = fixture
            .get("/api/v1/shares/documents/thumbnail?path=alpha.png&size=256")
            .await;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
        let bytes = body(response).await;
        let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
        let mut reader = decoder.read_info().unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        reader.next_frame(&mut pixels).unwrap();
        assert_eq!((reader.info().width, reader.info().height), (20, 10));
        assert_eq!(pixels[3], 0, "the transparent column stays transparent");
        assert_eq!(pixels[4 * 5 + 3], 255);
        // Text chunks or other metadata are never written.
        let info = reader.info();
        assert!(info.uncompressed_latin1_text.is_empty() && info.exif_metadata.is_none());
    }

    #[tokio::test]
    async fn raw_files_use_their_largest_embedded_preview() {
        let fixture = fixture();
        fixture.write("camera.dng", &raw_fixture(&jpeg_fixture(400, 300, None), 8));
        let response = fixture
            .get("/api/v1/shares/documents/thumbnail?path=camera.dng&size=256")
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/jpeg");
        // The 400×300 preview, not the 8×8 one, rotated by orientation 8.
        assert_eq!(jpeg_size(&body(response).await), (192, 256));

        let preview = json(
            fixture
                .get("/api/v1/shares/documents/preview?path=camera.dng")
                .await,
        )
        .await;
        assert_eq!(preview["kind"], "raw");
        assert_eq!(preview["thumbnailable"], true);
        assert_eq!(preview["openable"], false);
        assert!(preview.get("mimeType").is_none());
        // RAW is never served inline.
        let open = fixture
            .get("/api/v1/shares/documents/open?path=camera.dng")
            .await;
        assert_eq!(open.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // A TIFF without a usable JPEG preview is not thumbnailed.
        let mut plain = TiffBuilder::new();
        let ifd = plain.ifd(&[(0x0100, 3, 1, 10)], 0);
        plain.set_first_ifd(ifd);
        fixture.write("scan.tif", &plain.bytes);
        let refused = fixture
            .get("/api/v1/shares/documents/thumbnail?path=scan.tif&size=256")
            .await;
        assert_eq!(refused.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(json(refused).await["code"], "unsupported_entry");
    }

    #[tokio::test]
    async fn preview_documents_report_thumbnailable_images_only() {
        let fixture = fixture();
        fixture.write("notes.txt", b"plain text");
        let mut avif = 24_u32.to_be_bytes().to_vec();
        avif.extend_from_slice(b"ftypavif\0\0\0\0avifmif1");
        fixture.write("picture.avif", &avif);
        let mut heic = 24_u32.to_be_bytes().to_vec();
        heic.extend_from_slice(b"ftypheic\0\0\0\0mif1heic");
        fixture.write("picture.heic", &heic);
        for (name, expected) in [
            ("photo.png", true),
            ("notes.txt", false),
            ("picture.avif", false),
            ("picture.heic", false),
        ] {
            let document = json(
                fixture
                    .get(&format!("/api/v1/shares/documents/preview?path={name}"))
                    .await,
            )
            .await;
            assert_eq!(document["thumbnailable"], expected, "{name}");
        }
        let avif = fixture
            .get("/api/v1/shares/documents/thumbnail?path=picture.avif&size=256")
            .await;
        assert_eq!(avif.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        // HEIC gets the same answer, so the panel shows the original.
        let heic = fixture
            .get("/api/v1/shares/documents/thumbnail?path=picture.heic&size=256")
            .await;
        assert_eq!(heic.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(json(heic).await["code"], "unsupported_entry");
    }

    #[tokio::test]
    async fn sizes_come_from_a_fixed_allowlist() {
        let fixture = fixture();
        for query in ["size=512", "size=0", "size=abc", "size=", "size=1600.0", ""] {
            let response = fixture
                .get(&format!(
                    "/api/v1/shares/documents/thumbnail?path=photo.png&{query}"
                ))
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
            assert_eq!(
                json(response).await["code"],
                "invalid_thumbnail_size",
                "{query}"
            );
        }
    }

    #[tokio::test]
    async fn unauthorized_and_missing_requests_are_non_disclosing() {
        let fixture = fixture();
        let uri = "/api/v1/shares/documents/thumbnail?path=photo.png&size=256";
        assert_eq!(
            fixture.get_as(None, uri, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let stranger = AuthenticatedIdentity::new("user-2", vec![]);
        let ungranted = fixture.get_as(Some(&stranger), uri, None).await;
        let missing_share = fixture
            .get("/api/v1/shares/missing/thumbnail?path=photo.png&size=256")
            .await;
        assert_eq!(ungranted.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing_share.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(ungranted).await, json(missing_share).await);
        let missing_file = fixture
            .get("/api/v1/shares/documents/thumbnail?path=absent.png&size=256")
            .await;
        assert_eq!(missing_file.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(missing_file).await["code"], "not_found");
        let traversal = fixture
            .get("/api/v1/shares/documents/thumbnail?path=..%2Fsecret&size=256")
            .await;
        assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_cache_serves_hits_misses_on_change_and_never_crosses_grants() {
        let fixture = fixture();
        let uri = "/api/v1/shares/documents/thumbnail?path=photo.png&size=256";
        let first = body(fixture.get(uri).await).await;
        assert_eq!(fixture.service().render_count(), 1);
        let second = body(fixture.get(uri).await).await;
        assert_eq!(first, second);
        assert_eq!(fixture.service().render_count(), 1, "served from the cache");
        assert_eq!(fixture.service().cache().unwrap().totals().0, 1);

        // The same path and bytes in another share is another entry.
        body(
            fixture
                .get("/api/v1/shares/other/thumbnail?path=photo.png&size=256")
                .await,
        )
        .await;
        assert_eq!(fixture.service().render_count(), 2);

        // A cached thumbnail still requires the grant: without it, 404.
        let revoked = AuthenticatedIdentity::new("user-1", vec![grant("other")]);
        let refused = fixture.get_as(Some(&revoked), uri, None).await;
        assert_eq!(refused.status(), StatusCode::NOT_FOUND);

        // Replacing the source changes the key.
        fixture.write("photo.png", &png_fixture(41, 30, false));
        let changed = fixture.get(uri).await;
        assert_eq!(jpeg_size(&body(changed).await), (41, 30));
        assert_eq!(fixture.service().render_count(), 3);
    }

    #[tokio::test]
    async fn identical_concurrent_requests_decode_once() {
        let fixture = fixture();
        fixture.write("big.jpg", &jpeg_fixture(2000, 1500, None));
        let uri = "/api/v1/shares/documents/thumbnail?path=big.jpg&size=256";
        let (first, second) = tokio::join!(fixture.get(uri), fixture.get(uri));
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(fixture.service().render_count(), 1);
    }

    #[tokio::test]
    async fn an_estimate_above_the_whole_budget_is_413() {
        let fixture = fixture_with(1024 * 1024, None, Duration::from_millis(50));
        let response = fixture
            .get("/api/v1/shares/documents/thumbnail?path=photo.png&size=256")
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json(response).await["code"], "thumbnail_too_large");
        assert_eq!(fixture.service().render_count(), 0);

        // So is a source above the byte cap, before any decoding.
        let fixture = self::fixture();
        let file = fs::File::create(fixture.root.join("huge.png")).unwrap();
        file.set_len(decode::MAX_SOURCE_BYTES + 1).unwrap();
        let response = fixture
            .get("/api/v1/shares/documents/thumbnail?path=huge.png&size=256")
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json(response).await["code"], "thumbnail_too_large");
    }

    #[tokio::test]
    async fn a_full_budget_answers_busy_and_recovers() {
        let budget = 16 * 1024 * 1024;
        let fixture = fixture_with(budget, None, Duration::from_millis(50));
        let held = fixture.service().reserve(budget).await.ok().unwrap();
        assert_eq!(fixture.service().available_budget(), 0);
        let uri = "/api/v1/shares/documents/thumbnail?path=photo.png&size=256";
        let busy = fixture.get(uri).await;
        assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(busy.headers()[header::RETRY_AFTER], BUSY_RETRY_AFTER);
        assert_eq!(json(busy).await["error"]["code"], "busy");
        drop(held);
        assert_eq!(fixture.get(uri).await.status(), StatusCode::OK);
        assert_eq!(fixture.service().available_budget(), budget);
    }

    #[tokio::test]
    async fn reservations_are_released_on_success_error_and_panic() {
        let service = Arc::new(ThumbnailService::default());
        let full = service.available_budget();
        let reservation = service.reserve(10 * 1024 * 1024).await.ok().unwrap();
        assert_eq!(service.available_budget(), full - 10 * 1024 * 1024);
        drop(reservation);
        assert_eq!(service.available_budget(), full);

        // A failed decode releases its reservation.
        let fixture = fixture();
        fixture.write("broken.png", &png_fixture(30, 30, false)[..60]);
        let failed = fixture
            .get("/api/v1/shares/documents/thumbnail?path=broken.png&size=256")
            .await;
        assert_eq!(failed.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            fixture.service().available_budget(),
            DEFAULT_MAX_DECODE_MEMORY
        );

        // A panicking decode releases it while unwinding.
        let reservation = service.reserve(1024 * 1024).await.ok().unwrap();
        let joined = tokio::task::spawn_blocking(move || {
            let _held = reservation;
            panic!("decoder panic");
        })
        .await;
        assert!(joined.is_err());
        assert_eq!(service.available_budget(), full);

        // An estimate above the whole budget is refused without waiting.
        assert!(matches!(
            service.reserve(DEFAULT_MAX_DECODE_MEMORY + 1).await,
            Err(ThumbnailError::TooLarge)
        ));
    }

    #[test]
    fn the_budget_must_be_positive_and_bounded() {
        assert!(ThumbnailService::new(0, None, [1; 32]).is_err());
        assert!(ThumbnailService::new(HARD_MAX_DECODE_MEMORY + 1, None, [1; 32]).is_err());
        assert!(ThumbnailService::new(HARD_MAX_DECODE_MEMORY, None, [1; 32]).is_ok());
    }
}

//! Bounded, synchronous archive workers. No library unpack helper may write paths.
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Deserialize;

use crate::filesystem::{
    ArchiveLimits, AuthorizedShare, DIRECTORY_QUOTA_BYTES, EntryKind, FsError, MAX_PATH_DEPTH,
    PendingTree, PendingWrite, VirtualPath,
};

const CHUNK: usize = 64 * 1024;
const MAX_ZIP_DIRECTORY: u64 = 8 * 1024 * 1024;
const MAX_TAR_EXTENSION: u64 = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Format {
    Zip,
    Tar,
    TarGz,
    Gz,
    TarZst,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArchiveError {
    #[error("invalid, damaged, encrypted, or unsupported archive")]
    Invalid,
    #[error("archive exceeds a resource limit")]
    Limit,
    #[error("archive destination exceeds the folder depth limit")]
    Depth,
    #[error("archive operation cancelled or timed out")]
    Cancelled,
    #[error("filesystem operation failed")]
    Fs(#[from] FsError),
    #[error("archive I/O failed")]
    Io(io::Error),
}
impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::FileTooLarge => Self::Limit,
            io::ErrorKind::TimedOut => Self::Cancelled,
            _ => Self::Io(error),
        }
    }
}
type Result<T> = std::result::Result<T, ArchiveError>;

// During ZIP metadata discovery hide the file bodies. The ZIP reader retries
// older end records after malformed metadata; it must never discover a forged
// ZIP64 end record (and allocate its claimed extension) in a file's contents.
struct ZipInput {
    file: File,
    directory_start: u64,
    metadata_only: Arc<AtomicBool>,
}
impl Read for ZipInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.metadata_only.load(Ordering::Relaxed) {
            let position = self.file.stream_position()?;
            if position < self.directory_start {
                let n = bytes.len().min((self.directory_start - position) as usize);
                bytes[..n].fill(0);
                self.file.seek(SeekFrom::Current(n as i64))?;
                return Ok(n);
            }
        }
        self.file.read(bytes)
    }
}
impl Seek for ZipInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

/// Dropped by the request future, including on disconnect. A blocking worker
/// retains its admission lease until it observes cancellation and cleans up.
pub(crate) struct Cancellation(pub(crate) Arc<AtomicBool>);
impl Drop for Cancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub(crate) struct Work {
    cancelled: Arc<AtomicBool>,
    until: Instant,
}
impl Work {
    pub(crate) fn new() -> (Self, Cancellation) {
        let cancelled = Arc::new(AtomicBool::new(false));
        (
            Self {
                cancelled: cancelled.clone(),
                until: Instant::now() + DEADLINE,
            },
            Cancellation(cancelled),
        )
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) || Instant::now() >= self.until {
            return Err(ArchiveError::Cancelled);
        }
        Ok(())
    }
}

/// Bound bytes consumed/produced *inside* parsers, not just files they emit.
/// This also bounds streams of padding, empty frames, and metadata records.
struct Bounded<T> {
    inner: T,
    remaining: u64,
    work: Work,
}
impl<T> Bounded<T> {
    fn new(inner: T, remaining: u64, work: &Work) -> Self {
        Self {
            inner,
            remaining,
            work: work.clone(),
        }
    }
    fn check(&self) -> io::Result<()> {
        self.work
            .check()
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "archive cancelled or timed out"))
    }
}
impl<T: Read> Read for Bounded<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let size = bytes
            .len()
            .min(CHUNK)
            .min(self.remaining.saturating_add(1) as usize);
        let n = self.inner.read(&mut bytes[..size])?;
        if n as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "archive byte limit",
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}
impl<T: Write> Write for Bounded<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "archive byte limit",
            ));
        }
        let n = self.inner.write(&bytes[..bytes.len().min(CHUNK)])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}
impl<T: Seek> Seek for Bounded<T> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check()?;
        self.inner.seek(position)
    }
}

fn copy(input: &mut impl Read, output: &mut impl Write, max: u64, work: &Work) -> Result<u64> {
    let mut bytes = [0; CHUNK];
    let mut total = 0_u64;
    loop {
        work.check()?;
        let n = input.read(&mut bytes)?;
        if n == 0 {
            return Ok(total);
        }
        total = total.checked_add(n as u64).ok_or(ArchiveError::Limit)?;
        if total > max {
            return Err(ArchiveError::Limit);
        }
        output.write_all(&bytes[..n])?;
    }
}

pub(crate) enum Staged {
    File(PendingWrite),
    Tree(PendingTree),
}
impl Staged {
    pub(crate) fn publish(self) -> Result<()> {
        match self {
            Self::File(file) => file.publish_new()?,
            Self::Tree(tree) => tree.publish()?,
        }
        Ok(())
    }
}

/// Source selections use the existing no-follow download walk and its budgets.
pub(crate) fn compress(
    share: &AuthorizedShare<'_>,
    sources: &[VirtualPath],
    destination: &VirtualPath,
    limits: ArchiveLimits,
    max_charge: u64,
    work: &Work,
) -> Result<Staged> {
    let (parent, _) = sources
        .first()
        .and_then(VirtualPath::split_parent)
        .ok_or(ArchiveError::Invalid)?;
    let mut names = Vec::new();
    for source in sources {
        work.check()?;
        let (p, name) = source.split_parent().ok_or(ArchiveError::Invalid)?;
        if p != parent || source == destination {
            return Err(ArchiveError::Invalid);
        }
        names.push(name.clone());
    }
    let items = share.archive_selection_checked(&parent, &names, limits, &|| work.check().is_ok());
    work.check()?;
    let items = items?;
    // The walk happens before the output exists. Publication is outside all
    // sources, so creating an archive never includes itself.
    if sources.iter().any(|source| destination.starts_with(source)) {
        return Err(ArchiveError::Invalid);
    }
    let pending = share.begin_write(destination)?;
    let mut output = Bounded::new(pending.writer()?, limits.max_bytes.min(max_charge), work);
    let open = |relative: &str, size: u64| -> Result<File> {
        let path = VirtualPath::parse(&format!(
            "{}{relative}",
            if parent.is_root() {
                String::new()
            } else {
                format!("{parent}/")
            }
        ))?;
        let file = share.open_file(&path)?;
        if file.len() != size {
            return Err(ArchiveError::Invalid);
        }
        Ok(file.into_std())
    };
    let mut zip = zip::ZipWriter::new(&mut output);
    for item in &items {
        work.check()?;
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(2))
            .large_file(item.size >= u32::MAX as u64)
            .unix_permissions(if item.kind == EntryKind::Directory {
                0o755
            } else {
                0o644
            });
        if item.kind == EntryKind::Directory {
            zip.add_directory(format!("{}/", item.relative), options)
                .map_err(|_| ArchiveError::Invalid)?;
        } else {
            zip.start_file(&item.relative, options)
                .map_err(|_| ArchiveError::Invalid)?;
            let mut file = open(&item.relative, item.size)?;
            if copy(&mut file, &mut zip, item.size, work)? != item.size {
                return Err(ArchiveError::Invalid);
            }
        }
    }
    zip.finish().map_err(|_| ArchiveError::Invalid)?;
    output.flush()?;
    work.check()?;
    Ok(Staged::File(pending))
}

struct Extraction<'a> {
    tree: PendingTree,
    destination: &'a VirtualPath,
    limits: ArchiveLimits,
    work: &'a Work,
    // Includes implicit parent directories; bool records explicit entries.
    entries: HashMap<String, (EntryKind, bool)>,
    names: usize,
    bytes: u64,
    charge: u64,
    max_charge: u64,
}
impl Extraction<'_> {
    fn path(&self, raw: &[u8], directory: bool) -> Result<Option<VirtualPath>> {
        let mut name = std::str::from_utf8(raw).map_err(|_| ArchiveError::Invalid)?;
        while let Some(rest) = name.strip_prefix("./") {
            name = rest;
        }
        if directory && (name == "." || name.is_empty()) {
            return Ok(None);
        }
        if directory {
            name = name.strip_suffix('/').unwrap_or(name);
        }
        let path = VirtualPath::parse(name)?;
        for component in path.components() {
            component.ensure_creatable()?;
        }
        if self.destination.depth() + path.depth() > MAX_PATH_DEPTH {
            return Err(ArchiveError::Depth);
        }
        // Validate the *combined* path's length as well as its depth.
        VirtualPath::parse(&format!("{}/{path}", self.destination))?;
        Ok(Some(path))
    }
    fn add(&mut self, path: &VirtualPath, kind: EntryKind, explicit: bool) -> Result<bool> {
        self.work.check()?;
        let name = path.to_string();
        if let Some((previous, was_explicit)) = self.entries.get_mut(&name) {
            if kind != EntryKind::Directory || *previous != kind || (explicit && *was_explicit) {
                return Err(ArchiveError::Invalid);
            }
            *was_explicit |= explicit;
            return Ok(false);
        }
        self.names += name.len();
        if self.entries.len() >= self.limits.max_entries || self.names > self.limits.max_name_bytes
        {
            return Err(ArchiveError::Limit);
        }
        if kind == EntryKind::Directory {
            self.charge = self
                .charge
                .checked_add(DIRECTORY_QUOTA_BYTES)
                .ok_or(ArchiveError::Limit)?;
            if self.charge > self.max_charge {
                return Err(ArchiveError::Limit);
            }
            self.tree.directory(path)?;
        }
        self.entries.insert(name, (kind, explicit));
        Ok(true)
    }
    fn entry(
        &mut self,
        raw: &[u8],
        kind: EntryKind,
        size: u64,
        reader: &mut impl Read,
    ) -> Result<()> {
        if kind == EntryKind::Directory && size != 0 {
            return Err(ArchiveError::Invalid);
        }
        let Some(path) = self.path(raw, kind == EntryKind::Directory)? else {
            return Ok(());
        };
        if size > self.limits.max_bytes.saturating_sub(self.bytes)
            || size > self.max_charge.saturating_sub(self.charge)
        {
            return Err(ArchiveError::Limit);
        }
        let mut parent = VirtualPath::root();
        let components: Vec<_> = path.components().cloned().collect();
        for name in &components[..components.len() - 1] {
            parent = parent.join(name.clone());
            self.add(&parent, EntryKind::Directory, false)?;
        }
        self.add(&path, kind, true)?;
        if kind == EntryKind::File {
            let mut file = self.tree.file(&path)?;
            let max = self
                .limits
                .max_bytes
                .saturating_sub(self.bytes)
                .min(self.max_charge.saturating_sub(self.charge));
            let count = copy(reader, &mut file, max, self.work)?;
            if count != size {
                return Err(ArchiveError::Invalid);
            }
            file.sync_all()?;
            self.bytes += count;
            self.charge += count;
        } else if size != 0 {
            return Err(ArchiveError::Invalid);
        }
        Ok(())
    }
}

pub(crate) fn extract(
    share: &AuthorizedShare<'_>,
    source: &VirtualPath,
    destination: &VirtualPath,
    format: Format,
    limits: ArchiveLimits,
    max_charge: u64,
    work: &Work,
) -> Result<Staged> {
    if max_charge < DIRECTORY_QUOTA_BYTES {
        return Err(ArchiveError::Limit);
    }
    let source_file = share.open_file(source)?;
    if source_file.len() > limits.max_bytes {
        return Err(ArchiveError::Limit);
    }
    // Parse a stable private snapshot. In-place writers of the source cannot
    // change lengths/offsets between ZIP's preflight and its library parser.
    let snapshot = share.begin_write(destination)?;
    let mut file = snapshot.writer()?;
    let size = copy(
        &mut source_file.into_std(),
        &mut file,
        limits.max_bytes.min(max_charge),
        work,
    )?;
    let max_charge = max_charge.saturating_sub(size);
    if max_charge < DIRECTORY_QUOTA_BYTES {
        return Err(ArchiveError::Limit);
    }
    file.rewind()?;
    let mut state = Extraction {
        tree: share.begin_tree(destination)?,
        destination,
        limits,
        work,
        entries: HashMap::new(),
        names: 0,
        bytes: 0,
        charge: DIRECTORY_QUOTA_BYTES,
        max_charge,
    };
    match format {
        Format::Zip => {
            let (directory_start, entry_count) = preflight_zip(&mut file, size, limits, work)?;
            file.rewind()?;
            let metadata_only = Arc::new(AtomicBool::new(true));
            let input = ZipInput {
                file,
                directory_start,
                metadata_only: metadata_only.clone(),
            };
            let mut zip = zip::ZipArchive::with_config(
                zip::read::Config {
                    archive_offset: zip::read::ArchiveOffset::Known(0),
                },
                Bounded::new(
                    input,
                    limits.max_bytes.saturating_add(32 * 1024 * 1024),
                    work,
                ),
            )
            .map_err(|_| ArchiveError::Invalid)?;
            metadata_only.store(false, Ordering::Relaxed);
            if zip.len() != entry_count {
                return Err(ArchiveError::Invalid);
            }
            for index in 0..zip.len() {
                work.check()?;
                let mut entry = zip.by_index(index).map_err(|_| ArchiveError::Invalid)?;
                if entry.encrypted()
                    || !matches!(
                        entry.compression(),
                        zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
                    )
                {
                    return Err(ArchiveError::Invalid);
                }
                let directory = entry.is_dir();
                if let Some(mode) = entry.unix_mode() {
                    let kind = mode & 0o170000;
                    if kind != 0 && kind != if directory { 0o040000 } else { 0o100000 } {
                        return Err(ArchiveError::Invalid);
                    }
                }
                let name = entry.name_raw().to_vec();
                let size = entry.size();
                state.entry(
                    &name,
                    if directory {
                        EntryKind::Directory
                    } else {
                        EntryKind::File
                    },
                    size,
                    &mut entry,
                )?;
            }
        }
        Format::Gz => {
            let name = source.file_name().ok_or(ArchiveError::Invalid)?.as_str();
            let name = name.strip_suffix(".gz").unwrap_or("contents");
            let path = state
                .path(name.as_bytes(), false)?
                .ok_or(ArchiveError::Invalid)?;
            state.add(&path, EntryKind::File, true)?;
            let mut decoder =
                flate2::read::MultiGzDecoder::new(Bounded::new(file, limits.max_bytes, work));
            let mut output = state.tree.file(&path)?;
            copy(
                &mut decoder,
                &mut output,
                limits.max_bytes.min(max_charge - DIRECTORY_QUOTA_BYTES),
                work,
            )?;
            output.sync_all()?;
        }
        _ => {
            let input = Bounded::new(file, limits.max_bytes, work);
            let decoder: Box<dyn Read> = match format {
                Format::Tar => Box::new(input),
                Format::TarGz => Box::new(flate2::read::MultiGzDecoder::new(input)),
                Format::TarZst => {
                    let mut decoder = zstd::stream::read::Decoder::new(input)?;
                    decoder.window_log_max(23)?;
                    Box::new(decoder)
                }
                _ => unreachable!(),
            };
            // Headers/padding count too, including discarded trailing data.
            let mut decoded = Bounded::new(
                decoder,
                limits.max_bytes.saturating_add(MAX_ZIP_DIRECTORY),
                work,
            );
            extract_tar(&mut decoded, &mut state)?;
            copy(
                &mut decoded,
                &mut io::sink(),
                limits.max_bytes.saturating_add(MAX_ZIP_DIRECTORY),
                work,
            )?;
        }
    }
    work.check()?;
    Ok(Staged::Tree(state.tree))
}

/// Raw iteration avoids tar's eager, attacker-sized GNU/PAX metadata buffers.
fn extract_tar(reader: &mut impl Read, state: &mut Extraction<'_>) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut pending_name: Option<Vec<u8>> = None;
    let mut pending_size: Option<u64> = None;
    for (count, entry) in archive.entries()?.raw(true).enumerate() {
        state.work.check()?;
        if count >= state.limits.max_entries {
            return Err(ArchiveError::Limit);
        }
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        let size = entry.size();
        if kind.is_gnu_longname() || kind.is_pax_local_extensions() {
            if size > MAX_TAR_EXTENSION || pending_name.is_some() {
                return Err(ArchiveError::Limit);
            }
            let mut data = Vec::new();
            (&mut entry)
                .take(MAX_TAR_EXTENSION + 1)
                .read_to_end(&mut data)?;
            if kind.is_gnu_longname() {
                if data.last() == Some(&0) {
                    data.pop();
                }
                pending_name = Some(data);
            } else {
                for extension in tar::PaxExtensions::new(&data) {
                    let extension = extension?;
                    match extension.key_bytes() {
                        b"path" => {
                            if pending_name.is_some() {
                                return Err(ArchiveError::Invalid);
                            }
                            pending_name = Some(extension.value_bytes().to_vec());
                        }
                        b"size" => {
                            pending_size = Some(
                                std::str::from_utf8(extension.value_bytes())
                                    .map_err(|_| ArchiveError::Invalid)?
                                    .parse()
                                    .map_err(|_| ArchiveError::Invalid)?,
                            );
                        }
                        key if key.starts_with(b"GNU.sparse") => return Err(ArchiveError::Invalid),
                        _ => {}
                    }
                }
            }
            continue;
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(ArchiveError::Invalid);
        }
        if pending_size.take().is_some_and(|value| value != size) {
            return Err(ArchiveError::Invalid);
        }
        let name = pending_name
            .take()
            .unwrap_or_else(|| entry.path_bytes().into_owned());
        state.entry(
            &name,
            if kind.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            size,
            &mut entry,
        )?;
    }
    if pending_name.is_some() || pending_size.is_some() {
        return Err(ArchiveError::Invalid);
    }
    Ok(())
}

fn u16le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("fixed header"))
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed header"))
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed header"))
}

/// Check central-directory sizes and every record *before* ZipArchive allocates
/// its directory. Offsets are absolute; multipart/self-extracting ZIPs fail closed.
fn preflight_zip(
    file: &mut File,
    size: u64,
    limits: ArchiveLimits,
    work: &Work,
) -> Result<(u64, usize)> {
    let tail_size = size.min(65_557) as usize;
    file.seek(SeekFrom::End(-(tail_size as i64)))?;
    let mut tail = vec![0; tail_size];
    file.read_exact(&mut tail)?;
    let at = tail
        .windows(4)
        .rposition(|b| b == b"PK\x05\x06")
        .ok_or(ArchiveError::Invalid)?;
    if tail.len() - at < 22 || at + 22 + usize::from(u16le(&tail, at + 20)) != tail.len() {
        return Err(ArchiveError::Invalid);
    }
    let end = &tail[at..];
    if u16le(end, 4) != 0 || u16le(end, 6) != 0 || u16le(end, 8) != u16le(end, 10) {
        return Err(ArchiveError::Invalid);
    }
    let mut count = u64::from(u16le(end, 10));
    let mut bytes = u64::from(u32le(end, 12));
    let mut offset = u64::from(u32le(end, 16));
    let mut boundary = size - tail_size as u64 + at as u64;
    let eocd_at = boundary;
    let mut zip64_position = None;
    if count == u16::MAX as u64 || bytes == u32::MAX as u64 || offset == u32::MAX as u64 {
        if boundary < 20 {
            return Err(ArchiveError::Invalid);
        }
        file.seek(SeekFrom::Start(boundary - 20))?;
        let mut locator = [0; 20];
        file.read_exact(&mut locator)?;
        if &locator[..4] != b"PK\x06\x07" || u32le(&locator, 4) != 0 || u32le(&locator, 16) != 1 {
            return Err(ArchiveError::Invalid);
        }
        let zip64_at = u64le(&locator, 8);
        if zip64_at > boundary - 20 || boundary - 20 - zip64_at < 56 {
            return Err(ArchiveError::Invalid);
        }
        file.seek(SeekFrom::Start(zip64_at))?;
        let mut record = [0; 56];
        file.read_exact(&mut record)?;
        if &record[..4] != b"PK\x06\x06"
            || u64le(&record, 4) != 44
            || u32le(&record, 16) != 0
            || u32le(&record, 20) != 0
            || u64le(&record, 24) != u64le(&record, 32)
        {
            return Err(ArchiveError::Invalid);
        }
        count = u64le(&record, 32);
        bytes = u64le(&record, 40);
        offset = u64le(&record, 48);
        boundary = zip64_at;
        zip64_position = Some(zip64_at);
    }
    if count > limits.max_entries as u64 || bytes > MAX_ZIP_DIRECTORY {
        return Err(ArchiveError::Limit);
    }
    if offset.checked_add(bytes) != Some(boundary) {
        return Err(ArchiveError::Invalid);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut consumed = 0_u64;
    let mut names = 0_usize;
    for _ in 0..count {
        work.check()?;
        if bytes.saturating_sub(consumed) < 46 {
            return Err(ArchiveError::Invalid);
        }
        let mut header = [0; 46];
        file.read_exact(&mut header)?;
        if &header[..4] != b"PK\x01\x02" || u16le(&header, 34) != 0 {
            return Err(ArchiveError::Invalid);
        }
        names += usize::from(u16le(&header, 28));
        let variable = u64::from(u16le(&header, 28))
            + u64::from(u16le(&header, 30))
            + u64::from(u16le(&header, 32));
        consumed += 46 + variable;
        if consumed > bytes || names > limits.max_name_bytes {
            return Err(ArchiveError::Limit);
        }
        file.seek(SeekFrom::Current(variable as i64))?;
    }
    if consumed != bytes {
        return Err(ArchiveError::Invalid);
    }
    // Only these validated end records may be visible to the library's
    // fallback search. This bounded region includes the archive comment.
    let metadata_size = size.checked_sub(offset).ok_or(ArchiveError::Invalid)?;
    if metadata_size > MAX_ZIP_DIRECTORY + 65_657 {
        return Err(ArchiveError::Limit);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut metadata = vec![0; metadata_size as usize];
    file.read_exact(&mut metadata)?;
    for (index, magic) in metadata.windows(4).enumerate() {
        let position = offset + index as u64;
        if (magic == b"PK\x05\x06" && position != eocd_at)
            || (magic == b"PK\x06\x06" && Some(position) != zip64_position)
        {
            return Err(ArchiveError::Invalid);
        }
    }
    Ok((offset, count as usize))
}

/// Synthetic inputs keep decoder coverage independent of the production ZIP writer.
#[cfg(test)]
pub(crate) fn fixture_archive(format: Format, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let bytes = if format == Format::Gz {
        entries[0].1.to_vec()
    } else {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_entry_type(if name.ends_with('/') {
                tar::EntryType::Directory
            } else {
                tar::EntryType::Regular
            });
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    };
    match format {
        Format::Tar => bytes,
        Format::TarGz | Format::Gz => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&bytes).unwrap();
            encoder.finish().unwrap()
        }
        Format::TarZst => zstd::stream::encode_all(bytes.as_slice(), 1).unwrap(),
        Format::Zip => unreachable!("ZIP fixtures use the production writer"),
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "tests construct hostile synthetic archives in temporary shares"
)]
mod tests {
    use super::*;
    use crate::filesystem::{AccessLevel, GlobalPolicy, ShareFs, ShareGrant, ShareId};
    use std::fs;
    use tempfile::TempDir;

    fn limits() -> ArchiveLimits {
        ArchiveLimits {
            max_entries: 100,
            max_bytes: 1_048_576,
            max_name_bytes: 4096,
        }
    }
    fn fixture() -> (TempDir, ShareFs, ShareGrant) {
        let root = TempDir::new().unwrap();
        let id = ShareId::new("test").unwrap();
        let share = ShareFs::open(id.clone(), root.path()).unwrap();
        (
            root,
            share,
            ShareGrant {
                share_id: id,
                access: AccessLevel::ReadWrite,
            },
        )
    }
    fn path(value: &str) -> VirtualPath {
        VirtualPath::parse(value).unwrap()
    }
    fn assert_clean(root: &TempDir) {
        assert_eq!(
            fs::read_dir(root.path().join(".crabinet/staging"))
                .unwrap()
                .count(),
            0
        );
    }
    fn tar_entry(name: &str, kind: u8, bytes: &[u8], advertised: Option<u64>) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o7777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_size(advertised.unwrap_or(bytes.len() as u64));
        header.set_entry_type(tar::EntryType::new(kind));
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut result = header.as_bytes().to_vec();
        result.extend_from_slice(bytes);
        result.resize(512 + bytes.len().div_ceil(512) * 512, 0);
        result
    }
    fn zip_bytes(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
        zip.finish().unwrap().into_inner()
    }
    fn extract_bytes(bytes: &[u8], format: Format, limits: ArchiveLimits) -> Result<()> {
        let (root, filesystem, grant) = fixture();
        fs::write(root.path().join("input.gz"), bytes).unwrap();
        let share = filesystem
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let (work, _cancel) = Work::new();
        let result = extract(
            &share,
            &path("input.gz"),
            &path("output"),
            format,
            limits,
            u64::MAX,
            &work,
        )
        .and_then(Staged::publish);
        if result.is_err() {
            assert!(!root.path().join("output").exists());
        }
        assert_clean(&root);
        result
    }

    #[test]
    fn zip_creation_and_all_formats_extract_files_folders_empty_dirs_and_unicode() {
        for format in [
            Format::Zip,
            Format::Tar,
            Format::TarGz,
            Format::Gz,
            Format::TarZst,
        ] {
            let (root, filesystem, grant) = fixture();
            fs::create_dir_all(root.path().join("folder/empty")).unwrap();
            fs::write(root.path().join("folder/café.txt"), b"archive contents").unwrap();
            fs::write(root.path().join("plain"), b"single contents").unwrap();
            let share = filesystem
                .authorize(Some(&grant), GlobalPolicy::default())
                .unwrap();
            let (work, _cancel) = Work::new();
            if format == Format::Zip {
                compress(
                    &share,
                    &[path("folder")],
                    &path("archive.gz"),
                    limits(),
                    u64::MAX,
                    &work,
                )
                .unwrap()
                .publish()
                .unwrap();
            } else {
                let entries: &[(&str, &[u8])] = if format == Format::Gz {
                    &[("plain", b"single contents")]
                } else {
                    &[
                        ("folder/empty/", b""),
                        ("folder/café.txt", b"archive contents"),
                    ]
                };
                fs::write(
                    root.path().join("archive.gz"),
                    fixture_archive(format, entries),
                )
                .unwrap();
            }
            extract(
                &share,
                &path("archive.gz"),
                &path("output"),
                format,
                limits(),
                u64::MAX,
                &work,
            )
            .unwrap()
            .publish()
            .unwrap();
            if format == Format::Gz {
                assert_eq!(
                    fs::read(root.path().join("output/archive")).unwrap(),
                    b"single contents"
                );
            } else {
                assert_eq!(
                    fs::read(root.path().join("output/folder/café.txt")).unwrap(),
                    b"archive contents"
                );
                assert!(root.path().join("output/folder/empty").is_dir());
            }
            assert_clean(&root);
        }
    }

    #[test]
    fn zip_and_tar_reject_traversal_internal_and_noncanonical_names() {
        for name in [
            "../escape",
            "/absolute",
            "a/../../escape",
            "a\\escape",
            ".crabinet/secret",
            "a/.index-tmp-evil",
            "a/CON",
            "a/zero\u{200b}width",
            "cafe\u{301}.txt",
        ] {
            assert!(
                extract_bytes(&zip_bytes(name, b"bad"), Format::Zip, limits()).is_err(),
                "ZIP {name}"
            );
            let mut tar = tar_entry(name, b'0', b"bad", None);
            tar.extend_from_slice(&[0; 1024]);
            assert!(
                extract_bytes(&tar, Format::Tar, limits()).is_err(),
                "TAR {name}"
            );
        }
    }

    #[test]
    fn tar_rejects_links_devices_fifos_sparse_and_duplicate_entries() {
        for kind in *b"12346Sg" {
            assert!(
                extract_bytes(&tar_entry("bad", kind, &[], None), Format::Tar, limits()).is_err()
            );
        }
        for entries in [
            vec![
                tar_entry("a", b'0', b"one", None),
                tar_entry("a", b'0', b"two", None),
            ],
            vec![
                tar_entry("a", b'0', b"one", None),
                tar_entry("a/b", b'0', b"two", None),
            ],
        ] {
            assert!(extract_bytes(&entries.concat(), Format::Tar, limits()).is_err());
        }
    }

    #[test]
    fn parser_metadata_and_declared_sizes_are_bounded_before_allocation() {
        assert!(matches!(
            extract_bytes(
                &tar_entry("metadata", b'L', &[], Some(1 << 40)),
                Format::Tar,
                limits()
            ),
            Err(ArchiveError::Limit)
        ));
        assert!(matches!(
            extract_bytes(
                &tar_entry("huge", b'0', &[], Some(1 << 40)),
                Format::Tar,
                limits()
            ),
            Err(ArchiveError::Limit)
        ));
        let mut zip = zip_bytes("safe", b"data");
        let end = zip.len() - 22;
        zip[end + 8..end + 12].copy_from_slice(&[0xfe, 0xff, 0xfe, 0xff]);
        assert!(matches!(
            extract_bytes(&zip, Format::Zip, limits()),
            Err(ArchiveError::Limit)
        ));
    }

    #[test]
    fn expansion_entry_name_and_depth_budgets_include_implicit_directories() {
        let bomb = zip_bytes("bomb", &vec![b'a'; 100_000]);
        let mut small = limits();
        small.max_bytes = 8192;
        assert!(matches!(
            extract_bytes(&bomb, Format::Zip, small),
            Err(ArchiveError::Limit)
        ));
        let gzip = {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&vec![b'a'; 100_000]).unwrap();
            gz.finish().unwrap()
        };
        assert!(matches!(
            extract_bytes(&gzip, Format::Gz, small),
            Err(ArchiveError::Limit)
        ));
        let mut few = limits();
        few.max_entries = 2;
        assert!(matches!(
            extract_bytes(&zip_bytes("a/b/c", b"x"), Format::Zip, few),
            Err(ArchiveError::Limit)
        ));
        let deep = std::iter::repeat_n("d", MAX_PATH_DEPTH)
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            extract_bytes(&zip_bytes(&deep, b"x"), Format::Zip, limits()),
            Err(ArchiveError::Depth)
        ));
        let boundary = std::iter::repeat_n("d", MAX_PATH_DEPTH - 1)
            .collect::<Vec<_>>()
            .join("/");
        let mut wide = limits();
        wide.max_name_bytes = 100_000;
        extract_bytes(&zip_bytes(&boundary, b"x"), Format::Zip, wide).unwrap();
        let mut names = limits();
        names.max_name_bytes = 4;
        assert!(matches!(
            extract_bytes(&zip_bytes("a/b/c", b"x"), Format::Zip, names),
            Err(ArchiveError::Limit)
        ));
    }

    #[test]
    fn damaged_checksums_and_truncated_streams_publish_nothing() {
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(b"contents").unwrap();
        let mut bytes = gzip.finish().unwrap();
        let at = bytes.len() - 8;
        bytes[at] ^= 1;
        assert!(extract_bytes(&bytes, Format::Gz, limits()).is_err());
        let truncated = &bytes[..bytes.len() - 6];
        assert!(extract_bytes(truncated, Format::Gz, limits()).is_err());
        assert!(extract_bytes(b"not an archive", Format::Zip, limits()).is_err());
    }

    #[test]
    fn cancellation_timeout_and_quota_release_staging() {
        let (root, filesystem, grant) = fixture();
        fs::write(
            root.path().join("input.zip"),
            zip_bytes("safe", b"contents"),
        )
        .unwrap();
        let share = filesystem
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let (mut work, cancel) = Work::new();
        drop(cancel);
        assert!(matches!(
            extract(
                &share,
                &path("input.zip"),
                &path("output"),
                Format::Zip,
                limits(),
                u64::MAX,
                &work
            ),
            Err(ArchiveError::Cancelled)
        ));
        work.cancelled.store(false, Ordering::Relaxed);
        work.until = Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            extract(
                &share,
                &path("input.zip"),
                &path("output"),
                Format::Zip,
                limits(),
                u64::MAX,
                &work
            ),
            Err(ArchiveError::Cancelled)
        ));
        let (work, _cancel) = Work::new();
        assert!(matches!(
            extract(
                &share,
                &path("input.zip"),
                &path("output"),
                Format::Zip,
                limits(),
                4096,
                &work
            ),
            Err(ArchiveError::Limit)
        ));
        assert_clean(&root);
    }

    #[test]
    fn publication_never_overwrites_files_directories_or_symlinks() {
        let (root, filesystem, grant) = fixture();
        fs::write(
            root.path().join("input.zip"),
            zip_bytes("safe", b"contents"),
        )
        .unwrap();
        let share = filesystem
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let (work, _cancel) = Work::new();
        fs::write(root.path().join("output"), b"keep").unwrap();
        let pending = extract(
            &share,
            &path("input.zip"),
            &path("output"),
            Format::Zip,
            limits(),
            u64::MAX,
            &work,
        )
        .unwrap();
        assert!(pending.publish().is_err());
        assert_eq!(fs::read(root.path().join("output")).unwrap(), b"keep");
        assert_clean(&root);
        fs::remove_file(root.path().join("output")).unwrap();
        std::os::unix::fs::symlink("elsewhere", root.path().join("output")).unwrap();
        assert!(
            extract(
                &share,
                &path("input.zip"),
                &path("output"),
                Format::Zip,
                limits(),
                u64::MAX,
                &work
            )
            .unwrap()
            .publish()
            .is_err()
        );
        assert!(root.path().join("output").is_symlink());
        assert_clean(&root);
    }

    #[test]
    fn gnu_long_names_round_trip_without_unbounded_extension_parsing() {
        let (root, filesystem, grant) = fixture();
        let name = "a".repeat(120);
        fs::write(root.path().join(&name), b"long name").unwrap();
        let share = filesystem
            .authorize(Some(&grant), GlobalPolicy::default())
            .unwrap();
        let (work, _cancel) = Work::new();
        fs::write(
            root.path().join("archive.tar"),
            fixture_archive(Format::Tar, &[(&name, b"long name")]),
        )
        .unwrap();
        extract(
            &share,
            &path("archive.tar"),
            &path("output"),
            Format::Tar,
            limits(),
            u64::MAX,
            &work,
        )
        .unwrap()
        .publish()
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("output").join(name)).unwrap(),
            b"long name"
        );
    }

    #[test]
    fn zip_metadata_discovery_hides_forged_end_records_in_payloads() {
        let (root, _, _) = fixture();
        fs::write(root.path().join("bytes"), b"PK\x06\x06forged-body-metadata").unwrap();
        let flag = Arc::new(AtomicBool::new(true));
        let mut input = ZipInput {
            file: File::open(root.path().join("bytes")).unwrap(),
            directory_start: 10,
            metadata_only: flag.clone(),
        };
        let mut bytes = [1; 10];
        input.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [0; 10]);
        flag.store(false, Ordering::Relaxed);
        input.rewind().unwrap();
        input.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], b"PK\x06\x06");
    }

    #[test]
    fn local_pax_paths_are_validated_and_zstd_large_windows_are_refused() {
        let value = "path=../escape\n";
        let extension = format!("{} {value}", value.len() + 3);
        let mut bytes = tar_entry("pax", b'x', extension.as_bytes(), None);
        bytes.extend(tar_entry("safe", b'0', b"data", None));
        assert!(extract_bytes(&bytes, Format::Tar, limits()).is_err());
        // Frame descriptor without a single-segment bit; the window
        // descriptor requests 128 MiB, above our fixed 8 MiB cap.
        assert!(
            extract_bytes(
                &[0x28, 0xb5, 0x2f, 0xfd, 0, 0x88, 1, 0, 0],
                Format::TarZst,
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn zip_duplicate_central_names_cannot_be_hidden_by_library_deduplication() {
        let mut writer = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        for name in ["a", "b"] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"data").unwrap();
        }
        let mut bytes = writer.finish().unwrap().into_inner();
        let positions = bytes
            .windows(4)
            .enumerate()
            .filter_map(|(index, magic)| (magic == b"PK\x01\x02").then_some(index))
            .collect::<Vec<_>>();
        bytes[positions[1] + 46] = b'a';
        assert!(extract_bytes(&bytes, Format::Zip, limits()).is_err());
    }
}

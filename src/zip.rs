//! A streaming ZIP writer for folder and selection downloads.
//!
//! Every file entry is either stored or deflated. Whether an entry may be
//! deflated is decided when the archive is planned, from its size and name
//! alone (see [`may_deflate`]); such a candidate's first bytes then settle
//! it when its turn comes ([`sniff_deflate`]). An archive without candidates
//! has its layout fixed before the first byte is sent: each entry's size
//! comes from the folder walk, so every header offset and the total length
//! are known up front and the response can carry `Content-Length`. Once an
//! entry may be deflated, the offsets after it are known only as the archive
//! streams, so the writer records each entry's offset and compressed size as
//! it goes and builds the central directory from them.
//!
//! A file's CRC-32 is computed while its bytes stream, written in a data
//! descriptor after them, and repeated in the central directory. ZIP64
//! fields appear only for the entries, offsets, and counts that overflow the
//! classic 32-bit and 16-bit fields; a deflated entry uses them as soon as
//! its compressed size could overflow, which is decided from its file size
//! before its local header is written.

use std::{
    io::{self, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use flate2::{Compress, Compression, FlushCompress, Status};
use time::OffsetDateTime;

use crate::{config::ArchiveCompression, preview};

const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const ZIP64_END_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const END_SIGNATURE: u32 = 0x0605_4b50;
/// General-purpose flag bit 3: the CRC and sizes follow the file's bytes.
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
/// General-purpose flag bit 11: names are UTF-8.
const FLAG_UTF8: u16 = 1 << 11;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;
/// Version 2.0 covers stored and deflated entries alike.
const VERSION_DEFAULT: u16 = 20;
const VERSION_ZIP64: u16 = 45;
/// High byte of "version made by": external attributes hold Unix modes.
const CREATOR_UNIX: u16 = 3 << 8;
const EXTENDED_TIMESTAMP_ID: u16 = 0x5455;
const EXTENDED_TIMESTAMP_LEN: u64 = 9;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const LOCAL_HEADER_LEN: u64 = 30;
const CENTRAL_HEADER_LEN: u64 = 46;
const DATA_DESCRIPTOR_LEN: u64 = 16;
const ZIP64_DATA_DESCRIPTOR_LEN: u64 = 24;
const END_LEN: u64 = 22;
const ZIP64_END_LEN: u64 = 56;
const ZIP64_LOCATOR_LEN: u64 = 20;
const U32_SENTINEL: u64 = 0xFFFF_FFFF;
const U16_SENTINEL: u64 = 0xFFFF;
/// Fixed modes: the archive does not disclose host permissions.
const FILE_ATTRIBUTES: u32 = 0o100_644 << 16;
const DIRECTORY_ATTRIBUTES: u32 = (0o040_755 << 16) | 0x10;
/// 1980-01-01 00:00:00, the earliest MS-DOS timestamp.
const DOS_MIN: (u16, u16) = (0, (1 << 5) | 1);
/// 2107-12-31 23:59:58, the latest MS-DOS timestamp.
const DOS_MAX: (u16, u16) = (0xBF7D, 0xFF9F);

/// Files smaller than this are always stored: headers, the data descriptor,
/// and deflate's block overhead leave little to gain, and every candidate
/// costs the archive its exact length.
pub(crate) const MIN_DEFLATE_BYTES: u64 = 1024;
/// Leading bytes of a candidate read to decide whether it is text. They are
/// the start of the entry's data either way, so nothing is read twice.
pub(crate) const SNIFF_BYTES: usize = 8 * 1024;
/// miniz level 2 (greedy matching with short hash chains). Measured on one
/// core of the development VM over 64 MiB of source text and of CSV: level
/// 1 compressed 200–225 MB/s to 34–36 %, level 2 173–175 MB/s to 26–32 %,
/// level 3 74–100 MB/s to 24–30 %, and level 6 26–43 MB/s to 23–27 %. Level
/// 2 keeps one stream above gigabit line rate on one core for most of the
/// size gain.
const DEFLATE_LEVEL: u32 = 2;
/// Uncompressed bytes read from a deflated file at a time.
const DEFLATE_INPUT_BYTES: usize = 64 * 1024;
/// Extensions of formats that are already compressed: raster images and
/// camera RAW, audio and video, ZIP-based documents and packages, compressed
/// archives and disk images, PDF, and web fonts. A file with one of these
/// names is stored without reading it first, so an archive of such files
/// keeps its exact length. Lowercase; names are compared case-insensitively.
const COMPRESSED_EXTENSIONS: &[&str] = &[
    // Raster images.
    "apng", "avif", "gif", "heic", "heics", "heif", "hif", "jfif", "jpe", "jpeg", "jpg", "jxl",
    "png", "svgz", "webp", // Camera RAW.
    "3fr", "arw", "cr2", "cr3", "crw", "dng", "erf", "kdc", "mrw", "nef", "nrw", "orf", "pef",
    "raf", "rw2", "sr2", "srf", "srw", "x3f", // Video.
    "3g2", "3gp", "avi", "flv", "m2ts", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "mts", "ogv",
    "qt", "vob", "webm", "wmv", // Audio.
    "aac", "flac", "m4a", "m4b", "mp3", "oga", "ogg", "opus", "wma",
    // ZIP-based documents and packages.
    "aab", "apk", "docm", "docx", "ear", "epub", "ipa", "jar", "kmz", "nupkg", "odg", "odp", "ods",
    "odt", "pptm", "pptx", "vsix", "war", "whl", "xlsm", "xlsx", "xpi", "zip", "zipx",
    // Compressed archives, packages, and disk images.
    "7z", "br", "bz2", "cab", "deb", "dmg", "gz", "lz", "lz4", "lzma", "rar", "rpm", "tbz", "tbz2",
    "tgz", "txz", "tzst", "xz", "zst", // Documents and fonts.
    "pdf", "woff", "woff2",
];

/// Whether a file of `size` bytes named `name` may be deflated, from what is
/// known before it is read: large enough, and not named as an
/// already-compressed format.
pub(crate) fn may_deflate(name: &str, size: u64) -> bool {
    size >= MIN_DEFLATE_BYTES && !has_compressed_extension(name)
}

fn has_compressed_extension(name: &str) -> bool {
    let file = name.rsplit('/').next().unwrap_or(name);
    file.rsplit_once('.').is_some_and(|(_, extension)| {
        extension.len() <= 5
            && COMPRESSED_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

/// Whether a candidate whose first bytes are `prefix` is deflated: it must
/// not start with an already-compressed format's signature, and must read
/// as text, either UTF-8 by the text-preview rules or mostly printable ASCII
/// without NUL bytes (legacy 8-bit encodings). Everything else is stored.
/// `at_end` says that `prefix` is the whole file.
pub(crate) fn sniff_deflate(prefix: &[u8], at_end: bool) -> bool {
    !preview::has_compressed_signature(prefix)
        && (preview::is_text_prefix(prefix, at_end) || is_mostly_ascii(prefix))
}

/// No NUL byte, and at least 90% printable ASCII or whitespace.
fn is_mostly_ascii(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|byte| matches!(byte, b' '..=b'~' | b'\t' | b'\n' | b'\r'))
        .count();
    !bytes.contains(&0) && printable * 10 >= bytes.len() * 9
}

/// Whether deflating `size` bytes could produce 0xFFFFFFFF bytes or more.
/// Deflate's worst case is a few bytes per 64 KiB stored block; the margin
/// of an eighth plus 1 KiB also covers fixed-Huffman literals at 9 bits.
const fn deflated_may_overflow(size: u64) -> bool {
    size.saturating_add(size / 8).saturating_add(1024) >= U32_SENTINEL
}

/// The data of an entry differed from what the walk recorded.
pub(crate) fn entry_changed() -> io::Error {
    io::Error::other("an archived entry changed while streaming")
}

fn layout_error() -> io::Error {
    io::Error::other("archive length differs from its plan")
}

/// One entry to archive. `name` is relative to the archive root, uses `/`
/// separators, and has no trailing slash; directories gain one.
#[derive(Clone, Debug)]
pub(crate) struct ZipSource {
    pub(crate) name: String,
    /// `None` for a directory.
    pub(crate) size: Option<u64>,
    pub(crate) modified: Option<SystemTime>,
}

/// How an entry's bytes are encoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Stored,
    /// Deflated if its first bytes read as text, otherwise stored; settled
    /// when its local header is written.
    Candidate,
    Deflated,
}

#[derive(Debug)]
struct ZipEntry {
    name: String,
    size: Option<u64>,
    method: Method,
    dos_time: u16,
    dos_date: u16,
    unix_mtime: Option<u32>,
    /// Planned before streaming; recorded again when the header is written.
    offset: u64,
    crc: u32,
    /// Bytes of data written for the entry, known once it has streamed.
    compressed: u64,
}

impl ZipEntry {
    fn zip64_sizes(&self) -> bool {
        self.size.is_some_and(|size| match self.method {
            Method::Stored => size >= U32_SENTINEL,
            Method::Candidate | Method::Deflated => deflated_may_overflow(size),
        })
    }

    fn zip64_offset(&self) -> bool {
        self.offset >= U32_SENTINEL
    }

    fn version(&self) -> u16 {
        if self.zip64_sizes() || self.zip64_offset() {
            VERSION_ZIP64
        } else {
            VERSION_DEFAULT
        }
    }

    fn flags(&self) -> u16 {
        if self.size.is_some() {
            FLAG_UTF8 | FLAG_DATA_DESCRIPTOR
        } else {
            FLAG_UTF8
        }
    }

    fn method_code(&self) -> u16 {
        if self.method == Method::Deflated {
            METHOD_DEFLATED
        } else {
            METHOD_STORED
        }
    }

    fn timestamp_extra_len(&self) -> u64 {
        if self.unix_mtime.is_some() {
            EXTENDED_TIMESTAMP_LEN
        } else {
            0
        }
    }

    fn local_extra_len(&self) -> u64 {
        self.timestamp_extra_len() + if self.zip64_sizes() { 20 } else { 0 }
    }

    fn central_zip64_fields(&self) -> u64 {
        let sizes = if self.zip64_sizes() { 2 } else { 0 };
        sizes + u64::from(self.zip64_offset())
    }

    fn central_extra_len(&self) -> u64 {
        let fields = self.central_zip64_fields();
        let zip64 = if fields == 0 { 0 } else { 4 + 8 * fields };
        self.timestamp_extra_len() + zip64
    }

    fn local_len(&self) -> u64 {
        LOCAL_HEADER_LEN + self.name.len() as u64 + self.local_extra_len()
    }

    fn descriptor_len(&self) -> u64 {
        match self.size {
            None => 0,
            Some(_) if self.zip64_sizes() => ZIP64_DATA_DESCRIPTOR_LEN,
            Some(_) => DATA_DESCRIPTOR_LEN,
        }
    }

    fn central_len(&self) -> u64 {
        CENTRAL_HEADER_LEN + self.name.len() as u64 + self.central_extra_len()
    }
}

/// The byte layout of one archive: planned in full when no entry may be
/// deflated, otherwise completed as the entries stream.
#[derive(Debug)]
pub(crate) struct ZipPlan {
    entries: Vec<ZipEntry>,
    /// Whether some entry may be deflated, so the length is known only once
    /// every entry has streamed.
    variable: bool,
    /// Bytes of local headers, data, and descriptors written so far.
    position: u64,
    central_offset: u64,
    central_len: u64,
    len: u64,
}

impl ZipPlan {
    /// Lays out `sources` in order, marking the files that may be deflated
    /// under `compression`. Returns `None` for an empty or over-long name, or
    /// a layout whose stored length overflows `u64`.
    pub(crate) fn new(sources: Vec<ZipSource>, compression: ArchiveCompression) -> Option<Self> {
        let mut entries = Vec::with_capacity(sources.len());
        let mut offset = 0_u64;
        let mut variable = false;
        for source in sources {
            let mut name = source.name;
            if name.is_empty() || name.ends_with('/') {
                return None;
            }
            if source.size.is_none() {
                name.push('/');
            }
            if name.len() > usize::from(u16::MAX) {
                return None;
            }
            let method = match source.size {
                Some(size)
                    if compression == ArchiveCompression::Auto && may_deflate(&name, size) =>
                {
                    Method::Candidate
                }
                _ => Method::Stored,
            };
            variable |= method == Method::Candidate;
            let (dos_time, dos_date) = dos_timestamp(source.modified);
            let entry = ZipEntry {
                name,
                size: source.size,
                method,
                dos_time,
                dos_date,
                unix_mtime: unix_mtime(source.modified),
                offset,
                crc: 0,
                compressed: 0,
            };
            offset = offset
                .checked_add(entry.local_len())?
                .checked_add(entry.size.unwrap_or(0))?
                .checked_add(entry.descriptor_len())?;
            entries.push(entry);
        }
        let central_offset = offset;
        let central_len = entries
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.central_len()))?;
        let mut plan = Self {
            entries,
            variable,
            position: 0,
            central_offset,
            central_len,
            len: 0,
        };
        plan.len = central_offset
            .checked_add(central_len)?
            .checked_add(plan.end_len())?;
        Some(plan)
    }

    /// The exact length of an archive in which no entry may be deflated.
    pub(crate) const fn fixed_len(&self) -> Option<u64> {
        if self.variable { None } else { Some(self.len) }
    }

    /// The number of bytes the archive occupies: as planned, and exact once
    /// [`Self::finish_entries`] has run or when [`Self::fixed_len`] is known.
    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The archived name of entry `index`; a directory's ends with `/`.
    pub(crate) fn entry_name(&self, index: usize) -> &str {
        &self.entries[index].name
    }

    /// The file size of entry `index`, or `None` for a directory.
    pub(crate) fn entry_size(&self, index: usize) -> Option<u64> {
        self.entries[index].size
    }

    /// Whether file entry `index` is deflated if its first bytes read as text.
    pub(crate) fn may_deflate(&self, index: usize) -> bool {
        self.entries[index].method == Method::Candidate
    }

    /// Writes the local header of entry `index` at the current position.
    /// `deflate` settles a candidate; other entries ignore it.
    pub(crate) fn write_local_header(&mut self, index: usize, deflate: bool, out: &mut Vec<u8>) {
        let position = self.position;
        let entry = &mut self.entries[index];
        if entry.method == Method::Candidate {
            entry.method = if deflate {
                Method::Deflated
            } else {
                Method::Stored
            };
        }
        entry.offset = position;
        let size_field = if entry.zip64_sizes() { u32::MAX } else { 0 };
        put_u32(out, LOCAL_HEADER_SIGNATURE);
        put_u16(out, entry.version());
        put_u16(out, entry.flags());
        put_u16(out, entry.method_code());
        put_u16(out, entry.dos_time);
        put_u16(out, entry.dos_date);
        // With a data descriptor the CRC and sizes are zero here; a ZIP64
        // entry marks the 32-bit sizes as deferred to its extra field.
        put_u32(out, 0);
        put_u32(out, size_field);
        put_u32(out, size_field);
        put_u16(out, entry.name.len() as u16);
        put_u16(out, entry.local_extra_len() as u16);
        out.extend_from_slice(entry.name.as_bytes());
        put_timestamp_extra(out, entry.unix_mtime);
        if entry.zip64_sizes() {
            put_u16(out, ZIP64_EXTRA_ID);
            put_u16(out, 16);
            put_u64(out, 0);
            put_u64(out, 0);
        }
        self.position = position.saturating_add(entry.local_len());
    }

    /// Records the CRC and written length of file entry `index` and writes
    /// its data descriptor. Fails when a stored entry's length differs from
    /// its size, or a compressed length overflows the fields its local
    /// header chose.
    pub(crate) fn write_data_descriptor(
        &mut self,
        index: usize,
        crc: u32,
        compressed: u64,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        let entry = &mut self.entries[index];
        let Some(size) = entry.size else {
            return Ok(());
        };
        if (entry.method != Method::Deflated && compressed != size)
            || (!entry.zip64_sizes() && compressed >= U32_SENTINEL)
        {
            return Err(layout_error());
        }
        entry.crc = crc;
        entry.compressed = compressed;
        put_u32(out, DATA_DESCRIPTOR_SIGNATURE);
        put_u32(out, crc);
        if entry.zip64_sizes() {
            put_u64(out, compressed);
            put_u64(out, size);
        } else {
            put_u32(out, compressed as u32);
            put_u32(out, size as u32);
        }
        self.position = self
            .position
            .checked_add(compressed)
            .and_then(|position| position.checked_add(entry.descriptor_len()))
            .ok_or_else(layout_error)?;
        Ok(())
    }

    /// Fixes the central directory's place and the archive's length once
    /// every entry has been written. A fixed layout must end where planned.
    pub(crate) fn finish_entries(&mut self) -> io::Result<()> {
        let central_offset = self.position;
        let central_len = self
            .entries
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.central_len()))
            .ok_or_else(layout_error)?;
        let planned = (self.central_offset, self.central_len);
        self.central_offset = central_offset;
        self.central_len = central_len;
        let len = central_offset
            .checked_add(central_len)
            .and_then(|len| len.checked_add(self.end_len()))
            .ok_or_else(layout_error)?;
        if !self.variable && ((central_offset, central_len) != planned || len != self.len) {
            return Err(layout_error());
        }
        self.len = len;
        Ok(())
    }

    pub(crate) fn write_central_header(&self, index: usize, out: &mut Vec<u8>) {
        let entry = &self.entries[index];
        let size = entry.size.unwrap_or(0);
        let (compressed_field, size_field) = if entry.zip64_sizes() {
            (u32::MAX, u32::MAX)
        } else {
            (entry.compressed as u32, size as u32)
        };
        let offset_field = if entry.zip64_offset() {
            u32::MAX
        } else {
            entry.offset as u32
        };
        put_u32(out, CENTRAL_HEADER_SIGNATURE);
        put_u16(out, CREATOR_UNIX | entry.version());
        put_u16(out, entry.version());
        put_u16(out, entry.flags());
        put_u16(out, entry.method_code());
        put_u16(out, entry.dos_time);
        put_u16(out, entry.dos_date);
        put_u32(out, entry.crc);
        put_u32(out, compressed_field);
        put_u32(out, size_field);
        put_u16(out, entry.name.len() as u16);
        put_u16(out, entry.central_extra_len() as u16);
        put_u16(out, 0);
        put_u16(out, 0);
        put_u16(out, 0);
        put_u32(
            out,
            if entry.size.is_some() {
                FILE_ATTRIBUTES
            } else {
                DIRECTORY_ATTRIBUTES
            },
        );
        put_u32(out, offset_field);
        out.extend_from_slice(entry.name.as_bytes());
        put_timestamp_extra(out, entry.unix_mtime);
        let fields = entry.central_zip64_fields();
        if fields != 0 {
            put_u16(out, ZIP64_EXTRA_ID);
            put_u16(out, (8 * fields) as u16);
            if entry.zip64_sizes() {
                put_u64(out, size);
                put_u64(out, entry.compressed);
            }
            if entry.zip64_offset() {
                put_u64(out, entry.offset);
            }
        }
    }

    /// Writes the ZIP64 end records when needed, then the classic end record.
    pub(crate) fn write_end(&self, out: &mut Vec<u8>) {
        let count = self.entries.len() as u64;
        if self.needs_zip64_end() {
            let zip64_end_offset = self.central_offset + self.central_len;
            put_u32(out, ZIP64_END_SIGNATURE);
            put_u64(out, ZIP64_END_LEN - 12);
            put_u16(out, CREATOR_UNIX | VERSION_ZIP64);
            put_u16(out, VERSION_ZIP64);
            put_u32(out, 0);
            put_u32(out, 0);
            put_u64(out, count);
            put_u64(out, count);
            put_u64(out, self.central_len);
            put_u64(out, self.central_offset);
            put_u32(out, ZIP64_LOCATOR_SIGNATURE);
            put_u32(out, 0);
            put_u64(out, zip64_end_offset);
            put_u32(out, 1);
        }
        let count_field = count.min(U16_SENTINEL) as u16;
        put_u32(out, END_SIGNATURE);
        put_u16(out, 0);
        put_u16(out, 0);
        put_u16(out, count_field);
        put_u16(out, count_field);
        put_u32(out, self.central_len.min(U32_SENTINEL) as u32);
        put_u32(out, self.central_offset.min(U32_SENTINEL) as u32);
        put_u16(out, 0);
    }

    fn needs_zip64_end(&self) -> bool {
        self.entries.len() as u64 >= U16_SENTINEL
            || self.central_offset >= U32_SENTINEL
            || self.central_len >= U32_SENTINEL
    }

    fn end_len(&self) -> u64 {
        if self.needs_zip64_end() {
            ZIP64_END_LEN + ZIP64_LOCATOR_LEN + END_LEN
        } else {
            END_LEN
        }
    }
}

/// One file entry's data on its way into an archive: read from `source`,
/// checksummed, and stored or deflated. Every method reads and compresses
/// synchronously, so an async caller runs them on the blocking pool.
///
/// A deflating entry holds the compressor (about 312 KiB of tables, window,
/// and hash chains in miniz_oxide) and at most [`DEFLATE_INPUT_BYTES`] of
/// input; a stored candidate holds its [`SNIFF_BYTES`] prefix. The
/// compressor is handed from entry to entry, so one archive allocates it at
/// most once.
pub(crate) struct EntryEncoder<R> {
    source: R,
    /// File bytes not yet read.
    remaining: u64,
    crc: Crc32,
    /// Bytes of entry data produced so far.
    written: u64,
    /// Bytes read but not yet emitted (the sniffed prefix), or not yet
    /// consumed by the compressor, from `consumed` on.
    pending: Vec<u8>,
    consumed: usize,
    compressor: Option<Compress>,
    deflate: bool,
    /// Whether the read past the planned size was made.
    probed: bool,
}

impl<R: Read> EntryEncoder<R> {
    /// Starts a file entry of `size` bytes. A deflate candidate's first
    /// bytes are read now to settle its method, which its local header must
    /// carry; see [`Self::deflated`]. `compressor` is a previous entry's,
    /// reused if this one deflates.
    pub(crate) fn start(
        source: R,
        size: u64,
        candidate: bool,
        compressor: Option<Compress>,
    ) -> io::Result<Self> {
        let mut encoder = Self {
            source,
            remaining: size,
            crc: Crc32::new(),
            written: 0,
            pending: Vec::new(),
            consumed: 0,
            compressor,
            deflate: false,
            probed: false,
        };
        if candidate {
            let prefix = size.min(SNIFF_BYTES as u64) as usize;
            encoder.read_pending(prefix)?;
            encoder.deflate = sniff_deflate(&encoder.pending, prefix as u64 == size);
        }
        if encoder.deflate {
            match &mut encoder.compressor {
                Some(compressor) => compressor.reset(),
                None => {
                    encoder.compressor =
                        Some(Compress::new(Compression::new(DEFLATE_LEVEL), false));
                }
            }
        }
        Ok(encoder)
    }

    /// Whether the entry is deflated rather than stored.
    pub(crate) const fn deflated(&self) -> bool {
        self.deflate
    }

    /// Appends the entry's next data to `out` until it holds at least
    /// `budget` bytes or the entry is complete, and returns whether it is.
    /// Fails if the file ends early or continues past its planned size.
    pub(crate) fn fill(&mut self, out: &mut Vec<u8>, budget: usize) -> io::Result<bool> {
        if self.deflate {
            self.fill_deflated(out, budget)
        } else {
            self.fill_stored(out, budget)
        }
    }

    /// The entry's CRC-32 and data length, and the compressor for reuse.
    pub(crate) fn finish(self) -> (u32, u64, Option<Compress>) {
        (self.crc.finish(), self.written, self.compressor)
    }

    fn fill_stored(&mut self, out: &mut Vec<u8>, budget: usize) -> io::Result<bool> {
        if self.consumed < self.pending.len() {
            out.extend_from_slice(&self.pending[self.consumed..]);
            self.written += (self.pending.len() - self.consumed) as u64;
            self.consumed = self.pending.len();
        }
        while out.len() < budget && self.remaining > 0 {
            let start = out.len();
            let wanted = usize::try_from(self.remaining)
                .unwrap_or(usize::MAX)
                .min(budget - start);
            out.resize(start + wanted, 0);
            let read = self.source.read(&mut out[start..]);
            let read = match read {
                Ok(read) => read,
                Err(error) => {
                    out.truncate(start);
                    return Err(error);
                }
            };
            out.truncate(start + read);
            if read == 0 {
                return Err(entry_changed());
            }
            self.crc.update(&out[start..]);
            self.remaining -= read as u64;
            self.written += read as u64;
        }
        if self.remaining > 0 {
            return Ok(false);
        }
        self.probe_end()?;
        Ok(true)
    }

    fn fill_deflated(&mut self, out: &mut Vec<u8>, budget: usize) -> io::Result<bool> {
        while out.len() < budget {
            if self.consumed == self.pending.len() && self.remaining > 0 {
                let next = self.remaining.min(DEFLATE_INPUT_BYTES as u64) as usize;
                self.read_pending(next)?;
            }
            let finish = self.remaining == 0 && self.consumed == self.pending.len();
            if finish {
                self.probe_end()?;
            }
            let compressor = self.compressor.as_mut().ok_or_else(layout_error)?;
            let start = out.len();
            out.resize(budget, 0);
            let (read_before, written_before) = (compressor.total_in(), compressor.total_out());
            let status = compressor.compress(
                &self.pending[self.consumed..],
                &mut out[start..],
                if finish {
                    FlushCompress::Finish
                } else {
                    FlushCompress::None
                },
            );
            let used = (compressor.total_in() - read_before) as usize;
            let produced = (compressor.total_out() - written_before) as usize;
            out.truncate(start + produced);
            let status = status.map_err(io::Error::other)?;
            self.consumed += used;
            self.written += produced as u64;
            if status == Status::StreamEnd {
                return Ok(true);
            }
            if used == 0 && produced == 0 && (finish || self.consumed < self.pending.len()) {
                return Err(io::Error::other("deflate made no progress"));
            }
        }
        Ok(false)
    }

    /// Replaces the pending bytes with exactly the next `len` bytes.
    fn read_pending(&mut self, len: usize) -> io::Result<()> {
        self.pending.clear();
        self.pending.resize(len, 0);
        self.consumed = 0;
        self.source
            .read_exact(&mut self.pending)
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => entry_changed(),
                _ => error,
            })?;
        self.crc.update(&self.pending);
        self.remaining -= len as u64;
        Ok(())
    }

    /// A file that grew past its planned size has changed.
    fn probe_end(&mut self) -> io::Result<()> {
        if !self.probed {
            self.probed = true;
            if self.source.read(&mut [0])? != 0 {
                return Err(entry_changed());
            }
        }
        Ok(())
    }
}

/// CRC-32 (IEEE 802.3, as ZIP uses), computed eight bytes at a time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Crc32(u32);

const CRC_TABLES: [[u32; 256]; 8] = crc_tables();

const fn crc_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0_u32; 256]; 8];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                0xEDB8_8320 ^ (crc >> 1)
            };
            bit += 1;
        }
        tables[0][index] = crc;
        index += 1;
    }
    let mut index = 0;
    while index < 256 {
        let mut table = 1;
        while table < 8 {
            let previous = tables[table - 1][index];
            tables[table][index] = (previous >> 8) ^ tables[0][(previous & 0xFF) as usize];
            table += 1;
        }
        index += 1;
    }
    tables
}

impl Crc32 {
    pub(crate) const fn new() -> Self {
        Self(u32::MAX)
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        let table = &CRC_TABLES;
        let mut crc = self.0;
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            let low = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ crc;
            let high = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            crc = table[7][(low & 0xFF) as usize]
                ^ table[6][((low >> 8) & 0xFF) as usize]
                ^ table[5][((low >> 16) & 0xFF) as usize]
                ^ table[4][(low >> 24) as usize]
                ^ table[3][(high & 0xFF) as usize]
                ^ table[2][((high >> 8) & 0xFF) as usize]
                ^ table[1][((high >> 16) & 0xFF) as usize]
                ^ table[0][(high >> 24) as usize];
        }
        for byte in remainder {
            crc = table[0][((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
        }
        self.0 = crc;
    }

    pub(crate) const fn finish(self) -> u32 {
        !self.0
    }
}

/// MS-DOS time and date fields in UTC, clamped to the representable range.
fn dos_timestamp(modified: Option<SystemTime>) -> (u16, u16) {
    let Some(seconds) = modified.and_then(|time| time.duration_since(UNIX_EPOCH).ok()) else {
        return DOS_MIN;
    };
    let Ok(time) =
        OffsetDateTime::from_unix_timestamp(i64::try_from(seconds.as_secs()).unwrap_or(i64::MAX))
    else {
        return DOS_MAX;
    };
    match time.year() {
        ..1980 => DOS_MIN,
        2108.. => DOS_MAX,
        year => (
            (u16::from(time.hour()) << 11)
                | (u16::from(time.minute()) << 5)
                | u16::from(time.second() / 2),
            ((year - 1980) as u16) << 9
                | (u16::from(u8::from(time.month())) << 5)
                | u16::from(time.day()),
        ),
    }
}

/// The extended-timestamp modification time, when it fits the signed 32-bit
/// field that readers expect.
fn unix_mtime(modified: Option<SystemTime>) -> Option<u32> {
    let seconds = modified?.duration_since(UNIX_EPOCH).ok()?.as_secs();
    (seconds <= i32::MAX as u64).then_some(seconds as u32)
}

fn put_timestamp_extra(out: &mut Vec<u8>, mtime: Option<u32>) {
    if let Some(mtime) = mtime {
        put_u16(out, EXTENDED_TIMESTAMP_ID);
        put_u16(out, 5);
        out.push(1);
        put_u32(out, mtime);
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// An independent reader and layout checks, shared by the unit tests and the
/// `zip_archive` fuzz target.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod verify {
    use std::time::Duration;

    use flate2::{Decompress, FlushDecompress};

    use super::*;

    /// One entry as an independent reader sees it.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct ReadEntry {
        pub(crate) name: String,
        /// The compression method, `0` (stored) or `8` (deflated).
        pub(crate) method: u16,
        pub(crate) data: Option<Vec<u8>>,
    }

    pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    /// One central directory header, with ZIP64 extra fields applied.
    struct CentralRecord {
        flags: u16,
        method: u16,
        crc: u32,
        size: u64,
        compressed: u64,
        offset: u64,
        name: String,
        /// Where the next header starts.
        next: usize,
    }

    fn read_central(bytes: &[u8], at: usize) -> CentralRecord {
        assert_eq!(u32_at(bytes, at), CENTRAL_HEADER_SIGNATURE);
        let flags = u16_at(bytes, at + 8);
        assert_ne!(flags & FLAG_UTF8, 0);
        let method = u16_at(bytes, at + 10);
        assert!(
            method == METHOD_STORED || method == METHOD_DEFLATED,
            "method {method}"
        );
        let crc = u32_at(bytes, at + 16);
        let mut compressed = u64::from(u32_at(bytes, at + 20));
        let mut size = u64::from(u32_at(bytes, at + 24));
        let name_len = usize::from(u16_at(bytes, at + 28));
        let extra_len = usize::from(u16_at(bytes, at + 30));
        let mut offset = u64::from(u32_at(bytes, at + 42));
        let name = std::str::from_utf8(&bytes[at + 46..at + 46 + name_len])
            .unwrap()
            .to_owned();
        let mut extra = at + 46 + name_len;
        let extra_end = extra + extra_len;
        while extra < extra_end {
            let id = u16_at(bytes, extra);
            let len = usize::from(u16_at(bytes, extra + 2));
            if id == ZIP64_EXTRA_ID {
                // APPNOTE 4.5.3: only the overflowing fields, in this order.
                let mut field = extra + 4;
                if size == U32_SENTINEL {
                    size = u64_at(bytes, field);
                    field += 8;
                }
                if compressed == U32_SENTINEL {
                    compressed = u64_at(bytes, field);
                    field += 8;
                }
                if offset == U32_SENTINEL {
                    offset = u64_at(bytes, field);
                    field += 8;
                }
                assert_eq!(field, extra + 4 + len, "ZIP64 extra length");
            }
            extra += 4 + len;
        }
        assert_eq!(extra, extra_end);
        if method == METHOD_STORED {
            assert_eq!(compressed, size, "{name}");
        }
        CentralRecord {
            flags,
            method,
            crc,
            size,
            compressed,
            offset,
            name,
            next: extra_end,
        }
    }

    /// Inflates a raw deflate stream that must end exactly at the end of
    /// `raw` and expand to exactly `size` bytes.
    fn inflate(raw: &[u8], size: u64) -> Vec<u8> {
        let mut inflater = Decompress::new(false);
        let mut data = Vec::with_capacity(size as usize + 1);
        let status = inflater
            .decompress_vec(raw, &mut data, FlushDecompress::Finish)
            .expect("valid deflate stream");
        assert_eq!(status, Status::StreamEnd, "deflate stream ends");
        assert_eq!(inflater.total_in(), raw.len() as u64, "no bytes after it");
        assert_eq!(data.len() as u64, size, "inflated size");
        data
    }

    /// Reads an archive the way an extractor does: from the end record,
    /// through the central directory, to each local header and its data.
    /// Panics on any inconsistency between the two copies of the metadata.
    pub(crate) fn read_archive(bytes: &[u8]) -> Vec<ReadEntry> {
        let end = bytes.len() - END_LEN as usize;
        assert_eq!(u32_at(bytes, end), END_SIGNATURE);
        assert_eq!(u16_at(bytes, end + 20), 0, "no comment");
        let mut count = u64::from(u16_at(bytes, end + 10));
        let mut central_len = u64::from(u32_at(bytes, end + 12));
        let mut central_offset = u64::from(u32_at(bytes, end + 16));
        if count == U16_SENTINEL || central_len == U32_SENTINEL || central_offset == U32_SENTINEL {
            let locator = end - ZIP64_LOCATOR_LEN as usize;
            assert_eq!(u32_at(bytes, locator), ZIP64_LOCATOR_SIGNATURE);
            let zip64_end = u64_at(bytes, locator + 8) as usize;
            assert_eq!(zip64_end, locator - ZIP64_END_LEN as usize);
            assert_eq!(u32_at(bytes, zip64_end), ZIP64_END_SIGNATURE);
            count = u64_at(bytes, zip64_end + 32);
            central_len = u64_at(bytes, zip64_end + 40);
            central_offset = u64_at(bytes, zip64_end + 48);
        }
        let mut at = central_offset as usize;
        let mut entries = Vec::new();
        for _ in 0..count {
            let CentralRecord {
                flags,
                method,
                crc,
                size,
                compressed,
                offset,
                name,
                next,
            } = read_central(bytes, at);
            at = next;

            let local = offset as usize;
            assert_eq!(u32_at(bytes, local), LOCAL_HEADER_SIGNATURE);
            assert_eq!(u16_at(bytes, local + 6), flags);
            assert_eq!(u16_at(bytes, local + 8), method);
            let local_name_len = usize::from(u16_at(bytes, local + 26));
            let local_extra_len = usize::from(u16_at(bytes, local + 28));
            assert_eq!(
                &bytes[local + 30..local + 30 + local_name_len],
                name.as_bytes()
            );
            let data_start = local + 30 + local_name_len + local_extra_len;
            let zip64_local = (local + 30 + local_name_len..data_start).len() >= 20
                && u32_at(bytes, local + 18) == u32::MAX;
            let data = if name.ends_with('/') {
                assert_eq!(flags & FLAG_DATA_DESCRIPTOR, 0);
                assert_eq!(method, METHOD_STORED);
                assert_eq!(size, 0);
                None
            } else {
                assert_ne!(flags & FLAG_DATA_DESCRIPTOR, 0);
                let raw = &bytes[data_start..data_start + compressed as usize];
                let data = if method == METHOD_DEFLATED {
                    inflate(raw, size)
                } else {
                    raw.to_vec()
                };
                assert_eq!(reference_crc(&data), crc, "{name}");
                let descriptor = data_start + compressed as usize;
                assert_eq!(u32_at(bytes, descriptor), DATA_DESCRIPTOR_SIGNATURE);
                assert_eq!(u32_at(bytes, descriptor + 4), crc);
                if zip64_local {
                    assert_eq!(u64_at(bytes, descriptor + 8), compressed);
                    assert_eq!(u64_at(bytes, descriptor + 16), size);
                } else {
                    assert_eq!(u64::from(u32_at(bytes, descriptor + 8)), compressed);
                    assert_eq!(u64::from(u32_at(bytes, descriptor + 12)), size);
                }
                Some(data)
            };
            entries.push(ReadEntry { name, method, data });
        }
        assert_eq!(at as u64, central_offset + central_len);
        entries
    }

    /// Streams `contents` through a plan the way the HTTP handler does, in
    /// pieces of about `piece` bytes, or returns `None` when the sources have
    /// no valid layout.
    pub(crate) fn build_in_pieces(
        sources: Vec<ZipSource>,
        contents: &[Option<Vec<u8>>],
        compression: ArchiveCompression,
        piece: usize,
    ) -> Option<(ZipPlan, Vec<u8>)> {
        let mut plan = ZipPlan::new(sources, compression)?;
        let mut out = Vec::new();
        let mut compressor = None;
        for (index, data) in contents.iter().enumerate() {
            let Some(data) = data else {
                plan.write_local_header(index, false, &mut out);
                continue;
            };
            let mut encoder = EntryEncoder::start(
                data.as_slice(),
                data.len() as u64,
                plan.may_deflate(index),
                compressor.take(),
            )
            .expect("in-memory entry");
            plan.write_local_header(index, encoder.deflated(), &mut out);
            loop {
                let budget = out.len() + piece.max(1);
                if encoder.fill(&mut out, budget).expect("in-memory entry") {
                    break;
                }
            }
            let (crc, written, spare) = encoder.finish();
            compressor = spare;
            plan.write_data_descriptor(index, crc, written, &mut out)
                .expect("descriptor");
        }
        plan.finish_entries().expect("layout");
        for index in 0..plan.entry_count() {
            plan.write_central_header(index, &mut out);
        }
        plan.write_end(&mut out);
        Some((plan, out))
    }

    /// [`build_in_pieces`] with the HTTP handler's default chunk size.
    #[cfg(test)]
    pub(crate) fn build(
        sources: Vec<ZipSource>,
        contents: &[Option<Vec<u8>>],
        compression: ArchiveCompression,
    ) -> Option<(ZipPlan, Vec<u8>)> {
        build_in_pieces(sources, contents, compression, 64 * 1024)
    }

    /// Writes every record of a layout whose file bytes are not
    /// materialized and checks that each record has its planned length and
    /// that the central directory and end records decode to the written
    /// sizes, offsets, and counts. Every deflate candidate is taken as
    /// deflated to half its size plus a few bytes. This reaches the ZIP64
    /// branches, which real data would need gigabytes for.
    pub(crate) fn check_layout(sources: Vec<ZipSource>, compression: ArchiveCompression) {
        let Some(mut plan) = ZipPlan::new(sources, compression) else {
            return;
        };
        let fixed_len = plan.fixed_len();
        let planned_offsets: Vec<_> = plan.entries.iter().map(|entry| entry.offset).collect();
        let mut position = 0_u64;
        let mut record = Vec::new();
        for (index, planned) in planned_offsets.into_iter().enumerate() {
            if fixed_len.is_some() {
                assert_eq!(planned, position);
            }
            let deflate = plan.may_deflate(index);
            record.clear();
            plan.write_local_header(index, deflate, &mut record);
            let entry = &plan.entries[index];
            assert_eq!(entry.offset, position);
            assert_eq!(record.len() as u64, entry.local_len());
            assert_eq!(u16_at(&record, 8), entry.method_code());
            let zip64_local = u32_at(&record, 18) == u32::MAX;
            assert_eq!(zip64_local, entry.zip64_sizes());
            let size = entry.size.unwrap_or(0);
            let written = if deflate { size / 2 + 5 } else { size };
            position += record.len() as u64 + written;
            record.clear();
            plan.write_data_descriptor(index, 0x1234_5678, written, &mut record)
                .expect("descriptor");
            assert_eq!(record.len() as u64, plan.entries[index].descriptor_len());
            position += record.len() as u64;
        }
        plan.finish_entries().expect("layout");
        assert_eq!(position, plan.central_offset);

        let mut central = Vec::new();
        for index in 0..plan.entry_count() {
            plan.write_central_header(index, &mut central);
        }
        assert_eq!(central.len() as u64, plan.central_len);
        let mut at = 0;
        for entry in &plan.entries {
            let decoded = read_central(&central, at);
            assert_eq!(decoded.name, entry.name);
            assert_eq!(decoded.method, entry.method_code());
            assert_eq!(decoded.size, entry.size.unwrap_or(0));
            assert_eq!(decoded.compressed, entry.compressed);
            assert_eq!(decoded.offset, entry.offset);
            let expected_crc = if entry.size.is_some() { 0x1234_5678 } else { 0 };
            assert_eq!(decoded.crc, expected_crc);
            at = decoded.next;
        }
        assert_eq!(at, central.len());

        let mut end = Vec::new();
        plan.write_end(&mut end);
        assert_eq!(end.len() as u64, plan.end_len());
        assert_eq!(
            position + central.len() as u64 + end.len() as u64,
            plan.len()
        );
        if let Some(len) = fixed_len {
            assert_eq!(plan.len(), len);
        }
        let classic = end.len() - END_LEN as usize;
        assert_eq!(u32_at(&end, classic), END_SIGNATURE);
        let count = plan.entries.len() as u64;
        if plan.needs_zip64_end() {
            assert_eq!(u32_at(&end, 0), ZIP64_END_SIGNATURE);
            assert_eq!(u64_at(&end, 24), count);
            assert_eq!(u64_at(&end, 32), count);
            assert_eq!(u64_at(&end, 40), plan.central_len);
            assert_eq!(u64_at(&end, 48), plan.central_offset);
            let locator = ZIP64_END_LEN as usize;
            assert_eq!(u32_at(&end, locator), ZIP64_LOCATOR_SIGNATURE);
            assert_eq!(
                u64_at(&end, locator + 8),
                plan.central_offset + plan.central_len
            );
        } else {
            assert_eq!(u64::from(u16_at(&end, classic + 10)), count);
            assert_eq!(u64::from(u32_at(&end, classic + 12)), plan.central_len);
            assert_eq!(u64::from(u32_at(&end, classic + 16)), plan.central_offset);
        }
    }

    /// Decodes fuzzer bytes into archive entries. The first byte selects a
    /// round trip with real file bytes or a layout check with arbitrary
    /// declared sizes (bit 0), automatic compression or none (bit 1), and
    /// the size of the pieces a round trip streams in (bits 2–7); each entry
    /// then reads a control byte, a name, an optional modification time,
    /// and its size or bytes. Control bit 2 repeats a file's bytes 16 times,
    /// so files reach the deflate threshold.
    pub(crate) fn fuzz(data: &[u8]) {
        let mut input = Input(data);
        let Some(mode) = input.byte() else {
            return;
        };
        let round_trip = mode & 1 == 0;
        let compression = if mode & 2 == 0 {
            ArchiveCompression::Off
        } else {
            ArchiveCompression::Auto
        };
        let piece = (usize::from(mode >> 2) + 1) * 256;
        let mut sources = Vec::new();
        let mut contents = Vec::new();
        while sources.len() < 64 {
            let Some(control) = input.byte() else {
                break;
            };
            let Some(name) = input
                .take(usize::from(control >> 3) + 1)
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            else {
                break;
            };
            let modified = if control & 2 == 0 {
                None
            } else {
                let Some(seconds) = input.take(5) else {
                    break;
                };
                let mut wide = [0_u8; 8];
                wide[..5].copy_from_slice(seconds);
                UNIX_EPOCH.checked_add(Duration::from_secs(u64::from_le_bytes(wide)))
            };
            let directory = control & 1 == 1;
            let (size, bytes) = if directory {
                (None, None)
            } else if round_trip {
                let Some(len) = input.byte() else {
                    break;
                };
                let Some(bytes) = input.take(usize::from(len)) else {
                    break;
                };
                let bytes = if control & 4 == 0 {
                    bytes.to_vec()
                } else {
                    bytes.repeat(16)
                };
                (Some(bytes.len() as u64), Some(bytes))
            } else {
                let Some(size) = input.take(8) else {
                    break;
                };
                (Some(u64_at(size, 0)), None)
            };
            sources.push(ZipSource {
                name,
                size,
                modified,
            });
            contents.push(bytes);
        }

        if !round_trip {
            check_layout(sources, compression);
            return;
        }
        let expected: Vec<_> = sources
            .iter()
            .zip(&contents)
            .map(|(source, data)| {
                let name = if data.is_some() {
                    source.name.clone()
                } else {
                    format!("{}/", source.name)
                };
                (name, data.clone())
            })
            .collect();
        check_layout(sources.clone(), compression);
        let candidates: Vec<_> = sources
            .iter()
            .map(|source| {
                compression == ArchiveCompression::Auto
                    && source
                        .size
                        .is_some_and(|size| may_deflate(&source.name, size))
            })
            .collect();
        let Some((plan, bytes)) = build_in_pieces(sources, &contents, compression, piece) else {
            return;
        };
        assert_eq!(plan.len(), bytes.len() as u64);
        let read = read_archive(&bytes);
        for ((entry, candidate), data) in read.iter().zip(&candidates).zip(&contents) {
            let deflated = entry.method == METHOD_DEFLATED;
            assert_eq!(
                deflated,
                *candidate
                    && data.as_ref().is_some_and(|data| {
                        let prefix = &data[..data.len().min(SNIFF_BYTES)];
                        sniff_deflate(prefix, prefix.len() == data.len())
                    }),
                "{}",
                entry.name
            );
        }
        let read: Vec<_> = read
            .into_iter()
            .map(|entry| (entry.name, entry.data))
            .collect();
        assert_eq!(read, expected);
    }

    struct Input<'data>(&'data [u8]);

    impl<'data> Input<'data> {
        fn byte(&mut self) -> Option<u8> {
            self.take(1).map(|bytes| bytes[0])
        }

        fn take(&mut self, len: usize) -> Option<&'data [u8]> {
            if self.0.len() < len {
                return None;
            }
            let (taken, rest) = self.0.split_at(len);
            self.0 = rest;
            Some(taken)
        }
    }

    pub(crate) fn reference_crc(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    0xEDB8_8320 ^ (crc >> 1)
                };
            }
        }
        !crc
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use proptest::prelude::*;

    use super::{verify::*, *};

    #[test]
    fn crc_matches_the_standard_check_value() {
        let mut crc = Crc32::new();
        crc.update(b"123456789");
        assert_eq!(crc.finish(), 0xCBF4_3926);
        assert_eq!(Crc32::new().finish(), 0);
    }

    #[test]
    fn archive_round_trips_with_the_planned_length() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let sources = vec![
            ZipSource {
                name: "Photos".into(),
                size: None,
                modified: Some(modified),
            },
            ZipSource {
                name: "Photos/été.txt".into(),
                size: Some(5),
                modified: Some(modified),
            },
            ZipSource {
                name: "Photos/empty".into(),
                size: Some(0),
                modified: None,
            },
        ];
        let contents = [None, Some(b"hello".to_vec()), Some(Vec::new())];
        let (plan, bytes) = build(sources, &contents, ArchiveCompression::Off).expect("layout");
        assert_eq!(plan.len(), bytes.len() as u64);
        assert_eq!(
            read_archive(&bytes),
            vec![
                ReadEntry {
                    name: "Photos/".into(),
                    method: METHOD_STORED,
                    data: None,
                },
                ReadEntry {
                    name: "Photos/été.txt".into(),
                    method: METHOD_STORED,
                    data: Some(b"hello".to_vec()),
                },
                ReadEntry {
                    name: "Photos/empty".into(),
                    method: METHOD_STORED,
                    data: Some(Vec::new()),
                },
            ]
        );
    }

    #[test]
    fn layout_rejects_names_a_reader_could_misread() {
        for name in ["", "dir/", &"a".repeat(65_536)] {
            let source = ZipSource {
                name: name.to_owned(),
                size: Some(0),
                modified: None,
            };
            assert!(
                ZipPlan::new(vec![source], ArchiveCompression::Off).is_none(),
                "{name:.16}"
            );
        }
    }

    #[test]
    fn layout_uses_zip64_only_past_the_classic_fields() {
        let file = |name: &str, size| ZipSource {
            name: name.into(),
            size: Some(size),
            modified: None,
        };
        // A file that leaves room for every header below 4 GiB.
        let small = ZipPlan::new(
            vec![file("a", U32_SENTINEL - 1_000)],
            ArchiveCompression::Off,
        )
        .expect("layout");
        assert!(!small.entries[0].zip64_sizes());
        assert!(!small.needs_zip64_end());
        // One byte short of the sentinel still fits the size fields, but the
        // central directory then starts past them.
        let edge = ZipPlan::new(vec![file("a", U32_SENTINEL - 1)], ArchiveCompression::Off)
            .expect("layout");
        assert!(!edge.entries[0].zip64_sizes());
        assert!(edge.needs_zip64_end());

        // A file of exactly 0xFFFFFFFF bytes cannot use the sentinel value.
        let mut plan = ZipPlan::new(
            vec![file("big", U32_SENTINEL), file("after", 1)],
            ArchiveCompression::Off,
        )
        .expect("layout");
        assert!(plan.entries[0].zip64_sizes());
        assert!(!plan.entries[0].zip64_offset());
        assert!(!plan.entries[1].zip64_sizes());
        assert!(plan.entries[1].zip64_offset());
        assert!(plan.needs_zip64_end());
        let mut header = Vec::new();
        plan.write_local_header(0, false, &mut header);
        assert_eq!(header.len() as u64, plan.entries[0].local_len());
        assert_eq!(u16_at(&header, 4), VERSION_ZIP64);
        let mut central = Vec::new();
        plan.write_central_header(1, &mut central);
        assert_eq!(central.len() as u64, plan.entries[1].central_len());
        assert_eq!(u32_at(&central, 42), u32::MAX);
        assert_eq!(
            u64_at(&central, central.len() - 8),
            plan.entries[1].offset,
            "the ZIP64 extra carries the real offset"
        );
        let mut end = Vec::new();
        plan.write_end(&mut end);
        assert_eq!(end.len() as u64, plan.end_len());

        assert!(ZipPlan::new(vec![file("a", u64::MAX)], ArchiveCompression::Off).is_none());
    }

    #[test]
    fn many_entries_switch_to_a_zip64_end_record() {
        let sources: Vec<_> = (0..U16_SENTINEL)
            .map(|index| ZipSource {
                name: format!("{index}"),
                size: Some(0),
                modified: None,
            })
            .collect();
        let contents = vec![Some(Vec::new()); sources.len()];
        let (plan, bytes) = build(sources, &contents, ArchiveCompression::Off).expect("layout");
        assert!(plan.needs_zip64_end());
        assert_eq!(plan.len(), bytes.len() as u64);
        assert_eq!(read_archive(&bytes).len() as u64, U16_SENTINEL);
    }

    #[test]
    fn timestamps_clamp_to_the_dos_range() {
        assert_eq!(dos_timestamp(None), DOS_MIN);
        assert_eq!(dos_timestamp(Some(UNIX_EPOCH)), DOS_MIN);
        let far = UNIX_EPOCH + Duration::from_secs(5_000_000_000);
        assert_eq!(dos_timestamp(Some(far)), DOS_MAX);
        assert_eq!(unix_mtime(Some(far)), None);
        // 2024-02-29 13:45:31 UTC
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_214_331);
        assert_eq!(
            dos_timestamp(Some(leap)),
            ((13 << 11) | (45 << 5) | 15, (44 << 9) | (2 << 5) | 29)
        );
        assert_eq!(unix_mtime(Some(leap)), Some(1_709_214_331));
    }

    #[test]
    fn zip64_layouts_decode_to_their_planned_values() {
        let file = |name: &str, size| ZipSource {
            name: name.into(),
            size: Some(size),
            modified: None,
        };
        let sources = vec![
            file("a", U32_SENTINEL - 1),
            file("big", U32_SENTINEL),
            ZipSource {
                name: "dir".into(),
                size: None,
                modified: Some(UNIX_EPOCH + Duration::from_secs(1)),
            },
            file("after", u64::from(u32::MAX) * 3),
            file("movie.mp4", u64::from(u32::MAX) * 2),
        ];
        check_layout(sources.clone(), ArchiveCompression::Off);
        // The same names, every one but the video a deflate candidate.
        check_layout(sources, ArchiveCompression::Auto);
    }

    #[test]
    fn deflated_entries_switch_to_zip64_before_they_could_overflow() {
        assert!(!deflated_may_overflow(0));
        assert!(!deflated_may_overflow(3_000_000_000));
        assert!(deflated_may_overflow(U32_SENTINEL - 1_000));
        assert!(deflated_may_overflow(u64::MAX));
        let file = |name: &str, size| ZipSource {
            name: name.into(),
            size: Some(size),
            modified: None,
        };
        // A candidate below the stored threshold already reserves ZIP64
        // sizes, in its local header and its data descriptor, and keeps them
        // whichever way it is settled.
        let sources = vec![
            file("server.log", U32_SENTINEL - 1_000),
            file("notes.txt", 5_000),
        ];
        let mut plan = ZipPlan::new(sources.clone(), ArchiveCompression::Auto).expect("layout");
        assert!(plan.may_deflate(0));
        assert!(plan.entries[0].zip64_sizes());
        assert!(plan.fixed_len().is_none());
        let mut header = Vec::new();
        plan.write_local_header(0, true, &mut header);
        assert_eq!(u16_at(&header, 4), VERSION_ZIP64);
        assert_eq!(u16_at(&header, 8), METHOD_DEFLATED);
        assert_eq!(u32_at(&header, 18), u32::MAX);
        let mut descriptor = Vec::new();
        plan.write_data_descriptor(0, 1, 70_000_000, &mut descriptor)
            .expect("descriptor");
        assert_eq!(descriptor.len() as u64, ZIP64_DATA_DESCRIPTOR_LEN);
        assert_eq!(u64_at(&descriptor, 8), 70_000_000, "compressed first");
        assert_eq!(u64_at(&descriptor, 16), U32_SENTINEL - 1_000);
        // Without ZIP64 sizes, a compressed size past the classic field is
        // refused rather than truncated.
        plan.write_local_header(1, true, &mut header);
        assert!(!plan.entries[1].zip64_sizes());
        assert!(
            plan.write_data_descriptor(1, 1, U32_SENTINEL, &mut descriptor)
                .is_err()
        );
        // A stored entry must have exactly its planned size.
        let mut stored = ZipPlan::new(sources, ArchiveCompression::Off).expect("layout");
        stored.write_local_header(0, true, &mut header);
        assert!(!stored.entries[0].zip64_sizes(), "stays stored");
        assert!(
            stored
                .write_data_descriptor(0, 1, 70_000_000, &mut descriptor)
                .is_err()
        );
    }

    #[test]
    fn fuzz_seeds_cover_both_modes() {
        // Round trip: a directory "d" then a three-byte file "d/f".
        fuzz(&[
            0,
            0b0000_0001,
            b'd',
            0b0001_0000,
            b'd',
            b'/',
            b'f',
            3,
            1,
            2,
            3,
        ]);
        // Layout: one file declared just past the classic size field.
        let mut layout = vec![1, 0, b'x'];
        layout.extend_from_slice(&U32_SENTINEL.to_le_bytes());
        fuzz(&layout);
        // Automatic compression: a 1,600-byte text file "t" (100 bytes
        // repeated 16 times) is deflated, in 256-byte pieces.
        let mut text = vec![0b10, 0b0000_0100, b't', 100];
        text.extend(b"line of text\n".iter().cycle().take(100));
        fuzz(&text);
        // The same declared layout, as a deflate candidate.
        let mut layout = vec![0b11, 0, b'x'];
        layout.extend_from_slice(&(U32_SENTINEL - 1).to_le_bytes());
        fuzz(&layout);
    }

    #[test]
    fn deflate_candidates_are_chosen_by_size_and_name() {
        assert!(may_deflate("notes.txt", MIN_DEFLATE_BYTES));
        assert!(!may_deflate("notes.txt", MIN_DEFLATE_BYTES - 1));
        assert!(may_deflate("Makefile", 4_096));
        assert!(may_deflate("archive.tar", 4_096), "tar is not compressed");
        assert!(may_deflate("data.sqlite3", 4_096));
        for name in [
            "IMG_0001.JPG",
            "a/b/photo.jpeg",
            "scan.heic",
            "raw/DSC_1.NEF",
            "clip.MOV",
            "song.flac",
            "report.docx",
            "book.epub",
            "backup.tar.gz",
            "dump.zst",
            "paper.pdf",
            "font.woff2",
        ] {
            assert!(!may_deflate(name, 1 << 20), "{name}");
        }
        // Only the file's own name counts.
        assert!(may_deflate("photos.jpg/readme", 4_096));
        assert!(may_deflate("jpg", 4_096));
    }

    #[test]
    fn deflate_is_chosen_for_text_from_the_first_bytes() {
        let text = b"fn main() {\n    println!(\"hello\");\n}\n".repeat(50);
        assert!(sniff_deflate(&text, true));
        assert!(sniff_deflate(
            "Grüße, été, 東京\n".repeat(100).as_bytes(),
            true
        ));
        // A multibyte character cut by the sniff bound is tolerated.
        let cut = "é".repeat(SNIFF_BYTES / 2 + 1);
        let prefix = &cut.as_bytes()[..SNIFF_BYTES - 1];
        assert!(sniff_deflate(prefix, false));
        assert!(!sniff_deflate(prefix, true), "a truncated whole file");
        // Latin-1 text is not UTF-8 but mostly printable ASCII.
        let mut latin1 =
            b"The caf\xe9 on the corner serves cr\xe8me br\xfbl\xe9e every day of the week. "
                .repeat(20);
        assert!(sniff_deflate(&latin1, true));
        latin1[17] = 0;
        assert!(!sniff_deflate(&latin1, true), "a NUL byte");

        let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0];
        jpeg.extend(b"plain looking padding ".repeat(80));
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x10\0\0\0\x10".to_vec();
        png.extend(b"padding ".repeat(200));
        let mut gzip = vec![0x1f, 0x8b, 8, 0];
        gzip.extend(b"text-like payload ".repeat(80));
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(b"[Content_Types].xml ".repeat(80));
        let mut pdf = b"%PDF-1.4\n".to_vec();
        pdf.extend(b"1 0 obj << /Type /Catalog >> endobj\n".repeat(60));
        let mut id3 = b"ID3\x04\0\0\0\0\x01\0".to_vec();
        id3.extend(b"TIT2 title text ".repeat(80));
        let mut woff2 = b"wOF2".to_vec();
        woff2.extend(b"font table ".repeat(120));
        for (label, bytes) in [
            ("jpeg", jpeg),
            ("png", png),
            ("gzip", gzip),
            ("zip", zip),
            ("pdf", pdf),
            ("mp3", id3),
            ("woff2", woff2),
        ] {
            assert!(preview::has_compressed_signature(&bytes), "{label}");
            assert!(!sniff_deflate(&bytes, true), "{label}");
        }
        let binary: Vec<u8> = (0..4_096_u32)
            .map(|value| (value * 7919 % 251) as u8)
            .collect();
        assert!(!sniff_deflate(&binary, true));
    }

    /// Bytes that never read as text and do not compress.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn mixed_archives_deflate_only_text_and_read_back() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let text = b"2026-10-05T12:00:00Z INFO request served in 3 ms\n".repeat(400);
        let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0];
        jpeg.extend(noise(6_000, 1));
        let entries: Vec<(&str, Option<Vec<u8>>)> = vec![
            ("Mixed", None),
            ("Mixed/server.log", Some(text.clone())),
            ("Mixed/photo.jpg", Some(jpeg.clone())),
            ("Mixed/photo-without-extension", Some(jpeg.clone())),
            ("Mixed/blob.bin", Some(noise(5_000, 2))),
            ("Mixed/short.txt", Some(b"short text\n".to_vec())),
            ("Mixed/empty", Some(Vec::new())),
            (
                "Mixed/again.md",
                Some(b"# Heading\n\nSome *Markdown*.\n".repeat(200)),
            ),
        ];
        let sources: Vec<_> = entries
            .iter()
            .map(|(name, data)| ZipSource {
                name: (*name).into(),
                size: data.as_ref().map(|data| data.len() as u64),
                modified: Some(modified),
            })
            .collect();
        let contents: Vec<_> = entries.iter().map(|(_, data)| data.clone()).collect();

        let plan = ZipPlan::new(sources.clone(), ArchiveCompression::Auto).expect("layout");
        assert!(plan.fixed_len().is_none(), "text candidates");
        let candidates: Vec<_> = (0..plan.entry_count())
            .map(|index| plan.may_deflate(index))
            .collect();
        assert_eq!(
            candidates,
            [false, true, false, true, true, false, false, true]
        );

        let (plan, bytes) =
            build(sources.clone(), &contents, ArchiveCompression::Auto).expect("layout");
        assert_eq!(plan.len(), bytes.len() as u64);
        let read = read_archive(&bytes);
        let methods: Vec<_> = read.iter().map(|entry| entry.method).collect();
        assert_eq!(
            methods,
            [
                METHOD_STORED,
                METHOD_DEFLATED,
                METHOD_STORED,
                METHOD_STORED,
                METHOD_STORED,
                METHOD_STORED,
                METHOD_STORED,
                METHOD_DEFLATED,
            ]
        );
        for ((entry, (name, data)), source) in read.iter().zip(&entries).zip(&sources) {
            let expected_name = if data.is_some() {
                source.name.clone()
            } else {
                format!("{name}/")
            };
            assert_eq!(entry.name, expected_name);
            assert_eq!(&entry.data, data, "{name}");
        }
        let (_, stored) = build(sources, &contents, ArchiveCompression::Off).expect("layout");
        assert!(
            bytes.len() + text.len() / 2 < stored.len(),
            "{} deflated against {} stored",
            bytes.len(),
            stored.len()
        );

        // Streaming in small pieces produces the same bytes.
        let pieces = entries
            .iter()
            .map(|(name, data)| ZipSource {
                name: (*name).into(),
                size: data.as_ref().map(|data| data.len() as u64),
                modified: Some(modified),
            })
            .collect();
        let (_, in_pieces) =
            build_in_pieces(pieces, &contents, ArchiveCompression::Auto, 7).expect("layout");
        assert_eq!(in_pieces, bytes);
    }

    #[test]
    fn off_and_media_only_archives_are_byte_for_byte_store_only() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let text: Vec<u8> = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
            .iter()
            .copied()
            .cycle()
            .take(2_000)
            .collect();
        let golden = |compression, text_name: &str| {
            let sources = vec![
                ZipSource {
                    name: "Mixed".into(),
                    size: None,
                    modified: Some(modified),
                },
                ZipSource {
                    name: format!("Mixed/{text_name}"),
                    size: Some(text.len() as u64),
                    modified: Some(modified),
                },
                ZipSource {
                    name: "Mixed/tiny".into(),
                    size: Some(5),
                    modified: None,
                },
            ];
            let contents = [None, Some(text.clone()), Some(b"hello".to_vec())];
            let (plan, bytes) = build(sources, &contents, compression).expect("layout");
            assert_eq!(plan.len(), bytes.len() as u64);
            (plan.fixed_len(), bytes)
        };
        // The length and CRC-32 of this archive as the store-only writer
        // produced it before compression existed.
        let (fixed, off) = golden(ArchiveCompression::Off, "notes.txt");
        assert_eq!(fixed, Some(2_385));
        assert_eq!(off.len(), 2_385);
        assert_eq!(reference_crc(&off), 0xD5BA_1D16);

        // With automatic compression, the text file deflates and the length
        // is no longer planned.
        let (fixed, auto) = golden(ArchiveCompression::Auto, "notes.txt");
        assert_eq!(fixed, None);
        assert!(auto.len() < off.len());

        // A name that rules compression out keeps the stored bytes.
        let (fixed, media) = golden(ArchiveCompression::Auto, "notes.pdf");
        let (_, media_off) = golden(ArchiveCompression::Off, "notes.pdf");
        assert_eq!(fixed, Some(media.len() as u64));
        assert_eq!(media, media_off);
    }

    #[test]
    fn encoders_refuse_files_that_changed_size() {
        fn drain(mut encoder: EntryEncoder<&[u8]>) -> io::Result<()> {
            let mut out = Vec::new();
            loop {
                let budget = out.len() + 512;
                if encoder.fill(&mut out, budget)? {
                    return Ok(());
                }
            }
        }
        let text = b"a line of text\n".repeat(200);
        for candidate in [false, true] {
            // Shorter than planned.
            let short = &text[..text.len() - 10];
            let result =
                EntryEncoder::start(short, text.len() as u64, candidate, None).and_then(drain);
            assert!(result.is_err(), "short, candidate {candidate}");
            // Longer than planned.
            let encoder =
                EntryEncoder::start(text.as_slice(), text.len() as u64 - 10, candidate, None)
                    .expect("start");
            assert_eq!(encoder.deflated(), candidate);
            assert!(drain(encoder).is_err(), "long, candidate {candidate}");
        }
        // A file shorter than its sniffed prefix fails before its header.
        assert!(EntryEncoder::start(&text[..100], 2_000, true, None).is_err());
    }

    proptest! {
        #[test]
        fn fuzz_entry_point_holds_for_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz(&bytes);
        }

        #[test]
        fn crc_matches_a_bitwise_reference(bytes in proptest::collection::vec(any::<u8>(), 0..256), split in 0_usize..256) {
            let split = split.min(bytes.len());
            let mut crc = Crc32::new();
            crc.update(&bytes[..split]);
            crc.update(&bytes[split..]);
            prop_assert_eq!(crc.finish(), reference_crc(&bytes));
        }

        #[test]
        fn any_layout_round_trips(
            files in proptest::collection::vec(
                (proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)), any::<u32>()),
                0..12,
            ),
            auto in any::<bool>(),
        ) {
            let compression = if auto { ArchiveCompression::Auto } else { ArchiveCompression::Off };
            let sources = files
                .iter()
                .enumerate()
                .map(|(index, (data, seconds))| ZipSource {
                    name: format!("root/{index}-ä"),
                    size: data.as_ref().map(|data| data.len() as u64),
                    modified: Some(UNIX_EPOCH + Duration::from_secs(u64::from(*seconds))),
                })
                .collect();
            let contents: Vec<_> = files.iter().map(|(data, _)| data.clone()).collect();
            let (plan, bytes) = build(sources, &contents, compression).expect("layout");
            prop_assert_eq!(plan.len(), bytes.len() as u64);
            let read = read_archive(&bytes);
            prop_assert_eq!(read.len(), contents.len());
            for (entry, data) in read.iter().zip(&contents) {
                prop_assert_eq!(&entry.data, data);
            }
        }

        #[test]
        fn text_round_trips_deflated_in_any_pieces(
            lines in proptest::collection::vec("[ -~]{0,80}", 20..400),
            piece in 1_usize..20_000,
        ) {
            let text = lines.join("\n").into_bytes();
            let sources = vec![ZipSource {
                name: "notes.txt".into(),
                size: Some(text.len() as u64),
                modified: None,
            }];
            let contents = [Some(text.clone())];
            let (plan, bytes) =
                build_in_pieces(sources, &contents, ArchiveCompression::Auto, piece).expect("layout");
            prop_assert_eq!(plan.len(), bytes.len() as u64);
            let read = read_archive(&bytes);
            let expected = if text.len() as u64 >= MIN_DEFLATE_BYTES {
                METHOD_DEFLATED
            } else {
                METHOD_STORED
            };
            prop_assert_eq!(read[0].method, expected);
            prop_assert_eq!(read[0].data.as_deref(), Some(text.as_slice()));
        }
    }
}

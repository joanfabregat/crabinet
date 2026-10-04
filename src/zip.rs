//! A store-only ZIP writer for streamed folder downloads.
//!
//! The archive layout is fixed before the first byte is sent: each entry's
//! size comes from the folder walk, so every header offset and the total
//! length are known up front and the response can carry `Content-Length`.
//! Entries are stored without compression. A file's CRC-32 is computed while
//! its bytes stream, written in a data descriptor after them, and repeated
//! in the central directory. ZIP64 fields appear only for the entries,
//! offsets, and counts that overflow the classic 32-bit and 16-bit fields.

use std::time::{SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;

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

/// One entry to archive. `name` is relative to the archive root, uses `/`
/// separators, and has no trailing slash; directories gain one.
#[derive(Clone, Debug)]
pub(crate) struct ZipSource {
    pub(crate) name: String,
    /// `None` for a directory.
    pub(crate) size: Option<u64>,
    pub(crate) modified: Option<SystemTime>,
}

#[derive(Debug)]
struct ZipEntry {
    name: String,
    size: Option<u64>,
    dos_time: u16,
    dos_date: u16,
    unix_mtime: Option<u32>,
    offset: u64,
    crc: u32,
}

impl ZipEntry {
    fn zip64_sizes(&self) -> bool {
        self.size.is_some_and(|size| size >= U32_SENTINEL)
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

/// The complete byte layout of one archive.
#[derive(Debug)]
pub(crate) struct ZipPlan {
    entries: Vec<ZipEntry>,
    central_offset: u64,
    central_len: u64,
    len: u64,
}

impl ZipPlan {
    /// Lays out `sources` in order. Returns `None` for an empty or
    /// over-long name, or a layout whose length overflows `u64`.
    pub(crate) fn new(sources: Vec<ZipSource>) -> Option<Self> {
        let mut entries = Vec::with_capacity(sources.len());
        let mut offset = 0_u64;
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
            let (dos_time, dos_date) = dos_timestamp(source.modified);
            let entry = ZipEntry {
                name,
                size: source.size,
                dos_time,
                dos_date,
                unix_mtime: unix_mtime(source.modified),
                offset,
                crc: 0,
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
            central_offset,
            central_len,
            len: 0,
        };
        plan.len = central_offset
            .checked_add(central_len)?
            .checked_add(plan.end_len())?;
        Some(plan)
    }

    /// The exact number of bytes the archive occupies.
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

    pub(crate) fn write_local_header(&self, index: usize, out: &mut Vec<u8>) {
        let entry = &self.entries[index];
        let size_field = if entry.zip64_sizes() { u32::MAX } else { 0 };
        put_u32(out, LOCAL_HEADER_SIGNATURE);
        put_u16(out, entry.version());
        put_u16(out, entry.flags());
        put_u16(out, 0);
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
    }

    /// Records the CRC of file entry `index` and writes its data descriptor.
    pub(crate) fn write_data_descriptor(&mut self, index: usize, crc: u32, out: &mut Vec<u8>) {
        let entry = &mut self.entries[index];
        let Some(size) = entry.size else {
            return;
        };
        entry.crc = crc;
        put_u32(out, DATA_DESCRIPTOR_SIGNATURE);
        put_u32(out, crc);
        if entry.zip64_sizes() {
            put_u64(out, size);
            put_u64(out, size);
        } else {
            put_u32(out, size as u32);
            put_u32(out, size as u32);
        }
    }

    pub(crate) fn write_central_header(&self, index: usize, out: &mut Vec<u8>) {
        let entry = &self.entries[index];
        let size = entry.size.unwrap_or(0);
        let size_field = if entry.zip64_sizes() {
            u32::MAX
        } else {
            size as u32
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
        put_u16(out, 0);
        put_u16(out, entry.dos_time);
        put_u16(out, entry.dos_date);
        put_u32(out, entry.crc);
        put_u32(out, size_field);
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
                put_u64(out, size);
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

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use proptest::prelude::*;

    use super::*;

    /// One entry as an independent reader sees it.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct ReadEntry {
        pub(crate) name: String,
        pub(crate) data: Option<Vec<u8>>,
    }

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
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
            assert_eq!(u32_at(bytes, at), CENTRAL_HEADER_SIGNATURE);
            let flags = u16_at(bytes, at + 8);
            assert_ne!(flags & FLAG_UTF8, 0);
            assert_eq!(u16_at(bytes, at + 10), 0, "stored");
            let crc = u32_at(bytes, at + 16);
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
                    let mut field = extra + 4;
                    if size == U32_SENTINEL {
                        size = u64_at(bytes, field);
                        assert_eq!(u64_at(bytes, field + 8), size);
                        field += 16;
                    }
                    if offset == U32_SENTINEL {
                        offset = u64_at(bytes, field);
                    }
                }
                extra += 4 + len;
            }
            assert_eq!(extra, extra_end);
            at = extra_end;

            let local = offset as usize;
            assert_eq!(u32_at(bytes, local), LOCAL_HEADER_SIGNATURE);
            assert_eq!(u16_at(bytes, local + 6), flags);
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
                assert_eq!(size, 0);
                None
            } else {
                assert_ne!(flags & FLAG_DATA_DESCRIPTOR, 0);
                let data = &bytes[data_start..data_start + size as usize];
                let mut computed = Crc32::new();
                computed.update(data);
                assert_eq!(computed.finish(), crc, "{name}");
                let descriptor = data_start + size as usize;
                assert_eq!(u32_at(bytes, descriptor), DATA_DESCRIPTOR_SIGNATURE);
                assert_eq!(u32_at(bytes, descriptor + 4), crc);
                if zip64_local {
                    assert_eq!(u64_at(bytes, descriptor + 8), size);
                    assert_eq!(u64_at(bytes, descriptor + 16), size);
                } else {
                    assert_eq!(u64::from(u32_at(bytes, descriptor + 8)), size);
                    assert_eq!(u64::from(u32_at(bytes, descriptor + 12)), size);
                }
                Some(data.to_vec())
            };
            entries.push(ReadEntry { name, data });
        }
        assert_eq!(at as u64, central_offset + central_len);
        entries
    }

    /// Streams `contents` through a plan the way the HTTP handler does.
    fn build(sources: Vec<ZipSource>, contents: &[Option<Vec<u8>>]) -> (ZipPlan, Vec<u8>) {
        let mut plan = ZipPlan::new(sources).expect("layout");
        let mut out = Vec::new();
        for (index, data) in contents.iter().enumerate() {
            plan.write_local_header(index, &mut out);
            if let Some(data) = data {
                out.extend_from_slice(data);
                let mut crc = Crc32::new();
                crc.update(data);
                plan.write_data_descriptor(index, crc.finish(), &mut out);
            }
        }
        for index in 0..plan.entry_count() {
            plan.write_central_header(index, &mut out);
        }
        plan.write_end(&mut out);
        (plan, out)
    }

    fn reference_crc(bytes: &[u8]) -> u32 {
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
        let (plan, bytes) = build(sources, &contents);
        assert_eq!(plan.len(), bytes.len() as u64);
        assert_eq!(
            read_archive(&bytes),
            vec![
                ReadEntry {
                    name: "Photos/".into(),
                    data: None,
                },
                ReadEntry {
                    name: "Photos/été.txt".into(),
                    data: Some(b"hello".to_vec()),
                },
                ReadEntry {
                    name: "Photos/empty".into(),
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
            assert!(ZipPlan::new(vec![source]).is_none(), "{name:.16}");
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
        let small = ZipPlan::new(vec![file("a", U32_SENTINEL - 1_000)]).expect("layout");
        assert!(!small.entries[0].zip64_sizes());
        assert!(!small.needs_zip64_end());
        // One byte short of the sentinel still fits the size fields, but the
        // central directory then starts past them.
        let edge = ZipPlan::new(vec![file("a", U32_SENTINEL - 1)]).expect("layout");
        assert!(!edge.entries[0].zip64_sizes());
        assert!(edge.needs_zip64_end());

        // A file of exactly 0xFFFFFFFF bytes cannot use the sentinel value.
        let plan = ZipPlan::new(vec![file("big", U32_SENTINEL), file("after", 1)]).expect("layout");
        assert!(plan.entries[0].zip64_sizes());
        assert!(!plan.entries[0].zip64_offset());
        assert!(!plan.entries[1].zip64_sizes());
        assert!(plan.entries[1].zip64_offset());
        assert!(plan.needs_zip64_end());
        let mut header = Vec::new();
        plan.write_local_header(0, &mut header);
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

        assert!(ZipPlan::new(vec![file("a", u64::MAX)]).is_none());
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
        let (plan, bytes) = build(sources, &contents);
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

    proptest! {
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
            )
        ) {
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
            let (plan, bytes) = build(sources, &contents);
            prop_assert_eq!(plan.len(), bytes.len() as u64);
            let read = read_archive(&bytes);
            prop_assert_eq!(read.len(), contents.len());
            for (entry, data) in read.iter().zip(&contents) {
                prop_assert_eq!(&entry.data, data);
            }
        }
    }
}

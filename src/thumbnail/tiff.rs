//! A small, bounded TIFF structure walker.
//!
//! It serves two purposes: finding the JPEG previews that TIFF-based RAW
//! containers (DNG, NEF, ARW, CR2, PEF, ORF) embed, and reading the EXIF
//! orientation tag. It never decodes image data. Every bound is explicit: at
//! most [`MAX_IFDS`] directories are visited, each offset at most once (so a
//! cyclic chain ends), directories nest at most [`MAX_DEPTH`] levels, a
//! directory has at most [`MAX_ENTRIES`] entries, and every offset and length
//! must lie inside the input before anything is read.

use std::io::{Read, Seek, SeekFrom};

/// Directories visited across the whole file, including chained ones.
pub(crate) const MAX_IFDS: usize = 32;
/// Entries one directory may declare; real files use a few dozen.
const MAX_ENTRIES: u16 = 512;
/// SubIFD and EXIF pointers followed below IFD0.
const MAX_DEPTH: usize = 4;
/// Child directories taken from one SubIFDs tag.
const MAX_SUB_IFDS: usize = 8;
/// Preview candidates kept from one file.
pub(crate) const MAX_CANDIDATES: usize = 16;

const TAG_COMPRESSION: u16 = 0x0103;
const TAG_PHOTOMETRIC: u16 = 0x0106;
const TAG_STRIP_OFFSETS: u16 = 0x0111;
const TAG_ORIENTATION: u16 = 0x0112;
const TAG_STRIP_BYTE_COUNTS: u16 = 0x0117;
const TAG_SUB_IFDS: u16 = 0x014a;
const TAG_JPEG_OFFSET: u16 = 0x0201;
const TAG_JPEG_LENGTH: u16 = 0x0202;
const TAG_EXIF_IFD: u16 = 0x8769;

const TYPE_SHORT: u16 = 3;
const TYPE_LONG: u16 = 4;
const TYPE_IFD: u16 = 13;

/// Raw sensor data, never a displayable preview.
const PHOTOMETRIC_CFA: u32 = 32803;
const PHOTOMETRIC_LINEAR_RAW: u32 = 34892;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endian {
    Little,
    Big,
}

/// A byte range that may hold an embedded JPEG stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub offset: u64,
    pub length: u64,
}

/// What a walk found: IFD0's orientation and the JPEG candidates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TiffScan {
    pub orientation: Option<u8>,
    pub candidates: Vec<Candidate>,
}

/// The TIFF byte-order mark and magic, including Olympus ORF's variants.
#[must_use]
pub(crate) fn is_tiff(header: &[u8]) -> bool {
    matches!(
        header.get(..4),
        Some(b"II*\0" | b"MM\0*" | b"IIRO" | b"IIRS" | b"MMOR")
    )
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    tag: u16,
    kind: u16,
    count: u32,
    value: [u8; 4],
}

struct Walker<'r, R> {
    reader: &'r mut R,
    len: u64,
    endian: Endian,
}

impl<R: Read + Seek> Walker<'_, R> {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Option<()> {
        let end = offset.checked_add(buffer.len() as u64)?;
        if end > self.len {
            return None;
        }
        self.reader.seek(SeekFrom::Start(offset)).ok()?;
        self.reader.read_exact(buffer).ok()
    }

    fn u16(&self, bytes: [u8; 2]) -> u16 {
        match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(&self, bytes: [u8; 4]) -> u32 {
        match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        }
    }

    /// The entries of one directory and the offset of the next in its chain.
    fn directory(&mut self, offset: u64) -> Option<(Vec<Entry>, u64)> {
        let mut count = [0; 2];
        self.read_at(offset, &mut count)?;
        let count = self.u16(count);
        if count == 0 || count > MAX_ENTRIES {
            return None;
        }
        let mut raw = vec![0; usize::from(count) * 12 + 4];
        self.read_at(offset + 2, &mut raw)?;
        let (entries, next) = raw.split_at(usize::from(count) * 12);
        let entries = entries
            .as_chunks::<12>()
            .0
            .iter()
            .map(|entry| Entry {
                tag: self.u16([entry[0], entry[1]]),
                kind: self.u16([entry[2], entry[3]]),
                count: self.u32([entry[4], entry[5], entry[6], entry[7]]),
                value: [entry[8], entry[9], entry[10], entry[11]],
            })
            .collect();
        let next = self.u32([next[0], next[1], next[2], next[3]]);
        Some((entries, u64::from(next)))
    }

    /// Up to `max` unsigned values of a SHORT, LONG, or IFD entry, read
    /// inline or from the entry's offset. Longer arrays are refused.
    fn values(&mut self, entry: &Entry, max: usize) -> Option<Vec<u32>> {
        let size = match entry.kind {
            TYPE_SHORT => 2,
            TYPE_LONG | TYPE_IFD => 4,
            _ => return None,
        };
        let count = usize::try_from(entry.count).ok()?;
        if count == 0 || count > max {
            return None;
        }
        let total = count * size;
        let mut bytes = vec![0; total];
        if total <= 4 {
            bytes.copy_from_slice(&entry.value[..total]);
        } else {
            let offset = self.u32(entry.value);
            self.read_at(u64::from(offset), &mut bytes)?;
        }
        Some(
            bytes
                .chunks_exact(size)
                .map(|value| {
                    if size == 2 {
                        u32::from(self.u16([value[0], value[1]]))
                    } else {
                        self.u32([value[0], value[1], value[2], value[3]])
                    }
                })
                .collect(),
        )
    }

    fn single(&mut self, entry: &Entry) -> Option<u32> {
        self.values(entry, 1)
            .and_then(|values| values.first().copied())
    }
}

/// Walks a TIFF structure from `reader`, whose total length is `len`.
///
/// Returns `None` when the header is not TIFF or IFD0 cannot be read.
/// Malformed child directories are skipped rather than failing the walk.
pub(crate) fn scan<R: Read + Seek>(reader: &mut R, len: u64) -> Option<TiffScan> {
    let mut header = [0; 8];
    if len < 8 {
        return None;
    }
    reader.seek(SeekFrom::Start(0)).ok()?;
    reader.read_exact(&mut header).ok()?;
    if !is_tiff(&header) {
        return None;
    }
    let endian = if header[0] == b'I' {
        Endian::Little
    } else {
        Endian::Big
    };
    let mut walker = Walker {
        reader,
        len,
        endian,
    };
    let first = u64::from(walker.u32([header[4], header[5], header[6], header[7]]));
    let mut visited: Vec<u64> = Vec::with_capacity(MAX_IFDS);
    let mut pending: Vec<(u64, usize)> = vec![(first, 0)];
    let mut result = TiffScan::default();
    let mut read_first = false;

    while let Some((offset, depth)) = pending.pop() {
        if offset < 8 || visited.len() >= MAX_IFDS || visited.contains(&offset) {
            continue;
        }
        visited.push(offset);
        let Some((entries, next)) = walker.directory(offset) else {
            if offset == first {
                return None;
            }
            continue;
        };
        let is_first = offset == first;
        read_first |= is_first;

        let mut compression = None;
        let mut photometric = None;
        let mut strip_offsets = None;
        let mut strip_counts = None;
        let mut jpeg_offset = None;
        let mut jpeg_length = None;
        for entry in &entries {
            match entry.tag {
                TAG_ORIENTATION if is_first => {
                    result.orientation = walker
                        .single(entry)
                        .and_then(|value| u8::try_from(value).ok())
                        .filter(|value| (1..=8).contains(value));
                }
                TAG_COMPRESSION => compression = walker.single(entry),
                TAG_PHOTOMETRIC => photometric = walker.single(entry),
                TAG_STRIP_OFFSETS => strip_offsets = walker.values(entry, 1),
                TAG_STRIP_BYTE_COUNTS => strip_counts = walker.values(entry, 1),
                TAG_JPEG_OFFSET => jpeg_offset = walker.single(entry),
                TAG_JPEG_LENGTH => jpeg_length = walker.single(entry),
                TAG_SUB_IFDS if depth < MAX_DEPTH => {
                    if let Some(children) = walker.values(entry, MAX_SUB_IFDS) {
                        pending.extend(
                            children
                                .into_iter()
                                .map(|child| (u64::from(child), depth + 1)),
                        );
                    }
                }
                TAG_EXIF_IFD if depth < MAX_DEPTH => {
                    if let Some(child) = walker.single(entry) {
                        pending.push((u64::from(child), depth + 1));
                    }
                }
                _ => {}
            }
        }

        if let (Some(offset), Some(length)) = (jpeg_offset, jpeg_length) {
            push_candidate(&mut result, len, offset, length);
        }
        let raw_data = matches!(photometric, Some(PHOTOMETRIC_CFA | PHOTOMETRIC_LINEAR_RAW));
        if matches!(compression, Some(6 | 7))
            && !raw_data
            && let (Some(offsets), Some(counts)) = (strip_offsets, strip_counts)
        {
            push_candidate(&mut result, len, offsets[0], counts[0]);
        }
        if next != 0 {
            pending.push((next, depth));
        }
    }
    read_first.then_some(result)
}

fn push_candidate(result: &mut TiffScan, len: u64, offset: u32, length: u32) {
    let (offset, length) = (u64::from(offset), u64::from(length));
    let in_bounds = length >= 4 && offset.checked_add(length).is_some_and(|end| end <= len);
    let candidate = Candidate { offset, length };
    if in_bounds
        && result.candidates.len() < MAX_CANDIDATES
        && !result.candidates.contains(&candidate)
    {
        result.candidates.push(candidate);
    }
}

/// The orientation (1–8) in an EXIF TIFF structure, such as a JPEG APP1
/// payload after its `Exif\0\0` prefix.
#[must_use]
pub(crate) fn orientation(exif: &[u8]) -> Option<u8> {
    let mut cursor = std::io::Cursor::new(exif);
    scan(&mut cursor, exif.len() as u64).and_then(|scan| scan.orientation)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Cursor;

    use super::*;

    /// A little-endian TIFF builder for synthetic RAW containers.
    pub(crate) struct TiffBuilder {
        pub bytes: Vec<u8>,
    }

    impl TiffBuilder {
        pub(crate) fn new() -> Self {
            let mut bytes = b"II*\0".to_vec();
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            Self { bytes }
        }

        pub(crate) fn set_first_ifd(&mut self, offset: u32) {
            self.bytes[4..8].copy_from_slice(&offset.to_le_bytes());
        }

        /// Appends a directory of `(tag, type, count, value)` entries and
        /// returns its offset.
        pub(crate) fn ifd(&mut self, entries: &[(u16, u16, u32, u32)], next: u32) -> u32 {
            let offset = u32::try_from(self.bytes.len()).unwrap();
            self.bytes
                .extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
            for (tag, kind, count, value) in entries {
                self.bytes.extend_from_slice(&tag.to_le_bytes());
                self.bytes.extend_from_slice(&kind.to_le_bytes());
                self.bytes.extend_from_slice(&count.to_le_bytes());
                self.bytes.extend_from_slice(&value.to_le_bytes());
            }
            self.bytes.extend_from_slice(&next.to_le_bytes());
            offset
        }

        pub(crate) fn blob(&mut self, data: &[u8]) -> u32 {
            let offset = u32::try_from(self.bytes.len()).unwrap();
            self.bytes.extend_from_slice(data);
            offset
        }

        pub(crate) fn patch_u32(&mut self, at: usize, value: u32) {
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn scan_bytes(bytes: &[u8]) -> Option<TiffScan> {
        scan(&mut Cursor::new(bytes), bytes.len() as u64)
    }

    #[test]
    fn finds_previews_in_ifd0_subifds_and_strips() {
        let mut tiff = TiffBuilder::new();
        let small = tiff.blob(&[0xff, 0xd8, 0xff, 0xd9]);
        let large = tiff.blob(&[0xff, 0xd8, 0, 0, 0, 0, 0xff, 0xd9]);
        let strip = tiff.blob(&[0xff, 0xd8, 1, 1, 1, 0xff, 0xd9]);
        let raw = tiff.blob(&[0xff, 0xd8, 2, 2, 0xff, 0xd9]);
        let sub_preview = tiff.ifd(
            &[
                (TAG_JPEG_OFFSET, TYPE_LONG, 1, large),
                (TAG_JPEG_LENGTH, TYPE_LONG, 1, 8),
            ],
            0,
        );
        let sub_raw = tiff.ifd(
            &[
                (TAG_COMPRESSION, TYPE_SHORT, 1, 7),
                (TAG_PHOTOMETRIC, TYPE_SHORT, 1, PHOTOMETRIC_CFA),
                (TAG_STRIP_OFFSETS, TYPE_LONG, 1, raw),
                (TAG_STRIP_BYTE_COUNTS, TYPE_LONG, 1, 6),
            ],
            0,
        );
        let ifd1 = tiff.ifd(
            &[
                (TAG_COMPRESSION, TYPE_SHORT, 1, 6),
                (TAG_STRIP_OFFSETS, TYPE_LONG, 1, strip),
                (TAG_STRIP_BYTE_COUNTS, TYPE_LONG, 1, 7),
            ],
            0,
        );
        let children = tiff.blob(&[0; 8]);
        tiff.patch_u32(children as usize, sub_preview);
        tiff.patch_u32(children as usize + 4, sub_raw);
        let ifd0 = tiff.ifd(
            &[
                (TAG_ORIENTATION, TYPE_SHORT, 1, 6),
                (TAG_SUB_IFDS, TYPE_LONG, 2, children),
                (TAG_JPEG_OFFSET, TYPE_LONG, 1, small),
                (TAG_JPEG_LENGTH, TYPE_LONG, 1, 4),
            ],
            ifd1,
        );
        tiff.set_first_ifd(ifd0);
        let scan = scan_bytes(&tiff.bytes).expect("TIFF");
        assert_eq!(scan.orientation, Some(6));
        let mut found: Vec<_> = scan.candidates.iter().map(|c| c.offset).collect();
        found.sort_unstable();
        // The CFA strip is raw sensor data and never a candidate.
        assert_eq!(
            found,
            vec![u64::from(small), u64::from(large), u64::from(strip)]
        );
    }

    #[test]
    fn hostile_structures_are_bounded() {
        // A directory whose next pointer is itself, and two that point at
        // each other, end after one visit each.
        let mut tiff = TiffBuilder::new();
        let ifd0 = tiff.ifd(&[(TAG_ORIENTATION, TYPE_SHORT, 1, 3)], 0);
        tiff.patch_u32(ifd0 as usize + 2 + 12, ifd0);
        tiff.set_first_ifd(ifd0);
        assert_eq!(scan_bytes(&tiff.bytes).expect("TIFF").orientation, Some(3));

        let mut tiff = TiffBuilder::new();
        let a = tiff.ifd(&[(TAG_ORIENTATION, TYPE_SHORT, 1, 1)], 0);
        let b = tiff.ifd(&[(TAG_EXIF_IFD, TYPE_LONG, 1, a)], a);
        tiff.patch_u32(a as usize + 2 + 12, b);
        tiff.set_first_ifd(a);
        assert!(scan_bytes(&tiff.bytes).is_some());

        // Out-of-range offsets and lengths are ignored, not read.
        let mut tiff = TiffBuilder::new();
        let ifd0 = tiff.ifd(
            &[
                (TAG_JPEG_OFFSET, TYPE_LONG, 1, 0xffff_fff0),
                (TAG_JPEG_LENGTH, TYPE_LONG, 1, 0x100),
                (TAG_SUB_IFDS, TYPE_LONG, 1, 0x7fff_ffff),
                (TAG_EXIF_IFD, TYPE_LONG, 1, 0xffff_ffff),
            ],
            0xffff_0000,
        );
        tiff.set_first_ifd(ifd0);
        let scan = scan_bytes(&tiff.bytes).expect("TIFF");
        assert!(scan.candidates.is_empty());

        // A huge entry count or a huge value count is refused.
        let mut tiff = TiffBuilder::new();
        tiff.blob(&[0xff, 0xff]);
        tiff.set_first_ifd(8);
        assert_eq!(scan_bytes(&tiff.bytes), None);
        let mut tiff = TiffBuilder::new();
        let ifd0 = tiff.ifd(&[(TAG_SUB_IFDS, TYPE_LONG, u32::MAX, 8)], 0);
        tiff.set_first_ifd(ifd0);
        assert_eq!(scan_bytes(&tiff.bytes).expect("TIFF").candidates, vec![]);

        // An IFD0 outside the file, or a truncated header, is not TIFF.
        let mut tiff = TiffBuilder::new();
        tiff.set_first_ifd(4096);
        assert_eq!(scan_bytes(&tiff.bytes), None);
        assert_eq!(scan_bytes(b"II*\0"), None);
        assert_eq!(scan_bytes(b"not a tiff file"), None);
    }

    #[test]
    fn a_long_chain_visits_at_most_the_directory_cap() {
        let mut tiff = TiffBuilder::new();
        let mut next = 0;
        let mut first = 0;
        for _ in 0..(MAX_IFDS * 4) {
            first = tiff.ifd(&[(TAG_ORIENTATION, TYPE_SHORT, 1, 2)], next);
            next = first;
        }
        tiff.set_first_ifd(first);
        assert!(scan_bytes(&tiff.bytes).is_some());
    }

    #[test]
    fn orientation_reads_ifd0_of_an_exif_payload() {
        let mut big = b"MM\0*\0\0\0\x08".to_vec();
        big.extend_from_slice(&[
            0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(orientation(&big), Some(8));
        big[19] = 9;
        assert_eq!(orientation(&big), None);
    }
}

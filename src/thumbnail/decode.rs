//! Signature detection, decode-memory estimates, decoding, downscaling,
//! orientation, and encoding for thumbnails.
//!
//! [`plan`] reads only headers: it identifies the format from bytes, reads
//! the dimensions each decoder will allocate for, and computes a
//! conservative peak-memory estimate for the decode path it will take.
//! [`render`] then decodes under decoder limits derived from that plan, so a
//! header that lies to the planner also stops the decoder.

use std::{
    io::{BufReader, Read, Seek, SeekFrom},
    num::NonZeroU64,
};

use super::tiff;

/// Source files above this size are not thumbnailed.
pub(crate) const MAX_SOURCE_BYTES: u64 = 100 * 1024 * 1024;
/// The absolute pixel cap, whatever the budget allows.
pub(crate) const MAX_IMAGE_PIXELS: u64 = crate::preview::MAX_IMAGE_PIXELS;
/// JPEG quality of opaque thumbnails.
const JPEG_QUALITY: u8 = 82;
/// JPEG segments walked before the first frame header.
const MAX_JPEG_SEGMENTS: usize = 256;
/// Fill bytes tolerated before one JPEG marker.
const MAX_JPEG_FILL: usize = 64;
/// RIFF chunks walked in a WebP file, including animation frames.
const MAX_WEBP_CHUNKS: usize = 10_000;
/// Fixed allowance for decoder tables, reader buffers, and allocator slack.
const FIXED_OVERHEAD: u64 = 2 * 1024 * 1024;
/// Ancillary chunk bytes (EXIF, text, ICC) the PNG decoder may buffer.
const PNG_ANCILLARY_LIMIT: usize = 1024 * 1024;
/// Metadata bytes the WebP decoder may buffer.
const WEBP_METADATA_LIMIT: usize = 1024 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ThumbnailError {
    /// Not a supported signature, or a RAW container without a usable
    /// embedded JPEG preview.
    #[error("the file has no supported image signature")]
    Unsupported,
    /// The pixel cap, the decode estimate, or the source byte cap.
    #[error("the image is too large to thumbnail")]
    TooLarge,
    /// The bytes did not decode as their header promised.
    #[error("the image could not be decoded")]
    Corrupt,
    /// Reading the file failed.
    #[error("the image could not be read")]
    Unavailable,
}

/// The source formats a thumbnail can be made from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceKind {
    Jpeg,
    Png,
    Gif,
    WebP,
    /// The largest JPEG preview embedded in a TIFF-based RAW container.
    Raw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JpegHeader {
    pub width: u32,
    pub height: u32,
    pub components: u8,
    pub progressive: bool,
    pub orientation: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PngHeader {
    width: u32,
    height: u32,
    bits_per_pixel: u32,
    interlaced: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Codec {
    /// A JPEG stream decoded at `1 / scale` of its size.
    Jpeg {
        header: JpegHeader,
        scale: u32,
    },
    Png(PngHeader),
    Gif,
    WebP,
}

/// Everything [`render`] needs, decided from headers alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    pub kind: SourceKind,
    codec: Codec,
    /// The byte range of the decoded stream: the whole file, or a RAW
    /// container's embedded preview.
    window_start: u64,
    window_len: u64,
    /// Pixel dimensions the decoder allocates for.
    width: u32,
    height: u32,
    /// The downscaled size before orientation is applied.
    out_width: u32,
    out_height: u32,
    orientation: u8,
    /// The requested long edge.
    long_edge: u32,
    /// Conservative peak bytes for the whole decode, resize, and encode.
    pub estimate: u64,
}

/// An encoded thumbnail and its fixed media type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Encoded {
    pub bytes: Vec<u8>,
    pub media_type: &'static str,
}

impl From<std::io::Error> for ThumbnailError {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}

/// A `Read + Seek` view of `[start, start + len)` of an inner reader.
pub(crate) struct Window<R> {
    inner: R,
    start: u64,
    len: u64,
    position: u64,
}

impl<R: Seek> Window<R> {
    pub(crate) fn new(mut inner: R, start: u64, len: u64) -> std::io::Result<Self> {
        inner.seek(SeekFrom::Start(start))?;
        Ok(Self {
            inner,
            start,
            len,
            position: 0,
        })
    }
}

impl<R: Read + Seek> Read for Window<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.position);
        let wanted = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if wanted == 0 {
            return Ok(0);
        }
        let read = self.inner.read(&mut buffer[..wanted])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for Window<R> {
    fn seek(&mut self, target: SeekFrom) -> std::io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        }
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.inner
            .seek(SeekFrom::Start(self.start.saturating_add(position)))?;
        self.position = position;
        Ok(position)
    }
}

fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
    limit: u64,
) -> Result<(), ThumbnailError> {
    let end = offset
        .checked_add(buffer.len() as u64)
        .ok_or(ThumbnailError::Corrupt)?;
    if end > limit {
        return Err(ThumbnailError::Corrupt);
    }
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ThumbnailError::Corrupt
        } else {
            ThumbnailError::Unavailable
        }
    })
}

/// The output size for a long edge of `long_edge`, never upscaling.
#[must_use]
pub(crate) fn output_size(width: u32, height: u32, long_edge: u32) -> (u32, u32) {
    let longest = width.max(height);
    if longest <= long_edge {
        return (width, height);
    }
    let scale = |side: u32| {
        let scaled =
            (u64::from(side) * u64::from(long_edge) + u64::from(longest) / 2) / u64::from(longest);
        u32::try_from(scaled.max(1)).unwrap_or(long_edge)
    };
    (scale(width), scale(height))
}

fn check_pixels(width: u32, height: u32) -> Result<(), ThumbnailError> {
    if width == 0 || height == 0 {
        return Err(ThumbnailError::Corrupt);
    }
    if u64::from(width) * u64::from(height) > MAX_IMAGE_PIXELS {
        return Err(ThumbnailError::TooLarge);
    }
    Ok(())
}

/// Reads headers and decides how to decode, without decoding pixels.
pub(crate) fn plan<R: Read + Seek>(
    reader: &mut R,
    len: u64,
    long_edge: u32,
) -> Result<Plan, ThumbnailError> {
    if len > MAX_SOURCE_BYTES {
        return Err(ThumbnailError::TooLarge);
    }
    let mut signature = [0_u8; 16];
    let available = usize::try_from(len.min(16)).unwrap_or(16);
    read_at(reader, 0, &mut signature[..available], len)?;
    let signature = &signature[..available];

    let (kind, codec, window_start, window_len, width, height, orientation) =
        if signature.starts_with(b"\x89PNG\r\n\x1a\n") {
            let header = png_header(reader, len)?;
            let codec = Codec::Png(header);
            (
                SourceKind::Png,
                codec,
                0,
                len,
                header.width,
                header.height,
                1,
            )
        } else if signature.starts_with(b"GIF87a") || signature.starts_with(b"GIF89a") {
            let mut screen = [0; 4];
            read_at(reader, 6, &mut screen, len)?;
            let width = u32::from(u16::from_le_bytes([screen[0], screen[1]]));
            let height = u32::from(u16::from_le_bytes([screen[2], screen[3]]));
            (SourceKind::Gif, Codec::Gif, 0, len, width, height, 1)
        } else if signature.starts_with(&[0xff, 0xd8, 0xff]) {
            let header = jpeg_header(reader, 0, len)?;
            let codec = Codec::Jpeg { header, scale: 1 };
            let orientation = header.orientation.unwrap_or(1);
            (
                SourceKind::Jpeg,
                codec,
                0,
                len,
                header.width,
                header.height,
                orientation,
            )
        } else if signature.len() >= 12
            && signature.starts_with(b"RIFF")
            && &signature[8..12] == b"WEBP"
        {
            let (width, height) = webp_dimensions(reader, len)?;
            (SourceKind::WebP, Codec::WebP, 0, len, width, height, 1)
        } else if tiff::is_tiff(signature) {
            let preview = raw_preview(reader, len)?.ok_or(ThumbnailError::Unsupported)?;
            let codec = Codec::Jpeg {
                header: preview.header,
                scale: 1,
            };
            (
                SourceKind::Raw,
                codec,
                preview.offset,
                preview.length,
                preview.header.width,
                preview.header.height,
                preview.orientation,
            )
        } else {
            return Err(ThumbnailError::Unsupported);
        };
    check_pixels(width, height)?;
    let (out_width, out_height) = output_size(width, height, long_edge);
    let codec = match codec {
        Codec::Jpeg { header, .. } => Codec::Jpeg {
            header,
            scale: jpeg_scale(width, height, out_width, out_height),
        },
        other => other,
    };
    let mut plan = Plan {
        kind,
        codec,
        window_start,
        window_len,
        width,
        height,
        out_width,
        out_height,
        orientation,
        long_edge,
        estimate: 0,
    };
    plan.estimate = estimate(&plan);
    Ok(plan)
}

/// The largest decode scale denominator (1, 2, 4, or 8) whose scaled image
/// still covers the output size on both axes.
fn jpeg_scale(width: u32, height: u32, out_width: u32, out_height: u32) -> u32 {
    [8, 4, 2]
        .into_iter()
        .find(|scale| width.div_ceil(*scale) >= out_width && height.div_ceil(*scale) >= out_height)
        .unwrap_or(1)
}

/// Estimated bytes a JPEG decode holds at its peak.
///
/// Scaled IDCT shrinks the component planes and the colour output by
/// `scale²`; a progressive stream also keeps every quantized coefficient of
/// the full image (two bytes per sample) until the last scan. The decoder
/// retains ICC segments wherever they appear, so the stream length is
/// added as an upper bound for those.
pub(crate) fn jpeg_decode_estimate(header: &JpegHeader, scale: u32, stream_len: u64) -> u64 {
    // Components are padded to whole MCUs of at most 32 pixels.
    let padded_width = u64::from(header.width) + 64;
    let padded_height = u64::from(header.height) + 64;
    let scale = u64::from(scale);
    let scaled = padded_width.div_ceil(scale) * padded_height.div_ceil(scale);
    let components = u64::from(header.components);
    let planes = components * scaled;
    let output = components * scaled;
    let coefficients = if header.progressive {
        components * padded_width * padded_height * 2
    } else {
        0
    };
    // One MCU row of coefficients per component in flight.
    let mcu_rows = components * padded_width * 32 * 2 * 2;
    planes + output + coefficients + mcu_rows + stream_len
}

/// The peak estimate for a whole plan: decode, then resize, orientation,
/// and encode buffers, plus fixed allowances.
fn estimate(plan: &Plan) -> u64 {
    let pixels = u64::from(plan.width) * u64::from(plan.height);
    let width = u64::from(plan.width);
    let decode = match plan.codec {
        Codec::Jpeg { header, scale } => jpeg_decode_estimate(&header, scale, plan.window_len),
        Codec::Png(header) => {
            let raw_row = (width * u64::from(header.bits_per_pixel)).div_ceil(8) + 1;
            // The unfiltering stream keeps a few rows plus the inflate window.
            let stream = 12 * raw_row;
            let rows = 2 * width * 4;
            let frame = if header.interlaced { pixels * 4 } else { 0 };
            stream + rows + frame + PNG_ANCILLARY_LIMIT as u64
        }
        // The RGBA frame and the indexed pixels it is expanded from.
        Codec::Gif => pixels * 5,
        // Output, a lossless or animation scratch frame, the canvas, the
        // decoded alpha plane, and the YUV planes of a lossy frame.
        Codec::WebP => pixels * 20 + WEBP_METADATA_LIMIT as u64,
    };
    let out_pixels = u64::from(plan.out_width) * u64::from(plan.out_height);
    // Downscaled RGBA and its oriented copy.
    let stage = out_pixels * 4 * 2;
    // Per-column accumulators and the source column map.
    let resize = u64::from(plan.out_width) * (4 * 8 + 4) + width * 4;
    decode
        .saturating_add(stage)
        .saturating_add(resize)
        .saturating_add(encode_estimate(plan.out_width, plan.out_height))
        .saturating_add(FIXED_OVERHEAD)
}

/// Peak encoder memory for a `width`×`height` thumbnail, in either
/// orientation: the larger of the PNG output, budgeted at four bytes per
/// pixel, and the JPEG encoder's. jpeg-encoder holds one 16-row band per
/// YCbCr component, each row padded to a multiple of 16, and writes into an
/// output buffer reserved at [`jpeg_output_reserve`]; should an image ever
/// outgrow the reserve, its one doubling briefly holds both buffers.
fn encode_estimate(width: u32, height: u32) -> u64 {
    let png = u64::from(width) * u64::from(height) * 4;
    let band = u64::from(width.max(height)).next_multiple_of(16) * 16 * 3;
    let output = jpeg_output_reserve(width, height) as u64 * 3;
    png.max(band + output)
}

fn png_header<R: Read + Seek>(reader: &mut R, len: u64) -> Result<PngHeader, ThumbnailError> {
    let mut ihdr = [0; 25];
    read_at(reader, 8, &mut ihdr, len)?;
    if &ihdr[4..8] != b"IHDR" || u32::from_be_bytes([ihdr[0], ihdr[1], ihdr[2], ihdr[3]]) != 13 {
        return Err(ThumbnailError::Corrupt);
    }
    let width = u32::from_be_bytes([ihdr[8], ihdr[9], ihdr[10], ihdr[11]]);
    let height = u32::from_be_bytes([ihdr[12], ihdr[13], ihdr[14], ihdr[15]]);
    let depth = u32::from(ihdr[16]);
    let channels = match ihdr[17] {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => return Err(ThumbnailError::Corrupt),
    };
    if !matches!(depth, 1 | 2 | 4 | 8 | 16) {
        return Err(ThumbnailError::Corrupt);
    }
    Ok(PngHeader {
        width,
        height,
        bits_per_pixel: channels * depth,
        interlaced: ihdr[20] != 0,
    })
}

/// Walks JPEG segments in `[start, start + len)` up to the frame header.
///
/// Only baseline, extended sequential, and progressive Huffman frames with
/// 8-bit samples and one, three, or four components are accepted: they are
/// what browsers and the decoder display. The first EXIF APP1 segment's
/// orientation is kept.
pub(crate) fn jpeg_header<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    len: u64,
) -> Result<JpegHeader, ThumbnailError> {
    let end = start.checked_add(len).ok_or(ThumbnailError::Corrupt)?;
    let mut soi = [0; 2];
    read_at(reader, start, &mut soi, end)?;
    if soi != [0xff, 0xd8] {
        return Err(ThumbnailError::Corrupt);
    }
    let mut position = start + 2;
    let mut orientation = None;
    for _ in 0..MAX_JPEG_SEGMENTS {
        let mut prefix = [0; 2];
        read_at(reader, position, &mut prefix, end)?;
        if prefix[0] != 0xff {
            return Err(ThumbnailError::Corrupt);
        }
        let mut marker = prefix[1];
        let mut fill = 0;
        while marker == 0xff {
            fill += 1;
            if fill > MAX_JPEG_FILL {
                return Err(ThumbnailError::Corrupt);
            }
            position += 1;
            read_at(reader, position, &mut prefix, end)?;
            marker = prefix[1];
        }
        match marker {
            0x01 | 0xd0..=0xd7 => {
                position += 2;
                continue;
            }
            0x00 | 0xd8 | 0xd9 | 0xda => return Err(ThumbnailError::Corrupt),
            _ => {}
        }
        let mut length = [0; 2];
        read_at(reader, position + 2, &mut length, end)?;
        let length = u64::from(u16::from_be_bytes(length));
        if length < 2 {
            return Err(ThumbnailError::Corrupt);
        }
        let payload = position + 4;
        let next = position + 2 + length;
        if next > end {
            return Err(ThumbnailError::Corrupt);
        }
        match marker {
            0xc0..=0xc2 => {
                let mut frame = [0; 6];
                read_at(reader, payload, &mut frame, end)?;
                let height = u32::from(u16::from_be_bytes([frame[1], frame[2]]));
                let width = u32::from(u16::from_be_bytes([frame[3], frame[4]]));
                let components = frame[5];
                if frame[0] != 8 || width == 0 || height == 0 || !matches!(components, 1 | 3 | 4) {
                    return Err(ThumbnailError::Unsupported);
                }
                let mut specs = vec![0; usize::from(components) * 3];
                read_at(reader, payload + 6, &mut specs, next)?;
                for spec in specs.as_chunks::<3>().0 {
                    let (horizontal, vertical) = (spec[1] >> 4, spec[1] & 0x0f);
                    if !(1..=4).contains(&horizontal) || !(1..=4).contains(&vertical) {
                        return Err(ThumbnailError::Corrupt);
                    }
                }
                return Ok(JpegHeader {
                    width,
                    height,
                    components,
                    progressive: marker == 0xc2,
                    orientation,
                });
            }
            // Lossless, hierarchical, and arithmetic-coded frames.
            0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf => {
                return Err(ThumbnailError::Unsupported);
            }
            0xe1 if orientation.is_none() && length >= 2 + 6 + 8 => {
                let mut exif = vec![0; usize::try_from(length - 2).unwrap_or(0)];
                read_at(reader, payload, &mut exif, next)?;
                if let Some(tiff_bytes) = exif.strip_prefix(b"Exif\0\0") {
                    orientation = tiff::orientation(tiff_bytes);
                }
            }
            _ => {}
        }
        position = next;
    }
    Err(ThumbnailError::Corrupt)
}

/// The largest dimensions any VP8 or VP8L bitstream in the file declares,
/// and the VP8X canvas. The decoder allocates by bitstream dimensions before
/// it checks them against the canvas, so every bitstream counts.
fn webp_dimensions<R: Read + Seek>(reader: &mut R, len: u64) -> Result<(u32, u32), ThumbnailError> {
    let mut riff = [0; 4];
    read_at(reader, 4, &mut riff, len)?;
    let end = (u64::from(u32::from_le_bytes(riff)) + 8).min(len);
    let mut largest = (0_u32, 0_u32);
    // Per-axis maxima: their product bounds every bitstream's allocation.
    let mut consider = |width: u32, height: u32| {
        largest.0 = largest.0.max(width);
        largest.1 = largest.1.max(height);
    };
    // A stack of (position, end) chunk ranges: the file, then ANMF frames.
    let mut ranges = vec![(12_u64, end)];
    let mut chunks = 0;
    while let Some((mut position, range_end)) = ranges.pop() {
        while position + 8 <= range_end {
            chunks += 1;
            if chunks > MAX_WEBP_CHUNKS {
                return Err(ThumbnailError::Unsupported);
            }
            let mut header = [0; 8];
            read_at(reader, position, &mut header, range_end)?;
            let size = u64::from(u32::from_le_bytes([
                header[4], header[5], header[6], header[7],
            ]));
            let body = position + 8;
            let body_end = body.checked_add(size).ok_or(ThumbnailError::Corrupt)?;
            match &header[..4] {
                b"VP8 " => {
                    let mut frame = [0; 10];
                    read_at(reader, body, &mut frame, len)?;
                    if frame[3..6] != [0x9d, 0x01, 0x2a] {
                        return Err(ThumbnailError::Corrupt);
                    }
                    consider(
                        u32::from(u16::from_le_bytes([frame[6], frame[7]]) & 0x3fff),
                        u32::from(u16::from_le_bytes([frame[8], frame[9]]) & 0x3fff),
                    );
                }
                b"VP8L" => {
                    let mut frame = [0; 5];
                    read_at(reader, body, &mut frame, len)?;
                    if frame[0] != 0x2f {
                        return Err(ThumbnailError::Corrupt);
                    }
                    let bits = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
                    consider((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1);
                }
                b"VP8X" => {
                    let mut canvas = [0; 10];
                    read_at(reader, body, &mut canvas, len)?;
                    consider(
                        1 + u32::from_le_bytes([canvas[4], canvas[5], canvas[6], 0]),
                        1 + u32::from_le_bytes([canvas[7], canvas[8], canvas[9], 0]),
                    );
                }
                b"ANMF" if size >= 16 => {
                    let mut frame = [0; 16];
                    read_at(reader, body, &mut frame, len)?;
                    consider(
                        1 + u32::from_le_bytes([frame[6], frame[7], frame[8], 0]),
                        1 + u32::from_le_bytes([frame[9], frame[10], frame[11], 0]),
                    );
                    ranges.push((body + 16, body_end.min(range_end)));
                }
                _ => {}
            }
            // Chunks are padded to an even length.
            position = body_end + (size & 1);
        }
    }
    if largest.0 == 0 || largest.1 == 0 {
        return Err(ThumbnailError::Corrupt);
    }
    Ok(largest)
}

/// The JPEG preview a RAW container embeds, chosen by pixel count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawPreview {
    pub offset: u64,
    pub length: u64,
    pub header: JpegHeader,
    pub orientation: u8,
}

/// Finds the largest decodable JPEG preview in a TIFF-based container.
///
/// `Ok(None)` means the file is TIFF but has no preview this server can
/// decode; the orientation comes from IFD0, which describes the sensor
/// image the previews were rendered from.
pub(crate) fn raw_preview<R: Read + Seek>(
    reader: &mut R,
    len: u64,
) -> Result<Option<RawPreview>, ThumbnailError> {
    let Some(scan) = tiff::scan(reader, len) else {
        return Ok(None);
    };
    let mut best: Option<RawPreview> = None;
    for candidate in scan.candidates {
        let Ok(header) = jpeg_header(reader, candidate.offset, candidate.length) else {
            continue;
        };
        let pixels = u64::from(header.width) * u64::from(header.height);
        let better = best.is_none_or(|current| {
            pixels > u64::from(current.header.width) * u64::from(current.header.height)
        });
        if better {
            best = Some(RawPreview {
                offset: candidate.offset,
                length: candidate.length,
                header,
                orientation: scan.orientation.unwrap_or(1),
            });
        }
    }
    Ok(best)
}

/// Pixel layouts the downscaler accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Layout {
    Gray,
    GrayAlpha,
    Rgb,
    Rgba,
    /// Adobe-style inverted CMYK, as JPEG decoders return it.
    Cmyk,
}

impl Layout {
    const fn channels(self) -> usize {
        match self {
            Self::Gray => 1,
            Self::GrayAlpha => 2,
            Self::Rgb => 3,
            Self::Rgba | Self::Cmyk => 4,
        }
    }
}

/// A streaming area-average (box) downscaler.
///
/// Every source pixel contributes to exactly one output pixel, chosen by
/// integer mapping, and colour is averaged weighted by alpha so transparent
/// pixels do not darken edges. Only one output row of accumulators and the
/// output image are held, so a source can be fed one row at a time.
struct Downscaler {
    source_width: u32,
    source_height: u32,
    out_width: u32,
    out_height: u32,
    column: Vec<u32>,
    column_count: Vec<u32>,
    sums: Vec<u64>,
    rows_in_current: u64,
    current_row: u32,
    rows_seen: u32,
    output: Vec<u8>,
    opaque: bool,
}

impl Downscaler {
    fn new(source_width: u32, source_height: u32, out_width: u32, out_height: u32) -> Self {
        let column: Vec<u32> = (0..source_width)
            .map(|x| (u64::from(x) * u64::from(out_width) / u64::from(source_width)) as u32)
            .collect();
        let mut column_count = vec![0; out_width as usize];
        for &target in &column {
            column_count[target as usize] += 1;
        }
        Self {
            source_width,
            source_height,
            out_width,
            out_height,
            column,
            column_count,
            sums: vec![0; out_width as usize * 4],
            rows_in_current: 0,
            current_row: 0,
            rows_seen: 0,
            output: vec![0; out_width as usize * out_height as usize * 4],
            opaque: true,
        }
    }

    fn push(&mut self, row: &[u8], layout: Layout) -> Result<(), ThumbnailError> {
        let channels = layout.channels();
        if self.rows_seen >= self.source_height || row.len() < self.source_width as usize * channels
        {
            return Err(ThumbnailError::Corrupt);
        }
        let target = (u64::from(self.rows_seen) * u64::from(self.out_height)
            / u64::from(self.source_height)) as u32;
        if target != self.current_row {
            self.flush();
            self.current_row = target;
        }
        for (pixel, &out) in row.chunks_exact(channels).zip(&self.column) {
            let [red, green, blue, alpha] = match layout {
                Layout::Gray => [pixel[0], pixel[0], pixel[0], 255],
                Layout::GrayAlpha => [pixel[0], pixel[0], pixel[0], pixel[1]],
                Layout::Rgb => [pixel[0], pixel[1], pixel[2], 255],
                Layout::Rgba => [pixel[0], pixel[1], pixel[2], pixel[3]],
                Layout::Cmyk => {
                    let key = u16::from(pixel[3]);
                    let channel = |value: u8| ((u16::from(value) * key + 127) / 255) as u8;
                    [channel(pixel[0]), channel(pixel[1]), channel(pixel[2]), 255]
                }
            };
            let sums = &mut self.sums[out as usize * 4..out as usize * 4 + 4];
            let alpha64 = u64::from(alpha);
            sums[0] += u64::from(red) * alpha64;
            sums[1] += u64::from(green) * alpha64;
            sums[2] += u64::from(blue) * alpha64;
            sums[3] += alpha64;
        }
        self.rows_in_current += 1;
        self.rows_seen += 1;
        Ok(())
    }

    fn flush(&mut self) {
        if self.rows_in_current == 0 {
            return;
        }
        let row_start = self.current_row as usize * self.out_width as usize * 4;
        for column in 0..self.out_width as usize {
            let sums = &mut self.sums[column * 4..column * 4 + 4];
            let count = u64::from(self.column_count[column]) * self.rows_in_current;
            let pixel = &mut self.output[row_start + column * 4..row_start + column * 4 + 4];
            if sums[3] == 0 || count == 0 {
                pixel.copy_from_slice(&[0, 0, 0, 0]);
                self.opaque = false;
            } else {
                for channel in 0..3 {
                    pixel[channel] = ((sums[channel] + sums[3] / 2) / sums[3]) as u8;
                }
                let alpha = ((sums[3] + count / 2) / count) as u8;
                pixel[3] = alpha;
                self.opaque &= alpha == 255;
            }
            sums.fill(0);
        }
        self.rows_in_current = 0;
    }

    fn finish(mut self) -> Result<(Vec<u8>, bool), ThumbnailError> {
        self.flush();
        if self.rows_seen != self.source_height {
            return Err(ThumbnailError::Corrupt);
        }
        Ok((self.output, self.opaque))
    }
}

/// Applies an EXIF orientation (1–8) to an RGBA image.
#[must_use]
pub(crate) fn orient(
    rgba: Vec<u8>,
    width: u32,
    height: u32,
    orientation: u8,
) -> (Vec<u8>, u32, u32) {
    if !(2..=8).contains(&orientation) {
        return (rgba, width, height);
    }
    let (w, h) = (width as usize, height as usize);
    let swaps = orientation >= 5;
    let (new_width, new_height) = if swaps { (h, w) } else { (w, h) };
    let mut output = vec![0; rgba.len()];
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = match orientation {
                2 => (w - 1 - x, y),
                3 => (w - 1 - x, h - 1 - y),
                4 => (x, h - 1 - y),
                5 => (y, x),
                6 => (h - 1 - y, x),
                7 => (h - 1 - y, w - 1 - x),
                _ => (y, w - 1 - x),
            };
            let source = (y * w + x) * 4;
            let destination = (dy * new_width + dx) * 4;
            output[destination..destination + 4].copy_from_slice(&rgba[source..source + 4]);
        }
    }
    (output, new_width as u32, new_height as u32)
}

/// Decodes, downscales, orients, and encodes the planned image.
///
/// The caller holds a memory reservation of `plan.estimate` bytes. Each
/// decoder is also limited to the allocation the plan accounted for.
pub(crate) fn render<R: Read + Seek>(reader: R, plan: &Plan) -> Result<Encoded, ThumbnailError> {
    let window = Window::new(reader, plan.window_start, plan.window_len)?;
    let input = BufReader::with_capacity(READ_BUFFER_BYTES, window);
    // The decoded size must stay within what the plan reserved for. A JPEG
    // decoded at reduced scale keeps the planned output size, which the
    // scale was chosen to cover; anything else is resized by its own size.
    let downscaler = |width: u32, height: u32| -> Result<Downscaler, ThumbnailError> {
        if width == 0
            || height == 0
            || u64::from(width) * u64::from(height) > u64::from(plan.width) * u64::from(plan.height)
        {
            return Err(ThumbnailError::Corrupt);
        }
        let (out_width, out_height) = if matches!(plan.codec, Codec::Jpeg { .. }) {
            (plan.out_width.min(width), plan.out_height.min(height))
        } else {
            output_size(width, height, plan.long_edge)
        };
        Ok(Downscaler::new(width, height, out_width, out_height))
    };
    let scaler = match plan.codec {
        Codec::Jpeg { header, scale } => {
            let mut decoder = jpeg_decoder::Decoder::new(input);
            decoder.read_info().map_err(|_| ThumbnailError::Corrupt)?;
            let info = decoder.info().ok_or(ThumbnailError::Corrupt)?;
            if u32::from(info.width) != header.width || u32::from(info.height) != header.height {
                return Err(ThumbnailError::Corrupt);
            }
            let wanted_width = header.width.div_ceil(scale);
            let wanted_height = header.height.div_ceil(scale);
            let (width, height) = decoder
                .scale(
                    u16::try_from(wanted_width).map_err(|_| ThumbnailError::Corrupt)?,
                    u16::try_from(wanted_height).map_err(|_| ThumbnailError::Corrupt)?,
                )
                .map_err(|_| ThumbnailError::Corrupt)?;
            let (width, height) = (u32::from(width), u32::from(height));
            if width > wanted_width || height > wanted_height {
                return Err(ThumbnailError::Corrupt);
            }
            let layout = match info.pixel_format {
                jpeg_decoder::PixelFormat::L8 => Layout::Gray,
                jpeg_decoder::PixelFormat::RGB24 => Layout::Rgb,
                jpeg_decoder::PixelFormat::CMYK32 => Layout::Cmyk,
                jpeg_decoder::PixelFormat::L16 => return Err(ThumbnailError::Unsupported),
            };
            let row = width as usize * layout.channels();
            decoder.set_max_decoding_buffer_size(row * height as usize);
            let pixels = decoder.decode().map_err(|_| ThumbnailError::Corrupt)?;
            if pixels.len() != row * height as usize {
                return Err(ThumbnailError::Corrupt);
            }
            let mut scaler = downscaler(width, height)?;
            for line in pixels.chunks_exact(row) {
                scaler.push(line, layout)?;
            }
            scaler
        }
        Codec::Png(header) => {
            let mut decoder = png::Decoder::new_with_limits(
                input,
                png::Limits {
                    bytes: PNG_ANCILLARY_LIMIT,
                },
            );
            decoder
                .set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
            decoder.set_ignore_text_chunk(true);
            decoder.set_ignore_iccp_chunk(true);
            let mut reader = decoder.read_info().map_err(|_| ThumbnailError::Corrupt)?;
            let (width, height) = (reader.info().width, reader.info().height);
            if width != header.width || height != header.height {
                return Err(ThumbnailError::Corrupt);
            }
            let layout = match reader.output_color_type() {
                (png::ColorType::Grayscale, png::BitDepth::Eight) => Layout::Gray,
                (png::ColorType::GrayscaleAlpha, png::BitDepth::Eight) => Layout::GrayAlpha,
                (png::ColorType::Rgb, png::BitDepth::Eight) => Layout::Rgb,
                (png::ColorType::Rgba, png::BitDepth::Eight) => Layout::Rgba,
                _ => return Err(ThumbnailError::Unsupported),
            };
            let mut scaler = downscaler(width, height)?;
            if header.interlaced {
                let size = reader
                    .output_buffer_size()
                    .ok_or(ThumbnailError::TooLarge)?;
                if size as u64 > u64::from(width) * u64::from(height) * 4 {
                    return Err(ThumbnailError::Corrupt);
                }
                let mut frame = vec![0; size];
                let info = reader
                    .next_frame(&mut frame)
                    .map_err(|_| ThumbnailError::Corrupt)?;
                for line in frame[..info.buffer_size()].chunks_exact(info.line_size) {
                    scaler.push(line, layout)?;
                }
            } else {
                while let Some(row) = reader.next_row().map_err(|_| ThumbnailError::Corrupt)? {
                    scaler.push(row.data(), layout)?;
                }
            }
            scaler
        }
        Codec::Gif => {
            let frame_limit = u64::from(plan.width) * u64::from(plan.height) * 4;
            let mut options = gif::DecodeOptions::new();
            options.set_color_output(gif::ColorOutput::RGBA);
            options.set_memory_limit(gif::MemoryLimit::Bytes(
                NonZeroU64::new(frame_limit).ok_or(ThumbnailError::Corrupt)?,
            ));
            options.check_frame_consistency(true);
            let mut decoder = options
                .read_info(input)
                .map_err(|_| ThumbnailError::Corrupt)?;
            let frame = decoder
                .read_next_frame()
                .map_err(|_| ThumbnailError::Corrupt)?
                .ok_or(ThumbnailError::Corrupt)?;
            let (width, height) = (u32::from(frame.width), u32::from(frame.height));
            let mut scaler = downscaler(width, height)?;
            let row = width as usize * 4;
            if frame.buffer.len() != row * height as usize {
                return Err(ThumbnailError::Corrupt);
            }
            for line in frame.buffer.chunks_exact(row) {
                scaler.push(line, Layout::Rgba)?;
            }
            scaler
        }
        Codec::WebP => {
            let mut decoder =
                image_webp::WebPDecoder::new(input).map_err(|_| ThumbnailError::Corrupt)?;
            decoder.set_memory_limit(WEBP_METADATA_LIMIT);
            let (width, height) = decoder.dimensions();
            let mut scaler = downscaler(width, height)?;
            let size = decoder
                .output_buffer_size()
                .ok_or(ThumbnailError::TooLarge)?;
            let layout = if decoder.has_alpha() {
                Layout::Rgba
            } else {
                Layout::Rgb
            };
            let mut pixels = vec![0; size];
            decoder
                .read_image(&mut pixels)
                .map_err(|_| ThumbnailError::Corrupt)?;
            for line in pixels.chunks_exact(width as usize * layout.channels()) {
                scaler.push(line, layout)?;
            }
            scaler
        }
    };
    let (out_width, out_height) = (scaler.out_width, scaler.out_height);
    let (rgba, opaque) = scaler.finish()?;
    let (rgba, width, height) = orient(rgba, out_width, out_height, plan.orientation);
    encode(&rgba, width, height, opaque)
}

/// JPEG for opaque thumbnails, lossless PNG when any pixel is translucent.
/// Neither carries metadata.
fn encode(rgba: &[u8], width: u32, height: u32, opaque: bool) -> Result<Encoded, ThumbnailError> {
    if opaque {
        return Ok(Encoded {
            bytes: encode_jpeg(rgba, width, height)?,
            media_type: "image/jpeg",
        });
    }
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|_| ThumbnailError::Unavailable)?;
    writer
        .write_image_data(rgba)
        .map_err(|_| ThumbnailError::Unavailable)?;
    writer.finish().map_err(|_| ThumbnailError::Unavailable)?;
    Ok(Encoded {
        bytes,
        media_type: "image/png",
    })
}

/// The output buffer reserved for a JPEG thumbnail: one byte per pixel plus
/// the headers. Binary RGB noise, the densest input measured, encodes to
/// under 0.9 bytes per pixel at [`JPEG_QUALITY`] with 4:2:0 chroma.
fn jpeg_output_reserve(width: u32, height: u32) -> usize {
    width as usize * height as usize + 4096
}

/// A baseline JFIF with 4:2:0 box-averaged chroma: no EXIF, ICC, or other
/// application segment beyond the JFIF header.
pub(crate) fn encode_jpeg(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, ThumbnailError> {
    let width = u16::try_from(width).map_err(|_| ThumbnailError::TooLarge)?;
    let height = u16::try_from(height).map_err(|_| ThumbnailError::TooLarge)?;
    let mut bytes = Vec::with_capacity(jpeg_output_reserve(u32::from(width), u32::from(height)));
    let mut encoder = jpeg_encoder::Encoder::new(&mut bytes, JPEG_QUALITY);
    encoder.set_sampling_factor(jpeg_encoder::SamplingFactor::R_4_2_0);
    encoder.set_chroma_subsampling_method(jpeg_encoder::ChromaSubsamplingMethod::Average);
    encoder
        .encode(rgba, width, height, jpeg_encoder::ColorType::Rgba)
        .map_err(|_| ThumbnailError::Unavailable)?;
    Ok(bytes)
}

/// Plans and renders `data` under `budget` bytes, for the fuzz harness.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn render_bytes(
    data: &[u8],
    long_edge: u32,
    budget: u64,
) -> Result<Encoded, ThumbnailError> {
    let mut cursor = std::io::Cursor::new(data);
    let plan = plan(&mut cursor, data.len() as u64, long_edge)?;
    if plan.estimate > budget {
        return Err(ThumbnailError::TooLarge);
    }
    render(std::io::Cursor::new(data), &plan)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::thumbnail::{
        tests::{jpeg_fixture, png_fixture, raw_fixture},
        tiff::tests::TiffBuilder,
    };

    const BUDGET: u64 = 256 * 1024 * 1024;

    fn plan_bytes(data: &[u8], long_edge: u32) -> Result<Plan, ThumbnailError> {
        plan(&mut Cursor::new(data), data.len() as u64, long_edge)
    }

    fn gif_fixture(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let palette = [255, 0, 0, 0, 0, 255];
            let mut encoder = gif::Encoder::new(&mut bytes, width, height, &palette).unwrap();
            let pixels: Vec<u8> = (0..usize::from(width) * usize::from(height))
                .map(|index| u8::from(index % usize::from(width) >= usize::from(width) / 2))
                .collect();
            let frame = gif::Frame::from_palette_pixels(width, height, pixels, palette, None);
            encoder.write_frame(&frame).unwrap();
        }
        bytes
    }

    fn webp_fixture(width: u32, height: u32, alpha: bool) -> Vec<u8> {
        let mut rgba = Vec::new();
        for _ in 0..height {
            for x in 0..width {
                rgba.extend_from_slice(&[200, 30, 30, if alpha && x == 0 { 0 } else { 255 }]);
            }
        }
        let mut bytes = Vec::new();
        image_webp::WebPEncoder::new(&mut bytes)
            .encode(&rgba, width, height, image_webp::ColorType::Rgba8)
            .unwrap();
        bytes
    }

    fn header(width: u32, height: u32, progressive: bool) -> JpegHeader {
        JpegHeader {
            width,
            height,
            components: 3,
            progressive,
            orientation: None,
        }
    }

    #[test]
    fn scaled_jpeg_estimates_are_far_below_full_frame() {
        let photo = header(8000, 6000, false);
        let full = jpeg_decode_estimate(&photo, 1, 0);
        let eighth = jpeg_decode_estimate(&photo, 8, 0);
        assert!(eighth * 20 < full, "{eighth} vs {full}");
        assert!(jpeg_decode_estimate(&photo, 2, 0) < full);
        // Progressive streams keep every coefficient whatever the scale.
        let progressive = jpeg_decode_estimate(&header(8000, 6000, true), 8, 0);
        assert!(progressive > full);

        // A 256 thumbnail of a 4000×3000 JPEG decodes at ⅛ scale.
        let jpeg = jpeg_fixture(4000, 3000, None);
        let small = plan_bytes(&jpeg, 256).unwrap();
        assert!(matches!(small.codec, Codec::Jpeg { scale: 8, .. }));
        let large = plan_bytes(&jpeg, 1600).unwrap();
        assert!(matches!(large.codec, Codec::Jpeg { scale: 2, .. }));
        assert!(small.estimate < large.estimate);
        let rendered = render(Cursor::new(&jpeg), &small).unwrap();
        assert_eq!(rendered.media_type, "image/jpeg");
    }

    #[test]
    fn output_sizes_keep_aspect_and_never_upscale() {
        assert_eq!(output_size(4000, 3000, 256), (256, 192));
        assert_eq!(output_size(3000, 4000, 1600), (1200, 1600));
        assert_eq!(output_size(100, 50, 1600), (100, 50));
        assert_eq!(output_size(10_000, 1, 256), (256, 1));
    }

    #[test]
    fn orientation_maps_every_transform() {
        // A 2×1 image: red then blue.
        let rgba = vec![255, 0, 0, 255, 0, 0, 255, 255];
        let (mirrored, w, h) = orient(rgba.clone(), 2, 1, 2);
        assert_eq!((w, h, &mirrored[..4]), (2, 1, &[0, 0, 255, 255][..]));
        let (rotated, w, h) = orient(rgba.clone(), 2, 1, 6);
        assert_eq!((w, h, &rotated[..4]), (1, 2, &[255, 0, 0, 255][..]));
        let (rotated, w, h) = orient(rgba.clone(), 2, 1, 8);
        assert_eq!((w, h, &rotated[..4]), (1, 2, &[0, 0, 255, 255][..]));
        for orientation in [0, 1, 9, 255] {
            assert_eq!(orient(rgba.clone(), 2, 1, orientation).0, rgba);
        }
        let jpeg = jpeg_fixture(64, 32, Some(6));
        let header = jpeg_header(&mut Cursor::new(&jpeg), 0, jpeg.len() as u64).unwrap();
        assert_eq!(header.orientation, Some(6));
        assert_eq!(plan_bytes(&jpeg, 256).unwrap().orientation, 6);
    }

    #[test]
    fn renders_png_gif_and_webp() {
        let png = render_bytes(&png_fixture(30, 20, false), 256, BUDGET).unwrap();
        assert_eq!(png.media_type, "image/jpeg");
        let alpha = render_bytes(&png_fixture(30, 20, true), 256, BUDGET).unwrap();
        assert_eq!(alpha.media_type, "image/png");
        let gif = render_bytes(&gif_fixture(600, 300), 256, BUDGET).unwrap();
        assert_eq!(gif.media_type, "image/jpeg");
        let header = jpeg_header(&mut Cursor::new(&gif.bytes), 0, gif.bytes.len() as u64).unwrap();
        assert_eq!((header.width, header.height), (256, 128));
        let webp = render_bytes(&webp_fixture(500, 250, false), 256, BUDGET).unwrap();
        assert_eq!(webp.media_type, "image/jpeg");
        let webp_alpha = render_bytes(&webp_fixture(50, 25, true), 256, BUDGET).unwrap();
        assert_eq!(webp_alpha.media_type, "image/png");
    }

    #[test]
    fn tiny_budgets_and_lying_headers_are_refused() {
        let jpeg = jpeg_fixture(400, 300, None);
        assert_eq!(
            render_bytes(&jpeg, 256, 1024),
            Err(ThumbnailError::TooLarge)
        );

        // A PNG header claiming more than the pixel cap.
        let mut png = png_fixture(4, 4, false);
        png[16..20].copy_from_slice(&100_000_u32.to_be_bytes());
        png[20..24].copy_from_slice(&100_000_u32.to_be_bytes());
        assert_eq!(plan_bytes(&png, 256), Err(ThumbnailError::TooLarge));

        // Truncated and garbage inputs fail without panicking.
        for data in [
            &png_fixture(30, 30, false)[..60],
            &jpeg[..200],
            &gif_fixture(20, 20)[..30],
            &webp_fixture(20, 20, false)[..30],
            b"GIF89a".as_slice(),
            b"\xff\xd8\xff".as_slice(),
            b"RIFF\0\0\0\0WEBP".as_slice(),
            b"II*\0\x08\0\0\0".as_slice(),
            b"".as_slice(),
            b"plain text".as_slice(),
        ] {
            assert!(render_bytes(data, 256, BUDGET).is_err(), "{data:?}");
        }
        assert_eq!(
            plan_bytes(b"plain text", 256),
            Err(ThumbnailError::Unsupported)
        );
    }

    #[test]
    fn raw_containers_yield_their_largest_jpeg_preview() {
        let preview = jpeg_fixture(320, 200, None);
        let dng = raw_fixture(&preview, 6);
        let found = raw_preview(&mut Cursor::new(&dng), dng.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!((found.header.width, found.header.height), (320, 200));
        assert_eq!(found.orientation, 6);
        assert_eq!(found.length, preview.len() as u64);
        let plan = plan_bytes(&dng, 256).unwrap();
        assert_eq!(plan.kind, SourceKind::Raw);
        let rendered = render(Cursor::new(&dng), &plan).unwrap();
        let header = jpeg_header(
            &mut Cursor::new(&rendered.bytes),
            0,
            rendered.bytes.len() as u64,
        )
        .unwrap();
        assert_eq!((header.width, header.height), (160, 256));

        // Preview offsets past the end, previews that are not JPEG, and
        // CFA data marked as JPEG-compressed are all skipped.
        let mut tiff = TiffBuilder::new();
        let junk = tiff.blob(b"not a jpeg at all");
        let ifd = tiff.ifd(
            &[
                (0x0201, 4, 1, junk),
                (0x0202, 4, 1, 17),
                (0x0111, 4, 1, 0x7fff_0000),
                (0x0117, 4, 1, 4096),
            ],
            0,
        );
        tiff.set_first_ifd(ifd);
        assert_eq!(
            raw_preview(&mut Cursor::new(&tiff.bytes), tiff.bytes.len() as u64).unwrap(),
            None
        );
        let mut cfa = TiffBuilder::new();
        let data = cfa.blob(&preview);
        let ifd = cfa.ifd(
            &[
                (0x0103, 3, 1, 7),
                (0x0106, 3, 1, 32803),
                (0x0111, 4, 1, data),
                (0x0117, 4, 1, u32::try_from(preview.len()).unwrap()),
            ],
            0,
        );
        cfa.set_first_ifd(ifd);
        assert_eq!(
            plan_bytes(&cfa.bytes, 256),
            Err(ThumbnailError::Unsupported)
        );
    }

    #[test]
    fn a_source_above_the_byte_cap_is_refused_before_reading() {
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(
            plan(&mut empty, MAX_SOURCE_BYTES + 1, 256),
            Err(ThumbnailError::TooLarge)
        );
    }

    #[test]
    fn jpeg_output_decodes_to_the_input_without_metadata() {
        let (width, height) = (37_u32, 21_u32);
        let mut rgba = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let red = if x < width / 2 { 220 } else { 30 };
                rgba.extend_from_slice(&[red, (y * 10) as u8, 90, 255]);
            }
        }
        let jpeg = encode_jpeg(&rgba, width, height).unwrap();

        // SOI and the JFIF APP0, then no other APPn (EXIF, ICC, …) or
        // comment segment before the scan.
        assert_eq!(&jpeg[..4], &[0xff, 0xd8, 0xff, 0xe0]);
        assert_eq!(&jpeg[6..11], b"JFIF\0");
        let mut position = 2;
        let mut markers = Vec::new();
        while jpeg[position + 1] != 0xda {
            assert_eq!(jpeg[position], 0xff);
            markers.push(jpeg[position + 1]);
            position +=
                2 + usize::from(u16::from_be_bytes([jpeg[position + 2], jpeg[position + 3]]));
        }
        assert_eq!(markers[0], 0xe0);
        assert!(
            markers[1..]
                .iter()
                .all(|marker| matches!(marker, 0xc0 | 0xc4 | 0xdb)),
            "{markers:x?}"
        );
        let header = jpeg_header(&mut Cursor::new(&jpeg), 0, jpeg.len() as u64).unwrap();
        assert!(!header.progressive);
        assert_eq!(header.orientation, None);

        let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(&jpeg));
        let pixels = decoder.decode().unwrap();
        let info = decoder.info().unwrap();
        assert_eq!(
            (u32::from(info.width), u32::from(info.height)),
            (width, height)
        );
        assert_eq!(pixels.len(), (width * height * 3) as usize);
        let mut worst = 0_i32;
        for (index, decoded) in pixels.as_chunks::<3>().0.iter().enumerate() {
            let x = index as u32 % width;
            // Skip the colour edge, where 4:2:0 chroma legitimately blurs.
            if x.abs_diff(width / 2) <= 2 {
                continue;
            }
            let original = &rgba[index * 4..index * 4 + 3];
            for channel in 0..3 {
                worst =
                    worst.max((i32::from(decoded[channel]) - i32::from(original[channel])).abs());
            }
        }
        assert!(worst <= 24, "worst channel error {worst}");
    }

    #[test]
    fn dense_jpeg_output_fits_its_reserve_and_the_estimate() {
        // Binary RGB noise: every 8×8 block is all high-frequency detail.
        let (width, height) = (512_u32, 384_u32);
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rgba = Vec::new();
        for _ in 0..width * height {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bit = |mask: u64| if state & mask == 0 { 0 } else { 255 };
            rgba.extend_from_slice(&[bit(1), bit(2), bit(4), 255]);
        }
        let jpeg = encode_jpeg(&rgba, width, height).unwrap();
        let reserve = jpeg_output_reserve(width, height);
        assert!(jpeg.len() <= reserve, "{} > {reserve}", jpeg.len());
        // The buffer never grew past what was reserved.
        assert_eq!(jpeg.capacity(), reserve);
        let band = (width as usize).next_multiple_of(16) * 16 * 3;
        assert!(encode_estimate(width, height) >= (band + jpeg.capacity()) as u64);
        // PNG output stays budgeted at four bytes per pixel, in either
        // orientation, and above the JPEG encoder's peak.
        assert_eq!(encode_estimate(1600, 1067), 1600 * 1067 * 4);
        assert_eq!(encode_estimate(1067, 1600), encode_estimate(1600, 1067));
        assert!(encode_estimate(1, 1) >= (16 * 16 * 3 + 4097 * 3) as u64);
    }
}

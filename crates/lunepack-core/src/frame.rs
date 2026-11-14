//! Frames (FORMAT.md 9): the frame descriptor of a manifest file entry, its structural check,
//! and verify-then-decode.
//!
//! [`FrameDesc::check`] validates a descriptor against its file and the pack without touching any
//! byte and without allocating anything sized by a declared value. [`decode_verified`] then takes
//! the frame's bytes through FORMAT.md 9.2 in order: exact byte count, frame hash (before any
//! decoder sees a byte), stream split, decode into an exact-size hashing writer, consumed counts,
//! file hash.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::digest::{Sha256Digest, U53};
use crate::error::{Error, FrameError, Result, Untrusted};
use crate::traits::{Codec, CodecId, FrameView, HashState, Hasher, StreamView};
use crate::trust::present;

/// Smallest LZMA2 dictionary a descriptor may declare.
pub const MIN_DICT_SIZE: u64 = 4096;
/// Largest LZMA2 dictionary a descriptor may declare (16 MiB).
pub const MAX_DICT_SIZE: u64 = 16 * 1024 * 1024;
/// Decoder memory beyond the signed dictionaries, per codec (M4-D13). Each constant is the peak
/// heap measured by `lunepack-codec-lzma/tests/memory.rs` (a counting allocator, a frame at the
/// 16 MiB maximum dictionary), minus the dictionaries, times at least 1.25, rounded up to the next
/// 256 KiB. That test fails when a constant falls below its measurement plus 25 %, or when a
/// peak passes [`decoder_memory`].
///
/// The measured overhead is mostly not fixed state: `lzma-rust2` 0.25 grows each window by
/// doubling, and the last doubling holds the old block (half the dictionary) and the new one at
/// once, as the counting allocator sees any `realloc`. So an LZMA2 stream peaks at about 1.5
/// dictionaries, and the constants below cover half of 16 MiB. A smaller dictionary peaks lower,
/// so the budget over-charges small frames, never under-charges.
///
/// `stored` decodes straight from its input: 0. The I/O buffers around a decode are charged by the
/// stage engine (M4-D11), not here.
pub const DECODER_OVERHEAD_STORED_BYTES: u64 = 0;
/// `lzma2`: measured 8 519 715 bytes (8 MiB of growth plus 131 107 bytes of reader state and the
/// codec's copy buffer); with headroom, 41 × 256 KiB.
pub const DECODER_OVERHEAD_LZMA2_BYTES: u64 = 41 * 256 * 1024;
/// `bcj-x86+lzma2`: measured 8 523 811 bytes (the BCJ filter's 4 KiB buffer on top of `lzma2`);
/// with headroom, 41 × 256 KiB.
pub const DECODER_OVERHEAD_BCJ_X86_LZMA2_BYTES: u64 = 41 * 256 * 1024;
/// `bcj-arm64+lzma2`: measured 8 523 811 bytes, the same as x86; with headroom, 41 × 256 KiB.
pub const DECODER_OVERHEAD_BCJ_ARM64_LZMA2_BYTES: u64 = 41 * 256 * 1024;
/// `bcj2`, on top of its three dictionaries: measured 9 748 401 bytes (8 MiB of growth, the BCJ2
/// reader's four 256 KiB buffers and the three LZMA2 readers' state); with headroom, 47 × 256 KiB.
pub const DECODER_OVERHEAD_BCJ2_BYTES: u64 = 47 * 256 * 1024;

const BCJ2_STREAMS: usize = 4;
const RC: usize = 3;

/// One BCJ2 sub-stream as written (FORMAT.md 9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDesc {
    /// Encoded bytes of the sub-stream, at least 1.
    pub length: U53,
    /// Bytes it decodes to.
    pub decoded_size: U53,
    /// LZMA2 dictionary for MAIN, CALL and JUMP; absent for RC.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub dict_size: Option<U53>,
}

/// A file entry's `frame` as written (FORMAT.md 9.0). The writer serialises whatever it is given;
/// [`FrameDesc::check`] checks every field. `codec` is kept as text so an unknown id is reported
/// as [`Error::UnknownCodec`] rather than as a schema error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameDesc {
    /// The codec id, compared byte for byte.
    pub codec: String,
    /// Offset of the frame in the pack.
    pub offset: U53,
    /// Frame length in bytes, at least 1.
    pub length: U53,
    /// SHA-256 of the frame's bytes.
    pub sha256: Sha256Digest,
    /// LZMA2 variants only.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub dict_size: Option<U53>,
    /// `bcj2` only: MAIN, CALL, JUMP, RC.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub streams: Option<Vec<StreamDesc>>,
}

/// One stream of a checked frame: where it sits in the frame and what the decoder may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckedStream {
    start: u64,
    length: u64,
    decoded_size: u64,
    dict_size: Option<u32>,
}

/// A frame descriptor that passed [`FrameDesc::check`], bound to its file's size and hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedFrame {
    codec: CodecId,
    offset: u64,
    length: u64,
    sha256: Sha256Digest,
    file_size: u64,
    file_sha256: Sha256Digest,
    streams: Vec<CheckedStream>,
}

impl CheckedFrame {
    /// The codec.
    pub fn codec(&self) -> CodecId {
        self.codec
    }

    /// Offset in the pack.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Frame length.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// The frame's signed SHA-256.
    pub fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    /// The decoded file's size.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// The decoded file's signed SHA-256.
    pub fn file_sha256(&self) -> Sha256Digest {
        self.file_sha256
    }
}

fn dict(value: Option<U53>, codec: CodecId) -> Result<u32> {
    let value = value
        .ok_or(FrameError::MissingField {
            field: "dict_size",
            codec: codec.id(),
        })?
        .get();
    if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&value) || !value.is_power_of_two() {
        return Err(FrameError::DictSize { value }.into());
    }
    // In range, so it fits.
    Ok(value as u32)
}

fn foreign(field: &'static str, codec: CodecId) -> Error {
    FrameError::ForeignField {
        field,
        codec: codec.id(),
    }
    .into()
}

/// Checks a file entry's frame presence (FORMAT.md 8.1): a frame exactly when `file_size > 0`.
/// Returns the checked frame, or `None` for an empty file.
pub fn check_file_frame(
    frame: Option<&FrameDesc>,
    file_size: u64,
    file_sha256: Sha256Digest,
    pack_size: u64,
) -> Result<Option<CheckedFrame>> {
    match (frame, file_size) {
        (None, 0) => Ok(None),
        (Some(desc), size) if size > 0 => desc.check(size, file_sha256, pack_size).map(Some),
        _ => Err(FrameError::Presence.into()),
    }
}

impl FrameDesc {
    /// Structural check (FORMAT.md 9.0, 9.1), pure and byte-free: codec id in the closed set
    /// (byte for byte); `length >= 1`; `offset + length <= pack_size` without overflow; no field
    /// of another codec; `stored`: `length == file_size` and frame hash == file hash; LZMA2
    /// variants: `dict_size` a power of two in `4096 ..= 16 MiB`; `bcj2`: exactly four streams,
    /// each `length >= 1`, MAIN/CALL/JUMP with a valid `dict_size` and `decoded_size <= file_size`,
    /// RC without `dict_size` and `length == decoded_size`, lengths summing exactly to `length`.
    pub fn check(
        &self,
        file_size: u64,
        file_sha256: Sha256Digest,
        pack_size: u64,
    ) -> Result<CheckedFrame> {
        let codec = CodecId::from_id(&self.codec)
            .ok_or_else(|| Error::UnknownCodec(Untrusted::new(&self.codec)))?;
        let offset = self.offset.get();
        let length = self.length.get();
        if length == 0 {
            return Err(FrameError::ZeroLength.into());
        }
        match offset.checked_add(length) {
            Some(end) if end <= pack_size => {}
            _ => return Err(FrameError::OutOfPack.into()),
        }

        let streams = match codec {
            CodecId::Stored => {
                if self.dict_size.is_some() {
                    return Err(foreign("dict_size", codec));
                }
                if self.streams.is_some() {
                    return Err(foreign("streams", codec));
                }
                if length != file_size || self.sha256 != file_sha256 {
                    return Err(FrameError::StoredMismatch.into());
                }
                vec![CheckedStream {
                    start: 0,
                    length,
                    decoded_size: file_size,
                    dict_size: None,
                }]
            }
            CodecId::Lzma2 | CodecId::BcjX86Lzma2 | CodecId::BcjArm64Lzma2 => {
                if self.streams.is_some() {
                    return Err(foreign("streams", codec));
                }
                let dict_size = dict(self.dict_size, codec)?;
                vec![CheckedStream {
                    start: 0,
                    length,
                    decoded_size: file_size,
                    dict_size: Some(dict_size),
                }]
            }
            CodecId::Bcj2 => {
                if self.dict_size.is_some() {
                    return Err(foreign("dict_size", codec));
                }
                let descs = self.streams.as_deref().ok_or(FrameError::MissingField {
                    field: "streams",
                    codec: codec.id(),
                })?;
                if descs.len() != BCJ2_STREAMS {
                    return Err(FrameError::StreamCount { count: descs.len() }.into());
                }
                let mut streams = Vec::with_capacity(BCJ2_STREAMS);
                let mut start = 0u64;
                for (index, s) in descs.iter().enumerate() {
                    let stream_err = |reason| FrameError::Stream { index, reason };
                    let len = s.length.get();
                    let decoded = s.decoded_size.get();
                    if len == 0 {
                        return Err(stream_err("length is 0").into());
                    }
                    let dict_size = if index == RC {
                        if s.dict_size.is_some() {
                            return Err(stream_err("RC has no dict_size").into());
                        }
                        if len != decoded {
                            return Err(stream_err("RC length differs from decoded_size").into());
                        }
                        None
                    } else {
                        if decoded > file_size {
                            return Err(stream_err("decoded_size exceeds the file size").into());
                        }
                        let value = s.dict_size.ok_or_else(|| stream_err("dict_size missing"))?;
                        Some(dict(Some(value), codec)?)
                    };
                    streams.push(CheckedStream {
                        start,
                        length: len,
                        decoded_size: decoded,
                        dict_size,
                    });
                    start = start.checked_add(len).ok_or(FrameError::LengthSum)?;
                }
                if start != length {
                    return Err(FrameError::LengthSum.into());
                }
                streams
            }
        };
        Ok(CheckedFrame {
            codec,
            offset,
            length,
            sha256: self.sha256,
            file_size,
            file_sha256,
            streams,
        })
    }
}

/// Decoder memory a frame may need (C3's budget input, M4-D13): its signed dictionaries (one for
/// the LZMA2 variants, three for `bcj2`, none for `stored`) plus the overhead constant of its codec.
pub fn decoder_memory(frame: &CheckedFrame) -> u64 {
    let overhead = match frame.codec {
        CodecId::Stored => DECODER_OVERHEAD_STORED_BYTES,
        CodecId::Lzma2 => DECODER_OVERHEAD_LZMA2_BYTES,
        CodecId::BcjX86Lzma2 => DECODER_OVERHEAD_BCJ_X86_LZMA2_BYTES,
        CodecId::BcjArm64Lzma2 => DECODER_OVERHEAD_BCJ_ARM64_LZMA2_BYTES,
        CodecId::Bcj2 => DECODER_OVERHEAD_BCJ2_BYTES,
    };
    frame
        .streams
        .iter()
        .filter_map(|s| s.dict_size)
        .map(u64::from)
        .sum::<u64>()
        + overhead
}

/// A checked frame split over its (hash-verified) bytes, ready for the codec.
pub(crate) struct ParsedFrame<'a> {
    codec: CodecId,
    output_size: u64,
    streams: Vec<StreamView<'a>>,
}

impl<'a> ParsedFrame<'a> {
    /// Splits `bytes` into the frame's streams. `bytes` must be exactly the frame's length; the
    /// split uses only checked offsets, so it never panics and allocates at most four views.
    pub(crate) fn parse(frame: &CheckedFrame, bytes: &'a [u8]) -> Result<ParsedFrame<'a>> {
        if bytes.len() as u64 != frame.length {
            return Err(FrameError::ByteCount {
                expected: frame.length,
                actual: bytes.len() as u64,
            }
            .into());
        }
        let mut streams = Vec::with_capacity(frame.streams.len());
        for s in &frame.streams {
            let input = usize::try_from(s.start)
                .ok()
                .zip(usize::try_from(s.length).ok())
                .and_then(|(start, len)| bytes.get(start..start.checked_add(len)?))
                .ok_or(FrameError::LengthSum)?;
            streams.push(StreamView {
                input,
                decoded_size: s.decoded_size,
                dict_size: s.dict_size,
            });
        }
        Ok(ParsedFrame {
            codec: frame.codec,
            output_size: frame.file_size,
            streams,
        })
    }

    pub(crate) fn view(&self) -> FrameView<'_> {
        FrameView {
            codec: self.codec,
            output_size: self.output_size,
            streams: &self.streams,
        }
    }
}

/// Passes at most `remaining` bytes to `inner` and hashes them; a write that would go past
/// `remaining` fails without writing anything and is remembered.
struct ExactWriter<'w> {
    inner: &'w mut dyn Write,
    remaining: u64,
    written: u64,
    overflowed: bool,
    /// The first error the caller's writer returned: remembered because a codec may swallow it
    /// and keep writing, and `written` and the hash cover only accepted buffers. It is the cause
    /// of the `OutputWrite` error.
    failed: Option<io::Error>,
    hash: Option<Box<dyn HashState>>,
}

impl Write for ExactWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.overflowed || buf.len() as u64 > self.remaining {
            self.overflowed = true;
            return Err(io::Error::other("decoded output exceeds the file size"));
        }
        if self.failed.is_some() {
            return Err(io::Error::other("the output writer failed earlier"));
        }
        if let Err(e) = self.inner.write_all(buf) {
            // The codec gets an error of the same kind; the writer's own is kept as the cause.
            let kind = e.kind();
            self.failed = Some(e);
            return Err(io::Error::new(kind, "the output writer failed"));
        }
        if let Some(hash) = self.hash.as_mut() {
            hash.update(buf);
        }
        self.remaining -= buf.len() as u64;
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // A codec may ignore a flush error and return `Ok`, so it is latched like a write error.
        if let Err(e) = self.inner.flush() {
            let kind = e.kind();
            self.failed.get_or_insert(e);
            return Err(io::Error::new(kind, "the output writer failed"));
        }
        Ok(())
    }
}

/// Verifies and decodes one frame (FORMAT.md 9.2), in order: `frame_bytes` is exactly the
/// frame's length (checked before hashing); its SHA-256 equals the signed one (the codec is
/// never called otherwise); the streams are split; the codec decodes into a writer that fails as
/// soon as the output would exceed the file's size; then the output must be exactly the file's
/// size, every stream consumed exactly, and the output's SHA-256 equal to the file's.
///
/// `out` receives decoded bytes as they are produced. **On any error the caller must discard
/// everything `out` received**; only `Ok(())` means the bytes are the signed file.
pub fn decode_verified(
    frame: &CheckedFrame,
    frame_bytes: &[u8],
    hasher: &dyn Hasher,
    codec: &dyn Codec,
    out: &mut dyn Write,
) -> Result<()> {
    if frame_bytes.len() as u64 != frame.length {
        return Err(FrameError::ByteCount {
            expected: frame.length,
            actual: frame_bytes.len() as u64,
        }
        .into());
    }
    if hasher.sha256(frame_bytes) != frame.sha256 {
        return Err(FrameError::FrameHash.into());
    }
    let parsed = ParsedFrame::parse(frame, frame_bytes)?;

    let mut writer = ExactWriter {
        inner: out,
        remaining: frame.file_size,
        written: 0,
        overflowed: false,
        failed: None,
        hash: Some(hasher.sha256_start()),
    };
    let result = codec.decode(&parsed.view(), &mut writer);
    // An overflow is reported even when the codec swallowed the write error.
    if writer.overflowed {
        return Err(FrameError::OutputTooLong {
            size: frame.file_size,
        }
        .into());
    }
    // So is a failure of the caller's writer: `out` may hold part of a rejected buffer.
    if let Some(source) = writer.failed.take() {
        return Err(FrameError::OutputWrite(source).into());
    }
    let report = result?;
    if writer.written != frame.file_size {
        return Err(FrameError::OutputTooShort {
            expected: frame.file_size,
            actual: writer.written,
        }
        .into());
    }
    if report.consumed.len() != frame.streams.len() {
        return Err(FrameError::Consumed {
            index: report.consumed.len().min(frame.streams.len()),
            consumed: 0,
            length: 0,
        }
        .into());
    }
    for (index, (s, &consumed)) in frame.streams.iter().zip(&report.consumed).enumerate() {
        if consumed != s.length {
            return Err(FrameError::Consumed {
                index,
                consumed,
                length: s.length,
            }
            .into());
        }
    }
    let digest = writer.hash.take().map(|h| h.finalize());
    if digest != Some(frame.file_sha256) {
        return Err(FrameError::FileHash.into());
    }
    Ok(())
}

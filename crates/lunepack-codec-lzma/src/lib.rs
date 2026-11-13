//! LZMA2 codec adapter over the pure-Rust `lzma-rust2` (D34): decodes and encodes the five codec
//! ids of FORMAT.md 9 (`stored`, `lzma2`, `bcj-x86+lzma2`, `bcj-arm64+lzma2`, `bcj2`).
//!
//! Decoding allocates its dictionaries only from the signed `dict_size`s and checks every stream
//! against its signed `decoded_size` (the core's `Codec` contract). Encoding uses fixed settings
//! (liblzma's preset 9e, single-threaded, M3-D7), so the bytes depend only on the codec and the
//! input, never on the host.

mod decode;
mod encode;

use std::io::Write;

use lunepack_core::{Codec, CodecId, DecodeReport, EncodedFrame, Encoder, Error, FrameView};

/// The LZMA codec: a [`Codec`] and an [`Encoder`] for every codec id of format v1.
#[derive(Debug, Clone, Copy, Default)]
pub struct LzmaCodec;

impl Codec for LzmaCodec {
    fn decode(&self, frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
        decode::decode(frame, out)
    }
}

impl Encoder for LzmaCodec {
    fn encode(&self, codec: CodecId, input: &[u8]) -> Result<EncodedFrame, Error> {
        encode::encode(codec, input)
    }

    /// An upper bound on everything one `encode` call holds besides its input: for the LZMA2
    /// variants, `lzma-rust2`'s estimate (`LzmaOptions::get_memory_usage`, KiB) for the
    /// dictionary `input_len` selects plus the output buffer (reserved up front at
    /// `input_len + input_len / 1024 + 64`, so it never grows) and the BCJ filter's buffer; for
    /// `bcj2`, that state plus the BCJ2 writer's four 16 KiB buffers plus
    /// `5 × input_len + input_len / 512 + 512` for its raw split streams, their encoded forms and
    /// the assembled frame (derived in `encode::memory`); for `stored`, the copy.
    fn encode_memory(&self, codec: CodecId, input_len: u64) -> u64 {
        encode::memory(codec, input_len)
    }
}

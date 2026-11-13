//! Encoding with fixed settings (M3-D7): liblzma's 9e, a dictionary sized from each stream's
//! length, single-threaded and unchunked, BCJ start offset 0. Nothing here reads the host.

use std::io::{self, Write};

use lunepack_core::error::CodecError;
use lunepack_core::frame::{MAX_DICT_SIZE, MIN_DICT_SIZE};
use lunepack_core::{CodecId, EncodedFrame, EncodedStream, Error};
use lzma_rust2::filter::bcj::BcjWriter;
use lzma_rust2::filter::bcj2::{Bcj2Options, Bcj2Writer};
use lzma_rust2::{EncodeMode, Lzma2Options, Lzma2Writer, LzmaOptions, MfType};

/// The BCJ2 writer's four output buffers (`lzma-rust2`, filter/bcj2/encode.rs).
const BCJ2_WRITER_BUFFERS: u64 = 4 * 16 * 1024;

/// `clamp(next_pow2(len), 4096, 16 MiB)`: the smallest power-of-two dictionary that holds the
/// whole stream, within FORMAT.md 9.0's range.
fn dict_size_for(len: u64) -> u32 {
    let pow2 = len.checked_next_power_of_two().unwrap_or(u64::MAX);
    let dict = pow2.clamp(MIN_DICT_SIZE, MAX_DICT_SIZE);
    u32::try_from(dict).expect("MAX_DICT_SIZE fits in u32")
}

/// liblzma's preset 9e with the given dictionary.
fn options_9e(dict_size: u32) -> LzmaOptions {
    let mut opts = LzmaOptions::with_preset(9);
    opts.dict_size = dict_size;
    opts.lc = 3;
    opts.lp = 0;
    opts.pb = 2;
    opts.mode = EncodeMode::Normal;
    opts.mf = MfType::Bt4;
    opts.nice_len = 273;
    opts.depth_limit = 512;
    opts
}

fn writer(dict_size: u32) -> Lzma2Writer<Vec<u8>> {
    Lzma2Writer::new(
        Vec::new(),
        Lzma2Options {
            lzma_options: options_9e(dict_size),
            chunk_size: None,
        },
    )
}

fn encoder_err(e: io::Error) -> Error {
    CodecError::Encoder(Box::new(e)).into()
}

#[derive(Clone, Copy)]
enum Bcj {
    None,
    X86,
    Arm64,
}

/// One raw LZMA2 stream over `input`, with the BCJ filter first when asked.
fn lzma2(input: &[u8], bcj: Bcj) -> Result<(Vec<u8>, u32), Error> {
    let dict_size = dict_size_for(input.len() as u64);
    let lz = writer(dict_size);
    let bytes = match bcj {
        Bcj::None => {
            let mut lz = lz;
            lz.write_all(input).map_err(encoder_err)?;
            lz.finish().map_err(encoder_err)?
        }
        Bcj::X86 | Bcj::Arm64 => {
            let mut w = match bcj {
                Bcj::X86 => BcjWriter::new_x86(lz, 0),
                _ => BcjWriter::new_arm64(lz, 0),
            };
            w.write_all(input).map_err(encoder_err)?;
            // Outer first: the filter's held tail bytes go into LZMA2, then LZMA2 ends.
            w.finish()
                .map_err(encoder_err)?
                .finish()
                .map_err(encoder_err)?
        }
    };
    Ok((bytes, dict_size))
}

fn empty_stream() -> Error {
    encoder_err(io::Error::other("an encoded stream is empty"))
}

pub(crate) fn encode(codec: CodecId, input: &[u8]) -> Result<EncodedFrame, Error> {
    // A frame is at least one byte (FORMAT.md 9.0); an empty file has no frame.
    if input.is_empty() {
        return Err(empty_stream());
    }
    let single = |bcj| -> Result<EncodedFrame, Error> {
        let (bytes, dict_size) = lzma2(input, bcj)?;
        Ok(EncodedFrame {
            codec,
            bytes,
            dict_size: Some(dict_size),
            streams: None,
        })
    };
    match codec {
        CodecId::Stored => Ok(EncodedFrame {
            codec,
            bytes: input.to_vec(),
            dict_size: None,
            streams: None,
        }),
        CodecId::Lzma2 => single(Bcj::None),
        CodecId::BcjX86Lzma2 => single(Bcj::X86),
        CodecId::BcjArm64Lzma2 => single(Bcj::Arm64),
        CodecId::Bcj2 => bcj2(input),
    }
}

fn bcj2(input: &[u8]) -> Result<EncodedFrame, Error> {
    let options = Bcj2Options {
        uncompressed_size: Some(input.len() as u64),
        relative_limit: Bcj2Options::RELATIVE_LIMIT_DEFAULT,
    };
    let mut w =
        Bcj2Writer::new(std::array::from_fn(|_| Vec::new()), &options).map_err(encoder_err)?;
    w.write_all(input).map_err(encoder_err)?;
    let [main, call, jump, rc] = w.finish().map_err(encoder_err)?;

    let mut bytes = Vec::new();
    let mut streams = Vec::with_capacity(4);
    for raw in [&main, &call, &jump] {
        let (encoded, dict_size) = lzma2(raw, Bcj::None)?;
        if encoded.is_empty() {
            return Err(empty_stream());
        }
        streams.push(EncodedStream {
            length: encoded.len() as u64,
            decoded_size: raw.len() as u64,
            dict_size: Some(dict_size),
        });
        bytes.extend_from_slice(&encoded);
    }
    if rc.is_empty() {
        return Err(empty_stream());
    }
    streams.push(EncodedStream {
        length: rc.len() as u64,
        decoded_size: rc.len() as u64,
        dict_size: None,
    });
    bytes.extend_from_slice(&rc);
    Ok(EncodedFrame {
        codec: CodecId::Bcj2,
        bytes,
        dict_size: None,
        streams: Some(streams),
    })
}

pub(crate) fn memory(codec: CodecId, input_len: u64) -> u64 {
    let lzma = || u64::from(options_9e(dict_size_for(input_len)).get_memory_usage()) * 1024;
    match codec {
        CodecId::Stored => input_len,
        CodecId::Lzma2 | CodecId::BcjX86Lzma2 | CodecId::BcjArm64Lzma2 => lzma(),
        // Each of MAIN, CALL and JUMP is at most `input_len` long, and the three are encoded one
        // after the other, so the largest bounds them all.
        CodecId::Bcj2 => lzma() + BCJ2_WRITER_BUFFERS,
    }
}

#[cfg(test)]
mod tests {
    use super::dict_size_for;

    #[test]
    fn dict_size_rule() {
        assert_eq!(dict_size_for(0), 4096);
        assert_eq!(dict_size_for(1), 4096);
        assert_eq!(dict_size_for(3000), 4096);
        assert_eq!(dict_size_for(4097), 8192);
        assert_eq!(dict_size_for(1 << 20), 1 << 20);
        assert_eq!(dict_size_for((1 << 20) + 1), 2 << 20);
        assert_eq!(dict_size_for(20 << 20), 16 << 20);
        assert_eq!(dict_size_for(u64::MAX), 16 << 20);
    }
}

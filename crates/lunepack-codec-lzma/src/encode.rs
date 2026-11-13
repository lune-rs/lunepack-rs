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

/// The x86 and ARM64 BCJ writers' buffer (`lzma-rust2`, filter/bcj.rs `FILTER_BUF_SIZE`).
const BCJ_WRITER_BUFFER: u64 = 4096;

/// An upper bound on the length of the raw LZMA2 stream `lzma-rust2` writes for `len` input bytes:
/// `len + len / 1024 + 64`.
///
/// `Lzma2Writer` writes a chunk compressed only when its compressed size plus 2 is below its
/// uncompressed size `u` (so with its 5 or 6 byte header it takes at most `u + 3` bytes), and
/// otherwise stores it in pieces of at most 64 KiB behind a 3-byte header; one end byte follows.
/// A chunk ends at 64 KiB of range-coder output or 2 MiB of input, and LZMA spends at most 16
/// bytes of output per input byte, so every chunk but the last holds at least 4 KiB of input and
/// costs at most 3 + 3 bytes per 64 KiB more than its input: under `len / 1024 + 64` in total.
/// `tests::lzma2_output_fits_its_reservation` checks the bound on incompressible and adversarial
/// inputs.
fn lzma2_out_max(len: usize) -> usize {
    len.saturating_add(len / 1024).saturating_add(64)
}

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

fn writer(dict_size: u32, out: Vec<u8>) -> Lzma2Writer<Vec<u8>> {
    Lzma2Writer::new(
        out,
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
///
/// The output buffer is reserved at [`lzma2_out_max`] up front, so it never grows (and never
/// holds twice its length while it doubles): [`memory`] counts exactly that reservation.
fn lzma2(input: &[u8], bcj: Bcj) -> Result<(Vec<u8>, u32), Error> {
    let dict_size = dict_size_for(input.len() as u64);
    let lz = writer(dict_size, Vec::with_capacity(lzma2_out_max(input.len())));
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

    // Each raw stream is dropped as soon as it is encoded, and the frame is assembled in a buffer
    // of exactly its length once every stream is known (the peak [`memory`] accounts for).
    let mut encoded = Vec::with_capacity(3);
    let mut streams = Vec::with_capacity(4);
    for raw in [main, call, jump] {
        let (stream, dict_size) = lzma2(&raw, Bcj::None)?;
        if stream.is_empty() {
            return Err(empty_stream());
        }
        streams.push(EncodedStream {
            length: stream.len() as u64,
            decoded_size: raw.len() as u64,
            dict_size: Some(dict_size),
        });
        encoded.push(stream);
    }
    if rc.is_empty() {
        return Err(empty_stream());
    }
    streams.push(EncodedStream {
        length: rc.len() as u64,
        decoded_size: rc.len() as u64,
        dict_size: None,
    });
    let total = encoded.iter().map(Vec::len).sum::<usize>() + rc.len();
    let mut bytes = Vec::with_capacity(total);
    for stream in encoded {
        bytes.extend_from_slice(&stream);
    }
    bytes.extend_from_slice(&rc);
    Ok(EncodedFrame {
        codec: CodecId::Bcj2,
        bytes,
        dict_size: None,
        streams: Some(streams),
    })
}

/// An upper bound on the bytes one [`encode`] call holds at once, `input` excluded: the encoder
/// state, the writers' buffers, every intermediate buffer and the returned frame's buffer.
///
/// - `stored`: the copy, `n` bytes.
/// - The LZMA2 variants: the encoder state (`lzma-rust2`'s `get_memory_usage`, KiB, for the
///   dictionary `n` selects) plus the output reservation [`lzma2_out_max`]`(n)`, plus the BCJ
///   writer's buffer for the filtered ones.
/// - `bcj2`: the encoder state and the BCJ2 writer's buffers, plus `5n + n/512 + 512` for its
///   buffers, derived from the code above and `lzma-rust2` 0.25 (filter/bcj2/encode.rs):
///   - the writer moves each converted branch's 4 operand bytes to CALL or JUMP and keeps every
///     other byte in MAIN, so MAIN + CALL + JUMP = `n`; it codes one range-coder bit per E8/E9/
///     0F8x byte, and with 11-bit probabilities clamped to 31..=2017 a bit narrows the range by
///     at most 6.05 bits, so it causes at most one output byte: RC ≤ `n + 6` (one leading byte and
///     five flush bytes). A `Vec` that grows by appending holds at most `max(2 × len, 8)`, so the
///     four raw streams hold at most `2(n + n + 6) + 32 = 4n + 44`;
///   - encoding MAIN, CALL and JUMP (each with a state no larger than `n`'s, since its dictionary
///     is no larger) adds their reserved outputs, `Σ lzma2_out_max(len) ≤ n + n/1024 + 192`;
///     with the raw streams that is at most `5n + n/1024 + 236`;
///   - assembling the frame drops the three raw streams first; it then holds the encoded streams
///     (`≤ n + n/1024 + 192`), RC (`≤ 2n + 20`) and the exact-length frame
///     (`≤ n + n/1024 + 192 + n + 6`): at most `5n + n/512 + 410`.
///
/// `tests::bcj2_split_bounds` checks the split and RC bounds on adversarial inputs.
pub(crate) fn memory(codec: CodecId, input_len: u64) -> u64 {
    let n = input_len;
    let state = u64::from(options_9e(dict_size_for(n)).get_memory_usage()) * 1024;
    let out = n.saturating_add(n / 1024).saturating_add(64);
    match codec {
        CodecId::Stored => n,
        CodecId::Lzma2 => state.saturating_add(out),
        CodecId::BcjX86Lzma2 | CodecId::BcjArm64Lzma2 => {
            state.saturating_add(out).saturating_add(BCJ_WRITER_BUFFER)
        }
        CodecId::Bcj2 => state
            .saturating_add(BCJ2_WRITER_BUFFERS)
            .saturating_add(n.saturating_mul(5))
            .saturating_add(n / 512)
            .saturating_add(512),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lunepack_core::CodecId;
    use lzma_rust2::filter::bcj2::{Bcj2Options, Bcj2Writer};

    use super::{Bcj, dict_size_for, encode, lzma2, lzma2_out_max, memory};

    /// Fixed-seed xorshift64 noise.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Inputs that stress the bounds: incompressible noise, every byte a BCJ2 marker, markers
    /// whose operands never convert, markers with converting operands, and noise salted with
    /// markers so the range coder sees unpredictable bits.
    fn adversarial(len: usize) -> Vec<(&'static str, Vec<u8>)> {
        let salted: Vec<u8> = noise(3, len)
            .into_iter()
            .enumerate()
            .map(|(i, b)| if i % 3 == 0 { 0xE8 | (b & 1) } else { b })
            .collect();
        let converting: Vec<u8> = (0..len)
            .map(|i| match i % 5 {
                0 => 0xE8,
                1 => 0x10,
                _ => 0,
            })
            .collect();
        vec![
            ("noise", noise(1, len)),
            ("all E8", vec![0xE8; len]),
            ("all E9 FF", [0xE9, 0xFF].repeat(len / 2)),
            ("converting calls", converting),
            ("salted noise", salted),
        ]
    }

    #[test]
    fn lzma2_output_fits_its_reservation() {
        for len in [0, 1, 4096, 1 << 18] {
            for (what, input) in adversarial(len) {
                for bcj in [Bcj::None, Bcj::X86, Bcj::Arm64] {
                    let (out, _) = lzma2(&input, bcj).unwrap();
                    assert!(
                        out.len() <= lzma2_out_max(input.len()),
                        "{what}, {len}: {} > {}",
                        out.len(),
                        lzma2_out_max(input.len())
                    );
                }
            }
        }
    }

    #[test]
    fn bcj2_split_bounds() {
        let mut framed = 0;
        for len in [1, 5, 4096, 1 << 18] {
            for (what, input) in adversarial(len) {
                let options = Bcj2Options {
                    uncompressed_size: Some(input.len() as u64),
                    relative_limit: Bcj2Options::RELATIVE_LIMIT_DEFAULT,
                };
                let mut w = Bcj2Writer::new(std::array::from_fn(|_| Vec::new()), &options).unwrap();
                w.write_all(&input).unwrap();
                let [main, call, jump, rc] = w.finish().unwrap();
                let n = input.len();
                assert_eq!(main.len() + call.len() + jump.len(), n, "{what}, {len}");
                assert!(rc.len() <= n + 6, "{what}, {len}: rc {}", rc.len());
                for s in [&main, &call, &jump, &rc] {
                    assert!(s.capacity() <= (2 * s.len()).max(8), "{what}, {len}");
                }
                // The returned frame's buffer is exactly its length (an input with an empty
                // stream has no `bcj2` frame).
                if let Ok(frame) = encode(CodecId::Bcj2, &input) {
                    assert_eq!(frame.bytes.capacity(), frame.bytes.len(), "{what}, {len}");
                    framed += 1;
                }
            }
        }
        assert!(framed >= 8, "only {framed} inputs made a bcj2 frame");
    }

    #[test]
    fn memory_counts_the_buffers() {
        let n = 10 << 20;
        let lz = memory(CodecId::Lzma2, n);
        assert!(lz >= n, "the output reservation is counted");
        assert!(memory(CodecId::BcjX86Lzma2, n) > lz);
        assert!(memory(CodecId::Bcj2, n) >= lz - n - n / 1024 - 64 + 5 * n);
        assert_eq!(memory(CodecId::Stored, n), n);
        assert_eq!(memory(CodecId::Bcj2, u64::MAX), u64::MAX);
    }

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

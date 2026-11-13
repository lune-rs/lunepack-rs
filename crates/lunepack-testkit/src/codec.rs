//! A fake codec honouring the frame layout: real `stored`, and a reversible toy transform for the
//! compressed ids, with fault knobs for the failure cases a caller must survive.

use std::io::Write;

use lunepack_core::error::CodecError;
use lunepack_core::frame::{MAX_DICT_SIZE, MIN_DICT_SIZE};
use lunepack_core::{
    Codec, CodecId, DecodeReport, EncodedFrame, EncodedStream, Encoder, Error, FrameView,
    StreamView,
};

/// XOR key of the toy transform.
const TOY_KEY: u8 = 0x5A;
/// Last byte of every toy-encoded stream; stands in for the end of an LZMA2 stream.
const TOY_END: u8 = 0xA5;

/// A fault the codec injects while decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Writes one byte more than the streams decode to.
    ExtraBytes,
    /// Withholds the last output byte.
    TooFewBytes,
    /// Reports a consumed count of the first stream that is off by one.
    WrongConsumed,
    /// Writes half of the first stream's output, then fails.
    ErrorMidStream,
    /// Panics if `decode` is called at all (for "the codec is never called" checks).
    PanicIfCalled,
    /// Writes the output, then keeps writing 4 KiB chunks until a write fails, and returns that
    /// error (an over-producing decoder that stops on the first write error). Gives up and returns
    /// `Ok` after 64 MiB of extra output, so a writer that never fails cannot hang a test.
    Flood,
    /// Writes one byte more than the output, ignores the write error and returns `Ok` (a decoder
    /// that swallows write errors).
    ExtraBytesIgnoringErrors,
    /// Writes every stream's output; when a write fails it ignores the error and writes the same
    /// bytes again (a decoder that swallows write errors and retries), then returns `Ok`.
    RetryAfterWriteError,
}

/// Extra 4 KiB chunks [`Fault::Flood`] writes at most.
const FLOOD_CHUNKS: usize = 16 * 1024;

/// The fake codec. `Stored` is the real thing. A compressed id is encoded by [`FakeCodec::encode`]
/// as `data ^ 0x5A` followed by one end byte, per stream; BCJ2 is four such streams (the last one
/// stored) whose outputs are concatenated in order. Not a compressor: test-only.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeCodec {
    fault: Option<Fault>,
}

impl FakeCodec {
    /// A codec with no fault.
    pub fn new() -> Self {
        FakeCodec::default()
    }

    /// A codec that injects `fault`.
    pub fn with_fault(fault: Fault) -> Self {
        FakeCodec { fault: Some(fault) }
    }

    /// Encodes `data` as a frame of `codec`. For `Bcj2`, `data` is split into MAIN, CALL, JUMP and
    /// RC parts of nearly equal size (the remainder goes to MAIN); data shorter than 4 bytes puts
    /// its last byte in RC (the format wants an RC stream of at least one byte) and the rest in
    /// MAIN.
    ///
    /// # Panics
    ///
    /// Panics when `codec` is `Bcj2` and `data` is empty.
    pub fn encode(codec: CodecId, data: &[u8]) -> FakeEncoded {
        let parts: Vec<&[u8]> = match codec {
            CodecId::Bcj2 => {
                assert!(!data.is_empty(), "bcj2 toy encoding needs at least 1 byte");
                let (call_len, rc_len) = if data.len() >= 4 {
                    (data.len() / 4, data.len() / 4)
                } else {
                    (0, 1)
                };
                let main = data.len() - 2 * call_len - rc_len;
                vec![
                    &data[..main],
                    &data[main..main + call_len],
                    &data[main + call_len..main + 2 * call_len],
                    &data[main + 2 * call_len..],
                ]
            }
            _ => vec![data],
        };
        let mut frame = Vec::new();
        let mut streams = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let offset = frame.len();
            if stream_is_stored(codec, i) {
                frame.extend_from_slice(part);
            } else {
                frame.extend(part.iter().map(|b| b ^ TOY_KEY));
                frame.push(TOY_END);
            }
            streams.push(FakeStreamLayout {
                offset,
                length: frame.len() - offset,
                decoded_size: part.len() as u64,
            });
        }
        FakeEncoded {
            codec,
            frame,
            streams,
            output_size: data.len() as u64,
        }
    }
}

fn stream_is_stored(codec: CodecId, index: usize) -> bool {
    codec == CodecId::Stored || (codec == CodecId::Bcj2 && index == 3)
}

/// Where one stream sits inside an encoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeStreamLayout {
    /// Byte offset inside the frame.
    pub offset: usize,
    /// Encoded length.
    pub length: usize,
    /// Decoded length.
    pub decoded_size: u64,
}

/// A frame produced by [`FakeCodec::encode`].
#[derive(Debug, Clone)]
pub struct FakeEncoded {
    /// The codec the frame is for.
    pub codec: CodecId,
    /// The frame's bytes.
    pub frame: Vec<u8>,
    /// Its streams, in order.
    pub streams: Vec<FakeStreamLayout>,
    /// Size of the decoded file.
    pub output_size: u64,
}

impl FakeEncoded {
    /// The stream views for a [`FrameView`]. Compressed streams carry `dict_size`; stored ones
    /// (the `stored` codec and BCJ2's RC stream) carry none.
    pub fn views(&self, dict_size: u32) -> Vec<StreamView<'_>> {
        self.streams
            .iter()
            .enumerate()
            .map(|(i, s)| StreamView {
                input: &self.frame[s.offset..s.offset + s.length],
                decoded_size: s.decoded_size,
                dict_size: if stream_is_stored(self.codec, i) {
                    None
                } else {
                    Some(dict_size)
                },
            })
            .collect()
    }
}

/// The dictionary [`FakeCodec`] declares for a stream decoding to `decoded` bytes: the next power
/// of two, clamped to the format's range (the rule the real encoder follows, M3-D7).
fn fake_dict(decoded: u64) -> u32 {
    let dict = decoded
        .max(1)
        .next_power_of_two()
        .clamp(MIN_DICT_SIZE, MAX_DICT_SIZE);
    // Clamped to at most 16 MiB, so it fits.
    dict as u32
}

impl Encoder for FakeCodec {
    fn encode(&self, codec: CodecId, input: &[u8]) -> Result<EncodedFrame, Error> {
        if input.is_empty() {
            return Err(CodecError::Encoder("the toy encoder needs at least 1 byte".into()).into());
        }
        let enc = FakeCodec::encode(codec, input);
        let (dict_size, streams) = match codec {
            CodecId::Stored => (None, None),
            CodecId::Bcj2 => (
                None,
                Some(
                    enc.streams
                        .iter()
                        .enumerate()
                        .map(|(i, s)| EncodedStream {
                            length: s.length as u64,
                            decoded_size: s.decoded_size,
                            dict_size: (i < 3).then(|| fake_dict(s.decoded_size)),
                        })
                        .collect(),
                ),
            ),
            _ => (Some(fake_dict(input.len() as u64)), None),
        };
        Ok(EncodedFrame {
            codec,
            bytes: enc.frame,
            dict_size,
            streams,
        })
    }

    fn encode_memory(&self, _codec: CodecId, input_len: u64) -> u64 {
        // One copy of the input per stream at most, plus the frame.
        input_len.saturating_mul(2).saturating_add(64)
    }
}

impl Codec for FakeCodec {
    fn decode(&self, frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
        assert!(
            self.fault != Some(Fault::PanicIfCalled),
            "FakeCodec::decode called with Fault::PanicIfCalled"
        );
        let expected_streams = if frame.codec == CodecId::Bcj2 { 4 } else { 1 };
        if frame.streams.len() != expected_streams {
            return Err(CodecError::Corrupt("wrong stream count").into());
        }
        let mut consumed = Vec::with_capacity(frame.streams.len());
        let mut decoded: Vec<Vec<u8>> = Vec::with_capacity(frame.streams.len());
        for (i, stream) in frame.streams.iter().enumerate() {
            let stored = stream_is_stored(frame.codec, i);
            if stored != stream.dict_size.is_none() {
                return Err(CodecError::Corrupt("dictionary size does not fit the codec").into());
            }
            let data = if stored {
                stream.input.to_vec()
            } else {
                match stream.input.split_last() {
                    Some((&TOY_END, body)) => body.iter().map(|b| b ^ TOY_KEY).collect(),
                    _ => return Err(CodecError::Corrupt("missing end marker").into()),
                }
            };
            if data.len() as u64 != stream.decoded_size {
                return Err(CodecError::StreamSize {
                    index: i,
                    expected: stream.decoded_size,
                    actual: data.len() as u64,
                }
                .into());
            }
            // The toy has no matches to reach back: a stream longer than its dictionary (up to the
            // format's cap) stands in for a distance the dictionary cannot hold.
            if let Some(dict) = stream.dict_size
                && stream.decoded_size <= MAX_DICT_SIZE
                && stream.decoded_size > u64::from(dict)
            {
                return Err(CodecError::Corrupt("stream is longer than its dictionary").into());
            }
            consumed.push(stream.input.len() as u64);
            decoded.push(data);
        }

        let write =
            |out: &mut dyn Write, bytes: &[u8]| out.write_all(bytes).map_err(CodecError::Write);
        match self.fault {
            Some(Fault::ErrorMidStream) => {
                let first = &decoded[0];
                write(out, &first[..first.len() / 2])?;
                return Err(CodecError::Corrupt("injected mid-stream error").into());
            }
            Some(Fault::TooFewBytes) => {
                let all: Vec<u8> = decoded.concat();
                write(out, &all[..all.len().saturating_sub(1)])?;
            }
            Some(Fault::RetryAfterWriteError) => {
                for part in &decoded {
                    if out.write_all(part).is_err() {
                        let _ = out.write_all(part);
                    }
                }
            }
            _ => {
                for part in &decoded {
                    write(out, part)?;
                }
            }
        }
        if self.fault == Some(Fault::ExtraBytes) {
            write(out, &[0])?;
        }
        if self.fault == Some(Fault::Flood) {
            for _ in 0..FLOOD_CHUNKS {
                write(out, &[0x77; 4096])?;
            }
        }
        if self.fault == Some(Fault::ExtraBytesIgnoringErrors) {
            let _ = out.write_all(&[0]);
        }
        if self.fault == Some(Fault::WrongConsumed) {
            consumed[0] = if consumed[0] == 0 { 1 } else { consumed[0] - 1 };
        }
        Ok(DecodeReport { consumed })
    }
}

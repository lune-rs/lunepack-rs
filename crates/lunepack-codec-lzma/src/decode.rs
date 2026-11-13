//! Decoding: a pull pipeline of `lzma-rust2` readers over each stream's bytes, drained into the
//! caller's (exact-size) writer.
//!
//! Every stream is read through two wrappers whose counters the decoder reads afterwards:
//! [`Counted`] records the encoded bytes the reader really pulled (the `consumed` report), and
//! [`Limited`] passes at most the stream's signed `decoded_size` and fails on the first byte past
//! it. Dictionaries come only from the signed `dict_size`; nothing is sized from stream bytes.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::rc::Rc;

use lunepack_core::error::CodecError;
use lunepack_core::frame::{MAX_DICT_SIZE, MIN_DICT_SIZE};
use lunepack_core::{CodecId, DecodeReport, Error, FrameView, StreamView};
use lzma_rust2::filter::bcj::BcjReader;
use lzma_rust2::filter::bcj2::Bcj2Reader;
use lzma_rust2::{Lzma2Reader, lzma2_get_memory_usage};

/// Bytes moved from the decoder to the writer per read.
const COPY_BUF: usize = 64 * 1024;

/// Counters of one stream, shared by its reader chain and the decoder that checks them after.
#[derive(Default)]
struct Tally {
    /// Encoded bytes pulled from the stream's input.
    consumed: Cell<u64>,
    /// Decoded bytes passed on (at most `decoded_size`).
    produced: Cell<u64>,
    /// The stream had more decoded bytes than its `decoded_size`.
    overflow: Cell<bool>,
}

/// A stream's encoded bytes, counting what the reader pulls.
struct Counted<'a> {
    input: &'a [u8],
    tally: Rc<Tally>,
}

impl Read for Counted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.input.read(buf)?;
        self.tally
            .consumed
            .set(self.tally.consumed.get() + n as u64);
        Ok(n)
    }
}

/// Passes at most `limit` decoded bytes of `inner`. At the limit, one more read must find the
/// stream's end; a further byte is an error and sets `overflow`.
struct Limited<R> {
    inner: R,
    limit: u64,
    tally: Rc<Tally>,
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let produced = self.tally.produced.get();
        let room = self.limit.saturating_sub(produced);
        if room == 0 {
            // Draining to the end also reads an LZMA2 stream's end marker, so `consumed` counts it.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.tally.overflow.set(true);
                    Err(io::Error::other("a stream decodes past its decoded_size"))
                }
            };
        }
        let take = usize::try_from(room).map_or(buf.len(), |room| room.min(buf.len()));
        let n = self.inner.read(&mut buf[..take])?;
        self.tally.produced.set(produced + n as u64);
        Ok(n)
    }
}

type Lzma2Stream<'a> = Limited<Lzma2Reader<Counted<'a>>>;

/// BCJ2's inputs: three LZMA2 streams and the stored RC stream.
enum Bcj2Input<'a> {
    Lzma2(Box<Lzma2Stream<'a>>),
    Stored(Limited<Counted<'a>>),
}

impl Read for Bcj2Input<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Bcj2Input::Lzma2(r) => r.read(buf),
            Bcj2Input::Stored(r) => r.read(buf),
        }
    }
}

fn corrupt(reason: &'static str) -> Error {
    CodecError::Corrupt(reason).into()
}

/// The signed dictionary size, range-checked again (core checked it; this decoder may also be
/// called directly).
fn signed_dict(stream: &StreamView<'_>) -> Result<u32, Error> {
    let dict = stream
        .dict_size
        .ok_or_else(|| corrupt("an LZMA2 stream has no dict_size"))?;
    let wide = u64::from(dict);
    if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&wide) || !dict.is_power_of_two() {
        return Err(corrupt("dict_size is outside the format's range"));
    }
    Ok(dict)
}

fn lzma2_stream<'a>(stream: &StreamView<'a>, tally: &Rc<Tally>) -> Result<Lzma2Stream<'a>, Error> {
    let dict = signed_dict(stream)?;
    // The limit comes from the signed size alone: the reader refuses before allocating if its
    // dictionary plus overhead would need more.
    let mem_limit_kb = lzma2_get_memory_usage(dict);
    let input = Counted {
        input: stream.input,
        tally: Rc::clone(tally),
    };
    let reader = Lzma2Reader::new_mem_limit(input, dict, mem_limit_kb, None)
        .map_err(|e| Error::from(CodecError::Decoder(Box::new(e))))?;
    Ok(Limited {
        inner: reader,
        limit: stream.decoded_size,
        tally: Rc::clone(tally),
    })
}

/// How draining a reader into `out` ended badly.
enum PumpError {
    Read(io::Error),
    Write(io::Error),
}

/// Reads `r` to its end into `out`, stopping at the first write error.
fn pump(mut r: impl Read, out: &mut dyn Write) -> Result<(), PumpError> {
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(PumpError::Read(e)),
        };
        out.write_all(&buf[..n]).map_err(PumpError::Write)?;
    }
}

/// The error for a failed read: a stream that passed its `decoded_size` first, else the
/// library's error as the cause.
fn read_error(e: io::Error, streams: &[StreamView<'_>], tallies: &[Rc<Tally>]) -> Error {
    for (index, (s, t)) in streams.iter().zip(tallies).enumerate() {
        if t.overflow.get() {
            return CodecError::StreamSize {
                index,
                expected: s.decoded_size,
                // Decoding stopped at the first byte past the limit.
                actual: s.decoded_size + 1,
            }
            .into();
        }
    }
    CodecError::Decoder(Box::new(e)).into()
}

fn pump_error(e: PumpError, streams: &[StreamView<'_>], tallies: &[Rc<Tally>]) -> Error {
    match e {
        PumpError::Write(e) => CodecError::Write(e).into(),
        PumpError::Read(e) => read_error(e, streams, tallies),
    }
}

/// Every stream decoded to exactly its `decoded_size`; the report of what each consumed.
fn report(streams: &[StreamView<'_>], tallies: &[Rc<Tally>]) -> Result<DecodeReport, Error> {
    for (index, (s, t)) in streams.iter().zip(tallies).enumerate() {
        let actual = t.produced.get();
        if actual != s.decoded_size {
            return Err(CodecError::StreamSize {
                index,
                expected: s.decoded_size,
                actual,
            }
            .into());
        }
    }
    Ok(DecodeReport {
        consumed: tallies.iter().map(|t| t.consumed.get()).collect(),
    })
}

pub(crate) fn decode(frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
    match frame.codec {
        CodecId::Stored => stored(frame, out),
        CodecId::Lzma2 | CodecId::BcjX86Lzma2 | CodecId::BcjArm64Lzma2 => single(frame, out),
        CodecId::Bcj2 => bcj2(frame, out),
    }
}

fn stored(frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
    let [s] = frame.streams else {
        return Err(corrupt("a stored frame has one stream"));
    };
    let len = s.input.len() as u64;
    if len != s.decoded_size || len != frame.output_size {
        return Err(CodecError::StreamSize {
            index: 0,
            expected: s.decoded_size,
            actual: len,
        }
        .into());
    }
    out.write_all(s.input).map_err(CodecError::Write)?;
    Ok(DecodeReport {
        consumed: vec![len],
    })
}

fn single(frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
    let streams = frame.streams;
    let [s] = streams else {
        return Err(corrupt("an LZMA2 frame has one stream"));
    };
    if s.decoded_size != frame.output_size {
        return Err(corrupt("the stream's decoded_size is not the output size"));
    }
    let tallies = [Rc::new(Tally::default())];
    let r = lzma2_stream(s, &tallies[0])?;
    let res = match frame.codec {
        CodecId::BcjX86Lzma2 => pump(BcjReader::new_x86(r, 0), out),
        CodecId::BcjArm64Lzma2 => pump(BcjReader::new_arm64(r, 0), out),
        _ => pump(r, out),
    };
    res.map_err(|e| pump_error(e, streams, &tallies))?;
    report(streams, &tallies)
}

fn bcj2(frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
    let streams = frame.streams;
    let [main, call, jump, rc] = streams else {
        return Err(corrupt("a bcj2 frame has four streams"));
    };
    let tallies: [Rc<Tally>; 4] = std::array::from_fn(|_| Rc::new(Tally::default()));
    let inputs = vec![
        Bcj2Input::Lzma2(Box::new(lzma2_stream(main, &tallies[0])?)),
        Bcj2Input::Lzma2(Box::new(lzma2_stream(call, &tallies[1])?)),
        Bcj2Input::Lzma2(Box::new(lzma2_stream(jump, &tallies[2])?)),
        Bcj2Input::Stored(Limited {
            inner: Counted {
                input: rc.input,
                tally: Rc::clone(&tallies[3]),
            },
            limit: rc.decoded_size,
            tally: Rc::clone(&tallies[3]),
        }),
    ];
    let mut reader = Bcj2Reader::try_new(inputs, frame.output_size)
        .map_err(|e| Error::from(CodecError::Decoder(Box::new(e))))?;
    // The reader stops at `output_size`; `finish` then checks that every input has ended (it
    // reads one more byte from each, which `Limited` bounds to the stream).
    pump(&mut reader, out).map_err(|e| pump_error(e, streams, &tallies))?;
    reader
        .finish()
        .map_err(|e| read_error(e, streams, &tallies))?;
    report(streams, &tallies)
}

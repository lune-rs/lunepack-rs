//! Decoder heap peak per codec (M4 step 6, M4-D13).
//!
//! A counting global allocator (`peak_alloc`, a dev-dependency without dependencies of its own)
//! measures the peak heap of one `Codec::decode` call: the frame's bytes and its descriptor exist
//! before the measured region and the writer discards, so the number is what the decoder holds.
//! `peak_alloc` counts a `realloc` as an allocation of the new block while the old one is still
//! live, so it is an upper bound for any system allocator, which matters: `lzma-rust2` 0.25 grows
//! each LZMA2 window geometrically up to the signed dictionary, and the last doubling holds the
//! old and the new block at once (half a dictionary on top of it).
//!
//! `decoder_memory` (core, `frame.rs`) is the budget input stage charges per frame. This test
//! pins the measurement below it, at the maximum dictionary, for every codec, and checks that
//! every per-codec constant is at least 25 % above what was measured.
//!
//! Large frames are not made by the encoder (preset 9e takes minutes on 16 MiB in a debug build):
//! each LZMA2 stream is a real encoded head, so the decoder's LZMA state and probabilities are
//! live, followed by stored (uncompressed) chunks that fill the window. The decoded bytes are not
//! checked here (the contract suite and the known-answer tests do that); only the memory is.
//!
//! This is one test on purpose: the allocator counters are process-wide, so a second test running
//! in parallel would add its own allocations to the peak.

use std::hint::black_box;
use std::io::{self, Write};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::frame::{MAX_DICT_SIZE, decoder_memory};
use lunepack_core::{
    Codec, CodecId, Encoder, FrameDesc, FrameView, Hasher, StreamDesc, StreamView, U53,
};
use lunepack_testkit::FakeHasher;
use lzma_rust2::filter::bcj2::{Bcj2Options, Bcj2Writer};
use peak_alloc::PeakAlloc;

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
/// Real encoder output at the head of every LZMA2 stream.
const HEAD: usize = 32 * KIB;

/// Peak heap bytes above the level at the start of `f`, and `f`'s result.
fn measure<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = ALLOC.current_usage();
    ALLOC.reset_peak_usage();
    let result = f();
    let peak = ALLOC.peak_usage().saturating_sub(base);
    (result, peak)
}

/// A writer that drops everything, so the measured region holds no output.
struct Sink;

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn u53(value: u64) -> U53 {
    U53::new(value).expect("below 2^53")
}

/// An LZMA2 stream that decodes to `raw`: `raw[..HEAD]` encoded for real, then the rest in stored
/// chunks of at most 64 KiB (control byte 2: uncompressed, no dictionary reset), then the end
/// marker.
fn lzma2_with_stored_tail(raw: &[u8]) -> Vec<u8> {
    let head = raw.len().min(HEAD);
    let mut stream = LzmaCodec
        .encode(CodecId::Lzma2, &raw[..head])
        .expect("encode the head")
        .bytes;
    assert_eq!(
        stream.pop(),
        Some(0),
        "an LZMA2 stream ends with its end marker"
    );
    for chunk in raw[head..].chunks(64 * KIB) {
        let size = u16::try_from(chunk.len() - 1).expect("at most 64 KiB");
        stream.push(2);
        stream.extend_from_slice(&size.to_be_bytes());
        stream.extend_from_slice(chunk);
    }
    stream.push(0);
    stream
}

/// Filler bytes: one random 64 KiB block, repeated.
fn filler(len: usize) -> Vec<u8> {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let block: Vec<u8> = (0..64 * KIB).map(|_| (rng.next() >> 32) as u8).collect();
    block.iter().copied().cycle().take(len).collect()
}

/// x86-like data with `items` branches: two filler bytes, a CALL or JMP opcode (alternating) and
/// a small relative operand each, so BCJ2 moves every operand to CALL or JUMP.
fn x86_like(items: usize) -> Vec<u8> {
    let mut rng = XorShift(0xD6E8_FEB8_6659_FD93);
    let mut out = Vec::with_capacity(items * 7);
    for i in 0..items {
        out.push(0x48 + (rng.next() >> 61) as u8);
        out.push(0x48 + (rng.next() >> 61) as u8);
        out.push(if i % 2 == 0 { 0xE8 } else { 0xE9 });
        let rel = ((rng.next() >> 48) as i32 % 4096) - 2048;
        out.extend_from_slice(&rel.to_le_bytes());
    }
    out
}

/// A frame ready to decode: its bytes, descriptor and decoded size. Only the descriptor's shape
/// matters here, so the digests are placeholders.
struct Frame {
    id: CodecId,
    bytes: Vec<u8>,
    desc: FrameDesc,
    output_size: u64,
}

fn single(id: CodecId, raw_len: usize) -> Frame {
    let bytes = lzma2_with_stored_tail(&filler(raw_len));
    Frame {
        id,
        desc: FrameDesc {
            codec: id.id().to_owned(),
            offset: u53(0),
            length: u53(bytes.len() as u64),
            sha256: FakeHasher.sha256(&[]),
            dict_size: Some(u53(MAX_DICT_SIZE)),
            streams: None,
        },
        bytes,
        output_size: raw_len as u64,
    }
}

fn stored(len: usize) -> Frame {
    let bytes = filler(len);
    Frame {
        id: CodecId::Stored,
        desc: FrameDesc {
            codec: CodecId::Stored.id().to_owned(),
            offset: u53(0),
            length: u53(len as u64),
            sha256: FakeHasher.sha256(&[]),
            dict_size: None,
            streams: None,
        },
        bytes,
        output_size: len as u64,
    }
}

/// A BCJ2 frame whose MAIN, CALL and JUMP streams each decode to at least a full 16 MiB window.
fn bcj2() -> Frame {
    let data = x86_like(8_800_000);
    let options = Bcj2Options {
        uncompressed_size: Some(data.len() as u64),
        relative_limit: Bcj2Options::RELATIVE_LIMIT_DEFAULT,
    };
    let mut writer =
        Bcj2Writer::new(std::array::from_fn(|_| Vec::new()), &options).expect("bcj2 writer");
    writer.write_all(&data).expect("bcj2 split");
    let [main, call, jump, rc] = writer.finish().expect("bcj2 finish");
    for (name, raw) in [("MAIN", &main), ("CALL", &call), ("JUMP", &jump)] {
        assert!(
            raw.len() >= MAX_DICT_SIZE as usize,
            "{name} decodes to {} bytes, below the 16 MiB window",
            raw.len()
        );
    }

    let mut bytes = Vec::new();
    let mut streams = Vec::new();
    for raw in [&main, &call, &jump] {
        let stream = lzma2_with_stored_tail(raw);
        streams.push(StreamDesc {
            length: u53(stream.len() as u64),
            decoded_size: u53(raw.len() as u64),
            dict_size: Some(u53(MAX_DICT_SIZE)),
        });
        bytes.extend_from_slice(&stream);
    }
    streams.push(StreamDesc {
        length: u53(rc.len() as u64),
        decoded_size: u53(rc.len() as u64),
        dict_size: None,
    });
    bytes.extend_from_slice(&rc);
    Frame {
        id: CodecId::Bcj2,
        desc: FrameDesc {
            codec: CodecId::Bcj2.id().to_owned(),
            offset: u53(0),
            length: u53(bytes.len() as u64),
            sha256: FakeHasher.sha256(&[]),
            dict_size: None,
            streams: Some(streams),
        },
        bytes,
        output_size: data.len() as u64,
    }
}

/// What one decode measured.
struct Measured {
    /// Peak heap bytes of the decode.
    peak: u64,
    /// `decoder_memory` of the frame, as signed.
    budget: u64,
    /// The signed dictionaries added up.
    dicts: u64,
}

fn decode_peak(frame: &Frame) -> Measured {
    let checked = frame
        .desc
        .check(frame.output_size, FakeHasher.sha256(&[]), u64::MAX >> 12)
        .expect("a descriptor core accepts");
    let dict = |d: Option<U53>| d.map(|d| u32::try_from(d.get()).expect("fits u32"));
    let mut views = Vec::new();
    match &frame.desc.streams {
        Some(streams) => {
            let mut at = 0usize;
            for s in streams {
                let len = usize::try_from(s.length.get()).expect("fits");
                views.push(StreamView {
                    input: &frame.bytes[at..at + len],
                    decoded_size: s.decoded_size.get(),
                    dict_size: dict(s.dict_size),
                });
                at += len;
            }
        }
        None => views.push(StreamView {
            input: &frame.bytes,
            decoded_size: frame.output_size,
            dict_size: dict(frame.desc.dict_size),
        }),
    }
    let dicts = views
        .iter()
        .filter_map(|v| v.dict_size)
        .map(u64::from)
        .sum();
    let view = FrameView {
        codec: frame.id,
        output_size: frame.output_size,
        streams: &views,
    };
    let (report, peak) = measure(|| LzmaCodec.decode(&view, &mut Sink));
    let report = report.expect("the frame decodes");
    assert_eq!(report.consumed.len(), views.len());
    Measured {
        peak: peak as u64,
        budget: decoder_memory(&checked),
        dicts,
    }
}

#[test]
fn decoder_peak_is_within_decoder_memory() {
    // The instrument first: a Vec of exactly 8 MiB inside the region reads as 8 MiB and a bit.
    let (_, calibration) = measure(|| black_box(vec![0u8; 8 * MIB]));
    println!("calibration (8 MiB Vec): {calibration} bytes");
    assert!(
        (8 * MIB..8 * MIB + 64 * KIB).contains(&calibration),
        "the counting allocator reads {calibration} for an 8 MiB allocation"
    );

    let frames = [
        ("stored", stored(2 * MIB)),
        ("lzma2", single(CodecId::Lzma2, 17 * MIB)),
        ("bcj-x86+lzma2", single(CodecId::BcjX86Lzma2, 17 * MIB)),
        ("bcj-arm64+lzma2", single(CodecId::BcjArm64Lzma2, 17 * MIB)),
        ("bcj2", bcj2()),
    ];
    for (name, frame) in &frames {
        let m = decode_peak(frame);
        let overhead_seen = m.peak.saturating_sub(m.dicts);
        let overhead_const = m.budget - m.dicts;
        println!(
            "{name}: peak {} bytes, dictionaries {} bytes, measured overhead {overhead_seen} bytes, \
             decoder_memory {} bytes (constant {overhead_const})",
            m.peak, m.dicts, m.budget
        );
        if frame.id == CodecId::Stored {
            // The constant is 0 and the I/O buffers are charged apart (M4-D11); what remains is the
            // report's one-element vector.
            assert!(
                m.peak <= 64,
                "{name}: a stored frame decoded with {} bytes",
                m.peak
            );
            continue;
        }
        assert!(
            m.peak <= m.budget,
            "{name}: peak {} exceeds decoder_memory {}",
            m.peak,
            m.budget
        );
        assert!(
            overhead_const * 4 >= overhead_seen * 5,
            "{name}: the overhead constant {overhead_const} has less than 25 % headroom over the \
             measured {overhead_seen}"
        );
    }
}

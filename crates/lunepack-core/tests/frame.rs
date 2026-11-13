//! Step 9: frame descriptors, their structural check and verify-then-decode, with the testkit
//! fakes (FakeHasher is not SHA-256, FakeCodec is a toy transform with fault knobs).

use std::sync::atomic::{AtomicUsize, Ordering};

use lunepack_core::digest::{Sha256Digest, U53};
use lunepack_core::error::{CodecError, FrameError};
use lunepack_core::frame::{DECODER_OVERHEAD_BYTES, MAX_DICT_SIZE};
use lunepack_core::json::parse_strict;
use lunepack_core::{
    CheckedFrame, CodecId, Error, FrameDesc, HashState, Hasher, StreamDesc, check_file_frame,
    decode_verified, decoder_memory,
};
use lunepack_testkit::{FakeCodec, FakeEncoded, FakeHasher, Fault};

const ALL: [CodecId; 5] = [
    CodecId::Stored,
    CodecId::Lzma2,
    CodecId::BcjX86Lzma2,
    CodecId::BcjArm64Lzma2,
    CodecId::Bcj2,
];
const DICT: u64 = 65_536;
const PACK_PREFIX: u64 = 100;

fn u53(v: u64) -> U53 {
    U53::new(v).unwrap()
}

fn data() -> Vec<u8> {
    (0..1000u32).map(|i| (i * 7 % 256) as u8).collect()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    FakeHasher.sha256(bytes)
}

/// The descriptor the writer would emit for `enc` placed at `PACK_PREFIX` in a pack.
fn desc_for(enc: &FakeEncoded) -> FrameDesc {
    let lzma = !matches!(enc.codec, CodecId::Stored | CodecId::Bcj2);
    FrameDesc {
        codec: enc.codec.id().to_owned(),
        offset: u53(PACK_PREFIX),
        length: u53(enc.frame.len() as u64),
        sha256: sha(&enc.frame),
        dict_size: lzma.then(|| u53(DICT)),
        streams: (enc.codec == CodecId::Bcj2).then(|| {
            enc.streams
                .iter()
                .enumerate()
                .map(|(i, s)| StreamDesc {
                    length: u53(s.length as u64),
                    decoded_size: u53(s.decoded_size),
                    dict_size: (i < 3).then(|| u53(DICT)),
                })
                .collect()
        }),
    }
}

fn pack_size(enc: &FakeEncoded) -> u64 {
    PACK_PREFIX + enc.frame.len() as u64
}

fn checked(codec: CodecId) -> (FakeEncoded, CheckedFrame) {
    let d = data();
    let enc = FakeCodec::encode(codec, &d);
    let frame = desc_for(&enc)
        .check(d.len() as u64, sha(&d), pack_size(&enc))
        .unwrap_or_else(|e| panic!("{codec:?}: {e}"));
    (enc, frame)
}

fn check_err(desc: &FrameDesc) -> Error {
    let d = data();
    desc.check(d.len() as u64, sha(&d), 1 << 40)
        .expect_err("descriptor must be rejected")
}

fn frame_err(err: Error) -> FrameError {
    match err {
        Error::Frame(e) => e,
        other => panic!("expected a frame error, got {other:?}"),
    }
}

// ---- descriptor check ----

#[test]
fn writer_descriptors_check_for_every_codec() {
    for id in ALL {
        let (enc, frame) = checked(id);
        assert_eq!(frame.codec(), id);
        assert_eq!(frame.length(), enc.frame.len() as u64);
        assert_eq!(frame.offset(), PACK_PREFIX);
        assert_eq!(frame.file_size(), data().len() as u64);
    }
}

#[test]
fn unknown_codec_ids_fail_closed() {
    let (enc, _) = checked(CodecId::Lzma2);
    for id in [
        "LZMA2",
        "Lzma2",
        "zstd",
        "",
        "lzma2 ",
        "bcj-x86+LZMA2",
        "Stored",
        "BCJ2",
        "xz",
    ] {
        let mut desc = desc_for(&enc);
        desc.codec = id.to_owned();
        assert!(
            matches!(check_err(&desc), Error::UnknownCodec(_)),
            "{id:?} accepted"
        );
    }
}

#[test]
fn dict_size_must_be_a_power_of_two_in_range() {
    let (enc, _) = checked(CodecId::Lzma2);
    let d = data();
    for ok in [4096, 8192, 1 << 20, MAX_DICT_SIZE] {
        let mut desc = desc_for(&enc);
        desc.dict_size = Some(u53(ok));
        desc.check(d.len() as u64, sha(&d), 1 << 40).unwrap();
    }
    for bad in [
        0,
        1,
        2048,
        4095,
        4097,
        6144,
        MAX_DICT_SIZE + 1,
        MAX_DICT_SIZE * 2,
        (1 << 53) - 1,
    ] {
        let mut desc = desc_for(&enc);
        desc.dict_size = Some(u53(bad));
        assert_eq!(
            frame_err(check_err(&desc)),
            FrameError::DictSize { value: bad }
        );
    }
    let mut desc = desc_for(&enc);
    desc.dict_size = None;
    assert!(matches!(
        frame_err(check_err(&desc)),
        FrameError::MissingField {
            field: "dict_size",
            ..
        }
    ));
}

#[test]
fn fields_of_another_codec_are_rejected() {
    let (stored, _) = checked(CodecId::Stored);
    let (lzma, _) = checked(CodecId::BcjX86Lzma2);
    let (bcj2, _) = checked(CodecId::Bcj2);

    let mut d = desc_for(&stored);
    d.dict_size = Some(u53(DICT));
    assert!(matches!(
        frame_err(check_err(&d)),
        FrameError::ForeignField {
            field: "dict_size",
            ..
        }
    ));
    let mut d = desc_for(&stored);
    d.streams = desc_for(&bcj2).streams;
    assert!(matches!(
        frame_err(check_err(&d)),
        FrameError::ForeignField {
            field: "streams",
            ..
        }
    ));
    let mut d = desc_for(&lzma);
    d.streams = desc_for(&bcj2).streams;
    assert!(matches!(
        frame_err(check_err(&d)),
        FrameError::ForeignField {
            field: "streams",
            ..
        }
    ));
    let mut d = desc_for(&bcj2);
    d.dict_size = Some(u53(DICT));
    assert!(matches!(
        frame_err(check_err(&d)),
        FrameError::ForeignField {
            field: "dict_size",
            ..
        }
    ));
    let mut d = desc_for(&bcj2);
    d.streams = None;
    assert!(matches!(
        frame_err(check_err(&d)),
        FrameError::MissingField {
            field: "streams",
            ..
        }
    ));
}

#[test]
fn stored_frame_must_equal_its_file() {
    let (enc, _) = checked(CodecId::Stored);
    let d = data();
    let desc = desc_for(&enc);
    assert_eq!(
        frame_err(
            desc.check(d.len() as u64 + 1, sha(&d), 1 << 40)
                .unwrap_err()
        ),
        FrameError::StoredMismatch
    );
    assert_eq!(
        frame_err(
            desc.check(d.len() as u64, sha(b"other"), 1 << 40)
                .unwrap_err()
        ),
        FrameError::StoredMismatch
    );
}

#[test]
fn bcj2_stream_rules() {
    let (enc, _) = checked(CodecId::Bcj2);
    let base = desc_for(&enc);
    let with = |f: &dyn Fn(&mut Vec<StreamDesc>)| {
        let mut d = base.clone();
        f(d.streams.as_mut().unwrap());
        frame_err(check_err(&d))
    };
    assert_eq!(
        with(&|s| {
            s.pop();
        }),
        FrameError::StreamCount { count: 3 }
    );
    assert_eq!(
        with(&|s| s.push(s[3].clone())),
        FrameError::StreamCount { count: 5 }
    );
    assert_eq!(with(&|s| s.clear()), FrameError::StreamCount { count: 0 });
    // RC: length == decoded_size, no dict.
    assert!(matches!(
        with(&|s| s[3].decoded_size = u53(s[3].decoded_size.get() + 1)),
        FrameError::Stream { index: 3, .. }
    ));
    assert!(matches!(
        with(&|s| s[3].dict_size = Some(u53(DICT))),
        FrameError::Stream { index: 3, .. }
    ));
    // MAIN/CALL/JUMP need a valid dict and decoded_size <= file size.
    for i in 0..3 {
        assert!(matches!(
            with(&|s| s[i].dict_size = None),
            FrameError::Stream { index, .. } if index == i
        ));
        assert_eq!(
            with(&|s| s[i].dict_size = Some(u53(5000))),
            FrameError::DictSize { value: 5000 }
        );
        assert_eq!(
            with(&|s| s[i].dict_size = Some(u53(MAX_DICT_SIZE * 2))),
            FrameError::DictSize {
                value: MAX_DICT_SIZE * 2
            }
        );
        assert!(matches!(
            with(&|s| s[i].decoded_size = u53(1001)),
            FrameError::Stream { index, .. } if index == i
        ));
    }
    // Zero-length stream, sum short or long.
    assert!(matches!(
        with(&|s| s[1].length = u53(0)),
        FrameError::Stream { index: 1, .. }
    ));
    assert_eq!(
        with(&|s| s[0].length = u53(s[0].length.get() - 1)),
        FrameError::LengthSum
    );
    assert_eq!(
        with(&|s| s[0].length = u53(s[0].length.get() + 1)),
        FrameError::LengthSum
    );
    // Huge lengths never overflow into a match.
    assert_eq!(
        with(&|s| {
            for x in s.iter_mut().take(3) {
                x.length = U53::MAX;
            }
        }),
        FrameError::LengthSum
    );
}

#[test]
fn frame_must_fit_the_pack() {
    let (enc, _) = checked(CodecId::Lzma2);
    let d = data();
    let desc = desc_for(&enc);
    let exact = pack_size(&enc);
    desc.check(d.len() as u64, sha(&d), exact).unwrap();
    assert_eq!(
        frame_err(desc.check(d.len() as u64, sha(&d), exact - 1).unwrap_err()),
        FrameError::OutOfPack
    );
    // The largest offset and length: their sum is exact (no overflow), one past the pack fails.
    let mut far = desc.clone();
    far.offset = U53::MAX;
    far.length = U53::MAX;
    let end = 2 * U53::MAX.get();
    far.check(d.len() as u64, sha(&d), end).unwrap();
    assert_eq!(
        frame_err(far.check(d.len() as u64, sha(&d), end - 1).unwrap_err()),
        FrameError::OutOfPack
    );
    let mut zero = desc.clone();
    zero.length = u53(0);
    assert_eq!(frame_err(check_err(&zero)), FrameError::ZeroLength);
}

#[test]
fn frame_present_exactly_when_the_file_is_not_empty() {
    let (enc, _) = checked(CodecId::Lzma2);
    let d = data();
    let desc = desc_for(&enc);
    assert!(check_file_frame(None, 0, sha(b""), 0).unwrap().is_none());
    assert!(
        check_file_frame(Some(&desc), d.len() as u64, sha(&d), 1 << 40)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        frame_err(check_file_frame(Some(&desc), 0, sha(b""), 1 << 40).unwrap_err()),
        FrameError::Presence
    );
    assert_eq!(
        frame_err(check_file_frame(None, 1, sha(b"x"), 1 << 40).unwrap_err()),
        FrameError::Presence
    );
}

#[test]
fn decoder_memory_is_dictionaries_plus_overhead() {
    let (_, stored) = checked(CodecId::Stored);
    assert_eq!(decoder_memory(&stored), DECODER_OVERHEAD_BYTES);
    let (_, lzma) = checked(CodecId::BcjArm64Lzma2);
    assert_eq!(decoder_memory(&lzma), DICT + DECODER_OVERHEAD_BYTES);
    let (_, bcj2) = checked(CodecId::Bcj2);
    assert_eq!(decoder_memory(&bcj2), 3 * DICT + DECODER_OVERHEAD_BYTES);
    // The worst case is bounded by the signed caps: three 16 MiB dictionaries.
    let (enc, _) = checked(CodecId::Bcj2);
    let mut desc = desc_for(&enc);
    for s in desc.streams.as_mut().unwrap().iter_mut().take(3) {
        s.dict_size = Some(u53(MAX_DICT_SIZE));
    }
    let d = data();
    let max = desc.check(d.len() as u64, sha(&d), 1 << 40).unwrap();
    assert_eq!(
        decoder_memory(&max),
        3 * MAX_DICT_SIZE + DECODER_OVERHEAD_BYTES
    );
}

#[test]
fn descriptor_json_matches_the_format_example() {
    let text = br#"{
        "codec": "bcj2", "offset": 412345, "length": 700000,
        "sha256": "1bb5629b57e82f048ff63a42fd85dcd714fe5fd7b1861706a10c3e487b93461c",
        "streams": [
          { "length": 600000, "decoded_size": 1700000, "dict_size": 2097152 },
          { "length": 50000, "decoded_size": 200000, "dict_size": 262144 },
          { "length": 20000, "decoded_size": 100000, "dict_size": 65536 },
          { "length": 30000, "decoded_size": 30000 }
        ],
        "future_field": true
    }"#;
    let desc: FrameDesc = parse_strict(text).unwrap();
    let frame = desc
        .check(2_000_000, sha(b"file"), 1_113_545)
        .expect("FORMAT.md example checks");
    assert_eq!(
        decoder_memory(&frame),
        2_097_152 + 262_144 + 65_536 + DECODER_OVERHEAD_BYTES
    );
    // Writer output parses back to the same descriptor.
    let again: FrameDesc = parse_strict(&serde_json::to_vec(&desc).unwrap()).unwrap();
    assert_eq!(again, desc);
    // `null` is not a value.
    let nulled = br#"{"codec":"lzma2","offset":0,"length":1,"sha256":"1bb5629b57e82f048ff63a42fd85dcd714fe5fd7b1861706a10c3e487b93461c","dict_size":null}"#;
    assert!(matches!(
        parse_strict::<FrameDesc>(nulled),
        Err(Error::Schema(_))
    ));
    // Uppercase hex is rejected.
    let upper = br#"{"codec":"lzma2","offset":0,"length":1,"sha256":"1BB5629B57E82F048FF63A42FD85DCD714FE5FD7B1861706A10C3E487B93461C","dict_size":4096}"#;
    assert!(parse_strict::<FrameDesc>(upper).is_err());
}

#[test]
fn check_never_panics_on_edge_values() {
    let edges = [0, 1, 4095, 4096, 1 << 24, (1 << 53) - 1];
    let d = data();
    for codec in ["stored", "lzma2", "bcj2", "nope"] {
        for &offset in &edges {
            for &length in &edges {
                for &dict in &edges {
                    for &pack in &[0, 1, 1 << 40, u64::MAX] {
                        let desc = FrameDesc {
                            codec: codec.to_owned(),
                            offset: u53(offset),
                            length: u53(length),
                            sha256: sha(&d),
                            dict_size: (codec == "lzma2").then(|| u53(dict)),
                            streams: (codec == "bcj2").then(|| {
                                (0..4)
                                    .map(|i| StreamDesc {
                                        length: u53(length / 4),
                                        decoded_size: u53(dict),
                                        dict_size: (i < 3).then(|| u53(dict)),
                                    })
                                    .collect()
                            }),
                        };
                        let _ = desc.check(d.len() as u64, sha(&d), pack);
                    }
                }
            }
        }
    }
}

// ---- verify-then-decode ----

fn run(codec: &FakeCodec, frame: &CheckedFrame, bytes: &[u8]) -> (Result<(), Error>, Vec<u8>) {
    let mut out = Vec::new();
    let res = decode_verified(frame, bytes, &FakeHasher, codec, &mut out);
    (res, out)
}

#[test]
fn decodes_every_codec_and_checks_the_file_hash() {
    for id in ALL {
        let (enc, frame) = checked(id);
        let (res, out) = run(&FakeCodec::new(), &frame, &enc.frame);
        res.unwrap_or_else(|e| panic!("{id:?}: {e}"));
        assert_eq!(out, data());
    }
}

/// Counts hash computations, so "before hashing" is observable.
struct CountingHasher(AtomicUsize);

impl Hasher for CountingHasher {
    fn sha256_start(&self) -> Box<dyn HashState> {
        self.0.fetch_add(1, Ordering::SeqCst);
        FakeHasher.sha256_start()
    }
}

#[test]
fn wrong_byte_count_fails_before_hashing_and_decoding() {
    for id in ALL {
        let (enc, frame) = checked(id);
        let mut long = enc.frame.clone();
        long.push(0);
        for bytes in [&enc.frame[..enc.frame.len() - 1], &long[..], &[][..]] {
            let hasher = CountingHasher(AtomicUsize::new(0));
            let res = decode_verified(
                &frame,
                bytes,
                &hasher,
                &FakeCodec::with_fault(Fault::PanicIfCalled),
                &mut Vec::new(),
            );
            assert!(matches!(
                frame_err(res.unwrap_err()),
                FrameError::ByteCount { .. }
            ));
            assert_eq!(hasher.0.load(Ordering::SeqCst), 0, "{id:?} hashed");
        }
    }
}

#[test]
fn frame_hash_mismatch_never_reaches_the_codec() {
    for id in ALL {
        let (enc, frame) = checked(id);
        for index in [0, enc.frame.len() / 2, enc.frame.len() - 1] {
            let mut tampered = enc.frame.clone();
            tampered[index] ^= 0x01;
            let (res, out) = run(
                &FakeCodec::with_fault(Fault::PanicIfCalled),
                &frame,
                &tampered,
            );
            assert_eq!(frame_err(res.unwrap_err()), FrameError::FrameHash);
            assert!(out.is_empty());
        }
        // The untampered frame does reach the codec (the panicking fake proves it).
        let caught = std::panic::catch_unwind(|| {
            run(
                &FakeCodec::with_fault(Fault::PanicIfCalled),
                &frame,
                &enc.frame,
            )
        });
        assert!(
            caught.is_err(),
            "{id:?}: valid frame did not reach the codec"
        );
    }
}

#[test]
fn over_producing_decoder_is_stopped_at_the_file_size() {
    let size = data().len();
    for id in ALL {
        let (enc, frame) = checked(id);
        for fault in [
            Fault::Flood,
            Fault::ExtraBytes,
            Fault::ExtraBytesIgnoringErrors,
        ] {
            let (res, out) = run(&FakeCodec::with_fault(fault), &frame, &enc.frame);
            assert_eq!(
                frame_err(res.unwrap_err()),
                FrameError::OutputTooLong { size: size as u64 },
                "{id:?} {fault:?}"
            );
            assert!(
                out.len() <= size,
                "{id:?} {fault:?}: {} bytes passed",
                out.len()
            );
        }
    }
}

/// Accepts `keep` bytes of its first write, fails that write, then works normally.
struct FailsOncePartway {
    out: Vec<u8>,
    keep: usize,
    failed: bool,
}

impl std::io::Write for FailsOncePartway {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.failed {
            self.failed = true;
            self.out.extend_from_slice(&buf[..self.keep.min(buf.len())]);
            return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_writer_failure_is_reported_even_when_the_codec_swallows_it() {
    for id in ALL {
        let (enc, frame) = checked(id);
        let mut w = FailsOncePartway {
            out: Vec::new(),
            keep: 3,
            failed: false,
        };
        let res = decode_verified(
            &frame,
            &enc.frame,
            &FakeHasher,
            &FakeCodec::with_fault(Fault::RetryAfterWriteError),
            &mut w,
        );
        assert_eq!(
            frame_err(res.unwrap_err()),
            FrameError::OutputWrite {
                kind: std::io::ErrorKind::StorageFull
            },
            "{id:?}"
        );
        // The writer holds partial bytes plus the retry: size would match, content does not.
        assert!(w.failed, "{id:?}");
    }
    // A writer that never fails still succeeds with the same codec.
    let (enc, frame) = checked(CodecId::Lzma2);
    let (res, out) = run(
        &FakeCodec::with_fault(Fault::RetryAfterWriteError),
        &frame,
        &enc.frame,
    );
    res.unwrap();
    assert_eq!(out, data());
}

#[test]
fn short_output_wrong_consumed_and_codec_errors_fail() {
    for id in ALL {
        let (enc, frame) = checked(id);
        let (res, _) = run(
            &FakeCodec::with_fault(Fault::TooFewBytes),
            &frame,
            &enc.frame,
        );
        assert!(matches!(
            frame_err(res.unwrap_err()),
            FrameError::OutputTooShort { .. }
        ));
        let (res, _) = run(
            &FakeCodec::with_fault(Fault::WrongConsumed),
            &frame,
            &enc.frame,
        );
        assert!(matches!(
            frame_err(res.unwrap_err()),
            FrameError::Consumed { index: 0, .. }
        ));
        let (res, _) = run(
            &FakeCodec::with_fault(Fault::ErrorMidStream),
            &frame,
            &enc.frame,
        );
        assert!(matches!(res, Err(Error::Codec(CodecError::Corrupt(_)))));
    }
}

#[test]
fn wrong_decoded_hash_fails() {
    for id in [
        CodecId::Lzma2,
        CodecId::BcjX86Lzma2,
        CodecId::BcjArm64Lzma2,
        CodecId::Bcj2,
    ] {
        let d = data();
        let enc = FakeCodec::encode(id, &d);
        let mut other = d.clone();
        other[0] ^= 1;
        let frame = desc_for(&enc)
            .check(d.len() as u64, sha(&other), pack_size(&enc))
            .unwrap();
        let (res, out) = run(&FakeCodec::new(), &frame, &enc.frame);
        assert_eq!(frame_err(res.unwrap_err()), FrameError::FileHash);
        // The caller discards `out`: it held the full (wrong) output.
        assert_eq!(out, d);
    }
}

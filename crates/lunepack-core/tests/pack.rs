//! Step 4: file classification, codec choice with a round trip, and release layout, with the
//! testkit fakes (FakeHasher is not SHA-256) and a scripted encoder/decoder pair that can shrink.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Mutex;

use lunepack_core::error::{CodecError, PackError};
use lunepack_core::path::RelPath;
use lunepack_core::{
    AppId, Channel, ClockReading, Codec, CodecId, DecodeReport, EncodedFrame, EncodedStream,
    Encoder, Error, FeedTargetEntry, FileClass, FrameView, Hasher, PackedFile, PayloadKind,
    ReleaseLayout, RollbackFloor, Target, VerifiedEntry, VerifiedKeySet, candidates, classify,
    decode_verified, pack_file, verify_feed, verify_manifest,
};
use lunepack_testkit::exe_headers::{self, arm64_like, x86_like};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, Fault, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const X86_64: u32 = 0x0100_0007;
const I386: u32 = 7;
const ARM64: u32 = 0x0100_000C;

// ---- classification ----------------------------------------------------------------------------

#[test]
fn classification_table() {
    use FileClass::*;
    assert_eq!(classify(b""), Empty);
    assert_eq!(classify(b"hello, plain text"), Data);
    assert_eq!(classify(&[0u8]), Data);
    for (machine, want) in [
        (0x014C, X86),
        (0x8664, X86),
        (0xAA64, Arm64),
        (0x01C4, Data),
        (0x0000, Data),
    ] {
        assert_eq!(
            classify(&exe_headers::pe(machine, 600)),
            want,
            "pe {machine:#x}"
        );
    }
    for big in [false, true] {
        for (machine, want) in [(3, X86), (62, X86), (183, Arm64), (40, Data), (243, Data)] {
            assert_eq!(
                classify(&exe_headers::elf(machine, big, 600)),
                want,
                "elf {machine} big={big}"
            );
        }
        for (cpu, want) in [
            (I386, X86),
            (X86_64, X86),
            (ARM64, Arm64),
            (18, Data),          // ppc
            (0x0200_000C, Data), // arm64_32
        ] {
            assert_eq!(
                classify(&exe_headers::macho(cpu, big, 600)),
                want,
                "macho {cpu:#x} big={big}"
            );
        }
    }
    for (cpus, want) in [
        (
            &[X86_64][..],
            Fat {
                x86: true,
                arm64: false,
            },
        ),
        (
            &[I386][..],
            Fat {
                x86: true,
                arm64: false,
            },
        ),
        (
            &[ARM64][..],
            Fat {
                x86: false,
                arm64: true,
            },
        ),
        (
            &[X86_64, ARM64][..],
            Fat {
                x86: true,
                arm64: true,
            },
        ),
        (
            &[ARM64, 18, X86_64][..],
            Fat {
                x86: true,
                arm64: true,
            },
        ),
        (&[18][..], Data),
    ] {
        assert_eq!(
            classify(&exe_headers::fat(cpus, 600)),
            want,
            "fat {cpus:x?}"
        );
    }
}

#[test]
fn fat_slice_count_and_java_class_files() {
    let mut f = exe_headers::fat(&[X86_64], 600);
    // nfat_arch 0 and 21 are outside 1..=20.
    for n in [0u32, 21, u32::MAX] {
        f[4..8].copy_from_slice(&n.to_be_bytes());
        assert_eq!(classify(&f), FileClass::Data, "nfat {n}");
    }
    // 20 slices all arm64, but the header is cut short of the 20th: Data.
    let twenty = exe_headers::fat(&[ARM64; 20], 8 + 20 * 20);
    assert_eq!(
        classify(&twenty),
        FileClass::Fat {
            x86: false,
            arm64: true
        }
    );
    assert_eq!(classify(&twenty[..twenty.len() - 1]), FileClass::Data);
    // A Java class file: CA FE BA BE, minor 0, major 52.
    let mut java = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
    java.extend_from_slice(&[0x00; 64]);
    assert_eq!(classify(&java), FileClass::Data);
    // fat64 (32-byte slice records).
    let mut f64 = vec![0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 2];
    for cpu in [X86_64, ARM64] {
        f64.extend_from_slice(&cpu.to_be_bytes());
        f64.extend_from_slice(&[0u8; 28]);
    }
    assert_eq!(
        classify(&f64),
        FileClass::Fat {
            x86: true,
            arm64: true
        }
    );
}

#[test]
fn pe_header_offsets_are_bounds_checked() {
    let mut p = exe_headers::pe(0x8664, 600);
    for lfanew in [0u32, 0x3C, 0x84, 0x1000, u32::MAX - 3, u32::MAX] {
        p[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
        assert_eq!(classify(&p), FileClass::Data, "e_lfanew {lfanew:#x}");
    }
    // A bad signature.
    let mut p = exe_headers::pe(0x8664, 600);
    p[0x80] = b'X';
    assert_eq!(classify(&p), FileClass::Data);
}

#[test]
fn compressed_magics_are_stored_only() {
    let magics: [(&str, &[u8]); 13] = [
        ("zip", &[0x50, 0x4B, 0x03, 0x04]),
        ("gzip", &[0x1F, 0x8B, 0x08]),
        ("xz", &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
        ("zstd", &[0x28, 0xB5, 0x2F, 0xFD]),
        ("bzip2", &[0x42, 0x5A, 0x68, 0x39]),
        ("7z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
        ("lz4", &[0x04, 0x22, 0x4D, 0x18]),
        ("png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        ("jpeg", &[0xFF, 0xD8, 0xFF, 0xE0]),
        ("gif", &[0x47, 0x49, 0x46, 0x38, 0x39, 0x61]),
        ("webp", b"RIFF\x24\0\0\0WEBPVP8 "),
        ("woff2", &[0x77, 0x4F, 0x46, 0x32]),
        ("ogg", &[0x4F, 0x67, 0x67, 0x53]),
    ];
    for (name, magic) in magics {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&[0x55; 100]);
        assert_eq!(classify(&bytes), FileClass::Compressed, "{name}");
        assert!(candidates(classify(&bytes)).is_empty(), "{name}");
    }
    // RIFF that is not WebP (a WAV), and a RIFF cut short of the WEBP tag.
    assert_eq!(classify(b"RIFF\x24\0\0\0WAVEfmt "), FileClass::Data);
    assert_eq!(classify(b"RIFF\x24\0\0\0WEB"), FileClass::Data);
}

#[test]
fn truncated_headers_never_panic() {
    let samples: Vec<Vec<u8>> = vec![
        exe_headers::pe(0x8664, 600),
        exe_headers::pe(0xAA64, 600),
        exe_headers::elf(62, false, 600),
        exe_headers::elf(183, true, 600),
        exe_headers::macho(X86_64, false, 600),
        exe_headers::macho(ARM64, true, 600),
        exe_headers::fat(&[X86_64, ARM64], 600),
        vec![0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 20, 0xFF, 0xFF, 0xFF, 0xFF],
    ];
    for sample in &samples {
        for len in 0..=64usize {
            let class = classify(&sample[..len.min(sample.len())]);
            if len == 0 {
                assert_eq!(class, FileClass::Empty);
            }
        }
    }
    // The PE needs 0x86 bytes: every prefix up to 64 bytes is plain data.
    for len in 1..=64 {
        assert_eq!(
            classify(&samples[0][..len]),
            FileClass::Data,
            "pe prefix {len}"
        );
    }
    // ELF needs 20 bytes, thin Mach-O 8, fat 8 + 20 per slice.
    for len in 1..20 {
        assert_eq!(
            classify(&samples[2][..len]),
            FileClass::Data,
            "elf prefix {len}"
        );
    }
    assert_eq!(classify(&samples[2][..20]), FileClass::X86);
    for len in 1..8 {
        assert_eq!(
            classify(&samples[4][..len]),
            FileClass::Data,
            "macho prefix {len}"
        );
    }
    for len in 1..48 {
        assert_eq!(
            classify(&samples[6][..len]),
            FileClass::Data,
            "fat prefix {len}"
        );
    }
    assert_eq!(
        classify(&samples[6][..48]),
        FileClass::Fat {
            x86: true,
            arm64: true
        }
    );
}

#[test]
fn candidate_lists_per_class() {
    use CodecId::*;
    assert_eq!(candidates(FileClass::Empty), vec![]);
    assert_eq!(candidates(FileClass::Compressed), vec![]);
    assert_eq!(candidates(FileClass::Data), vec![Lzma2]);
    assert_eq!(candidates(FileClass::X86), vec![BcjX86Lzma2, Bcj2]);
    assert_eq!(candidates(FileClass::Arm64), vec![BcjArm64Lzma2]);
    assert_eq!(
        candidates(FileClass::Fat {
            x86: true,
            arm64: true
        }),
        vec![BcjX86Lzma2, BcjArm64Lzma2, Bcj2]
    );
    assert_eq!(
        candidates(FileClass::Fat {
            x86: true,
            arm64: false
        }),
        vec![BcjX86Lzma2, Bcj2]
    );
    assert_eq!(
        candidates(FileClass::Fat {
            x86: false,
            arm64: true
        }),
        vec![BcjArm64Lzma2]
    );
}

#[test]
fn filler_looks_like_code_and_is_deterministic() {
    assert_eq!(x86_like(1000), x86_like(1000));
    assert_eq!(arm64_like(1000), arm64_like(1000));
    assert!(x86_like(1000).iter().any(|&b| b == 0xE8 || b == 0xE9));
    // BL words: top six bits 100101.
    assert!(arm64_like(1000).chunks(4).any(|w| w[3] >> 2 == 0b100101));
    assert_eq!(exe_headers::pe(0x8664, 777).len(), 777);
    assert_eq!(exe_headers::elf(62, false, 777).len(), 777);
    assert_eq!(exe_headers::macho(ARM64, false, 777).len(), 777);
    assert_eq!(exe_headers::fat(&[ARM64], 777).len(), 777);
}

// ---- a scripted encoder and decoder ------------------------------------------------------------

/// Encodes with a chosen frame length per codec and decodes by looking the plaintext up, so a
/// test can make any candidate shorter, longer or equal. A frame starts with the index of its
/// plaintext in the table; the rest is zero padding. `stored` is real.
#[derive(Default)]
struct Scripted {
    lengths: HashMap<CodecId, usize>,
    fail_encode: HashSet<CodecId>,
    corrupt: HashSet<CodecId>,
    table: Mutex<Vec<Vec<u8>>>,
    encoded: Mutex<Vec<CodecId>>,
}

impl Scripted {
    fn with_lengths(lengths: &[(CodecId, usize)]) -> Self {
        Scripted {
            lengths: lengths.iter().copied().collect(),
            ..Scripted::default()
        }
    }
}

impl Encoder for Scripted {
    fn encode(&self, codec: CodecId, input: &[u8]) -> Result<EncodedFrame, Error> {
        self.encoded.lock().unwrap().push(codec);
        if self.fail_encode.contains(&codec) {
            return Err(CodecError::Encoder("scripted failure".into()).into());
        }
        let mut plain = input.to_vec();
        if self.corrupt.contains(&codec) {
            plain[0] ^= 1;
        }
        let index = {
            let mut table = self.table.lock().unwrap();
            table.push(plain);
            (table.len() - 1) as u32
        };
        let total = self.lengths[&codec].max(8);
        let mut bytes = index.to_be_bytes().to_vec();
        bytes.resize(total, 0);
        Ok(match codec {
            CodecId::Bcj2 => EncodedFrame {
                codec,
                dict_size: None,
                streams: Some(vec![
                    EncodedStream {
                        length: (total - 3) as u64,
                        decoded_size: input.len() as u64,
                        dict_size: Some(4096),
                    },
                    EncodedStream {
                        length: 1,
                        decoded_size: 0,
                        dict_size: Some(4096),
                    },
                    EncodedStream {
                        length: 1,
                        decoded_size: 0,
                        dict_size: Some(4096),
                    },
                    EncodedStream {
                        length: 1,
                        decoded_size: 1,
                        dict_size: None,
                    },
                ]),
                bytes,
            },
            _ => EncodedFrame {
                codec,
                dict_size: Some(4096),
                streams: None,
                bytes,
            },
        })
    }

    fn encode_memory(&self, _codec: CodecId, _input_len: u64) -> u64 {
        0
    }
}

impl Codec for Scripted {
    fn decode(&self, frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
        let consumed = frame.streams.iter().map(|s| s.input.len() as u64).collect();
        if frame.codec == CodecId::Stored {
            out.write_all(frame.streams[0].input)
                .map_err(CodecError::Write)?;
            return Ok(DecodeReport { consumed });
        }
        let head: [u8; 4] = frame.streams[0]
            .input
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or(CodecError::Corrupt("short frame"))?;
        let table = self.table.lock().unwrap();
        let plain = table
            .get(u32::from_be_bytes(head) as usize)
            .ok_or(CodecError::Corrupt("unknown plaintext"))?;
        out.write_all(plain).map_err(CodecError::Write)?;
        Ok(DecodeReport { consumed })
    }
}

fn chosen(p: &PackedFile) -> CodecId {
    p.frame.as_ref().expect("a frame").codec
}

fn pack(scripted: &Scripted, input: &[u8]) -> PackedFile {
    pack_file(input, scripted, scripted, &FakeHasher).unwrap()
}

// ---- pack_file ---------------------------------------------------------------------------------

#[test]
fn shortest_candidate_wins() {
    let input = exe_headers::pe(0x8664, 1000);
    let s = Scripted::with_lengths(&[(CodecId::BcjX86Lzma2, 300), (CodecId::Bcj2, 200)]);
    let p = pack(&s, &input);
    assert_eq!(chosen(&p), CodecId::Bcj2);
    assert_eq!(p.frame.as_ref().unwrap().bytes.len(), 200);
    assert_eq!(p.size, 1000);
    assert_eq!(p.sha256, FakeHasher.sha256(&input));
    assert!(p.dropped.is_empty());

    let s = Scripted::with_lengths(&[(CodecId::BcjX86Lzma2, 100), (CodecId::Bcj2, 200)]);
    assert_eq!(chosen(&pack(&s, &input)), CodecId::BcjX86Lzma2);

    let data = vec![b'a'; 1000];
    let s = Scripted::with_lengths(&[(CodecId::Lzma2, 10)]);
    assert_eq!(chosen(&pack(&s, &data)), CodecId::Lzma2);
}

#[test]
fn equal_lengths_pick_the_earlier_rank() {
    let both = exe_headers::fat(&[X86_64, ARM64], 1000);
    let s = Scripted::with_lengths(&[
        (CodecId::BcjX86Lzma2, 100),
        (CodecId::BcjArm64Lzma2, 100),
        (CodecId::Bcj2, 100),
    ]);
    assert_eq!(chosen(&pack(&s, &both)), CodecId::BcjX86Lzma2);
    // Arm beats bcj2 on a tie; bcj2 wins when it is strictly shorter.
    let s = Scripted::with_lengths(&[
        (CodecId::BcjX86Lzma2, 120),
        (CodecId::BcjArm64Lzma2, 100),
        (CodecId::Bcj2, 100),
    ]);
    assert_eq!(chosen(&pack(&s, &both)), CodecId::BcjArm64Lzma2);
    let s = Scripted::with_lengths(&[
        (CodecId::BcjX86Lzma2, 120),
        (CodecId::BcjArm64Lzma2, 110),
        (CodecId::Bcj2, 100),
    ]);
    assert_eq!(chosen(&pack(&s, &both)), CodecId::Bcj2);
}

#[test]
fn stored_unless_a_candidate_is_strictly_shorter_than_the_file() {
    let data = vec![7u8; 500];
    for len in [500, 501, 900] {
        let s = Scripted::with_lengths(&[(CodecId::Lzma2, len)]);
        let p = pack(&s, &data);
        assert_eq!(chosen(&p), CodecId::Stored, "candidate of {len} bytes");
        assert_eq!(p.frame.as_ref().unwrap().bytes, data);
        assert!(p.dropped.is_empty());
    }
    let s = Scripted::with_lengths(&[(CodecId::Lzma2, 499)]);
    assert_eq!(chosen(&pack(&s, &data)), CodecId::Lzma2);
}

#[test]
fn a_candidate_failing_the_round_trip_is_dropped() {
    let input = exe_headers::pe(0x8664, 1000);
    let mut s = Scripted::with_lengths(&[(CodecId::BcjX86Lzma2, 300), (CodecId::Bcj2, 100)]);
    // The shortest candidate decodes to the wrong bytes.
    s.corrupt.insert(CodecId::Bcj2);
    let p = pack(&s, &input);
    assert_eq!(chosen(&p), CodecId::BcjX86Lzma2);
    assert_eq!(p.dropped.len(), 1);
    assert_eq!(p.dropped[0].0, CodecId::Bcj2);
    assert!(!p.dropped[0].1.is_empty());

    // Every candidate broken: stored.
    s.corrupt.insert(CodecId::BcjX86Lzma2);
    let p = pack(&s, &input);
    assert_eq!(chosen(&p), CodecId::Stored);
    assert_eq!(p.dropped.len(), 2);
}

#[test]
fn a_candidate_failing_to_encode_is_dropped_with_its_reason() {
    let input = exe_headers::pe(0x8664, 1000);
    let mut s = Scripted::with_lengths(&[(CodecId::BcjX86Lzma2, 300), (CodecId::Bcj2, 100)]);
    s.fail_encode.insert(CodecId::Bcj2);
    let p = pack(&s, &input);
    assert_eq!(chosen(&p), CodecId::BcjX86Lzma2);
    assert_eq!(p.dropped.len(), 1);
    assert_eq!(p.dropped[0].0, CodecId::Bcj2);
    assert!(p.dropped[0].1.contains("encoder failed"), "{:?}", p.dropped);
    assert!(
        p.dropped[0].1.contains("scripted failure"),
        "{:?}",
        p.dropped
    );
}

#[test]
fn an_encoder_returning_another_codec_is_dropped() {
    struct Liar;
    impl Encoder for Liar {
        fn encode(&self, _: CodecId, input: &[u8]) -> Result<EncodedFrame, Error> {
            Ok(EncodedFrame {
                codec: CodecId::Stored,
                bytes: input[..1].to_vec(),
                dict_size: None,
                streams: None,
            })
        }
        fn encode_memory(&self, _: CodecId, _: u64) -> u64 {
            0
        }
    }
    let p = pack_file(&[1u8; 100], &Liar, &FakeCodec::new(), &FakeHasher).unwrap();
    assert_eq!(chosen(&p), CodecId::Stored);
    assert_eq!(p.dropped.len(), 1);
}

#[test]
fn empty_file_has_no_frame() {
    let s = Scripted::default();
    let p = pack(&s, b"");
    assert_eq!(p.size, 0);
    assert!(p.frame.is_none());
    assert_eq!(p.sha256, FakeHasher.sha256(b""));
    assert!(s.encoded.lock().unwrap().is_empty());
}

#[test]
fn compressed_files_are_stored_without_trying_an_encoder() {
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend_from_slice(&[0u8; 200]);
    let s = Scripted::default();
    let p = pack(&s, &png);
    assert_eq!(chosen(&p), CodecId::Stored);
    assert!(s.encoded.lock().unwrap().is_empty());
}

#[test]
fn the_real_toy_codec_never_shrinks_so_everything_is_stored() {
    let c = FakeCodec::new();
    for input in [
        exe_headers::pe(0x8664, 2000),
        exe_headers::elf(183, false, 2000),
        vec![9u8; 3000],
        vec![1u8],
    ] {
        let p = pack_file(&input, &c, &c, &FakeHasher).unwrap();
        assert_eq!(chosen(&p), CodecId::Stored);
        assert!(p.dropped.is_empty(), "{:?}", p.dropped);
    }
}

#[test]
fn the_stored_frame_is_round_tripped_too() {
    let broken = FakeCodec::with_fault(Fault::TooFewBytes);
    let err = pack_file(&[5u8; 100], &FakeCodec::new(), &broken, &FakeHasher).unwrap_err();
    assert!(
        matches!(err, Error::Pack(PackError::StoredRoundTrip(_))),
        "{err}"
    );
}

// ---- ReleaseLayout -----------------------------------------------------------------------------

const VERSION: &str = "1.2.0";

fn rel(path: &str) -> RelPath {
    RelPath::parse(path).unwrap()
}

fn layout(target: Target) -> ReleaseLayout {
    ReleaseLayout::new(AppId::parse(SUITE_APP_ID).unwrap(), VERSION, target).unwrap()
}

struct Tree {
    files: Vec<(&'static str, bool, Vec<u8>)>,
}

fn tree() -> Tree {
    let exe = exe_headers::pe(0x8664, 4000);
    let blob = vec![b'z'; 3000];
    Tree {
        files: vec![
            ("bin/app", true, exe),
            ("lib/libx.so", false, exe_headers::elf(62, false, 2500)),
            ("share/a.dat", false, blob.clone()),
            ("share/b.dat", false, blob),
            ("share/empty", false, Vec::new()),
            ("share/tiny", false, vec![1, 2, 3]),
            ("Share/Docs/readme.txt", false, b"readme text".repeat(40)),
        ],
    }
}

fn scripted() -> Scripted {
    Scripted::with_lengths(&[
        (CodecId::Lzma2, 40),
        (CodecId::BcjX86Lzma2, 60),
        (CodecId::Bcj2, 50),
    ])
}

fn packed(s: &Scripted, t: &Tree) -> Vec<PackedFile> {
    t.files.iter().map(|(_, _, b)| pack(s, b)).collect()
}

fn fill(l: &mut ReleaseLayout, t: &Tree, packed: &[PackedFile], order: &[usize], links: bool) {
    for &i in order {
        let (path, exec, _) = &t.files[i];
        l.add_file(rel(path), *exec, &packed[i]).unwrap();
    }
    l.add_dir(rel("share")).unwrap();
    l.add_dir(rel("bin")).unwrap();
    if links {
        l.add_symlink(rel("lib/libx.so.1"), "libx.so").unwrap();
    }
}

fn entry_for(
    fx: &ChainFixture<'_>,
    keys: &VerifiedKeySet,
    target: Target,
    manifest: &[u8],
) -> FeedTargetEntry {
    let doc = fx.feed_document(
        1,
        None,
        vec![fx.release(VERSION, &[(target, manifest)], None)],
    );
    let bytes = fx.envelope(PayloadKind::Feed, &doc.to_payload(), &[5]);
    verify_feed(
        keys,
        &bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(SUITE_T0), None),
        fx.verifier,
    )
    .unwrap()
    .target_entry(0, target)
    .unwrap()
}

#[test]
fn a_finished_layout_verifies_and_every_frame_decodes() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let s = scripted();
    let t = tree();
    let packed = packed(&s, &t);
    let mut l = layout(Target::LinuxX86_64);
    fill(&mut l, &t, &packed, &[0, 1, 2, 3, 4, 5, 6], true);
    let (doc, pack_bytes) = l.finish(SUITE_T0, &FakeHasher).unwrap();

    assert_eq!(doc.format.get(), 1);
    assert_eq!(doc.kind, "manifest");
    assert!(doc.critical.is_empty());
    assert_eq!(doc.version, VERSION);
    assert_eq!(doc.target, "linux-x86_64");
    assert_eq!(doc.pack.path, "1.2.0/linux-x86_64.pack");
    assert_eq!(doc.pack.size.get(), pack_bytes.len() as u64);
    // Sorted by path bytes ("Share/..." before lowercase names), directories included.
    let paths: Vec<_> = doc.entries.iter().map(|e| e.path.as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted);
    assert_eq!(paths.len(), 10);

    let bytes = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[5]);
    let entry = entry_for(&fx, &keys, Target::LinuxX86_64, &bytes);
    let verified = verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier).unwrap();
    assert_eq!(verified.issued(), SUITE_T0);

    let originals: HashMap<_, _> = t.files.iter().map(|(p, _, b)| (*p, b)).collect();
    let mut decoded = 0;
    let mut codecs = HashSet::new();
    for e in verified.entries() {
        match e {
            VerifiedEntry::File {
                path,
                frame,
                exec,
                size,
                ..
            } => {
                let want = originals[path.as_str()];
                assert_eq!(*size, want.len() as u64);
                assert_eq!(
                    *exec,
                    t.files.iter().any(|(p, x, _)| *p == path.as_str() && *x)
                );
                let Some(frame) = frame else {
                    assert!(want.is_empty());
                    continue;
                };
                codecs.insert(frame.codec());
                let start = frame.offset() as usize;
                let mut out = Vec::new();
                decode_verified(
                    frame,
                    &pack_bytes[start..start + frame.length() as usize],
                    &FakeHasher,
                    &s,
                    &mut out,
                )
                .unwrap();
                assert_eq!(&out, want, "{path}");
                decoded += 1;
            }
            VerifiedEntry::Symlink { target, .. } => assert_eq!(target, "libx.so"),
            VerifiedEntry::Dir { .. } => {}
        }
    }
    assert_eq!(decoded, 6);
    // The tiny file is stored, the others use the scripted codecs.
    assert!(codecs.contains(&CodecId::Stored));
    assert!(codecs.contains(&CodecId::Bcj2) || codecs.contains(&CodecId::BcjX86Lzma2));
    assert!(codecs.contains(&CodecId::Lzma2));
}

#[test]
fn identical_files_share_the_first_frame_and_frames_are_contiguous() {
    let s = scripted();
    let t = tree();
    let packed = packed(&s, &t);
    let mut l = layout(Target::LinuxX86_64);
    fill(&mut l, &t, &packed, &[0, 1, 2, 3, 4, 5, 6], false);
    let (doc, pack_bytes) = l.finish(SUITE_T0, &FakeHasher).unwrap();
    let by_path: HashMap<_, _> = doc.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let a = by_path["share/a.dat"].frame.as_ref().unwrap();
    let b = by_path["share/b.dat"].frame.as_ref().unwrap();
    assert_eq!(a, b, "same size and hash share one frame");

    // Walk sorted entries: each new frame starts where the previous one ended.
    let mut end = 0u64;
    let mut seen = HashSet::new();
    for e in &doc.entries {
        if let Some(f) = &e.frame
            && seen.insert((f.offset.get(), f.length.get()))
        {
            assert_eq!(f.offset.get(), end, "{}", e.path);
            end += f.length.get();
        }
    }
    assert_eq!(end, pack_bytes.len() as u64, "no padding, no gaps");
    // One shared frame stored once: the pack is the five distinct frames.
    assert_eq!(seen.len(), 5);
}

#[test]
fn output_does_not_depend_on_insertion_order() {
    let s = scripted();
    let t = tree();
    let packed = packed(&s, &t);
    let mut forward = layout(Target::LinuxX86_64);
    fill(&mut forward, &t, &packed, &[0, 1, 2, 3, 4, 5, 6], true);
    let mut backward = layout(Target::LinuxX86_64);
    fill(&mut backward, &t, &packed, &[6, 5, 4, 3, 2, 1, 0], true);
    let (da, pa) = forward.finish(SUITE_T0, &FakeHasher).unwrap();
    let (db, pb) = backward.finish(SUITE_T0, &FakeHasher).unwrap();
    assert_eq!(da.to_payload(), db.to_payload());
    assert_eq!(pa, pb);
}

#[test]
fn an_empty_layout_has_an_empty_pack() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let (doc, pack_bytes) = layout(Target::LinuxX86_64)
        .finish(SUITE_T0, &FakeHasher)
        .unwrap();
    assert!(pack_bytes.is_empty());
    assert_eq!(doc.pack.size.get(), 0);
    assert_eq!(doc.pack.sha256, FakeHasher.sha256(b""));
    assert!(doc.entries.is_empty());
    let bytes = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[5]);
    let entry = entry_for(&fx, &keys, Target::LinuxX86_64, &bytes);
    verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier).unwrap();
}

#[test]
fn only_empty_files_leave_the_pack_empty() {
    let s = scripted();
    let empty = pack(&s, b"");
    let mut l = layout(Target::WindowsX86_64);
    l.add_file(rel("a.txt"), false, &empty).unwrap();
    l.add_file(rel("b.txt"), false, &empty).unwrap();
    let (doc, pack_bytes) = l.finish(SUITE_T0, &FakeHasher).unwrap();
    assert!(pack_bytes.is_empty());
    assert!(doc.entries.iter().all(|e| e.frame.is_none()));
}

#[test]
fn bad_layouts_are_errors() {
    let s = scripted();
    let file = pack(&s, b"some bytes");

    // The same path twice, even as another kind.
    let mut l = layout(Target::LinuxX86_64);
    l.add_file(rel("a"), false, &file).unwrap();
    for result in [
        l.add_file(rel("a"), true, &file),
        l.add_dir(rel("a")),
        l.add_symlink(rel("a"), "b"),
    ] {
        assert!(
            matches!(result, Err(Error::Pack(PackError::DuplicatePath(_)))),
            "{result:?}"
        );
    }

    // Names that fold to one key.
    let mut l = layout(Target::LinuxX86_64);
    l.add_file(rel("Readme"), false, &file).unwrap();
    l.add_file(rel("README"), false, &file).unwrap();
    assert!(matches!(
        l.finish(SUITE_T0, &FakeHasher),
        Err(Error::Tree(_))
    ));

    // Something under a file.
    let mut l = layout(Target::LinuxX86_64);
    l.add_file(rel("a"), false, &file).unwrap();
    l.add_file(rel("a/b"), false, &file).unwrap();
    assert!(matches!(
        l.finish(SUITE_T0, &FakeHasher),
        Err(Error::Tree(_))
    ));

    // A symlink on Windows, and one that escapes the tree.
    let mut l = layout(Target::WindowsX86_64);
    l.add_symlink(rel("l"), "a").unwrap();
    assert!(matches!(
        l.finish(SUITE_T0, &FakeHasher),
        Err(Error::Tree(_))
    ));
    let mut l = layout(Target::LinuxX86_64);
    l.add_symlink(rel("l"), "../a").unwrap();
    assert!(matches!(
        l.finish(SUITE_T0, &FakeHasher),
        Err(Error::Tree(_))
    ));

    // A version that is not SemVer.
    assert!(matches!(
        ReleaseLayout::new(
            AppId::parse(SUITE_APP_ID).unwrap(),
            "1.2",
            Target::LinuxX86_64
        ),
        Err(Error::Version(_))
    ));

    // A frame that does not belong to the file (empty file with a frame, file without one).
    let mut with_frame = file.clone();
    with_frame.size = 0;
    let mut without = file.clone();
    without.frame = None;
    let mut l = layout(Target::LinuxX86_64);
    for bad in [&with_frame, &without] {
        assert!(matches!(
            l.add_file(rel("x"), false, bad),
            Err(Error::Pack(PackError::Invariant(_)))
        ));
    }

    // A frame descriptor the client would reject (LZMA2 without a dictionary).
    let mut broken = pack(&s, &vec![b'q'; 1000]);
    assert_eq!(chosen(&broken), CodecId::Lzma2);
    broken.frame.as_mut().unwrap().dict_size = None;
    let mut l = layout(Target::LinuxX86_64);
    l.add_file(rel("x"), false, &broken).unwrap();
    assert!(matches!(
        l.finish(SUITE_T0, &FakeHasher),
        Err(Error::Frame(_))
    ));

    // A time outside the format's integer range.
    let l = layout(Target::LinuxX86_64);
    assert!(matches!(
        l.finish(1 << 53, &FakeHasher),
        Err(Error::Integer(_))
    ));
}

#[test]
fn the_version_text_is_kept_verbatim() {
    let l = ReleaseLayout::new(
        AppId::parse(SUITE_APP_ID).unwrap(),
        "1.2.0-rc.1+build.5",
        Target::MacosUniversal,
    )
    .unwrap();
    let (doc, _) = l.finish(SUITE_T0, &FakeHasher).unwrap();
    assert_eq!(doc.version, "1.2.0-rc.1+build.5");
    assert_eq!(doc.pack.path, "1.2.0-rc.1+build.5/macos-universal.pack");
    assert!(doc.pack.check().is_ok());
}

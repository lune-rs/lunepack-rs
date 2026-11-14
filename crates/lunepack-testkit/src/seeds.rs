//! Seed inputs for the fuzz harnesses of `lunepack_core::fuzz` (M2-D8), written by the real writers
//! (the core's payload serialisers, `write_envelope` and the frame descriptor's `Serialize`) over
//! the testkit fakes. They are committed under `fuzz/seeds/<harness>/`; a replay test regenerates
//! them in memory and fails if a committed file differs.
//!
//! No secret is involved: the keys are the fakes of [`crate::FakeKeyPair`], envelopes carry dummy
//! 64-byte signatures, and the payload harnesses sign with the fake scheme at run time.

use lunepack_core::digest::{Sha256Digest, U53};
use std::path::{Path, PathBuf};

use lunepack_core::fuzz::{
    FRAME_HEADER_LEN, FUZZ_APP_ID, FUZZ_TARGET, FUZZ_VERSION, HTTP_HEADER_LEN, STATE_NAME_SEQ,
};
use lunepack_core::state::{self, MAX_RECORD_BYTES};
use lunepack_core::trust::PublicKey;
use lunepack_core::{
    AppId, ByteRange, Channel, CodecId, ContentRange, CurrentRef, EnvelopeSignature, Floors,
    FrameDesc, Fs, Hasher, InstallCounters, InstallState, Loaded, PayloadKind, PreviousRef,
    RootParts, Scope, StagedRef, StreamDesc, Target, Validator, Version, write_envelope,
};

use crate::docs::{ChainFixture, PackBuilder, SUITE_T0};
use crate::hasher::FakeHasher;
use crate::memfs::MemFs;

const DAY: u64 = 86_400;
const MANIFEST_STUB: &[u8] = b"manifest bytes the feed seeds point at";
const DUMMY_SIGNATURE: [u8; 64] = [0x11; 64];

/// One seed input of one harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    /// The harness (`lunepack_core::fuzz::HARNESSES`).
    pub harness: &'static str,
    /// File name under `fuzz/seeds/<harness>/`.
    pub name: String,
    /// The input.
    pub bytes: Vec<u8>,
    /// Whether the harness must take this input all the way through (`fuzz::accepts`).
    pub accepted: bool,
}

struct Out(Vec<Seed>);

impl Out {
    fn ok(&mut self, harness: &'static str, name: &str, bytes: impl Into<Vec<u8>>) {
        self.add(harness, format!("ok-{name}"), bytes.into(), true);
    }

    fn bad(&mut self, harness: &'static str, name: &str, bytes: impl Into<Vec<u8>>) {
        self.add(harness, format!("bad-{name}"), bytes.into(), false);
    }

    fn add(&mut self, harness: &'static str, name: String, bytes: Vec<u8>, accepted: bool) {
        self.0.push(Seed {
            harness,
            name,
            bytes,
            accepted,
        });
    }
}

fn u53(v: u64) -> U53 {
    U53::new(v).expect("value in range")
}

/// Every seed of every harness, in a fixed order.
pub fn fuzz_seeds() -> Vec<Seed> {
    let fx = ChainFixture::fake();
    let mut out = Out(Vec::new());
    envelope_seeds(&fx, &mut out);
    root_seeds(&fx, &mut out);
    keys_seeds(&fx, &mut out);
    feed_seeds(&fx, &mut out);
    manifest_seeds(&fx, &mut out);
    path_seeds(&mut out);
    tree_seeds(&mut out);
    rules_seeds(&mut out);
    json_seeds(&fx, &mut out);
    frame_seeds(&mut out);
    http_seeds(&mut out);
    state_seeds(&mut out);
    out.0
}

fn dummy_envelope(
    fx: &ChainFixture<'_>,
    payload_type: &str,
    payload: &[u8],
    sigs: usize,
) -> Vec<u8> {
    let sigs: Vec<EnvelopeSignature> = (0..sigs)
        .map(|i| EnvelopeSignature {
            keyid: fx.key_id(i as u8),
            sig: DUMMY_SIGNATURE,
        })
        .collect();
    write_envelope(payload_type, payload, &sigs)
}

fn envelope_seeds(fx: &ChainFixture<'_>, out: &mut Out) {
    let pack = sample_pack(fx);
    let payloads: [(&str, PayloadKind, Vec<u8>); 4] = [
        (
            "root",
            PayloadKind::Root,
            fx.root_document(2, 1, &[1]).to_payload(),
        ),
        (
            "keys",
            PayloadKind::Keys,
            fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
        ),
        (
            "feed",
            PayloadKind::Feed,
            fx.feed_document(
                1,
                None,
                vec![fx.release("1.0.0", &[(FUZZ_TARGET, MANIFEST_STUB)], None)],
            )
            .to_payload(),
        ),
        (
            "manifest",
            PayloadKind::Manifest,
            fx.manifest_document("1.0.0", FUZZ_TARGET, &pack)
                .to_payload(),
        ),
    ];
    for (name, kind, payload) in &payloads {
        out.ok(
            "envelope",
            name,
            dummy_envelope(fx, kind.payload_type(), payload, 1),
        );
    }
    let (_, kind, payload) = &payloads[1];
    out.ok(
        "envelope",
        "keys-three-signatures",
        dummy_envelope(fx, kind.payload_type(), payload, 3),
    );
    out.bad(
        "envelope",
        "unknown-payload-type",
        dummy_envelope(fx, "application/vnd.lunepack.keys.v2+json", payload, 1),
    );
    out.bad(
        "envelope",
        "no-signatures",
        dummy_envelope(fx, kind.payload_type(), payload, 0),
    );
}

fn root_seeds(fx: &ChainFixture<'_>, out: &mut Out) {
    out.ok(
        "root",
        "rotate-one-key",
        fx.root_document(2, 1, &[1]).to_payload(),
    );
    out.ok(
        "root",
        "rotate-two-of-three",
        fx.root_document(2, 2, &[1, 2, 3]).to_payload(),
    );
    out.bad(
        "root",
        "skips-a-version",
        fx.root_document(3, 1, &[1]).to_payload(),
    );
    out.bad(
        "root",
        "threshold-zero",
        fx.root_document(2, 0, &[1]).to_payload(),
    );
    out.bad(
        "root",
        "duplicate-key",
        fx.root_document(2, 1, &[1, 1]).to_payload(),
    );
    out.bad(
        "root",
        "threshold-over-keys",
        fx.root_document(2, 3, &[1, 2]).to_payload(),
    );
}

fn keys_seeds(fx: &ChainFixture<'_>, out: &mut Out) {
    out.ok(
        "keys",
        "one-release-key",
        fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
    );
    out.ok(
        "keys",
        "expiring",
        fx.keyset_document(1, 2, Some(SUITE_T0 + 30 * DAY), 1, &[5])
            .to_payload(),
    );
    out.ok(
        "keys",
        "two-of-three",
        fx.keyset_document(1, 1, None, 2, &[5, 6, 7]).to_payload(),
    );
    out.bad(
        "keys",
        "root-version-2",
        fx.keyset_document(2, 1, None, 1, &[5]).to_payload(),
    );
    out.bad(
        "keys",
        "expired",
        fx.keyset_document(1, 1, Some(SUITE_T0 - 1), 1, &[5])
            .to_payload(),
    );
    out.bad(
        "keys",
        "threshold-over-keys",
        fx.keyset_document(1, 1, None, 4, &[5]).to_payload(),
    );
}

fn feed_seeds(fx: &ChainFixture<'_>, out: &mut Out) {
    let one = vec![fx.release(FUZZ_VERSION, &[(FUZZ_TARGET, MANIFEST_STUB)], None)];
    out.ok(
        "feed",
        "one-release",
        fx.feed_document(1, None, one.clone()).to_payload(),
    );
    out.ok(
        "feed",
        "expiring",
        fx.feed_document(2, Some(SUITE_T0 + 30 * DAY), one.clone())
            .to_payload(),
    );
    let many = vec![
        fx.release(
            "1.0.0",
            &[
                (Target::LinuxX86_64, MANIFEST_STUB),
                (Target::MacosUniversal, MANIFEST_STUB),
                (Target::WindowsX86_64, MANIFEST_STUB),
            ],
            None,
        ),
        fx.release(
            "1.1.0-rc.1",
            &[(Target::LinuxX86_64, MANIFEST_STUB)],
            Some((2500, [0x44; 32])),
        ),
    ];
    out.ok(
        "feed",
        "rollout-and-three-targets",
        fx.feed_document(3, None, many).to_payload(),
    );
    out.ok(
        "feed",
        "no-releases",
        fx.feed_document(1, None, Vec::new()).to_payload(),
    );
    out.bad(
        "feed",
        "expired",
        fx.feed_document(1, Some(SUITE_T0 - 1), one.clone())
            .to_payload(),
    );
    let duplicate = vec![
        fx.release("1.0.0+a", &[(FUZZ_TARGET, MANIFEST_STUB)], None),
        fx.release("1.0.0+b", &[(FUZZ_TARGET, MANIFEST_STUB)], None),
    ];
    out.bad(
        "feed",
        "equal-precedence",
        fx.feed_document(1, None, duplicate).to_payload(),
    );
    let mut other_channel = fx.feed_document(1, None, one.clone());
    other_channel.channel = Channel::parse("beta").expect("valid channel");
    out.bad("feed", "other-channel", other_channel.to_payload());
    let bad_rollout = vec![fx.release(
        FUZZ_VERSION,
        &[(FUZZ_TARGET, MANIFEST_STUB)],
        Some((10_001, [0x44; 32])),
    )];
    out.bad(
        "feed",
        "rollout-over-10000",
        fx.feed_document(1, None, bad_rollout).to_payload(),
    );
}

fn sample_pack(fx: &ChainFixture<'_>) -> PackBuilder {
    let data = |n: usize, salt: u8| -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
            .collect()
    };
    let mut pack = PackBuilder::new();
    pack.file(fx.hasher, "bin/app", &data(300, 1), CodecId::BcjX86Lzma2)
        .file(fx.hasher, "lib/x.so.1", &data(200, 2), CodecId::Bcj2)
        .file(fx.hasher, "share/README", &data(50, 3), CodecId::Stored)
        .file(fx.hasher, "share/empty", b"", CodecId::Stored)
        .file(fx.hasher, "data/blob", &data(70, 4), CodecId::Lzma2)
        .file(
            fx.hasher,
            "bin/tool-arm",
            &data(64, 5),
            CodecId::BcjArm64Lzma2,
        )
        .dir("share/doc")
        .symlink("lib/x.so", "x.so.1");
    pack
}

fn manifest_seeds(fx: &ChainFixture<'_>, out: &mut Out) {
    let pack = sample_pack(fx);
    out.ok(
        "manifest",
        "every-codec",
        fx.manifest_document(FUZZ_VERSION, FUZZ_TARGET, &pack)
            .to_payload(),
    );
    let mut minimal = PackBuilder::new();
    minimal.file(fx.hasher, "app", b"hello", CodecId::Stored);
    out.ok(
        "manifest",
        "one-stored-file",
        fx.manifest_document(FUZZ_VERSION, FUZZ_TARGET, &minimal)
            .to_payload(),
    );
    out.ok(
        "manifest",
        "no-entries",
        fx.manifest_document(FUZZ_VERSION, FUZZ_TARGET, &PackBuilder::new())
            .to_payload(),
    );
    out.bad(
        "manifest",
        "version-differs-from-the-feed",
        fx.manifest_document("1.0.1", FUZZ_TARGET, &pack)
            .to_payload(),
    );
    out.bad(
        "manifest",
        "target-differs-from-the-feed",
        fx.manifest_document(FUZZ_VERSION, Target::MacosUniversal, &pack)
            .to_payload(),
    );
    let mut collision = PackBuilder::new();
    collision
        .file(fx.hasher, "Readme.md", b"a", CodecId::Stored)
        .file(fx.hasher, "readme.md", b"b", CodecId::Stored);
    out.bad(
        "manifest",
        "case-collision",
        fx.manifest_document(FUZZ_VERSION, FUZZ_TARGET, &collision)
            .to_payload(),
    );
    let mut escaping = PackBuilder::new();
    escaping.symlink("lib/x", "../../etc/passwd");
    out.bad(
        "manifest",
        "symlink-escapes",
        fx.manifest_document(FUZZ_VERSION, FUZZ_TARGET, &escaping)
            .to_payload(),
    );
}

fn path_seeds(out: &mut Out) {
    for (name, text) in [
        ("plain", "bin/app"),
        ("nested", "share/doc/README.md"),
        ("nfc-accent", "lib/lib\u{e9}.so.1"),
        ("dotfile", ".config/app.toml"),
    ] {
        out.ok("path", name, text);
    }
    for (name, text) in [
        ("dot-dot", "../x"),
        ("empty-component", "a//b"),
        ("device-name", "dir/CON.txt"),
        ("trailing-space", "a/b "),
        ("absolute", "/abs/path"),
        ("backslash", "x\\y"),
        ("short-name", "PROGRA~1/app"),
        ("nfd-accent", "lib/libe\u{301}.so"),
    ] {
        out.bad("path", name, text);
    }
}

fn tree_seeds(out: &mut Out) {
    out.ok(
        "tree",
        "files-dirs-links",
        "f bin/app\nd share\nf share/a.txt\nl lib/x.so>x.so.1\nf lib/x.so.1\n",
    );
    out.ok("tree", "empty", "");
    out.bad("tree", "case-collision", "f A\nf a\n");
    out.bad("tree", "entry-under-a-file", "f a\nf a/b\n");
    out.bad("tree", "link-escapes", "l x>../../y\n");
    out.bad("tree", "link-through-link", "d w\nl y>w\nl x>y/z\n");
}

fn rules_seeds(out: &mut Out) {
    for (name, text) in [
        ("version", "1.2.3"),
        ("version-pre-build", "1.2.3-rc.1+build.5"),
        ("target", "linux-x86_64"),
        ("app-id", "org.example.hello"),
        ("channel", "stable"),
        ("algorithm", "ed25519"),
        ("codec", "bcj-x86+lzma2"),
        ("hex-digest", &"ab".repeat(32)),
        ("base64", "aGVsbG8="),
        ("reference", "1.2.3/linux-x86_64.manifest.json"),
        ("two-versions", "1.0.0\n2.0.0-rc.1"),
    ] {
        out.ok("rules", name, text);
    }
    out.bad("rules", "control-byte", "\u{0}\u{1}");
    out.ok("rules", "empty-is-valid-base64", "");
}

fn json_seeds(fx: &ChainFixture<'_>, out: &mut Out) {
    out.ok(
        "json",
        "nested",
        r#"{"a":1,"b":[true,null,{"c":"x"}],"d":{"e":{"f":[]}}}"#,
    );
    out.ok(
        "json",
        "key-set-payload",
        fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
    );
    out.ok("json", "escapes", r#"{"a":"é\n\"","b":-0.5e3}"#);
    out.bad("json", "duplicate-key", r#"{"a":1,"a":2}"#);
    out.bad("json", "duplicate-nested-key", r#"{"a":{"b":1,"b":2}}"#);
    out.bad("json", "duplicate-in-array", r#"{"a":[{"b":1,"b":1}]}"#);
    out.bad("json", "trailing-data", r#"{"a":1} x"#);
    out.bad("json", "not-an-object", "[1,2]");
    out.bad("json", "lone-surrogate", r#"{"a":"\ud800"}"#);
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(br#"{"a":1}"#);
    out.bad("json", "byte-order-mark", bom);
    out.bad(
        "json",
        "depth-33",
        format!("{}1{}", r#"{"a":"#.repeat(33), "}".repeat(33)),
    );
}

/// A `frame` input: header, descriptor JSON, frame bytes.
fn frame_input(
    desc: &FrameDesc,
    file_size: u64,
    pack_size: u64,
    file_sha256: Sha256Digest,
    frame: &[u8],
) -> Vec<u8> {
    let json = serde_json::to_vec(desc).expect("descriptor serialises");
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + json.len() + frame.len());
    out.extend_from_slice(&u16::try_from(json.len()).expect("small").to_be_bytes());
    out.extend_from_slice(&file_size.to_be_bytes());
    out.extend_from_slice(&pack_size.to_be_bytes());
    out.extend_from_slice(file_sha256.as_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(frame);
    out
}

/// The identity-coded frame of `data` under `codec` (the harness's codec writes streams unchanged).
fn identity_frame(codec: CodecId, data: &[u8]) -> (FrameDesc, Sha256Digest) {
    let file_hash = FakeHasher.sha256(data);
    let lzma = matches!(
        codec,
        CodecId::Lzma2 | CodecId::BcjX86Lzma2 | CodecId::BcjArm64Lzma2
    );
    let streams = (codec == CodecId::Bcj2).then(|| {
        let each = data.len() / 4;
        let main = data.len() - 3 * each;
        [main, each, each, each]
            .iter()
            .enumerate()
            .map(|(i, &len)| StreamDesc {
                length: u53(len as u64),
                decoded_size: u53(len as u64),
                dict_size: (i < 3).then(|| u53(65_536)),
            })
            .collect()
    });
    let desc = FrameDesc {
        codec: codec.id().to_owned(),
        offset: u53(0),
        length: u53(data.len() as u64),
        sha256: FakeHasher.sha256(data),
        dict_size: lzma.then(|| u53(65_536)),
        streams,
    };
    (desc, file_hash)
}

fn frame_seeds(out: &mut Out) {
    let data: Vec<u8> = (0..200u32).map(|i| (i * 7 + 3) as u8).collect();
    let len = data.len() as u64;
    for codec in [
        CodecId::Stored,
        CodecId::Lzma2,
        CodecId::BcjX86Lzma2,
        CodecId::BcjArm64Lzma2,
        CodecId::Bcj2,
    ] {
        let (desc, file_hash) = identity_frame(codec, &data);
        out.ok(
            "frame",
            codec.id(),
            frame_input(&desc, len, len + 10, file_hash, &data),
        );
    }
    let (desc, file_hash) = identity_frame(CodecId::Lzma2, &data);
    let mut tampered = data.clone();
    tampered[17] ^= 0x01;
    out.bad(
        "frame",
        "frame-bytes-differ-from-the-signed-hash",
        frame_input(&desc, len, len, file_hash, &tampered),
    );
    out.bad(
        "frame",
        "frame-shorter-than-declared",
        frame_input(&desc, len, len, file_hash, &data[..100]),
    );
    let mut bad_dict = desc.clone();
    bad_dict.dict_size = Some(u53(65_535));
    out.bad(
        "frame",
        "dict-size-not-a-power-of-two",
        frame_input(&bad_dict, len, len, file_hash, &data),
    );
    let mut unknown = desc.clone();
    unknown.codec = "LZMA2".to_owned();
    out.bad(
        "frame",
        "codec-id-in-another-case",
        frame_input(&unknown, len, len, file_hash, &data),
    );
    let mut outside = desc.clone();
    outside.offset = u53(len);
    out.bad(
        "frame",
        "frame-outside-the-pack",
        frame_input(&outside, len, len, file_hash, &data),
    );
    let (bcj2, file_hash) = identity_frame(CodecId::Bcj2, &data);
    let mut short_sum = bcj2.clone();
    if let Some(streams) = short_sum.streams.as_mut() {
        streams[0].length = u53(streams[0].length.get() - 1);
    }
    out.bad(
        "frame",
        "bcj2-lengths-do-not-sum-to-the-frame",
        frame_input(&short_sum, len, len, file_hash, &data),
    );
    let mut with_dict = bcj2;
    with_dict.dict_size = Some(u53(65_536));
    out.bad(
        "frame",
        "bcj2-with-a-frame-dict-size",
        frame_input(&with_dict, len, len, file_hash, &data),
    );
}

/// The pack size of the `http` seeds (the size of the GitHub release asset P-N1 fetched).
const HTTP_TOTAL: u64 = 1_787_248;

/// An `http` input: parameter bytes, then one `name: value` line per header.
fn http_input(
    range: Option<ByteRange>,
    total: u64,
    expected_len: u64,
    status: u16,
    headers: &[(&str, &[u8])],
) -> Vec<u8> {
    let flags =
        u8::from(range.is_some()) | (u8::from(range.is_some_and(|r| r.last.is_some())) << 1);
    let range = range.unwrap_or(ByteRange {
        first: 0,
        last: None,
    });
    let mut out = Vec::with_capacity(HTTP_HEADER_LEN + 64 * headers.len());
    out.push(flags);
    out.extend_from_slice(&range.first.to_be_bytes());
    out.extend_from_slice(&range.last.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&expected_len.to_be_bytes());
    out.extend_from_slice(&status.to_be_bytes());
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out
}

fn content_range(first: u64, last: u64, total: u64) -> String {
    ContentRange { first, last, total }.to_string()
}

fn http_seeds(out: &mut Out) {
    let first_100 = Some(ByteRange {
        first: 0,
        last: Some(99),
    });
    let etag = match Validator::from_etag(b"\"5d41402abc4b2a76\"") {
        Some(Validator::StrongETag(tag)) => tag,
        _ => unreachable!("a quoted ASCII tag is a strong validator"),
    };
    let cr = content_range(0, 99, HTTP_TOTAL);
    let total_len = HTTP_TOTAL.to_string();

    out.ok(
        "http",
        "partial",
        http_input(
            first_100,
            HTTP_TOTAL,
            100,
            206,
            &[
                ("content-range", cr.as_bytes()),
                ("content-length", b"100"),
                ("etag", etag.as_bytes()),
                ("last-modified", b"Wed, 21 Oct 2026 07:28:00 GMT"),
            ],
        ),
    );
    out.ok(
        "http",
        "partial-open-ended",
        http_input(
            Some(ByteRange {
                first: HTTP_TOTAL - 100,
                last: None,
            }),
            HTTP_TOTAL,
            100,
            206,
            &[(
                "content-range",
                content_range(HTTP_TOTAL - 100, HTTP_TOTAL - 1, HTTP_TOTAL).as_bytes(),
            )],
        ),
    );
    out.ok(
        "http",
        "full-answering-a-range-request",
        http_input(
            first_100,
            HTTP_TOTAL,
            100,
            200,
            &[("content-length", total_len.as_bytes())],
        ),
    );
    out.ok(
        "http",
        "full-identity-encoding",
        http_input(
            None,
            HTTP_TOTAL,
            HTTP_TOTAL,
            200,
            &[
                ("content-length", total_len.as_bytes()),
                ("content-encoding", b"identity"),
            ],
        ),
    );
    out.ok(
        "http",
        "full-without-content-length",
        http_input(None, HTTP_TOTAL, HTTP_TOTAL, 200, &[("server", b"x")]),
    );

    let partial = |headers: &[(&str, &[u8])]| http_input(first_100, HTTP_TOTAL, 100, 206, headers);
    let cases: [(&str, Vec<u8>); 16] = [
        (
            "unit-in-capitals",
            partial(&[("content-range", b"Bytes 0-99/1787248")]),
        ),
        (
            "two-spaces-after-the-unit",
            partial(&[("content-range", b"bytes  0-99/1787248")]),
        ),
        (
            "unknown-total",
            partial(&[("content-range", b"bytes 0-99/*")]),
        ),
        (
            "unsatisfied-range-form",
            partial(&[("content-range", b"bytes */1787248")]),
        ),
        (
            "last-byte-differs-from-the-request",
            partial(&[("content-range", content_range(0, 98, HTTP_TOTAL).as_bytes())]),
        ),
        (
            "first-byte-differs-from-the-request",
            partial(&[("content-range", content_range(1, 99, HTTP_TOTAL).as_bytes())]),
        ),
        (
            "total-differs-from-the-signed-size",
            partial(&[(
                "content-range",
                content_range(0, 99, HTTP_TOTAL + 1).as_bytes(),
            )]),
        ),
        (
            "seventeen-digits",
            partial(&[("content-range", b"bytes 0-99/10000000000000000")]),
        ),
        (
            "total-above-2-pow-53",
            partial(&[("content-range", b"bytes 0-99/9007199254740992")]),
        ),
        (
            "last-before-first",
            partial(&[("content-range", b"bytes 99-0/1787248")]),
        ),
        (
            "two-content-range-headers",
            partial(&[
                ("content-range", cr.as_bytes()),
                ("content-range", cr.as_bytes()),
            ]),
        ),
        (
            "content-encoding-gzip",
            partial(&[
                ("content-range", cr.as_bytes()),
                ("content-encoding", b"gzip"),
            ]),
        ),
        (
            "content-length-differs",
            partial(&[("content-range", cr.as_bytes()), ("content-length", b"101")]),
        ),
        ("partial-without-content-range", partial(&[])),
        (
            "non-ascii-header-byte",
            partial(&[("content-range", b"bytes 0-99/1787248\xff")]),
        ),
        (
            "unsatisfiable-range-status",
            http_input(first_100, HTTP_TOTAL, 100, 416, &[]),
        ),
    ];
    for (name, bytes) in cases {
        out.bad("http", name, bytes);
    }
    out.bad(
        "http",
        "full-with-a-content-range",
        http_input(
            first_100,
            HTTP_TOTAL,
            100,
            200,
            &[("content-range", cr.as_bytes())],
        ),
    );
}

// ---- state ----------------------------------------------------------------------------------------

/// The install-state record the `state` seeds start from: every field set. `seq` is its number.
fn sample_install_state(seq: u64) -> InstallState {
    let app_id = AppId::parse(FUZZ_APP_ID).expect("fuzz app id");
    let version = |t: &str| Version::parse(t).expect("version");
    let key = |label: &str| PublicKey::from_bytes(*FakeHasher.sha256(label.as_bytes()).as_bytes());
    let mut record = InstallState::new(
        seq,
        app_id,
        Scope::User,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        FUZZ_TARGET,
    );
    record.current = Some(CurrentRef {
        version: version(FUZZ_VERSION),
        issued: SUITE_T0,
    });
    record.previous = Some(PreviousRef {
        version: version("0.9.0"),
    });
    record.staged = Some(StagedRef::new(
        version("1.1.0"),
        FUZZ_TARGET,
        FakeHasher.sha256(b"the 1.1.0 manifest"),
    ));
    record.bad = vec![version("1.0.1"), version("1.0.2-beta.1")];
    record.floors = Floors {
        root: Some(RootParts {
            version: 2,
            threshold: 1,
            keys: vec![key("root key 1"), key("root key 2")],
        }),
        keyset_version: 3,
        feed_seq: [(Channel::parse("stable").expect("channel"), 42)]
            .into_iter()
            .collect(),
    };
    record
}

/// Commits `records` in order into a fresh store and returns the last file's bytes.
fn committed<T: state::Record>(records: &[T]) -> Vec<u8> {
    let fs = MemFs::new();
    let dir = PathBuf::from("/state");
    let mut last = 0;
    for record in records {
        let loaded: Loaded<T> = state::load(&fs, &dir, record.app_id(), &FakeHasher).expect("load");
        state::commit(&fs, &dir, &loaded, record, &FakeHasher).expect("commit");
        last = record.seq();
    }
    record_bytes(&fs, &dir, last)
}

fn record_bytes(fs: &MemFs, dir: &Path, seq: u64) -> Vec<u8> {
    fs.read_capped(&dir.join(format!("{seq:020}.rec")), MAX_RECORD_BYTES)
        .expect("read record")
}

/// The JSON payload of a record file.
fn payload_value(file: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let len = u32::from_be_bytes([file[5], file[6], file[7], file[8]]) as usize;
    serde_json::from_slice(&file[9..9 + len]).expect("payload")
}

/// `payload` (a record payload from `commit`, edited) framed by the real framing code.
fn raw_record(payload: &serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
    let fs = MemFs::new();
    let dir = PathBuf::from("/state");
    let bytes = serde_json::to_vec(payload).expect("payload");
    state::commit_raw_payload(&fs, &dir, STATE_NAME_SEQ, &bytes, &FakeHasher).expect("raw");
    record_bytes(&fs, &dir, STATE_NAME_SEQ)
}

fn state_seeds(out: &mut Out) {
    let valid = committed(&[sample_install_state(STATE_NAME_SEQ)]);
    out.ok("state", "install-state", valid.clone());

    let fresh = InstallState::new(
        STATE_NAME_SEQ,
        AppId::parse(FUZZ_APP_ID).expect("fuzz app id"),
        Scope::Machine,
        [0x5a; 16],
        Target::WindowsX86_64,
    );
    out.ok("state", "install-state-first", committed(&[fresh]));

    let mut counters = InstallCounters::new(
        STATE_NAME_SEQ,
        AppId::parse(FUZZ_APP_ID).expect("fuzz app id"),
        [0x5a; 16],
    );
    counters.floors = sample_install_state(1).floors;
    out.ok("state", "install-counters", committed(&[counters]));

    let mut extra = payload_value(&valid);
    extra.insert("x_future".to_owned(), serde_json::json!({ "a": [1, 2] }));
    extra.insert("health".to_owned(), serde_json::json!({ "t": "token" }));
    out.ok("state", "extra-fields", raw_record(&extra));

    out.bad("state", "torn", valid[..valid.len() / 2].to_vec());
    out.bad("state", "empty", Vec::new());
    let mut flipped = valid.clone();
    flipped[20] ^= 0x01;
    out.bad("state", "flipped-payload", flipped);
    let mut flipped = valid.clone();
    flipped[7] ^= 0x01;
    out.bad("state", "flipped-length", flipped);
    let mut flipped = valid.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    out.bad("state", "flipped-checksum", flipped);
    let mut newer = valid.clone();
    newer[4] = 2;
    out.bad("state", "format-byte-2", newer);
    out.bad(
        "state",
        "renamed",
        committed(&[
            sample_install_state(STATE_NAME_SEQ),
            sample_install_state(STATE_NAME_SEQ + 1),
        ]),
    );

    let mut critical = payload_value(&valid);
    critical.insert("critical".to_owned(), serde_json::json!(["x_future"]));
    out.bad("state", "unknown-critical", raw_record(&critical));
    let mut nested = payload_value(&valid);
    if let Some(serde_json::Value::Object(floors)) = nested.get_mut("floors") {
        floors.insert("x_future".to_owned(), serde_json::json!(1));
    }
    out.bad("state", "unknown-key-in-floors", raw_record(&nested));
    let mut unsorted = payload_value(&valid);
    unsorted.insert("bad".to_owned(), serde_json::json!(["1.0.2", "1.0.1"]));
    out.bad("state", "bad-not-sorted", raw_record(&unsorted));
}

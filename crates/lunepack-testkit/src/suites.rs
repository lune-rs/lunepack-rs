//! Contract suites: one function per trait, run by every adapter's `tests/` against its real
//! implementation and by this crate against the fakes. They panic (assert) on a violation.

use std::io::{self, Read, Write};

use lunepack_core::encoding::{base64_encode, hex_encode};
use lunepack_core::error::FrameError;
use lunepack_core::fetch::classify;
use lunepack_core::frame::{MAX_DICT_SIZE, MIN_DICT_SIZE};
use lunepack_core::{
    BlockingTransport, ByteRange, CancelToken, Clock, Codec, CodecId, DecodeReport, EncodedFrame,
    Encoder, Error, FrameDesc, FrameView, Hasher, Head, Outcome, Request, ResponseInfo,
    Sha256Digest, SignatureAlg, Signer, StreamDesc, StreamView, Transport, TransportError,
    TransportErrorKind, U53, Validator, Verifier, decode_verified,
};

use crate::transport::{SeenRequest, TransportFixture, block_on};

/// A hash known answer: the input and its digest in lowercase hex.
#[derive(Debug, Clone, Copy)]
pub struct HashKat {
    /// The message.
    pub input: &'static [u8],
    /// Its digest, 64 lowercase hex characters.
    pub digest_hex: &'static str,
}

/// SHA-256 known answers (FIPS 180-4 examples). Pass these to [`run_hasher_suite`] for a real
/// SHA-256 implementation; a fake passes its own.
pub const SHA256_KATS: &[HashKat] = &[
    HashKat {
        input: b"",
        digest_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    HashKat {
        input: b"abc",
        digest_hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    HashKat {
        input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        digest_hex: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
];

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect()
}

/// Hasher contract: every known answer in `kats` matches; a streaming computation split at every
/// boundary of a 1 KiB input equals the one-shot digest; the one-shot digest is stable and depends
/// on the input.
pub fn run_hasher_suite(hasher: &dyn Hasher, kats: &[HashKat]) {
    for kat in kats {
        let want = Sha256Digest::from_hex(kat.digest_hex).expect("kat digest is valid hex");
        assert_eq!(
            hasher.sha256(kat.input),
            want,
            "one-shot KAT {:?}",
            kat.input
        );
        let mut state = hasher.sha256_start();
        state.update(kat.input);
        assert_eq!(state.finalize(), want, "streaming KAT {:?}", kat.input);
    }

    let data = pattern(1024);
    let whole = hasher.sha256(&data);
    assert_eq!(whole, hasher.sha256(&data), "one-shot is deterministic");
    for split in 0..=data.len() {
        let mut state = hasher.sha256_start();
        state.update(&data[..split]);
        state.update(&data[split..]);
        assert_eq!(state.finalize(), whole, "streaming split at {split}");
    }
    let mut state = hasher.sha256_start();
    for byte in &data {
        state.update(std::slice::from_ref(byte));
    }
    assert_eq!(state.finalize(), whole, "byte-at-a-time streaming");

    let mut changed = data.clone();
    changed[512] ^= 1;
    assert_ne!(
        hasher.sha256(&changed),
        whole,
        "a flipped input bit changes the digest"
    );
    assert_ne!(
        hasher.sha256(&data[..1023]),
        whole,
        "a shorter input changes the digest"
    );
    // An empty update must not change the result.
    let mut state = hasher.sha256_start();
    state.update(&[]);
    state.update(&data);
    state.update(&[]);
    assert_eq!(state.finalize(), whole, "empty updates are no-ops");
}

/// A verify-only known answer (for example an RFC 8032 vector): it must be accepted.
#[derive(Debug, Clone)]
pub struct VerifyKat {
    /// The public key.
    pub public_key: [u8; 32],
    /// The message.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: [u8; 64],
}

/// Makes a key pair from a seed and signs: `(seed, message) -> (public_key, signature)`.
pub type SignFixture<'a> = dyn Fn(u8, &[u8]) -> ([u8; 32], [u8; 64]) + 'a;

/// Verifier contract. `sign(seed, message)` returns `(public_key, signature)` for the key pair the
/// adapter's fixture derives from `seed`; different seeds must give different keys. Checks that a
/// valid signature is accepted, that a flipped message bit, signature bit or key bit, a signature
/// made under another key, and an empty-for-non-empty message swap are rejected, and that every
/// entry of `kats` is accepted. Key validation (FORMAT.md 2.5): every fixture key and KAT key
/// passes `check_public_key`; every entry of `invalid_keys` (the adapter supplies at least a
/// small-order and a non-canonical key) fails `check_public_key` and fails `verify` even with a
/// signature the fixture made.
///
/// A signature of the wrong length is not testable here: the trait takes `&[u8; 64]`, so a wrong
/// length cannot be expressed; the types enforce it.
pub fn run_verifier_suite(
    verifier: &dyn Verifier,
    sign: &SignFixture<'_>,
    kats: &[VerifyKat],
    invalid_keys: &[[u8; 32]],
) {
    let alg = SignatureAlg::Ed25519;
    let messages: [Vec<u8>; 3] = [Vec::new(), b"lunepack".to_vec(), pattern(1024)];
    for message in &messages {
        let (pk, sig) = sign(1, message);
        verifier
            .verify(alg, &pk, message, &sig)
            .expect("a valid signature is accepted");

        if !message.is_empty() {
            let mut bad = message.clone();
            bad[message.len() / 2] ^= 0x01;
            assert!(
                verifier.verify(alg, &pk, &bad, &sig).is_err(),
                "flipped message bit accepted"
            );
            assert!(
                verifier.verify(alg, &pk, &[], &sig).is_err(),
                "signature accepted for an empty message"
            );
        }
        for index in [0usize, 31, 32, 63] {
            let mut bad = sig;
            bad[index] ^= 0x80;
            assert!(
                verifier.verify(alg, &pk, message, &bad).is_err(),
                "flipped signature bit {index} accepted"
            );
        }
        for index in [0usize, 31] {
            let mut bad = pk;
            bad[index] ^= 0x01;
            assert!(
                verifier.verify(alg, &bad, message, &sig).is_err(),
                "flipped key bit {index} accepted"
            );
        }
        let (other_pk, other_sig) = sign(2, message);
        assert_ne!(pk, other_pk, "fixture must give different keys per seed");
        assert!(
            verifier.verify(alg, &other_pk, message, &sig).is_err(),
            "signature accepted under another key"
        );
        assert!(
            verifier.verify(alg, &pk, message, &other_sig).is_err(),
            "another key's signature accepted"
        );
    }

    for (i, kat) in kats.iter().enumerate() {
        verifier
            .verify(alg, &kat.public_key, &kat.message, &kat.signature)
            .unwrap_or_else(|e| panic!("known answer {i} rejected: {e}"));
        verifier
            .check_public_key(alg, &kat.public_key)
            .unwrap_or_else(|e| panic!("known answer {i} key rejected: {e}"));
    }

    assert!(
        invalid_keys.len() >= 2,
        "supply at least a small-order and a non-canonical key"
    );
    for seed in 1..=2u8 {
        let (pk, _) = sign(seed, b"");
        verifier
            .check_public_key(alg, &pk)
            .unwrap_or_else(|e| panic!("fixture key {seed} rejected: {e}"));
    }
    let (_, sig) = sign(1, b"lunepack");
    for (i, key) in invalid_keys.iter().enumerate() {
        assert!(
            verifier.check_public_key(alg, key).is_err(),
            "invalid key {i} passed check_public_key"
        );
        assert!(
            verifier.verify(alg, key, b"lunepack", &sig).is_err(),
            "invalid key {i} accepted by verify"
        );
    }
}

/// Clock contract: readings never go backwards within a test. With `shifted`, a factory for a
/// clock set to the given Unix seconds, also checks that far-future times (2100-01-01 and 400 days
/// past it) are read back without a panic and without going backwards. A real clock cannot be
/// moved, so its adapter passes `None`.
pub fn run_clock_suite(clock: &dyn Clock, shifted: Option<&dyn Fn(u64) -> Box<dyn Clock>>) {
    let mut last = clock.now_unix_secs();
    for _ in 0..100 {
        let now = clock.now_unix_secs();
        assert!(now >= last, "clock went backwards: {last} then {now}");
        last = now;
    }
    if let Some(make) = shifted {
        for secs in [
            crate::YEAR_2100_UNIX_SECS,
            crate::YEAR_2100_UNIX_SECS + 400 * 86_400,
        ] {
            let far = make(secs);
            let first = far.now_unix_secs();
            assert!(first >= secs, "shifted clock reads {first}, set to {secs}");
            assert!(far.now_unix_secs() >= first, "shifted clock went backwards");
        }
    }
}

/// Signer contract. `verifier` must be a real verifier for the signer's algorithm; `secret_probe`
/// is the signer's private key material as the test knows it (non-empty). Checks that the
/// signature over each of three messages (empty, one byte, 1 MiB) verifies under `public_key()`,
/// that `public_key()` passes `check_public_key`, that signing is deterministic, that another
/// message's signature does not verify, and that neither `{signer:?}` nor `{signer:#?}` contains
/// `secret_probe` as hex (either case), as base64 (standard and URL-safe alphabets, with and
/// without padding) or as a rendered byte list (`[1, 2, 3]`).
pub fn run_signer_suite(signer: &dyn Signer, verifier: &dyn Verifier, secret_probe: &[u8]) {
    assert!(!secret_probe.is_empty(), "secret_probe must not be empty");
    let alg = signer.alg();
    let pk = signer.public_key();
    verifier
        .check_public_key(alg, &pk)
        .expect("the signer's public key is a valid key");
    assert_eq!(pk, signer.public_key(), "public_key is stable");

    let messages: [Vec<u8>; 3] = [Vec::new(), vec![0x5a], pattern(1024 * 1024)];
    let mut sigs = Vec::new();
    for message in &messages {
        let sig = signer.sign(message).expect("signing succeeds");
        verifier
            .verify(alg, &pk, message, &sig)
            .unwrap_or_else(|e| panic!("signature over {} bytes rejected: {e}", message.len()));
        assert_eq!(
            sig,
            signer.sign(message).expect("signing succeeds"),
            "signing is deterministic ({} bytes)",
            message.len()
        );
        sigs.push(sig);
    }
    for (i, sig) in sigs.iter().enumerate() {
        for (j, message) in messages.iter().enumerate() {
            if i != j {
                assert!(
                    verifier.verify(alg, &pk, message, sig).is_err(),
                    "the signature over message {i} verifies for message {j}"
                );
            }
        }
    }

    let std_b64 = base64_encode(secret_probe);
    let url_b64 = std_b64.replace('+', "-").replace('/', "_");
    let hex = hex_encode(secret_probe);
    let needles = [
        ("hex", hex.clone()),
        ("upper-case hex", hex.to_uppercase()),
        ("base64", std_b64.clone()),
        ("unpadded base64", std_b64.trim_end_matches('=').to_owned()),
        ("URL-safe base64", url_b64.clone()),
        (
            "unpadded URL-safe base64",
            url_b64.trim_end_matches('=').to_owned(),
        ),
        ("byte list", format!("{secret_probe:?}")),
    ];
    for shown in [format!("{signer:?}"), format!("{signer:#?}")] {
        for (what, needle) in &needles {
            assert!(
                !shown.contains(needle.as_str()),
                "Debug output contains the secret as {what}"
            );
        }
    }
}

// ---- codec suite ------------------------------------------------------------------------------

/// xorshift64*: a fixed-seed byte source, so every run sees the same inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 56) as u8).collect()
    }
}

fn text(len: usize) -> Vec<u8> {
    let line = b"The quick brown fox jumps over the lazy dog; lunepack frames every file. ";
    line.iter().copied().cycle().take(len).collect()
}

/// Bytes shaped like x86 code: runs of filler broken by `E8`/`E9` and a small little-endian
/// relative offset, which is what the BCJ filters rewrite.
fn x86_like(len: usize, rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        let filler = (rng.next() >> 60) as usize + 1;
        for _ in 0..filler {
            out.push(0x48 + ((rng.next() >> 61) as u8));
        }
        out.push(if rng.next() & 1 == 0 { 0xE8 } else { 0xE9 });
        let rel = ((rng.next() >> 48) as i32 % 4096) - 2048;
        out.extend_from_slice(&rel.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// 64 KiB made of one random 32 KiB block twice: every match of the second half reaches back
/// 32 KiB.
fn long_repeats(rng: &mut Rng) -> Vec<u8> {
    let block = rng.bytes(32 * 1024);
    [block.clone(), block].concat()
}

fn u53(value: u64) -> U53 {
    U53::new(value).expect("value below 2^53")
}

fn describe(hasher: &dyn Hasher, enc: &EncodedFrame) -> FrameDesc {
    FrameDesc {
        codec: enc.codec.id().to_owned(),
        offset: u53(0),
        length: u53(enc.bytes.len() as u64),
        sha256: hasher.sha256(&enc.bytes),
        dict_size: enc.dict_size.map(|d| u53(u64::from(d))),
        streams: enc.streams.as_ref().map(|streams| {
            streams
                .iter()
                .map(|s| StreamDesc {
                    length: u53(s.length),
                    decoded_size: u53(s.decoded_size),
                    dict_size: s.dict_size.map(|d| u53(u64::from(d))),
                })
                .collect()
        }),
    }
}

/// Sets the descriptor's frame `length` and `sha256` to those of `bytes`.
fn rehash(hasher: &dyn Hasher, desc: &mut FrameDesc, bytes: &[u8]) {
    desc.length = u53(bytes.len() as u64);
    desc.sha256 = hasher.sha256(bytes);
}

/// A codec that must never run.
struct NeverCalled;

impl Codec for NeverCalled {
    fn decode(&self, _: &FrameView<'_>, _: &mut dyn Write) -> Result<DecodeReport, Error> {
        panic!("the codec ran on a frame that must be rejected first");
    }
}

/// Fails every write that would take the total past `limit` bytes, and counts the writes that are
/// attempted after the first failure.
struct FailAfter {
    limit: usize,
    accepted: usize,
    failed: bool,
    after_failure: usize,
}

impl FailAfter {
    fn new(limit: usize) -> Self {
        FailAfter {
            limit,
            accepted: 0,
            failed: false,
            after_failure: 0,
        }
    }
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            self.after_failure += 1;
            return Err(io::Error::other("injected failure"));
        }
        if self.accepted + buf.len() > self.limit {
            self.failed = true;
            return Err(io::Error::other("injected failure"));
        }
        self.accepted += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The file `input` through core's descriptor check and `decode_verified`.
fn through_core(
    hasher: &dyn Hasher,
    codec: &dyn Codec,
    desc: &FrameDesc,
    bytes: &[u8],
    input: &[u8],
    out: &mut dyn Write,
) -> Result<(), Error> {
    let frame = desc.check(input.len() as u64, hasher.sha256(input), bytes.len() as u64)?;
    decode_verified(&frame, bytes, hasher, codec, out)
}

/// `Codec::decode` directly on the descriptor's streams, bypassing every core check.
fn direct(
    codec: &dyn Codec,
    id: CodecId,
    desc: &FrameDesc,
    bytes: &[u8],
    file_size: u64,
    out: &mut dyn Write,
) -> Result<DecodeReport, Error> {
    let dict = |d: Option<U53>| d.map(|d| u32::try_from(d.get()).expect("dict_size fits u32"));
    let mut views = Vec::new();
    match &desc.streams {
        Some(streams) => {
            let mut at = 0usize;
            for s in streams {
                let len = usize::try_from(s.length.get()).expect("length fits usize");
                views.push(StreamView {
                    input: &bytes[at..at + len],
                    decoded_size: s.decoded_size.get(),
                    dict_size: dict(s.dict_size),
                });
                at += len;
            }
        }
        None => views.push(StreamView {
            input: bytes,
            decoded_size: file_size,
            dict_size: dict(desc.dict_size),
        }),
    }
    codec.decode(
        &FrameView {
            codec: id,
            output_size: file_size,
            streams: &views,
        },
        out,
    )
}

fn frame_error(err: &Error) -> Option<&FrameError> {
    match err {
        Error::Frame(e) => Some(e),
        _ => None,
    }
}

/// Codec contract: an `encoder`/`codec` pair, with `hasher` the digest the descriptors use, run
/// through core's `FrameDesc::check` and `decode_verified` wherever core can express the case and
/// through `Codec::decode` directly otherwise.
///
/// A codec id is tested when `encoder` encodes one byte with it; at least one must be. Inputs per
/// id: 1 byte, 64 KiB pseudo-random (fixed seed), 256 KiB of repeated text, 64 KiB of x86-like
/// code (an empty file has no frame, FORMAT.md 8.1, so it is not a case). Each input must satisfy:
///
/// 1. the round trip equals the input;
/// 2. `encode` is deterministic;
/// 3. the descriptor fields are valid: `dict_size` a power of two in 4096..=16 MiB and at least
///    the stream's decoded length when that is at most 16 MiB; BCJ2 lengths at least 1 and
///    summing to the frame's length;
/// 4. one flipped byte in the frame is `FrameHash`, and the codec never runs;
/// 5. a flipped byte with the frame hash recomputed is an `Err` (frames under 32 bytes of a
///    compressed codec are skipped: a flipped bit in a range coder's tail can be harmless);
/// 6. a `dict_size` of 32 MiB is rejected before decoding;
/// 7. a `dict_size` of 4096 on a frame of 64 KiB with 32 KiB repeats is an `Err`;
/// 8. the frame truncated by one byte (hash and lengths recomputed) is an `Err`;
/// 9. one trailing byte (hash and lengths recomputed) is an `Err`;
/// 10. BCJ2 lengths that do not add up are `LengthSum`;
/// 11. (F6) BCJ2 with MAIN's `decoded_size` + 1 and CALL's (or JUMP's) - 1, the total unchanged,
///     is an `Err` through both paths;
/// 12. a writer failing after N bytes gives an `Err` and no write after the failure, through both
///     paths.
pub fn run_codec_suite(codec: &dyn Codec, encoder: &dyn Encoder, hasher: &dyn Hasher) {
    const IDS: [CodecId; 5] = [
        CodecId::Stored,
        CodecId::Lzma2,
        CodecId::BcjX86Lzma2,
        CodecId::BcjArm64Lzma2,
        CodecId::Bcj2,
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("1 byte", vec![0x41]),
        ("64 KiB random", rng.bytes(64 * 1024)),
        ("256 KiB text", text(256 * 1024)),
        ("64 KiB x86-like", x86_like(64 * 1024, &mut rng)),
    ];
    let repeats = long_repeats(&mut rng);

    let mut tested = 0;
    for id in IDS {
        if encoder.encode(id, &[0x41]).is_err() {
            continue;
        }
        tested += 1;
        for (name, input) in &inputs {
            codec_cases(codec, encoder, hasher, id, name, input);
        }
        if id != CodecId::Stored {
            long_distance_case(codec, encoder, hasher, id, &repeats);
        }
    }
    assert!(tested > 0, "the encoder supports no codec id");
}

fn codec_cases(
    codec: &dyn Codec,
    encoder: &dyn Encoder,
    hasher: &dyn Hasher,
    id: CodecId,
    name: &str,
    input: &[u8],
) {
    let ctx = format!("{id:?} / {name}");
    let enc = encoder
        .encode(id, input)
        .unwrap_or_else(|e| panic!("{ctx}: encode failed: {e}"));
    assert_eq!(enc.codec, id, "{ctx}: the frame names its codec");
    assert!(!enc.bytes.is_empty(), "{ctx}: empty frame");
    let desc = describe(hasher, &enc);
    let bytes = &enc.bytes;

    // 1. round trip
    let mut out = Vec::new();
    through_core(hasher, codec, &desc, bytes, input, &mut out)
        .unwrap_or_else(|e| panic!("{ctx}: round trip failed: {e}"));
    assert_eq!(out, input, "{ctx}: round trip differs");

    // 2. deterministic
    let again = encoder.encode(id, input).expect("second encode");
    assert_eq!(enc, again, "{ctx}: encode is not deterministic");

    // 3. descriptor valid
    check_descriptor(&ctx, &enc, input.len() as u64);

    // 4. a flipped byte is a frame-hash failure and the codec never runs
    for at in [0, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[at] ^= 0xFF;
        let err = through_core(hasher, &NeverCalled, &desc, &bad, input, &mut Vec::new())
            .expect_err("a flipped byte must be rejected");
        assert_eq!(
            frame_error(&err),
            Some(&FrameError::FrameHash),
            "{ctx}: flip at {at}: {err}"
        );
    }

    // 5. a flipped byte with the frame hash recomputed
    if id == CodecId::Stored || bytes.len() >= 32 {
        for at in [bytes.len() / 4, bytes.len() / 2] {
            let mut bad = bytes.clone();
            bad[at] ^= 0xFF;
            let mut bad_desc = desc.clone();
            rehash(hasher, &mut bad_desc, &bad);
            let res = through_core(hasher, codec, &bad_desc, &bad, input, &mut Vec::new());
            assert!(
                res.is_err(),
                "{ctx}: flip at {at} with a fresh hash decoded"
            );
        }
    }

    // 6. dict_size above the cap is rejected before decoding
    if id != CodecId::Stored {
        let mut big = desc.clone();
        let cap = u53(2 * MAX_DICT_SIZE);
        match big.streams.as_mut() {
            Some(streams) => streams[0].dict_size = Some(cap),
            None => big.dict_size = Some(cap),
        }
        let err = through_core(hasher, &NeverCalled, &big, bytes, input, &mut Vec::new())
            .expect_err("a dict_size above the cap must be rejected");
        assert!(
            matches!(frame_error(&err), Some(FrameError::DictSize { .. })),
            "{ctx}: {err}"
        );
    }

    // 8. truncated by one byte
    {
        let mut short = bytes.clone();
        short.pop();
        let mut short_desc = desc.clone();
        if let Some(last) = short_desc.streams.as_mut().and_then(|s| s.last_mut())
            && last.length.get() > 1
        {
            last.length = u53(last.length.get() - 1);
            last.decoded_size = u53(last.decoded_size.get() - 1);
        }
        if !short.is_empty() {
            rehash(hasher, &mut short_desc, &short);
        }
        let res = through_core(hasher, codec, &short_desc, &short, input, &mut Vec::new());
        assert!(res.is_err(), "{ctx}: a truncated frame decoded");
    }

    // 9. one trailing byte
    {
        let mut long = bytes.clone();
        long.push(0);
        let mut long_desc = desc.clone();
        if let Some(last) = long_desc.streams.as_mut().and_then(|s| s.last_mut()) {
            last.length = u53(last.length.get() + 1);
            last.decoded_size = u53(last.decoded_size.get() + 1);
        }
        rehash(hasher, &mut long_desc, &long);
        let res = through_core(hasher, codec, &long_desc, &long, input, &mut Vec::new());
        assert!(res.is_err(), "{ctx}: a frame with a trailing byte decoded");
    }

    if let Some(streams) = &desc.streams {
        // 10. lengths that do not add up
        let mut off = desc.clone();
        let first = &mut off.streams.as_mut().expect("streams")[0];
        first.length = u53(first.length.get() + 1);
        let err = through_core(hasher, &NeverCalled, &off, bytes, input, &mut Vec::new())
            .expect_err("lengths that do not add up must be rejected");
        assert_eq!(frame_error(&err), Some(&FrameError::LengthSum), "{ctx}");

        // 11. F6: per-stream decoded sizes that lie while the total does not
        let donor = [1usize, 2]
            .into_iter()
            .find(|&i| streams[i].decoded_size.get() > 0);
        if let Some(donor) = donor {
            let mut lie = desc.clone();
            let s = lie.streams.as_mut().expect("streams");
            s[0].decoded_size = u53(s[0].decoded_size.get() + 1);
            s[donor].decoded_size = u53(s[donor].decoded_size.get() - 1);
            let res = through_core(hasher, codec, &lie, bytes, input, &mut Vec::new());
            assert!(
                res.is_err(),
                "{ctx}: lying stream sizes decoded (core path)"
            );
            let res = direct(codec, id, &lie, bytes, input.len() as u64, &mut Vec::new());
            assert!(res.is_err(), "{ctx}: lying stream sizes decoded (direct)");
        }
    }

    // 12. a writer failing after N bytes
    let limit = input.len() / 2;
    let mut w = FailAfter::new(limit);
    let err = through_core(hasher, codec, &desc, bytes, input, &mut w)
        .expect_err("a failing writer must fail the decode");
    assert!(
        matches!(frame_error(&err), Some(FrameError::OutputWrite { .. })),
        "{ctx}: {err}"
    );
    assert_eq!(w.after_failure, 0, "{ctx}: writes after the failure (core)");
    let mut w = FailAfter::new(limit);
    let res = direct(codec, id, &desc, bytes, input.len() as u64, &mut w);
    assert_eq!(
        w.after_failure, 0,
        "{ctx}: writes after the failure (direct)"
    );
    assert!(
        res.is_err(),
        "{ctx}: a failing writer did not fail the decode"
    );
}

fn check_descriptor(ctx: &str, enc: &EncodedFrame, input_len: u64) {
    let valid_dict = |dict: u32, decoded: u64| {
        let dict = u64::from(dict);
        assert!(
            (MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict) && dict.is_power_of_two(),
            "{ctx}: dict_size {dict} is not a power of two in 4096..=16 MiB"
        );
        if decoded <= MAX_DICT_SIZE {
            assert!(
                dict >= decoded,
                "{ctx}: dict_size {dict} < decoded {decoded}"
            );
        }
    };
    match enc.codec {
        CodecId::Stored => {
            assert!(enc.dict_size.is_none() && enc.streams.is_none(), "{ctx}");
            assert_eq!(enc.bytes.len() as u64, input_len, "{ctx}: stored length");
        }
        CodecId::Bcj2 => {
            assert!(
                enc.dict_size.is_none(),
                "{ctx}: bcj2 has no frame dict_size"
            );
            let streams = enc.streams.as_ref().expect("bcj2 carries streams");
            assert_eq!(streams.len(), 4, "{ctx}: bcj2 has four streams");
            let mut sum = 0u64;
            for (i, s) in streams.iter().enumerate() {
                assert!(s.length >= 1, "{ctx}: stream {i} is empty");
                sum += s.length;
                match (i, s.dict_size) {
                    (3, None) => {}
                    (3, Some(_)) => panic!("{ctx}: RC has a dict_size"),
                    (_, Some(d)) => valid_dict(d, s.decoded_size),
                    (_, None) => panic!("{ctx}: stream {i} has no dict_size"),
                }
            }
            assert_eq!(sum, enc.bytes.len() as u64, "{ctx}: stream lengths");
        }
        _ => {
            assert!(enc.streams.is_none(), "{ctx}: only bcj2 has streams");
            valid_dict(
                enc.dict_size.expect("LZMA2 variants carry dict_size"),
                input_len,
            );
        }
    }
}

/// Case 7: a 4096-byte dictionary on a frame whose matches reach back 32 KiB.
fn long_distance_case(
    codec: &dyn Codec,
    encoder: &dyn Encoder,
    hasher: &dyn Hasher,
    id: CodecId,
    input: &[u8],
) {
    let ctx = format!("{id:?} / long-distance repeats");
    let enc = encoder
        .encode(id, input)
        .unwrap_or_else(|e| panic!("{ctx}: encode failed: {e}"));
    let mut desc = describe(hasher, &enc);
    let small = Some(u53(MIN_DICT_SIZE));
    match desc.streams.as_mut() {
        Some(streams) => streams[..3].iter_mut().for_each(|s| s.dict_size = small),
        None => desc.dict_size = small,
    }
    let res = through_core(hasher, codec, &desc, &enc.bytes, input, &mut Vec::new());
    assert!(res.is_err(), "{ctx}: decoded with a dictionary of 4096");
}

// ---- transport suites (M4 step 2) -----------------------------------------------------------------

/// How a suite gets one whole response from the transport under test.
trait SuiteClient {
    fn fetch(&self, request: Request) -> Result<(Head, Vec<u8>), TransportError>;
}

struct BlockingClient<'a>(&'a dyn BlockingTransport);

impl SuiteClient for BlockingClient<'_> {
    fn fetch(&self, request: Request) -> Result<(Head, Vec<u8>), TransportError> {
        let response = self.0.get(&request, &CancelToken::new())?;
        let mut body = Vec::new();
        let mut reader = response.body;
        reader.read_to_end(&mut body).map_err(|e| {
            match e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<TransportError>())
            {
                Some(_) => {
                    TransportError::new(TransportErrorKind::Io, &request.url, Some(e.into()))
                }
                None => panic!("body read failed with a plain I/O error: {e}"),
            }
        })?;
        Ok((response.head, body))
    }
}

struct AsyncClient<'a>(&'a dyn Transport);

impl SuiteClient for AsyncClient<'_> {
    fn fetch(&self, request: Request) -> Result<(Head, Vec<u8>), TransportError> {
        let future = self.0.get(request);
        block_on(async move {
            let mut response = future.await?;
            let mut body = Vec::new();
            while let Some(chunk) = response.body.next_chunk().await? {
                assert!(!chunk.is_empty(), "a body chunk is never empty");
                body.extend_from_slice(&chunk);
            }
            Ok((response.head, body))
        })
    }
}

fn get(
    client: &dyn SuiteClient,
    base: &str,
    name: &str,
    range: Option<ByteRange>,
    if_range: Option<Validator>,
) -> (Head, Vec<u8>) {
    let url = format!("{}/{name}", base.trim_end_matches('/'));
    client
        .fetch(Request {
            url,
            range,
            if_range,
        })
        .unwrap_or_else(|e| panic!("GET {name} {range:?} failed: {e}"))
}

fn bounded(first: u64, last: u64) -> Option<ByteRange> {
    Some(ByteRange {
        first,
        last: Some(last),
    })
}

fn transport_cases(client: &dyn SuiteClient, base: &str, seen: &dyn Fn() -> Vec<SeenRequest>) {
    let large = TransportFixture::bytes(TransportFixture::LARGE).expect("fixture");
    let len = large.len() as u64;

    // Whole files, with their exact bytes.
    for name in [
        TransportFixture::EMPTY,
        TransportFixture::ONE_BYTE,
        TransportFixture::LARGE,
    ] {
        let (head, body) = get(client, base, name, None, None);
        assert_eq!(head.status, 200, "{name}: status");
        assert_eq!(
            body,
            TransportFixture::bytes(name).expect("fixture"),
            "{name}: body"
        );
    }
    let (head, _) = get(client, base, TransportFixture::LARGE, None, None);
    let info = ResponseInfo::from_head(&head).expect("a plain 200 passes the response rules");
    assert_eq!(
        info.content_length,
        Some(len),
        "content-length of the large file"
    );
    let Some(Validator::StrongETag(etag)) = info.validator.clone() else {
        panic!("the large file's answer has no strong etag: {head:?}");
    };

    // A closed range: 206 with the exact content-range.
    let first_100 = bounded(0, 99);
    let (head, body) = get(client, base, TransportFixture::LARGE, first_100, None);
    assert_eq!(head.status, 206, "range 0-99: status");
    assert_eq!(body, &large[..100], "range 0-99: body");
    let range_value = head
        .headers
        .iter()
        .find(|(n, _)| n == "content-range")
        .map(|(_, v)| v.clone());
    assert_eq!(
        range_value.as_deref(),
        Some(format!("bytes 0-99/{len}").as_bytes()),
        "range 0-99: content-range"
    );
    let info = ResponseInfo::from_head(&head).expect("a 206 passes the response rules");
    assert_eq!(
        classify(first_100, &info, len, 100),
        Ok(Outcome::Partial { first: 0, last: 99 }),
        "range 0-99: classify"
    );

    // An open range.
    let from = len - 1000;
    let (head, body) = get(
        client,
        base,
        TransportFixture::LARGE,
        Some(ByteRange {
            first: from,
            last: None,
        }),
        None,
    );
    assert_eq!(head.status, 206, "open range: status");
    assert_eq!(body, &large[from as usize..], "open range: body");
    let info = ResponseInfo::from_head(&head).expect("rules");
    assert_eq!(
        info.content_range.map(|c| (c.first, c.last, c.total)),
        Some((from, len - 1, len)),
        "open range: content-range"
    );

    // If-Range: the current validators keep the range, a stale one drops it.
    let (head, body) = get(
        client,
        base,
        TransportFixture::LARGE,
        first_100,
        Some(Validator::StrongETag(etag.clone())),
    );
    assert_eq!(head.status, 206, "If-Range with the current etag: status");
    assert_eq!(body, &large[..100], "If-Range with the current etag: body");
    let last_modified = head
        .headers
        .iter()
        .find(|(n, _)| n == "last-modified")
        .and_then(|(_, v)| Validator::from_last_modified(v))
        .expect("the answer has a last-modified");
    let (head, _) = get(
        client,
        base,
        TransportFixture::LARGE,
        first_100,
        Some(last_modified),
    );
    assert_eq!(
        head.status, 206,
        "If-Range with the current last-modified: status"
    );
    let stale = Validator::from_etag(b"\"stale\"").expect("a strong tag");
    let (head, body) = get(
        client,
        base,
        TransportFixture::LARGE,
        first_100,
        Some(stale),
    );
    assert_eq!(head.status, 200, "If-Range with a stale etag: status");
    assert_eq!(body, large, "If-Range with a stale etag: the full body");
    assert!(
        head.headers.iter().all(|(n, _)| n != "content-range"),
        "a 200 has no content-range"
    );

    // A missing name is a 404 head, not an error.
    let (head, _) = get(client, base, TransportFixture::MISSING, None, None);
    assert_eq!(head.status, 404, "missing file");

    // A redirect is followed to the final response.
    let (head, body) = get(client, base, TransportFixture::ALIAS, None, None);
    assert_eq!(head.status, 200, "redirect: final status");
    assert_eq!(body, large, "redirect: final body");

    // Header names are lowercase and a duplicate arrives twice, in order.
    let (head, _) = get(client, base, TransportFixture::DUPLICATE, None, None);
    assert!(
        head.headers
            .iter()
            .all(|(n, _)| *n == n.to_ascii_lowercase()),
        "header names are lowercased: {head:?}"
    );
    let dups: Vec<&[u8]> = head
        .headers
        .iter()
        .filter(|(n, _)| n == "x-dup")
        .map(|(_, v)| v.as_slice())
        .collect();
    assert_eq!(
        dups,
        [&b"one"[..], b"two"],
        "a duplicate header arrives twice"
    );
    assert!(
        head.headers
            .iter()
            .any(|(n, v)| n == "x-mixed-case" && v == b"v"),
        "a mixed-case header arrives lowercased: {head:?}"
    );

    // What was sent: no accept-encoding anywhere, and the range and validator exactly as given.
    let log = seen();
    assert!(!log.is_empty(), "the request log is empty");
    assert!(
        log.iter().all(|r| r.accept_encoding.is_none()),
        "a request carried accept-encoding: {log:?}"
    );
    let large_url = format!("/{}", TransportFixture::LARGE);
    assert!(
        log.iter().any(|r| r.url.ends_with(&large_url)
            && r.range_header.as_deref() == Some("bytes=0-99")
            && r.if_range.is_none()),
        "no request with exactly Range: bytes=0-99: {log:?}"
    );
    assert!(
        log.iter()
            .any(|r| r.range_header.as_deref() == Some(format!("bytes={from}-").as_str())),
        "no request with the open range: {log:?}"
    );
    assert!(
        log.iter()
            .any(|r| r.if_range.as_deref() == Some(etag.as_str())),
        "no request with If-Range: {etag}: {log:?}"
    );
    assert!(
        log.iter()
            .any(|r| r.url.ends_with(&format!("/{}", TransportFixture::ALIAS)))
            && log.iter().filter(|r| r.url.ends_with(&large_url)).count() >= 2,
        "the redirect hop was not logged: {log:?}"
    );
}

/// Transport contract for the sync trait. `base_url` serves [`TransportFixture`] (for a real
/// server, `LoopbackServer::fixture`; for a fake, its `fixture()` and `FAKE_BASE_URL`), and `seen`
/// returns the requests the server saw (`FakeOrigin::requests`). Checks:
///
/// 1. whole files (0 B, 1 B, 100 KiB) arrive with their exact bytes;
/// 2. `Range: bytes=0-99` is a `206` with `content-range: bytes 0-99/<len>` that passes the core's
///    response rules, and an open range `first-` works;
/// 3. `If-Range` with the current `ETag` or `Last-Modified` keeps the range (`206`), a stale
///    `ETag` gives `200` with the full body;
/// 4. a missing name is a `404` head, not an error;
/// 5. a `302` is followed;
/// 6. header names arrive lowercased and a duplicated header arrives twice;
/// 7. no `Accept-Encoding` is ever sent, and the range and validator reach the server exactly as
///    given;
/// 8. a `CancelToken` cancelled before `get` fails with `TransportErrorKind::Cancelled`.
pub fn run_blocking_transport_suite(
    transport: &dyn BlockingTransport,
    base_url: &str,
    seen: &dyn Fn() -> Vec<SeenRequest>,
) {
    transport_cases(&BlockingClient(transport), base_url, seen);
    let cancel = CancelToken::new();
    cancel.cancel();
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        TransportFixture::LARGE
    );
    let request = Request {
        url,
        range: None,
        if_range: None,
    };
    match transport.get(&request, &cancel) {
        Err(e) => assert_eq!(
            e.kind,
            TransportErrorKind::Cancelled,
            "a cancelled token before get: {e}"
        ),
        Ok(_) => panic!("get succeeded with a cancelled token"),
    }
}

/// Transport contract for the async trait: checks 1 to 7 of [`run_blocking_transport_suite`] (the
/// async `get` takes no token, so cancellation there is dropping the future). The futures are
/// driven by a std-only `block_on` private to the testkit.
pub fn run_transport_suite(
    transport: &dyn Transport,
    base_url: &str,
    seen: &dyn Fn() -> Vec<SeenRequest>,
) {
    transport_cases(&AsyncClient(transport), base_url, seen);
}

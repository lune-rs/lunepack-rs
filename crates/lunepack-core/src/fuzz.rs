//! Fuzz entry points (M2-D8): `fn(&[u8])` harnesses that run untrusted bytes through the real
//! parsers and verification chain and drop the result, so fuzzing never needs a public "parse
//! without verifying" API that returns typed values. Hidden from the docs; not part of the API.
//!
//! The payload harnesses (`root`, `keys`, `feed`, `manifest`) take the bytes as a payload, wrap them
//! in an envelope signed by a built-in fake key and run the real verification function, so the
//! payload parser and every check behind it are reached. The hasher and signature scheme used here
//! are private to this module, identical in algorithm to the testkit fakes (the testkit's replay
//! test pins that with a known answer) so seeds written with the testkit fakes reach the deep
//! checks. They are fuzz scaffolding, not an accept-everything mode, and nothing outside this
//! module can name them.
//!
//! Every harness must return for any input without panicking, over-allocating or looping. The
//! `bool` of [`accepts`] says whether the input got all the way through; it exists for the seed
//! tests and is ignored by the fuzz targets.

use std::collections::BTreeMap;
use std::io;

use crate::digest::{Sha256Digest, U53};
use crate::encoding::{base64_decode, hex_decode_array};
use crate::envelope::{EnvelopeSignature, OpenedEnvelope, PayloadKind, pae, write_envelope};
use crate::error::{CodecError, Error};
use crate::feed::{ArtifactRef, FeedDocument, ReleaseDoc, verify_feed};
use crate::fetch::{ResponseInfo, check_document, classify};
use crate::frame::{FrameDesc, decode_verified, decoder_memory};
use crate::ident::{AppId, Channel};
use crate::json::{check_strict, parse_strict};
use crate::keyset::{KeySetDocument, ReleaseKeyEntry, VerifiedKeySet, verify_key_set};
use crate::limits::Limits;
use crate::manifest::{ManifestDocument, verify_manifest};
use crate::path::{EntryKind, RelPath, fold_key, validate_path, validate_tree};
use crate::root::{RootDocument, TrustedRoot, advance_root};
use crate::target::Target;
use crate::traits::{
    Clock, Codec, CodecId, DecodeReport, FrameView, HashState, Hasher, SignatureAlg, Verifier,
};
use crate::transport::{ByteRange, Head};
use crate::trust::{ClockReading, PublicKey, RollbackFloor, parse_payload};
use crate::version::Version;

/// The app id of the fuzz fixtures.
pub const FUZZ_APP_ID: &str = "org.example.hello";
/// The channel of the fuzz fixtures.
pub const FUZZ_CHANNEL: &str = "stable";
/// The fuzz clock's reading (2027-01-15T08:00:00Z).
pub const FUZZ_NOW: u64 = 1_800_000_000;
/// The version the manifest harness's feed lists.
pub const FUZZ_VERSION: &str = "1.0.0";
/// The target the manifest harness's feed lists.
pub const FUZZ_TARGET: Target = Target::LinuxX86_64;
/// Fake key seed of the root key.
pub const ROOT_SEED: u8 = 0;
/// Fake key seed of the release key.
pub const RELEASE_SEED: u8 = 5;
/// Bytes before the descriptor JSON in a `frame` input: JSON length (u16 BE), file size (u64 BE),
/// pack size (u64 BE), file SHA-256 (32 bytes).
pub const FRAME_HEADER_LEN: usize = 2 + 8 + 8 + 32;
/// Bytes before the header lines in an `http` input: flags (bit 0 a range was requested, bit 1 the
/// range has a last byte), request first byte (u64 BE), request last byte (u64 BE), signed pack
/// size (u64 BE), expected body length (u64 BE), status (u16 BE).
pub const HTTP_HEADER_LEN: usize = 1 + 8 + 8 + 8 + 8 + 2;

const DAY: u64 = 86_400;
const ALL_SEEDS: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const KINDS: [PayloadKind; 4] = [
    PayloadKind::Root,
    PayloadKind::Keys,
    PayloadKind::Feed,
    PayloadKind::Manifest,
];

/// A harness entry point.
pub type Harness = fn(&[u8]);

/// Every harness by name.
pub const HARNESSES: &[(&str, Harness)] = &[
    ("envelope", envelope),
    ("root", root),
    ("keys", keys),
    ("feed", feed),
    ("manifest", manifest),
    ("path", path),
    ("tree", tree),
    ("rules", rules),
    ("json", json),
    ("frame", frame),
    ("http", http),
];

/// Runs the harness `name` and reports whether `data` got all the way through it (`None`: no such
/// harness). For the seed tests; fuzz targets call the harness functions.
pub fn accepts(name: &str, data: &[u8]) -> Option<bool> {
    Some(match name {
        "envelope" => envelope_run(data),
        "root" => root_run(data),
        "keys" => keys_run(data),
        "feed" => feed_run(data),
        "manifest" => manifest_run(data),
        "path" => path_run(data),
        "tree" => tree_run(data),
        "rules" => rules_run(data),
        "json" => json_run(data),
        "frame" => frame_run(data),
        "http" => http_run(data),
        _ => return None,
    })
}

/// Parses `data` as the document `kind` (`envelope`, `root`, `keys`, `feed` or `manifest`) with
/// the reader's own syntax and schema checks (strict JSON, `format`, `kind`, `critical`, the typed
/// fields; for `envelope` the key-independent checks of any of the four kinds), without keys or
/// signatures. Used by the test that keeps the examples in `docs/FORMAT.md` parsing.
pub fn parse_example(kind: &str, data: &[u8]) -> Result<(), String> {
    let result = match kind {
        "envelope" => {
            let opened = KINDS
                .iter()
                .map(|&k| OpenedEnvelope::open(data, k, &Limits::V1))
                .collect::<Vec<_>>();
            if opened.iter().any(Result::is_ok) {
                return Ok(());
            }
            opened
                .into_iter()
                .next()
                .map(|r| r.map(|_| ()))
                .unwrap_or(Ok(()))
        }
        "root" => parse_payload::<RootDocument>(data, PayloadKind::Root).map(|_| ()),
        "keys" => parse_payload::<KeySetDocument>(data, PayloadKind::Keys).map(|_| ()),
        "feed" => parse_payload::<FeedDocument>(data, PayloadKind::Feed).map(|_| ()),
        "manifest" => parse_payload::<ManifestDocument>(data, PayloadKind::Manifest).map(|_| ()),
        _ => return Err(format!("unknown example kind {kind:?}")),
    };
    result.map_err(|e| e.to_string())
}

/// `data` as an envelope of each kind: the key-independent checks, then the signatures.
pub fn envelope(data: &[u8]) {
    let _ = envelope_run(data);
}

/// `data` as the payload of `root-2.json`, signed by the fake keys, advanced from root 1.
pub fn root(data: &[u8]) {
    let _ = root_run(data);
}

/// `data` as the payload of `keys.json` under root 1.
pub fn keys(data: &[u8]) {
    let _ = keys_run(data);
}

/// `data` as the payload of `feed-stable.json` under a fixed key set.
pub fn feed(data: &[u8]) {
    let _ = feed_run(data);
}

/// `data` as the payload of a manifest reached from a fixed feed entry.
pub fn manifest(data: &[u8]) {
    let _ = manifest_run(data);
}

/// `data` as one entry path.
pub fn path(data: &[u8]) {
    let _ = path_run(data);
}

/// `data` as lines of entries (`f <path>`, `d <path>`, `l <path>><link target>`).
pub fn tree(data: &[u8]) {
    let _ = tree_run(data);
}

/// `data` as text through the version, target, id, encoding and reference rules.
pub fn rules(data: &[u8]) {
    let _ = rules_run(data);
}

/// `data` through the strict JSON pre-pass.
pub fn json(data: &[u8]) {
    let _ = json_run(data);
}

/// `data` as a frame input: [`FRAME_HEADER_LEN`] header bytes, the descriptor JSON, the frame bytes.
pub fn frame(data: &[u8]) {
    let _ = frame_run(data);
}

/// `data` as a response to a pack request: [`HTTP_HEADER_LEN`] parameter bytes, then header lines
/// (`name: value`, one per line, name lowercased) through the response header
/// rules, the `Content-Range` and `Content-Length` checks and the document check.
pub fn http(data: &[u8]) {
    let _ = http_run(data);
}

// ---- scaffolding: fake hasher, fake signatures, clock, codec -------------------------------------

const HASH_SEEDS: [u64; 4] = [
    0xcbf2_9ce4_8422_2325,
    0x9e37_79b9_7f4a_7c15,
    0xd6e8_feb8_6659_fd93,
    0xa076_1d64_78bd_642f,
];
const HASH_PRIME: u64 = 0x0000_0100_0000_01b3;

struct FuzzHashState {
    lanes: [u64; 4],
    len: u64,
}

impl HashState for FuzzHashState {
    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            for (i, lane) in self.lanes.iter_mut().enumerate() {
                *lane = (*lane ^ u64::from(byte.wrapping_add(i as u8))).wrapping_mul(HASH_PRIME);
            }
        }
        self.len = self.len.wrapping_add(data.len() as u64);
    }

    fn finalize(self: Box<Self>) -> Sha256Digest {
        let mut out = [0u8; 32];
        for (i, lane) in self.lanes.iter().enumerate() {
            let mixed = (lane ^ self.len)
                .wrapping_mul(HASH_PRIME)
                .rotate_left(17 + i as u32);
            out[i * 8..i * 8 + 8].copy_from_slice(&mixed.to_be_bytes());
        }
        Sha256Digest::from_bytes(out)
    }
}

/// Not SHA-256; see the module docs.
struct FuzzHasher;

impl Hasher for FuzzHasher {
    fn sha256_start(&self) -> Box<dyn HashState> {
        Box::new(FuzzHashState {
            lanes: HASH_SEEDS,
            len: 0,
        })
    }
}

fn keyed(public_key: &[u8; 32], half: u8, message: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(33 + message.len());
    input.extend_from_slice(public_key);
    input.push(half);
    input.extend_from_slice(message);
    *FuzzHasher.sha256(&input).as_bytes()
}

fn fake_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&keyed(public_key, 0, message));
    sig[32..].copy_from_slice(&keyed(public_key, 1, message));
    sig
}

/// The fake public key of `seed`.
fn public_key(seed: u8) -> [u8; 32] {
    let mut input = b"lunepack-testkit fake key".to_vec();
    input.push(seed);
    *FuzzHasher.sha256(&input).as_bytes()
}

/// A keyed fake hash; all-zero and all-0xff keys are invalid, like the testkit's.
struct FuzzVerifier;

impl Verifier for FuzzVerifier {
    fn verify(
        &self,
        alg: SignatureAlg,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        self.check_public_key(alg, public_key)?;
        if fake_signature(public_key, message) == *signature {
            Ok(())
        } else {
            Err(crate::error::SignatureError::Mismatch.into())
        }
    }

    fn check_public_key(&self, _alg: SignatureAlg, public_key: &[u8; 32]) -> Result<(), Error> {
        if *public_key == [0x00; 32] || *public_key == [0xff; 32] {
            Err(crate::error::SignatureError::InvalidPublicKey.into())
        } else {
            Ok(())
        }
    }
}

struct FuzzClock;

impl Clock for FuzzClock {
    fn now_unix_secs(&self) -> u64 {
        FUZZ_NOW
    }
}

/// Writes every stream's bytes unchanged and reports them consumed: the identity codec.
struct FuzzCodec;

impl Codec for FuzzCodec {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn io::Write,
    ) -> Result<DecodeReport, Error> {
        let mut consumed = Vec::with_capacity(frame.streams.len());
        for stream in frame.streams {
            out.write_all(stream.input).map_err(CodecError::Write)?;
            consumed.push(stream.input.len() as u64);
        }
        Ok(DecodeReport { consumed })
    }
}

// ---- fixtures --------------------------------------------------------------------------------------

fn u53(value: u64) -> Option<U53> {
    U53::new(value).ok()
}

fn app_id() -> Option<AppId> {
    AppId::parse(FUZZ_APP_ID).ok()
}

fn channel() -> Option<Channel> {
    Channel::parse(FUZZ_CHANNEL).ok()
}

fn clock() -> ClockReading {
    ClockReading::read(&FuzzClock, None)
}

/// An envelope of `kind` around `payload`, signed by the fake keys of `seeds`.
fn sign_envelope(kind: PayloadKind, payload: &[u8], seeds: &[u8]) -> Vec<u8> {
    let payload_type = kind.payload_type();
    let message = pae(payload_type, payload);
    let signatures: Vec<EnvelopeSignature> = seeds
        .iter()
        .map(|&seed| {
            let key = public_key(seed);
            EnvelopeSignature {
                keyid: FuzzHasher.sha256(&key),
                sig: fake_signature(&key, &message),
            }
        })
        .collect();
    write_envelope(payload_type, payload, &signatures)
}

/// Root version 1, one key (seed [`ROOT_SEED`]), threshold 1.
fn trusted_root() -> Option<TrustedRoot> {
    TrustedRoot::from_parts(
        app_id()?,
        1,
        1,
        &[public_key(ROOT_SEED)],
        &FuzzHasher,
        &FuzzVerifier,
    )
    .ok()
}

/// The key-set document the feed and manifest harnesses verify under: key set 1 of root 1, one
/// release key (seed [`RELEASE_SEED`]), threshold 1, valid for 1000 days around [`FUZZ_NOW`].
fn key_set_document() -> Option<KeySetDocument> {
    let key = public_key(RELEASE_SEED);
    Some(KeySetDocument {
        format: u53(1)?,
        kind: "keys".to_owned(),
        critical: Vec::new(),
        app_id: app_id()?,
        root_version: u53(1)?,
        version: u53(1)?,
        expires: None,
        threshold: u53(1)?,
        keys: vec![ReleaseKeyEntry {
            id: FuzzHasher.sha256(&key),
            alg: "ed25519".to_owned(),
            public: PublicKey::from_bytes(key),
            not_before: u53(FUZZ_NOW - DAY)?,
            not_after: u53(FUZZ_NOW + 1000 * DAY)?,
        }],
    })
}

fn verified_key_set() -> Option<VerifiedKeySet> {
    let root = trusted_root()?;
    let bytes = sign_envelope(
        PayloadKind::Keys,
        &key_set_document()?.to_payload(),
        &[ROOT_SEED],
    );
    verify_key_set(
        &root,
        &bytes,
        &RollbackFloor::default(),
        &clock(),
        &FuzzHasher,
        &FuzzVerifier,
    )
    .ok()
}

// ---- harness bodies --------------------------------------------------------------------------------

fn envelope_run(data: &[u8]) -> bool {
    let root = trusted_root();
    let mut opened = false;
    for kind in KINDS {
        if let Ok(env) = OpenedEnvelope::open(data, kind, &Limits::V1) {
            opened = true;
            if let Some(root) = &root {
                let _ = env.authenticate(root.keys(), root.threshold(), &FuzzVerifier);
            }
        }
    }
    opened
}

fn root_run(data: &[u8]) -> bool {
    let Some(trusted) = trusted_root() else {
        return false;
    };
    let bytes = sign_envelope(PayloadKind::Root, data, &ALL_SEEDS);
    advance_root(&trusted, &bytes, &FuzzHasher, &FuzzVerifier).is_ok()
}

fn keys_run(data: &[u8]) -> bool {
    let Some(root) = trusted_root() else {
        return false;
    };
    let bytes = sign_envelope(PayloadKind::Keys, data, &[ROOT_SEED]);
    verify_key_set(
        &root,
        &bytes,
        &RollbackFloor::default(),
        &clock(),
        &FuzzHasher,
        &FuzzVerifier,
    )
    .is_ok()
}

fn feed_run(data: &[u8]) -> bool {
    let (Some(keys), Some(app), Some(channel)) = (verified_key_set(), app_id(), channel()) else {
        return false;
    };
    let bytes = sign_envelope(PayloadKind::Feed, data, &[RELEASE_SEED]);
    verify_feed(
        &keys,
        &bytes,
        &app,
        &channel,
        &RollbackFloor::default(),
        &clock(),
        &FuzzVerifier,
    )
    .is_ok()
}

fn manifest_run(data: &[u8]) -> bool {
    let (Some(keys), Some(app), Some(channel)) = (verified_key_set(), app_id(), channel()) else {
        return false;
    };
    let manifest_bytes = sign_envelope(PayloadKind::Manifest, data, &[RELEASE_SEED]);
    let (Some(format), Some(seq), Some(issued), Some(size)) = (
        u53(1),
        u53(1),
        u53(FUZZ_NOW),
        u53(manifest_bytes.len() as u64),
    ) else {
        return false;
    };
    let reference = ArtifactRef {
        path: format!("{FUZZ_VERSION}/{}.manifest.json", FUZZ_TARGET.as_str()),
        size,
        sha256: FuzzHasher.sha256(&manifest_bytes),
    };
    let feed_doc = FeedDocument {
        format,
        kind: "feed".to_owned(),
        critical: Vec::new(),
        app_id: app.clone(),
        channel: channel.clone(),
        seq,
        issued,
        expires: None,
        releases: vec![ReleaseDoc {
            version: FUZZ_VERSION.to_owned(),
            targets: BTreeMap::from([(FUZZ_TARGET.as_str().to_owned(), reference)]),
            rollout: None,
        }],
    };
    let feed_bytes = sign_envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[RELEASE_SEED]);
    let Ok(feed) = verify_feed(
        &keys,
        &feed_bytes,
        &app,
        &channel,
        &RollbackFloor::default(),
        &clock(),
        &FuzzVerifier,
    ) else {
        return false;
    };
    let Some(entry) = feed.target_entry(0, FUZZ_TARGET) else {
        return false;
    };
    verify_manifest(&keys, &entry, &manifest_bytes, &FuzzHasher, &FuzzVerifier).is_ok()
}

fn path_run(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let _ = fold_key(text);
    let checked = validate_path(text);
    let parsed = RelPath::parse(text);
    assert_eq!(
        checked.is_ok(),
        parsed.is_ok(),
        "validate_path vs RelPath::parse"
    );
    match checked {
        Ok(path) => {
            assert_eq!(
                path.as_str(),
                text,
                "an accepted path is kept byte for byte"
            );
            let rejoined: Vec<&str> = path.components().collect();
            assert_eq!(rejoined.join("/"), text, "components rejoin to the path");
            true
        }
        Err(_) => false,
    }
}

fn tree_run(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let mut entries: Vec<(RelPath, EntryKind<'_>)> = Vec::new();
    for line in text.lines() {
        let Some((tag, rest)) = line.split_once(' ') else {
            continue;
        };
        let (path_text, kind) = match tag {
            "f" => (rest, EntryKind::File),
            "d" => (rest, EntryKind::Dir),
            "l" => match rest.split_once('>') {
                Some((path_text, link)) => (path_text, EntryKind::Symlink { target: link }),
                None => continue,
            },
            _ => continue,
        };
        if let Ok(path) = validate_path(path_text) {
            entries.push((path, kind));
        }
    }
    let mut accepted = false;
    for target in Target::ALL {
        let result = validate_tree(entries.iter().map(|(p, k)| (p, *k)), target);
        if target == FUZZ_TARGET {
            accepted = result.is_ok();
        }
    }
    accepted
}

fn rules_run(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let Some(zero) = u53(0) else {
        return false;
    };
    let mut any = false;
    any |= Version::parse(text).is_ok();
    any |= Target::parse(text).is_ok();
    any |= AppId::parse(text).is_ok();
    any |= Channel::parse(text).is_ok();
    any |= SignatureAlg::from_id(text).is_some();
    any |= CodecId::from_id(text).is_some();
    any |= hex_decode_array::<32>(text).is_ok();
    any |= base64_decode(text, 1024).is_ok();
    any |= ArtifactRef {
        path: text.to_owned(),
        size: zero,
        sha256: Sha256Digest::from_bytes([0; 32]),
    }
    .check()
    .is_ok();
    // The order on versions is a total order: antisymmetric on any two lines.
    if let Some((a, b)) = text.split_once('\n')
        && let (Ok(a), Ok(b)) = (Version::parse(a), Version::parse(b))
    {
        assert_eq!(
            a.cmp(&b),
            b.cmp(&a).reverse(),
            "version order is antisymmetric"
        );
        any = true;
    }
    any
}

fn json_run(data: &[u8]) -> bool {
    let strict = check_strict(data).is_ok();
    let typed = parse_strict::<serde_json::Value>(data).is_ok();
    assert_eq!(strict, typed, "check_strict and parse_strict agree");
    if strict {
        assert!(
            serde_json::from_slice::<serde_json::Value>(data).is_ok(),
            "strict JSON is plain JSON"
        );
    }
    strict
}

fn frame_run(data: &[u8]) -> bool {
    if data.len() < FRAME_HEADER_LEN {
        return false;
    }
    let (header, rest) = data.split_at(FRAME_HEADER_LEN);
    let json_len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    let file_size = be_u64(&header[2..10]);
    let pack_size = be_u64(&header[10..18]);
    let mut file_hash = [0u8; 32];
    file_hash.copy_from_slice(&header[18..50]);
    let file_sha256 = Sha256Digest::from_bytes(file_hash);
    if rest.len() < json_len {
        return false;
    }
    let (json_bytes, frame_bytes) = rest.split_at(json_len);
    let Ok(desc) = parse_strict::<FrameDesc>(json_bytes) else {
        return false;
    };
    let Ok(checked) = desc.check(file_size, file_sha256, pack_size) else {
        return false;
    };
    let _ = decoder_memory(&checked);
    decode_verified(
        &checked,
        frame_bytes,
        &FuzzHasher,
        &FuzzCodec,
        &mut io::sink(),
    )
    .is_ok()
}

fn http_run(data: &[u8]) -> bool {
    let Some((params, lines)) = data.split_first_chunk::<HTTP_HEADER_LEN>() else {
        return false;
    };
    let flags = params[0];
    let first = be_u64(&params[1..9]);
    let last = be_u64(&params[9..17]);
    let signed_total = be_u64(&params[17..25]);
    let expected_len = be_u64(&params[25..33]);
    let status = u16::from_be_bytes([params[33], params[34]]);
    let range = (flags & 1 != 0).then_some(ByteRange {
        first,
        last: (flags & 2 != 0).then_some(last),
    });
    let headers = lines
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = match line.iter().position(|&b| b == b':') {
                Some(at) => (&line[..at], &line[at + 1..]),
                None => (line, &line[line.len()..]),
            };
            let value = value.strip_prefix(b" ").unwrap_or(value);
            (
                String::from_utf8_lossy(name).to_ascii_lowercase(),
                value.to_vec(),
            )
        })
        .collect();
    let head = Head { status, headers };
    let Ok(info) = ResponseInfo::from_head(&head) else {
        return false;
    };
    let _ = check_document(&info, expected_len);
    classify(range, &info, signed_total, expected_len).is_ok()
}

fn be_u64(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    u64::from_be_bytes(out)
}

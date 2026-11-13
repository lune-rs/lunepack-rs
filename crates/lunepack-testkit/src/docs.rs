//! Document builders over the core's real writer, and the trust-chain suite (envelope, root walk,
//! key set) that runs them with fakes (core tests) and with real crypto (`lunepack-crypto` tests).
//!
//! Every document is produced the way production produces it: the core's payload types
//! serialised by the core, signatures made by the caller's signing closure over the core's
//! `pae`, the envelope written by the core's `write_envelope`. Negative cases change one thing
//! in that output.

use std::panic::{AssertUnwindSafe, catch_unwind};

use lunepack_core::digest::{Sha256Digest, U53};
use lunepack_core::encoding::base64_encode;
use lunepack_core::error::{Base64Error, JsonError, SignatureError};
use lunepack_core::path::RelPath;
use lunepack_core::{
    AppId, Clock, ClockReading, EnvelopeSignature, Error, Hasher, KeyEntry, KeySetDocument,
    PayloadKind, PublicKey, ReleaseKeyEntry, RollbackFloor, RootDocument, TrustedRoot,
    VerifiedKeySet, Verifier, advance_root, pae, verify_key_set, write_envelope,
};
use lunepack_core::{
    ArtifactRef, Channel, CodecId, EntryDoc, FeedDocument, FrameDesc, ManifestDocument, ReleaseDoc,
    RolloutDoc, StreamDesc, Target,
};

use crate::clock::{FakeClock, YEAR_2100_UNIX_SECS};
use crate::codec::FakeCodec;
use crate::hasher::FakeHasher;
use crate::suites::SignFixture;
use crate::verifier::{FAKE_INVALID_KEYS, FakeKeyPair, FakeVerifier};

/// The app id the suite's documents use.
pub const SUITE_APP_ID: &str = "org.example.hello";
/// The channel the suite's feeds use.
pub const SUITE_CHANNEL: &str = "stable";
/// The suite's base time: 2027-01-15T08:00:00Z.
pub const SUITE_T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

/// Signs with [`FakeKeyPair::from_seed`]: `(seed, message) -> (public_key, signature)`.
pub fn fake_sign(seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
    let pair = FakeKeyPair::from_seed(seed);
    (pair.public_key(), pair.sign(message))
}

/// What the builders need: the hasher and verifier under test, a signing closure that gives a
/// distinct key per seed for seeds `0..=7`, and one public key the verifier must reject.
pub struct ChainFixture<'a> {
    /// Hasher for key ids.
    pub hasher: &'a dyn Hasher,
    /// Verifier for signatures and keys.
    pub verifier: &'a dyn Verifier,
    /// `(seed, message) -> (public_key, signature)`.
    pub sign: &'a SignFixture<'a>,
    /// A key `verifier.check_public_key` rejects (for Ed25519: small-order or non-canonical).
    pub invalid_key: [u8; 32],
}

impl ChainFixture<'static> {
    /// The fixture over the testkit fakes.
    pub fn fake() -> Self {
        ChainFixture {
            hasher: &FakeHasher,
            verifier: &FakeVerifier,
            sign: &fake_sign,
            invalid_key: FAKE_INVALID_KEYS[0],
        }
    }
}

impl ChainFixture<'_> {
    /// The public key of `seed`.
    pub fn public_key(&self, seed: u8) -> [u8; 32] {
        (self.sign)(seed, b"").0
    }

    /// The key id of `seed`: the fixture hasher's SHA-256 of its public key.
    pub fn key_id(&self, seed: u8) -> Sha256Digest {
        self.hasher.sha256(&self.public_key(seed))
    }

    /// A root key-list entry for `seed`.
    pub fn key_entry(&self, seed: u8) -> KeyEntry {
        KeyEntry {
            id: self.key_id(seed),
            alg: "ed25519".to_owned(),
            public: PublicKey::from_bytes(self.public_key(seed)),
        }
    }

    /// A release key for `seed`, valid in `not_before .. not_after`.
    pub fn release_key(&self, seed: u8, not_before: u64, not_after: u64) -> ReleaseKeyEntry {
        ReleaseKeyEntry {
            id: self.key_id(seed),
            alg: "ed25519".to_owned(),
            public: PublicKey::from_bytes(self.public_key(seed)),
            not_before: u53(not_before),
            not_after: u53(not_after),
        }
    }

    /// `seed`'s signature over `message` exactly (no PAE added), with its key id.
    pub fn raw_signature(&self, seed: u8, message: &[u8]) -> EnvelopeSignature {
        let (pk, sig) = (self.sign)(seed, message);
        EnvelopeSignature {
            keyid: self.hasher.sha256(&pk),
            sig,
        }
    }

    /// `seed`'s signature over `pae(payload_type, payload)`.
    pub fn signature(&self, seed: u8, payload_type: &str, payload: &[u8]) -> EnvelopeSignature {
        self.raw_signature(seed, &pae(payload_type, payload))
    }

    /// An envelope of `kind` around `payload`, signed by each of `seeds` in order.
    pub fn envelope(&self, kind: PayloadKind, payload: &[u8], seeds: &[u8]) -> Vec<u8> {
        let ty = kind.payload_type();
        let sigs: Vec<_> = seeds
            .iter()
            .map(|&s| self.signature(s, ty, payload))
            .collect();
        write_envelope(ty, payload, &sigs)
    }

    /// A root document with the keys of `seeds`.
    pub fn root_document(&self, version: u64, threshold: u64, seeds: &[u8]) -> RootDocument {
        RootDocument {
            format: u53(1),
            kind: "root".to_owned(),
            critical: Vec::new(),
            app_id: app_id(),
            version: u53(version),
            threshold: u53(threshold),
            keys: seeds.iter().map(|&s| self.key_entry(s)).collect(),
        }
    }

    /// A key-set document whose release keys (`seeds`) are valid from `SUITE_T0 - 1 day` for
    /// 1000 days.
    pub fn keyset_document(
        &self,
        root_version: u64,
        version: u64,
        expires: Option<u64>,
        threshold: u64,
        seeds: &[u8],
    ) -> KeySetDocument {
        KeySetDocument {
            format: u53(1),
            kind: "keys".to_owned(),
            critical: Vec::new(),
            app_id: app_id(),
            root_version: u53(root_version),
            version: u53(version),
            expires: expires.map(u53),
            threshold: u53(threshold),
            keys: seeds
                .iter()
                .map(|&s| self.release_key(s, SUITE_T0 - DAY, SUITE_T0 + 1000 * DAY))
                .collect(),
        }
    }

    /// A compiled-in trusted root with the keys of `seeds`.
    pub fn trusted_root(&self, version: u64, threshold: u64, seeds: &[u8]) -> TrustedRoot {
        let keys: Vec<[u8; 32]> = seeds.iter().map(|&s| self.public_key(s)).collect();
        TrustedRoot::from_parts(
            app_id(),
            version,
            threshold,
            &keys,
            self.hasher,
            self.verifier,
        )
        .expect("valid compiled-in root")
    }

    /// A root (version 1, key of seed 0) and a key set (version 1, no expiry) whose release keys
    /// are `release_seeds` with `threshold`, verified at [`SUITE_T0`].
    pub fn verified_chain(
        &self,
        release_seeds: &[u8],
        threshold: u64,
    ) -> (TrustedRoot, VerifiedKeySet) {
        let root = self.trusted_root(1, 1, &[0]);
        let ks = self.keyset_document(1, 1, None, threshold, release_seeds);
        let bytes = self.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        let keys = verify_key_set(
            &root,
            &bytes,
            &RollbackFloor::default(),
            &ClockReading::read(&FakeClock::new(SUITE_T0), None),
            self.hasher,
            self.verifier,
        )
        .expect("valid key set");
        (root, keys)
    }

    /// An artifact reference to `bytes` at `path`.
    pub fn artifact_ref(&self, path: &str, bytes: &[u8]) -> ArtifactRef {
        ArtifactRef {
            path: path.to_owned(),
            size: u53(bytes.len() as u64),
            sha256: self.hasher.sha256(bytes),
        }
    }

    /// A feed for [`SUITE_APP_ID`] on channel `stable`, issued at [`SUITE_T0`].
    pub fn feed_document(
        &self,
        seq: u64,
        expires: Option<u64>,
        releases: Vec<ReleaseDoc>,
    ) -> FeedDocument {
        FeedDocument {
            format: u53(1),
            kind: "feed".to_owned(),
            critical: Vec::new(),
            app_id: app_id(),
            channel: Channel::parse(SUITE_CHANNEL).expect("valid channel"),
            seq: u53(seq),
            issued: u53(SUITE_T0),
            expires: expires.map(u53),
            releases,
        }
    }

    /// A release of `version` listing each `(target, manifest bytes)` at the writer's names.
    pub fn release(
        &self,
        version: &str,
        manifests: &[(Target, &[u8])],
        rollout: Option<(u64, [u8; 32])>,
    ) -> ReleaseDoc {
        ReleaseDoc {
            version: version.to_owned(),
            targets: manifests
                .iter()
                .map(|(t, bytes)| {
                    let path = format!("{version}/{}.manifest.json", t.as_str());
                    (t.as_str().to_owned(), self.artifact_ref(&path, bytes))
                })
                .collect(),
            rollout: rollout.map(|(bp, seed)| RolloutDoc {
                basis_points: u53(bp),
                seed: Sha256Digest::from_bytes(seed),
            }),
        }
    }

    /// A manifest for [`SUITE_APP_ID`] issued at [`SUITE_T0`] over `pack`'s entries.
    pub fn manifest_document(
        &self,
        version: &str,
        target: Target,
        pack: &PackBuilder,
    ) -> ManifestDocument {
        ManifestDocument {
            format: u53(1),
            kind: "manifest".to_owned(),
            critical: Vec::new(),
            app_id: app_id(),
            version: version.to_owned(),
            target: target.as_str().to_owned(),
            issued: u53(SUITE_T0),
            pack: self.artifact_ref(&format!("{version}/{}.pack", target.as_str()), &pack.bytes),
            entries: pack.entries.clone(),
        }
    }

    fn advance(&self, trusted: &TrustedRoot, bytes: &[u8]) -> Result<TrustedRoot, Error> {
        advance_root(trusted, bytes, self.hasher, self.verifier)
    }

    fn keys(
        &self,
        root: &TrustedRoot,
        bytes: &[u8],
        floor: RollbackFloor,
        clock: ClockReading,
    ) -> Result<VerifiedKeySet, Error> {
        verify_key_set(root, bytes, &floor, &clock, self.hasher, self.verifier)
    }
}

/// Builds a pack and its manifest entries the way the packager does: each file encoded by
/// [`FakeCodec::encode`] and appended as one frame.
#[derive(Debug, Clone, Default)]
pub struct PackBuilder {
    /// The pack's bytes.
    pub bytes: Vec<u8>,
    /// The manifest entries, in the order added.
    pub entries: Vec<EntryDoc>,
}

impl PackBuilder {
    /// An empty pack.
    pub fn new() -> Self {
        PackBuilder::default()
    }

    /// Adds a file; a non-empty one gets a frame of `codec` (dictionary 64 KiB).
    pub fn file(
        &mut self,
        hasher: &dyn Hasher,
        path: &str,
        data: &[u8],
        codec: CodecId,
    ) -> &mut Self {
        let frame = (!data.is_empty()).then(|| {
            let enc = FakeCodec::encode(codec, data);
            let lzma = !matches!(codec, CodecId::Stored | CodecId::Bcj2);
            let desc = FrameDesc {
                codec: codec.id().to_owned(),
                offset: u53(self.bytes.len() as u64),
                length: u53(enc.frame.len() as u64),
                sha256: hasher.sha256(&enc.frame),
                dict_size: lzma.then(|| u53(65_536)),
                streams: (codec == CodecId::Bcj2).then(|| {
                    enc.streams
                        .iter()
                        .enumerate()
                        .map(|(i, st)| StreamDesc {
                            length: u53(st.length as u64),
                            decoded_size: u53(st.decoded_size),
                            dict_size: (i < 3).then(|| u53(65_536)),
                        })
                        .collect()
                }),
            };
            self.bytes.extend_from_slice(&enc.frame);
            desc
        });
        self.entries.push(EntryDoc {
            path: RelPath::parse(path).expect("valid path"),
            kind: "file".to_owned(),
            size: Some(u53(data.len() as u64)),
            sha256: Some(hasher.sha256(data)),
            exec: Some(false),
            frame,
            target: None,
        });
        self
    }

    /// Adds a directory entry.
    pub fn dir(&mut self, path: &str) -> &mut Self {
        self.entries.push(EntryDoc {
            path: RelPath::parse(path).expect("valid path"),
            kind: "dir".to_owned(),
            size: None,
            sha256: None,
            exec: None,
            frame: None,
            target: None,
        });
        self
    }

    /// Adds a symlink entry.
    pub fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
        self.entries.push(EntryDoc {
            path: RelPath::parse(path).expect("valid path"),
            kind: "symlink".to_owned(),
            size: None,
            sha256: None,
            exec: None,
            frame: None,
            target: Some(target.to_owned()),
        });
        self
    }
}

fn u53(v: u64) -> U53 {
    U53::new(v).expect("value in range")
}

fn app_id() -> AppId {
    AppId::parse(SUITE_APP_ID).expect("valid app id")
}

fn at(now: u64, floor_time: Option<u64>) -> ClockReading {
    ClockReading::read(&FakeClock::new(now), floor_time)
}

fn now0() -> ClockReading {
    at(SUITE_T0, None)
}

fn replace(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("writer output is UTF-8");
    assert!(text.contains(from), "{from:?} not in the document");
    text.replacen(from, to, 1).into_bytes()
}

macro_rules! assert_err {
    ($res:expr, $pat:pat) => {
        match $res {
            Err($pat) => {}
            Err(other) => panic!("expected {}, got {other:?}", stringify!($pat)),
            Ok(_) => panic!("expected {}, got Ok", stringify!($pat)),
        }
    };
}

type Case = (&'static str, fn(&ChainFixture<'_>));

/// The trust-chain cases, by name.
pub const TRUST_CHAIN_CASES: &[Case] = &[
    ("pae_known_answers", pae_known_answers),
    ("root_walk_and_key_set_accept", root_walk_and_key_set_accept),
    ("wrong_payload_type", wrong_payload_type),
    ("key_not_in_ring", key_not_in_ring),
    ("one_key_twice_against_threshold_two", one_key_twice),
    ("junk_signature_with_unknown_keyid", junk_signature),
    ("malformed_keyid", malformed_keyid),
    ("signature_over_base64_text", signature_over_base64_text),
    ("key_set_version_below_floor", key_set_below_floor),
    ("root_skip", root_skip),
    (
        "new_root_without_its_own_signatures",
        new_root_unsigned_by_itself,
    ),
    ("duplicate_key_in_root", duplicate_key_in_root),
    ("tampered_payload_byte", tampered_payload_byte),
    ("unknown_critical_feature", unknown_critical),
    ("clock_400_days_and_2100", clock_cases),
    ("check_order", check_order),
    ("envelope_structure", envelope_structure),
    ("key_list_rules", key_list_rules),
    ("bindings", bindings),
    ("compiled_in_root_rules", compiled_in_root_rules),
];

/// Runs every case of [`TRUST_CHAIN_CASES`] and panics naming each one that failed.
pub fn run_trust_chain_suite(fx: &ChainFixture<'_>) {
    let mut failed = Vec::new();
    for (name, case) in TRUST_CHAIN_CASES {
        if catch_unwind(AssertUnwindSafe(|| case(fx))).is_err() {
            failed.push(*name);
        }
    }
    assert!(failed.is_empty(), "trust-chain cases failed: {failed:?}");
}

fn pae_known_answers(_: &ChainFixture<'_>) {
    assert_eq!(pae("t", b"x"), b"DSSEv1 1 t 1 x");
    assert_eq!(pae("t", b""), b"DSSEv1 1 t 0 ");
    assert_eq!(
        pae("application/vnd.lunepack.keys.v1+json", b"{}"),
        b"DSSEv1 37 application/vnd.lunepack.keys.v1+json 2 {}"
    );
}

fn root_walk_and_key_set_accept(fx: &ChainFixture<'_>) {
    let r1 = fx.trusted_root(1, 1, &[0, 1]);
    let doc2 = fx.root_document(2, 2, &[2, 3]).to_payload();
    let r2 = fx
        .advance(&r1, &fx.envelope(PayloadKind::Root, &doc2, &[1, 2, 3]))
        .expect("root 2");
    assert_eq!((r2.version(), r2.threshold(), r2.keys().len()), (2, 2, 2));
    let doc3 = fx.root_document(3, 1, &[4]).to_payload();
    let r3 = fx
        .advance(&r2, &fx.envelope(PayloadKind::Root, &doc3, &[3, 2, 4]))
        .expect("root 3");
    assert_eq!(r3.version(), 3);
    assert_eq!(r3.keys().keys()[0].id(), fx.key_id(4));

    let ks = fx.keyset_document(3, 7, Some(SUITE_T0 + 30 * DAY), 1, &[5, 6]);
    let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[4]);
    let verified = fx
        .keys(&r3, &bytes, RollbackFloor::new(2, 6), now0())
        .expect("key set");
    assert_eq!(verified.version(), 7);
    assert_eq!(verified.root_version(), 3);
    assert_eq!(verified.threshold(), 1);
    assert_eq!(verified.keys().len(), 2);
    assert_eq!(verified.keys().keys()[1].id(), fx.key_id(6));
    assert!(verified.windows()[0].contains(SUITE_T0));
    assert!(verified.expiry_checked());
    let raised = RollbackFloor::new(2, 6).raised_by(&verified);
    assert_eq!(raised, RollbackFloor::new(3, 7));
    // Raising never lowers.
    assert_eq!(
        RollbackFloor::new(9, 9).raised_by(&verified),
        RollbackFloor::new(9, 9)
    );
}

fn wrong_payload_type(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    for ty in [
        PayloadKind::Feed.payload_type(),
        PayloadKind::Root.payload_type(),
        "application/vnd.lunepack.KEYS.v1+json",
        "application/vnd.lunepack.keys.v1+json ",
        "application/vnd.lunepack.keys.v2+json",
        "application/vnd.lunepack.keys.v1+json\u{0}",
    ] {
        // Signed correctly for the type it carries: only the type check can reject it.
        let sig = fx.signature(0, ty, &payload);
        let bytes = write_envelope(ty, &payload, &[sig]);
        assert_err!(
            fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
            Error::PayloadType { .. }
        );
    }
}

fn key_not_in_ring(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let bytes = fx.envelope(PayloadKind::Keys, &payload, &[1]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::Threshold { need: 1, got: 0 }
    );
    // A release key cannot sign the key set either.
    let bytes = fx.envelope(PayloadKind::Keys, &payload, &[5]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::Threshold { need: 1, got: 0 }
    );
}

fn one_key_twice(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 2, &[0, 1]);
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let bytes = fx.envelope(PayloadKind::Keys, &payload, &[0, 0]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::Threshold { need: 2, got: 1 }
    );
    let bytes = fx.envelope(PayloadKind::Keys, &payload, &[0, 0, 1]);
    fx.keys(&root, &bytes, RollbackFloor::default(), now0())
        .expect("two distinct keys meet threshold 2");
}

fn junk_signature(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let ty = PayloadKind::Keys.payload_type();
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let junk = EnvelopeSignature {
        keyid: fx.hasher.sha256(b"not a key of this ring"),
        sig: [7; 64],
    };
    let valid = fx.signature(0, ty, &payload);
    // A bad signature under a known key id is skipped too.
    let bad_known = EnvelopeSignature {
        keyid: fx.key_id(0),
        sig: [9; 64],
    };
    for sigs in [
        vec![junk, valid],
        vec![valid, junk],
        vec![bad_known, junk, valid],
    ] {
        let bytes = write_envelope(ty, &payload, &sigs);
        fx.keys(&root, &bytes, RollbackFloor::default(), now0())
            .expect("junk next to a valid signature is skipped");
    }
    let bytes = write_envelope(ty, &payload, &[junk, bad_known]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::Threshold { need: 1, got: 0 }
    );
}

fn malformed_keyid(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let ty = PayloadKind::Keys.payload_type();
    let junk = EnvelopeSignature {
        keyid: fx.hasher.sha256(b"junk"),
        sig: [7; 64],
    };
    // The malformed id sits on a junk signature next to a valid one: still the whole envelope fails.
    let good = write_envelope(ty, &payload, &[fx.signature(0, ty, &payload), junk]);
    let junk_hex = junk.keyid.to_hex();
    for bad in [
        junk_hex.to_uppercase(),
        junk_hex[..63].to_owned(),
        format!("{junk_hex}0"),
        String::new(),
        format!("{}g", &junk_hex[..63]),
    ] {
        let bytes = replace(&good, &junk_hex, &bad);
        assert_err!(
            fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
            Error::KeyIdSyntax(_)
        );
    }
}

fn signature_over_base64_text(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let ty = PayloadKind::Keys.payload_type();
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let b64 = base64_encode(&payload);
    for message in [
        b64.as_bytes().to_vec(),
        payload.clone(),
        pae(ty, b64.as_bytes()),
    ] {
        let bytes = write_envelope(ty, &payload, &[fx.raw_signature(0, &message)]);
        assert_err!(
            fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
            Error::Threshold { need: 1, got: 0 }
        );
    }
}

fn key_set_below_floor(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let bytes = fx.envelope(
        PayloadKind::Keys,
        &fx.keyset_document(1, 7, None, 1, &[5]).to_payload(),
        &[0],
    );
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::new(0, 8), now0()),
        Error::Rollback {
            floor: 8,
            found: 7,
            ..
        }
    );
    fx.keys(&root, &bytes, RollbackFloor::new(0, 7), now0())
        .expect("equal to the floor is allowed");
    // A root below its floor is a rollback too.
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::new(2, 0), now0()),
        Error::Rollback {
            floor: 2,
            found: 1,
            ..
        }
    );
}

fn root_skip(fx: &ChainFixture<'_>) {
    let r1 = fx.trusted_root(1, 1, &[0]);
    for version in [1, 3, 4] {
        let doc = fx.root_document(version, 1, &[2]).to_payload();
        assert_err!(
            fx.advance(&r1, &fx.envelope(PayloadKind::Root, &doc, &[0, 2])),
            Error::RootVersion { expected: 2, .. }
        );
    }
}

fn new_root_unsigned_by_itself(fx: &ChainFixture<'_>) {
    let r1 = fx.trusted_root(1, 1, &[0]);
    let doc = fx.root_document(2, 1, &[2]).to_payload();
    assert_err!(
        fx.advance(&r1, &fx.envelope(PayloadKind::Root, &doc, &[0])),
        Error::Threshold { need: 1, got: 0 }
    );
    // Only the new root signed: the old root's threshold fails first.
    assert_err!(
        fx.advance(&r1, &fx.envelope(PayloadKind::Root, &doc, &[2])),
        Error::Threshold { need: 1, got: 0 }
    );
    // New threshold 2, only one new key signed.
    let doc = fx.root_document(2, 2, &[2, 3]).to_payload();
    assert_err!(
        fx.advance(&r1, &fx.envelope(PayloadKind::Root, &doc, &[0, 2, 2])),
        Error::Threshold { need: 2, got: 1 }
    );
}

fn duplicate_key_in_root(fx: &ChainFixture<'_>) {
    let r1 = fx.trusted_root(1, 1, &[0]);
    let doc = fx.root_document(2, 1, &[2]);
    let mut other_id = fx.key_entry(2);
    other_id.id = fx.key_id(3);
    for extra in [other_id, fx.key_entry(2)] {
        let mut d = doc.clone();
        d.keys.push(extra);
        let bytes = fx.envelope(PayloadKind::Root, &d.to_payload(), &[0, 2]);
        assert_err!(fx.advance(&r1, &bytes), Error::DuplicatePublicKey);
    }
    // The compiled-in root is held to the same rule.
    let k = fx.public_key(0);
    assert_err!(
        TrustedRoot::from_parts(app_id(), 1, 1, &[k, k], fx.hasher, fx.verifier),
        Error::DuplicatePublicKey
    );
    // And a key set.
    let root = fx.trusted_root(1, 1, &[0]);
    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    let mut dup = ks.keys[0].clone();
    dup.id = fx.key_id(6);
    ks.keys.push(dup);
    let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::DuplicatePublicKey
    );
}

fn tampered_payload_byte(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let ty = PayloadKind::Keys.payload_type();
    let payload = fx.keyset_document(1, 7, None, 1, &[5]).to_payload();
    let sig = fx.signature(0, ty, &payload);
    let at = payload
        .windows(b"\"version\":7".len())
        .position(|w| w == b"\"version\":7")
        .expect("version field")
        + b"\"version\":".len();
    for (index, value) in [(at, b'8'), (0, b' '), (payload.len() - 1, b' ')] {
        let mut tampered = payload.clone();
        tampered[index] = value;
        let bytes = write_envelope(ty, &tampered, &[sig]);
        assert_err!(
            fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
            Error::Threshold { need: 1, got: 0 }
        );
    }
    // Same for a root document.
    let r1 = fx.trusted_root(1, 1, &[0]);
    let doc = fx.root_document(2, 1, &[2]).to_payload();
    let rty = PayloadKind::Root.payload_type();
    let sigs = [fx.signature(0, rty, &doc), fx.signature(2, rty, &doc)];
    let mut tampered = doc.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    assert_err!(
        fx.advance(&r1, &write_envelope(rty, &tampered, &sigs)),
        Error::Threshold { .. }
    );
}

fn unknown_critical(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    ks.critical = vec!["delta-v2".to_owned()];
    let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::UnknownCritical(_)
    );
    let r1 = fx.trusted_root(1, 1, &[0]);
    let mut doc = fx.root_document(2, 1, &[2]);
    doc.critical = vec!["x".to_owned()];
    let bytes = fx.envelope(PayloadKind::Root, &doc.to_payload(), &[0, 2]);
    assert_err!(fx.advance(&r1, &bytes), Error::UnknownCritical(_));
    // Malformed critical lists are schema errors.
    for critical in [
        vec![String::new()],
        vec!["Upper".to_owned()],
        vec!["a".repeat(65)],
        vec!["a".to_owned(), "a".to_owned()],
        (0..17).map(|i| format!("f{i}")).collect(),
    ] {
        let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
        ks.critical = critical;
        let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        assert_err!(
            fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
            Error::Schema(_)
        );
    }
}

fn clock_cases(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let expires = SUITE_T0 + 30 * DAY;
    let bytes = fx.envelope(
        PayloadKind::Keys,
        &fx.keyset_document(1, 1, Some(expires), 1, &[5])
            .to_payload(),
        &[0],
    );
    let check = |clock: ClockReading| fx.keys(&root, &bytes, RollbackFloor::default(), clock);

    let ok = check(at(SUITE_T0, None)).expect("fresh");
    assert!(ok.expiry_checked());
    check(at(expires - 1, None)).expect("one second before expiry");
    assert_err!(check(at(expires, None)), Error::Expired { .. });

    // The shifted clock comes from the fake clock the code reads, never the real one.
    let shifted = FakeClock::new(SUITE_T0);
    shifted.advance_400_days();
    let plus_400 = shifted.now_unix_secs();
    assert_err!(check(at(plus_400, None)), Error::Expired { .. });
    assert_err!(check(at(plus_400, Some(SUITE_T0))), Error::Expired { .. });
    let skipped = check(at(plus_400, Some(plus_400 + 1))).expect("implausible clock skips expiry");
    assert!(!skipped.expiry_checked());
    assert!(!skipped.clock().is_plausible());

    shifted.set_year_2100();
    let y2100 = shifted.now_unix_secs();
    assert_eq!(y2100, YEAR_2100_UNIX_SECS);
    assert_err!(check(at(y2100, None)), Error::Expired { .. });
    assert_err!(check(at(y2100, Some(SUITE_T0))), Error::Expired { .. });
    let skipped = check(at(y2100, Some(y2100 + 1))).expect("implausible clock skips expiry");
    assert!(!skipped.expiry_checked());

    // Without `expires` nothing expires, and the check still counts as run.
    let bytes = fx.envelope(
        PayloadKind::Keys,
        &fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
        &[0],
    );
    let never = fx
        .keys(&root, &bytes, RollbackFloor::default(), at(y2100, None))
        .expect("no expiry");
    assert!(never.expiry_checked());
    // Other checks still run on an implausible clock.
    assert_err!(
        fx.keys(
            &root,
            &bytes,
            RollbackFloor::new(0, 2),
            at(y2100, Some(y2100 + 1))
        ),
        Error::Rollback { .. }
    );
}

fn check_order(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let floor = RollbackFloor::default();
    // Wrong type and no valid signature: the type check comes first.
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let bytes = fx.envelope(PayloadKind::Feed, &payload, &[3]);
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::PayloadType { .. }
    );
    // Wrong type and zero signatures: still the type first.
    let bytes = write_envelope(PayloadKind::Feed.payload_type(), &payload, &[]);
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::PayloadType { .. }
    );
    // Nothing in an unauthenticated payload is looked at: garbage, an unknown critical feature
    // or a wrong format all fail on the threshold.
    let mut critical = fx.keyset_document(1, 1, None, 1, &[5]);
    critical.critical = vec!["x".to_owned()];
    for unsigned in [
        b"not json".to_vec(),
        b"{\"a\":1,\"a\":2}".to_vec(),
        critical.to_payload(),
        b"{\"format\":2}".to_vec(),
    ] {
        let bytes = fx.envelope(PayloadKind::Keys, &unsigned, &[3]);
        assert_err!(
            fx.keys(&root, &bytes, floor.clone(), now0()),
            Error::Threshold { .. }
        );
    }
    // Signed garbage reaches the payload parser and fails there.
    let bytes = fx.envelope(PayloadKind::Keys, b"not json", &[0]);
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Json(_)
    );
    let bytes = fx.envelope(
        PayloadKind::Keys,
        b"{\"format\":1,\"kind\":\"keys\",\"critical\":[],\"x\":1,\"x\":1}",
        &[0],
    );
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Json(JsonError::DuplicateKey(_))
    );
    // format before kind before critical.
    for (payload, which) in [
        (
            &b"{\"format\":2,\"kind\":\"feed\",\"critical\":[\"x\"]}"[..],
            0,
        ),
        (
            &b"{\"format\":1,\"kind\":\"feed\",\"critical\":[\"x\"]}"[..],
            1,
        ),
        (
            &b"{\"format\":1,\"kind\":\"keys\",\"critical\":[\"x\"]}"[..],
            2,
        ),
    ] {
        let bytes = fx.envelope(PayloadKind::Keys, payload, &[0]);
        let res = fx.keys(&root, &bytes, floor.clone(), now0());
        match which {
            0 => assert_err!(res, Error::FormatVersion { found: 2 }),
            1 => assert_err!(res, Error::Kind { .. }),
            _ => assert_err!(res, Error::UnknownCritical(_)),
        }
    }
    // Binding before floors before freshness.
    let mut ks = fx.keyset_document(2, 1, Some(SUITE_T0), 1, &[5]);
    let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::new(0, 5), now0()),
        Error::KeySetRootVersion { .. }
    );
    ks.root_version = u53(1);
    let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::new(0, 5), now0()),
        Error::Rollback { .. }
    );
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::new(0, 1), now0()),
        Error::Expired { .. }
    );
}

fn envelope_structure(fx: &ChainFixture<'_>) {
    let root = fx.trusted_root(1, 1, &[0]);
    let floor = RollbackFloor::default();
    let ty = PayloadKind::Keys.payload_type();
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let good = fx.envelope(PayloadKind::Keys, &payload, &[0]);
    fx.keys(&root, &good, floor.clone(), now0())
        .expect("baseline");

    // Unknown fields at either level.
    let bytes = replace(&good, "\"payloadType\"", "\"extra\": 1, \"payloadType\"");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Schema(_)
    );
    let bytes = replace(&good, "\"keyid\"", "\"extra\": 1, \"keyid\"");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Schema(_)
    );
    // Missing field.
    let keyid = fx.key_id(0).to_hex();
    let bytes = replace(&good, &format!("\"keyid\": \"{keyid}\","), "");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Schema(_)
    );
    // Duplicate member.
    let bytes = replace(
        &good,
        "\"payloadType\"",
        &format!("\"payloadType\": \"{ty}\", \"payloadType\""),
    );
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Json(JsonError::DuplicateKey(_))
    );
    // Trailing data, not an object.
    let mut bytes = good.clone();
    bytes.extend_from_slice(b" {}");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Json(_)
    );
    assert_err!(fx.keys(&root, b"[]", floor.clone(), now0()), Error::Json(_));

    // Signature counts.
    let bytes = write_envelope(ty, &payload, &[]);
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::SignatureCount { count: 0, max: 16 }
    );
    let sig = fx.signature(0, ty, &payload);
    let bytes = write_envelope(ty, &payload, &[sig; 17]);
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::SignatureCount { count: 17, max: 16 }
    );
    fx.keys(
        &root,
        &write_envelope(ty, &payload, &[sig; 16]),
        floor.clone(),
        now0(),
    )
    .expect("16 signatures");

    // Signature length.
    let sig_b64 = base64_encode(&sig.sig);
    for (bad, len) in [
        (base64_encode(&sig.sig[..63]), 63),
        (base64_encode(&[sig.sig.as_slice(), &[0]].concat()), 65),
        (String::new(), 0),
    ] {
        let bytes = replace(&good, &sig_b64, &bad);
        match fx.keys(&root, &bytes, floor.clone(), now0()) {
            Err(Error::SignatureLength { len: l }) => assert_eq!(l, len),
            other => panic!("expected SignatureLength, got {:?}", other.err()),
        }
    }

    // Base64: URL-safe alphabet, missing padding, whitespace.
    let odd = [0xfbu8, 0xff];
    let url = write_envelope(ty, &odd, &[sig]);
    let bytes = replace(&url, "+/8=", "-_8=");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Base64(Base64Error::InvalidCharacter { .. })
    );
    let bytes = replace(&url, "+/8=", "+/8");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Base64(_)
    );
    let bytes = replace(&url, "+/8=", "+/8=\\n");
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Base64(_)
    );
    let bytes = replace(&good, &sig_b64, &sig_b64.replace('=', ""));
    assert_err!(
        fx.keys(&root, &bytes, floor.clone(), now0()),
        Error::Base64(_)
    );

    // Size cap: one byte over 64 KiB fails before anything is parsed.
    let mut big = good.clone();
    big.resize(64 * 1024 + 1, b' ');
    assert_err!(
        fx.keys(&root, &big, floor.clone(), now0()),
        Error::TooLarge {
            size: 65_537,
            cap: 65_536,
            ..
        }
    );
    let mut fits = good.clone();
    fits.resize(64 * 1024, b' ');
    fx.keys(&root, &fits, floor.clone(), now0())
        .expect("trailing whitespace within the cap");
    let mut big_root = fx.envelope(
        PayloadKind::Root,
        &fx.root_document(2, 1, &[2]).to_payload(),
        &[0, 2],
    );
    big_root.resize(64 * 1024 + 1, b' ');
    assert_err!(fx.advance(&root, &big_root), Error::TooLarge { .. });
}

fn key_list_rules(fx: &ChainFixture<'_>) {
    let r1 = fx.trusted_root(1, 1, &[0]);
    let root_case = |doc: RootDocument| {
        let bytes = fx.envelope(PayloadKind::Root, &doc.to_payload(), &[0, 2, 3]);
        fx.advance(&r1, &bytes)
    };
    // Threshold range.
    assert_err!(
        root_case(fx.root_document(2, 0, &[2])),
        Error::KeyThreshold { threshold: 0, .. }
    );
    assert_err!(
        root_case(fx.root_document(2, 3, &[2, 3])),
        Error::KeyThreshold {
            threshold: 3,
            keys: 2,
            ..
        }
    );
    assert_err!(
        root_case(fx.root_document(2, 1, &[])),
        Error::KeyThreshold { keys: 0, .. }
    );
    let mut many = fx.root_document(2, 1, &[2]);
    many.keys = vec![fx.key_entry(2); 17];
    assert_err!(
        root_case(many),
        Error::KeyThreshold {
            keys: 17,
            max: 16,
            ..
        }
    );
    // Id mismatch, algorithm, invalid key.
    let mut doc = fx.root_document(2, 1, &[2]);
    doc.keys[0].id = fx.key_id(3);
    assert_err!(root_case(doc), Error::KeyIdMismatch);
    for alg in ["Ed25519", "ed448", ""] {
        let mut doc = fx.root_document(2, 1, &[2]);
        doc.keys[0].alg = alg.to_owned();
        assert_err!(
            root_case(doc),
            Error::Signature(SignatureError::UnsupportedAlgorithm)
        );
    }
    let mut doc = fx.root_document(2, 1, &[2, 3]);
    doc.keys.push(KeyEntry {
        id: fx.hasher.sha256(&fx.invalid_key),
        alg: "ed25519".to_owned(),
        public: PublicKey::from_bytes(fx.invalid_key),
    });
    assert_err!(
        root_case(doc),
        Error::Signature(SignatureError::InvalidPublicKey)
    );

    // Key set: release-key count, threshold, window, id.
    let root = fx.trusted_root(1, 1, &[0]);
    let ks_case = |ks: KeySetDocument| {
        let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        fx.keys(&root, &bytes, RollbackFloor::default(), now0())
    };
    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    ks.keys = vec![ks.keys[0].clone(); 65];
    assert_err!(
        ks_case(ks),
        Error::KeyThreshold {
            keys: 65,
            max: 64,
            ..
        }
    );
    assert_err!(
        ks_case(fx.keyset_document(1, 1, None, 0, &[5])),
        Error::KeyThreshold { .. }
    );
    assert_err!(
        ks_case(fx.keyset_document(1, 1, None, 3, &[5, 6])),
        Error::KeyThreshold { .. }
    );
    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    ks.keys[0].not_after = ks.keys[0].not_before;
    assert_err!(ks_case(ks), Error::KeyWindow);
    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    ks.keys[0].id = fx.key_id(6);
    assert_err!(ks_case(ks), Error::KeyIdMismatch);
    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    ks.keys[0].public = PublicKey::from_bytes(fx.invalid_key);
    ks.keys[0].id = fx.hasher.sha256(&fx.invalid_key);
    assert_err!(
        ks_case(ks),
        Error::Signature(SignatureError::InvalidPublicKey)
    );
    assert_err!(
        ks_case(fx.keyset_document(1, 0, None, 1, &[5])),
        Error::Schema(_)
    );
    // `null` is never a valid value; uppercase hex is rejected.
    let ks = fx.keyset_document(1, 1, Some(SUITE_T0 + DAY), 1, &[5]);
    let text = String::from_utf8(ks.to_payload()).expect("utf-8");
    let nulled = text.replace(
        &format!("\"expires\":{}", SUITE_T0 + DAY),
        "\"expires\":null",
    );
    assert_ne!(nulled, text);
    let bytes = fx.envelope(PayloadKind::Keys, nulled.as_bytes(), &[0]);
    assert_err!(
        fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
        Error::Schema(_)
    );
    let hex = ks.keys[0].public.to_hex();
    if hex != hex.to_uppercase() {
        let upper = text.replace(&hex, &hex.to_uppercase());
        let bytes = fx.envelope(PayloadKind::Keys, upper.as_bytes(), &[0]);
        assert_err!(
            fx.keys(&root, &bytes, RollbackFloor::default(), now0()),
            Error::Schema(_)
        );
    }
}

fn bindings(fx: &ChainFixture<'_>) {
    let r1 = fx.trusted_root(1, 1, &[0]);
    let other = AppId::parse("org.example.other").expect("valid");
    let mut doc = fx.root_document(2, 1, &[2]);
    doc.app_id = other.clone();
    let bytes = fx.envelope(PayloadKind::Root, &doc.to_payload(), &[0, 2]);
    assert_err!(fx.advance(&r1, &bytes), Error::AppIdMismatch);

    let mut ks = fx.keyset_document(1, 1, None, 1, &[5]);
    ks.app_id = other;
    let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
    assert_err!(
        fx.keys(&r1, &bytes, RollbackFloor::default(), now0()),
        Error::AppIdMismatch
    );

    // A key set for root 1 after the walk reached root 2, and the reverse.
    let doc2 = fx.root_document(2, 1, &[2]).to_payload();
    let r2 = fx
        .advance(&r1, &fx.envelope(PayloadKind::Root, &doc2, &[0, 2]))
        .expect("root 2");
    let ks1 = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let bytes = fx.envelope(PayloadKind::Keys, &ks1, &[2]);
    assert_err!(
        fx.keys(&r2, &bytes, RollbackFloor::default(), now0()),
        Error::KeySetRootVersion {
            expected: 2,
            found: 1
        }
    );
    let ks2 = fx.keyset_document(2, 1, None, 1, &[5]).to_payload();
    let bytes = fx.envelope(PayloadKind::Keys, &ks2, &[0]);
    assert_err!(
        fx.keys(&r1, &bytes, RollbackFloor::default(), now0()),
        Error::KeySetRootVersion {
            expected: 1,
            found: 2
        }
    );
    // The old root no longer signs once rotated away.
    let bytes = fx.envelope(PayloadKind::Keys, &ks2, &[0]);
    assert_err!(
        fx.keys(&r2, &bytes, RollbackFloor::default(), now0()),
        Error::Threshold { .. }
    );
    // A key set envelope is not a root document.
    let bytes = fx.envelope(PayloadKind::Keys, &doc2, &[0, 2]);
    assert_err!(fx.advance(&r1, &bytes), Error::PayloadType { .. });
    // A root payload in a root envelope with kind "keys".
    let mut wrong_kind = fx.root_document(2, 1, &[2]);
    wrong_kind.kind = "keys".to_owned();
    let bytes = fx.envelope(PayloadKind::Root, &wrong_kind.to_payload(), &[0, 2]);
    assert_err!(fx.advance(&r1, &bytes), Error::Kind { .. });
}

fn compiled_in_root_rules(fx: &ChainFixture<'_>) {
    let k0 = fx.public_key(0);
    let k1 = fx.public_key(1);
    let make = |version, threshold, keys: &[[u8; 32]]| {
        TrustedRoot::from_parts(app_id(), version, threshold, keys, fx.hasher, fx.verifier)
    };
    make(1, 2, &[k0, k1]).expect("valid");
    assert_err!(make(0, 1, &[k0]), Error::Schema(_));
    assert_err!(make(1 << 53, 1, &[k0]), Error::Schema(_));
    assert_err!(make(1, 0, &[k0]), Error::KeyThreshold { .. });
    assert_err!(make(1, 3, &[k0, k1]), Error::KeyThreshold { .. });
    assert_err!(make(1, 1, &[]), Error::KeyThreshold { .. });
    assert_err!(
        make(1, 1, &[k0, fx.invalid_key]),
        Error::Signature(SignatureError::InvalidPublicKey)
    );
    let root = make(5, 1, &[k0]).expect("valid");
    assert_eq!(root.app_id().as_str(), SUITE_APP_ID);
    assert_eq!(root.keys().keys()[0].id(), fx.key_id(0));
}

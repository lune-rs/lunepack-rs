//! The whole verify chain with real Ed25519 and SHA-256 (M2 step 11): root 1 → root 2 rotation,
//! key set, feed, candidate selection, manifest and file decoding, then a one-byte change in each
//! document, and the rollout-bucket known answer of FORMAT.md 11.5. Keys are generated at test
//! time; none is committed.

use ed25519_dalek::{Signer, SigningKey};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use lunepack_core::{
    AppId, Channel, ClockReading, CodecId, Error, FeedTargetEntry, Hasher, PayloadKind,
    RollbackFloor, Target, TrustedRoot, VerifiedEntry, VerifiedFeed, VerifiedKeySet, Version,
    advance_root, decode_verified, in_rollout, rollout_bucket, select_candidate, verify_feed,
    verify_key_set, verify_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, PackBuilder, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const VERSION: &str = "1.2.0";
const TARGET: Target = Target::LinuxX86_64;
const DAY: u64 = 86_400;
/// FORMAT.md 11.5 known answer: install id, seed and the resulting bucket.
const KAT_INSTALL: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const KAT_SEED_HEX: &str = "44abc528db54f66d40174cfcdd43bab36285a5d953cbd185c672350a46f89691";
const KAT_BUCKET: u16 = 6700;

/// One fresh signing key per seed `0..=7`: 0 root 1, 1 root 2, 5 release.
struct Keys(Vec<SigningKey>);

impl Keys {
    fn new() -> Self {
        let mut rng = UnwrapErr(SysRng);
        Keys((0..8).map(|_| SigningKey::generate(&mut rng)).collect())
    }

    fn sign(&self, seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
        let key = &self.0[usize::from(seed)];
        (key.verifying_key().to_bytes(), key.sign(message).to_bytes())
    }
}

fn small_order_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
}

fn kat_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&KAT_SEED_HEX[2 * i..2 * i + 2], 16).unwrap();
    }
    seed
}

fn clock() -> ClockReading {
    ClockReading::read(&FakeClock::new(SUITE_T0), None)
}

fn feed_of(
    keys: &VerifiedKeySet,
    bytes: &[u8],
    floor: &RollbackFloor,
) -> Result<VerifiedFeed, Error> {
    verify_feed(
        keys,
        bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        floor,
        &clock(),
        &Ed25519Verifier,
    )
}

/// Everything the chain produced, with the bytes of each document.
struct Chain {
    root2: Vec<u8>,
    key_set: Vec<u8>,
    feed: Vec<u8>,
    manifest: Vec<u8>,
    pack: PackBuilder,
}

#[test]
fn real_chain_verifies_end_to_end_and_every_one_byte_change_is_rejected() {
    let keys = Keys::new();
    let sign = |seed: u8, message: &[u8]| keys.sign(seed, message);
    let fx = ChainFixture {
        hasher: &Sha256Hasher,
        verifier: &Ed25519Verifier,
        sign: &sign,
        invalid_key: small_order_key(),
    };

    // Root 1 is compiled in; root 2 rotates to a new key, signed by both roots.
    let root1 = fx.trusted_root(1, 1, &[0]);
    let root2_bytes = fx.envelope(
        PayloadKind::Root,
        &fx.root_document(2, 1, &[1]).to_payload(),
        &[0, 1],
    );
    let root2 = advance_root(&root1, &root2_bytes, &Sha256Hasher, &Ed25519Verifier)
        .expect("root 2 is reachable from root 1");
    assert_eq!(root2.version(), 2);

    // Key set 1 under root 2 with one release key.
    let ks_bytes = fx.envelope(
        PayloadKind::Keys,
        &fx.keyset_document(2, 1, None, 1, &[5]).to_payload(),
        &[1],
    );
    let key_set = verify_key_set(
        &root2,
        &ks_bytes,
        &RollbackFloor::default(),
        &clock(),
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .expect("key set verifies under root 2");

    // A pack with every codec, its manifest and the feed that lists it with a 6701 rollout.
    let mut pack = PackBuilder::new();
    let data = |n: usize, salt: u8| -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
            .collect()
    };
    pack.file(
        &Sha256Hasher,
        "bin/app",
        &data(300, 1),
        CodecId::BcjX86Lzma2,
    )
    .file(&Sha256Hasher, "lib/x.so.1", &data(200, 2), CodecId::Bcj2)
    .file(&Sha256Hasher, "README", &data(50, 3), CodecId::Stored)
    .file(&Sha256Hasher, "empty", b"", CodecId::Stored)
    .symlink("lib/x.so", "x.so.1");
    let manifest_bytes = fx.envelope(
        PayloadKind::Manifest,
        &fx.manifest_document(VERSION, TARGET, &pack).to_payload(),
        &[5],
    );
    let release = |basis_points: u64, manifest: &[u8]| {
        fx.release(
            VERSION,
            &[(TARGET, manifest)],
            Some((basis_points, kat_seed())),
        )
    };
    let feed_doc = fx.feed_document(
        1,
        Some(SUITE_T0 + 30 * DAY),
        vec![release(KAT_BUCKET as u64 + 1, &manifest_bytes)],
    );
    let feed_bytes = fx.envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[5]);
    let feed = feed_of(&key_set, &feed_bytes, &RollbackFloor::default()).expect("feed verifies");

    // Candidate selection with the FORMAT.md 11.5 install id: bucket 6700 < 6701.
    let current = Version::parse("1.0.0").unwrap();
    let candidate = select_candidate(&feed, &current, TARGET, &[], &KAT_INSTALL, &Sha256Hasher)
        .expect("inside the rollout");
    assert_eq!(candidate.entry.version_text(), VERSION);
    assert_eq!(candidate.entry.target(), TARGET);

    // Manifest and files.
    let manifest = verify_manifest(
        &key_set,
        &candidate.entry,
        &manifest_bytes,
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .expect("manifest verifies");
    let mut decoded = 0;
    for entry in manifest.entries() {
        if let VerifiedEntry::File {
            frame: Some(frame), ..
        } = entry
        {
            let start = frame.offset() as usize;
            let bytes = &pack.bytes[start..start + frame.length() as usize];
            let mut out = Vec::new();
            decode_verified(frame, bytes, &Sha256Hasher, &FakeCodec::new(), &mut out)
                .expect("frame verifies and decodes");
            assert_eq!(Sha256Hasher.sha256(&out), frame.file_sha256());
            decoded += 1;
        }
    }
    assert_eq!(decoded, 3);

    let chain = Chain {
        root2: root2_bytes,
        key_set: ks_bytes,
        feed: feed_bytes,
        manifest: manifest_bytes,
        pack,
    };
    wrong_roles_are_rejected(&fx, &root1, &root2, &key_set, &chain);
    one_byte_changes_are_rejected(&fx, &root1, &root2, &key_set, &chain);
}

/// Keys of the wrong role or of a retired root never satisfy a threshold.
fn wrong_roles_are_rejected(
    fx: &ChainFixture<'_>,
    root1: &TrustedRoot,
    root2: &TrustedRoot,
    key_set: &VerifiedKeySet,
    chain: &Chain,
) {
    // Root 1's key no longer signs key sets once root 2 is trusted.
    let by_old_root = fx.envelope(
        PayloadKind::Keys,
        &fx.keyset_document(2, 1, None, 1, &[5]).to_payload(),
        &[0],
    );
    assert!(matches!(
        verify_key_set(
            root2,
            &by_old_root,
            &RollbackFloor::default(),
            &clock(),
            &Sha256Hasher,
            &Ed25519Verifier
        ),
        Err(Error::Threshold { .. })
    ));
    // A root key does not sign a feed.
    let doc = fx.feed_document(1, None, Vec::new());
    let by_root_key = fx.envelope(PayloadKind::Feed, &doc.to_payload(), &[1]);
    assert!(matches!(
        feed_of(key_set, &by_root_key, &RollbackFloor::default()),
        Err(Error::Threshold { .. })
    ));
    // Root 2 cannot be reached by root 1's key alone (the new root must sign it too).
    let only_old = fx.envelope(
        PayloadKind::Root,
        &fx.root_document(2, 1, &[1]).to_payload(),
        &[0],
    );
    assert!(advance_root(root1, &only_old, &Sha256Hasher, &Ed25519Verifier).is_err());
    // The feed seq floor holds with real signatures too.
    let floor = RollbackFloor::default().with_feed_seq(Channel::parse(SUITE_CHANNEL).unwrap(), 2);
    assert!(matches!(
        feed_of(key_set, &chain.feed, &floor),
        Err(Error::Rollback { .. })
    ));
}

/// Changes each byte of each document in turn (`^ 0x01`) and expects a rejection every time.
fn one_byte_changes_are_rejected(
    fx: &ChainFixture<'_>,
    root1: &TrustedRoot,
    root2: &TrustedRoot,
    key_set: &VerifiedKeySet,
    chain: &Chain,
) {
    let flipped = |bytes: &[u8], at: usize| {
        let mut b = bytes.to_vec();
        b[at] ^= 0x01;
        b
    };
    for at in 0..chain.root2.len() {
        let bytes = flipped(&chain.root2, at);
        assert!(
            advance_root(root1, &bytes, &Sha256Hasher, &Ed25519Verifier).is_err(),
            "root-2.json accepted with byte {at} changed"
        );
    }
    for at in 0..chain.key_set.len() {
        let bytes = flipped(&chain.key_set, at);
        assert!(
            verify_key_set(
                root2,
                &bytes,
                &RollbackFloor::default(),
                &clock(),
                &Sha256Hasher,
                &Ed25519Verifier
            )
            .is_err(),
            "keys.json accepted with byte {at} changed"
        );
    }
    for at in 0..chain.feed.len() {
        let bytes = flipped(&chain.feed, at);
        assert!(
            feed_of(key_set, &bytes, &RollbackFloor::default()).is_err(),
            "the feed was accepted with byte {at} changed"
        );
    }
    // The manifest is bound by the feed's hash; so that the signature check is reached too, each
    // changed manifest is also listed by a freshly signed feed.
    let feed = feed_of(key_set, &chain.feed, &RollbackFloor::default()).unwrap();
    let entry = feed.target_entry(0, TARGET).unwrap();
    for at in 0..chain.manifest.len() {
        let bytes = flipped(&chain.manifest, at);
        assert!(
            verify_manifest(key_set, &entry, &bytes, &Sha256Hasher, &Ed25519Verifier).is_err(),
            "the manifest was accepted with byte {at} changed"
        );
        let relisted = relisted_entry(fx, key_set, &bytes);
        assert!(
            verify_manifest(key_set, &relisted, &bytes, &Sha256Hasher, &Ed25519Verifier).is_err(),
            "a re-listed manifest was accepted with byte {at} changed"
        );
    }
    // Unchanged, the same path accepts (the loop above rejects for the change, not the setup).
    let relisted = relisted_entry(fx, key_set, &chain.manifest);
    verify_manifest(
        key_set,
        &relisted,
        &chain.manifest,
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .expect("the unchanged manifest verifies through a re-listed entry");
    assert!(!chain.pack.bytes.is_empty());
}

fn relisted_entry(
    fx: &ChainFixture<'_>,
    key_set: &VerifiedKeySet,
    manifest: &[u8],
) -> FeedTargetEntry {
    let doc = fx.feed_document(
        1,
        None,
        vec![fx.release(VERSION, &[(TARGET, manifest)], None)],
    );
    let bytes = fx.envelope(PayloadKind::Feed, &doc.to_payload(), &[5]);
    feed_of(key_set, &bytes, &RollbackFloor::default())
        .expect("re-listed feed verifies")
        .target_entry(0, TARGET)
        .expect("target listed")
}

#[test]
fn rollout_bucket_known_answer_with_real_sha256() {
    // FORMAT.md 11.5: first eight hash bytes f728fb2e5aacef3c, bucket 6700.
    let mut joined = KAT_INSTALL.to_vec();
    joined.extend_from_slice(&kat_seed());
    let digest = Sha256Hasher.sha256(&joined);
    assert_eq!(
        &digest.as_bytes()[..8],
        &[0xf7, 0x28, 0xfb, 0x2e, 0x5a, 0xac, 0xef, 0x3c]
    );
    assert_eq!(
        rollout_bucket(&KAT_INSTALL, &kat_seed(), &Sha256Hasher),
        KAT_BUCKET
    );
}

#[test]
fn rollout_boundaries_with_the_known_bucket() {
    use lunepack_core::Rollout;
    let rollout = |basis_points: u16| {
        Some(Rollout {
            basis_points,
            seed: kat_seed(),
        })
    };
    // bucket < basis_points: 6700 is outside 6700 and inside 6701; 0 is nobody, 10000 everybody.
    assert!(!in_rollout(rollout(0), &KAT_INSTALL, &Sha256Hasher));
    assert!(!in_rollout(
        rollout(KAT_BUCKET),
        &KAT_INSTALL,
        &Sha256Hasher
    ));
    assert!(in_rollout(
        rollout(KAT_BUCKET + 1),
        &KAT_INSTALL,
        &Sha256Hasher
    ));
    assert!(in_rollout(rollout(10_000), &KAT_INSTALL, &Sha256Hasher));
    assert!(in_rollout(None, &KAT_INSTALL, &Sha256Hasher));
}

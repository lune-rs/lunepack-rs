//! Step 5: envelope signing and the document builders, checked by the real verifiers with the
//! testkit fakes (FakeSigner, FakeVerifier, FakeHasher, FakeClock).

use lunepack_core::error::SignerError;
use lunepack_core::{
    AppId, Channel, ClockReading, DEFAULT_FEED_LIFETIME_SECS, Error, FeedDocument, Hasher,
    PayloadKind, ReleaseDoc, RollbackFloor, SignatureAlg, Signer, Target, VerifiedFeed,
    VerifiedKeySet, advance_root, next_feed, next_key_set, rollout_seed, rotate_root,
    sign_envelope, verify_feed, verify_key_set,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeHasher, FakeKeyPair, FakeSigner, FakeVerifier, SUITE_APP_ID,
    SUITE_CHANNEL, SUITE_T0,
};

const DAY: u64 = 86_400;
const MAX_INT: u64 = (1 << 53) - 1;

fn app() -> AppId {
    AppId::parse(SUITE_APP_ID).unwrap()
}

fn chan() -> Channel {
    Channel::parse(SUITE_CHANNEL).unwrap()
}

fn rel(fx: &ChainFixture<'_>, version: &str) -> ReleaseDoc {
    fx.release(version, &[(Target::LinuxX86_64, b"manifest bytes")], None)
}

fn sign(kind: PayloadKind, payload: &[u8], seeds: &[u8]) -> Result<Vec<u8>, Error> {
    let signers: Vec<FakeSigner> = seeds.iter().map(|&s| FakeSigner::new(s)).collect();
    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s as &dyn Signer).collect();
    sign_envelope(kind, payload, &refs, &FakeHasher, &FakeVerifier)
}

fn reading(now: u64) -> ClockReading {
    ClockReading::read(&FakeClock::new(now), None)
}

fn verify(keys: &VerifiedKeySet, bytes: &[u8], now: u64) -> Result<VerifiedFeed, Error> {
    verify_feed(
        keys,
        bytes,
        &app(),
        &chan(),
        &RollbackFloor::default(),
        &reading(now),
        &FakeVerifier,
    )
}

/// A verified feed with sequence number `seq` (signed by release key 5).
fn feed_at(fx: &ChainFixture<'_>, keys: &VerifiedKeySet, seq: u64) -> VerifiedFeed {
    let doc = fx.feed_document(seq, None, vec![rel(fx, "1.0.0")]);
    let bytes = sign(PayloadKind::Feed, &doc.to_payload(), &[5]).unwrap();
    verify(keys, &bytes, SUITE_T0).unwrap()
}

// ---- sign_envelope -----------------------------------------------------------------------------

#[test]
fn signed_envelopes_pass_the_readers() {
    let fx = ChainFixture::fake();
    let (root, keys) = fx.verified_chain(&[5], 1);

    // A feed under release key 5.
    let doc = next_feed(
        None,
        &app(),
        &chan(),
        SUITE_T0,
        vec![rel(&fx, "1.0.0")],
        None,
    )
    .unwrap();
    let bytes = sign(PayloadKind::Feed, &doc.to_payload(), &[5]).unwrap();
    verify(&keys, &bytes, SUITE_T0).unwrap();

    // A key set under the root key.
    let ks = next_key_set(
        None,
        1,
        &app(),
        vec![fx.release_key(5, SUITE_T0 - DAY, SUITE_T0 + 1000 * DAY)],
        1,
        None,
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    let bytes = sign(PayloadKind::Keys, &ks.to_payload(), &[0]).unwrap();
    let verified = verify_key_set(
        &root,
        &bytes,
        &RollbackFloor::default(),
        &reading(SUITE_T0),
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    assert_eq!(verified.version(), 1);
}

#[test]
fn envelope_bytes_are_identical_across_runs_and_signer_orders() {
    let payload = b"{\"a\":1}";
    let a = sign(PayloadKind::Feed, payload, &[3, 7, 5]).unwrap();
    let b = sign(PayloadKind::Feed, payload, &[3, 7, 5]).unwrap();
    let c = sign(PayloadKind::Feed, payload, &[5, 3, 7]).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, c, "signatures are sorted by key id");
    // And the payload type of the kind is what is written.
    let text = String::from_utf8(a).unwrap();
    assert!(text.contains(PayloadKind::Feed.payload_type()));
}

#[test]
fn threshold_two_needs_both_signatures_and_both_are_written() {
    let fx = ChainFixture::fake();
    let root = fx.trusted_root(1, 2, &[0, 1]);
    let ks = fx.keyset_document(1, 1, None, 1, &[5]);
    let ok = sign(PayloadKind::Keys, &ks.to_payload(), &[1, 0]).unwrap();
    let check = |bytes: &[u8]| {
        verify_key_set(
            &root,
            bytes,
            &RollbackFloor::default(),
            &reading(SUITE_T0),
            &FakeHasher,
            &FakeVerifier,
        )
    };
    check(&ok).unwrap();
    let one = sign(PayloadKind::Keys, &ks.to_payload(), &[0]).unwrap();
    assert!(matches!(check(&one), Err(Error::Threshold { .. })));
}

/// A signer that claims one key and signs with another.
#[derive(Debug)]
struct Liar {
    claims: FakeSigner,
    signs: FakeSigner,
}

impl Signer for Liar {
    fn alg(&self) -> SignatureAlg {
        SignatureAlg::Ed25519
    }
    fn public_key(&self) -> [u8; 32] {
        self.claims.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        self.signs.sign(message)
    }
}

/// A signer whose backend fails.
#[derive(Debug)]
struct Broken(FakeSigner);

impl Signer for Broken {
    fn alg(&self) -> SignatureAlg {
        SignatureAlg::Ed25519
    }
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], Error> {
        Err(SignerError::Failed {
            reason: "backend down",
            source: None,
        }
        .into())
    }
}

#[test]
fn a_signature_by_another_key_is_wrong_key() {
    let liar = Liar {
        claims: FakeSigner::new(5),
        signs: FakeSigner::new(6),
    };
    let r = sign_envelope(
        PayloadKind::Feed,
        b"{}",
        &[&liar],
        &FakeHasher,
        &FakeVerifier,
    );
    assert!(
        matches!(r, Err(Error::Signer(SignerError::WrongKey))),
        "{r:?}"
    );
    // Even when other signers are fine.
    let good = FakeSigner::new(1);
    let r = sign_envelope(
        PayloadKind::Feed,
        b"{}",
        &[&good, &liar],
        &FakeHasher,
        &FakeVerifier,
    );
    assert!(matches!(r, Err(Error::Signer(SignerError::WrongKey))));
}

#[test]
fn a_failing_signer_fails_the_envelope() {
    let broken = Broken(FakeSigner::new(5));
    let r = sign_envelope(
        PayloadKind::Feed,
        b"{}",
        &[&broken],
        &FakeHasher,
        &FakeVerifier,
    );
    assert!(
        matches!(r, Err(Error::Signer(SignerError::Failed { .. }))),
        "{r:?}"
    );
}

#[test]
fn duplicate_signers_zero_signers_and_too_many_are_errors() {
    let r = sign(PayloadKind::Feed, b"{}", &[5, 5]);
    assert!(
        matches!(r, Err(Error::Signer(SignerError::DuplicateKey))),
        "{r:?}"
    );
    // The same key behind two signer objects is still a duplicate.
    let (a, b) = (FakeSigner::new(5), FakeSigner::new(5));
    let r = sign_envelope(
        PayloadKind::Feed,
        b"{}",
        &[&a, &b],
        &FakeHasher,
        &FakeVerifier,
    );
    assert!(matches!(r, Err(Error::Signer(SignerError::DuplicateKey))));

    assert!(matches!(
        sign(PayloadKind::Feed, b"{}", &[]),
        Err(Error::SignatureCount { count: 0, .. })
    ));
    let many: Vec<u8> = (0..17).collect();
    assert!(matches!(
        sign(PayloadKind::Feed, b"{}", &many),
        Err(Error::SignatureCount { count: 17, max: 16 })
    ));
    let sixteen: Vec<u8> = (0..16).collect();
    sign(PayloadKind::Feed, b"{}", &sixteen).unwrap();
}

// ---- root rotation -----------------------------------------------------------------------------

#[test]
fn rotated_root_needs_both_sides() {
    let fx = ChainFixture::fake();
    let trusted = fx.trusted_root(1, 1, &[0]);
    let current = fx.root_document(1, 1, &[0]);
    let next = rotate_root(&current, 2, vec![fx.key_entry(1), fx.key_entry(2)]).unwrap();
    assert_eq!(next.version.get(), 2);
    assert_eq!(next.app_id, current.app_id);
    assert_eq!(next.kind, "root");
    assert_eq!(next.format.get(), 1);
    assert!(next.critical.is_empty());
    let payload = next.to_payload();
    let advance = |bytes: &[u8]| advance_root(&trusted, bytes, &FakeHasher, &FakeVerifier);

    // Current signer plus the new keys (threshold 2): accepted.
    let both = sign(PayloadKind::Root, &payload, &[0, 1, 2]).unwrap();
    let advanced = advance(&both).unwrap();
    assert_eq!(advanced.version(), 2);
    assert_eq!(advanced.threshold(), 2);

    // Only the old side, or only the new side: rejected.
    let old_only = sign(PayloadKind::Root, &payload, &[0]).unwrap();
    assert!(matches!(advance(&old_only), Err(Error::Threshold { .. })));
    let new_only = sign(PayloadKind::Root, &payload, &[1, 2]).unwrap();
    assert!(matches!(advance(&new_only), Err(Error::Threshold { .. })));
    // The new side short of its own threshold.
    let one_new = sign(PayloadKind::Root, &payload, &[0, 1]).unwrap();
    assert!(matches!(advance(&one_new), Err(Error::Threshold { .. })));
}

#[test]
fn a_key_in_both_roots_signs_once() {
    let fx = ChainFixture::fake();
    let trusted = fx.trusted_root(1, 1, &[0]);
    let current = fx.root_document(1, 1, &[0]);
    let next = rotate_root(&current, 2, vec![fx.key_entry(0), fx.key_entry(1)]).unwrap();
    // The union of {0} and {0, 1} is {0, 1}: key 0 signs once.
    let bytes = sign(PayloadKind::Root, &next.to_payload(), &[0, 1]).unwrap();
    assert_eq!(
        advance_root(&trusted, &bytes, &FakeHasher, &FakeVerifier)
            .unwrap()
            .version(),
        2
    );
    // Listing it twice is the signer's DuplicateKey, not a silent double signature.
    assert!(matches!(
        sign(PayloadKind::Root, &next.to_payload(), &[0, 0, 1]),
        Err(Error::Signer(SignerError::DuplicateKey))
    ));
}

#[test]
fn bad_root_rotations_are_errors() {
    let fx = ChainFixture::fake();
    let current = fx.root_document(3, 1, &[0]);
    assert_eq!(
        rotate_root(&current, 1, vec![fx.key_entry(1)])
            .unwrap()
            .version
            .get(),
        4
    );
    assert!(matches!(
        rotate_root(&current, 0, vec![fx.key_entry(1)]),
        Err(Error::KeyThreshold { .. })
    ));
    assert!(matches!(
        rotate_root(&current, 2, vec![fx.key_entry(1)]),
        Err(Error::KeyThreshold { .. })
    ));
    assert!(matches!(
        rotate_root(&current, 1, Vec::new()),
        Err(Error::KeyThreshold { .. })
    ));
    let seventeen: Vec<_> = (0..17).map(|s| fx.key_entry(s)).collect();
    assert!(matches!(
        rotate_root(&current, 1, seventeen),
        Err(Error::KeyThreshold { max: 16, .. })
    ));
    assert!(matches!(
        rotate_root(&current, 1, vec![fx.key_entry(1), fx.key_entry(1)]),
        Err(Error::DuplicatePublicKey)
    ));
    let mut bad_alg = fx.key_entry(1);
    bad_alg.alg = "rsa".to_owned();
    assert!(matches!(
        rotate_root(&current, 1, vec![bad_alg]),
        Err(Error::Signature(_))
    ));
    let mut maxed = fx.root_document(3, 1, &[0]);
    maxed.version = lunepack_core::U53::MAX;
    assert!(matches!(
        rotate_root(&maxed, 1, vec![fx.key_entry(1)]),
        Err(Error::Integer(_))
    ));
}

// ---- key sets ----------------------------------------------------------------------------------

fn release_keys(fx: &ChainFixture<'_>, seeds: &[u8]) -> Vec<lunepack_core::ReleaseKeyEntry> {
    seeds
        .iter()
        .map(|&s| fx.release_key(s, SUITE_T0 - DAY, SUITE_T0 + 1000 * DAY))
        .collect()
}

fn key_set(
    prev: Option<&VerifiedKeySet>,
    keys: Vec<lunepack_core::ReleaseKeyEntry>,
    threshold: u64,
    expires: Option<u64>,
) -> Result<lunepack_core::KeySetDocument, Error> {
    next_key_set(
        prev,
        1,
        &app(),
        keys,
        threshold,
        expires,
        &FakeHasher,
        &FakeVerifier,
    )
}

#[test]
fn key_set_versions_count_up() {
    let fx = ChainFixture::fake();
    let (root, first) = fx.verified_chain(&[5], 1);
    assert_eq!(first.version(), 1);
    let doc = key_set(
        Some(&first),
        release_keys(&fx, &[5, 6]),
        2,
        Some(SUITE_T0 + DAY),
    )
    .unwrap();
    assert_eq!(doc.version.get(), 2);
    assert_eq!(doc.root_version.get(), 1);
    assert_eq!(doc.expires.map(|e| e.get()), Some(SUITE_T0 + DAY));
    let bytes = sign(PayloadKind::Keys, &doc.to_payload(), &[0]).unwrap();
    let verified = verify_key_set(
        &root,
        &bytes,
        &RollbackFloor::default(),
        &reading(SUITE_T0),
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    assert_eq!(verified.version(), 2);
    assert_eq!(verified.threshold(), 2);
    assert_eq!(
        key_set(None, release_keys(&fx, &[5]), 1, None)
            .unwrap()
            .version
            .get(),
        1
    );
}

#[test]
fn key_set_rules_are_applied_before_signing() {
    let fx = ChainFixture::fake();
    let ok = || release_keys(&fx, &[5, 6]);
    assert!(matches!(
        key_set(None, ok(), 0, None),
        Err(Error::KeyThreshold { .. })
    ));
    assert!(matches!(
        key_set(None, ok(), 3, None),
        Err(Error::KeyThreshold { .. })
    ));
    assert!(matches!(
        key_set(None, Vec::new(), 1, None),
        Err(Error::KeyThreshold { .. })
    ));

    let sixty_five: Vec<_> = (0..65u8)
        .map(|s| fx.release_key(s, SUITE_T0 - DAY, SUITE_T0 + DAY))
        .collect();
    assert!(matches!(
        key_set(None, sixty_five, 1, None),
        Err(Error::KeyThreshold { max: 64, .. })
    ));
    let sixty_four: Vec<_> = (0..64u8)
        .map(|s| fx.release_key(s, SUITE_T0 - DAY, SUITE_T0 + DAY))
        .collect();
    key_set(None, sixty_four, 1, None).unwrap();

    // Empty and inverted windows.
    for (nb, na) in [(SUITE_T0, SUITE_T0), (SUITE_T0 + 1, SUITE_T0)] {
        let keys = vec![fx.release_key(5, nb, na)];
        assert!(matches!(
            key_set(None, keys, 1, None),
            Err(Error::KeyWindow)
        ));
    }
    // The same key twice (under one id), and an id that is not the key's hash.
    let mut keys = release_keys(&fx, &[5]);
    keys.push(keys[0].clone());
    assert!(matches!(
        key_set(None, keys, 1, None),
        Err(Error::DuplicatePublicKey)
    ));
    let mut keys = release_keys(&fx, &[5]);
    keys[0].id = fx.key_id(6);
    assert!(matches!(
        key_set(None, keys, 1, None),
        Err(Error::KeyIdMismatch)
    ));
    // A key the verifier rejects.
    let mut keys = release_keys(&fx, &[5]);
    keys[0].public = lunepack_core::PublicKey::from_bytes(fx.invalid_key);
    keys[0].id = FakeHasher.sha256(&fx.invalid_key);
    assert!(key_set(None, keys, 1, None).is_err());
    // Unknown algorithm.
    let mut keys = release_keys(&fx, &[5]);
    keys[0].alg = "rsa".to_owned();
    assert!(matches!(
        key_set(None, keys, 1, None),
        Err(Error::Signature(_))
    ));

    // Root version 0; another app's previous set.
    assert!(next_key_set(None, 0, &app(), ok(), 1, None, &FakeHasher, &FakeVerifier).is_err());
    let (_, first) = fx.verified_chain(&[5], 1);
    let other = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        next_key_set(
            Some(&first),
            1,
            &other,
            ok(),
            1,
            None,
            &FakeHasher,
            &FakeVerifier
        ),
        Err(Error::AppIdMismatch)
    ));
    // An expiry outside the integer range.
    assert!(matches!(
        key_set(None, ok(), 1, Some(1 << 53)),
        Err(Error::Integer(_))
    ));
}

// ---- feeds -------------------------------------------------------------------------------------

#[test]
fn feed_seq_follows_the_clock_and_never_goes_back() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let seq = |prev: Option<&VerifiedFeed>, now: u64| -> Result<u64, Error> {
        next_feed(prev, &app(), &chan(), now, vec![rel(&fx, "1.0.0")], None).map(|d| d.seq.get())
    };
    // First feed: the clock in milliseconds.
    assert_eq!(seq(None, 1000).unwrap(), 1_000_000);
    assert_eq!(seq(None, 0).unwrap(), 0);

    let prev = feed_at(&fx, &keys, 5);
    assert_eq!(seq(Some(&prev), 0).unwrap(), 6);
    assert_eq!(seq(Some(&prev), 1000).unwrap(), 1_000_000);
    // A clock far in the past never lowers it.
    let high = feed_at(&fx, &keys, 5_000_000);
    assert_eq!(seq(Some(&high), 1000).unwrap(), 5_000_001);

    // At the ceiling: an error, not a wrap.
    let top = feed_at(&fx, &keys, MAX_INT);
    assert!(matches!(seq(Some(&top), 0), Err(Error::Integer(_))));
    let below = feed_at(&fx, &keys, MAX_INT - 1);
    assert_eq!(seq(Some(&below), 0).unwrap(), MAX_INT);
    // A clock whose milliseconds pass 2^53 - 1, or overflow u64.
    assert!(matches!(
        seq(None, MAX_INT / 1000 + 1),
        Err(Error::Integer(_))
    ));
    assert_eq!(seq(None, MAX_INT / 1000).unwrap(), MAX_INT / 1000 * 1000);
    assert!(matches!(seq(None, u64::MAX), Err(Error::Integer(_))));
}

#[test]
fn feed_expiry_defaults_to_ninety_days_and_can_be_overridden() {
    let fx = ChainFixture::fake();
    let one = || vec![rel(&fx, "1.0.0")];
    let doc = next_feed(None, &app(), &chan(), SUITE_T0, one(), None).unwrap();
    assert_eq!(doc.issued.get(), SUITE_T0);
    assert_eq!(DEFAULT_FEED_LIFETIME_SECS, 90 * DAY);
    assert_eq!(doc.expires.map(|e| e.get()), Some(SUITE_T0 + 90 * DAY));
    let doc = next_feed(None, &app(), &chan(), SUITE_T0, one(), Some(3600)).unwrap();
    assert_eq!(doc.expires.map(|e| e.get()), Some(SUITE_T0 + 3600));
    // Not after `issued`, or past the integer range.
    assert!(matches!(
        next_feed(None, &app(), &chan(), SUITE_T0, one(), Some(0)),
        Err(Error::Field(_))
    ));
    assert!(matches!(
        next_feed(None, &app(), &chan(), SUITE_T0, one(), Some(MAX_INT)),
        Err(Error::Integer(_))
    ));
    assert!(matches!(
        next_feed(None, &app(), &chan(), SUITE_T0, one(), Some(u64::MAX)),
        Err(Error::Integer(_))
    ));
}

#[test]
fn feed_releases_are_sorted_by_precedence() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let versions = [
        "2.0.0",
        "1.10.0",
        "1.2.0-rc.1",
        "1.2.0",
        "1.0.0+build.9",
        "1.2.0-alpha",
    ];
    let releases = versions.iter().map(|v| rel(&fx, v)).collect();
    let doc = next_feed(None, &app(), &chan(), SUITE_T0, releases, None).unwrap();
    let got: Vec<&str> = doc.releases.iter().map(|r| r.version.as_str()).collect();
    // Build metadata is kept verbatim; the order is SemVer precedence.
    assert_eq!(
        got,
        [
            "1.0.0+build.9",
            "1.2.0-alpha",
            "1.2.0-rc.1",
            "1.2.0",
            "1.10.0",
            "2.0.0"
        ]
    );
    let bytes = sign(PayloadKind::Feed, &doc.to_payload(), &[5]).unwrap();
    let feed = verify(&keys, &bytes, SUITE_T0).unwrap();
    assert_eq!(feed.releases().len(), 6);
}

#[test]
fn feed_rejects_what_a_reader_would() {
    let fx = ChainFixture::fake();
    let make =
        |releases: Vec<ReleaseDoc>| next_feed(None, &app(), &chan(), SUITE_T0, releases, None);
    // Equal precedence, whatever the build metadata.
    assert!(matches!(
        make(vec![rel(&fx, "1.0.0+a"), rel(&fx, "1.0.0+b")]),
        Err(Error::DuplicateRelease)
    ));
    assert!(matches!(
        make(vec![
            rel(&fx, "1.0.0"),
            rel(&fx, "2.0.0"),
            rel(&fx, "1.0.0")
        ]),
        Err(Error::DuplicateRelease)
    ));
    // Not SemVer.
    assert!(matches!(
        make(vec![rel(&fx, "1.0")]),
        Err(Error::Version(_))
    ));
    // No target.
    let mut empty = rel(&fx, "1.0.0");
    empty.targets.clear();
    assert!(matches!(make(vec![empty]), Err(Error::Field(_))));
    // Over the release cap, counted before any other work.
    let many = vec![rel(&fx, "1.0.0"); 10_001];
    assert!(matches!(
        make(many),
        Err(Error::TooMany { max: 10_000, .. })
    ));
    // No releases at all is a valid, empty feed.
    assert!(make(Vec::new()).unwrap().releases.is_empty());

    // Another app's or channel's previous feed.
    let (_, keys) = fx.verified_chain(&[5], 1);
    let prev = feed_at(&fx, &keys, 1);
    let other_app = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        next_feed(Some(&prev), &other_app, &chan(), SUITE_T0, Vec::new(), None),
        Err(Error::AppIdMismatch)
    ));
    let beta = Channel::parse("beta").unwrap();
    assert!(matches!(
        next_feed(Some(&prev), &app(), &beta, SUITE_T0, Vec::new(), None),
        Err(Error::ChannelMismatch)
    ));
}

#[test]
fn a_feed_written_at_t_verifies_for_89_days_and_expires_by_400() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let doc: FeedDocument = next_feed(
        None,
        &app(),
        &chan(),
        SUITE_T0,
        vec![rel(&fx, "1.0.0")],
        None,
    )
    .unwrap();
    let bytes = sign(PayloadKind::Feed, &doc.to_payload(), &[5]).unwrap();
    verify(&keys, &bytes, SUITE_T0).unwrap();
    verify(&keys, &bytes, SUITE_T0 + 89 * DAY).unwrap();
    let at_expiry = verify(&keys, &bytes, SUITE_T0 + 90 * DAY);
    assert!(
        matches!(at_expiry, Err(Error::Expired { .. })),
        "{at_expiry:?}"
    );
    let late = verify(&keys, &bytes, SUITE_T0 + 400 * DAY);
    assert!(matches!(late, Err(Error::Expired { .. })), "{late:?}");
}

// ---- rollout seed ------------------------------------------------------------------------------

#[test]
fn rollout_seed_is_the_documented_hash() {
    let seed = rollout_seed(&app(), "1.2.0", &FakeHasher);
    let mut input = b"lunepack-rollout-v1".to_vec();
    input.push(0);
    input.extend_from_slice(SUITE_APP_ID.as_bytes());
    input.push(0);
    input.extend_from_slice(b"1.2.0");
    assert_eq!(seed, FakeHasher.sha256(&input));
    assert_eq!(seed, rollout_seed(&app(), "1.2.0", &FakeHasher));
    // Version text, not precedence: build metadata changes the seed; so does the app.
    assert_ne!(seed, rollout_seed(&app(), "1.2.0+x", &FakeHasher));
    assert_ne!(
        seed,
        rollout_seed(
            &AppId::parse("org.example.other").unwrap(),
            "1.2.0",
            &FakeHasher
        )
    );
    // The separators matter: ("ab", "c") and ("a", "bc") differ.
    assert_ne!(
        rollout_seed(&AppId::parse("ab").unwrap(), "1.0.0", &FakeHasher),
        rollout_seed(&AppId::parse("a").unwrap(), "b1.0.0", &FakeHasher)
    );
}

#[test]
fn the_fake_signer_matches_the_fixture_keys() {
    // The fixtures and FakeSigner derive keys from the same seed, which these tests rely on.
    let fx = ChainFixture::fake();
    for seed in 0..8u8 {
        assert_eq!(FakeSigner::new(seed).public_key(), fx.public_key(seed));
        assert_eq!(
            FakeSigner::new(seed).public_key(),
            FakeKeyPair::from_seed(seed).public_key()
        );
    }
}

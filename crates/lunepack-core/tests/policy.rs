//! Step 10: candidate selection and the rollout bucket (FORMAT.md 11.4, 11.5) with the testkit
//! hasher. The SHA-256 known answer (bucket 6700) is checked with real SHA-256 in step 11.

use lunepack_core::{
    AppId, Channel, ClockReading, Hasher, PayloadKind, ReleaseDoc, RollbackFloor, Target,
    VerifiedFeed, Version, in_rollout, rollout_bucket, select_candidate, verify_feed,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeHasher, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const M: &[u8] = b"manifest";
const SEED: [u8; 32] = [0x44; 32];

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn feed(fx: &ChainFixture<'_>, releases: Vec<ReleaseDoc>) -> VerifiedFeed {
    let (_, keys) = fx.verified_chain(&[5], 1);
    let bytes = fx.envelope(
        PayloadKind::Feed,
        &fx.feed_document(1, None, releases).to_payload(),
        &[5],
    );
    verify_feed(
        &keys,
        &bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(SUITE_T0), None),
        fx.verifier,
    )
    .unwrap()
}

fn id(n: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[12..].copy_from_slice(&n.to_be_bytes());
    out
}

/// Picks `(version text, target)` of the candidate.
fn pick(
    feed: &VerifiedFeed,
    current: &str,
    host: Target,
    bad: &[&str],
    install: &[u8; 16],
) -> Option<(String, Target)> {
    let bad: Vec<Version> = bad.iter().map(|b| v(b)).collect();
    select_candidate(feed, &v(current), host, &bad, install, &FakeHasher)
        .map(|c| (c.entry.version_text().to_owned(), c.entry.target()))
}

#[test]
fn bucket_is_sha256_of_install_id_then_seed_mod_10000() {
    let install = id(7);
    let mut joined = install.to_vec();
    joined.extend_from_slice(&SEED);
    let digest = FakeHasher.sha256(&joined);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest.as_bytes()[..8]);
    let want = (u64::from_be_bytes(first) % 10_000) as u16;
    assert_eq!(rollout_bucket(&install, &SEED, &FakeHasher), want);
    // Order matters: the seed is appended to the install id.
    let mut swapped = SEED.to_vec();
    swapped.extend_from_slice(&install);
    let digest = FakeHasher.sha256(&swapped);
    first.copy_from_slice(&digest.as_bytes()[..8]);
    assert_ne!((u64::from_be_bytes(first) % 10_000) as u16, want);
    // Always below 10000.
    for n in 0..2000 {
        assert!(rollout_bucket(&id(n), &SEED, &FakeHasher) < 10_000);
    }
}

#[test]
fn highest_newer_release_for_the_host_wins() {
    let fx = ChainFixture::fake();
    let f = feed(
        &fx,
        vec![
            fx.release("1.0.0", &[(Target::LinuxX86_64, M)], None),
            fx.release("1.2.0", &[(Target::LinuxX86_64, M)], None),
            fx.release("1.1.0", &[(Target::LinuxX86_64, M)], None),
            fx.release("0.9.0", &[(Target::LinuxX86_64, M)], None),
        ],
    );
    let host = Target::LinuxX86_64;
    let me = id(1);
    assert_eq!(
        pick(&f, "1.0.0", host, &[], &me),
        Some(("1.2.0".into(), host))
    );
    // Equal precedence is not newer (build metadata ignored); never a downgrade.
    assert_eq!(pick(&f, "1.2.0", host, &[], &me), None);
    assert_eq!(pick(&f, "1.2.0+local", host, &[], &me), None);
    assert_eq!(pick(&f, "2.0.0", host, &[], &me), None);
    // A pre-release of 1.2.0 is older than 1.2.0.
    assert_eq!(
        pick(&f, "1.2.0-rc.1", host, &[], &me),
        Some(("1.2.0".into(), host))
    );
    // Bad versions are skipped (by precedence) and the next newer one is taken.
    assert_eq!(
        pick(&f, "1.0.0", host, &["1.2.0"], &me),
        Some(("1.1.0".into(), host))
    );
    assert_eq!(pick(&f, "1.0.0", host, &["1.2.0+x", "1.1.0"], &me), None);
    // No release for this host.
    assert_eq!(pick(&f, "1.0.0", Target::WindowsX86_64, &[], &me), None);
}

#[test]
fn host_target_then_first_listed_fallback() {
    let fx = ChainFixture::fake();
    let f = feed(
        &fx,
        vec![
            fx.release(
                "2.0.0",
                &[(Target::WindowsX86_64, M), (Target::MacosUniversal, M)],
                None,
            ),
            fx.release(
                "1.5.0",
                &[(Target::WindowsAarch64, M), (Target::MacosAarch64, M)],
                None,
            ),
        ],
    );
    let me = id(1);
    assert_eq!(
        pick(&f, "1.0.0", Target::WindowsAarch64, &[], &me),
        Some(("2.0.0".into(), Target::WindowsX86_64))
    );
    assert_eq!(
        pick(&f, "1.0.0", Target::MacosAarch64, &[], &me),
        Some(("2.0.0".into(), Target::MacosUniversal))
    );
    assert_eq!(
        pick(&f, "1.0.0", Target::MacosX86_64, &[], &me),
        Some(("2.0.0".into(), Target::MacosUniversal))
    );
    // The host's own id beats a fallback in the same release.
    assert_eq!(
        pick(&f, "1.0.0", Target::WindowsAarch64, &["2.0.0"], &me),
        Some(("1.5.0".into(), Target::WindowsAarch64))
    );
    // x86_64 has no fallback to aarch64.
    assert_eq!(
        pick(&f, "1.0.0", Target::WindowsX86_64, &["2.0.0"], &me),
        None
    );
    assert_eq!(pick(&f, "1.0.0", Target::LinuxX86_64, &[], &me), None);
}

#[test]
fn pre_release_only_because_the_feed_lists_it() {
    let fx = ChainFixture::fake();
    let f = feed(
        &fx,
        vec![
            fx.release("2.0.0-beta.2", &[(Target::LinuxX86_64, M)], None),
            fx.release("1.5.0", &[(Target::LinuxX86_64, M)], None),
        ],
    );
    let host = Target::LinuxX86_64;
    let me = id(1);
    assert_eq!(
        pick(&f, "1.0.0", host, &[], &me),
        Some(("2.0.0-beta.2".into(), host))
    );
    assert_eq!(pick(&f, "2.0.0-beta.2", host, &[], &me), None);
    assert_eq!(
        pick(&f, "2.0.0-beta.1", host, &[], &me),
        Some(("2.0.0-beta.2".into(), host))
    );
    assert_eq!(pick(&f, "2.0.0", host, &[], &me), None);
}

#[test]
fn rollout_at_0_1_and_10000_basis_points() {
    let fx = ChainFixture::fake();
    let host = Target::LinuxX86_64;
    // Fixed install ids with known buckets under the testkit hasher.
    let in_zero = (0..1_000_000u32)
        .map(id)
        .find(|i| rollout_bucket(i, &SEED, &FakeHasher) == 0)
        .expect("an install id in bucket 0");
    let in_other = id(1);
    assert_ne!(rollout_bucket(&in_other, &SEED, &FakeHasher), 0);

    for (bp, zero_in, other_in) in [(0, false, false), (1, true, false), (10_000, true, true)] {
        let f = feed(
            &fx,
            vec![
                fx.release("2.0.0", &[(host, M)], Some((bp, SEED))),
                fx.release("1.5.0", &[(host, M)], None),
            ],
        );
        let expect = |inside: bool| Some((if inside { "2.0.0" } else { "1.5.0" }.to_owned(), host));
        assert_eq!(
            pick(&f, "1.0.0", host, &[], &in_zero),
            expect(zero_in),
            "bp {bp}"
        );
        assert_eq!(
            pick(&f, "1.0.0", host, &[], &in_other),
            expect(other_in),
            "bp {bp}"
        );
        let rollout = f.releases()[0].rollout();
        assert_eq!(in_rollout(rollout, &in_zero, &FakeHasher), zero_in);
    }
    // Absent rollout: everyone.
    assert!(in_rollout(None, &in_other, &FakeHasher));
    // An install exactly at the threshold bucket is outside (`bucket < basis_points`).
    let b = rollout_bucket(&in_other, &SEED, &FakeHasher);
    let f = feed(
        &fx,
        vec![fx.release("2.0.0", &[(host, M)], Some((u64::from(b), SEED)))],
    );
    assert_eq!(pick(&f, "1.0.0", host, &[], &in_other), None);
    let f = feed(
        &fx,
        vec![fx.release("2.0.0", &[(host, M)], Some((u64::from(b) + 1, SEED)))],
    );
    assert_eq!(
        pick(&f, "1.0.0", host, &[], &in_other),
        Some(("2.0.0".into(), host))
    );
}

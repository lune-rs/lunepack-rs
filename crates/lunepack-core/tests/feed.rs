//! Step 10: feed verification with the testkit fakes; documents come from the testkit builders over
//! the core's writer.

use lunepack_core::{
    AppId, Channel, ClockReading, Error, FeedDocument, PayloadKind, RollbackFloor, Target,
    VerifiedFeed, VerifiedKeySet, verify_feed,
};
use lunepack_testkit::{ChainFixture, FakeClock, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0};

const DAY: u64 = 86_400;
const M1: &[u8] = b"manifest one";
const M2: &[u8] = b"manifest two";

fn at(now: u64, floor_time: Option<u64>) -> ClockReading {
    ClockReading::read(&FakeClock::new(now), floor_time)
}

fn app() -> AppId {
    AppId::parse(SUITE_APP_ID).unwrap()
}

fn channel() -> Channel {
    Channel::parse(SUITE_CHANNEL).unwrap()
}

fn simple(fx: &ChainFixture<'_>, seq: u64, expires: Option<u64>) -> FeedDocument {
    fx.feed_document(
        seq,
        expires,
        vec![
            fx.release("1.0.0", &[(Target::LinuxX86_64, M1)], None),
            fx.release(
                "1.1.0",
                &[(Target::LinuxX86_64, M2), (Target::MacosUniversal, M1)],
                Some((2500, [7; 32])),
            ),
        ],
    )
}

fn verify(
    fx: &ChainFixture<'_>,
    keys: &VerifiedKeySet,
    doc: &FeedDocument,
    seeds: &[u8],
    floor: &RollbackFloor,
    clock: ClockReading,
) -> Result<VerifiedFeed, Error> {
    let bytes = fx.envelope(PayloadKind::Feed, &doc.to_payload(), seeds);
    verify_feed(keys, &bytes, &app(), &channel(), floor, &clock, fx.verifier)
}

#[test]
fn a_valid_feed_verifies() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5, 6], 1);
    let feed = verify(
        &fx,
        &keys,
        &simple(&fx, 3, Some(SUITE_T0 + 90 * DAY)),
        &[5],
        &RollbackFloor::default(),
        at(SUITE_T0, None),
    )
    .unwrap();
    assert_eq!(feed.seq(), 3);
    assert_eq!(feed.channel().as_str(), SUITE_CHANNEL);
    assert_eq!(feed.releases().len(), 2);
    assert!(feed.time_checked());
    let r = &feed.releases()[1];
    assert_eq!(r.version_text(), "1.1.0");
    assert_eq!(r.rollout().unwrap().basis_points, 2500);
    let entry = feed.target_entry(1, Target::MacosUniversal).unwrap();
    assert_eq!(
        entry.reference().path(),
        "1.1.0/macos-universal.manifest.json"
    );
    assert_eq!(entry.reference().size(), M1.len() as u64);
    assert!(feed.target_entry(0, Target::MacosUniversal).is_none());
    assert!(feed.target_entry(9, Target::LinuxX86_64).is_none());
}

#[test]
fn tampered_feed_byte_fails_the_signature() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let payload = simple(&fx, 3, None).to_payload();
    let ty = PayloadKind::Feed.payload_type();
    let sig = fx.signature(5, ty, &payload);
    for index in [0, payload.len() / 2, payload.len() - 1] {
        let mut tampered = payload.clone();
        tampered[index] ^= 0x01;
        let bytes = lunepack_core::write_envelope(ty, &tampered, &[sig]);
        let res = verify_feed(
            &keys,
            &bytes,
            &app(),
            &channel(),
            &RollbackFloor::default(),
            &at(SUITE_T0, None),
            fx.verifier,
        );
        assert!(matches!(res, Err(Error::Threshold { .. })), "{res:?}");
    }
}

#[test]
fn feed_must_be_signed_by_release_keys_at_the_release_threshold() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5, 6], 2);
    let doc = simple(&fx, 1, None);
    let floor = RollbackFloor::default();
    for seeds in [&[5][..], &[5, 5], &[0], &[0, 5]] {
        assert!(matches!(
            verify(&fx, &keys, &doc, seeds, &floor, at(SUITE_T0, None)),
            Err(Error::Threshold { need: 2, .. })
        ));
    }
    verify(&fx, &keys, &doc, &[6, 5], &floor, at(SUITE_T0, None)).unwrap();
}

#[test]
fn seq_rollback_is_rejected_and_equal_is_allowed() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let doc = simple(&fx, 7, None);
    let now = at(SUITE_T0, None);
    let floor = RollbackFloor::default().with_feed_seq(channel(), 8);
    assert!(matches!(
        verify(&fx, &keys, &doc, &[5], &floor, now),
        Err(Error::Rollback {
            floor: 8,
            found: 7,
            ..
        })
    ));
    let floor = RollbackFloor::default().with_feed_seq(channel(), 7);
    let feed = verify(&fx, &keys, &doc, &[5], &floor, now).unwrap();
    // Another channel's floor does not apply.
    let other = RollbackFloor::default().with_feed_seq(Channel::parse("beta").unwrap(), 100);
    verify(&fx, &keys, &doc, &[5], &other, now).unwrap();
    // RollbackFloor::raise: raises this channel, keeps others, never lowers.
    let raised = other.raise(&keys, &feed);
    assert_eq!(raised.feed_seq(&channel()), 7);
    assert_eq!(raised.feed_seq(&Channel::parse("beta").unwrap()), 100);
    assert_eq!((raised.root_version(), raised.keyset_version()), (1, 1));
    let high = RollbackFloor::new(5, 5).with_feed_seq(channel(), 9);
    let kept = high.raise(&keys, &feed);
    assert_eq!(kept, high);
}

#[test]
fn wrong_app_or_channel_is_rejected() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let now = at(SUITE_T0, None);
    let floor = RollbackFloor::default();
    let mut doc = simple(&fx, 1, None);
    doc.app_id = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        verify(&fx, &keys, &doc, &[5], &floor, now),
        Err(Error::AppIdMismatch)
    ));
    let bytes = fx.envelope(PayloadKind::Feed, &simple(&fx, 1, None).to_payload(), &[5]);
    let other_app = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        verify_feed(
            &keys,
            &bytes,
            &other_app,
            &channel(),
            &floor,
            &now,
            fx.verifier
        ),
        Err(Error::AppIdMismatch)
    ));
    let beta = Channel::parse("beta").unwrap();
    assert!(matches!(
        verify_feed(&keys, &bytes, &app(), &beta, &floor, &now, fx.verifier),
        Err(Error::ChannelMismatch)
    ));
    let mut doc = simple(&fx, 1, None);
    doc.channel = beta;
    assert!(matches!(
        verify(&fx, &keys, &doc, &[5], &floor, now),
        Err(Error::ChannelMismatch)
    ));
}

#[test]
fn expired_feed_at_400_days_and_2100() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let floor = RollbackFloor::default();
    let doc = simple(&fx, 1, Some(SUITE_T0 + 30 * DAY));
    let check = |clock| verify(&fx, &keys, &doc, &[5], &floor, clock);

    // The shifted time comes from the fake clock the code reads.
    let clock = FakeClock::new(SUITE_T0);
    clock.advance_400_days();
    let plus_400 = lunepack_core::Clock::now_unix_secs(&clock);
    assert!(matches!(
        check(at(plus_400, None)),
        Err(Error::Expired { what: "feed", .. })
    ));
    assert!(matches!(
        check(at(plus_400, Some(SUITE_T0))),
        Err(Error::Expired { .. })
    ));
    let skipped = check(at(plus_400, Some(plus_400 + 1))).unwrap();
    assert!(!skipped.time_checked());
    assert!(matches!(
        check(at(SUITE_T0 + 30 * DAY, None)),
        Err(Error::Expired { .. })
    ));
    check(at(SUITE_T0 + 30 * DAY - 1, None)).unwrap();

    // Year 2100: the release keys' windows have ended too, so a plausible clock fails on them.
    clock.set_year_2100();
    let y2100 = lunepack_core::Clock::now_unix_secs(&clock);
    assert!(matches!(
        check(at(y2100, None)),
        Err(Error::Threshold { .. })
    ));
    assert!(matches!(
        check(at(y2100, Some(SUITE_T0))),
        Err(Error::Threshold { .. })
    ));
    let skipped = check(at(y2100, Some(y2100 + 1))).unwrap();
    assert!(!skipped.time_checked());
    // Without `expires` and inside the windows, a later clock is fine.
    verify(
        &fx,
        &keys,
        &simple(&fx, 1, None),
        &[5],
        &floor,
        at(plus_400, None),
    )
    .unwrap();
}

#[test]
fn signing_key_outside_its_window_does_not_count() {
    let fx = ChainFixture::fake();
    // Release keys are valid from SUITE_T0 - 1 day for 1000 days.
    let (_, keys) = fx.verified_chain(&[5], 1);
    let doc = simple(&fx, 1, None);
    let floor = RollbackFloor::default();
    let before = SUITE_T0 - 2 * DAY;
    let after = SUITE_T0 + 1000 * DAY;
    for now in [before, after] {
        assert!(matches!(
            verify(&fx, &keys, &doc, &[5], &floor, at(now, None)),
            Err(Error::Threshold { need: 1, got: 0 })
        ));
    }
    verify(&fx, &keys, &doc, &[5], &floor, at(after - 1, None)).unwrap();
    verify(&fx, &keys, &doc, &[5], &floor, at(SUITE_T0 - DAY, None)).unwrap();
    // Implausible clock (earlier than the installed manifest's issued): windows skipped, reported.
    let feed = verify(&fx, &keys, &doc, &[5], &floor, at(before, Some(SUITE_T0))).unwrap();
    assert!(!feed.time_checked());
}

#[test]
fn revoked_key_absent_from_a_newer_key_set_cannot_sign() {
    let fx = ChainFixture::fake();
    let root = fx.trusted_root(1, 1, &[0]);
    let clock = at(SUITE_T0, None);
    let key_set = |version, seeds: &[u8]| {
        let ks = fx.keyset_document(1, version, None, 1, seeds);
        let bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        lunepack_core::verify_key_set(
            &root,
            &bytes,
            &RollbackFloor::default(),
            &clock,
            fx.hasher,
            fx.verifier,
        )
        .unwrap()
    };
    let v1 = key_set(1, &[5, 6]);
    let v2 = key_set(2, &[5]);
    let doc = simple(&fx, 1, None);
    let floor = RollbackFloor::default();
    verify(&fx, &v1, &doc, &[6], &floor, clock).unwrap();
    assert!(matches!(
        verify(&fx, &v2, &doc, &[6], &floor, clock),
        Err(Error::Threshold { .. })
    ));
    verify(&fx, &v2, &doc, &[5], &floor, clock).unwrap();
    // Once v2 was seen, v1 is a rollback.
    let ks1 = fx.keyset_document(1, 1, None, 1, &[5, 6]);
    let bytes = fx.envelope(PayloadKind::Keys, &ks1.to_payload(), &[0]);
    assert!(matches!(
        lunepack_core::verify_key_set(
            &root,
            &bytes,
            &RollbackFloor::default().raised_by(&v2),
            &clock,
            fx.hasher,
            fx.verifier
        ),
        Err(Error::Rollback { .. })
    ));
}

#[test]
fn duplicate_precedence_releases_are_rejected() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let floor = RollbackFloor::default();
    for (a, b) in [
        ("1.0.0+a", "1.0.0+b"),
        ("1.0.0", "1.0.0+build"),
        ("2.0.0-rc.1", "2.0.0-rc.1+x"),
    ] {
        let doc = fx.feed_document(
            1,
            None,
            vec![
                fx.release(a, &[(Target::LinuxX86_64, M1)], None),
                fx.release("0.1.0", &[(Target::LinuxX86_64, M1)], None),
                fx.release(b, &[(Target::LinuxX86_64, M2)], None),
            ],
        );
        assert!(
            matches!(
                verify(&fx, &keys, &doc, &[5], &floor, at(SUITE_T0, None)),
                Err(Error::DuplicateRelease)
            ),
            "{a} / {b}"
        );
    }
    // Distinct precedence is fine, including pre-releases.
    let doc = fx.feed_document(
        1,
        None,
        vec![
            fx.release("1.0.0-alpha", &[(Target::LinuxX86_64, M1)], None),
            fx.release("1.0.0", &[(Target::LinuxX86_64, M1)], None),
        ],
    );
    verify(&fx, &keys, &doc, &[5], &floor, at(SUITE_T0, None)).unwrap();
}

#[test]
fn release_and_reference_rules() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let floor = RollbackFloor::default();
    let now = at(SUITE_T0, None);
    let with = |edit: &dyn Fn(&mut FeedDocument)| {
        let mut doc = simple(&fx, 1, None);
        edit(&mut doc);
        verify(&fx, &keys, &doc, &[5], &floor, now)
    };
    // References: path rules plus ASCII [A-Za-z0-9._+-].
    for (path, path_rule) in [
        ("https://example.org/m.json", true),
        ("../m.json", true),
        ("/abs/m.json", true),
        ("a//b", true),
        ("a\\b", true),
        ("a%20b/m.json", false),
        ("m.json?x=1", true),
        ("m.json#f", false),
        ("dir/ünï.json", false),
        ("a b.json", false),
    ] {
        let res = with(&|d| {
            let r = d.releases[0].targets.get_mut("linux-x86_64").unwrap();
            r.path = path.to_owned();
        });
        if path_rule {
            assert!(matches!(res, Err(Error::Path(_))), "{path}: {res:?}");
        } else {
            assert!(matches!(res, Err(Error::ReferenceChar)), "{path}: {res:?}");
        }
    }
    let ok = with(&|d| {
        let r = d.releases[0].targets.get_mut("linux-x86_64").unwrap();
        r.path = "1.0.0+b/Linux_x86-64.manifest.json".to_owned();
    });
    ok.unwrap();
    // Targets.
    let res = with(&|d| {
        let r = d.releases[0].targets.remove("linux-x86_64").unwrap();
        d.releases[0].targets.insert("linux-x86".to_owned(), r);
    });
    assert!(matches!(res, Err(Error::Target(_))));
    let res = with(&|d| d.releases[0].targets.clear());
    assert!(matches!(res, Err(Error::Field(_))));
    // Version text.
    let res = with(&|d| d.releases[0].version = "v1.0.0".to_owned());
    assert!(matches!(res, Err(Error::Version(_))));
    // Rollout range.
    let res = with(&|d| {
        d.releases[1].rollout.as_mut().unwrap().basis_points = 10_001u64.try_into().unwrap()
    });
    assert!(matches!(res, Err(Error::Field(_))));
    with(&|d| d.releases[1].rollout.as_mut().unwrap().basis_points = 10_000u64.try_into().unwrap())
        .unwrap();
    // expires must be after issued.
    let res = with(&|d| d.expires = Some(d.issued));
    assert!(matches!(res, Err(Error::Field(_))));
}

#[test]
fn null_values_are_rejected() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let text = String::from_utf8(simple(&fx, 1, Some(SUITE_T0 + DAY)).to_payload()).unwrap();
    for (from, to) in [
        (
            format!("\"expires\":{}", SUITE_T0 + DAY),
            "\"expires\":null".to_owned(),
        ),
        (
            "\"rollout\":{".to_owned(),
            "\"rollout\":null,\"x\":{".to_owned(),
        ),
    ] {
        let nulled = text.replacen(&from, &to, 1);
        assert_ne!(nulled, text);
        let bytes = fx.envelope(PayloadKind::Feed, nulled.as_bytes(), &[5]);
        let res = verify_feed(
            &keys,
            &bytes,
            &app(),
            &channel(),
            &RollbackFloor::default(),
            &at(SUITE_T0, None),
            fx.verifier,
        );
        assert!(matches!(res, Err(Error::Schema(_))), "{to}: {res:?}");
    }
}

#[test]
fn at_most_10000_releases() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let release = |i: usize| {
        fx.release(
            &format!("0.{}.{}", i / 100, i % 100),
            &[(Target::LinuxX86_64, M1)],
            None,
        )
    };
    let floor = RollbackFloor::default();
    let doc = fx.feed_document(1, None, (0..10_000).map(release).collect());
    verify(&fx, &keys, &doc, &[5], &floor, at(SUITE_T0, None)).unwrap();
    let doc = fx.feed_document(1, None, (0..10_001).map(release).collect());
    assert!(matches!(
        verify(&fx, &keys, &doc, &[5], &floor, at(SUITE_T0, None)),
        Err(Error::TooMany {
            what: "releases",
            count: 10_001,
            max: 10_000
        })
    ));
}

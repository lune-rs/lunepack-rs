//! Step 10: manifest verification with the testkit fakes, end to end from a verified feed to
//! decoded files.

use lunepack_core::digest::U53;
use lunepack_core::error::FrameError;
use lunepack_core::path::RelPath;
use lunepack_core::{
    AppId, Channel, ClockReading, CodecId, EntryDoc, Error, FeedTargetEntry, ManifestDocument,
    PayloadKind, RollbackFloor, Target, VerifiedEntry, VerifiedKeySet, VerifiedManifest,
    decode_verified, verify_feed, verify_manifest,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, PackBuilder, SUITE_APP_ID, SUITE_CHANNEL,
    SUITE_T0,
};

const VERSION: &str = "1.2.0";

fn data(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

fn pack(fx: &ChainFixture<'_>) -> PackBuilder {
    let mut p = PackBuilder::new();
    p.file(fx.hasher, "bin/app", &data(3000, 1), CodecId::BcjX86Lzma2)
        .file(fx.hasher, "lib/x.so.1", &data(2000, 2), CodecId::Bcj2)
        .file(fx.hasher, "share/README", &data(500, 3), CodecId::Stored)
        .file(fx.hasher, "share/empty", b"", CodecId::Stored)
        .file(fx.hasher, "data/blob", &data(700, 4), CodecId::Lzma2)
        .dir("share/doc")
        .symlink("lib/x.so", "x.so.1");
    p
}

/// A verified feed listing `manifest` bytes for `target` (and the release's `version`), then the
/// entry the manifest is checked against.
fn entry_for(
    fx: &ChainFixture<'_>,
    keys: &VerifiedKeySet,
    version: &str,
    target: Target,
    manifest: &[u8],
) -> FeedTargetEntry {
    let doc = fx.feed_document(
        1,
        None,
        vec![fx.release(version, &[(target, manifest)], None)],
    );
    let bytes = fx.envelope(PayloadKind::Feed, &doc.to_payload(), &[5]);
    let feed = verify_feed(
        keys,
        &bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(SUITE_T0), None),
        fx.verifier,
    )
    .unwrap();
    feed.target_entry(0, target).unwrap()
}

/// Signs `doc` with release key 5 and verifies it through a feed that references those bytes.
fn verify_doc(
    fx: &ChainFixture<'_>,
    keys: &VerifiedKeySet,
    doc: &ManifestDocument,
) -> Result<VerifiedManifest, Error> {
    let bytes = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[5]);
    let entry = entry_for(fx, keys, VERSION, Target::LinuxX86_64, &bytes);
    verify_manifest(keys, &entry, &bytes, fx.hasher, fx.verifier)
}

fn base(fx: &ChainFixture<'_>, p: &PackBuilder) -> ManifestDocument {
    fx.manifest_document(VERSION, Target::LinuxX86_64, p)
}

#[test]
fn verified_manifest_decodes_every_file() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let p = pack(&fx);
    let m = verify_doc(&fx, &keys, &base(&fx, &p)).unwrap();
    assert_eq!(m.version().to_string(), VERSION);
    assert_eq!(m.target(), Target::LinuxX86_64);
    assert_eq!(m.issued(), SUITE_T0);
    assert_eq!(m.entries().len(), 7);
    assert_eq!(m.pack().size(), p.bytes.len() as u64);
    let mut decoded = 0;
    for e in m.entries() {
        if let VerifiedEntry::File {
            frame: Some(frame), ..
        } = e
        {
            let start = frame.offset() as usize;
            let bytes = &p.bytes[start..start + frame.length() as usize];
            let mut out = Vec::new();
            decode_verified(frame, bytes, &FakeHasher, &FakeCodec::new(), &mut out).unwrap();
            assert_eq!(out.len() as u64, frame.file_size());
            decoded += 1;
        }
    }
    assert_eq!(decoded, 4);
}

#[test]
fn manifest_bytes_are_checked_against_the_feed_before_opening() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let bytes = fx.envelope(
        PayloadKind::Manifest,
        &base(&fx, &pack(&fx)).to_payload(),
        &[5],
    );
    let entry = entry_for(&fx, &keys, VERSION, Target::LinuxX86_64, &bytes);
    // Tampered byte, same length: hash mismatch (the envelope is never opened).
    let mut tampered = bytes.clone();
    let i = tampered.len() / 2;
    tampered[i] ^= 0x01;
    assert!(matches!(
        verify_manifest(&keys, &entry, &tampered, fx.hasher, fx.verifier),
        Err(Error::ArtifactHash)
    ));
    // Garbage of another length: a size error, not a JSON error.
    assert!(matches!(
        verify_manifest(&keys, &entry, b"not json", fx.hasher, fx.verifier),
        Err(Error::ArtifactSize { .. })
    ));
    let mut longer = bytes.clone();
    longer.push(b' ');
    assert!(matches!(
        verify_manifest(&keys, &entry, &longer, fx.hasher, fx.verifier),
        Err(Error::ArtifactSize { .. })
    ));
    verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier).unwrap();
}

#[test]
fn manifest_must_be_signed_by_release_keys() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    for seeds in [&[0][..], &[6]] {
        let bytes = fx.envelope(
            PayloadKind::Manifest,
            &base(&fx, &pack(&fx)).to_payload(),
            seeds,
        );
        let entry = entry_for(&fx, &keys, VERSION, Target::LinuxX86_64, &bytes);
        assert!(matches!(
            verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier),
            Err(Error::Threshold { .. })
        ));
    }
}

#[test]
fn version_target_and_app_must_match_the_feed() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let p = pack(&fx);
    // Precedence-equal but not byte-equal, and a different version.
    for v in ["1.2.0+build", "1.2.1", "1.2.0-rc.1"] {
        let doc = fx.manifest_document(v, Target::LinuxX86_64, &p);
        assert!(
            matches!(verify_doc(&fx, &keys, &doc), Err(Error::VersionMismatch)),
            "{v}"
        );
    }
    let mut doc = base(&fx, &p);
    doc.version = "1.2".to_owned();
    assert!(matches!(
        verify_doc(&fx, &keys, &doc),
        Err(Error::Version(_))
    ));
    // Target.
    let doc = fx.manifest_document(VERSION, Target::LinuxAarch64, &p);
    assert!(matches!(
        verify_doc(&fx, &keys, &doc),
        Err(Error::TargetMismatch {
            expected: "linux-x86_64",
            found: "linux-aarch64"
        })
    ));
    let mut doc = base(&fx, &p);
    doc.target = "Linux-x86_64".to_owned();
    assert!(matches!(
        verify_doc(&fx, &keys, &doc),
        Err(Error::Target(_))
    ));
    // App id.
    let mut doc = base(&fx, &p);
    doc.app_id = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        verify_doc(&fx, &keys, &doc),
        Err(Error::AppIdMismatch)
    ));
}

#[test]
fn entry_rules() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let p = pack(&fx);
    let with = |edit: &dyn Fn(&mut ManifestDocument)| {
        let mut doc = base(&fx, &p);
        edit(&mut doc);
        verify_doc(&fx, &keys, &doc)
    };
    let field = |r: Result<VerifiedManifest, Error>| matches!(r, Err(Error::Field(_)));
    // 0 bin/app, 1 lib/x.so.1, 2 share/README, 3 share/empty, 4 data/blob, 5 dir, 6 symlink.
    assert!(field(with(&|d| d.entries[0].exec = None)));
    assert!(field(with(&|d| d.entries[0].size = None)));
    assert!(field(with(&|d| d.entries[0].sha256 = None)));
    assert!(field(with(&|d| d.entries[0].target = Some("x".into()))));
    assert!(field(with(
        &|d| d.entries[5].size = Some(U53::new(1).unwrap())
    )));
    assert!(field(with(&|d| d.entries[5].exec = Some(true))));
    assert!(field(with(&|d| d.entries[6].exec = Some(false))));
    assert!(field(with(&|d| d.entries[6].target = None)));
    assert!(field(with(&|d| d.entries[5].kind = "Dir".into())));
    assert!(field(with(&|d| d.entries[5].kind = "fifo".into())));
    // Empty file: sha256 of nothing, no frame.
    assert!(field(with(&|d| d.entries[3].sha256 = Some(fake_sha(b"x")))));
    let r = with(&|d| d.entries[3].frame = d.entries[2].frame.clone());
    assert!(
        matches!(r, Err(Error::Frame(FrameError::Presence))),
        "{r:?}"
    );
    let r = with(&|d| d.entries[0].frame = None);
    assert!(
        matches!(r, Err(Error::Frame(FrameError::Presence))),
        "{r:?}"
    );
    // Frames are checked against pack.size.
    let r = with(&|d| d.pack.size = U53::new(d.pack.size.get() - 1).unwrap());
    assert!(
        matches!(r, Err(Error::Frame(FrameError::OutOfPack))),
        "{r:?}"
    );
    let r = with(&|d| d.entries[4].frame.as_mut().unwrap().codec = "LZMA2".into());
    assert!(matches!(r, Err(Error::UnknownCodec(_))), "{r:?}");
    let r = with(&|d| {
        d.entries[4].frame.as_mut().unwrap().dict_size = Some(U53::new(1 << 25).unwrap())
    });
    assert!(
        matches!(r, Err(Error::Frame(FrameError::DictSize { .. }))),
        "{r:?}"
    );
    // Pack reference path.
    let r = with(&|d| d.pack.path = "../x.pack".into());
    assert!(matches!(r, Err(Error::Path(_))), "{r:?}");
    // Tree rules.
    let r = with(&|d| {
        let mut e = d.entries[0].clone();
        e.path = RelPath::parse("BIN/APP").unwrap();
        d.entries.push(e);
    });
    assert!(matches!(r, Err(Error::Tree(_))), "{r:?}");
    let r = with(&|d| d.entries[6].target = Some("../../x".into()));
    assert!(matches!(r, Err(Error::Tree(_))), "{r:?}");
}

fn fake_sha(bytes: &[u8]) -> lunepack_core::Sha256Digest {
    use lunepack_core::Hasher;
    FakeHasher.sha256(bytes)
}

#[test]
fn symlinks_are_rejected_on_windows_targets() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let p = pack(&fx);
    let doc = fx.manifest_document(VERSION, Target::WindowsX86_64, &p);
    let bytes = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[5]);
    let entry = entry_for(&fx, &keys, VERSION, Target::WindowsX86_64, &bytes);
    assert!(matches!(
        verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier),
        Err(Error::Tree(_))
    ));
}

#[test]
fn reserved_fields_and_nulls_are_rejected() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let text = String::from_utf8(base(&fx, &pack(&fx)).to_payload()).unwrap();
    for (from, to) in [
        ("\"issued\"", "\"install\":{},\"issued\""),
        ("\"issued\"", "\"deltas\":[],\"issued\""),
        ("\"issued\"", "\"install\":null,\"issued\""),
        ("\"exec\":false", "\"exec\":null"),
    ] {
        let edited = text.replacen(from, to, 1);
        assert_ne!(edited, text);
        let bytes = fx.envelope(PayloadKind::Manifest, edited.as_bytes(), &[5]);
        let entry = entry_for(&fx, &keys, VERSION, Target::LinuxX86_64, &bytes);
        let r = verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier);
        assert!(
            matches!(r, Err(Error::Field(_)) | Err(Error::Schema(_))),
            "{to}: {r:?}"
        );
    }
    // An unknown plain field is ignored.
    let edited = text.replacen("\"issued\"", "\"note\":\"x\",\"issued\"", 1);
    let bytes = fx.envelope(PayloadKind::Manifest, edited.as_bytes(), &[5]);
    let entry = entry_for(&fx, &keys, VERSION, Target::LinuxX86_64, &bytes);
    verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier).unwrap();
}

#[test]
fn at_most_200000_entries() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let mut doc = base(&fx, &PackBuilder::new());
    let dir = |i: usize| EntryDoc {
        path: RelPath::parse(&format!("d{i}")).unwrap(),
        kind: "dir".to_owned(),
        size: None,
        sha256: None,
        exec: None,
        frame: None,
        target: None,
    };
    doc.entries = (0..200_001).map(dir).collect();
    let r = verify_doc(&fx, &keys, &doc);
    assert!(
        matches!(
            r,
            Err(Error::TooMany {
                what: "entries",
                count: 200_001,
                max: 200_000
            })
        ),
        "{r:?}"
    );
    doc.entries.pop();
    verify_doc(&fx, &keys, &doc).unwrap();
}

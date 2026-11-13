//! Step 8: envelope, root rotation and key-set verification with the testkit fakes. The same
//! suite runs with real Ed25519 and SHA-256 in `lunepack-crypto/tests/chain_keys.rs`.

use lunepack_core::error::Error;
use lunepack_core::limits::Limits;
use lunepack_core::{ClockReading, OpenedEnvelope, PayloadKind, TrustedRoot, write_envelope};
use lunepack_testkit::{ChainFixture, FakeClock, TRUST_CHAIN_CASES, run_trust_chain_suite};

#[test]
fn trust_chain_suite_with_fakes() {
    assert!(TRUST_CHAIN_CASES.len() >= 20);
    run_trust_chain_suite(&ChainFixture::fake());
}

#[test]
fn authenticate_returns_the_exact_signed_payload() {
    let fx = ChainFixture::fake();
    let root: TrustedRoot = fx.trusted_root(1, 1, &[0]);
    let payload = b"{\"any\":\"bytes\"}";
    let bytes = fx.envelope(PayloadKind::Feed, payload, &[0]);
    let opened = OpenedEnvelope::open(&bytes, PayloadKind::Feed, &Limits::V1).unwrap();
    assert_eq!(opened.kind(), PayloadKind::Feed);
    assert_eq!(
        opened.authenticate(root.keys(), 1, fx.verifier).unwrap(),
        payload
    );
    // A threshold of 0 never passes, even with a valid signature.
    assert!(matches!(
        opened.authenticate(root.keys(), 0, fx.verifier),
        Err(Error::Threshold { need: 0, got: 1 })
    ));
    // Debug output never shows the payload.
    assert!(!format!("{opened:?}").contains("bytes"));
}

#[test]
fn open_without_keys_checks_only_the_envelope() {
    let ty = PayloadKind::Manifest.payload_type();
    let bytes = write_envelope(ty, b"", &[]);
    assert!(matches!(
        OpenedEnvelope::open(&bytes, PayloadKind::Manifest, &Limits::V1),
        Err(Error::SignatureCount { count: 0, .. })
    ));
}

#[test]
fn clock_is_plausible_at_or_after_the_floor() {
    let clock = FakeClock::new(1000);
    assert!(ClockReading::read(&clock, None).is_plausible());
    assert!(ClockReading::read(&clock, Some(1000)).is_plausible());
    assert!(ClockReading::read(&clock, Some(999)).is_plausible());
    let r = ClockReading::read(&clock, Some(1001));
    assert!(!r.is_plausible());
    assert_eq!(r.now(), 1000);
}

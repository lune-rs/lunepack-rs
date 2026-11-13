//! The trust-chain suite (envelope, root walk, key set) with real Ed25519 and SHA-256, plus the
//! cases only real crypto can show. Keys are generated at test time; none is committed.

use ed25519_dalek::{Signer, SigningKey};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use lunepack_core::{
    AppId, ClockReading, EnvelopeSignature, Error, PayloadKind, RollbackFloor, TrustedRoot,
    verify_key_set, write_envelope,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::{ChainFixture, FakeClock, SUITE_T0, run_trust_chain_suite};

/// One fresh signing key per seed `0..=7`.
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

/// The identity point (small order).
fn small_order_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
}

/// `y = p + 1`, a non-canonical encoding.
fn non_canonical_key() -> [u8; 32] {
    let mut k = [0xffu8; 32];
    k[0] = 0xee;
    k[31] = 0x7f;
    k
}

#[test]
fn trust_chain_suite_with_real_crypto() {
    let keys = Keys::new();
    let sign = |seed: u8, message: &[u8]| keys.sign(seed, message);
    for invalid_key in [small_order_key(), non_canonical_key()] {
        run_trust_chain_suite(&ChainFixture {
            hasher: &Sha256Hasher,
            verifier: &Ed25519Verifier,
            sign: &sign,
            invalid_key,
        });
    }
}

#[test]
fn key_ids_are_real_sha256_of_the_public_key() {
    // RFC 8032 section 7.1 TEST 1 public key; its SHA-256 computed independently with
    // `shasum -a 256` over the 32 raw bytes.
    let pk: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let root = TrustedRoot::from_parts(
        AppId::parse("org.example.hello").unwrap(),
        1,
        1,
        &[pk],
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .unwrap();
    assert_eq!(
        root.keys().keys()[0].id().to_hex(),
        "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
    );
}

#[test]
fn malleated_signature_does_not_count() {
    // Group order L, little endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let keys = Keys::new();
    let sign = |seed: u8, message: &[u8]| keys.sign(seed, message);
    let fx = ChainFixture {
        hasher: &Sha256Hasher,
        verifier: &Ed25519Verifier,
        sign: &sign,
        invalid_key: small_order_key(),
    };
    let root = fx.trusted_root(1, 1, &[0]);
    let ty = PayloadKind::Keys.payload_type();
    let payload = fx.keyset_document(1, 1, None, 1, &[5]).to_payload();
    let good = fx.signature(0, ty, &payload);
    let mut mall = good;
    let mut carry = 0u16;
    for (i, l) in L.iter().enumerate() {
        let sum = u16::from(good.sig[32 + i]) + u16::from(*l) + carry;
        mall.sig[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    let clock = ClockReading::read(&FakeClock::new(SUITE_T0), None);
    let check = |sigs: &[EnvelopeSignature]| {
        verify_key_set(
            &root,
            &write_envelope(ty, &payload, sigs),
            &RollbackFloor::default(),
            &clock,
            &Sha256Hasher,
            &Ed25519Verifier,
        )
    };
    assert!(matches!(
        check(&[mall]),
        Err(Error::Threshold { need: 1, got: 0 })
    ));
    check(&[mall, good]).expect("the canonical signature still counts");
}

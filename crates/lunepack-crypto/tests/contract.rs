//! Contract suites from the testkit run against the real adapters, plus the strictness cases that
//! only a real Ed25519 implementation can show. All keys are generated at test time; the RFC 8032
//! vectors are verify-only (public key, message, signature).

use ed25519_dalek::{Signer, SigningKey};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use lunepack_core::error::SignatureError;
use lunepack_core::{Error, Hasher, SignatureAlg, Verifier};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::{SHA256_KATS, VerifyKat, run_hasher_suite, run_verifier_suite};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rfc8032_kats() -> Vec<VerifyKat> {
    let triples: [(&str, &str, &str); 3] = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    triples
        .iter()
        .map(|(pk, msg, sig)| VerifyKat {
            public_key: hex(pk).try_into().unwrap(),
            message: hex(msg),
            signature: hex(sig).try_into().unwrap(),
        })
        .collect()
}

/// A test signing key per seed, generated fresh from the OS (the seed only distinguishes keys
/// inside one fixture; the `sign` closure keeps one key per seed for the whole run).
struct Keys(Vec<(u8, SigningKey)>);

impl Keys {
    fn new() -> Self {
        let mut rng = UnwrapErr(SysRng);
        Keys(
            (0..=3u8)
                .map(|seed| (seed, SigningKey::generate(&mut rng)))
                .collect(),
        )
    }
    fn sign(&self, seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
        let key = &self.0.iter().find(|(s, _)| *s == seed).unwrap().1;
        (key.verifying_key().to_bytes(), key.sign(message).to_bytes())
    }
}

#[test]
fn sha256_hasher_passes_suite_with_real_kats() {
    run_hasher_suite(&Sha256Hasher, SHA256_KATS);
}

#[test]
fn sha256_of_a_million_a() {
    let mut state = Sha256Hasher.sha256_start();
    for _ in 0..1000 {
        state.update(&[b'a'; 1000]);
    }
    assert_eq!(
        state.finalize().to_hex(),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn ed25519_passes_suite_with_real_keys_and_rfc8032_vectors() {
    let keys = Keys::new();
    run_verifier_suite(
        &Ed25519Verifier,
        &|seed, msg| keys.sign(seed, msg),
        &rfc8032_kats(),
        &invalid_keys(),
    );
}

/// The identity point (small order) and `y = p + 1` (a non-canonical encoding of it).
fn invalid_keys() -> [[u8; 32]; 2] {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut non_canonical = [0xffu8; 32];
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;
    [identity, non_canonical]
}

#[test]
fn rfc8032_vector_with_changed_message_is_rejected() {
    let kat = &rfc8032_kats()[1];
    let err = Ed25519Verifier
        .verify(SignatureAlg::Ed25519, &kat.public_key, b"s", &kat.signature)
        .unwrap_err();
    assert!(matches!(err, Error::Signature(SignatureError::Mismatch)));
}

#[test]
fn small_order_public_keys_are_rejected() {
    // The identity point (y = 1) and the order-2 point (y = -1), with signatures that would verify
    // under a non-strict check for the identity key (R = identity, S = 0).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut order2 = [0xffu8; 32];
    order2[0] = 0xec;
    order2[31] = 0x7f;
    let mut sig = [0u8; 64];
    sig[0] = 1; // R = identity, S = 0
    for key in [identity, order2] {
        for message in [&b""[..], b"anything"] {
            let err = Ed25519Verifier
                .verify(SignatureAlg::Ed25519, &key, message, &sig)
                .unwrap_err();
            assert!(
                matches!(err, Error::Signature(SignatureError::InvalidPublicKey)),
                "{err}"
            );
        }
        assert!(Ed25519Verifier::check_public_key(&key).is_err());
    }
}

#[test]
fn non_canonical_public_key_encoding_is_rejected() {
    // y = p + 1 (p = 2^255 - 19) is a non-canonical encoding of the identity point.
    let mut key = [0xffu8; 32];
    key[0] = 0xee;
    key[31] = 0x7f;
    let err = Ed25519Verifier
        .verify(SignatureAlg::Ed25519, &key, b"m", &[0u8; 64])
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Signature(SignatureError::InvalidPublicKey)
    ));
    // Non-canonical encodings of points that are NOT small-order: y = p + small, for the few y
    // below 19 that are curve points of large order. Their canonical encodings are accepted, so
    // only the canonical-encoding check can be what rejects the p + y form.
    let mut found = 0;
    for y in 0..19u8 {
        let mut canonical = [0u8; 32];
        canonical[0] = y;
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xed + y; // 2^255 - 19 + y, little endian
        non_canonical[31] = 0x7f;
        if Ed25519Verifier::check_public_key(&canonical).is_ok() {
            found += 1;
            let err = Ed25519Verifier::check_public_key(&non_canonical).unwrap_err();
            assert!(
                matches!(err, Error::Signature(SignatureError::InvalidPublicKey)),
                "y = {y}: {err}"
            );
        }
    }
    assert!(found > 0, "no large-order point with y < 19 was found");
}

#[test]
fn valid_keys_pass_check_public_key() {
    let keys = Keys::new();
    for seed in 0..=3 {
        let (pk, _) = keys.sign(seed, b"");
        Ed25519Verifier::check_public_key(&pk).unwrap();
    }
}

#[test]
fn non_canonical_s_is_rejected() {
    // Group order L, little endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let keys = Keys::new();
    let message = b"malleability";
    let (pk, sig) = keys.sign(1, message);
    Ed25519Verifier
        .verify(SignatureAlg::Ed25519, &pk, message, &sig)
        .unwrap();

    // S' = S + L is the same scalar mod L: a lax verifier accepts it, a strict one must not.
    let mut mall = sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(sig[32 + i]) + u16::from(L[i]) + carry;
        mall[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 32 bytes");
    assert_ne!(mall, sig);
    let err = Ed25519Verifier
        .verify(SignatureAlg::Ed25519, &pk, message, &mall)
        .unwrap_err();
    assert!(matches!(err, Error::Signature(SignatureError::Mismatch)));
}

#[test]
fn hasher_and_verifier_are_object_safe_and_shareable() {
    fn assert_traits<T: Send + Sync + ?Sized>() {}
    assert_traits::<dyn Hasher>();
    assert_traits::<dyn Verifier>();
    let _h: Box<dyn Hasher> = Box::new(Sha256Hasher);
    let _v: Box<dyn Verifier> = Box::new(Ed25519Verifier);
}

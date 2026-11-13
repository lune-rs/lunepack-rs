//! Contract suites: one function per trait, run by every adapter's `tests/` against its real
//! implementation and by this crate against the fakes. They panic (assert) on a violation.

use lunepack_core::{Clock, Hasher, Sha256Digest, SignatureAlg, Verifier};

/// A hash known answer: the input and its digest in lowercase hex.
#[derive(Debug, Clone, Copy)]
pub struct HashKat {
    /// The message.
    pub input: &'static [u8],
    /// Its digest, 64 lowercase hex characters.
    pub digest_hex: &'static str,
}

/// SHA-256 known answers (FIPS 180-4 examples). Pass these to [`run_hasher_suite`] for a real
/// SHA-256 implementation; a fake passes its own.
pub const SHA256_KATS: &[HashKat] = &[
    HashKat {
        input: b"",
        digest_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    HashKat {
        input: b"abc",
        digest_hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    HashKat {
        input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        digest_hex: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
];

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect()
}

/// Hasher contract: every known answer in `kats` matches; a streaming computation split at every
/// boundary of a 1 KiB input equals the one-shot digest; the one-shot digest is stable and depends
/// on the input.
pub fn run_hasher_suite(hasher: &dyn Hasher, kats: &[HashKat]) {
    for kat in kats {
        let want = Sha256Digest::from_hex(kat.digest_hex).expect("kat digest is valid hex");
        assert_eq!(
            hasher.sha256(kat.input),
            want,
            "one-shot KAT {:?}",
            kat.input
        );
        let mut state = hasher.sha256_start();
        state.update(kat.input);
        assert_eq!(state.finalize(), want, "streaming KAT {:?}", kat.input);
    }

    let data = pattern(1024);
    let whole = hasher.sha256(&data);
    assert_eq!(whole, hasher.sha256(&data), "one-shot is deterministic");
    for split in 0..=data.len() {
        let mut state = hasher.sha256_start();
        state.update(&data[..split]);
        state.update(&data[split..]);
        assert_eq!(state.finalize(), whole, "streaming split at {split}");
    }
    let mut state = hasher.sha256_start();
    for byte in &data {
        state.update(std::slice::from_ref(byte));
    }
    assert_eq!(state.finalize(), whole, "byte-at-a-time streaming");

    let mut changed = data.clone();
    changed[512] ^= 1;
    assert_ne!(
        hasher.sha256(&changed),
        whole,
        "a flipped input bit changes the digest"
    );
    assert_ne!(
        hasher.sha256(&data[..1023]),
        whole,
        "a shorter input changes the digest"
    );
    // An empty update must not change the result.
    let mut state = hasher.sha256_start();
    state.update(&[]);
    state.update(&data);
    state.update(&[]);
    assert_eq!(state.finalize(), whole, "empty updates are no-ops");
}

/// A verify-only known answer (for example an RFC 8032 vector): it must be accepted.
#[derive(Debug, Clone)]
pub struct VerifyKat {
    /// The public key.
    pub public_key: [u8; 32],
    /// The message.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: [u8; 64],
}

/// Makes a key pair from a seed and signs: `(seed, message) -> (public_key, signature)`.
pub type SignFixture<'a> = dyn Fn(u8, &[u8]) -> ([u8; 32], [u8; 64]) + 'a;

/// Verifier contract. `sign(seed, message)` returns `(public_key, signature)` for the key pair the
/// adapter's fixture derives from `seed`; different seeds must give different keys. Checks that a
/// valid signature is accepted, that a flipped message bit, signature bit or key bit, a signature
/// made under another key, and an empty-for-non-empty message swap are rejected, and that every
/// entry of `kats` is accepted. Key validation (FORMAT.md 2.5): every fixture key and KAT key
/// passes `check_public_key`; every entry of `invalid_keys` (the adapter supplies at least a
/// small-order and a non-canonical key) fails `check_public_key` and fails `verify` even with a
/// signature the fixture made.
///
/// A signature of the wrong length is not testable here: the trait takes `&[u8; 64]`, so a wrong
/// length cannot be expressed; the types enforce it.
pub fn run_verifier_suite(
    verifier: &dyn Verifier,
    sign: &SignFixture<'_>,
    kats: &[VerifyKat],
    invalid_keys: &[[u8; 32]],
) {
    let alg = SignatureAlg::Ed25519;
    let messages: [Vec<u8>; 3] = [Vec::new(), b"lunepack".to_vec(), pattern(1024)];
    for message in &messages {
        let (pk, sig) = sign(1, message);
        verifier
            .verify(alg, &pk, message, &sig)
            .expect("a valid signature is accepted");

        if !message.is_empty() {
            let mut bad = message.clone();
            bad[message.len() / 2] ^= 0x01;
            assert!(
                verifier.verify(alg, &pk, &bad, &sig).is_err(),
                "flipped message bit accepted"
            );
            assert!(
                verifier.verify(alg, &pk, &[], &sig).is_err(),
                "signature accepted for an empty message"
            );
        }
        for index in [0usize, 31, 32, 63] {
            let mut bad = sig;
            bad[index] ^= 0x80;
            assert!(
                verifier.verify(alg, &pk, message, &bad).is_err(),
                "flipped signature bit {index} accepted"
            );
        }
        for index in [0usize, 31] {
            let mut bad = pk;
            bad[index] ^= 0x01;
            assert!(
                verifier.verify(alg, &bad, message, &sig).is_err(),
                "flipped key bit {index} accepted"
            );
        }
        let (other_pk, other_sig) = sign(2, message);
        assert_ne!(pk, other_pk, "fixture must give different keys per seed");
        assert!(
            verifier.verify(alg, &other_pk, message, &sig).is_err(),
            "signature accepted under another key"
        );
        assert!(
            verifier.verify(alg, &pk, message, &other_sig).is_err(),
            "another key's signature accepted"
        );
    }

    for (i, kat) in kats.iter().enumerate() {
        verifier
            .verify(alg, &kat.public_key, &kat.message, &kat.signature)
            .unwrap_or_else(|e| panic!("known answer {i} rejected: {e}"));
        verifier
            .check_public_key(alg, &kat.public_key)
            .unwrap_or_else(|e| panic!("known answer {i} key rejected: {e}"));
    }

    assert!(
        invalid_keys.len() >= 2,
        "supply at least a small-order and a non-canonical key"
    );
    for seed in 1..=2u8 {
        let (pk, _) = sign(seed, b"");
        verifier
            .check_public_key(alg, &pk)
            .unwrap_or_else(|e| panic!("fixture key {seed} rejected: {e}"));
    }
    let (_, sig) = sign(1, b"lunepack");
    for (i, key) in invalid_keys.iter().enumerate() {
        assert!(
            verifier.check_public_key(alg, key).is_err(),
            "invalid key {i} passed check_public_key"
        );
        assert!(
            verifier.verify(alg, key, b"lunepack", &sig).is_err(),
            "invalid key {i} accepted by verify"
        );
    }
}

/// Clock contract: readings never go backwards within a test. With `shifted`, a factory for a
/// clock set to the given Unix seconds, also checks that far-future times (2100-01-01 and 400 days
/// past it) are read back without a panic and without going backwards. A real clock cannot be
/// moved, so its adapter passes `None`.
pub fn run_clock_suite(clock: &dyn Clock, shifted: Option<&dyn Fn(u64) -> Box<dyn Clock>>) {
    let mut last = clock.now_unix_secs();
    for _ in 0..100 {
        let now = clock.now_unix_secs();
        assert!(now >= last, "clock went backwards: {last} then {now}");
        last = now;
    }
    if let Some(make) = shifted {
        for secs in [
            crate::YEAR_2100_UNIX_SECS,
            crate::YEAR_2100_UNIX_SECS + 400 * 86_400,
        ] {
            let far = make(secs);
            let first = far.now_unix_secs();
            assert!(first >= secs, "shifted clock reads {first}, set to {secs}");
            assert!(far.now_unix_secs() >= first, "shifted clock went backwards");
        }
    }
}

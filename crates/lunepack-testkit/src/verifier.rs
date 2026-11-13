//! A fake signature scheme: a keyed fake hash, with no accept-everything mode.

use lunepack_core::error::SignatureError;
use lunepack_core::{Error, Hasher, SignatureAlg, Verifier};

use crate::hasher::FakeHasher;

fn keyed(public_key: &[u8; 32], half: u8, message: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(33 + message.len());
    input.extend_from_slice(public_key);
    input.push(half);
    input.extend_from_slice(message);
    *FakeHasher.sha256(&input).as_bytes()
}

fn fake_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&keyed(public_key, 0, message));
    sig[32..].copy_from_slice(&keyed(public_key, 1, message));
    sig
}

/// A fake key pair. The "public key" is a fake hash of the seed; a signature is the keyed fake hash
/// of the message under the public key (64 bytes). Not secure; test-only.
#[derive(Debug, Clone)]
pub struct FakeKeyPair {
    public_key: [u8; 32],
}

impl FakeKeyPair {
    /// A key pair derived from `seed`; different seeds give different keys.
    pub fn from_seed(seed: u8) -> Self {
        let mut input = b"lunepack-testkit fake key".to_vec();
        input.push(seed);
        FakeKeyPair {
            public_key: *FakeHasher.sha256(&input).as_bytes(),
        }
    }

    /// The public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Signs `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        fake_signature(&self.public_key, message)
    }
}

/// Keys [`FakeVerifier`] treats as invalid, standing in for a small-order point (all zero) and a
/// non-canonical encoding (all `0xff`). `FakeKeyPair` never yields them for the seeds tests use.
pub const FAKE_INVALID_KEYS: [[u8; 32]; 2] = [[0x00; 32], [0xff; 32]];

/// Verifies signatures made by [`FakeKeyPair`]; anything else is a mismatch. Keys in
/// [`FAKE_INVALID_KEYS`] fail both `check_public_key` and `verify`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeVerifier;

impl Verifier for FakeVerifier {
    fn verify(
        &self,
        alg: SignatureAlg,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        match alg {
            SignatureAlg::Ed25519 => {}
            #[allow(unreachable_patterns)]
            _ => return Err(SignatureError::UnsupportedAlgorithm.into()),
        }
        self.check_public_key(alg, public_key)?;
        // Both halves are always compared so a mismatch does not depend on where it is.
        let expected = fake_signature(public_key, message);
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(signature.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(SignatureError::Mismatch.into())
        }
    }

    fn check_public_key(&self, alg: SignatureAlg, public_key: &[u8; 32]) -> Result<(), Error> {
        match alg {
            SignatureAlg::Ed25519 => {}
            #[allow(unreachable_patterns)]
            _ => return Err(SignatureError::UnsupportedAlgorithm.into()),
        }
        if FAKE_INVALID_KEYS.contains(public_key) {
            Err(SignatureError::InvalidPublicKey.into())
        } else {
            Ok(())
        }
    }
}

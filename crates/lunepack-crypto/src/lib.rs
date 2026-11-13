//! Hashing, signature-verification and signing adapters implementing the core traits:
//! [`Sha256Hasher`] (SHA-256), [`Ed25519Verifier`] (Ed25519 with strict verification) and the
//! signers of [`signer`] ([`Ed25519Signer`] over a PKCS#8 PEM key, [`CommandSigner`] over an
//! external command, [`generate_key_file`]). Pure Rust.

pub mod signer;

pub use signer::{CommandSigner, Ed25519Signer, GeneratedKey, generate_key_file};

use ed25519_dalek::{Signature, VerifyingKey};
use lunepack_core::error::SignatureError;
use lunepack_core::{Error, HashState, Hasher, Sha256Digest, SignatureAlg, Verifier};
use sha2::Digest;

/// SHA-256, backed by the `sha2` crate.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

struct Sha256State(sha2::Sha256);

impl HashState for Sha256State {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Sha256Digest {
        Sha256Digest::from_bytes(self.0.finalize().into())
    }
}

impl Hasher for Sha256Hasher {
    fn sha256_start(&self) -> Box<dyn HashState> {
        Box::new(Sha256State(sha2::Sha256::new()))
    }
}

/// Ed25519 verification with `verify_strict` semantics (FORMAT.md 2.5): the public key must be a
/// canonical encoding and not small-order, the signature's `S` must be reduced, and small-order
/// `R` is rejected.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Checks that `public_key` is a canonical, non-small-order Ed25519 point encoding and returns
    /// the decoded key.
    fn decode_key(public_key: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        let key =
            VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::InvalidPublicKey)?;
        // Decoding accepts (and reduces) a non-canonical y coordinate, and `to_bytes` returns the
        // input unchanged, so the point is re-encoded from its coordinates to compare.
        if key.to_edwards().compress().to_bytes() != *public_key || key.is_weak() {
            return Err(SignatureError::InvalidPublicKey);
        }
        Ok(key)
    }

    /// `Ok(())` when `public_key` is a canonical, non-small-order Ed25519 key.
    pub fn check_public_key(public_key: &[u8; 32]) -> Result<(), Error> {
        Self::decode_key(public_key)
            .map(|_| ())
            .map_err(Error::from)
    }
}

impl Verifier for Ed25519Verifier {
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
        let key = Self::decode_key(public_key)?;
        let signature = Signature::from_bytes(signature);
        key.verify_strict(message, &signature)
            .map_err(|_| SignatureError::Mismatch)?;
        Ok(())
    }

    fn check_public_key(&self, alg: SignatureAlg, public_key: &[u8; 32]) -> Result<(), Error> {
        match alg {
            SignatureAlg::Ed25519 => Ed25519Verifier::check_public_key(public_key),
            #[allow(unreachable_patterns)]
            _ => Err(SignatureError::UnsupportedAlgorithm.into()),
        }
    }
}

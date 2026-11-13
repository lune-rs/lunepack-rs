//! A fake signer over [`FakeKeyPair`], for tests of code that signs.

use std::fmt;

use lunepack_core::{Error, SignatureAlg, Signer};

use crate::verifier::FakeKeyPair;

/// Signs with a [`FakeKeyPair`]; verify with [`crate::FakeVerifier`]. Not secure; test-only.
///
/// Its `Debug` prints the public key only, never the seed the key derives from.
#[derive(Clone)]
pub struct FakeSigner {
    pair: FakeKeyPair,
    seed: u8,
}

impl FakeSigner {
    /// A signer for the key pair [`FakeKeyPair::from_seed`] derives from `seed`.
    pub fn new(seed: u8) -> Self {
        FakeSigner {
            pair: FakeKeyPair::from_seed(seed),
            seed,
        }
    }

    /// The bytes the fake key derives from, for the signer suite's secret-leak check (a real
    /// signer's equivalent is its private key).
    pub fn secret(&self) -> Vec<u8> {
        let mut secret = b"lunepack-testkit fake key".to_vec();
        secret.push(self.seed);
        secret
    }
}

impl fmt::Debug for FakeSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSigner")
            .field("public_key", &self.pair.public_key())
            .finish_non_exhaustive()
    }
}

impl Signer for FakeSigner {
    fn alg(&self) -> SignatureAlg {
        SignatureAlg::Ed25519
    }

    fn public_key(&self) -> [u8; 32] {
        self.pair.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        Ok(self.pair.sign(message))
    }
}

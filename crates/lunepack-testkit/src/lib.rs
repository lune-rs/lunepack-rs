//! In-memory fakes and contract suites for the core traits (test support only, never published).
//!
//! Every fake here is deterministic and offers no accept-everything mode. The hasher and the
//! signature scheme are deliberately not SHA-256 and not Ed25519, so no core test can pass by
//! assuming the real algorithm. Contract suites (the `run_*_suite` functions) are what each
//! adapter's `tests/` runs against its real implementation.

mod clock;
mod codec;
mod docs;
mod hasher;
mod suites;
mod verifier;

pub use clock::{FakeClock, YEAR_2100_UNIX_SECS};
pub use codec::{FakeCodec, FakeEncoded, FakeStreamLayout, Fault};
pub use docs::{
    ChainFixture, SUITE_APP_ID, SUITE_T0, TRUST_CHAIN_CASES, fake_sign, run_trust_chain_suite,
};
pub use hasher::FakeHasher;
pub use suites::{
    HashKat, SHA256_KATS, SignFixture, VerifyKat, run_clock_suite, run_hasher_suite,
    run_verifier_suite,
};
pub use verifier::{FAKE_INVALID_KEYS, FakeKeyPair, FakeVerifier};

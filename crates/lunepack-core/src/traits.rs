//! The four traits behind everything external the verification code needs (hard rule 3):
//! hashing, signature verification, the clock and frame decoding. Core code never reaches for a
//! digest, a signature algorithm, the time or a decoder any other way. Each trait is object-safe
//! and `Send + Sync`; implementations live in adapter crates, fakes in `lunepack-testkit`.

use std::io::Write;

use crate::digest::Sha256Digest;
use crate::error::{Error, Result};

/// A streaming SHA-256 computation, created by [`Hasher::sha256_start`].
pub trait HashState: Send {
    /// Feeds more bytes.
    fn update(&mut self, data: &[u8]);
    /// Ends the computation.
    fn finalize(self: Box<Self>) -> Sha256Digest;
}

/// SHA-256, one-shot and streaming.
pub trait Hasher: Send + Sync {
    /// Starts a streaming computation.
    fn sha256_start(&self) -> Box<dyn HashState>;

    /// SHA-256 of `data` in one call.
    fn sha256(&self, data: &[u8]) -> Sha256Digest {
        let mut state = self.sha256_start();
        state.update(data);
        state.finalize()
    }
}

/// Signature algorithms of format v1 (FORMAT.md 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlg {
    /// Ed25519 (RFC 8032), strict verification.
    Ed25519,
}

impl SignatureAlg {
    /// The id written in key lists.
    pub const fn id(self) -> &'static str {
        match self {
            SignatureAlg::Ed25519 => "ed25519",
        }
    }

    /// Parses an algorithm id; compared byte for byte, any other value is rejected.
    pub fn from_id(id: &str) -> Option<SignatureAlg> {
        match id {
            "ed25519" => Some(SignatureAlg::Ed25519),
            _ => None,
        }
    }
}

/// Signature verification.
pub trait Verifier: Send + Sync {
    /// Verifies `signature` over `message` with `public_key`. Strict semantics: a signature that
    /// is not canonical or a key that is small-order must fail. `Ok(())` only for a valid one.
    fn verify(
        &self,
        alg: SignatureAlg,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Error>;

    /// `Ok(())` when `public_key` is a valid key for `alg`: for Ed25519 a canonical point
    /// encoding that is not small-order (FORMAT.md 2.5). Readers call it on every key of a key
    /// list before the list is trusted.
    fn check_public_key(&self, alg: SignatureAlg, public_key: &[u8; 32]) -> Result<(), Error>;
}

/// The reader's clock; the only source of `now` (FORMAT.md 11.3).
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch (UTC).
    fn now_unix_secs(&self) -> u64;
}

/// Codec ids of format v1 (FORMAT.md 9.0); the set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecId {
    /// The file's bytes unchanged.
    Stored,
    /// One raw LZMA2 stream.
    Lzma2,
    /// x86 BCJ filter then one raw LZMA2 stream.
    BcjX86Lzma2,
    /// ARM64 BCJ filter then one raw LZMA2 stream.
    BcjArm64Lzma2,
    /// BCJ2: four sub-streams.
    Bcj2,
}

impl CodecId {
    /// The id written in manifests.
    pub const fn id(self) -> &'static str {
        match self {
            CodecId::Stored => "stored",
            CodecId::Lzma2 => "lzma2",
            CodecId::BcjX86Lzma2 => "bcj-x86+lzma2",
            CodecId::BcjArm64Lzma2 => "bcj-arm64+lzma2",
            CodecId::Bcj2 => "bcj2",
        }
    }

    /// Parses a codec id, byte for byte; an unknown id (another case included) is `None`.
    pub fn from_id(id: &str) -> Option<CodecId> {
        match id {
            "stored" => Some(CodecId::Stored),
            "lzma2" => Some(CodecId::Lzma2),
            "bcj-x86+lzma2" => Some(CodecId::BcjX86Lzma2),
            "bcj-arm64+lzma2" => Some(CodecId::BcjArm64Lzma2),
            "bcj2" => Some(CodecId::Bcj2),
            _ => None,
        }
    }
}

/// One encoded stream of a frame, already checked against its signed descriptor.
#[derive(Debug, Clone, Copy)]
pub struct StreamView<'a> {
    /// The stream's encoded bytes.
    pub input: &'a [u8],
    /// Exact number of bytes this stream decodes to.
    pub decoded_size: u64,
    /// LZMA2 dictionary bytes the decoder may use, at most; `None` for a stored stream.
    pub dict_size: Option<u32>,
}

/// A frame whose hash and descriptor were verified, ready to decode.
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    /// The codec.
    pub codec: CodecId,
    /// Exact size of the decoded file.
    pub output_size: u64,
    /// The frame's streams in order (one, or four for BCJ2).
    pub streams: &'a [StreamView<'a>],
}

/// What a decoder consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeReport {
    /// Input bytes consumed, one entry per stream, in stream order.
    pub consumed: Vec<u64>,
}

/// Frame decoding. The caller wraps `out` in an exact-size, hashing writer; the decoder must stop
/// on the first write error and must not allocate beyond each stream's `dict_size`.
pub trait Codec: Send + Sync {
    /// Decodes `frame` into `out` and reports the bytes consumed per stream.
    fn decode(&self, frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error>;
}

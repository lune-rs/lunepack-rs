//! The traits behind everything external the core needs (hard rule 3): hashing, signature
//! verification, the clock and frame decoding on the reading side; frame encoding, signing and the
//! code-signing hook on the producing side. Core code never reaches for a digest, a signature
//! algorithm, the time, a codec or a private key any other way. Each trait is object-safe and
//! `Send + Sync`; implementations live in adapter crates, fakes in `lunepack-testkit`.

use std::io::Write;

use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::path::RelPath;

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

/// Frame decoding. The caller wraps `out` in an exact-size, hashing writer.
///
/// A decoder must:
/// - produce exactly `output_size` bytes;
/// - make each stream decode to exactly its `decoded_size`, BCJ2's sub-streams included (core
///   sees only the total, so it cannot check them; a stream that decodes to another size is
///   [`CodecError::StreamSize`](crate::error::CodecError::StreamSize) even when the total fits);
/// - report the input it really consumed, per stream;
/// - allocate no more than each stream's `dict_size` (plus a fixed overhead);
/// - stop on the first write error.
pub trait Codec: Send + Sync {
    /// Decodes `frame` into `out` and reports the bytes consumed per stream.
    fn decode(&self, frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error>;
}

/// One encoded stream of an [`EncodedFrame`] (BCJ2 only): what the manifest's `streams` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedStream {
    /// Encoded bytes of the stream, at least 1.
    pub length: u64,
    /// Bytes the stream decodes to.
    pub decoded_size: u64,
    /// LZMA2 dictionary of MAIN, CALL and JUMP; `None` for RC.
    pub dict_size: Option<u32>,
}

/// The result of encoding one file: the frame's bytes and the descriptor fields the encoder alone
/// knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// The codec the frame was encoded with.
    pub codec: CodecId,
    /// The frame's bytes (all streams back to back for BCJ2).
    pub bytes: Vec<u8>,
    /// The LZMA2 dictionary, for the LZMA2 variants; `None` for `stored` and `bcj2`.
    pub dict_size: Option<u32>,
    /// The four sub-streams, for `bcj2` only; `None` otherwise.
    pub streams: Option<Vec<EncodedStream>>,
}

/// Frame encoding for one file. The output is deterministic: the same codec and input give the
/// same bytes, whatever the host or the thread count.
pub trait Encoder: Send + Sync {
    /// Encodes `input` (at least one byte) with `codec`. An id the encoder does not implement is an
    /// error.
    fn encode(&self, codec: CodecId, input: &[u8]) -> Result<EncodedFrame, Error>;

    /// An upper bound, in bytes, on the memory one [`Encoder::encode`] call of `codec` over
    /// `input_len` bytes needs, excluding `input` itself.
    fn encode_memory(&self, codec: CodecId, input_len: u64) -> u64;
}

/// An Ed25519 signer. The private key never leaves the implementation.
///
/// Signatures are deterministic (Ed25519, RFC 8032): signing the same message twice gives the same
/// bytes. `Debug` is a supertrait so a signer can be logged, which is why an implementation's `Debug`
/// must not print secret material.
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// The signature algorithm.
    fn alg(&self) -> SignatureAlg;

    /// The public key.
    fn public_key(&self) -> [u8; 32];

    /// Signs `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error>;
}

/// The code-signing hook (C2 stage 2). It runs on the assembled tree before any file is hashed;
/// `order` lists the paths to sign from inner to outer (a bundle's contents before the bundle).
/// The identity implementation changes nothing.
pub trait CodeSign: Send + Sync {
    /// Signs the items of `order` under `root` in place.
    fn sign_tree(&self, root: &std::path::Path, order: &[RelPath]) -> Result<(), Error>;
}

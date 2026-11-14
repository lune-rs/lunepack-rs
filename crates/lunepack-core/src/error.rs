//! The core error enum: one typed variant per rejection class, causes kept (hard rule 4).
//!
//! Untrusted text (a document's key name, a serde message that echoes input) only ever enters an
//! error through [`Untrusted`], which caps it at 64 characters and escapes control characters.

use std::fmt;

use crate::fetch::RangeError;
use crate::fs::FsError;
use crate::path::{PathError, TreeError};
use crate::target::TargetError;
use crate::traits::CodecId;
use crate::transport::TransportError;
use crate::version::VersionError;

/// Result alias for the core.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A piece of untrusted text made safe to print: control and format characters are escaped and
/// the whole shown text is at most [`Untrusted::MAX_CHARS`] characters.
#[derive(Clone, PartialEq, Eq)]
pub struct Untrusted(String);

impl Untrusted {
    /// Most characters ever shown, ellipsis included.
    pub const MAX_CHARS: usize = 64;

    /// Escapes and truncates `text`.
    pub fn new(text: &str) -> Self {
        let mut out = String::new();
        let mut count = 0usize;
        let mut truncated = false;
        for c in text.chars() {
            let piece = if c.is_control() || is_format_char(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            };
            let n = piece.chars().count();
            if count + n > Self::MAX_CHARS {
                truncated = true;
                break;
            }
            out.push_str(&piece);
            count += n;
        }
        if truncated {
            // Keep the total, ellipsis included, within the cap.
            let keep = Self::MAX_CHARS - 3;
            let cut = out.char_indices().nth(keep).map_or(out.len(), |(i, _)| i);
            out.truncate(cut);
            out.push_str("...");
        }
        Untrusted(out)
    }

    /// The safe text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invisible or direction-changing characters that are not `is_control` but can disguise log text.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

impl fmt::Display for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Why the strict JSON pre-pass (FORMAT.md 3.1) rejected a document.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonError {
    /// The bytes are not UTF-8.
    #[error("not valid UTF-8")]
    InvalidUtf8,
    /// The document starts with a UTF-8 byte-order mark.
    #[error("starts with a byte-order mark")]
    ByteOrderMark,
    /// The top-level value is not an object.
    #[error("top-level value is not an object")]
    NotObject,
    /// An object has two members with the same name (after unescaping).
    #[error("duplicate object key {0}")]
    DuplicateKey(Untrusted),
    /// Nesting deeper than the cap.
    #[error("nesting deeper than {max}")]
    TooDeep {
        /// The cap.
        max: u32,
    },
    /// An escaped surrogate without its pair.
    #[error("lone surrogate escape")]
    LoneSurrogate,
    /// Something follows the top-level value besides whitespace.
    #[error("trailing data after the document")]
    TrailingData,
    /// Any other syntax error.
    #[error("syntax error: {0}")]
    Syntax(Untrusted),
}

/// Why a hex string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HexError {
    /// Wrong number of characters.
    #[error("expected {expected} hex characters, found {actual}")]
    Length {
        /// Required length in characters.
        expected: usize,
        /// Length found.
        actual: usize,
    },
    /// A character outside `[0-9a-f]` (uppercase included).
    #[error("character at offset {offset} is not lowercase hex")]
    InvalidCharacter {
        /// Byte offset of the first bad character.
        offset: usize,
    },
}

/// Why a base64 string was rejected (FORMAT.md 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Base64Error {
    /// A character outside the standard alphabet (URL-safe characters and whitespace included).
    #[error("character at offset {offset} is not in the standard base64 alphabet")]
    InvalidCharacter {
        /// Byte offset of the bad character.
        offset: usize,
    },
    /// The length is impossible for base64.
    #[error("invalid base64 length")]
    InvalidLength,
    /// Padding missing, extra or misplaced.
    #[error("non-canonical padding")]
    InvalidPadding,
    /// Unused trailing bits are not zero.
    #[error("non-zero trailing bits")]
    TrailingBits,
    /// The decoded value would exceed the caller's cap.
    #[error("decoded value would exceed {cap} bytes")]
    TooLong {
        /// The cap in decoded bytes.
        cap: usize,
    },
}

/// Why an integer was rejected (FORMAT.md 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntegerError {
    /// Below zero.
    #[error("negative integer")]
    Negative,
    /// A fraction or exponent form.
    #[error("not an integer")]
    NotAnInteger,
    /// Above 2^53 - 1.
    #[error("integer above {max}")]
    TooLarge {
        /// The largest accepted value.
        max: u64,
    },
}

/// Why a signature check failed (the cause, not a policy decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The algorithm id is not one this reader implements.
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    /// The public key is not a canonical, non-small-order key.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The signature does not verify under the key.
    #[error("signature does not verify")]
    Mismatch,
}

/// Why a codec failed to decode a frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// The codec id is not implemented by this decoder.
    #[error("codec {0:?} is not supported")]
    Unsupported(CodecId),
    /// The encoded bytes are malformed.
    #[error("corrupt frame: {0}")]
    Corrupt(&'static str),
    /// Writing the decoded output failed.
    #[error("writing decoded output failed")]
    Write(#[source] std::io::Error),
    /// The decoder library failed on the frame's bytes; its error is kept as the cause.
    #[error("decoder failed")]
    Decoder(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The encoder library failed; its error is kept as the cause.
    #[error("encoder failed")]
    Encoder(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A stream decoded to a size other than its signed `decoded_size` (the core cannot see
    /// BCJ2's sub-streams, so the codec checks each one).
    #[error("stream {index} decoded to {actual} bytes, the descriptor says {expected}")]
    StreamSize {
        /// Stream index (0 for a single-stream frame).
        index: usize,
        /// The signed `decoded_size`.
        expected: u64,
        /// What the stream really decoded to.
        actual: u64,
    },
}

/// Why a signer failed (no variant ever carries key material).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer's public key is not the key the caller required.
    #[error("the signer's key is not the required key")]
    WrongKey,
    /// The same public key was given to sign twice where one signature per key is required.
    #[error("the same signing key was used twice")]
    DuplicateKey,
    /// The signer could not produce a signature; `reason` is a fixed text, the cause is kept.
    #[error("signing failed: {reason}")]
    Failed {
        /// What failed, as a fixed text (never input bytes, never a secret).
        reason: &'static str,
        /// The underlying error, when there is one.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

/// Why the packager's planning step (`pack_file`, `ReleaseLayout`) failed. No variant carries file
/// content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PackError {
    /// The same entry path was added twice.
    #[error("entry {0} added twice")]
    DuplicatePath(Untrusted),
    /// A caller-supplied piece broke an invariant the planner relies on (a fixed text).
    #[error("pack invariant broken: {0}")]
    Invariant(&'static str),
    /// The stored frame of a file failed its own round trip, so the codec or the hasher is broken.
    #[error("the stored frame failed its round trip")]
    StoredRoundTrip(#[source] Box<Error>),
}

/// Why a frame descriptor or a frame's bytes were rejected (FORMAT.md 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// A non-empty file without a frame, or an empty file with one.
    #[error("frame must be present exactly when the file is not empty")]
    Presence,
    /// A field that belongs to another codec.
    #[error("field {field} does not belong to codec {codec}")]
    ForeignField {
        /// The field.
        field: &'static str,
        /// The codec id.
        codec: &'static str,
    },
    /// A field the codec requires is missing.
    #[error("codec {codec} requires field {field}")]
    MissingField {
        /// The field.
        field: &'static str,
        /// The codec id.
        codec: &'static str,
    },
    /// A dictionary size that is not a power of two in `4096 ..= 16 MiB`.
    #[error("dictionary size {value} is not a power of two from 4096 to 16777216")]
    DictSize {
        /// The declared size.
        value: u64,
    },
    /// A frame or stream length of 0.
    #[error("frame length is 0")]
    ZeroLength,
    /// `offset + length` is past the pack's size (or overflows).
    #[error("frame ends past the pack")]
    OutOfPack,
    /// A `stored` frame whose length or hash differs from its file's.
    #[error("stored frame does not match its file")]
    StoredMismatch,
    /// A `bcj2` frame without exactly four streams.
    #[error("bcj2 needs 4 streams, found {count}")]
    StreamCount {
        /// Streams found.
        count: usize,
    },
    /// A BCJ2 sub-stream breaks a rule of FORMAT.md 9.1.
    #[error("bcj2 stream {index}: {reason}")]
    Stream {
        /// Stream index (0 MAIN, 1 CALL, 2 JUMP, 3 RC).
        index: usize,
        /// The rule broken.
        reason: &'static str,
    },
    /// BCJ2 sub-stream lengths do not sum to the frame length (or overflow).
    #[error("stream lengths do not sum to the frame length")]
    LengthSum,
    /// The frame bytes handed in are not exactly `length` bytes.
    #[error("frame is {actual} bytes, expected {expected}")]
    ByteCount {
        /// The signed length.
        expected: u64,
        /// Bytes received.
        actual: u64,
    },
    /// The frame's SHA-256 differs from the signed one.
    #[error("frame hash does not match")]
    FrameHash,
    /// The decoder tried to write more than the file's size.
    #[error("decoded output exceeds {size} bytes")]
    OutputTooLong {
        /// The file's size.
        size: u64,
    },
    /// The caller's output writer failed; what it holds is not the file.
    #[error("the output writer failed: {kind}")]
    OutputWrite {
        /// The writer's error kind.
        kind: std::io::ErrorKind,
    },
    /// The decoder wrote fewer bytes than the file's size.
    #[error("decoded {actual} of {expected} bytes")]
    OutputTooShort {
        /// The file's size.
        expected: u64,
        /// Bytes written.
        actual: u64,
    },
    /// A stream was not consumed exactly (or the report has the wrong number of entries).
    #[error("stream {index} consumed {consumed} of {length} bytes")]
    Consumed {
        /// Stream index.
        index: usize,
        /// Bytes the decoder reports consumed.
        consumed: u64,
        /// The stream's length.
        length: u64,
    },
    /// The decoded file's SHA-256 differs from the signed one.
    #[error("decoded file hash does not match")]
    FileHash,
}

/// The install-state store refused to load or commit (FORMAT.md 12). Paths are never shown.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// A filesystem operation failed.
    #[error("{0}")]
    Fs(#[from] FsError),
    /// The record file for this seq already exists (another writer got there first).
    #[error("state record {seq} already exists")]
    Conflict {
        /// The seq.
        seq: u64,
    },
    /// A whole record is from a newer format (format byte or `format` above 1, or a `critical`
    /// entry this build does not implement): nothing is read past it and nothing is written.
    #[error("state record is from a newer format")]
    NewerFormat,
    /// A whole record (its checksum matches) fails parsing or a semantic rule; the load stops
    /// rather than fall back to an older record (M4-D23).
    #[error("invalid state record: {0}")]
    Invalid(Untrusted),
    /// A commit's seq is not the next one.
    #[error("state record seq {found} is not the next seq {expected}")]
    Seq {
        /// The next seq.
        expected: u64,
        /// The record's seq.
        found: u64,
    },
    /// The next seq would be above `2^53 - 1`.
    #[error("state record seq space exhausted")]
    SeqExhausted,
    /// A record would be over the size cap.
    #[error("state record is {size} bytes, over the {cap} byte cap")]
    TooLarge {
        /// The framed size.
        size: u64,
        /// The cap.
        cap: u64,
    },
    /// A commit would lower an anti-rollback floor of the loaded record.
    #[error("state commit would lower an anti-rollback floor")]
    FloorLowered,
}

/// Every way the core rejects input or fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A document or field is over its cap.
    #[error("{what} is {size} bytes, over the {cap} byte cap")]
    TooLarge {
        /// What was measured.
        what: &'static str,
        /// Its size.
        size: u64,
        /// The cap.
        cap: u64,
    },
    /// The strict JSON pre-pass rejected the bytes.
    #[error("rejected JSON: {0}")]
    Json(#[from] JsonError),
    /// The JSON is well formed but does not fit the expected shape.
    #[error("malformed document: {0}")]
    Schema(Untrusted),
    /// A hex string was rejected.
    #[error("bad hex: {0}")]
    Hex(#[from] HexError),
    /// A base64 string was rejected.
    #[error("bad base64: {0}")]
    Base64(#[from] Base64Error),
    /// An integer was rejected.
    #[error("bad integer: {0}")]
    Integer(#[from] IntegerError),
    /// A signature check failed.
    #[error("signature: {0}")]
    Signature(#[from] SignatureError),
    /// A codec failed.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// A signer failed or was the wrong signer.
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
    /// Planning a pack or a release layout failed.
    #[error("pack: {0}")]
    Pack(#[from] PackError),
    /// The code-signing hook failed.
    #[error("code signing failed")]
    CodeSign(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The envelope's `payloadType` is not the expected kind's type (FORMAT.md 2.2). The found
    /// type is untrusted and never shown.
    #[error("payload type is not {expected}")]
    PayloadType {
        /// The type the reader expected.
        expected: &'static str,
    },
    /// An envelope carries no signature or more than the cap (FORMAT.md 2.1).
    #[error("{count} signatures, expected 1 to {max}")]
    SignatureCount {
        /// Signatures found.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// An envelope `sig` does not decode to exactly 64 bytes.
    #[error("signature is {len} bytes, expected 64")]
    SignatureLength {
        /// Decoded length.
        len: usize,
    },
    /// An envelope `keyid` is not 64 lowercase hex characters (FORMAT.md 2.5).
    #[error("malformed key id: {0}")]
    KeyIdSyntax(HexError),
    /// Fewer distinct keys verified than the threshold requires.
    #[error("{got} of {need} required distinct keys verified")]
    Threshold {
        /// Distinct verified keys required.
        need: usize,
        /// Distinct verified keys found.
        got: usize,
    },
    /// The payload's `format` is not 1.
    #[error("format {found} is not supported")]
    FormatVersion {
        /// The format found.
        found: u64,
    },
    /// The payload's `kind` does not match its payload type.
    #[error("payload kind is not {expected}")]
    Kind {
        /// The kind expected.
        expected: &'static str,
    },
    /// The payload names a critical feature this reader does not implement (FORMAT.md 3.2).
    #[error("unknown critical feature {0}")]
    UnknownCritical(Untrusted),
    /// A key list entry's `id` is not the SHA-256 of its public key.
    #[error("key id does not match its public key")]
    KeyIdMismatch,
    /// A key list holds the same public key twice.
    #[error("public key listed twice")]
    DuplicatePublicKey,
    /// A key list's size or threshold is out of range (`1 <= threshold <= keys <= max`).
    #[error("threshold {threshold} with {keys} keys is out of range (at most {max} keys)")]
    KeyThreshold {
        /// The threshold.
        threshold: u64,
        /// Keys in the list.
        keys: usize,
        /// The key cap.
        max: usize,
    },
    /// A release key's `not_before` is not before its `not_after`.
    #[error("release key validity window is empty")]
    KeyWindow,
    /// A root document is not the next root version (FORMAT.md 5.2).
    #[error("root version {found} is not the next version {expected}")]
    RootVersion {
        /// The only accepted version.
        expected: u64,
        /// The version found.
        found: u64,
    },
    /// A document's `app_id` differs from the trusted root's. Neither id is shown.
    #[error("app id does not match the trusted root")]
    AppIdMismatch,
    /// A key set names a root version other than the trusted root's (FORMAT.md 6).
    #[error("key set names root version {found}, trusted root is {expected}")]
    KeySetRootVersion {
        /// The trusted root's version.
        expected: u64,
        /// The version named.
        found: u64,
    },
    /// A value is below its anti-rollback floor (FORMAT.md 11.2).
    #[error("{what} {found} is below the floor {floor}")]
    Rollback {
        /// What was compared.
        what: &'static str,
        /// The floor.
        floor: u64,
        /// The value found.
        found: u64,
    },
    /// A codec id outside the closed set of FORMAT.md 9.0 (another case included).
    #[error("unknown codec {0}")]
    UnknownCodec(Untrusted),
    /// A frame descriptor or frame was rejected.
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    /// A path failed the path rules (FORMAT.md 10.1).
    #[error("path: {0}")]
    Path(#[from] PathError),
    /// A manifest's entry set failed the tree rules (FORMAT.md 10.2).
    #[error("tree: {0}")]
    Tree(#[from] TreeError),
    /// A version failed the version rules (FORMAT.md 10.3).
    #[error("version: {0}")]
    Version(#[from] VersionError),
    /// A target id is not one of v1's (FORMAT.md 10.4).
    #[error("target: {0}")]
    Target(#[from] TargetError),
    /// An artifact reference's path uses a character outside `[A-Za-z0-9._+-]` (FORMAT.md 7.1).
    #[error("artifact reference path has a character outside [A-Za-z0-9._+-]")]
    ReferenceChar,
    /// More items than the format's cap.
    #[error("{count} {what}, at most {max}")]
    TooMany {
        /// What was counted.
        what: &'static str,
        /// Items found.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A feed's `channel` differs from the expected one. Neither is shown.
    #[error("channel does not match the expected channel")]
    ChannelMismatch,
    /// A manifest's `target` differs from the feed entry's.
    #[error("target {found} is not the expected {expected}")]
    TargetMismatch {
        /// The feed entry's target.
        expected: &'static str,
        /// The manifest's target.
        found: &'static str,
    },
    /// A manifest's `version` is not byte-equal to the feed entry's.
    #[error("manifest version does not match the feed")]
    VersionMismatch,
    /// Two feed releases with equal precedence (FORMAT.md 7).
    #[error("two releases with equal precedence")]
    DuplicateRelease,
    /// An artifact's length differs from its reference's `size`.
    #[error("artifact is {actual} bytes, the reference says {expected}")]
    ArtifactSize {
        /// The signed size.
        expected: u64,
        /// Bytes received.
        actual: u64,
    },
    /// An artifact's SHA-256 differs from its reference's.
    #[error("artifact hash does not match its reference")]
    ArtifactHash,
    /// A field rule of a feed or manifest (FORMAT.md 7, 8) is broken.
    #[error("invalid field: {0}")]
    Field(&'static str),
    /// A document is expired at the reader's `now` (FORMAT.md 11.3).
    #[error("{what} expired at {expires}, now is {now}")]
    Expired {
        /// What expired.
        what: &'static str,
        /// Its `expires`.
        expires: u64,
        /// The clock's reading.
        now: u64,
    },
    /// A transport failed to produce a response or a body chunk.
    #[error("{0}")]
    Transport(#[from] TransportError),
    /// A response broke the HTTP response rules of the fetch (M4-D9).
    #[error("response refused: {0}")]
    Range(#[from] RangeError),
    /// A filesystem operation failed.
    #[error("{0}")]
    Fs(#[from] FsError),
    /// The operation's cancel token was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// The install-state store failed.
    #[error("install state: {0}")]
    State(#[from] StateError),
}

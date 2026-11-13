//! The core error enum: one typed variant per rejection class, causes kept (hard rule 4).
//!
//! Untrusted text (a document's key name, a serde message that echoes input) only ever enters an
//! error through [`Untrusted`], which caps it at 64 characters and escapes control characters.

use std::fmt;

use crate::traits::CodecId;

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
}

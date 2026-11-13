//! Lowercase hex and canonical base64 (FORMAT.md 2.4, 3.2): one accepted encoding per byte string.

use base64::DecodeError;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

use crate::error::{Base64Error, HexError};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Standard alphabet, padding required exactly when needed, trailing bits must be zero.
const CANONICAL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(false),
);

/// Lowercase hex of `bytes`.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decodes exactly `N` bytes from `2 * N` lowercase hex characters; uppercase is rejected.
pub fn hex_decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * N {
        return Err(HexError::Length {
            expected: 2 * N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(bytes[2 * i]).ok_or(HexError::InvalidCharacter { offset: 2 * i })?;
        let lo =
            nibble(bytes[2 * i + 1]).ok_or(HexError::InvalidCharacter { offset: 2 * i + 1 })?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// Standard base64 with canonical padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    CANONICAL.encode(bytes)
}

/// Decodes canonical base64 into at most `max_decoded` bytes. Rejects URL-safe characters,
/// whitespace, missing or extra padding and non-zero trailing bits. The cap is checked on the
/// text length before any decoding work.
pub fn base64_decode(text: &str, max_decoded: usize) -> Result<Vec<u8>, Base64Error> {
    // 4 characters carry at most 3 bytes; this bound never rejects a value within the cap.
    let max_chars = max_decoded.div_ceil(3).saturating_mul(4);
    if text.len() > max_chars {
        return Err(Base64Error::TooLong { cap: max_decoded });
    }
    let out = CANONICAL.decode(text.as_bytes()).map_err(|e| match e {
        DecodeError::InvalidByte(offset, _) => Base64Error::InvalidCharacter { offset },
        DecodeError::InvalidLength(_) => Base64Error::InvalidLength,
        DecodeError::InvalidLastSymbol(..) => Base64Error::TrailingBits,
        DecodeError::InvalidPadding => Base64Error::InvalidPadding,
    })?;
    if out.len() > max_decoded {
        return Err(Base64Error::TooLong { cap: max_decoded });
    }
    Ok(out)
}

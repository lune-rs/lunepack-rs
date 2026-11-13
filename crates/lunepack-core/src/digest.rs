//! Digest and bounded-integer value types.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

use crate::encoding::{hex_decode_array, hex_encode};
use crate::error::{HexError, IntegerError};
use crate::limits::MAX_JSON_INT;

/// A SHA-256 digest: 32 bytes, written as 64 lowercase hex characters (uppercase is rejected).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Sha256Digest(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses 64 lowercase hex characters.
    pub fn from_hex(text: &str) -> Result<Self, HexError> {
        hex_decode_array::<32>(text).map(Sha256Digest)
    }

    /// 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HexVisitor;
        impl Visitor<'_> for HexVisitor {
            type Value = Sha256Digest;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 lowercase hex characters")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Sha256Digest::from_hex(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(HexVisitor)
    }
}

/// An integer in `0 ..= 2^53 - 1`, the only kind of number a v1 document carries (FORMAT.md 3.1).
/// Deserialising accepts a JSON integer in range and nothing else: a sign, fraction or exponent
/// form (`-1`, `1.0`, `1e3`) and `2^53` are rejected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U53(u64);

impl U53 {
    /// The largest value.
    pub const MAX: U53 = U53(MAX_JSON_INT);

    /// Checks the range.
    pub const fn new(value: u64) -> Result<U53, IntegerError> {
        if value > MAX_JSON_INT {
            Err(IntegerError::TooLarge { max: MAX_JSON_INT })
        } else {
            Ok(U53(value))
        }
    }

    /// The value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for U53 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for U53 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl TryFrom<u64> for U53 {
    type Error = IntegerError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        U53::new(value)
    }
}

impl From<U53> for u64 {
    fn from(value: U53) -> u64 {
        value.0
    }
}

impl Serialize for U53 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for U53 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IntVisitor;
        impl Visitor<'_> for IntVisitor {
            type Value = U53;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer from 0 to 9007199254740991")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<U53, E> {
                U53::new(v).map_err(E::custom)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<U53, E> {
                match u64::try_from(v) {
                    Ok(v) => self.visit_u64(v),
                    Err(_) => Err(E::custom(IntegerError::Negative)),
                }
            }
            fn visit_f64<E: de::Error>(self, _v: f64) -> Result<U53, E> {
                Err(E::custom(IntegerError::NotAnInteger))
            }
        }
        deserializer.deserialize_u64(IntVisitor)
    }
}

//! App ids (FORMAT.md 10.6) and channel ids (FORMAT.md 10.5).

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

use crate::path::is_device_name;

/// Longest app id in bytes.
pub const MAX_APP_ID_BYTES: usize = 64;
/// Longest channel id in bytes.
pub const MAX_CHANNEL_BYTES: usize = 32;

/// Why an app id or channel id was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentError {
    /// Empty.
    #[error("empty id")]
    Empty,
    /// Over the cap.
    #[error("id is {len} bytes, over the {max} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// A byte outside the allowed set (or a first byte outside `[a-z0-9]`).
    #[error("byte at offset {offset} is not allowed")]
    InvalidByte {
        /// Byte offset.
        offset: usize,
    },
    /// An app id containing `..`.
    #[error("id contains `..`")]
    DotDot,
    /// An app id ending with `.`.
    #[error("id ends with `.`")]
    TrailingDot,
    /// An app id that is a Windows device name.
    #[error("id is a Windows device name")]
    DeviceName,
}

/// An app id: 1–64 bytes, `[a-z0-9]` first, then `[a-z0-9._-]`; no `..`, no trailing `.`, not a
/// Windows device name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppId(String);

impl AppId {
    /// Validates `text`.
    pub fn parse(text: &str) -> Result<Self, IdentError> {
        check_charset(text, MAX_APP_ID_BYTES, |b| matches!(b, b'.' | b'_' | b'-'))?;
        if text.contains("..") {
            return Err(IdentError::DotDot);
        }
        if text.ends_with('.') {
            return Err(IdentError::TrailingDot);
        }
        if is_device_name(text) {
            return Err(IdentError::DeviceName);
        }
        Ok(AppId(text.to_owned()))
    }

    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A channel id: 1–32 bytes, `[a-z0-9]` first, then `[a-z0-9-]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Channel(String);

impl Channel {
    /// Validates `text`.
    pub fn parse(text: &str) -> Result<Self, IdentError> {
        check_charset(text, MAX_CHANNEL_BYTES, |b| b == b'-')?;
        Ok(Channel(text.to_owned()))
    }

    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Length, then `[a-z0-9]` first and `[a-z0-9]` or `extra` after.
fn check_charset(text: &str, max: usize, extra: impl Fn(u8) -> bool) -> Result<(), IdentError> {
    if text.is_empty() {
        return Err(IdentError::Empty);
    }
    if text.len() > max {
        return Err(IdentError::TooLong {
            len: text.len(),
            max,
        });
    }
    for (offset, &b) in text.as_bytes().iter().enumerate() {
        let base = b.is_ascii_lowercase() || b.is_ascii_digit();
        if !(base || (offset > 0 && extra(b))) {
            return Err(IdentError::InvalidByte { offset });
        }
    }
    Ok(())
}

macro_rules! ident_impls {
    ($ty:ident, $expecting:literal) => {
        impl FromStr for $ty {
            type Err = IdentError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $ty::parse(s)
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($ty), "({:?})"), self.0)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct IdVisitor;
                impl Visitor<'_> for IdVisitor {
                    type Value = $ty;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                        $ty::parse(v).map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

ident_impls!(AppId, "an app id");
ident_impls!(Channel, "a channel id");

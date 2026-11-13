//! Versions (FORMAT.md 10.3): SemVer 2.0.0, at most 64 bytes, ordered by precedence only.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

/// Longest version string in bytes.
pub const MAX_VERSION_BYTES: usize = 64;

/// A SemVer 2.0.0 version. Equality, ordering and hashing use precedence only: build metadata is
/// kept for display and ignored otherwise, so `1.0.0+a == 1.0.0+b`.
#[derive(Clone)]
pub struct Version(semver::Version);

/// Why a version string was rejected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VersionError {
    /// Over [`MAX_VERSION_BYTES`].
    #[error("version is {len} bytes, over the {MAX_VERSION_BYTES} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// Not a SemVer 2.0.0 string (leading `v`, leading zeros, missing parts, ...).
    #[error("not a SemVer 2.0.0 version")]
    Invalid(#[source] semver::Error),
}

impl Version {
    /// Parses a strict SemVer 2.0.0 string of at most 64 bytes.
    pub fn parse(text: &str) -> Result<Self, VersionError> {
        if text.len() > MAX_VERSION_BYTES {
            return Err(VersionError::TooLong { len: text.len() });
        }
        semver::Version::parse(text)
            .map(Version)
            .map_err(VersionError::Invalid)
    }

    /// The parsed SemVer value (build metadata included).
    pub fn as_semver(&self) -> &semver::Version {
        &self.0
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp_precedence(&other.0)
    }
}

impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Exactly the fields precedence reads, so equal values hash alike.
        self.0.major.hash(state);
        self.0.minor.hash(state);
        self.0.patch.hash(state);
        self.0.pre.hash(state);
    }
}

impl FromStr for Version {
    type Err = VersionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Version::parse(s)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Version({})", self.0)
    }
}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct VersionVisitor;
        impl Visitor<'_> for VersionVisitor {
            type Value = Version;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a SemVer 2.0.0 version")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Version::parse(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(VersionVisitor)
    }
}

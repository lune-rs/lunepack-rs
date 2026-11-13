//! Target ids (FORMAT.md 10.4): exactly the seven ids of format v1, and their fallbacks.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

use crate::error::Untrusted;

/// One of the seven target ids of format v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// `windows-x86_64`
    WindowsX86_64,
    /// `windows-aarch64`
    WindowsAarch64,
    /// `macos-x86_64`
    MacosX86_64,
    /// `macos-aarch64`
    MacosAarch64,
    /// `macos-universal`
    MacosUniversal,
    /// `linux-x86_64`
    LinuxX86_64,
    /// `linux-aarch64`
    LinuxAarch64,
}

/// A string that is not a v1 target id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown target {0}")]
pub struct TargetError(pub Untrusted);

impl Target {
    /// Every v1 target, in FORMAT.md order.
    pub const ALL: [Target; 7] = [
        Target::WindowsX86_64,
        Target::WindowsAarch64,
        Target::MacosX86_64,
        Target::MacosAarch64,
        Target::MacosUniversal,
        Target::LinuxX86_64,
        Target::LinuxAarch64,
    ];

    /// Parses an exact id; anything else (another case, an alias such as `macos-arm64`) fails.
    pub fn parse(text: &str) -> Result<Self, TargetError> {
        Target::ALL
            .into_iter()
            .find(|t| t.as_str() == text)
            .ok_or_else(|| TargetError(Untrusted::new(text)))
    }

    /// The id text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Target::WindowsX86_64 => "windows-x86_64",
            Target::WindowsAarch64 => "windows-aarch64",
            Target::MacosX86_64 => "macos-x86_64",
            Target::MacosAarch64 => "macos-aarch64",
            Target::MacosUniversal => "macos-universal",
            Target::LinuxX86_64 => "linux-x86_64",
            Target::LinuxAarch64 => "linux-aarch64",
        }
    }

    /// The ids tried, in order, after this host's own id (the own id is not included).
    pub const fn fallbacks(self) -> &'static [Target] {
        match self {
            Target::WindowsAarch64 => &[Target::WindowsX86_64],
            Target::MacosX86_64 | Target::MacosAarch64 => &[Target::MacosUniversal],
            Target::WindowsX86_64
            | Target::MacosUniversal
            | Target::LinuxX86_64
            | Target::LinuxAarch64 => &[],
        }
    }

    /// Whether this is a `windows-*` target (no symlink entries allowed).
    pub const fn is_windows(self) -> bool {
        matches!(self, Target::WindowsX86_64 | Target::WindowsAarch64)
    }
}

impl FromStr for Target {
    type Err = TargetError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Target::parse(s)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TargetVisitor;
        impl Visitor<'_> for TargetVisitor {
            type Value = Target;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a v1 target id")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Target::parse(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(TargetVisitor)
    }
}

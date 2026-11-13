//! Entry paths and trees (FORMAT.md 10.1 and 10.2): one validator for the writer and every reader
//! (C1).
//!
//! Two layers, both pure: [`validate_path`] holds the rules for one string, [`validate_tree`] the
//! rules that only hold for the entry set of one manifest (case-fold collisions, nothing under a
//! non-directory, symlink targets). Several rules over-reject on purpose: they fail closed against
//! the Win32 path normaliser, NTFS, APFS and Linux at once.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};
use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::error::Untrusted;
use crate::target::Target;

/// Longest path, and longest symlink target, in UTF-8 bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// Most components in a path.
pub const MAX_PATH_DEPTH: usize = 32;
/// Longest component in UTF-8 bytes (the conservative bound for NTFS, APFS and ext4).
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Characters Windows refuses in a name; `:` also rules out drive letters and NTFS streams.
const WINDOWS_RESERVED: &[char] = &['<', '>', ':', '"', '|', '?', '*'];
/// Characters whose look-alikes must not appear after NFKC (best-fit and compatibility mappings).
const NFKC_FORBIDDEN: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];

/// Why a path (or a symlink target) was rejected. Untrusted text never appears unescaped or longer
/// than [`Untrusted::MAX_CHARS`] in the message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// The path is empty.
    #[error("empty path")]
    Empty,
    /// Over [`MAX_PATH_BYTES`].
    #[error("path is {len} bytes, over the {MAX_PATH_BYTES} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// More than [`MAX_PATH_DEPTH`] components.
    #[error("path has more than {MAX_PATH_DEPTH} components")]
    TooDeep,
    /// Not in Unicode NFC.
    #[error("path is not in Unicode NFC")]
    NotNfc,
    /// Starts with `/`.
    #[error("path is absolute")]
    Absolute,
    /// A forbidden character: `\`, NUL, a C0 control, DEL or one of `< > : " | ? *`.
    #[error("forbidden character {ch:?} at byte {offset}")]
    ForbiddenChar {
        /// The character.
        ch: char,
        /// Its byte offset in the path.
        offset: usize,
    },
    /// An empty component (`a//b`, a trailing `/`).
    #[error("component {index} is empty")]
    EmptyComponent {
        /// Zero-based component index.
        index: usize,
    },
    /// Over [`MAX_COMPONENT_BYTES`].
    #[error("component {index} is {len} bytes, over the {MAX_COMPONENT_BYTES} byte cap")]
    ComponentTooLong {
        /// Zero-based component index.
        index: usize,
        /// Length in bytes.
        len: usize,
    },
    /// A `.` or `..` component.
    #[error("component {index} is `.` or `..`")]
    DotComponent {
        /// Zero-based component index.
        index: usize,
    },
    /// A component ends with `.` or a space (Win32 strips them).
    #[error("component {index} ends with a dot or a space")]
    TrailingDotOrSpace {
        /// Zero-based component index.
        index: usize,
    },
    /// A component is a Windows device name.
    #[error("component {index} is a Windows device name")]
    DeviceName {
        /// Zero-based component index.
        index: usize,
    },
    /// A component contains `~` followed by an ASCII digit (an 8.3 short-name look-alike).
    #[error("component {index} looks like an 8.3 short name")]
    ShortNameLike {
        /// Zero-based component index.
        index: usize,
    },
    /// A component's NFKC form holds a forbidden character or is `.` or `..`.
    #[error("component {index} has a compatibility form that is forbidden")]
    CompatibilityForm {
        /// Zero-based component index.
        index: usize,
    },
}

/// A path that passed [`validate_path`]: relative, `/`-separated, NFC.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

impl RelPath {
    /// Validates `text` ([`validate_path`]).
    pub fn parse(text: &str) -> Result<Self, PathError> {
        validate_path(text)
    }

    /// The path text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The components, in order.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The case-fold key of FORMAT.md 10.2: `NFC(lowercase(uppercase(p)))`.
    pub fn fold_key(&self) -> String {
        fold_key(&self.0)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelPath({:?})", self.0)
    }
}

impl Serialize for RelPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PathVisitor;
        impl Visitor<'_> for PathVisitor {
            type Value = RelPath;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a relative entry path")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                validate_path(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(PathVisitor)
    }
}

/// Validates one entry path against every rule of FORMAT.md 10.1.
pub fn validate_path(text: &str) -> Result<RelPath, PathError> {
    if text.is_empty() {
        return Err(PathError::Empty);
    }
    if text.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong { len: text.len() });
    }
    // Characters first: they are meaningful before splitting (`\` is a separator on Windows).
    for (offset, ch) in text.char_indices() {
        if ch == '\\' || ch < ' ' || ch == '\u{7f}' || WINDOWS_RESERVED.contains(&ch) {
            return Err(PathError::ForbiddenChar { ch, offset });
        }
    }
    if !is_nfc(text) {
        return Err(PathError::NotNfc);
    }
    if text.starts_with('/') {
        return Err(PathError::Absolute);
    }
    if text.split('/').count() > MAX_PATH_DEPTH {
        return Err(PathError::TooDeep);
    }
    for (index, comp) in text.split('/').enumerate() {
        validate_component(comp, index)?;
    }
    Ok(RelPath(text.to_owned()))
}

/// The per-component rules; `index` only labels the error. Characters were checked by the caller.
fn validate_component(comp: &str, index: usize) -> Result<(), PathError> {
    if comp.is_empty() {
        return Err(PathError::EmptyComponent { index });
    }
    if comp.len() > MAX_COMPONENT_BYTES {
        return Err(PathError::ComponentTooLong {
            index,
            len: comp.len(),
        });
    }
    if comp == "." || comp == ".." {
        return Err(PathError::DotComponent { index });
    }
    if comp.ends_with('.') || comp.ends_with(' ') {
        return Err(PathError::TrailingDotOrSpace { index });
    }
    if is_device_name(comp) {
        return Err(PathError::DeviceName { index });
    }
    if comp
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'~' && w[1].is_ascii_digit())
    {
        return Err(PathError::ShortNameLike { index });
    }
    let compat: String = comp.nfkc().collect();
    if compat == "." || compat == ".." || compat.contains(NFKC_FORBIDDEN) {
        return Err(PathError::CompatibilityForm { index });
    }
    Ok(())
}

/// Whether `name` is a Windows device name in any case, with or without an extension and with or
/// without spaces before the extension (`con`, `Con.txt`, `CON .txt`, `lpt¹.log`). Names that
/// only start with one (`CONSOLE`, `nul1.txt`, `com10`) are not.
pub(crate) fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let Some(rest) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = rest.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}'),
        _ => false,
    }
}

/// `NFC(lowercase(uppercase(text)))` with Unicode full case mapping (FORMAT.md 10.2). Case mapping
/// never produces or removes `/`, and `/` is neither cased nor case-ignorable, so the key of a path
/// is the keys of its components joined by `/`.
pub fn fold_key(text: &str) -> String {
    text.to_uppercase().to_lowercase().nfc().collect()
}

/// The kind of one manifest entry, as [`validate_tree`] needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind<'a> {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink with its target text.
    Symlink {
        /// The link text, checked by the tree rules.
        target: &'a str,
    },
}

/// Why a symlink target was rejected (FORMAT.md 10.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkTargetError {
    /// The target is empty.
    #[error("empty target")]
    Empty,
    /// Over [`MAX_PATH_BYTES`].
    #[error("target is {len} bytes, over the {MAX_PATH_BYTES} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// Not in Unicode NFC.
    #[error("target is not in Unicode NFC")]
    NotNfc,
    /// `\`, NUL, a C0 control or DEL.
    #[error("forbidden character {ch:?} at byte {offset}")]
    ForbiddenChar {
        /// The character.
        ch: char,
        /// Its byte offset in the target.
        offset: usize,
    },
    /// Starts with `/`.
    #[error("target is absolute")]
    Absolute,
    /// An empty component.
    #[error("target has an empty component")]
    EmptyComponent,
    /// Lexical resolution from the link's parent leaves the tree.
    #[error("target leaves the tree")]
    Escapes,
    /// A non-final component of the resolution is another symlink entry.
    #[error("target passes through the symlink {0}")]
    ThroughSymlink(Untrusted),
}

/// Why an entry set was rejected (FORMAT.md 10.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeError {
    /// Two entries have the same case-fold key.
    #[error("{first} and {second} collide when case is folded")]
    Collision {
        /// The earlier entry.
        first: Untrusted,
        /// The later entry.
        second: Untrusted,
    },
    /// An entry lies under a `file` or `symlink` entry.
    #[error("{path} lies under the non-directory {parent}")]
    UnderNonDirectory {
        /// The file or symlink entry.
        parent: Untrusted,
        /// The entry under it.
        path: Untrusted,
    },
    /// A symlink in a manifest for a Windows target.
    #[error("symlink {0} in a Windows manifest")]
    SymlinkOnWindows(Untrusted),
    /// A symlink target broke a rule.
    #[error("symlink {path}: {source}")]
    LinkTarget {
        /// The symlink entry.
        path: Untrusted,
        /// The broken rule.
        #[source]
        source: LinkTargetError,
    },
}

/// Validates the entry set of one manifest for `target` (FORMAT.md 10.2): no two entries with equal
/// fold keys, nothing under a `file` or `symlink` entry, no symlink on a Windows target, and every
/// symlink target stays inside the tree without passing through another symlink.
///
/// Cost: one fold key and one ordered-map insert per entry, one range lookup per non-directory
/// entry, and per symlink one lookup per target component: `O(n log n)` in the entry count.
pub fn validate_tree<'a, I>(entries: I, target: Target) -> Result<(), TreeError>
where
    I: IntoIterator<Item = (&'a RelPath, EntryKind<'a>)>,
{
    // fold key -> (entry path, kind)
    let mut by_key: BTreeMap<String, (&RelPath, EntryKind<'_>)> = BTreeMap::new();
    let mut links: Vec<(&RelPath, &str)> = Vec::new();
    for (path, kind) in entries {
        if let EntryKind::Symlink { target: link } = kind {
            if target.is_windows() {
                return Err(TreeError::SymlinkOnWindows(untrusted(path)));
            }
            links.push((path, link));
        }
        if let Some((first, _)) = by_key.insert(path.fold_key(), (path, kind)) {
            return Err(TreeError::Collision {
                first: untrusted(first),
                second: untrusted(path),
            });
        }
    }
    // Nothing under a non-directory: the keys under `k` are exactly those starting with `k/`, and
    // they sort contiguously from `k/`, so the first key at or after `k/` decides.
    for (key, (parent, kind)) in &by_key {
        if matches!(kind, EntryKind::Dir) {
            continue;
        }
        let prefix = format!("{key}/");
        let next = by_key
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .next();
        if let Some((under, (path, _))) = next
            && under.starts_with(&prefix)
        {
            return Err(TreeError::UnderNonDirectory {
                parent: untrusted(parent),
                path: untrusted(path),
            });
        }
    }
    for (path, link) in links {
        check_link_target(path, link, &by_key).map_err(|source| TreeError::LinkTarget {
            path: untrusted(path),
            source,
        })?;
    }
    Ok(())
}

/// Checks one symlink's target text and resolves it lexically from the link's parent directory.
fn check_link_target(
    link_path: &RelPath,
    link: &str,
    by_key: &BTreeMap<String, (&RelPath, EntryKind<'_>)>,
) -> Result<(), LinkTargetError> {
    if link.is_empty() {
        return Err(LinkTargetError::Empty);
    }
    if link.len() > MAX_PATH_BYTES {
        return Err(LinkTargetError::TooLong { len: link.len() });
    }
    for (offset, ch) in link.char_indices() {
        if ch == '\\' || ch < ' ' || ch == '\u{7f}' {
            return Err(LinkTargetError::ForbiddenChar { ch, offset });
        }
    }
    if !is_nfc(link) {
        return Err(LinkTargetError::NotNfc);
    }
    if link.starts_with('/') {
        return Err(LinkTargetError::Absolute);
    }
    let comps: Vec<&str> = link.split('/').collect();
    if comps.iter().any(|c| c.is_empty()) {
        return Err(LinkTargetError::EmptyComponent);
    }
    // The resolution stack holds the fold keys of components, starting at the link's parent.
    let mut stack: Vec<String> = link_path.components().map(fold_key).collect();
    stack.pop();
    let last = comps.len() - 1;
    for (i, comp) in comps.into_iter().enumerate() {
        match comp {
            // `.` names the directory the resolution is in, so it stays there. Pushing it as a
            // name would let `./..` pop it and hide one level of escape.
            "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return Err(LinkTargetError::Escapes);
                }
            }
            name => {
                stack.push(fold_key(name));
                if i < last
                    && let Some((other, EntryKind::Symlink { .. })) = by_key.get(&stack.join("/"))
                {
                    return Err(LinkTargetError::ThroughSymlink(untrusted(other)));
                }
            }
        }
    }
    Ok(())
}

fn untrusted(path: &RelPath) -> Untrusted {
    Untrusted::new(path.as_str())
}

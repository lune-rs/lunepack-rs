//! The manifest, `<ver>/<target>.manifest.json` (FORMAT.md 8): one release's file tree for one
//! target, bound to the feed by size and hash.

use serde::{Deserialize, Serialize};

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, Result};
use crate::feed::{ArtifactRef, CheckedRef, FeedTargetEntry};
use crate::frame::{CheckedFrame, FrameDesc, check_file_frame};
use crate::ident::AppId;
use crate::keyset::VerifiedKeySet;
use crate::limits::Limits;
use crate::path::{EntryKind, RelPath, validate_tree};
use crate::target::Target;
use crate::traits::{Hasher, Verifier};
use crate::trust::{from_checked, parse_payload, present};
use crate::version::Version;

/// One manifest entry as written (FORMAT.md 8.1). Fields of another `type` are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryDoc {
    /// The entry's path (FORMAT.md 10.1).
    pub path: RelPath,
    /// `file`, `dir` or `symlink`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `file`: byte size.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub size: Option<U53>,
    /// `file`: SHA-256 of the file's bytes.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha256: Option<Sha256Digest>,
    /// `file`: executable bit, required.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub exec: Option<bool>,
    /// `file`: the frame, present exactly when `size > 0`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub frame: Option<FrameDesc>,
    /// `symlink`: the link text.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub target: Option<String>,
}

/// A manifest payload as written (FORMAT.md 8). The writer serialises whatever it is given;
/// [`verify_manifest`] checks every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDocument {
    /// Must be 1.
    pub format: U53,
    /// Must be `"manifest"`.
    pub kind: String,
    /// Critical features; v1 accepts only an empty list.
    pub critical: Vec<String>,
    /// The app id.
    pub app_id: AppId,
    /// The release version, byte-equal to the feed's.
    pub version: String,
    /// The target id.
    pub target: String,
    /// When the manifest was written.
    pub issued: U53,
    /// The release's pack.
    pub pack: ArtifactRef,
    /// The entries.
    pub entries: Vec<EntryDoc>,
}

/// Reserved manifest fields v1 writers never write (FORMAT.md 8); a v1 reader rejects them.
#[derive(Deserialize)]
struct Reserved {
    #[serde(default, deserialize_with = "present")]
    install: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "present")]
    deltas: Option<serde::de::IgnoredAny>,
}

impl ManifestDocument {
    /// The payload bytes the writer signs: this document as JSON.
    pub fn to_payload(&self) -> Vec<u8> {
        // Plain strings, integers and booleans cannot fail to serialise.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A verified entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedEntry {
    /// A regular file.
    File {
        /// Its path.
        path: RelPath,
        /// Byte size.
        size: u64,
        /// SHA-256 of its bytes.
        sha256: Sha256Digest,
        /// Executable bit.
        exec: bool,
        /// Its checked frame; `None` for an empty file.
        frame: Option<CheckedFrame>,
    },
    /// A directory.
    Dir {
        /// Its path.
        path: RelPath,
    },
    /// A symlink (macOS and Linux targets only).
    Symlink {
        /// Its path.
        path: RelPath,
        /// The link text, checked by the tree rules.
        target: String,
    },
}

impl VerifiedEntry {
    /// The entry's path.
    pub fn path(&self) -> &RelPath {
        match self {
            VerifiedEntry::File { path, .. }
            | VerifiedEntry::Dir { path }
            | VerifiedEntry::Symlink { path, .. } => path,
        }
    }

    fn kind(&self) -> EntryKind<'_> {
        match self {
            VerifiedEntry::File { .. } => EntryKind::File,
            VerifiedEntry::Dir { .. } => EntryKind::Dir,
            VerifiedEntry::Symlink { target, .. } => EntryKind::Symlink { target },
        }
    }
}

/// A manifest that passed [`verify_manifest`]; there is no other constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    app_id: AppId,
    version: Version,
    target: Target,
    issued: u64,
    pack: CheckedRef,
    entries: Vec<VerifiedEntry>,
}

impl VerifiedManifest {
    /// The app id.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The release version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// When the manifest was written; the next check's implausible-clock floor (FORMAT.md 11.3).
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The pack reference.
    pub fn pack(&self) -> &CheckedRef {
        &self.pack
    }

    /// The entries in document order.
    pub fn entries(&self) -> &[VerifiedEntry] {
        &self.entries
    }
}

fn foreign(present: bool, what: &'static str) -> Result<()> {
    if present {
        Err(Error::Field(what))
    } else {
        Ok(())
    }
}

fn check_entry(doc: EntryDoc, pack_size: u64, empty_sha256: Sha256Digest) -> Result<VerifiedEntry> {
    match doc.kind.as_str() {
        "file" => {
            foreign(doc.target.is_some(), "target on a file entry")?;
            let size = doc
                .size
                .ok_or(Error::Field("file entry without size"))?
                .get();
            let sha256 = doc
                .sha256
                .ok_or(Error::Field("file entry without sha256"))?;
            let exec = doc.exec.ok_or(Error::Field("file entry without exec"))?;
            if size == 0 && sha256 != empty_sha256 {
                return Err(Error::Field(
                    "empty file whose sha256 is not that of no bytes",
                ));
            }
            let frame = check_file_frame(doc.frame.as_ref(), size, sha256, pack_size)?;
            Ok(VerifiedEntry::File {
                path: doc.path,
                size,
                sha256,
                exec,
                frame,
            })
        }
        "dir" => {
            foreign(
                doc.size.is_some()
                    || doc.sha256.is_some()
                    || doc.exec.is_some()
                    || doc.frame.is_some()
                    || doc.target.is_some(),
                "file or symlink field on a dir entry",
            )?;
            Ok(VerifiedEntry::Dir { path: doc.path })
        }
        "symlink" => {
            foreign(
                doc.size.is_some()
                    || doc.sha256.is_some()
                    || doc.exec.is_some()
                    || doc.frame.is_some(),
                "file field on a symlink entry",
            )?;
            let target = doc
                .target
                .ok_or(Error::Field("symlink entry without target"))?;
            Ok(VerifiedEntry::Symlink {
                path: doc.path,
                target,
            })
        }
        _ => Err(Error::Field("unknown entry type")),
    }
}

/// Verifies a manifest (FORMAT.md 8, 11.1 step 5) reached from `entry` of a verified feed. Order:
/// the bytes' length and SHA-256 equal the feed entry's reference **before** the envelope is
/// opened; the envelope meets the key set's release threshold (no key windows for manifests: the
/// feed binds the manifest by hash); only then the payload is parsed (format, kind, critical,
/// fields; reserved `install` and `deltas` rejected); at most 200,000 entries; app id equal to the
/// key set's and the feed's, version byte-equal (and so precedence-equal) to the feed entry's,
/// target equal to the feed entry's; the pack reference (FORMAT.md 7.1); every entry's fields, an
/// empty file's hash, every file frame against `pack.size` (FORMAT.md 9); the tree rules.
pub fn verify_manifest(
    keys: &VerifiedKeySet,
    entry: &FeedTargetEntry,
    bytes: &[u8],
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<VerifiedManifest> {
    entry.reference().check_bytes(bytes, hasher)?;
    let envelope = OpenedEnvelope::open(bytes, PayloadKind::Manifest, &Limits::V1)?;
    let payload = envelope.authenticate(keys.keys(), keys.threshold(), verifier)?;
    let doc: ManifestDocument = parse_payload(payload, PayloadKind::Manifest)?;
    let reserved: Reserved = from_checked(payload)?;
    if reserved.install.is_some() || reserved.deltas.is_some() {
        return Err(Error::Field("reserved manifest field"));
    }

    let max = Limits::V1.manifest_entries;
    if doc.entries.len() > max {
        return Err(Error::TooMany {
            what: "entries",
            count: doc.entries.len(),
            max,
        });
    }
    if doc.app_id != *keys.app_id() || doc.app_id != *entry.app_id() {
        return Err(Error::AppIdMismatch);
    }
    let version = Version::parse(&doc.version)?;
    if doc.version.as_bytes() != entry.version_text().as_bytes() || version != *entry.version() {
        return Err(Error::VersionMismatch);
    }
    let target = Target::parse(&doc.target)?;
    if target != entry.target() {
        return Err(Error::TargetMismatch {
            expected: entry.target().as_str(),
            found: target.as_str(),
        });
    }

    let pack = doc.pack.check()?;
    let empty = hasher.sha256(b"");
    let entries = doc
        .entries
        .into_iter()
        .map(|e| check_entry(e, pack.size(), empty))
        .collect::<Result<Vec<_>>>()?;
    validate_tree(entries.iter().map(|e| (e.path(), e.kind())), target)?;

    Ok(VerifiedManifest {
        app_id: doc.app_id,
        version,
        target,
        issued: doc.issued.get(),
        pack,
        entries,
    })
}

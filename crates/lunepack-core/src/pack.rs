//! Pack planning (M3-D6, M3-D8): which codecs a file may use, the choice among them with a round
//! trip through the client's own [`decode_verified`], and the layout of one release's pack and
//! manifest. Pure: the bytes of every file come in through the caller, encoding goes through the
//! [`Encoder`] trait, hashing through [`Hasher`].
//!
//! Classification reads the file's content only, never its name, so any language's executables and
//! libraries get the right filter.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::digest::{Sha256Digest, U53};
use crate::error::{Error, PackError, Result, Untrusted};
use crate::feed::ArtifactRef;
use crate::frame::{FrameDesc, StreamDesc, check_file_frame, decode_verified};
use crate::ident::AppId;
use crate::limits::Limits;
use crate::manifest::{EntryDoc, ManifestDocument};
use crate::path::{EntryKind, RelPath, validate_tree};
use crate::target::Target;
use crate::traits::{Codec, CodecId, EncodedFrame, EncodedStream, Encoder, Hasher};
use crate::version::Version;

/// What a file's bytes say it is, for the choice of codec candidates (M3-D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// No bytes: no frame at all.
    Empty,
    /// Already compressed (an archive, a compressed stream or a compressed image or font): stored.
    Compressed,
    /// x86 or x86-64 code.
    X86,
    /// ARM64 code.
    Arm64,
    /// A fat Mach-O whose slices include the marked architectures (at least one is `true`).
    Fat {
        /// Some slice is x86 or x86-64.
        x86: bool,
        /// Some slice is ARM64.
        arm64: bool,
    },
    /// Everything else, executables of other architectures included.
    Data,
}

const MH_CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | MH_CPU_ARCH_ABI64;
const CPU_TYPE_ARM64: u32 = 12 | MH_CPU_ARCH_ABI64;
const MAX_FAT_ARCHS: u32 = 20;

fn u16_at(bytes: &[u8], at: usize, big: bool) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if big {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    })
}

fn u32_at(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}

/// Magic numbers of formats that are already compressed (M3-D6).
fn is_compressed(bytes: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 12] = [
        &[0x50, 0x4B, 0x03, 0x04],                         // zip
        &[0x1F, 0x8B],                                     // gzip
        &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],             // xz
        &[0x28, 0xB5, 0x2F, 0xFD],                         // zstd
        &[0x42, 0x5A, 0x68],                               // bzip2
        &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],             // 7z
        &[0x04, 0x22, 0x4D, 0x18],                         // lz4
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], // PNG
        &[0xFF, 0xD8, 0xFF],                               // JPEG
        &[0x47, 0x49, 0x46, 0x38],                         // GIF
        &[0x77, 0x4F, 0x46, 0x32],                         // WOFF2
        &[0x4F, 0x67, 0x67, 0x53],                         // Ogg
    ];
    PREFIXES.iter().any(|p| bytes.starts_with(p))
        || (bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
}

fn pe(bytes: &[u8]) -> Option<FileClass> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let lfanew = usize::try_from(u32_at(bytes, 0x3C, false)?).ok()?;
    let sig_end = lfanew.checked_add(4)?;
    if bytes.get(lfanew..sig_end)? != b"PE\0\0" {
        return None;
    }
    match u16_at(bytes, sig_end, false)? {
        0x014C | 0x8664 => Some(FileClass::X86),
        0xAA64 => Some(FileClass::Arm64),
        _ => None,
    }
}

fn elf(bytes: &[u8]) -> Option<FileClass> {
    if !bytes.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return None;
    }
    // EI_CLASS 1 or 2, EI_DATA 1 (little) or 2 (big): anything else is not a header we read.
    if !matches!(bytes.get(4)?, 1 | 2) {
        return None;
    }
    let big = match bytes.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    match u16_at(bytes, 18, big)? {
        3 | 62 => Some(FileClass::X86),
        183 => Some(FileClass::Arm64),
        _ => None,
    }
}

fn macho_class(cputype: u32) -> Option<FileClass> {
    match cputype {
        CPU_TYPE_X86 | CPU_TYPE_X86_64 => Some(FileClass::X86),
        CPU_TYPE_ARM64 => Some(FileClass::Arm64),
        _ => None,
    }
}

fn macho(bytes: &[u8]) -> Option<FileClass> {
    let big = match bytes.get(..4)? {
        [0xFE, 0xED, 0xFA, 0xCE | 0xCF] => true,
        [0xCE | 0xCF, 0xFA, 0xED, 0xFE] => false,
        _ => return None,
    };
    macho_class(u32_at(bytes, 4, big)?)
}

fn fat(bytes: &[u8]) -> Option<FileClass> {
    // `CA FE BA BE` is also a Java class file; its next four bytes are minor and major version
    // (major 45 or more), far above the 20 slices accepted here.
    let stride = match bytes.get(..4)? {
        [0xCA, 0xFE, 0xBA, 0xBE] => 20usize,
        [0xCA, 0xFE, 0xBA, 0xBF] => 32usize,
        _ => return None,
    };
    let count = u32_at(bytes, 4, true)?;
    if !(1..=MAX_FAT_ARCHS).contains(&count) {
        return None;
    }
    // The whole slice table must be present.
    let table_end = (count as usize)
        .checked_mul(stride)
        .and_then(|n| n.checked_add(8))?;
    if bytes.len() < table_end {
        return None;
    }
    // Slices of other architectures are skipped; only x86 and ARM64 ones add candidates.
    let (mut x86, mut arm64) = (false, false);
    for i in 0..count as usize {
        match macho_class(u32_at(bytes, 8 + i * stride, true)?) {
            Some(FileClass::X86) => x86 = true,
            Some(FileClass::Arm64) => arm64 = true,
            _ => {}
        }
    }
    (x86 || arm64).then_some(FileClass::Fat { x86, arm64 })
}

/// Classifies a file from its bytes (M3-D6): size 0, a compressed magic, the PE, ELF or Mach-O
/// machine, or a fat Mach-O's slices. Bounds-checked; a malformed or unknown header is
/// [`FileClass::Data`]. Never panics.
pub fn classify(bytes: &[u8]) -> FileClass {
    if bytes.is_empty() {
        return FileClass::Empty;
    }
    if is_compressed(bytes) {
        return FileClass::Compressed;
    }
    pe(bytes)
        .or_else(|| elf(bytes))
        .or_else(|| macho(bytes))
        .or_else(|| fat(bytes))
        .unwrap_or(FileClass::Data)
}

/// The codecs worth trying for `class`, in the fixed rank order `lzma2 < bcj-x86+lzma2 <
/// bcj-arm64+lzma2 < bcj2`. `stored` is never listed: it is the baseline every candidate must beat,
/// and the choice when none does. An empty list means "store" (or, for an empty file, no frame).
pub fn candidates(class: FileClass) -> Vec<CodecId> {
    match class {
        FileClass::Empty | FileClass::Compressed => Vec::new(),
        FileClass::X86 => vec![CodecId::BcjX86Lzma2, CodecId::Bcj2],
        FileClass::Arm64 => vec![CodecId::BcjArm64Lzma2],
        FileClass::Fat { x86, arm64 } => {
            let mut list = Vec::new();
            if x86 {
                list.push(CodecId::BcjX86Lzma2);
            }
            if arm64 {
                list.push(CodecId::BcjArm64Lzma2);
            }
            if x86 {
                list.push(CodecId::Bcj2);
            }
            list
        }
        FileClass::Data => vec![CodecId::Lzma2],
    }
}

/// Tie-break rank: the earlier wins on equal length (M3-D6).
fn rank(codec: CodecId) -> u8 {
    match codec {
        CodecId::Stored => 0,
        CodecId::Lzma2 => 1,
        CodecId::BcjX86Lzma2 => 2,
        CodecId::BcjArm64Lzma2 => 3,
        CodecId::Bcj2 => 4,
    }
}

/// One file ready to enter a pack: its size and hash, the chosen frame, and the candidates that
/// were tried and discarded.
#[derive(Debug, Clone)]
pub struct PackedFile {
    /// The file's size in bytes.
    pub size: u64,
    /// The file's SHA-256.
    pub sha256: Sha256Digest,
    /// The chosen frame; `None` exactly when `size == 0`.
    pub frame: Option<EncodedFrame>,
    /// Candidates whose encode or round trip failed, with the reason (never file bytes).
    pub dropped: Vec<(CodecId, String)>,
}

/// The parts of a frame that a descriptor is made from.
struct Parts<'a> {
    codec: CodecId,
    bytes: &'a [u8],
    dict_size: Option<u32>,
    streams: Option<&'a [EncodedStream]>,
}

impl<'a> From<&'a EncodedFrame> for Parts<'a> {
    fn from(f: &'a EncodedFrame) -> Self {
        Parts {
            codec: f.codec,
            bytes: &f.bytes,
            dict_size: f.dict_size,
            streams: f.streams.as_deref(),
        }
    }
}

fn describe(parts: &Parts<'_>, offset: u64, hasher: &dyn Hasher) -> Result<FrameDesc> {
    let streams = parts
        .streams
        .map(|streams| {
            streams
                .iter()
                .map(|s| {
                    Ok(StreamDesc {
                        length: U53::new(s.length)?,
                        decoded_size: U53::new(s.decoded_size)?,
                        dict_size: s.dict_size.map(|d| U53::new(u64::from(d))).transpose()?,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    Ok(FrameDesc {
        codec: parts.codec.id().to_owned(),
        offset: U53::new(offset)?,
        length: U53::new(parts.bytes.len() as u64)?,
        sha256: hasher.sha256(parts.bytes),
        dict_size: parts
            .dict_size
            .map(|d| U53::new(u64::from(d)))
            .transpose()?,
        streams,
    })
}

/// The check a client makes: descriptor structure, then verify-then-decode into a sink.
fn round_trip(
    parts: &Parts<'_>,
    size: u64,
    sha256: Sha256Digest,
    hasher: &dyn Hasher,
    codec: &dyn Codec,
) -> Result<()> {
    let desc = describe(parts, 0, hasher)?;
    let checked = desc.check(size, sha256, parts.bytes.len() as u64)?;
    decode_verified(&checked, parts.bytes, hasher, codec, &mut io::sink())
}

/// An error and its causes, joined; error Display strings carry no input bytes.
fn reason(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut next = error.source();
    while let Some(cause) = next {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        next = cause.source();
    }
    out
}

/// Chooses the frame for one file (M3-D6): every candidate of its class is encoded and round-tripped
/// through [`FrameDesc::check`] and [`decode_verified`] with a sink that discards the output. A
/// candidate whose encode or round trip fails is recorded in `dropped`. The smallest kept candidate
/// that is strictly shorter than the file wins, the earlier in the fixed rank on equal length;
/// when there is none, the file is stored (and that frame is round-tripped too). An empty file has
/// no frame.
///
/// Only an internal invariant is an `Err`: the stored frame failing its own round trip.
pub fn pack_file(
    input: &[u8],
    encoder: &dyn Encoder,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
) -> Result<PackedFile> {
    let size = input.len() as u64;
    let sha256 = hasher.sha256(input);
    if input.is_empty() {
        return Ok(PackedFile {
            size,
            sha256,
            frame: None,
            dropped: Vec::new(),
        });
    }

    let mut dropped = Vec::new();
    let mut best: Option<EncodedFrame> = None;
    for id in candidates(classify(input)) {
        let frame = match encoder.encode(id, input) {
            Ok(frame) => frame,
            Err(e) => {
                dropped.push((id, reason(&e)));
                continue;
            }
        };
        if frame.codec != id {
            dropped.push((id, "the encoder returned another codec".to_owned()));
            continue;
        }
        if let Err(e) = round_trip(&Parts::from(&frame), size, sha256, hasher, codec) {
            dropped.push((id, reason(&e)));
            continue;
        }
        let len = frame.bytes.len() as u64;
        if len >= size {
            continue;
        }
        let better = best
            .as_ref()
            .is_none_or(|b| (len, rank(frame.codec)) < (b.bytes.len() as u64, rank(b.codec)));
        if better {
            best = Some(frame);
        }
    }

    let frame = match best {
        Some(frame) => frame,
        None => {
            let stored = Parts {
                codec: CodecId::Stored,
                bytes: input,
                dict_size: None,
                streams: None,
            };
            round_trip(&stored, size, sha256, hasher, codec)
                .map_err(|e| PackError::StoredRoundTrip(Box::new(e)))?;
            EncodedFrame {
                codec: CodecId::Stored,
                bytes: input.to_vec(),
                dict_size: None,
                streams: None,
            }
        }
    };
    Ok(PackedFile {
        size,
        sha256,
        frame: Some(frame),
        dropped,
    })
}

enum Body {
    File {
        exec: bool,
        size: u64,
        sha256: Sha256Digest,
        frame: Option<EncodedFrame>,
    },
    Dir,
    Symlink(String),
}

struct LayoutEntry {
    path: RelPath,
    body: Body,
}

/// One release's entries, collected in any order and turned into a manifest document and its pack
/// by [`ReleaseLayout::finish`] (M3-D8).
pub struct ReleaseLayout {
    app_id: AppId,
    version: String,
    target: Target,
    entries: Vec<LayoutEntry>,
    seen: BTreeSet<RelPath>,
}

impl ReleaseLayout {
    /// A layout for `app_id`, `version` and `target`. The version must be SemVer 2.0.0
    /// ([`Version::parse`]); its text is kept verbatim.
    pub fn new(app_id: AppId, version: &str, target: Target) -> Result<Self> {
        Version::parse(version)?;
        Ok(ReleaseLayout {
            app_id,
            version: version.to_owned(),
            target,
            entries: Vec::new(),
            seen: BTreeSet::new(),
        })
    }

    fn push(&mut self, path: RelPath, body: Body) -> Result<()> {
        if !self.seen.insert(path.clone()) {
            return Err(PackError::DuplicatePath(Untrusted::new(path.as_str())).into());
        }
        self.entries.push(LayoutEntry { path, body });
        Ok(())
    }

    /// Adds a file. `packed.frame` must be present exactly when `packed.size > 0`; the frame is
    /// copied. Adding a path twice is an error.
    pub fn add_file(&mut self, path: RelPath, exec: bool, packed: &PackedFile) -> Result<()> {
        if packed.frame.is_some() != (packed.size > 0) {
            return Err(PackError::Invariant("a frame exactly when the file is not empty").into());
        }
        self.push(
            path,
            Body::File {
                exec,
                size: packed.size,
                sha256: packed.sha256,
                frame: packed.frame.clone(),
            },
        )
    }

    /// Adds a directory entry.
    pub fn add_dir(&mut self, path: RelPath) -> Result<()> {
        self.push(path, Body::Dir)
    }

    /// Adds a symlink entry with its link text (FORMAT.md 10.2 is checked in [`finish`](Self::finish)).
    pub fn add_symlink(&mut self, path: RelPath, target: &str) -> Result<()> {
        self.push(path, Body::Symlink(target.to_owned()))
    }

    /// Builds the manifest document and the pack bytes.
    ///
    /// Entries are sorted by path bytes and checked with [`validate_tree`] (symlinks are rejected
    /// for Windows targets); identical files (same size and SHA-256) share the frame of the first
    /// in that order; frames are laid out back to back in entry order with no padding; the pack
    /// reference is `<version>/<target>.pack`. The output depends only on the set of entries added,
    /// never on the order they were added in. Every frame descriptor is checked with
    /// [`check_file_frame`] against the finished pack before it is returned.
    pub fn finish(self, issued: u64, hasher: &dyn Hasher) -> Result<(ManifestDocument, Vec<u8>)> {
        let ReleaseLayout {
            app_id,
            version,
            target,
            mut entries,
            ..
        } = self;
        let max = Limits::V1.manifest_entries;
        if entries.len() > max {
            return Err(Error::TooMany {
                what: "entries",
                count: entries.len(),
                max,
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        validate_tree(
            entries.iter().map(|e| {
                let kind = match &e.body {
                    Body::File { .. } => EntryKind::File,
                    Body::Dir => EntryKind::Dir,
                    Body::Symlink(link) => EntryKind::Symlink { target: link },
                };
                (&e.path, kind)
            }),
            target,
        )?;

        // Reserve the pack once: the frames of the first file of each (size, hash).
        let mut counted = BTreeSet::new();
        let mut total = 0usize;
        for e in &entries {
            if let Body::File {
                size,
                sha256,
                frame: Some(frame),
                ..
            } = &e.body
                && counted.insert((*size, *sha256.as_bytes()))
            {
                total = total.saturating_add(frame.bytes.len());
            }
        }
        let mut pack = Vec::with_capacity(total);
        let mut shared: BTreeMap<(u64, [u8; 32]), FrameDesc> = BTreeMap::new();
        let mut docs = Vec::with_capacity(entries.len());
        for e in entries {
            let doc = match e.body {
                Body::File {
                    exec,
                    size,
                    sha256,
                    frame,
                } => {
                    let desc = match frame {
                        None => None,
                        Some(frame) => Some(match shared.get(&(size, *sha256.as_bytes())) {
                            Some(first) => first.clone(),
                            None => {
                                let desc =
                                    describe(&Parts::from(&frame), pack.len() as u64, hasher)?;
                                pack.extend_from_slice(&frame.bytes);
                                shared.insert((size, *sha256.as_bytes()), desc.clone());
                                desc
                            }
                        }),
                    };
                    EntryDoc {
                        path: e.path,
                        kind: "file".to_owned(),
                        size: Some(U53::new(size)?),
                        sha256: Some(sha256),
                        exec: Some(exec),
                        frame: desc,
                        target: None,
                    }
                }
                Body::Dir => EntryDoc {
                    path: e.path,
                    kind: "dir".to_owned(),
                    size: None,
                    sha256: None,
                    exec: None,
                    frame: None,
                    target: None,
                },
                Body::Symlink(link) => EntryDoc {
                    path: e.path,
                    kind: "symlink".to_owned(),
                    size: None,
                    sha256: None,
                    exec: None,
                    frame: None,
                    target: Some(link),
                },
            };
            docs.push(doc);
        }

        let pack_size = pack.len() as u64;
        for doc in &docs {
            if let (Some(size), Some(sha256)) = (doc.size, doc.sha256) {
                check_file_frame(doc.frame.as_ref(), size.get(), sha256, pack_size)?;
            }
        }
        let manifest = ManifestDocument {
            format: U53::new(1)?,
            kind: "manifest".to_owned(),
            critical: Vec::new(),
            app_id,
            pack: ArtifactRef {
                path: format!("{version}/{}.pack", target.as_str()),
                size: U53::new(pack_size)?,
                sha256: hasher.sha256(&pack),
            },
            version,
            target: target.as_str().to_owned(),
            issued: U53::new(issued)?,
            entries: docs,
        };
        Ok((manifest, pack))
    }
}

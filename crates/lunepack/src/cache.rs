//! The download cache (M4-D17): `<cache>/frames/<frame-sha256>` and `<cache>/packs/<pack-sha256>`.
//!
//! A file without `.part` is complete: it was length- and hash-checked when it was finished (and is
//! re-checked when used). A partial download is `<name>.part`, with a `<name>.meta` sidecar that
//! holds strict JSON `{format, validator, url_sha256}` for the next call's `If-Range`. The sidecar
//! is a hint only: an unreadable or foreign one means "resume without `If-Range`", and the hash
//! check still guards the result.
//!
//! Everything here is blocking file I/O through [`Fs`]; the fetch engine runs it on worker jobs
//! (C9). Names are built from digests only, never from response text.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lunepack_core::json::parse_strict;
use lunepack_core::{
    FileKind, FileWrite, Fs, FsError, FsErrorKind, HashState, Hasher, Sha256Digest, Validator,
};
use serde::{Deserialize, Serialize};

use crate::Error;

/// The sidecar format this build writes and reads.
const META_FORMAT: u64 = 1;
/// A sidecar is a few hundred bytes; anything longer is not ours.
const META_CAP: u64 = 4096;
/// Read size when hashing a part that is resumed.
const HASH_READ: usize = 64 * 1024;

/// Which cache directory an entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheKind {
    /// `frames/`: one pack frame.
    Frame,
    /// `packs/`: a whole pack.
    Pack,
}

impl CacheKind {
    fn dir(self) -> &'static str {
        match self {
            CacheKind::Frame => "frames",
            CacheKind::Pack => "packs",
        }
    }
}

/// The validator stored in a sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum MetaValidator {
    Etag(String),
    LastModified(String),
}

/// A part's sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartMeta {
    format: u64,
    validator: Option<MetaValidator>,
    url_sha256: Sha256Digest,
}

/// The download cache over an [`Fs`]. Cheap to clone.
#[derive(Clone)]
pub struct Cache {
    fs: Arc<dyn Fs>,
    dir: PathBuf,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache").finish_non_exhaustive()
    }
}

fn ignore_missing(result: Result<(), FsError>) -> Result<(), FsError> {
    match result {
        Err(e) if e.kind == FsErrorKind::NotFound => Ok(()),
        other => other,
    }
}

impl Cache {
    /// A cache rooted at `dir` (absolute).
    pub fn new(fs: Arc<dyn Fs>, dir: PathBuf) -> Self {
        Cache { fs, dir }
    }

    /// The filesystem.
    pub fn fs(&self) -> &Arc<dyn Fs> {
        &self.fs
    }

    /// The path of the complete entry.
    pub fn path(&self, kind: CacheKind, sha: &Sha256Digest) -> PathBuf {
        self.dir.join(kind.dir()).join(sha.to_hex())
    }

    /// The path of the entry's partial download.
    pub fn part_path(&self, kind: CacheKind, sha: &Sha256Digest) -> PathBuf {
        self.dir
            .join(kind.dir())
            .join(format!("{}.part", sha.to_hex()))
    }

    fn meta_path(&self, kind: CacheKind, sha: &Sha256Digest) -> PathBuf {
        self.dir
            .join(kind.dir())
            .join(format!("{}.meta", sha.to_hex()))
    }

    fn kind_dir(&self, kind: CacheKind) -> PathBuf {
        self.dir.join(kind.dir())
    }

    /// Creates `frames/` and `packs/` and makes their entries (and the cache directory's own
    /// entry in its parent) durable, so a synced part is never lost with a volatile directory.
    pub fn ensure_dirs(&self) -> Result<(), FsError> {
        self.fs.create_dir_all(&self.kind_dir(CacheKind::Frame))?;
        self.fs.create_dir_all(&self.kind_dir(CacheKind::Pack))?;
        self.fs.sync_dir(&self.dir)?;
        if let Some(parent) = self.dir.parent() {
            self.fs.sync_dir(parent)?;
        }
        Ok(())
    }

    /// Whether the complete entry exists as a regular file of exactly `size` bytes. A complete
    /// entry of another size is removed (it can only be damage).
    pub fn is_complete(
        &self,
        kind: CacheKind,
        sha: &Sha256Digest,
        size: u64,
    ) -> Result<bool, FsError> {
        let path = self.path(kind, sha);
        match self.fs.symlink_metadata(&path)? {
            None => Ok(false),
            Some(meta) if meta.kind == FileKind::File && meta.len == size => Ok(true),
            Some(meta) => {
                remove_any(&*self.fs, &path, meta.kind)?;
                Ok(false)
            }
        }
    }

    /// The length of the entry's `.part`, or 0. A part longer than `signed` bytes, or one that is
    /// not a regular file, is deleted with its sidecar and reads as 0.
    pub fn part_len(
        &self,
        kind: CacheKind,
        sha: &Sha256Digest,
        signed: u64,
    ) -> Result<u64, FsError> {
        let path = self.part_path(kind, sha);
        match self.fs.symlink_metadata(&path)? {
            None => Ok(0),
            Some(meta) if meta.kind == FileKind::File && meta.len <= signed => Ok(meta.len),
            Some(meta) => {
                remove_any(&*self.fs, &path, meta.kind)?;
                ignore_missing(self.fs.remove_file(&self.meta_path(kind, sha)))?;
                Ok(0)
            }
        }
    }

    /// The `If-Range` validator stored for the entry's part, when its sidecar is readable, of this
    /// format, written for `url_sha256`, and the validator still passes the core's rules.
    pub fn stored_validator(
        &self,
        kind: CacheKind,
        sha: &Sha256Digest,
        url_sha256: &Sha256Digest,
    ) -> Option<Validator> {
        let bytes = self
            .fs
            .read_capped(&self.meta_path(kind, sha), META_CAP)
            .ok()?;
        let meta: PartMeta = parse_strict(&bytes).ok()?;
        if meta.format != META_FORMAT || meta.url_sha256 != *url_sha256 {
            return None;
        }
        match meta.validator? {
            MetaValidator::Etag(v) => Validator::from_etag(v.as_bytes()),
            MetaValidator::LastModified(v) => Validator::from_last_modified(v.as_bytes()),
        }
    }

    /// Replaces the entry's sidecar (synced). Not atomic: a torn sidecar is unreadable, which only
    /// costs the `If-Range` of the next resume.
    fn write_meta(
        &self,
        kind: CacheKind,
        sha: &Sha256Digest,
        validator: Option<&Validator>,
        url_sha256: &Sha256Digest,
    ) -> Result<(), Error> {
        let meta = PartMeta {
            format: META_FORMAT,
            validator: validator.map(|v| match v {
                Validator::StrongETag(t) => MetaValidator::Etag(t.clone()),
                Validator::LastModified(t) => MetaValidator::LastModified(t.clone()),
            }),
            url_sha256: *url_sha256,
        };
        let bytes = serde_json::to_vec(&meta)
            .map_err(|_| Error::Config("cache sidecar could not be encoded"))?;
        let path = self.meta_path(kind, sha);
        ignore_missing(self.fs.remove_file(&path))?;
        let mut file = self.fs.create_new(&path)?;
        file.write_all(&bytes).map_err(|e| io_error(e, &path))?;
        file.sync()?;
        Ok(())
    }

    /// Removes the entry: the complete file, the part and the sidecar (each if present).
    pub fn remove_entry(&self, kind: CacheKind, sha: &Sha256Digest) -> Result<(), FsError> {
        self.remove_part(kind, sha)?;
        ignore_missing(self.fs.remove_file(&self.path(kind, sha)))
    }

    /// Removes the entry's part and sidecar (each if present).
    pub fn remove_part(&self, kind: CacheKind, sha: &Sha256Digest) -> Result<(), FsError> {
        ignore_missing(self.fs.remove_file(&self.part_path(kind, sha)))?;
        ignore_missing(self.fs.remove_file(&self.meta_path(kind, sha)))
    }

    /// Removes every entry of `frames/` and `packs/` that `keep_frames` and `keep_packs` do not
    /// name (complete files, parts and sidecars alike), and anything else found there.
    pub fn cleanup(
        &self,
        keep_frames: &HashSet<Sha256Digest>,
        keep_packs: &HashSet<Sha256Digest>,
    ) -> Result<(), FsError> {
        for (kind, keep) in [
            (CacheKind::Frame, keep_frames),
            (CacheKind::Pack, keep_packs),
        ] {
            let dir = self.kind_dir(kind);
            let entries = match self.fs.list_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind == FsErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let mut removed = false;
            for entry in entries {
                let named = entry.name.to_str().and_then(entry_digest);
                if named.is_some_and(|sha| keep.contains(&sha)) {
                    continue;
                }
                remove_any(&*self.fs, &dir.join(&entry.name), entry.kind)?;
                removed = true;
            }
            if removed {
                self.fs.sync_dir(&dir)?;
            }
        }
        Ok(())
    }
}

/// The digest an entry name stands for: `<hex>`, `<hex>.part` or `<hex>.meta`.
fn entry_digest(name: &str) -> Option<Sha256Digest> {
    let stem = name
        .strip_suffix(".part")
        .or_else(|| name.strip_suffix(".meta"))
        .unwrap_or(name);
    Sha256Digest::from_hex(stem).ok()
}

fn remove_any(fs: &dyn Fs, path: &Path, kind: FileKind) -> Result<(), FsError> {
    if kind == FileKind::Dir {
        ignore_missing(fs.remove_dir_all_nofollow(path))
    } else {
        ignore_missing(fs.remove_file(path))
    }
}

fn io_error(e: std::io::Error, path: &Path) -> Error {
    Error::Fs(FsError::from_io(path, e))
}

/// Feeds the first `len` bytes of the file at `path` to `state`.
fn hash_prefix(
    fs: &dyn Fs,
    path: &Path,
    len: u64,
    state: &mut Box<dyn HashState>,
) -> Result<(), FsError> {
    if len == 0 {
        return Ok(());
    }
    let file = fs.open_read(path)?;
    let mut buf = vec![0u8; HASH_READ];
    let mut at = 0u64;
    while at < len {
        let n = usize::try_from((len - at).min(HASH_READ as u64)).unwrap_or(HASH_READ);
        file.read_exact_at(at, &mut buf[..n])?;
        state.update(&buf[..n]);
        at += n as u64;
    }
    Ok(())
}

/// One part being written: open file, running hash, bytes in the part so far.
struct OpenPart {
    file: Box<dyn FileWrite>,
    hash: Box<dyn HashState>,
    written: u64,
}

impl Cache {
    /// Opens the entry's part for writing. `resume_from > 0` appends to the existing part of that
    /// length (its bytes are hashed first); otherwise any old part is replaced by an empty one and
    /// a fresh sidecar.
    fn open_part(
        &self,
        hasher: &dyn Hasher,
        kind: CacheKind,
        sha: &Sha256Digest,
        resume_from: u64,
        validator: Option<&Validator>,
        url_sha256: &Sha256Digest,
    ) -> Result<OpenPart, Error> {
        let path = self.part_path(kind, sha);
        let mut hash = hasher.sha256_start();
        if resume_from > 0 {
            hash_prefix(&*self.fs, &path, resume_from, &mut hash)?;
            // Bytes past `resume_from` (none, unless the part grew since it was measured) would
            // be appended after; cut them so the part is exactly the hashed prefix.
            self.fs.truncate(&path, resume_from)?;
            let file = self.fs.open_append(&path)?;
            return Ok(OpenPart {
                file,
                hash,
                written: resume_from,
            });
        }
        self.remove_part(kind, sha)?;
        self.write_meta(kind, sha, validator, url_sha256)?;
        let file = self.fs.create_new(&path)?;
        Ok(OpenPart {
            file,
            hash,
            written: 0,
        })
    }

    /// Syncs a part and makes it the complete entry if its hash is `sha`; otherwise deletes it.
    /// Whether it matched.
    fn finish_part(
        &self,
        kind: CacheKind,
        sha: &Sha256Digest,
        mut part: OpenPart,
    ) -> Result<bool, Error> {
        part.file
            .flush()
            .map_err(|e| io_error(e, &self.part_path(kind, sha)))?;
        part.file.sync()?;
        drop(part.file);
        let ok = part.hash.finalize() == *sha;
        let dir = self.kind_dir(kind);
        if ok {
            let complete = self.path(kind, sha);
            ignore_missing(self.fs.remove_file(&complete))?;
            self.fs.rename(&self.part_path(kind, sha), &complete)?;
            ignore_missing(self.fs.remove_file(&self.meta_path(kind, sha)))?;
        } else {
            self.remove_part(kind, sha)?;
        }
        self.fs.sync_dir(&dir)?;
        Ok(ok)
    }
}

/// A frame a run writes: where it sits in the pack and what it must hash to.
#[derive(Debug, Clone)]
pub(crate) struct RunTarget {
    pub(crate) sha: Sha256Digest,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    /// Bytes of an existing part to keep and append to (only the run's first frame).
    pub(crate) resume_from: u64,
}

/// What a writer reports when its stream ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteReport {
    /// Every target is complete (a frame whose hash failed is listed in `bad`).
    Complete { bad: Vec<Sha256Digest> },
    /// The stream ended early; parts are synced for a resume.
    Incomplete { bad: Vec<Sha256Digest> },
    /// The pack's bytes did not hash to `pack.sha256`; its part is deleted.
    PackHashMismatch,
    /// The writer was told to drop its parts, or the stream was aborted.
    Stopped,
}

struct RunSlot {
    target: RunTarget,
    part: Option<OpenPart>,
    done: bool,
}

/// Writes one range response's body into frame parts, split at frame boundaries (a byte that lies
/// in several overlapping frames goes to each). Runs on a writer job.
pub(crate) struct RunWriter {
    cache: Cache,
    hasher: Arc<dyn Hasher>,
    slots: Vec<RunSlot>,
    /// Pack offset of the next body byte.
    pos: u64,
    validator: Option<Validator>,
    url_sha256: Sha256Digest,
    bad: Vec<Sha256Digest>,
}

impl RunWriter {
    pub(crate) fn new(
        cache: Cache,
        hasher: Arc<dyn Hasher>,
        targets: Vec<RunTarget>,
        start: u64,
        validator: Option<Validator>,
        url_sha256: Sha256Digest,
    ) -> Self {
        RunWriter {
            cache,
            hasher,
            slots: targets
                .into_iter()
                .map(|target| RunSlot {
                    target,
                    part: None,
                    done: false,
                })
                .collect(),
            pos: start,
            validator,
            url_sha256,
            bad: Vec::new(),
        }
    }

    /// Writes the body bytes at the current position.
    pub(crate) fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        let chunk_start = self.pos;
        let chunk_end = chunk_start.saturating_add(chunk.len() as u64);
        for i in 0..self.slots.len() {
            if self.slots[i].done {
                continue;
            }
            let t = self.slots[i].target.clone();
            let frame_end = t.offset.saturating_add(t.length);
            if chunk_end <= t.offset || chunk_start >= frame_end {
                continue;
            }
            if self.slots[i].part.is_none() {
                let part = self.cache.open_part(
                    &*self.hasher,
                    CacheKind::Frame,
                    &t.sha,
                    t.resume_from,
                    self.validator.as_ref(),
                    &self.url_sha256,
                )?;
                self.slots[i].part = Some(part);
            }
            let Some(part) = self.slots[i].part.as_mut() else {
                continue;
            };
            // The next byte this frame needs, as a pack offset.
            let want = t.offset + part.written;
            let from = chunk_start.max(want);
            let to = chunk_end.min(frame_end);
            if from >= to {
                continue;
            }
            if from != want {
                // A gap would leave a hole in the frame: the run was planned wrong. Never write
                // around it.
                return Err(Error::Config("frame bytes arrived out of order"));
            }
            let slice = &chunk[(from - chunk_start) as usize..(to - chunk_start) as usize];
            part.file
                .write_all(slice)
                .map_err(|e| io_error(e, &self.cache.part_path(CacheKind::Frame, &t.sha)))?;
            part.hash.update(slice);
            part.written += slice.len() as u64;
            if part.written == t.length {
                let Some(part) = self.slots[i].part.take() else {
                    continue;
                };
                self.slots[i].done = true;
                if !self.cache.finish_part(CacheKind::Frame, &t.sha, part)? {
                    self.bad.push(t.sha);
                }
            }
        }
        self.pos = chunk_end;
        Ok(())
    }

    /// Syncs the open parts (they stay for a resume).
    fn sync_open(&mut self) -> Result<(), Error> {
        let mut any = false;
        for slot in &mut self.slots {
            if let Some(part) = slot.part.as_mut() {
                part.file.flush().map_err(|e| {
                    io_error(e, &self.cache.part_path(CacheKind::Frame, &slot.target.sha))
                })?;
                part.file.sync()?;
                any = true;
            }
        }
        if any {
            self.cache
                .fs
                .sync_dir(&self.cache.kind_dir(CacheKind::Frame))?;
        }
        Ok(())
    }

    /// The body ended normally.
    pub(crate) fn end(mut self) -> Result<WriteReport, Error> {
        let complete = self.slots.iter().all(|s| s.done);
        self.sync_open()?;
        let bad = std::mem::take(&mut self.bad);
        Ok(if complete {
            WriteReport::Complete { bad }
        } else {
            WriteReport::Incomplete { bad }
        })
    }

    /// The stream was aborted (cancel, a dropped future): keep and sync what is written.
    pub(crate) fn abort(mut self) -> WriteReport {
        let _ = self.sync_open();
        WriteReport::Stopped
    }
}

/// Writes a pack download into `packs/<sha>.part`. Runs on a writer job.
pub(crate) struct PackWriter {
    cache: Cache,
    sha: Sha256Digest,
    size: u64,
    part: OpenPart,
}

impl PackWriter {
    /// `resume_from > 0` appends to the existing part of that length (a matching `206`); `0`
    /// starts an empty part (a `200`, or nothing to resume).
    pub(crate) fn new(
        cache: Cache,
        hasher: &dyn Hasher,
        sha: Sha256Digest,
        size: u64,
        resume_from: u64,
        validator: Option<Validator>,
        url_sha256: Sha256Digest,
    ) -> Result<Self, Error> {
        let part = cache.open_part(
            hasher,
            CacheKind::Pack,
            &sha,
            resume_from,
            validator.as_ref(),
            &url_sha256,
        )?;
        Ok(PackWriter {
            cache,
            sha,
            size,
            part,
        })
    }

    /// Appends body bytes. The caller never sends more than `size` in all; a writer that would
    /// pass it refuses.
    pub(crate) fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        let len = chunk.len() as u64;
        if self.part.written.saturating_add(len) > self.size {
            return Err(Error::Verify(lunepack_core::Error::TooLarge {
                what: "pack download",
                size: self.part.written.saturating_add(len),
                cap: self.size,
            }));
        }
        self.part
            .file
            .write_all(chunk)
            .map_err(|e| io_error(e, &self.cache.part_path(CacheKind::Pack, &self.sha)))?;
        self.part.hash.update(chunk);
        self.part.written += len;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), Error> {
        self.part
            .file
            .flush()
            .map_err(|e| io_error(e, &self.cache.part_path(CacheKind::Pack, &self.sha)))?;
        self.part.file.sync()?;
        self.cache
            .fs
            .sync_dir(&self.cache.kind_dir(CacheKind::Pack))?;
        Ok(())
    }

    /// The body ended normally: a full part is checked and completed, a short one synced.
    pub(crate) fn end(mut self) -> Result<WriteReport, Error> {
        if self.part.written < self.size {
            self.sync()?;
            return Ok(WriteReport::Incomplete { bad: Vec::new() });
        }
        if self
            .cache
            .finish_part(CacheKind::Pack, &self.sha, self.part)?
        {
            Ok(WriteReport::Complete { bad: Vec::new() })
        } else {
            Ok(WriteReport::PackHashMismatch)
        }
    }

    /// The stream was aborted: keep and sync the part.
    pub(crate) fn abort(mut self) -> WriteReport {
        let _ = self.sync();
        WriteReport::Stopped
    }

    /// The response broke its cap: delete the part and its sidecar.
    pub(crate) fn discard(self) -> Result<WriteReport, Error> {
        let PackWriter {
            cache, sha, part, ..
        } = self;
        drop(part);
        cache.remove_part(CacheKind::Pack, &sha)?;
        Ok(WriteReport::Stopped)
    }
}

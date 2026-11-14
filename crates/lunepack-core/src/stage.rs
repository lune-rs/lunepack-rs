//! The stage engine (C3, M4 step 7): [`scan`] finds the files of the current tree that a new
//! version keeps unchanged (M4-D7), and [`stage`] builds and verifies the new version's tree from
//! its sources, in bounded parallel under a memory budget (M4-D11, M4-D12), resumably.
//!
//! Both are sync and run over the core's traits only ([`Fs`], [`Codec`], [`Hasher`]); they read no
//! ambient parallelism, clock or filesystem. With `workers <= 1` everything runs on the calling
//! thread; otherwise on `std::thread::scope` threads, and progress events are still delivered on the
//! calling thread, in the order the workers produced them.
//!
//! Layout (M4-D4, M4-D18): version `V` is built in `<versions_dir>/<V>.partial` and renamed to
//! `<versions_dir>/<V>` once every file is verified and every directory synced. A file is written
//! to a temporary `~<entry index>.lptmp` beside its final name (a name no manifest path can have:
//! `~` followed by a digit is refused by [`crate::validate_path`]), synced, and renamed into place
//! only after its bytes matched the signed SHA-256. No write ever passes through a symlink: the
//! partial tree's symlinks are all removed (never followed) before anything is written, the
//! manifest's own symlinks are created last, and [`Fs::create_dir_all`] refuses symlinked
//! components.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError, mpsc};

use crate::cancel::CancelToken;
use crate::digest::Sha256Digest;
use crate::error::{Error, StageError};
use crate::frame::{CheckedFrame, decode_verified, decoder_memory};
use crate::fs::{FileKind, FileWrite, Fs, FsError, FsErrorKind, Meta};
use crate::manifest::{VerifiedEntry, VerifiedManifest};
use crate::path::RelPath;
use crate::progress::{FileProgress, Phase, Progress, Source};
use crate::target::Target;
use crate::traits::{Codec, Hasher};
use crate::version::Version;

/// I/O buffer bytes charged to every job on top of its frame and decoder (M4-D11); also the chunk
/// size of hashing reads and copies.
pub const IO_BUFFER_BYTES: u64 = 256 * 1024;
/// Suffix of the directory a version is built in.
pub const PARTIAL_SUFFIX: &str = ".partial";
/// Suffix of a file being written; a leftover one is removed when a stage resumes.
pub const TMP_SUFFIX: &str = ".lptmp";

/// Where the bytes of one manifest entry come from. Only file entries with at least one byte use
/// their source; the source of a directory, a symlink or an empty file is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFor {
    /// A file of the current tree, copied while hashing (from [`scan`]).
    Unchanged(PathBuf),
    /// A cache file holding exactly the entry's frame.
    Frame(PathBuf),
    /// The full pack file.
    Pack(PathBuf),
    /// Reserved: a delta patch. Always [`StageError::Unsupported`].
    Patch,
}

/// What to stage.
#[derive(Debug)]
pub struct StageInput<'a> {
    /// The verified manifest of the version.
    pub manifest: &'a VerifiedManifest,
    /// The directory holding version trees; the tree is `<versions_dir>/<version text>`.
    pub versions_dir: PathBuf,
    /// One source per manifest entry, in manifest order.
    pub sources: Vec<SourceFor>,
}

/// The capabilities and limits a stage runs with.
pub struct StageEnv<'a> {
    /// The filesystem.
    pub fs: &'a dyn Fs,
    /// The frame decoder.
    pub codec: &'a dyn Codec,
    /// SHA-256.
    pub hasher: &'a dyn Hasher,
    /// Parallel jobs at most; `0` and `1` run inline on the calling thread.
    pub workers: usize,
    /// The concurrent sum of job costs (`frame.length + decoder_memory(frame) + 256 KiB`) stays at
    /// or below this, except that a job above it runs alone.
    pub budget_bytes: u64,
    /// Checked between jobs and on every write.
    pub cancel: &'a CancelToken,
    /// Progress events ([`Phase::Stage`]), delivered on the calling thread.
    pub progress: &'a dyn Fn(Progress),
}

/// A staged version tree: every file verified and synced, the directory renamed into place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVersion {
    /// The version.
    pub version: Version,
    /// Its target.
    pub target: Target,
    /// `<versions_dir>/<version text>`.
    pub tree: PathBuf,
}

// ---------------------------------------------------------------------------------------------
// The job pool.

struct Sched {
    next: usize,
    in_use: u64,
    running: usize,
    stop: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every critical section here only adds and subtracts counters; a panic cannot leave them
    // half-edited beyond what the release guard repairs.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Takes the next job in order when its cost fits beside the running ones, or when nothing runs.
fn take(
    sched: &Mutex<Sched>,
    cv: &Condvar,
    costs: &[u64],
    budget: u64,
    cancel: &CancelToken,
) -> Option<usize> {
    let mut st = lock(sched);
    loop {
        if st.stop || cancel.is_cancelled() || st.next >= costs.len() {
            return None;
        }
        let cost = costs[st.next];
        if st.running == 0 || st.in_use.saturating_add(cost) <= budget {
            let i = st.next;
            st.next += 1;
            st.in_use = st.in_use.saturating_add(cost);
            st.running += 1;
            return Some(i);
        }
        st = cv.wait(st).unwrap_or_else(PoisonError::into_inner);
    }
}

/// Gives a job's cost back when the job ends, normally or by a panic (which also stops the pool,
/// so no waiter is left waiting for a slot that never frees).
struct Release<'s> {
    sched: &'s Mutex<Sched>,
    cv: &'s Condvar,
    cost: u64,
    stop: bool,
}

impl Drop for Release<'_> {
    fn drop(&mut self) {
        let mut st = lock(self.sched);
        st.in_use = st.in_use.saturating_sub(self.cost);
        st.running -= 1;
        if self.stop || std::thread::panicking() {
            st.stop = true;
        }
        drop(st);
        self.cv.notify_all();
    }
}

/// Runs `job(i, report)` for every `i` in `0..costs.len()`, in order of start, on at most `workers`
/// threads, keeping the concurrent sum of costs within `budget` (a job above it runs alone). A job
/// returns its result and whether the pool must stop starting jobs. `report(done)` events reach
/// `on_event(i, done)` on the calling thread. A job not started (cancel or stop) has `None`.
fn run_pool<R, F, E>(
    workers: usize,
    budget: u64,
    costs: &[u64],
    cancel: &CancelToken,
    job: F,
    mut on_event: E,
) -> Vec<Option<R>>
where
    R: Send,
    F: Fn(usize, &dyn Fn(u64)) -> (R, bool) + Sync,
    E: FnMut(usize, u64),
{
    let n = costs.len();
    let threads = workers.max(1).min(n);
    if threads <= 1 {
        let mut results: Vec<Option<R>> = (0..n).map(|_| None).collect();
        let sink = RefCell::new(&mut on_event);
        for (i, slot) in results.iter_mut().enumerate() {
            if cancel.is_cancelled() {
                break;
            }
            let (r, stop) = job(i, &|done| (*sink.borrow_mut())(i, done));
            *slot = Some(r);
            if stop {
                break;
            }
        }
        return results;
    }

    let sched = Mutex::new(Sched {
        next: 0,
        in_use: 0,
        running: 0,
        stop: false,
    });
    let cv = Condvar::new();
    let slots: Vec<Mutex<Option<R>>> = (0..n).map(|_| Mutex::new(None)).collect();
    let (tx, rx) = mpsc::channel::<(usize, u64)>();
    std::thread::scope(|s| {
        for _ in 0..threads {
            let tx = tx.clone();
            let (sched, cv, slots, job) = (&sched, &cv, &slots, &job);
            s.spawn(move || {
                while let Some(i) = take(sched, cv, costs, budget, cancel) {
                    let mut release = Release {
                        sched,
                        cv,
                        cost: costs[i],
                        stop: false,
                    };
                    let (r, stop) = job(i, &|done| {
                        // The receiver lives until every worker is done; a send only fails when
                        // the caller's progress callback panicked, and then events don't matter.
                        let _ = tx.send((i, done));
                    });
                    *lock(&slots[i]) = Some(r);
                    release.stop = stop;
                }
            });
        }
        drop(tx);
        for (i, done) in rx {
            on_event(i, done);
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(PoisonError::into_inner))
        .collect()
}

/// Turns per-job byte counts into overall progress events.
struct Agg<'a> {
    phase: Phase,
    total: u64,
    done: u64,
    last: Vec<u64>,
    files: Vec<(&'a RelPath, u64, Source)>,
    progress: &'a dyn Fn(Progress),
}

impl Agg<'_> {
    fn on(&mut self, k: usize, file_done: u64) {
        let (path, size, source) = self.files[k];
        if file_done > self.last[k] {
            self.done = self.done.saturating_add(file_done - self.last[k]);
            self.last[k] = file_done;
        }
        (self.progress)(Progress {
            phase: self.phase,
            done: self.done.min(self.total),
            total: self.total,
            file: Some(FileProgress {
                path: path.clone(),
                done: file_done,
                total: size,
                source,
            }),
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Shared helpers.

/// `base` joined with a validated relative path, component by component.
fn join(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
    }
    p
}

/// Why a job did not place its file.
enum JobErr {
    /// The source is unusable: the file needs fetching.
    Source,
    /// The cancel token was cancelled.
    Cancelled,
    /// The destination failed (or the filesystem crashed).
    Dest(FsError),
}

/// A source read error: the source is unusable, unless the filesystem itself is gone.
fn src_err(e: FsError) -> JobErr {
    if e.kind == FsErrorKind::Crashed {
        JobErr::Dest(e)
    } else {
        JobErr::Source
    }
}

/// Hashes the first `len` bytes of the file at `path`, checking `cancel` per chunk. `Ok(None)`
/// when the file cannot be read that far.
fn hash_file(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    cancel: &CancelToken,
    path: &Path,
    len: u64,
    report: &dyn Fn(u64),
) -> Result<Option<Sha256Digest>, JobErr> {
    let reader = match fs.open_read(path) {
        Ok(r) => r,
        Err(e) => return src_err(e).none_unless_fatal(),
    };
    let mut state = hasher.sha256_start();
    let mut buf = vec![0u8; IO_BUFFER_BYTES.min(len) as usize];
    let mut off = 0u64;
    while off < len {
        if cancel.is_cancelled() {
            return Err(JobErr::Cancelled);
        }
        let n = (len - off).min(buf.len() as u64) as usize;
        if let Err(e) = reader.read_exact_at(off, &mut buf[..n]) {
            return src_err(e).none_unless_fatal();
        }
        state.update(&buf[..n]);
        off += n as u64;
        report(off);
    }
    Ok(Some(state.finalize()))
}

impl JobErr {
    fn none_unless_fatal<T>(self) -> Result<Option<T>, JobErr> {
        match self {
            JobErr::Source => Ok(None),
            other => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Scan (M4-D7).

enum ScanResult {
    Match,
    NoMatch,
    Cancelled,
    Crashed(FsError),
}

/// For each manifest entry, the path of a regular file in `current_tree` at the same relative
/// path with the same size and SHA-256 (M4-D7), else `None` (always `None` for directories,
/// symlinks and empty files). No symlink in the current tree is followed: every component of an
/// entry's path is checked with [`Fs::symlink_metadata`] to be a real directory, and the file
/// itself a regular file. A current tree that is `None` or not a real directory yields no match.
///
/// A current-tree file that cannot be read is not a match. Fails only when `cancel` is cancelled
/// ([`Error::Cancelled`]) or the filesystem fails as a whole. Hashing runs on up to `workers`
/// threads; [`Phase::Scan`] events (per file, [`Source::Unchanged`], total = bytes of the files
/// hashed) are delivered on the calling thread.
pub fn scan(
    manifest: &VerifiedManifest,
    current_tree: Option<&Path>,
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    workers: usize,
    cancel: &CancelToken,
    progress: &dyn Fn(Progress),
) -> Result<Vec<Option<PathBuf>>, Error> {
    let entries = manifest.entries();
    let mut out: Vec<Option<PathBuf>> = vec![None; entries.len()];
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let Some(root) = current_tree else {
        return Ok(out);
    };
    if !is_kind(fs, root, FileKind::Dir)? {
        return Ok(out);
    }

    // Candidates: same relative path, every parent a real directory, a regular file of equal size.
    let mut dirs: BTreeMap<String, bool> = BTreeMap::new();
    let mut cands: Vec<(usize, &RelPath, u64, Sha256Digest, PathBuf)> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let VerifiedEntry::File {
            path, size, sha256, ..
        } = e
        else {
            continue;
        };
        if *size == 0 {
            continue;
        }
        let text = path.as_str();
        let mut parents_ok = true;
        for (pos, _) in text.match_indices('/') {
            let prefix = &text[..pos];
            let ok = match dirs.get(prefix) {
                Some(&ok) => ok,
                None => {
                    let ok = is_kind(fs, &join(root, prefix), FileKind::Dir)?;
                    dirs.insert(prefix.to_owned(), ok);
                    ok
                }
            };
            if !ok {
                parents_ok = false;
                break;
            }
        }
        if !parents_ok {
            continue;
        }
        let file = join(root, text);
        match fs.symlink_metadata(&file) {
            Ok(Some(Meta {
                kind: FileKind::File,
                len,
            })) if len == *size => cands.push((i, path, *size, *sha256, file)),
            Ok(_) => {}
            Err(e) if e.kind == FsErrorKind::Crashed => return Err(e.into()),
            Err(_) => {}
        }
    }

    let costs = vec![0u64; cands.len()];
    let mut agg = Agg {
        phase: Phase::Scan,
        total: cands.iter().map(|c| c.2).sum(),
        done: 0,
        last: vec![0; cands.len()],
        files: cands
            .iter()
            .map(|c| (c.1, c.2, Source::Unchanged))
            .collect(),
        progress,
    };
    let results = run_pool(
        workers,
        u64::MAX,
        &costs,
        cancel,
        |k, report| {
            let (_, _, size, sha256, file) = &cands[k];
            match hash_file(fs, hasher, cancel, file, *size, report) {
                Ok(Some(d)) if d == *sha256 => (ScanResult::Match, false),
                Ok(_) => (ScanResult::NoMatch, false),
                Err(JobErr::Cancelled) => (ScanResult::Cancelled, true),
                Err(JobErr::Dest(e)) => (ScanResult::Crashed(e), true),
                Err(JobErr::Source) => (ScanResult::NoMatch, false),
            }
        },
        |k, done| agg.on(k, done),
    );
    let mut cancelled = cancel.is_cancelled();
    for (k, r) in results.into_iter().enumerate() {
        match r {
            Some(ScanResult::Match) => out[cands[k].0] = Some(cands[k].4.clone()),
            Some(ScanResult::NoMatch) => {}
            Some(ScanResult::Cancelled) | None => cancelled = true,
            Some(ScanResult::Crashed(e)) => return Err(e.into()),
        }
    }
    if cancelled {
        return Err(Error::Cancelled);
    }
    Ok(out)
}

/// Whether `path` is of `kind` (symlinks not followed); a crashed filesystem is an error.
fn is_kind(fs: &dyn Fs, path: &Path, kind: FileKind) -> Result<bool, Error> {
    match fs.symlink_metadata(path) {
        Ok(Some(m)) => Ok(m.kind == kind),
        Ok(None) => Ok(false),
        Err(e) if e.kind == FsErrorKind::Crashed => Err(e.into()),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------------------------
// Stage (C3).

/// What the partial tree should hold at a relative path.
#[derive(Clone, Copy)]
enum Expect {
    Dir,
    /// A file: its index among the file jobs.
    File(usize),
    Symlink,
}

/// The `Sync` part of a [`StageEnv`] that jobs use (the progress callback stays on the caller).
struct Ctx<'a> {
    fs: &'a dyn Fs,
    codec: &'a dyn Codec,
    hasher: &'a dyn Hasher,
    cancel: &'a CancelToken,
}

/// One file entry to place.
struct FileJob<'a> {
    path: &'a RelPath,
    size: u64,
    sha256: Sha256Digest,
    exec: bool,
    frame: Option<&'a CheckedFrame>,
    source: &'a SourceFor,
    /// The length of a regular file already at its final path in the partial tree.
    existing: Option<u64>,
    dest: PathBuf,
    tmp: PathBuf,
}

/// A decoder's output: a temporary file, with cancel checked and progress reported on every write.
/// The reason a write failed is kept here, so a decode error can be told apart from a cancel or a
/// destination failure.
struct OutWriter<'a> {
    inner: Box<dyn FileWrite>,
    path: &'a Path,
    cancel: &'a CancelToken,
    fail: Option<JobErr>,
    written: u64,
    report: &'a dyn Fn(u64),
}

impl OutWriter<'_> {
    fn take_fail(&mut self) -> JobErr {
        self.fail.take().unwrap_or(JobErr::Source)
    }
}

impl Write for OutWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fail.is_some() {
            return Err(io::Error::other("the stage output failed earlier"));
        }
        if self.cancel.is_cancelled() {
            self.fail = Some(JobErr::Cancelled);
            return Err(io::Error::other("cancelled"));
        }
        match self.inner.write(buf) {
            Ok(n) => {
                self.written += n as u64;
                (self.report)(self.written);
                Ok(n)
            }
            Err(e) => {
                self.fail = Some(JobErr::Dest(FsError::from_io(self.path, e)));
                Err(io::Error::other("the stage output failed"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Err(e) = self.inner.flush() {
            self.fail
                .get_or_insert(JobErr::Dest(FsError::from_io(self.path, e)));
            return Err(io::Error::other("the stage output failed"));
        }
        Ok(())
    }
}

/// Builds and verifies the version tree of `input.manifest` (C3) in
/// `<versions_dir>/<version>.partial`, then renames it to `<versions_dir>/<version>`.
///
/// - Every placed file's bytes match the signed SHA-256 before its final name exists (Frame and
///   Pack sources through [`decode_verified`], Unchanged through a hashing copy); empty files are
///   created empty; files are created non-executable and made executable only when `exec` is set;
///   directories are created; symlinks are created last with the exact signed target text.
/// - A file whose source fails (hash mismatch, decode error, missing or short source) is
///   collected, its temporary file deleted, and the others continue: the result is
///   [`StageError::NeedFetch`] with those paths in manifest order, and the partial tree stays. A
///   failure of the destination is [`StageError::Other`].
/// - Resume: an existing partial tree is reused. Leftover temporary files, entries the manifest
///   does not list, every symlink, and anything of the wrong type at an entry's path are removed
///   without following symlinks; a placed file of the right size and hash is kept. An existing
///   `<version>` directory (a crash after the rename, before the caller's state commit) is moved
///   back to `.partial` and re-verified the same way before it is returned.
/// - Cancel is checked between jobs and on every write: [`StageError::Cancelled`], with no
///   temporary file left.
/// - The output does not depend on `workers`.
pub fn stage(input: &StageInput<'_>, env: &StageEnv<'_>) -> Result<StagedVersion, StageError> {
    let manifest = input.manifest;
    let entries = manifest.entries();
    if input.sources.len() != entries.len() {
        return Err(Error::Field("stage sources do not match the manifest entries").into());
    }
    if input.sources.iter().any(|s| matches!(s, SourceFor::Patch)) {
        return Err(StageError::Unsupported);
    }
    if env.cancel.is_cancelled() {
        return Err(StageError::Cancelled);
    }
    let fs = env.fs;
    let fs_err = |e: FsError| StageError::Other(Error::Fs(e));
    let name = manifest.version().to_string();
    let versions_dir = input.versions_dir.as_path();
    let tree = versions_dir.join(&name);
    let partial = versions_dir.join(format!("{name}{PARTIAL_SUFFIX}"));

    fs.create_dir_all(versions_dir).map_err(fs_err)?;
    prepare_partial(fs, &tree, &partial).map_err(fs_err)?;

    // What the tree holds: every entry, and every parent directory of one.
    let mut jobs: Vec<FileJob<'_>> = Vec::new();
    let mut expected: BTreeMap<&str, Expect> = BTreeMap::new();
    let mut dirs: BTreeSet<&str> = BTreeSet::new();
    let mut links: Vec<(&RelPath, &str)> = Vec::new();
    for (e, source) in entries.iter().zip(&input.sources) {
        let text = e.path().as_str();
        for (pos, _) in text.match_indices('/') {
            expected.entry(&text[..pos]).or_insert(Expect::Dir);
            dirs.insert(&text[..pos]);
        }
        match e {
            VerifiedEntry::File {
                path,
                size,
                sha256,
                exec,
                frame,
            } => {
                let dest = join(&partial, text);
                let tmp = dest.with_file_name(format!("~{}{TMP_SUFFIX}", jobs.len()));
                expected.insert(text, Expect::File(jobs.len()));
                jobs.push(FileJob {
                    path,
                    size: *size,
                    sha256: *sha256,
                    exec: *exec,
                    frame: frame.as_ref(),
                    source,
                    existing: None,
                    dest,
                    tmp,
                });
            }
            VerifiedEntry::Dir { .. } => {
                expected.insert(text, Expect::Dir);
                dirs.insert(text);
            }
            VerifiedEntry::Symlink { path, target } => {
                expected.insert(text, Expect::Symlink);
                links.push((path, target));
            }
        }
    }

    clean(fs, &partial, &expected, &mut jobs).map_err(fs_err)?;
    for d in &dirs {
        fs.create_dir_all(&join(&partial, d)).map_err(fs_err)?;
    }

    // Place the files.
    let costs: Vec<u64> = jobs
        .iter()
        .map(|j| match (j.frame, j.source) {
            (Some(f), SourceFor::Frame(_) | SourceFor::Pack(_)) => f
                .length()
                .saturating_add(decoder_memory(f))
                .saturating_add(IO_BUFFER_BYTES),
            _ => IO_BUFFER_BYTES,
        })
        .collect();
    let mut agg = Agg {
        phase: Phase::Stage,
        total: jobs.iter().map(|j| j.size).sum(),
        done: 0,
        last: vec![0; jobs.len()],
        files: jobs
            .iter()
            .map(|j| (j.path, j.size, progress_source(j.source)))
            .collect(),
        progress: env.progress,
    };
    let ctx = Ctx {
        fs,
        codec: env.codec,
        hasher: env.hasher,
        cancel: env.cancel,
    };
    let results = run_pool(
        env.workers,
        env.budget_bytes,
        &costs,
        env.cancel,
        |k, report| {
            let r = place(&ctx, &jobs[k], report);
            let stop = matches!(r, Err(JobErr::Cancelled | JobErr::Dest(_)));
            (r, stop)
        },
        |k, done| agg.on(k, done),
    );

    let mut need = Vec::new();
    let mut dest_err = None;
    let mut cancelled = env.cancel.is_cancelled();
    for (k, r) in results.into_iter().enumerate() {
        match r {
            Some(Ok(())) => {}
            Some(Err(JobErr::Source)) => need.push(jobs[k].path.clone()),
            Some(Err(JobErr::Cancelled)) => cancelled = true,
            Some(Err(JobErr::Dest(e))) => {
                dest_err.get_or_insert(e);
            }
            None => cancelled |= dest_err.is_none(),
        }
    }
    if let Some(e) = dest_err {
        return Err(fs_err(e));
    }
    if cancelled {
        return Err(StageError::Cancelled);
    }
    if !need.is_empty() {
        return Err(StageError::NeedFetch(need));
    }

    // Symlinks last, then make every directory entry durable, then the rename.
    for (path, target) in links {
        fs.symlink(target, &join(&partial, path.as_str()))
            .map_err(fs_err)?;
    }
    for d in dirs.iter().rev() {
        fs.sync_dir(&join(&partial, d)).map_err(fs_err)?;
    }
    fs.sync_dir(&partial).map_err(fs_err)?;
    if env.cancel.is_cancelled() {
        return Err(StageError::Cancelled);
    }
    fs.rename(&partial, &tree).map_err(fs_err)?;
    fs.sync_dir(versions_dir).map_err(fs_err)?;
    Ok(StagedVersion {
        version: manifest.version().clone(),
        target: manifest.target(),
        tree,
    })
}

fn progress_source(source: &SourceFor) -> Source {
    match source {
        SourceFor::Unchanged(_) => Source::Unchanged,
        SourceFor::Frame(_) => Source::Range,
        SourceFor::Pack(_) => Source::FullPack,
        SourceFor::Patch => Source::Patch,
    }
}

/// Removes whatever is at `path` without following a symlink; nothing there is fine.
fn remove_any(fs: &dyn Fs, path: &Path) -> Result<(), FsError> {
    match fs.symlink_metadata(path)? {
        None => Ok(()),
        Some(Meta {
            kind: FileKind::Dir,
            ..
        }) => fs.remove_dir_all_nofollow(path),
        Some(_) => fs.remove_file(path),
    }
}

/// Leaves a real directory at `partial`: an existing complete `tree` is moved back to it (to be
/// re-verified), anything else of the wrong type is removed.
fn prepare_partial(fs: &dyn Fs, tree: &Path, partial: &Path) -> Result<(), FsError> {
    match fs.symlink_metadata(tree)? {
        Some(Meta {
            kind: FileKind::Dir,
            ..
        }) => {
            remove_any(fs, partial)?;
            fs.rename(tree, partial)?;
        }
        Some(_) => fs.remove_file(tree)?,
        None => {}
    }
    match fs.symlink_metadata(partial)? {
        Some(Meta {
            kind: FileKind::Dir,
            ..
        }) => Ok(()),
        Some(_) => {
            fs.remove_file(partial)?;
            fs.create_dir_all(partial)
        }
        None => fs.create_dir_all(partial),
    }
}

/// Walks the partial tree (never following a symlink) and removes everything the manifest does
/// not expect there: unlisted entries, leftover temporary files, every symlink, and entries of the
/// wrong type. Records the length of each regular file found at a file entry's path.
fn clean(
    fs: &dyn Fs,
    partial: &Path,
    expected: &BTreeMap<&str, Expect>,
    jobs: &mut [FileJob<'_>],
) -> Result<(), FsError> {
    let mut stack: Vec<(PathBuf, String)> = vec![(partial.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for child in fs.list_dir(&dir)? {
            let path = dir.join(&child.name);
            let rel = child.name.to_str().map(|n| {
                if prefix.is_empty() {
                    n.to_owned()
                } else {
                    format!("{prefix}/{n}")
                }
            });
            match (rel.as_deref().and_then(|r| expected.get(r)), child.kind) {
                (Some(Expect::Dir), FileKind::Dir) => {
                    // `rel` is Some here: the lookup succeeded.
                    stack.push((path, rel.unwrap_or_default()));
                }
                (Some(&Expect::File(k)), FileKind::File) => {
                    jobs[k].existing = fs.symlink_metadata(&path)?.map(|m| m.len);
                }
                (_, FileKind::Dir) => fs.remove_dir_all_nofollow(&path)?,
                _ => fs.remove_file(&path)?,
            }
        }
    }
    Ok(())
}

/// Places one file: keeps a verified existing one, or produces it from its source into a
/// temporary file that is renamed into place after verification. On failure the temporary file
/// is removed.
fn place(env: &Ctx<'_>, job: &FileJob<'_>, report: &dyn Fn(u64)) -> Result<(), JobErr> {
    let fs = env.fs;
    if let Some(len) = job.existing {
        if len == job.size {
            let digest = hash_file(fs, env.hasher, env.cancel, &job.dest, len, &|_| {})?;
            if digest == Some(job.sha256) {
                fs.set_exec(&job.dest, job.exec).map_err(JobErr::Dest)?;
                report(job.size);
                return Ok(());
            }
        }
        fs.remove_file(&job.dest).map_err(JobErr::Dest)?;
    }
    report(0);
    let result = produce(env, job, report);
    if result.is_err() {
        match fs.remove_file(&job.tmp) {
            Ok(()) => {}
            Err(e) if e.kind == FsErrorKind::NotFound => {}
            Err(e) => {
                // The temporary file could not be removed: that is the destination failing.
                return Err(JobErr::Dest(e));
            }
        }
    }
    result
}

fn produce(env: &Ctx<'_>, job: &FileJob<'_>, report: &dyn Fn(u64)) -> Result<(), JobErr> {
    let fs = env.fs;
    // Read the frame's bytes (exactly its signed length) before creating anything.
    let frame_bytes = match (job.frame, job.source) {
        (Some(frame), SourceFor::Frame(p)) => {
            let bytes = fs.read_capped(p, frame.length()).map_err(src_err)?;
            if bytes.len() as u64 != frame.length() {
                return Err(JobErr::Source);
            }
            Some((frame, bytes))
        }
        (Some(frame), SourceFor::Pack(p)) => {
            let len = usize::try_from(frame.length()).map_err(|_| JobErr::Source)?;
            let reader = fs.open_read(p).map_err(src_err)?;
            let mut bytes = vec![0u8; len];
            reader
                .read_exact_at(frame.offset(), &mut bytes)
                .map_err(src_err)?;
            Some((frame, bytes))
        }
        _ => None,
    };
    let source = match (job.frame, job.source) {
        (Some(_), SourceFor::Unchanged(p)) => {
            match fs.symlink_metadata(p) {
                Ok(Some(Meta {
                    kind: FileKind::File,
                    len,
                })) if len == job.size => {}
                Ok(_) => return Err(JobErr::Source),
                Err(e) => return Err(src_err(e)),
            }
            Some(fs.open_read(p).map_err(src_err)?)
        }
        _ => None,
    };
    if env.cancel.is_cancelled() {
        return Err(JobErr::Cancelled);
    }

    let mut out = OutWriter {
        inner: fs.create_new(&job.tmp).map_err(JobErr::Dest)?,
        path: &job.tmp,
        cancel: env.cancel,
        fail: None,
        written: 0,
        report,
    };
    if let Some((frame, bytes)) = frame_bytes {
        if decode_verified(frame, &bytes, env.hasher, env.codec, &mut out).is_err() {
            return Err(out.take_fail());
        }
    } else if let Some(reader) = source {
        // A hashing copy: the bytes hashed are exactly the bytes written.
        let mut state = env.hasher.sha256_start();
        let mut buf = vec![0u8; IO_BUFFER_BYTES.min(job.size) as usize];
        let mut off = 0u64;
        while off < job.size {
            let n = (job.size - off).min(buf.len() as u64) as usize;
            reader.read_exact_at(off, &mut buf[..n]).map_err(src_err)?;
            state.update(&buf[..n]);
            if out.write_all(&buf[..n]).is_err() {
                return Err(out.take_fail());
            }
            off += n as u64;
        }
        if state.finalize() != job.sha256 {
            return Err(JobErr::Source);
        }
    } else if job.size != 0 {
        // A non-empty file without a usable source: only Patch, refused before any job runs.
        return Err(JobErr::Source);
    }
    if out.flush().is_err() {
        return Err(out.take_fail());
    }
    if env.cancel.is_cancelled() {
        return Err(JobErr::Cancelled);
    }
    out.inner.sync().map_err(JobErr::Dest)?;
    drop(out);
    if job.exec {
        fs.set_exec(&job.tmp, true).map_err(JobErr::Dest)?;
    }
    fs.rename(&job.tmp, &job.dest).map_err(JobErr::Dest)?;
    report(job.size);
    Ok(())
}

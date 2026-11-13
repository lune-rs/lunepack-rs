//! The packing pipeline of C2, stages 1 to 4 and the layout of stage 5: assemble (a copy of the
//! input in a work dir), code-sign, hash, pack. Each stage is a function, called in that order by
//! [`build`]; nothing after the hash stage reads the tree except by re-reading a file and comparing
//! it with the hash stage's SHA-256.
//!
//! Parallelism lives only in the pack stage ([`pack_jobs`]): workers take job indices in order from
//! a shared counter, a memory gate admits a job only when its estimate fits the budget (or nothing
//! else runs), and each result lands in the slot of its index. Everything after reads the slots in
//! index order, so neither the worker count nor the scheduling reaches the output bytes.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use anyhow::{Context, Result, anyhow, bail};
use lunepack_core::path::MAX_PATH_DEPTH;
use lunepack_core::{
    CodeSign, Codec, CodecId, Encoder, EntryKind, Hasher, ManifestDocument, PackedFile, RelPath,
    ReleaseLayout, Sha256Digest, Target, pack_file, validate_tree,
};

/// Fixed per-job allowance on top of the input, output and encoder estimates: 16 MiB of slack for
/// the decoder of the round trip and allocator overhead, 1 MiB for the decoder's fixed state.
const JOB_OVERHEAD: u64 = 16 * 1024 * 1024 + 1024 * 1024;

/// Read size of the hash stage.
const CHUNK: usize = 64 * 1024;

/// Every codec an encoder may be asked for; the estimate takes the largest of them.
const ENCODED_CODECS: [CodecId; 4] = [
    CodecId::Lzma2,
    CodecId::BcjX86Lzma2,
    CodecId::BcjArm64Lzma2,
    CodecId::Bcj2,
];

/// One entry of the hashed tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemKind {
    /// A directory.
    Dir,
    /// A symlink and its link text.
    Symlink(String),
    /// A regular file.
    File {
        /// Bytes read.
        size: u64,
        /// SHA-256 of the bytes read.
        sha256: Sha256Digest,
        /// Executable bit (Unix mode `& 0o111`; always false on other hosts).
        exec: bool,
    },
}

/// One path of the tree with what the hash stage found there.
#[derive(Debug, Clone)]
pub struct Item {
    /// The path relative to the tree's root.
    pub path: RelPath,
    /// What it is.
    pub kind: ItemKind,
}

/// The kind of a directory entry, without following symlinks; specials are an error.
enum Found {
    Dir,
    File,
    Symlink,
}

fn found(path: &Path) -> Result<(Found, fs::Metadata)> {
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        Found::Dir
    } else if ft.is_file() {
        Found::File
    } else if ft.is_symlink() {
        Found::Symlink
    } else {
        bail!(
            "{} is a special file (fifo, socket or device); only files, directories and symlinks can be packed",
            path.display()
        );
    };
    Ok((kind, meta))
}

/// The names in `dir`, sorted by bytes; a name that is not UTF-8 is an error.
fn names(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        let name = entry.file_name().into_string().map_err(|_| {
            anyhow!(
                "a name in {} is not UTF-8 and cannot be packed",
                dir.display()
            )
        })?;
        out.push(name);
    }
    out.sort();
    Ok(out)
}

fn link_text(path: &Path) -> Result<String> {
    let link = fs::read_link(path).with_context(|| format!("cannot read {}", path.display()))?;
    link.into_os_string()
        .into_string()
        .map_err(|_| anyhow!("the target of {} is not UTF-8", path.display()))
}

#[cfg(unix)]
fn make_symlink(text: &str, at: &Path) -> Result<()> {
    std::os::unix::fs::symlink(text, at).with_context(|| format!("cannot create {}", at.display()))
}

#[cfg(not(unix))]
fn make_symlink(_text: &str, at: &Path) -> Result<()> {
    bail!(
        "{} is a symlink; symlinks are packed only on Unix hosts",
        at.display()
    )
}

/// Stage 1: copies the tree at `input` into `dest` (which must not exist): files (with their
/// permissions), directories, and symlinks as links on Unix. A special file is refused; a hard link
/// is copied as a file.
pub fn assemble(input: &Path, dest: &Path) -> Result<()> {
    if !input.is_dir() {
        bail!("--input {} is not a directory", input.display());
    }
    fs::create_dir(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    copy_dir(input, dest, 0)
}

fn copy_dir(from: &Path, to: &Path, depth: usize) -> Result<()> {
    if depth >= MAX_PATH_DEPTH {
        bail!(
            "{} is nested more than {MAX_PATH_DEPTH} levels deep",
            from.display()
        );
    }
    for name in names(from)? {
        let (src, dst) = (from.join(&name), to.join(&name));
        match found(&src)?.0 {
            Found::Dir => {
                fs::create_dir(&dst).with_context(|| format!("cannot create {}", dst.display()))?;
                copy_dir(&src, &dst, depth + 1)?;
            }
            Found::File => {
                fs::copy(&src, &dst).with_context(|| format!("cannot copy {}", src.display()))?;
            }
            Found::Symlink => make_symlink(&link_text(&src)?, &dst)?,
        }
    }
    Ok(())
}

/// Every path under `root`, sorted by path bytes, with what it is.
fn walk(root: &Path) -> Result<Vec<(RelPath, PathBuf, Found, fs::Metadata)>> {
    let mut out = Vec::new();
    walk_into(root, "", &mut out, 0)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_into(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(RelPath, PathBuf, Found, fs::Metadata)>,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_PATH_DEPTH {
        bail!(
            "{} is nested more than {MAX_PATH_DEPTH} levels deep",
            dir.display()
        );
    }
    for name in names(dir)? {
        let rel = format!("{prefix}{name}");
        let full = dir.join(&name);
        let path = RelPath::parse(&rel).with_context(|| format!("{rel:?} cannot be packed"))?;
        let (kind, meta) = found(&full)?;
        let is_dir = matches!(kind, Found::Dir);
        out.push((path, full.clone(), kind, meta));
        if is_dir {
            walk_into(&full, &format!("{rel}/"), out, depth + 1)?;
        }
    }
    Ok(())
}

/// The code-signing order (C2 stage 2): the files under `root`, deepest first, then by path bytes.
pub fn sign_order(root: &Path) -> Result<Vec<RelPath>> {
    let mut files: Vec<RelPath> = walk(root)?
        .into_iter()
        .filter(|(_, _, kind, _)| matches!(kind, Found::File))
        .map(|(path, ..)| path)
        .collect();
    files.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    Ok(files)
}

#[cfg(unix)]
fn is_exec(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec(_meta: &fs::Metadata) -> bool {
    false
}

/// SHA-256 and length of the file at `path`, streamed through `hasher`.
fn hash_file(path: &Path, hasher: &dyn Hasher) -> Result<(u64, Sha256Digest)> {
    let mut file = File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut state = hasher.sha256_start();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        state.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, state.finalize()))
}

/// Stage 3: walks the tree at `root` into items sorted by path bytes, with each file's size,
/// SHA-256 and exec bit, then checks the tree rules for `target` before anything is encoded.
pub fn hash_tree(root: &Path, target: Target, hasher: &dyn Hasher) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for (path, full, kind, meta) in walk(root)? {
        let kind = match kind {
            Found::Dir => ItemKind::Dir,
            Found::Symlink => ItemKind::Symlink(link_text(&full)?),
            Found::File => {
                let (size, sha256) = hash_file(&full, hasher)?;
                ItemKind::File {
                    size,
                    sha256,
                    exec: is_exec(&meta),
                }
            }
        };
        items.push(Item { path, kind });
    }
    validate_tree(
        items.iter().map(|i| {
            let kind = match &i.kind {
                ItemKind::Dir => EntryKind::Dir,
                ItemKind::Symlink(link) => EntryKind::Symlink { target: link },
                ItemKind::File { .. } => EntryKind::File,
            };
            (&i.path, kind)
        }),
        target,
    )
    .context("the input tree cannot be packed")?;
    Ok(items)
}

/// One file to encode: the first of its (size, SHA-256) in path order.
#[derive(Debug, Clone)]
pub struct Job {
    /// Where to read it.
    pub file: PathBuf,
    /// Its path in the tree, for messages.
    pub path: RelPath,
    /// Size from the hash stage.
    pub size: u64,
    /// SHA-256 from the hash stage.
    pub sha256: Sha256Digest,
}

/// The memory one job may need, in bytes: the input, twice the input for the best candidate
/// `pack_file` keeps while the next one runs (a frame is kept only when shorter than the input,
/// and `LzmaCodec`'s buffer is at most twice the input from 65 bytes up; below that it fits
/// [`JOB_OVERHEAD`]), the largest `encode_memory` of any codec (one running `encode` call, its
/// intermediate and output buffers included), and [`JOB_OVERHEAD`]. The largest over all codecs
/// bounds the largest over the file's own candidates, which are known only once its bytes are
/// read.
pub fn estimate(size: u64, encoder: &dyn Encoder) -> u64 {
    let state = ENCODED_CODECS
        .iter()
        .map(|c| encoder.encode_memory(*c, size))
        .max()
        .unwrap_or(0);
    size.saturating_mul(3)
        .saturating_add(state)
        .saturating_add(JOB_OVERHEAD)
}

/// The memory gate: admits a job while `in_use + est <= budget`, or when nothing else is admitted
/// (a job over the whole budget still runs, alone).
struct Gate {
    in_use: Mutex<u64>,
    freed: Condvar,
    budget: u64,
}

/// An admitted job's share of the budget; returned on drop, so an error or a panic gives it back.
struct Permit<'a> {
    gate: &'a Gate,
    est: u64,
}

impl Gate {
    fn admit(&self, est: u64) -> Permit<'_> {
        let mut in_use = self.in_use.lock().unwrap_or_else(PoisonError::into_inner);
        while *in_use != 0 && in_use.saturating_add(est) > self.budget {
            in_use = self
                .freed
                .wait(in_use)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *in_use = in_use.saturating_add(est);
        Permit { gate: self, est }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut in_use = self
            .gate
            .in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *in_use = in_use.saturating_sub(self.est);
        self.gate.freed.notify_all();
    }
}

fn run_job(
    job: &Job,
    encoder: &dyn Encoder,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
) -> Result<PackedFile> {
    let bytes = fs::read(&job.file).with_context(|| format!("cannot read {}", job.path))?;
    if bytes.len() as u64 != job.size || hasher.sha256(&bytes) != job.sha256 {
        bail!("{}: file changed after hashing", job.path);
    }
    pack_file(&bytes, encoder, codec, hasher).with_context(|| format!("cannot pack {}", job.path))
}

/// Stage 4: encodes `jobs` on up to `workers` threads within `budget` bytes (see [`estimate`]).
///
/// Workers take indices in order; a taken job always runs to the end, and once any job fails no
/// further job is taken. Results are kept by index, so the output does not depend on `workers` or
/// on timing, and the error returned is the lowest-index one: every index below a failed one was
/// taken before it, and so ran.
pub fn pack_jobs(
    jobs: &[Job],
    workers: usize,
    budget: u64,
    encoder: &dyn Encoder,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
) -> Result<Vec<PackedFile>> {
    let gate = Gate {
        in_use: Mutex::new(0),
        freed: Condvar::new(),
        budget,
    };
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let slots: Mutex<Vec<Option<Result<PackedFile>>>> =
        Mutex::new((0..jobs.len()).map(|_| None).collect());
    let threads = workers.clamp(1, jobs.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::AcqRel);
                    let Some(job) = jobs.get(i) else { break };
                    let permit = gate.admit(estimate(job.size, encoder));
                    let result = run_job(job, encoder, codec, hasher);
                    drop(permit);
                    if result.is_err() {
                        stop.store(true, Ordering::Release);
                    }
                    slots.lock().unwrap_or_else(PoisonError::into_inner)[i] = Some(result);
                }
            });
        }
    });
    let slots = slots.into_inner().unwrap_or_else(PoisonError::into_inner);
    let mut out = Vec::with_capacity(jobs.len());
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(Ok(packed)) => out.push(packed),
            Some(Err(e)) => return Err(e),
            // Only possible after an error, which is returned first, at a lower index.
            None => bail!("internal error: job {i} did not run"),
        }
    }
    Ok(out)
}

/// What [`build`] reports.
#[derive(Debug, Default)]
pub struct Report {
    /// File entries.
    pub files: usize,
    /// Directory entries.
    pub dirs: usize,
    /// Symlink entries.
    pub symlinks: usize,
    /// Bytes of all file entries.
    pub input_bytes: u64,
    /// Distinct non-empty files encoded.
    pub unique: usize,
    /// File entries per codec id (`none` for empty files).
    pub per_codec: BTreeMap<&'static str, usize>,
    /// Candidates dropped: the path, the codec and the reason.
    pub dropped: Vec<(String, CodecId, String)>,
}

/// Settings of [`build`].
pub struct Settings<'a> {
    /// Encoder threads.
    pub workers: usize,
    /// Memory budget of the pack stage, in bytes.
    pub budget: u64,
    /// The code-signing hook.
    pub code_sign: &'a dyn CodeSign,
    /// The encoder.
    pub encoder: &'a dyn Encoder,
    /// The decoder of the round trip.
    pub codec: &'a dyn Codec,
    /// SHA-256.
    pub hasher: &'a dyn Hasher,
}

/// The unsigned result of stages 1 to 5.
pub struct Built {
    /// The manifest payload's document.
    pub manifest: ManifestDocument,
    /// The pack bytes.
    pub pack: Vec<u8>,
    /// Counts for the output.
    pub report: Report,
}

/// Runs C2 stages 1 to 4 in order over `input`, with `work` (an existing, empty directory) as the
/// work dir, then lays out the release (stage 5 without the signature) with `issued`. `say`
/// receives one line per stage.
pub fn build(
    input: &Path,
    work: &Path,
    layout: ReleaseLayout,
    target: Target,
    issued: u64,
    set: &Settings<'_>,
    say: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Built> {
    let tree = work.join("tree");
    assemble(input, &tree)?;
    say(&format!("assemble: copied {}", input.display()))?;

    let order = sign_order(&tree)?;
    set.code_sign
        .sign_tree(&tree, &order)
        .context("code signing failed")?;
    say(&format!("code-sign: {} file(s)", order.len()))?;

    let items = hash_tree(&tree, target, set.hasher)?;
    let mut report = Report::default();
    let mut jobs = Vec::new();
    let mut index: HashMap<(u64, [u8; 32]), usize> = HashMap::new();
    let mut job_of = Vec::with_capacity(items.len());
    for item in &items {
        let mut job = None;
        match &item.kind {
            ItemKind::Dir => report.dirs += 1,
            ItemKind::Symlink(_) => report.symlinks += 1,
            ItemKind::File { size, sha256, .. } => {
                report.files += 1;
                report.input_bytes = report.input_bytes.saturating_add(*size);
                if *size > 0 {
                    let key = (*size, *sha256.as_bytes());
                    let i = *index.entry(key).or_insert_with(|| {
                        jobs.push(Job {
                            file: tree.join(item.path.as_str()),
                            path: item.path.clone(),
                            size: *size,
                            sha256: *sha256,
                        });
                        jobs.len() - 1
                    });
                    job = Some(i);
                }
            }
        }
        job_of.push(job);
    }
    report.unique = jobs.len();
    say(&format!(
        "hash: {} file(s), {} dir(s), {} symlink(s), {} bytes",
        report.files, report.dirs, report.symlinks, report.input_bytes
    ))?;

    let packed = pack_jobs(
        &jobs,
        set.workers,
        set.budget,
        set.encoder,
        set.codec,
        set.hasher,
    )?;
    say(&format!(
        "pack: {} distinct file(s) encoded on {} worker(s)",
        jobs.len(),
        set.workers.clamp(1, jobs.len().max(1))
    ))?;
    for (job, p) in jobs.iter().zip(&packed) {
        for (codec, reason) in &p.dropped {
            report
                .dropped
                .push((job.path.as_str().to_owned(), *codec, reason.clone()));
        }
    }

    // Each frame is dropped right after its last user is added, so the peak stays near one copy
    // of the frames (the layout holds its own).
    let mut last_use = vec![0usize; jobs.len()];
    for (pos, job) in job_of.iter().enumerate() {
        if let Some(j) = job {
            last_use[*j] = pos;
        }
    }
    let mut packed: Vec<Option<PackedFile>> = packed.into_iter().map(Some).collect();
    let mut layout = layout;
    for (pos, (item, job)) in items.into_iter().zip(job_of).enumerate() {
        match item.kind {
            ItemKind::Dir => layout.add_dir(item.path)?,
            ItemKind::Symlink(link) => layout.add_symlink(item.path, &link)?,
            ItemKind::File { size, sha256, exec } => {
                let codec = match job {
                    None => {
                        let empty = PackedFile {
                            size,
                            sha256,
                            frame: None,
                            dropped: Vec::new(),
                        };
                        layout.add_file(item.path, exec, &empty)?;
                        "none"
                    }
                    Some(j) => {
                        let p = packed[j]
                            .as_ref()
                            .context("internal error: a frame was used after its last user")?;
                        let id = p.frame.as_ref().map_or("none", |f| f.codec.id());
                        layout.add_file(item.path, exec, p)?;
                        if last_use[j] == pos {
                            packed[j] = None;
                        }
                        id
                    }
                };
                *report.per_codec.entry(codec).or_default() += 1;
            }
        }
    }
    let (manifest, pack) = layout.finish(issued, set.hasher)?;
    Ok(Built {
        manifest,
        pack,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack_codec_lzma::LzmaCodec;
    use lunepack_core::{AppId, Error};
    use lunepack_crypto::Sha256Hasher;

    /// Rewrites one file in place and records the order it was given.
    struct Rewrite {
        path: &'static str,
        bytes: &'static [u8],
        seen: Mutex<Vec<String>>,
    }

    impl CodeSign for Rewrite {
        fn sign_tree(&self, root: &Path, order: &[RelPath]) -> Result<(), Error> {
            *self.seen.lock().unwrap() = order.iter().map(|p| p.as_str().to_owned()).collect();
            fs::write(root.join(self.path), self.bytes).expect("rewrite");
            Ok(())
        }
    }

    fn file_sha(manifest: &ManifestDocument, path: &str) -> Sha256Digest {
        manifest
            .entries
            .iter()
            .find(|e| e.path.as_str() == path)
            .and_then(|e| e.sha256)
            .expect("file entry")
    }

    #[test]
    fn code_sign_runs_between_assemble_and_hash() {
        let input = tempfile::tempdir().unwrap();
        fs::create_dir_all(input.path().join("sub/deeper")).unwrap();
        fs::write(input.path().join("app.bin"), b"original bytes of the app").unwrap();
        fs::write(input.path().join("sub/lib.bin"), b"a library").unwrap();
        fs::write(input.path().join("sub/deeper/x.bin"), b"deep").unwrap();
        let work = tempfile::tempdir().unwrap();
        let sign = Rewrite {
            path: "app.bin",
            bytes: b"the signed app, longer than before",
            seen: Mutex::new(Vec::new()),
        };
        let set = Settings {
            workers: 2,
            budget: 1 << 30,
            code_sign: &sign,
            encoder: &LzmaCodec,
            codec: &LzmaCodec,
            hasher: &Sha256Hasher,
        };
        let layout = ReleaseLayout::new(
            AppId::parse("org.example.app").unwrap(),
            "1.0.0",
            Target::LinuxX86_64,
        )
        .unwrap();
        let built = build(
            input.path(),
            work.path(),
            layout,
            Target::LinuxX86_64,
            1_800_000_000,
            &set,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            file_sha(&built.manifest, "app.bin"),
            Sha256Hasher.sha256(b"the signed app, longer than before")
        );
        assert_eq!(
            file_sha(&built.manifest, "sub/lib.bin"),
            Sha256Hasher.sha256(b"a library")
        );
        // Deepest first, then by path.
        assert_eq!(
            *sign.seen.lock().unwrap(),
            ["sub/deeper/x.bin", "sub/lib.bin", "app.bin"]
        );
        // The input itself is never touched.
        assert_eq!(
            fs::read(input.path().join("app.bin")).unwrap(),
            b"original bytes of the app"
        );
    }

    #[test]
    fn gate_admits_a_job_over_the_budget_alone() {
        let gate = Gate {
            in_use: Mutex::new(0),
            freed: Condvar::new(),
            budget: 10,
        };
        let big = gate.admit(100);
        assert_eq!(*gate.in_use.lock().unwrap(), 100);
        drop(big);
        let a = gate.admit(4);
        let b = gate.admit(6);
        assert_eq!(*gate.in_use.lock().unwrap(), 10);
        drop((a, b));
        assert_eq!(*gate.in_use.lock().unwrap(), 0);
    }
}

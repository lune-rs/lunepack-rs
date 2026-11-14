//! The stage engine (M4 step 7) over the crash-injecting `MemFs` and `FakeCodec`: every source
//! kind, the scan's no-follow rule, NeedFetch, resume of a partial tree and of a complete one, a
//! crash at every write point, the memory budget, determinism across worker counts, cancel in the
//! middle of a decode, and (Unix) a planted symlink in the partial tree on a real directory.

use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use lunepack_core::stage::{IO_BUFFER_BYTES, PARTIAL_SUFFIX, TMP_SUFFIX};
use lunepack_core::{
    AppId, CancelToken, Channel, ClockReading, Codec, CodecId, DecodeReport, DirEntryInfo, Error,
    FileKind, FileWrite, FrameView, Fs, FsError, FsErrorKind, LockGuard, Meta, PayloadKind, Phase,
    Progress, ReadAt, RollbackFloor, Source, SourceFor, StageEnv, StageError, StageInput, Target,
    VerifiedEntry, VerifiedManifest, decoder_memory, scan, stage, verify_feed, verify_manifest,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, Fault, MemFs, PackBuilder, RecoverMode,
    SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const VERSION: &str = "2.0.0";
const H: FakeHasher = FakeHasher;

fn data(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

/// A manifest verified the way production verifies one: through a signed feed entry.
fn verify(fx: &ChainFixture<'_>, p: &PackBuilder) -> VerifiedManifest {
    let (_, keys) = fx.verified_chain(&[5], 1);
    let doc = fx.manifest_document(VERSION, Target::LinuxX86_64, p);
    let bytes = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[5]);
    let feed_doc = fx.feed_document(
        1,
        None,
        vec![fx.release(VERSION, &[(Target::LinuxX86_64, &bytes)], None)],
    );
    let feed_bytes = fx.envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[5]);
    let feed = verify_feed(
        &keys,
        &feed_bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(SUITE_T0), None),
        fx.verifier,
    )
    .unwrap();
    let entry = feed.target_entry(0, Target::LinuxX86_64).unwrap();
    verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier).unwrap()
}

/// The main fixture: every codec, an executable, an empty file, a directory, a symlink.
fn pack() -> PackBuilder {
    let mut p = PackBuilder::new();
    p.file(&H, "bin/app", &data(3000, 1), CodecId::BcjX86Lzma2)
        .file(&H, "lib/x.so.1", &data(2000, 2), CodecId::Bcj2)
        .file(&H, "share/README", &data(500, 3), CodecId::Stored)
        .file(&H, "share/empty", b"", CodecId::Stored)
        .file(&H, "data/blob", &data(700, 4), CodecId::Lzma2)
        .file(&H, "data/keep", &data(900, 5), CodecId::Lzma2)
        .dir("share/doc")
        .symlink("lib/x.so", "x.so.1");
    p.entries[0].exec = Some(true);
    p
}

/// The file contents of `pack()`, by path.
fn contents() -> BTreeMap<String, Vec<u8>> {
    [
        ("bin/app", data(3000, 1)),
        ("lib/x.so.1", data(2000, 2)),
        ("share/README", data(500, 3)),
        ("share/empty", Vec::new()),
        ("data/blob", data(700, 4)),
        ("data/keep", data(900, 5)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

fn root() -> PathBuf {
    PathBuf::from("/data")
}
fn versions() -> PathBuf {
    root().join("versions")
}
fn pack_path() -> PathBuf {
    root().join("cache/pack")
}
fn frame_path(i: usize) -> PathBuf {
    root().join(format!("cache/frame-{i}"))
}
fn tree() -> PathBuf {
    versions().join(VERSION)
}
fn partial() -> PathBuf {
    versions().join(format!("{VERSION}{PARTIAL_SUFFIX}"))
}

/// Writes `bytes` at `path` durably (the file and every directory above it synced).
fn put(fs: &dyn Fs, path: &Path, bytes: &[u8]) {
    let parent = path.parent().unwrap();
    fs.create_dir_all(parent).unwrap();
    if fs.symlink_metadata(path).unwrap().is_some() {
        fs.remove_file(path).unwrap();
    }
    let mut w = fs.create_new(path).unwrap();
    w.write_all(bytes).unwrap();
    w.sync().unwrap();
    drop(w);
    for dir in path.ancestors().skip(1) {
        fs.sync_dir(dir).unwrap();
    }
}

/// The bytes of entry `i`'s frame inside the pack.
fn frame_bytes(m: &VerifiedManifest, p: &PackBuilder, i: usize) -> Vec<u8> {
    match &m.entries()[i] {
        VerifiedEntry::File { frame: Some(f), .. } => {
            p.bytes[f.offset() as usize..(f.offset() + f.length()) as usize].to_vec()
        }
        _ => panic!("entry {i} has no frame"),
    }
}

/// Writes the pack and every frame into the cache.
fn seed_cache(fs: &dyn Fs, m: &VerifiedManifest, p: &PackBuilder) {
    put(fs, &pack_path(), &p.bytes);
    for (i, e) in m.entries().iter().enumerate() {
        if let VerifiedEntry::File { frame: Some(_), .. } = e {
            put(fs, &frame_path(i), &frame_bytes(m, p, i));
        }
    }
}

/// Every non-empty file from its cached frame.
fn frame_sources(m: &VerifiedManifest) -> Vec<SourceFor> {
    (0..m.entries().len())
        .map(|i| SourceFor::Frame(frame_path(i)))
        .collect()
}

/// A mix: frames for even entries, the pack for odd ones.
fn mixed_sources(m: &VerifiedManifest) -> Vec<SourceFor> {
    (0..m.entries().len())
        .map(|i| {
            if i % 2 == 0 {
                SourceFor::Frame(frame_path(i))
            } else {
                SourceFor::Pack(pack_path())
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Dir,
    File(Vec<u8>),
    Symlink,
}

/// Everything under `dir`, by relative path (symlinks not followed).
fn dump(fs: &dyn Fs, dir: &Path) -> BTreeMap<String, Node> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, prefix)) = stack.pop() {
        for e in fs.list_dir(&d).unwrap() {
            let name = e.name.to_str().unwrap().to_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let path = d.join(&e.name);
            match e.kind {
                FileKind::Dir => {
                    out.insert(rel.clone(), Node::Dir);
                    stack.push((path, rel));
                }
                FileKind::File => {
                    out.insert(rel, Node::File(fs.read_capped(&path, 1 << 30).unwrap()));
                }
                _ => {
                    out.insert(rel, Node::Symlink);
                }
            }
        }
    }
    out
}

/// The tree `pack()` stages to.
fn expected_tree() -> BTreeMap<String, Node> {
    let mut t: BTreeMap<String, Node> = contents()
        .into_iter()
        .map(|(k, v)| (k, Node::File(v)))
        .collect();
    for d in ["bin", "lib", "share", "share/doc", "data"] {
        t.insert(d.to_owned(), Node::Dir);
    }
    t.insert("lib/x.so".to_owned(), Node::Symlink);
    t
}

fn no_tmp_files(fs: &dyn Fs, dir: &Path) -> bool {
    fs.symlink_metadata(dir).unwrap().is_none()
        || dump(fs, dir).keys().all(|k| !k.ends_with(TMP_SUFFIX))
}

/// Runs a stage with the given knobs.
#[allow(clippy::too_many_arguments)]
fn run(
    fs: &dyn Fs,
    codec: &dyn Codec,
    m: &VerifiedManifest,
    sources: Vec<SourceFor>,
    workers: usize,
    budget: u64,
    cancel: &CancelToken,
    progress: &dyn Fn(Progress),
) -> Result<lunepack_core::StagedVersion, StageError> {
    let input = StageInput {
        manifest: m,
        versions_dir: versions(),
        sources,
    };
    let env = StageEnv {
        fs,
        codec,
        hasher: &H,
        workers,
        budget_bytes: budget,
        cancel,
        progress,
    };
    stage(&input, &env)
}

fn simple(
    fs: &dyn Fs,
    m: &VerifiedManifest,
    sources: Vec<SourceFor>,
    workers: usize,
) -> Result<lunepack_core::StagedVersion, StageError> {
    run(
        fs,
        &FakeCodec::new(),
        m,
        sources,
        workers,
        256 << 20,
        &CancelToken::new(),
        &|_| {},
    )
}

// ---------------------------------------------------------------------------------------------
// A recording Fs wrapper.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    SetExec(PathBuf, bool),
    Symlink(String, PathBuf),
    Rename(PathBuf, PathBuf),
    CreateNew(PathBuf),
}

struct Spy<'a> {
    inner: &'a dyn Fs,
    log: Mutex<Vec<Op>>,
    /// Fail every `create_new` of a temporary file (a full disk).
    fail_tmp: bool,
}

impl<'a> Spy<'a> {
    fn new(inner: &'a dyn Fs) -> Self {
        Spy {
            inner,
            log: Mutex::new(Vec::new()),
            fail_tmp: false,
        }
    }
    fn ops(&self) -> Vec<Op> {
        self.log.lock().unwrap().clone()
    }
    fn record(&self, op: Op) {
        self.log.lock().unwrap().push(op);
    }
}

impl Fs for Spy<'_> {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        self.inner.read_capped(path, max)
    }
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        self.inner.open_read(path)
    }
    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.record(Op::CreateNew(path.to_path_buf()));
        if self.fail_tmp && path.to_string_lossy().ends_with(TMP_SUFFIX) {
            return Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("disk full")),
            ));
        }
        self.inner.create_new(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.inner.open_append(path)
    }
    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        self.inner.truncate(path, len)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.record(Op::Rename(from.to_path_buf(), to.to_path_buf()));
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_dir_all_nofollow(path)
    }
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        self.inner.list_dir(path)
    }
    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        self.inner.symlink_metadata(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(path)
    }
    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
        self.inner.copy_file(from, to_new)
    }
    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
        self.record(Op::SetExec(path.to_path_buf(), exec));
        self.inner.set_exec(path, exec)
    }
    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        self.record(Op::Symlink(target.to_owned(), link_path.to_path_buf()));
        self.inner.symlink(target, link_path)
    }
    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        self.inner.try_lock(path)
    }
}

// ---------------------------------------------------------------------------------------------
// Codecs around FakeCodec.

/// Records how many decodes run at once. Each decode waits (up to `wait`) for a second one to
/// start, so a budget that allows two shows two.
struct Concurrency {
    active: AtomicUsize,
    max: AtomicUsize,
    wait: Duration,
}

impl Concurrency {
    fn new(wait: Duration) -> Self {
        Concurrency {
            active: AtomicUsize::new(0),
            max: AtomicUsize::new(0),
            wait,
        }
    }
}

impl Codec for Concurrency {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn io::Write,
    ) -> Result<DecodeReport, Error> {
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max.fetch_max(now, Ordering::SeqCst);
        let start = Instant::now();
        while self.active.load(Ordering::SeqCst) < 2 && start.elapsed() < self.wait {
            std::thread::sleep(Duration::from_millis(1));
        }
        let r = FakeCodec::new().decode(frame, out);
        self.active.fetch_sub(1, Ordering::SeqCst);
        r
    }
}

/// Writes half of a file, tells the test, blocks until the token is cancelled, then writes the
/// rest (which the stage's writer refuses).
struct BlockMidDecode {
    cancel: CancelToken,
    mid: Mutex<mpsc::Sender<()>>,
}

impl Codec for BlockMidDecode {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn io::Write,
    ) -> Result<DecodeReport, Error> {
        let mut buf = Vec::new();
        let report = FakeCodec::new().decode(frame, &mut buf)?;
        let half = buf.len() / 2;
        out.write_all(&buf[..half])
            .map_err(lunepack_core::error::CodecError::Write)?;
        let _ = self.mid.lock().unwrap().send(());
        let start = Instant::now();
        while !self.cancel.is_cancelled() {
            assert!(start.elapsed() < Duration::from_secs(20), "never cancelled");
            std::thread::sleep(Duration::from_millis(1));
        }
        out.write_all(&buf[half..])
            .map_err(lunepack_core::error::CodecError::Write)?;
        Ok(report)
    }
}

// ---------------------------------------------------------------------------------------------
// Tests.

#[test]
fn stages_every_source_kind_and_verifies_before_placing() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    // `data/keep` comes from the current tree.
    let current = root().join("versions/1.0.0");
    put(&mem, &current.join("data/keep"), &data(900, 5));
    let mut sources = mixed_sources(&m);
    sources[5] = SourceFor::Unchanged(current.join("data/keep"));

    let spy = Spy::new(&mem);
    let events = Mutex::new(Vec::new());
    let staged = run(
        &spy,
        &FakeCodec::new(),
        &m,
        sources,
        4,
        256 << 20,
        &CancelToken::new(),
        &|e| events.lock().unwrap().push(e),
    )
    .unwrap();
    assert_eq!(staged.tree, tree());
    assert_eq!(staged.version.to_string(), VERSION);
    assert_eq!(staged.target, Target::LinuxX86_64);
    assert_eq!(dump(&mem, &tree()), expected_tree());
    assert!(mem.symlink_metadata(&partial()).unwrap().is_none());

    let ops = spy.ops();
    // Executable only for the exec entry, and only `true`; every other file is never made exec.
    let exec_true: Vec<_> = ops
        .iter()
        .filter(|o| matches!(o, Op::SetExec(_, true)))
        .collect();
    assert_eq!(exec_true.len(), 1);
    assert!(
        ops.iter().all(|o| !matches!(o, Op::SetExec(_, false))),
        "fresh files are created non-exec, never cleared"
    );
    // The symlink holds the exact signed text and is created after every file is placed.
    let link = ops
        .iter()
        .position(|o| *o == Op::Symlink("x.so.1".into(), partial().join("lib/x.so")))
        .expect("symlink created");
    let last_file_rename = ops
        .iter()
        .rposition(|o| matches!(o, Op::Rename(f, _) if f.to_string_lossy().ends_with(TMP_SUFFIX)))
        .unwrap();
    assert!(link > last_file_rename);
    // Every file is written under a temporary name and renamed into the partial tree.
    for o in &ops {
        if let Op::CreateNew(p) = o {
            assert!(p.to_string_lossy().ends_with(TMP_SUFFIX), "{p:?}");
            assert!(p.starts_with(partial()));
        }
    }

    let events = events.into_inner().unwrap();
    let total: u64 = contents().values().map(|v| v.len() as u64).sum();
    assert!(
        events
            .iter()
            .all(|e| e.phase == Phase::Stage && e.total == total)
    );
    assert_eq!(events.iter().map(|e| e.done).max(), Some(total));
    let source_of = |path: &str| {
        events
            .iter()
            .filter_map(|e| e.file.as_ref())
            .find(|f| f.path.as_str() == path)
            .map(|f| f.source)
    };
    assert_eq!(source_of("bin/app"), Some(Source::Range));
    assert_eq!(source_of("lib/x.so.1"), Some(Source::FullPack));
    assert_eq!(source_of("data/keep"), Some(Source::Unchanged));
}

#[test]
fn workers_do_not_change_the_tree_or_the_need_fetch_list() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mut outcomes = Vec::new();
    for workers in [1, 8] {
        let mem = MemFs::new();
        seed_cache(&mem, &m, &p);
        // Corrupt entries 1 and 4; drop entry 5's cache file.
        let mut bad = frame_bytes(&m, &p, 1);
        bad[0] ^= 1;
        put(&mem, &frame_path(1), &bad);
        let mut bad = frame_bytes(&m, &p, 4);
        bad[3] ^= 1;
        put(&mem, &frame_path(4), &bad);
        mem.remove_file(&frame_path(5)).unwrap();
        let err = simple(&mem, &m, frame_sources(&m), workers).unwrap_err();
        let StageError::NeedFetch(list) = err else {
            panic!("expected NeedFetch, got {err:?}")
        };
        let names: Vec<_> = list.iter().map(|p| p.as_str().to_owned()).collect();
        assert_eq!(names, ["lib/x.so.1", "data/blob", "data/keep"]);
        assert!(no_tmp_files(&mem, &partial()));
        let partial_tree = dump(&mem, &partial());
        seed_cache(&mem, &m, &p);
        simple(&mem, &m, frame_sources(&m), workers).unwrap();
        outcomes.push((names, partial_tree, dump(&mem, &tree())));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(outcomes[0].2, expected_tree());
}

#[test]
fn source_failures_are_need_fetch_in_manifest_order() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    // A short cache file, a long one, a missing pack for one entry, a current-tree file that
    // changed since the scan.
    let f0 = frame_bytes(&m, &p, 0);
    put(&mem, &frame_path(0), &f0[..f0.len() - 1]);
    let mut long = frame_bytes(&m, &p, 2);
    long.push(0);
    put(&mem, &frame_path(2), &long);
    let current = root().join("versions/1.0.0");
    put(&mem, &current.join("data/keep"), &data(900, 6));
    let mut sources = frame_sources(&m);
    sources[1] = SourceFor::Pack(root().join("cache/missing"));
    sources[5] = SourceFor::Unchanged(current.join("data/keep"));
    let err = simple(&mem, &m, sources, 4).unwrap_err();
    let StageError::NeedFetch(list) = err else {
        panic!("expected NeedFetch, got {err:?}")
    };
    let names: Vec<_> = list.iter().map(|p| p.as_str()).collect();
    assert_eq!(
        names,
        ["bin/app", "lib/x.so.1", "share/README", "data/keep"]
    );
    // The good files are placed, the failed ones absent, no temporary file anywhere.
    let t = dump(&mem, &partial());
    assert_eq!(t.get("data/blob"), Some(&Node::File(data(700, 4))));
    assert_eq!(t.get("share/empty"), Some(&Node::File(Vec::new())));
    assert!(!t.contains_key("bin/app") && !t.contains_key("data/keep"));
    assert!(no_tmp_files(&mem, &partial()));

    // A decode error is a source failure too.
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    let err = run(
        &mem,
        &FakeCodec::with_fault(Fault::TooFewBytes),
        &m,
        frame_sources(&m),
        2,
        256 << 20,
        &CancelToken::new(),
        &|_| {},
    )
    .unwrap_err();
    assert!(
        matches!(err, StageError::NeedFetch(ref l) if l.len() == 5),
        "{err:?}"
    );
    assert!(no_tmp_files(&mem, &partial()));
}

#[test]
fn a_destination_failure_is_other_not_need_fetch() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    let mut spy = Spy::new(&mem);
    spy.fail_tmp = true;
    for workers in [1, 4] {
        let err = simple(&spy, &m, frame_sources(&m), workers).unwrap_err();
        assert!(
            matches!(err, StageError::Other(Error::Fs(ref e)) if e.kind == FsErrorKind::Other),
            "{err:?}"
        );
    }
}

#[test]
fn patch_sources_are_unsupported_and_sources_must_match_entries() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    let mut sources = frame_sources(&m);
    sources[0] = SourceFor::Patch;
    assert!(matches!(
        simple(&mem, &m, sources, 1),
        Err(StageError::Unsupported)
    ));
    let mut sources = frame_sources(&m);
    sources.pop();
    assert!(matches!(
        simple(&mem, &m, sources, 1),
        Err(StageError::Other(Error::Field(_)))
    ));
}

#[test]
fn resume_cleans_the_partial_tree_and_keeps_verified_files() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    let part = partial();
    put(&mem, &part.join("data/~3.lptmp"), b"leftover");
    put(&mem, &part.join("unlisted"), b"x");
    put(&mem, &part.join("olddir/deep/file"), b"x");
    put(&mem, &part.join("data/blob"), &data(700, 9)); // right size, wrong hash
    put(&mem, &part.join("share/README/inner"), b"x"); // a dir where a file belongs
    put(&mem, &part.join("data/keep"), &data(900, 5)); // correct: kept
    mem.create_dir_all(&part.join("bin")).unwrap();
    mem.symlink("../data/keep", &part.join("bin/app")).unwrap(); // a symlink where a file belongs
    mem.symlink("elsewhere", &part.join("lib")).unwrap(); // a symlink where a dir belongs

    let spy = Spy::new(&mem);
    simple(&spy, &m, frame_sources(&m), 4).unwrap();
    assert_eq!(dump(&mem, &tree()), expected_tree());
    assert_eq!(
        mem.read_capped(&tree().join("data/keep"), 1 << 20).unwrap(),
        data(900, 5)
    );
    // The verified file was kept: nothing was renamed onto it.
    assert!(
        !spy.ops()
            .iter()
            .any(|o| matches!(o, Op::Rename(_, to) if *to == part.join("data/keep")))
    );
    assert!(
        spy.ops()
            .iter()
            .any(|o| matches!(o, Op::Rename(_, to) if *to == part.join("data/blob")))
    );
}

#[test]
fn an_existing_complete_tree_is_reverified_before_it_is_returned() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    simple(&mem, &m, frame_sources(&m), 2).unwrap();
    // Unchanged: staged again as is.
    simple(&mem, &m, frame_sources(&m), 2).unwrap();
    assert_eq!(dump(&mem, &tree()), expected_tree());
    // A damaged file and a stray entry in the complete tree are repaired.
    put(&mem, &tree().join("bin/app"), &data(3000, 7));
    put(&mem, &tree().join("stray"), b"x");
    let staged = simple(&mem, &m, frame_sources(&m), 2).unwrap();
    assert_eq!(staged.tree, tree());
    assert_eq!(dump(&mem, &tree()), expected_tree());
    assert!(mem.symlink_metadata(&partial()).unwrap().is_none());
}

#[test]
fn a_crash_at_any_write_point_resumes_to_the_same_tree() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let fresh = || {
        let mem = MemFs::new();
        seed_cache(&mem, &m, &p);
        mem
    };
    let probe = fresh();
    let base = probe.op_count();
    simple(&probe, &m, mixed_sources(&m), 1).unwrap();
    let ops = probe.op_count() - base;
    assert!(ops > 20, "{ops} ops");
    for n in 0..ops {
        for mode in [RecoverMode::DropVolatile, RecoverMode::KeepVolatile] {
            let mem = fresh();
            mem.crash_after(base + n);
            assert!(simple(&mem, &m, mixed_sources(&m), 1).is_err());
            let disk = mem.recover(mode);
            simple(&disk, &m, mixed_sources(&m), 1)
                .unwrap_or_else(|e| panic!("op {n} {mode:?}: {e:?}"));
            assert_eq!(dump(&disk, &tree()), expected_tree(), "op {n} {mode:?}");
            assert!(disk.symlink_metadata(&partial()).unwrap().is_none());
        }
    }
}

/// Six equal LZMA2 files, so every job has the same cost.
fn equal_jobs() -> (PackBuilder, u64) {
    let mut p = PackBuilder::new();
    for i in 0..6u8 {
        p.file(&H, &format!("f{i}"), &data(3000, i), CodecId::Lzma2);
    }
    let fx = ChainFixture::fake();
    let m = verify(&fx, &p);
    let VerifiedEntry::File { frame: Some(f), .. } = &m.entries()[0] else {
        unreachable!()
    };
    let cost = f.length() + decoder_memory(f) + IO_BUFFER_BYTES;
    (p, cost)
}

#[test]
fn the_budget_bounds_concurrent_decodes() {
    let (p, cost) = equal_jobs();
    let m = verify(&ChainFixture::fake(), &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    let codec = Concurrency::new(Duration::from_millis(300));
    run(
        &mem,
        &codec,
        &m,
        frame_sources(&m),
        8,
        2 * cost,
        &CancelToken::new(),
        &|_| {},
    )
    .unwrap();
    assert_eq!(codec.max.load(Ordering::SeqCst), 2);
}

#[test]
fn a_job_above_the_budget_runs_alone_and_completes() {
    let (p, cost) = equal_jobs();
    let m = verify(&ChainFixture::fake(), &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    let codec = Concurrency::new(Duration::from_millis(30));
    run(
        &mem,
        &codec,
        &m,
        frame_sources(&m),
        8,
        cost / 3,
        &CancelToken::new(),
        &|_| {},
    )
    .unwrap();
    assert_eq!(codec.max.load(Ordering::SeqCst), 1);
    assert_eq!(dump(&mem, &tree()).len(), 6);
}

#[test]
fn cancel_mid_decode_discards_the_frame_and_a_later_call_resumes() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let reference = MemFs::new();
    seed_cache(&reference, &m, &p);
    simple(&reference, &m, frame_sources(&m), 1).unwrap();

    for workers in [1, 4] {
        let mem = MemFs::new();
        seed_cache(&mem, &m, &p);
        let cancel = CancelToken::new();
        let (tx, rx) = mpsc::channel();
        let codec = BlockMidDecode {
            cancel: cancel.clone(),
            mid: Mutex::new(tx),
        };
        let result = std::thread::scope(|s| {
            let job = s.spawn(|| {
                run(
                    &mem,
                    &codec,
                    &m,
                    frame_sources(&m),
                    workers,
                    256 << 20,
                    &cancel,
                    &|_| {},
                )
            });
            rx.recv_timeout(Duration::from_secs(20))
                .expect("a decode started");
            cancel.cancel();
            job.join().unwrap()
        });
        assert!(matches!(result, Err(StageError::Cancelled)), "{result:?}");
        assert!(no_tmp_files(&mem, &partial()), "workers {workers}");
        assert!(mem.symlink_metadata(&tree()).unwrap().is_none());
        simple(&mem, &m, frame_sources(&m), workers).unwrap();
        assert_eq!(dump(&mem, &tree()), dump(&reference, &tree()));
    }

    // Cancelled before it starts: nothing is created.
    let mem = MemFs::new();
    let cancel = CancelToken::new();
    cancel.cancel();
    let r = run(
        &mem,
        &FakeCodec::new(),
        &m,
        frame_sources(&m),
        2,
        256 << 20,
        &cancel,
        &|_| {},
    );
    assert!(matches!(r, Err(StageError::Cancelled)));
    assert!(!matches!(mem.symlink_metadata(&versions()), Ok(Some(_))));
}

#[test]
fn scan_matches_size_and_hash_and_never_follows_a_symlink() {
    let fx = ChainFixture::fake();
    let mut p = PackBuilder::new();
    p.file(&H, "same", &data(400, 1), CodecId::Lzma2)
        .file(&H, "changed", &data(400, 2), CodecId::Lzma2)
        .file(&H, "resized", &data(400, 3), CodecId::Lzma2)
        .file(&H, "linkdir/f", &data(400, 4), CodecId::Lzma2)
        .file(&H, "link", &data(400, 5), CodecId::Lzma2)
        .file(&H, "sub/deep", &data(400, 6), CodecId::Lzma2)
        .file(&H, "empty", b"", CodecId::Stored)
        .dir("d");
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    let cur = root().join("current");
    put(&mem, &cur.join("same"), &data(400, 1));
    put(&mem, &cur.join("changed"), &data(400, 9));
    put(&mem, &cur.join("resized"), &data(401, 3));
    put(&mem, &root().join("outside/f"), &data(400, 4));
    put(&mem, &root().join("outside/link"), &data(400, 5));
    mem.symlink("../outside", &cur.join("linkdir")).unwrap();
    mem.symlink("../outside/link", &cur.join("link")).unwrap();
    put(&mem, &cur.join("sub/deep"), &data(400, 6));
    put(&mem, &cur.join("empty"), b"");

    let events = Mutex::new(Vec::new());
    for workers in [1, 4] {
        events.lock().unwrap().clear();
        let found = scan(
            &m,
            Some(&cur),
            &mem,
            &H,
            workers,
            &CancelToken::new(),
            &|e| events.lock().unwrap().push(e),
        )
        .unwrap();
        assert_eq!(
            found,
            vec![
                Some(cur.join("same")),
                None,
                None,
                None,
                None,
                Some(cur.join("sub/deep")),
                None,
                None
            ]
        );
        let events = events.lock().unwrap();
        assert!(events.iter().all(|e| {
            e.phase == Phase::Scan
                && e.total == 1200
                && e.file
                    .as_ref()
                    .is_some_and(|f| f.source == Source::Unchanged)
        }));
        assert_eq!(events.iter().map(|e| e.done).max(), Some(1200));
    }
    let none = vec![None; m.entries().len()];
    let token = CancelToken::new();
    assert_eq!(scan(&m, None, &mem, &H, 2, &token, &|_| {}).unwrap(), none);
    assert_eq!(
        scan(&m, Some(&cur.join("same")), &mem, &H, 2, &token, &|_| {}).unwrap(),
        none
    );
    mem.symlink("current", &root().join("cur-link")).unwrap();
    assert_eq!(
        scan(
            &m,
            Some(&root().join("cur-link")),
            &mem,
            &H,
            2,
            &token,
            &|_| {}
        )
        .unwrap(),
        none
    );
    token.cancel();
    assert!(matches!(
        scan(&m, Some(&cur), &mem, &H, 2, &token, &|_| {}),
        Err(Error::Cancelled)
    ));
}

#[test]
fn scan_results_feed_stage_as_unchanged_sources() {
    let fx = ChainFixture::fake();
    let p = pack();
    let m = verify(&fx, &p);
    let mem = MemFs::new();
    seed_cache(&mem, &m, &p);
    let cur = root().join("versions/1.0.0");
    for (path, bytes) in contents() {
        put(&mem, &cur.join(&path), &bytes);
    }
    let found = scan(&m, Some(&cur), &mem, &H, 3, &CancelToken::new(), &|_| {}).unwrap();
    let sources: Vec<SourceFor> = found
        .into_iter()
        .map(|f| {
            f.map_or(
                SourceFor::Pack(root().join("cache/none")),
                SourceFor::Unchanged,
            )
        })
        .collect();
    // Every non-empty file is unchanged, so the (missing) pack is never read.
    simple(&mem, &m, sources, 3).unwrap();
    assert_eq!(dump(&mem, &tree()), expected_tree());
}

// ---------------------------------------------------------------------------------------------
// Unix: a planted symlink on a real directory.

#[cfg(unix)]
mod real {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{FileExt, PermissionsExt};

    /// A minimal std-backed `Fs` for this test only (the real adapter lives in `lunepack-fs`,
    /// which the core may not depend on).
    struct TestFs;

    fn err(path: &Path, e: io::Error) -> FsError {
        FsError::from_io(path, e)
    }

    struct Reader(fs::File);
    impl ReadAt for Reader {
        fn size(&self) -> Result<u64, FsError> {
            self.0
                .metadata()
                .map(|m| m.len())
                .map_err(|e| err(Path::new(""), e))
        }
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
            self.0
                .read_exact_at(buf, offset)
                .map_err(|e| err(Path::new(""), e))
        }
    }

    struct Writer(fs::File);
    impl io::Write for Writer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    impl FileWrite for Writer {
        fn sync(&mut self) -> Result<(), FsError> {
            self.0.sync_all().map_err(|e| err(Path::new(""), e))
        }
    }

    fn kind(t: fs::FileType) -> FileKind {
        if t.is_symlink() {
            FileKind::Symlink
        } else if t.is_dir() {
            FileKind::Dir
        } else if t.is_file() {
            FileKind::File
        } else {
            FileKind::Other
        }
    }

    impl Fs for TestFs {
        fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
            let bytes = fs::read(path).map_err(|e| err(path, e))?;
            if bytes.len() as u64 > max {
                return Err(FsError::new(FsErrorKind::TooLarge, path, None));
            }
            Ok(bytes)
        }
        fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
            Ok(Box::new(Reader(
                fs::File::open(path).map_err(|e| err(path, e))?,
            )))
        }
        fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
            let f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| err(path, e))?;
            Ok(Box::new(Writer(f)))
        }
        fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
            let f = fs::OpenOptions::new()
                .append(true)
                .open(path)
                .map_err(|e| err(path, e))?;
            Ok(Box::new(Writer(f)))
        }
        fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|f| f.set_len(len))
                .map_err(|e| err(path, e))
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
            fs::rename(from, to).map_err(|e| err(to, e))
        }
        fn remove_file(&self, path: &Path) -> Result<(), FsError> {
            fs::remove_file(path).map_err(|e| err(path, e))
        }
        fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
            let m = fs::symlink_metadata(path).map_err(|e| err(path, e))?;
            if m.file_type().is_symlink() {
                return fs::remove_file(path).map_err(|e| err(path, e));
            }
            // std's remove_dir_all removes symlinks inside the tree without following them.
            fs::remove_dir_all(path).map_err(|e| err(path, e))
        }
        fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
            let mut cur = PathBuf::new();
            for c in path.components() {
                cur.push(c);
                match fs::symlink_metadata(&cur) {
                    Ok(m) if m.file_type().is_symlink() => {
                        return Err(FsError::new(FsErrorKind::IsSymlink, &cur, None));
                    }
                    Ok(m) if m.is_dir() => {}
                    Ok(_) => return Err(FsError::new(FsErrorKind::NotADirectory, &cur, None)),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&cur).map_err(|e| err(&cur, e))?;
                    }
                    Err(e) => return Err(err(&cur, e)),
                }
            }
            Ok(())
        }
        fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
            let mut out = Vec::new();
            for e in fs::read_dir(path).map_err(|e| err(path, e))? {
                let e = e.map_err(|e| err(path, e))?;
                let t = e.file_type().map_err(|e| err(path, e))?;
                out.push(DirEntryInfo {
                    name: e.file_name(),
                    kind: kind(t),
                });
            }
            Ok(out)
        }
        fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
            match fs::symlink_metadata(path) {
                Ok(m) => Ok(Some(Meta {
                    kind: kind(m.file_type()),
                    len: m.len(),
                })),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(err(path, e)),
            }
        }
        fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
            fs::File::open(path)
                .and_then(|f| f.sync_all())
                .map_err(|e| err(path, e))
        }
        fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
            let bytes = fs::read(from).map_err(|e| err(from, e))?;
            let mut w = self.create_new(to_new)?;
            w.write_all(&bytes).map_err(|e| err(to_new, e))
        }
        fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
            let mode = if exec { 0o755 } else { 0o644 };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| err(path, e))
        }
        fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
            std::os::unix::fs::symlink(target, link_path).map_err(|e| err(link_path, e))
        }
        fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
            Err(FsError::new(FsErrorKind::Other, path, None))
        }
    }

    /// A fresh directory under the system temp dir, canonical (macOS `/var` is a symlink), removed
    /// on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Scratch {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = base.join(format!("lunepack-stage-{}-{nanos}", std::process::id()));
            assert!(fs::symlink_metadata(&dir).is_err());
            fs::create_dir(&dir).unwrap();
            Scratch(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_planted_symlink_in_the_partial_tree_is_removed_not_followed() {
        let fx = ChainFixture::fake();
        let mut p = PackBuilder::new();
        p.file(&H, "a/b", &data(600, 1), CodecId::Lzma2).file(
            &H,
            "run",
            &data(100, 2),
            CodecId::Stored,
        );
        p.entries[1].exec = Some(true);
        let m = verify(&fx, &p);
        let scratch = Scratch::new();
        let base = &scratch.0;
        let outside = base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"outside").unwrap();
        let versions = base.join("versions");
        let part = versions.join(format!("{VERSION}{PARTIAL_SUFFIX}"));
        fs::create_dir_all(&part).unwrap();
        std::os::unix::fs::symlink(&outside, part.join("a")).unwrap();
        let pack = base.join("pack");
        fs::write(&pack, &p.bytes).unwrap();

        let input = StageInput {
            manifest: &m,
            versions_dir: versions.clone(),
            sources: vec![SourceFor::Pack(pack.clone()); 2],
        };
        let env = StageEnv {
            fs: &TestFs,
            codec: &FakeCodec::new(),
            hasher: &H,
            workers: 2,
            budget_bytes: 256 << 20,
            cancel: &CancelToken::new(),
            progress: &|_| {},
        };
        let staged = stage(&input, &env).unwrap();
        let tree = versions.join(VERSION);
        assert_eq!(staged.tree, tree);
        // Nothing outside changed.
        let names: Vec<_> = fs::read_dir(&outside)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["keep"]);
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside");
        // `a` is a real directory now, holding the verified file.
        assert!(fs::symlink_metadata(tree.join("a")).unwrap().is_dir());
        assert_eq!(fs::read(tree.join("a/b")).unwrap(), data(600, 1));
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o111;
        assert_ne!(mode(&tree.join("run")), 0);
        assert_eq!(mode(&tree.join("a/b")), 0);
    }
}

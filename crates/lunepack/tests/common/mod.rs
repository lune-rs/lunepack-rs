//! A published release world for the updater tests: signed documents written by the testkit's
//! builders (the same writers the suites use), served by a `FakeTransport`, an install state
//! committed by the core's real writer, and every capability faked (MemFs, FakeHasher,
//! FakeVerifier, FakeCodec, FakeClock).
//!
//! The second half (`Fixture`, `Site`) is the real-writer world of the scenario suite: releases
//! packed by the core's `ReleaseLayout` with the real LZMA codec, documents signed with real
//! Ed25519 keys generated at test time (never written into the repo), installs on a real
//! temporary directory.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use lunepack::{DownloadOptions, Layout, Updater, UpdaterBuilder, block_on, live_workers};
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::state::{InstallState, Loaded, Scope, UserScope, load};
use lunepack_core::{
    AppId, BoxFuture, Channel, CodecId, Fs, Hasher, PayloadKind, RelPath, ReleaseLayout, Request,
    Response, Signer, Target, Transport, TransportError, TrustedRoot, Version, pack_file,
};
use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file};
use lunepack_fs::StdFs;
use lunepack_testkit::exe_headers;
use lunepack_testkit::{
    ChainFixture, FAKE_BASE_URL, FakeClock, FakeCodec, FakeHasher, FakeOrigin, FakeTransport,
    FakeVerifier, MemFs, PackBuilder, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

pub const DAY: u64 = 86_400;
pub const TARGET: Target = Target::LinuxX86_64;
pub const INSTALL_ID: [u8; 16] = [7; 16];

static SERIAL: Mutex<()> = Mutex::new(());

/// Tests count process-wide workers; each takes this.
pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn wait_until(limit: Duration, cond: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

pub fn workers_stopped() {
    assert!(
        wait_until(Duration::from_secs(2), || live_workers() == 0),
        "workers still alive: {}",
        live_workers()
    );
}

pub fn app_id() -> AppId {
    AppId::parse(SUITE_APP_ID).expect("app id")
}

pub fn channel() -> Channel {
    Channel::parse(SUITE_CHANNEL).expect("channel")
}

pub fn version(text: &str) -> Version {
    Version::parse(text).expect("version")
}

/// The files of a release: `(path, bytes)`, all regular files.
pub fn files(version: &str) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "bin/app".to_owned(),
            format!("app {version}").repeat(40).into_bytes(),
        ),
        (
            "lib/common.so".to_owned(),
            b"shared library bytes".repeat(30),
        ),
        ("share/readme.txt".to_owned(), b"read me".repeat(10)),
        ("share/big.dat".to_owned(), vec![0x5a; 9000]),
    ]
}

pub struct World {
    pub fx: ChainFixture<'static>,
    pub origin: FakeOrigin,
    pub transport: Arc<dyn Transport>,
    pub fs: MemFs,
    pub clock: Arc<FakeClock>,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub versions_dir: PathBuf,
}

impl World {
    pub fn new() -> World {
        let fake = FakeTransport::new(FakeOrigin::new());
        let origin = fake.origin().clone();
        World::with_transport(origin, Arc::new(fake))
    }

    pub fn with_transport(origin: FakeOrigin, transport: Arc<dyn Transport>) -> World {
        let world = World {
            fx: ChainFixture::fake(),
            origin,
            transport,
            fs: MemFs::new(),
            clock: Arc::new(FakeClock::new(SUITE_T0 + 3600)),
            state_dir: PathBuf::from("/user/state"),
            cache_dir: PathBuf::from("/user/cache"),
            versions_dir: PathBuf::from("/user/versions"),
        };
        world.publish_keys();
        world
    }

    pub fn root(&self) -> TrustedRoot {
        self.fx.trusted_root(1, 1, &[0])
    }

    pub fn feed_url(&self) -> String {
        format!("{FAKE_BASE_URL}/feed-{SUITE_CHANNEL}.json")
    }

    /// `keys.json`: version 1 under root 1, release key seed 1, threshold 1.
    pub fn publish_keys(&self) {
        let ks = self.fx.keyset_document(1, 1, None, 1, &[1]);
        let bytes = self.fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        self.origin.put("keys.json", bytes);
    }

    /// The pack of `version` (each file one FakeCodec LZMA2 frame).
    pub fn pack(&self, version: &str) -> PackBuilder {
        let mut pack = PackBuilder::new();
        for (path, bytes) in files(version) {
            pack.file(&FakeHasher, &path, &bytes, CodecId::Lzma2);
        }
        pack
    }

    /// Publishes `version`'s manifest and pack, and a feed `seq` listing it (expires in 30 days).
    pub fn publish(&self, seq: u64, version: &str) -> PackBuilder {
        let pack = self.pack(version);
        self.publish_pack(seq, version, &pack);
        pack
    }

    /// Publishes `pack` as `version` and a feed `seq` listing it.
    pub fn publish_pack(&self, seq: u64, version: &str, pack: &PackBuilder) {
        let manifest = self.fx.manifest_document(version, TARGET, pack);
        let manifest_bytes = self
            .fx
            .envelope(PayloadKind::Manifest, &manifest.to_payload(), &[1]);
        self.origin.put(
            &format!("{version}/{}.manifest.json", TARGET.as_str()),
            manifest_bytes.clone(),
        );
        self.origin.put(
            &format!("{version}/{}.pack", TARGET.as_str()),
            pack.bytes.clone(),
        );
        let release = self.fx.release(version, &[(TARGET, &manifest_bytes)], None);
        self.publish_feed(seq, vec![release]);
    }

    pub fn publish_feed(&self, seq: u64, releases: Vec<lunepack_core::ReleaseDoc>) {
        let feed = self
            .fx
            .feed_document(seq, Some(SUITE_T0 + 30 * DAY), releases);
        let bytes = self
            .fx
            .envelope(PayloadKind::Feed, &feed.to_payload(), &[1]);
        self.origin
            .put(&format!("feed-{SUITE_CHANNEL}.json"), bytes);
    }

    /// The feed bytes now served (to replay later).
    pub fn feed_bytes(&self) -> Vec<u8> {
        self.served(&format!("feed-{SUITE_CHANNEL}.json"))
    }

    pub fn served(&self, name: &str) -> Vec<u8> {
        let fake = FakeTransport::new(self.origin.clone());
        lunepack::block_on(async move {
            let mut r = fake
                .get(Request {
                    url: format!("{FAKE_BASE_URL}/{name}"),
                    range: None,
                    if_range: None,
                })
                .await
                .expect("get");
            let mut out = Vec::new();
            while let Some(c) = r.body.next_chunk().await.expect("chunk") {
                out.extend_from_slice(&c);
            }
            out
        })
    }

    /// A user install of `current` (issued at `issued`), committed by the core's writer.
    pub fn install(&self, current: &str, issued: u64) -> InstallState {
        let record = InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET)
            .install(version(current), issued, TARGET, INSTALL_ID)
            .with_seq(1);
        self.commit_user(record)
    }

    /// Commits `record` (its seq is replaced by the next one) into the user state dir.
    pub fn commit_user(&self, record: InstallState) -> InstallState {
        let store = UserScope {
            dir: self.state_dir.clone(),
            app_id: app_id(),
        };
        let loaded = store.load(&self.fs, &FakeHasher).expect("load");
        let record = record.with_seq(loaded.next_seq);
        store
            .commit(&self.fs, &loaded, &record, &FakeHasher)
            .expect("commit");
        record
    }

    pub fn user_state(&self) -> Loaded<InstallState> {
        load::<InstallState>(&self.fs, &self.state_dir, &app_id(), &FakeHasher).expect("load")
    }

    /// Writes a tree for `version` under the versions dir with that version's files.
    pub fn write_tree(&self, dir: &Path, version: &str) {
        for (path, bytes) in files(version) {
            let full = dir.join(&path);
            self.fs
                .create_dir_all(full.parent().expect("parent"))
                .expect("dirs");
            let mut w = self.fs.create_new(&full).expect("create");
            std::io::Write::write_all(&mut w, &bytes).expect("write");
            w.sync().expect("sync");
        }
    }

    pub fn user_layout(&self, current_tree: Option<PathBuf>) -> Layout {
        Layout::User {
            state_dir: self.state_dir.clone(),
            cache_dir: self.cache_dir.clone(),
            versions_dir: self.versions_dir.clone(),
            current_tree,
        }
    }

    pub fn builder(&self, layout: Layout, fs: Arc<dyn Fs>) -> UpdaterBuilder {
        UpdaterBuilder::new(app_id(), self.root(), &self.feed_url(), channel(), layout)
            .transport(Arc::clone(&self.transport))
            .fs(fs)
            .hasher(Arc::new(FakeHasher))
            .verifier(Arc::new(FakeVerifier))
            .codec(Arc::new(FakeCodec::new()))
            .clock(Arc::clone(&self.clock) as Arc<dyn lunepack_core::Clock>)
            .workers(2)
    }

    pub fn updater(&self) -> Updater {
        self.builder(self.user_layout(None), Arc::new(self.fs.clone()))
            .build()
            .expect("build")
    }

    /// The bytes of the file at `path` on the world's disk.
    pub fn read(&self, path: &Path) -> Vec<u8> {
        self.fs.read_capped(path, 1 << 30).expect("read")
    }
}

impl Default for World {
    fn default() -> Self {
        World::new()
    }
}

/// A transport whose `get` waits at a gate until released (to hold an operation inside its lock).
pub struct GateTransport {
    pub inner: Arc<dyn Transport>,
    pub entered: Arc<AtomicBool>,
    pub open: Arc<AtomicBool>,
}

impl Transport for GateTransport {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let inner = Arc::clone(&self.inner);
        let entered = Arc::clone(&self.entered);
        let open = Arc::clone(&self.open);
        Box::pin(async move {
            entered.store(true, Ordering::SeqCst);
            // Pending until the gate opens; a helper thread re-wakes the task every 5 ms.
            std::future::poll_fn(|cx| {
                if open.load(Ordering::SeqCst) {
                    return std::task::Poll::Ready(());
                }
                let waker = cx.waker().clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(5));
                    waker.wake();
                });
                std::task::Poll::Pending
            })
            .await;
            inner.get(request).await
        })
    }
}

/// Hashing helper over the fake hasher.
pub fn sha(bytes: &[u8]) -> lunepack_core::Sha256Digest {
    FakeHasher.sha256(bytes)
}

// =====================================================================================================
// The real-writer world: real LZMA packs, real Ed25519 signatures, a real temporary directory.
// =====================================================================================================

pub const FEED_NAME: &str = "feed-stable.json";
/// The fake-origin feed URL (for injected transports).
pub fn fake_feed_url() -> String {
    format!("{FAKE_BASE_URL}/{FEED_NAME}")
}

/// One node of an input or output tree. Every directory is listed (parents included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    File { bytes: Vec<u8>, exec: bool },
    Dir,
    Symlink(String),
}

pub type Tree = BTreeMap<String, Node>;

#[derive(Default)]
struct TreeBuilder(Tree);

impl TreeBuilder {
    fn parents(&mut self, path: &str) {
        let mut at = 0;
        while let Some(i) = path[at..].find('/') {
            at += i;
            self.0.insert(path[..at].to_owned(), Node::Dir);
            at += 1;
        }
    }

    fn file(&mut self, path: &str, bytes: Vec<u8>, exec: bool) {
        self.parents(path);
        self.0.insert(path.to_owned(), Node::File { bytes, exec });
    }

    fn dir(&mut self, path: &str) {
        self.parents(path);
        self.0.insert(path.to_owned(), Node::Dir);
    }

    #[cfg(unix)]
    fn symlink(&mut self, path: &str, target: &str) {
        self.parents(path);
        self.0
            .insert(path.to_owned(), Node::Symlink(target.to_owned()));
    }
}

/// Deterministic incompressible bytes (xorshift64*).
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Compressible text.
pub fn text(len: usize, salt: u8) -> Vec<u8> {
    let line = format!("line {salt} of the shared library, repeated for the packer\n");
    line.bytes().cycle().take(len).collect()
}

/// A file that starts with a gzip magic (the packer stores it) followed by noise.
pub fn gz(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0x00];
    out.extend(noise(len - 4, seed));
    out
}

pub const V090: &str = "0.9.0";
pub const V100: &str = "1.0.0";
pub const V110: &str = "1.1.0";
/// 1.1.0 plus a large stored file: the progress tests' release.
pub const V120: &str = "1.2.0";

/// The input tree of a release: 1.0.0 (installed), 1.1.0 (changed, unchanged, renamed, empty,
/// exec, dir and symlink entries, `bcj` and stored frames) and 1.2.0 (1.1.0 plus 1.7 MB).
pub fn release_tree(version: &str) -> Tree {
    let n: u64 = match version {
        V100 => 0,
        V110 => 1,
        V120 => 2,
        other => panic!("no tree for {other}"),
    };
    let mut t = TreeBuilder::default();
    t.file(
        "bin/app",
        exe_headers::pe(0x8664, 60_000 + 4_000 * n as usize),
        true,
    );
    // Unchanged between releases, executable.
    t.file("bin/helper", exe_headers::elf(62, false, 30_000), true);
    // Unchanged, compressible: the scan finds it.
    t.file("lib/libcore.so", text(40_000, 1), false);
    #[cfg(unix)]
    t.symlink("lib/libcore.so.1", "libcore.so");
    // Same size, other bytes: the scan hashes it and the hash differs.
    t.file("share/data.bin", noise(20_000, 100 + n), false);
    t.file(
        "share/blob.gz",
        gz(150_000 + 100 * n as usize, 7 + n),
        false,
    );
    if n == 2 {
        t.file("share/big.gz", gz(1_700_000, 9), false);
    }
    // A rename: the same bytes under another name.
    t.file(
        if n == 0 {
            "docs/old.txt"
        } else {
            "docs/new.txt"
        },
        text(5_000, 3),
        false,
    );
    t.file("share/empty.txt", Vec::new(), false);
    t.dir("share/emptydir");
    t.file(
        "config/default.json",
        format!("{{\"version\":\"{version}\"}}").into_bytes(),
        false,
    );
    t.0
}

/// Fresh Ed25519 keys (seeds 0..=1), generated through the signer crate in a throwaway directory.
struct Keys(Vec<Ed25519Signer>);

impl Keys {
    fn generate() -> Keys {
        let dir = tempfile::tempdir().expect("tempdir");
        let signers = (0..2)
            .map(|i| {
                let key = generate_key_file(&dir.path().join(format!("k{i}"))).expect("key");
                Ed25519Signer::from_key_file(&key.path).expect("load key")
            })
            .collect();
        Keys(signers)
    }

    fn sign(&self, seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
        let signer = &self.0[usize::from(seed)];
        (
            signer.public_key(),
            signer.sign(message).expect("sign with a fresh key"),
        )
    }
}

/// Everything the published world holds, built once per process by the real writers.
pub struct Fixture {
    /// `keys.json`, the manifests and the packs, by path under the base URL.
    pub files: BTreeMap<String, Vec<u8>>,
    /// The feed documents: index 0 lists 1.0.0 (seq 1), 1 lists 1.1.0 (seq 2), 2 lists 1.2.0 (seq 3).
    pub feeds: Vec<Vec<u8>>,
    pub root_public: [u8; 32],
    /// The codec ids of 1.1.0's frames.
    pub codecs_110: BTreeSet<String>,
    /// The pack size of each release.
    pub pack_sizes: BTreeMap<&'static str, u64>,
}

pub fn pack_path(version: &str) -> String {
    format!("{version}/{}.pack", TARGET.as_str())
}

pub fn manifest_path(version: &str) -> String {
    format!("{version}/{}.manifest.json", TARGET.as_str())
}

pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(build_fixture)
}

fn build_fixture() -> Fixture {
    let keys = Keys::generate();
    let sign = |seed: u8, message: &[u8]| keys.sign(seed, message);
    let mut small_order = [0u8; 32];
    small_order[0] = 1;
    let fx = ChainFixture {
        hasher: &Sha256Hasher,
        verifier: &Ed25519Verifier,
        sign: &sign,
        invalid_key: small_order,
    };
    let mut files = BTreeMap::new();
    let ks = fx.keyset_document(1, 1, None, 1, &[1]);
    files.insert(
        "keys.json".to_owned(),
        fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]),
    );

    let mut feeds = Vec::new();
    let mut codecs_110 = BTreeSet::new();
    let mut pack_sizes = BTreeMap::new();
    for (version, issued, seq) in [
        (V100, SUITE_T0 - DAY, 1),
        (V110, SUITE_T0, 2),
        (V120, SUITE_T0, 3),
    ] {
        let mut layout = ReleaseLayout::new(app_id(), version, TARGET).expect("layout");
        for (path, node) in release_tree(version) {
            let rel = RelPath::parse(&path).expect("path");
            match node {
                Node::File { bytes, exec } => {
                    let packed = pack_file(&bytes, &LzmaCodec, &LzmaCodec, &Sha256Hasher)
                        .expect("pack file");
                    layout.add_file(rel, exec, &packed).expect("add file");
                }
                Node::Dir => layout.add_dir(rel).expect("add dir"),
                Node::Symlink(target) => layout.add_symlink(rel, &target).expect("add symlink"),
            }
        }
        let (doc, pack) = layout.finish(issued, &Sha256Hasher).expect("finish");
        if version == V110 {
            codecs_110 = doc
                .entries
                .iter()
                .filter_map(|e| e.frame.as_ref().map(|f| f.codec.clone()))
                .collect();
        }
        let manifest = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[1]);
        let release = fx.release(version, &[(TARGET, &manifest)], None);
        let feed = fx.feed_document(seq, Some(SUITE_T0 + 30 * DAY), vec![release]);
        feeds.push(fx.envelope(PayloadKind::Feed, &feed.to_payload(), &[1]));
        pack_sizes.insert(version, pack.len() as u64);
        files.insert(manifest_path(version), manifest);
        files.insert(pack_path(version), pack);
    }
    Fixture {
        files,
        feeds,
        root_public: fx.public_key(0),
        codecs_110,
        pack_sizes,
    }
}

impl Fixture {
    /// The trusted root the app compiles in (version 1, one key).
    pub fn root(&self) -> TrustedRoot {
        TrustedRoot::from_parts(
            app_id(),
            1,
            1,
            &[self.root_public],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .expect("root")
    }

    /// The feed document number `n` (1, 2 or 3).
    pub fn feed(&self, n: usize) -> &[u8] {
        &self.feeds[n - 1]
    }

    /// An origin serving every file and the feed `n`.
    pub fn origin(&self, n: usize) -> FakeOrigin {
        let origin = FakeOrigin::new();
        for (path, bytes) in &self.files {
            origin.put(path, bytes.clone());
        }
        origin.put(FEED_NAME, self.feed(n).to_vec());
        origin
    }

    /// Writes every file and the feed `n` into `dir` (a `file:` origin).
    pub fn write_dir(&self, dir: &Path, n: usize) {
        for (path, bytes) in &self.files {
            let full = dir.join(path);
            std::fs::create_dir_all(full.parent().expect("parent")).expect("dirs");
            std::fs::write(&full, bytes).expect("write");
        }
        std::fs::write(dir.join(FEED_NAME), self.feed(n)).expect("feed");
    }
}

/// An install on a real temporary directory.
pub struct Site {
    pub tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub versions_dir: PathBuf,
}

impl Site {
    /// Empty directories under a fresh temporary directory (resolved, so no symlinked component).
    pub fn empty() -> Site {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonical temp dir");
        let site = Site {
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            versions_dir: root.join("versions"),
            root,
            tmp,
        };
        for dir in [&site.state_dir, &site.cache_dir, &site.versions_dir] {
            std::fs::create_dir_all(dir).expect("dir");
        }
        site
    }

    /// The site's directories under `root` (what a second process rebuilds).
    pub fn at(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        (
            root.join("state"),
            root.join("cache"),
            root.join("versions"),
        )
    }

    pub fn layout(&self) -> Layout {
        Layout::User {
            state_dir: self.state_dir.clone(),
            cache_dir: self.cache_dir.clone(),
            versions_dir: self.versions_dir.clone(),
            current_tree: None,
        }
    }

    /// A builder with every default adapter (StdFs, LzmaCodec, SHA-256, Ed25519) and the real
    /// root; only the clock is fixed. Add a transport, or give a feed URL the defaults serve.
    pub fn builder(&self, feed_url: &str) -> UpdaterBuilder {
        UpdaterBuilder::new(
            app_id(),
            fixture().root(),
            feed_url,
            channel(),
            self.layout(),
        )
        .clock(Arc::new(FakeClock::new(SUITE_T0 + 3600)))
        .workers(2)
    }

    /// Commits the record `f` makes from the loaded one, with the real filesystem and hasher.
    pub fn commit(&self, f: impl FnOnce(Option<&InstallState>) -> InstallState) -> InstallState {
        let store = UserScope {
            dir: self.state_dir.clone(),
            app_id: app_id(),
        };
        let loaded = store.load(&StdFs::new(), &Sha256Hasher).expect("load");
        let record = f(loaded.record.as_ref()).with_seq(loaded.next_seq);
        store
            .commit(&StdFs::new(), &loaded, &record, &Sha256Hasher)
            .expect("commit");
        record
    }

    /// A site with 0.9.0 installed and no tree for it (every file of a later release is fetched).
    pub fn with_090() -> Site {
        let site = Site::empty();
        site.commit(|_| {
            InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET).install(
                version(V090),
                SUITE_T0 - 30 * DAY,
                TARGET,
                INSTALL_ID,
            )
        });
        site
    }

    /// A site with 1.0.0 installed: 0.9.0 first, then 1.0.0 checked, downloaded and staged by the
    /// updater itself and committed as current.
    pub fn with_baseline() -> Site {
        let site = Site::with_090();
        let transport = FakeTransport::new(fixture().origin(1));
        let u = site
            .builder(&fake_feed_url())
            .transport(Arc::new(transport))
            .build()
            .expect("build");
        let info = block_on(u.check())
            .expect("check 1.0.0")
            .expect("1.0.0 is offered");
        assert_eq!(info.version_text(), V100);
        let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
        let staged = block_on(u.stage(downloaded)).expect("stage");
        assert_eq!(staged.tree(), site.versions_dir.join(V100));
        site.commit(|r| {
            r.expect("state")
                .install(version(V100), info.issued(), TARGET, INSTALL_ID)
        });
        site
    }

    pub fn tree(&self, version: &str) -> PathBuf {
        self.versions_dir.join(version)
    }
}

/// Reads a directory into a [`Tree`] (exec bits on Unix only; symlinks are read, not followed).
pub fn read_tree(root: &Path) -> Tree {
    fn walk(root: &Path, dir: &Path, out: &mut Tree) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            let rel = path
                .strip_prefix(root)
                .expect("inside")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let meta = std::fs::symlink_metadata(&path).expect("lstat");
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).expect("readlink");
                out.insert(rel, Node::Symlink(target.to_string_lossy().into_owned()));
            } else if meta.is_dir() {
                out.insert(rel, Node::Dir);
                walk(root, &path, out);
            } else {
                #[cfg(unix)]
                let exec = {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let exec = false;
                out.insert(
                    rel,
                    Node::File {
                        bytes: std::fs::read(&path).expect("read"),
                        exec,
                    },
                );
            }
        }
    }
    let mut out = Tree::new();
    walk(root, root, &mut out);
    out
}

/// Asserts `dir` holds exactly `expected` (byte for byte; exec bits compared on Unix).
pub fn assert_tree(dir: &Path, expected: &Tree) {
    let actual = read_tree(dir);
    let norm = |t: &Tree| -> Tree {
        t.iter()
            .map(|(k, v)| {
                let v = match v {
                    Node::File { bytes, exec } => Node::File {
                        bytes: bytes.clone(),
                        exec: *exec && cfg!(unix),
                    },
                    other => other.clone(),
                };
                (k.clone(), v)
            })
            .collect()
    };
    let (actual, expected) = (norm(&actual), norm(expected));
    let a: BTreeSet<&String> = actual.keys().collect();
    let e: BTreeSet<&String> = expected.keys().collect();
    assert_eq!(a, e, "the tree's paths differ");
    for (path, node) in &expected {
        assert!(
            actual[path] == *node,
            "{path}: the staged entry differs from the input ({} vs {})",
            describe(&actual[path]),
            describe(node)
        );
    }
}

fn describe(node: &Node) -> String {
    match node {
        Node::File { bytes, exec } => format!("file of {} bytes, exec {exec}", bytes.len()),
        Node::Dir => "dir".to_owned(),
        Node::Symlink(t) => format!("symlink to {t}"),
    }
}

/// Every path under `dir` whose name ends with `suffix`.
pub fn find_suffix(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.to_string_lossy().ends_with(suffix) {
            out.push(path.clone());
        }
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            out.extend(find_suffix(&path, suffix));
        }
    }
    out
}

/// A 1.0.0 install built once, copied for every run that needs its own directories (the copy is
/// byte for byte, symlinks and modes included).
pub struct Baseline(Site);

impl Baseline {
    pub fn new() -> Baseline {
        Baseline(Site::with_baseline())
    }

    pub fn fresh(&self) -> Site {
        let site = Site::empty();
        for (from, to) in [
            (&self.0.state_dir, &site.state_dir),
            (&self.0.cache_dir, &site.cache_dir),
            (&self.0.versions_dir, &site.versions_dir),
        ] {
            copy_dir(from, to);
        }
        site
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline::new()
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("dir");
    for entry in std::fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("entry");
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type().expect("file type");
        if kind.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(std::fs::read_link(&src).expect("readlink"), &dst)
                .expect("symlink");
        } else if kind.is_dir() {
            copy_dir(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).expect("copy");
        }
    }
}

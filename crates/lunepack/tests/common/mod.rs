//! A published release world for the updater tests: signed documents written by the testkit's
//! builders (the same writers the suites use), served by a `FakeTransport`, an install state
//! committed by the core's real writer, and every capability faked (MemFs, FakeHasher,
//! FakeVerifier, FakeCodec, FakeClock).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use lunepack::{Layout, Updater, UpdaterBuilder, live_workers};
use lunepack_core::state::{InstallState, Loaded, Scope, UserScope, load};
use lunepack_core::{
    AppId, BoxFuture, Channel, CodecId, Fs, Hasher, PayloadKind, Request, Response, Target,
    Transport, TransportError, TrustedRoot, Version,
};
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

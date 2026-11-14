//! The [`Updater`] (C9): check for an update, download it resumably and stage a verified version
//! tree, on any async executor (or none, through [`crate::blocking`]).
//!
//! Every operation takes the updater lock (`<state dir>/lock`; for a machine install the user
//! state dir) on a short job when it starts, and a held lock is [`Error::Busy`] at once. The
//! operation's future holds one clone of the lock and every job it spawns holds another, so the
//! lock is released only when the future and all of its workers are gone (M4-D15). All file I/O
//! runs on lunepack worker threads; transports are polled on the caller's task (M4-D2).
//!
//! State changes only at a commit: `check` raises the floors after a fully verified check, `stage`
//! records the staged tree after it is complete. A failing or cancelled operation leaves the state
//! as it was (FORMAT.md 11.1).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::{Future, poll_fn};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lunepack_core::fetch::FetchPolicy;
use lunepack_core::state::{
    Floors, InstallCounters, InstallState, Loaded, MachineScope as MachineStore, RootParts,
    StagedRef, UserScope,
};
use lunepack_core::{
    AppId, BlockingResponse, BlockingTransport, CancelToken, Channel, ClockReading, Codec,
    FileKind, Fs, Hasher, Limits, Phase, Progress, Request, Sha256Digest, SourceFor, StageEnv,
    StageError, StageInput, Target, Transport, TransportError, TrustedRoot, VerifiedEntry,
    VerifiedManifest, Verifier, Version, advance_root, select_candidate, verify_feed,
    verify_key_set, verify_manifest,
};

use crate::cache::{Cache, CacheKind};
use crate::fetch::{self, FeedUrls, FetchCtx, FrameNeed, PackTarget, cancellable};
use crate::progress::{ProgressPump, ProgressSink, progress};
use crate::task::{OpLock, spawn_job};
use crate::worker_transport::WorkerTransport;
use crate::{Error, SystemClock};

/// The most root rotations one check walks (a bound on a hostile mirror's root chain).
const MAX_ROOT_STEPS: u64 = 1024;
/// The default stage memory budget (M4-D11).
const DEFAULT_BUDGET: u64 = 256 * 1024 * 1024;

// ---- configuration -------------------------------------------------------------------------------

/// Where an install keeps its state, cache and version trees (M4-D4).
///
/// Version `V`'s tree is `<versions_dir>/<V's version text>`. The current tree is `current_tree`
/// when given (for a layout whose live tree is not under `versions_dir`), else
/// `<versions_dir>/<current version>`; it counts only when it is a real directory (not a
/// symlink). Without a current tree every file is fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Layout {
    /// A per-user install.
    User {
        /// The install-state directory.
        state_dir: PathBuf,
        /// The download cache.
        cache_dir: PathBuf,
        /// Where version trees are staged.
        versions_dir: PathBuf,
        /// The live tree, when it is not `<versions_dir>/<current>`.
        current_tree: Option<PathBuf>,
    },
    /// A per-machine install: the library reads the machine state and tree, never writes them, and
    /// keeps this user's floors and cache in the user's directories (C3).
    Machine {
        /// The machine install's state directory (read-only here).
        machine_state_dir: PathBuf,
        /// This user's state directory (counters records and the lock).
        user_state_dir: PathBuf,
        /// This user's download cache.
        cache_dir: PathBuf,
        /// The machine install's version trees (read-only), if readable.
        versions_dir: Option<PathBuf>,
        /// The machine install's live tree, when it is not under `versions_dir`.
        current_tree: Option<PathBuf>,
    },
}

impl Layout {
    fn lock_dir(&self) -> &Path {
        match self {
            Layout::User { state_dir, .. } => state_dir,
            Layout::Machine { user_state_dir, .. } => user_state_dir,
        }
    }

    fn cache_dir(&self) -> &Path {
        match self {
            Layout::User { cache_dir, .. } | Layout::Machine { cache_dir, .. } => cache_dir,
        }
    }

    fn versions_dir(&self) -> Option<&Path> {
        match self {
            Layout::User { versions_dir, .. } => Some(versions_dir),
            Layout::Machine { versions_dir, .. } => versions_dir.as_deref(),
        }
    }

    fn current_tree(&self) -> Option<&Path> {
        match self {
            Layout::User { current_tree, .. } | Layout::Machine { current_tree, .. } => {
                current_tree.as_deref()
            }
        }
    }

    fn map(&self, f: impl Fn(&Path) -> PathBuf) -> Layout {
        match self {
            Layout::User {
                state_dir,
                cache_dir,
                versions_dir,
                current_tree,
            } => Layout::User {
                state_dir: f(state_dir),
                cache_dir: f(cache_dir),
                versions_dir: f(versions_dir),
                current_tree: current_tree.as_deref().map(&f),
            },
            Layout::Machine {
                machine_state_dir,
                user_state_dir,
                cache_dir,
                versions_dir,
                current_tree,
            } => Layout::Machine {
                machine_state_dir: f(machine_state_dir),
                user_state_dir: f(user_state_dir),
                cache_dir: f(cache_dir),
                versions_dir: versions_dir.as_deref().map(&f),
                current_tree: current_tree.as_deref().map(&f),
            },
        }
    }
}

/// Timeouts of the default HTTP transport (M4-D14). There is no global timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Longest wait for a connection, TLS included.
    pub connect: Duration,
    /// Longest wait for one read.
    pub read: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(30),
            read: Duration::from_secs(30),
        }
    }
}

/// Builds an [`Updater`]; every capability has a default adapter and can be replaced.
pub struct UpdaterBuilder {
    app_id: AppId,
    root: TrustedRoot,
    feed_url: String,
    channel: Channel,
    layout: Layout,
    transport: Option<Arc<dyn Transport>>,
    blocking_transport: Option<Arc<dyn BlockingTransport>>,
    fs: Option<Arc<dyn Fs>>,
    codec: Option<Arc<dyn Codec>>,
    hasher: Option<Arc<dyn Hasher>>,
    verifier: Option<Arc<dyn Verifier>>,
    clock: Option<Arc<dyn lunepack_core::Clock>>,
    workers: Option<usize>,
    budget: u64,
    policy: FetchPolicy,
    timeouts: Timeouts,
}

impl fmt::Debug for UpdaterBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdaterBuilder").finish_non_exhaustive()
    }
}

impl UpdaterBuilder {
    /// A builder for the app `app_id`, trusting `trusted_root` (kept in the app's code, D44 note),
    /// reading the feed at `feed_url` on `channel`, with the install's `layout`.
    pub fn new(
        app_id: AppId,
        trusted_root: TrustedRoot,
        feed_url: &str,
        channel: Channel,
        layout: Layout,
    ) -> Self {
        UpdaterBuilder {
            app_id,
            root: trusted_root,
            feed_url: feed_url.to_owned(),
            channel,
            layout,
            transport: None,
            blocking_transport: None,
            fs: None,
            codec: None,
            hasher: None,
            verifier: None,
            clock: None,
            workers: None,
            budget: DEFAULT_BUDGET,
            policy: FetchPolicy::default(),
            timeouts: Timeouts::default(),
        }
    }

    /// An async transport (polled on the caller's task); wins over every other transport.
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// A blocking transport, run on lunepack worker threads.
    pub fn blocking_transport(mut self, transport: Arc<dyn BlockingTransport>) -> Self {
        self.blocking_transport = Some(transport);
        self
    }

    /// The filesystem (default: `lunepack-fs`).
    pub fn fs(mut self, fs: Arc<dyn Fs>) -> Self {
        self.fs = Some(fs);
        self
    }

    /// The frame decoder (default: `lunepack-codec-lzma`).
    pub fn codec(mut self, codec: Arc<dyn Codec>) -> Self {
        self.codec = Some(codec);
        self
    }

    /// SHA-256 (default: `lunepack-crypto`).
    pub fn hasher(mut self, hasher: Arc<dyn Hasher>) -> Self {
        self.hasher = Some(hasher);
        self
    }

    /// The signature verifier (default: `lunepack-crypto` Ed25519).
    pub fn verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// The clock (default: [`SystemClock`]).
    pub fn clock(mut self, clock: Arc<dyn lunepack_core::Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Worker threads for scan and stage (default `min(available_parallelism, 8)`).
    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = Some(workers);
        self
    }

    /// The stage memory budget in bytes (default 256 MiB, M4-D11).
    pub fn memory_budget(mut self, bytes: u64) -> Self {
        self.budget = bytes;
        self
    }

    /// The fetch strategy (M4-D8).
    pub fn fetch_policy(mut self, policy: FetchPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Timeouts of the default HTTP transport.
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Wires the defaults and checks the configuration. A development run with no install state
    /// builds fine; its operations report [`Error::NotInstalled`].
    pub fn build(self) -> Result<Updater, Error> {
        let urls = FeedUrls::new(&self.feed_url)?;
        if self.root.app_id() != &self.app_id {
            return Err(Error::Verify(lunepack_core::Error::AppIdMismatch));
        }
        let (fs, layout): (Arc<dyn Fs>, Layout) = match self.fs {
            Some(fs) => (fs, self.layout),
            None => (
                Arc::new(lunepack_fs::StdFs::new()),
                // lunepack-fs refuses symlinked components (macOS /var, a symlinked home):
                // resolve the layout's existing ancestors once.
                self.layout.map(canonical),
            ),
        };
        let transport: Arc<dyn Transport> = match (self.transport, self.blocking_transport) {
            (Some(t), _) => t,
            (None, Some(b)) => Arc::new(WorkerTransport::new(DynBlocking(b))),
            (None, None) => default_transport(&self.feed_url, self.timeouts)?,
        };
        let workers = self.workers.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(8)
        });
        let feed_url = urls.feed(&self.channel)?;
        Ok(Updater {
            inner: Arc::new(Inner {
                app_id: self.app_id,
                root: self.root,
                urls,
                feed_url,
                channel: self.channel,
                layout,
                transport,
                fs,
                codec: self
                    .codec
                    .unwrap_or_else(|| Arc::new(lunepack_codec_lzma::LzmaCodec)),
                hasher: self
                    .hasher
                    .unwrap_or_else(|| Arc::new(lunepack_crypto::Sha256Hasher)),
                verifier: self
                    .verifier
                    .unwrap_or_else(|| Arc::new(lunepack_crypto::Ed25519Verifier)),
                clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
                workers: workers.max(1),
                budget: self.budget,
                policy: self.policy,
            }),
        })
    }
}

/// `path` with its longest existing ancestor resolved through the OS (symlinks included), the rest
/// appended as given.
fn canonical(path: &Path) -> PathBuf {
    let mut head = path.to_path_buf();
    let mut tail = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&head) {
            let mut out = resolved;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (head.file_name().map(|n| n.to_os_string()), head.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                head = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// The default transport: ureq for `http`/`https`, the directory source for `file:`.
fn default_transport(feed_url: &str, timeouts: Timeouts) -> Result<Arc<dyn Transport>, Error> {
    let url =
        url::Url::parse(feed_url).map_err(|_| Error::Config("feed URL is not a valid URL"))?;
    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|()| Error::Config("feed file URL has no local path"))?;
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .ok_or(Error::Config("feed file URL has no directory"))?;
        return Ok(Arc::new(WorkerTransport::new(
            lunepack_http::DirSource::new(root),
        )));
    }
    let options = lunepack_http::UreqOptions {
        connect_timeout: timeouts.connect,
        read_timeout: timeouts.read,
        ..lunepack_http::UreqOptions::default()
    };
    Ok(Arc::new(WorkerTransport::new(
        lunepack_http::UreqTransport::with_options(&options),
    )))
}

/// A shared blocking transport, so an `Arc<dyn BlockingTransport>` can run on worker threads.
struct DynBlocking(Arc<dyn BlockingTransport>);

impl BlockingTransport for DynBlocking {
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError> {
        self.0.get(request, cancel)
    }
}

// ---- public values -------------------------------------------------------------------------------

/// An update found by [`Updater::check`]: a verified manifest of a newer version.
#[derive(Clone)]
pub struct UpdateInfo {
    version: Version,
    version_text: String,
    target: Target,
    issued: u64,
    feed_seq: u64,
    time_checked: bool,
    manifest: Arc<VerifiedManifest>,
    manifest_sha256: Sha256Digest,
    pack: PackTarget,
}

impl fmt::Debug for UpdateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateInfo")
            .field("version", &self.version_text)
            .field("target", &self.target)
            .field("issued", &self.issued)
            .field("feed_seq", &self.feed_seq)
            .field("time_checked", &self.time_checked)
            .finish_non_exhaustive()
    }
}

impl UpdateInfo {
    /// The new version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The version as the feed writes it.
    pub fn version_text(&self) -> &str {
        &self.version_text
    }

    /// The manifest's target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// The manifest's `issued` time.
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The `seq` of the feed it came from.
    pub fn feed_seq(&self) -> u64 {
        self.feed_seq
    }

    /// Whether expiry and key windows were checked; `false` when the clock was implausible
    /// (before the installed version's `issued`) and they were skipped (FORMAT.md 11.3).
    pub fn time_checked(&self) -> bool {
        self.time_checked
    }

    /// The most bytes a download can fetch: the pack's signed size.
    pub fn download_size_max(&self) -> u64 {
        self.pack.size
    }
}

/// The installed version (from the install state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledVersion {
    version: Version,
    issued: u64,
    target: Target,
}

impl InstalledVersion {
    /// The installed version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Its manifest's `issued` time.
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The target the install uses.
    pub fn target(&self) -> Target {
        self.target
    }
}

/// A staged version tree, ready for the apply step (C4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVersion {
    version: Version,
    target: Target,
    tree: PathBuf,
}

impl StagedVersion {
    /// The staged version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Its target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// The tree's directory.
    pub fn tree(&self) -> &Path {
        &self.tree
    }
}

/// A progress callback; it runs on the thread that polls the operation.
pub type ProgressCallback = Box<dyn FnMut(&Progress) + Send>;

/// Options of [`Updater::download`] (and, carried by [`Downloaded`], of [`Updater::stage`]).
#[derive(Default)]
pub struct DownloadOptions {
    /// Called with coalesced progress events on the polling thread.
    pub progress: Option<ProgressCallback>,
    /// Cancels the operation (dropping its future does too).
    pub cancel: Option<CancelToken>,
}

impl fmt::Debug for DownloadOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadOptions")
            .field("progress", &self.progress.is_some())
            .field("cancel", &self.cancel)
            .finish()
    }
}

/// A completed download, the input of [`Updater::stage`].
pub struct Downloaded {
    info: UpdateInfo,
    /// Per manifest entry: the current-tree file that already matches it.
    unchanged: Vec<Option<PathBuf>>,
    frames: HashMap<Sha256Digest, PathBuf>,
    pack: Option<PathBuf>,
    options: DownloadOptions,
}

impl fmt::Debug for Downloaded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Downloaded")
            .field("info", &self.info)
            .field("frames", &self.frames.len())
            .field("pack", &self.pack.is_some())
            .finish_non_exhaustive()
    }
}

impl Downloaded {
    /// The update it downloaded.
    pub fn info(&self) -> &UpdateInfo {
        &self.info
    }

    /// Replaces the options `stage` runs with.
    pub fn with_options(mut self, options: DownloadOptions) -> Self {
        self.options = options;
        self
    }
}

// ---- the updater ---------------------------------------------------------------------------------

/// The updater handle: cheap to clone (an `Arc`), `Send + Sync`.
#[derive(Clone)]
pub struct Updater {
    inner: Arc<Inner>,
}

impl fmt::Debug for Updater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Updater").finish_non_exhaustive()
    }
}

struct Inner {
    app_id: AppId,
    root: TrustedRoot,
    urls: FeedUrls,
    feed_url: String,
    channel: Channel,
    layout: Layout,
    transport: Arc<dyn Transport>,
    fs: Arc<dyn Fs>,
    codec: Arc<dyn Codec>,
    hasher: Arc<dyn Hasher>,
    verifier: Arc<dyn Verifier>,
    clock: Arc<dyn lunepack_core::Clock>,
    workers: usize,
    budget: u64,
    policy: FetchPolicy,
}

/// The loaded state of either scope.
#[derive(Clone)]
enum Snapshot {
    User {
        store: UserScope,
        loaded: Box<Loaded<InstallState>>,
        record: InstallState,
    },
    Machine {
        store: MachineStore,
        machine: InstallState,
        counters: Box<Loaded<InstallCounters>>,
    },
}

impl Snapshot {
    /// The record that describes the install.
    fn record(&self) -> &InstallState {
        match self {
            Snapshot::User { record, .. } => record,
            Snapshot::Machine { machine, .. } => machine,
        }
    }

    /// The floors a check starts from (machine: the higher of machine and user, C3).
    fn floors(&self) -> Floors {
        match self {
            Snapshot::User { record, .. } => record.floors.clone(),
            Snapshot::Machine {
                machine, counters, ..
            } => MachineStore::effective_floors(machine, counters.record.as_ref()),
        }
    }
}

impl Inner {
    /// Loads the install state (blocking; on a job, or directly for the read-only calls).
    fn load(&self) -> Result<Snapshot, Error> {
        match &self.layout {
            Layout::User { state_dir, .. } => {
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: self.app_id.clone(),
                };
                let loaded = store.load(&*self.fs, &*self.hasher)?;
                let record = loaded.record.clone().ok_or(Error::NotInstalled)?;
                Ok(Snapshot::User {
                    store,
                    loaded: Box::new(loaded),
                    record,
                })
            }
            Layout::Machine {
                machine_state_dir,
                user_state_dir,
                ..
            } => {
                let store = MachineStore {
                    machine_dir: machine_state_dir.clone(),
                    user_dir: user_state_dir.clone(),
                    app_id: self.app_id.clone(),
                };
                let loaded = store.load_machine(&*self.fs, &*self.hasher)?;
                let machine = loaded.record.ok_or(Error::NotInstalled)?;
                let counters = store.load_counters(&*self.fs, &machine, &*self.hasher)?;
                Ok(Snapshot::Machine {
                    store,
                    machine,
                    counters: Box::new(counters),
                })
            }
        }
    }

    /// Commits `floors` (raised with max, never lowered): the user record, or this user's counters
    /// for a machine install. Nothing is written when no floor rises.
    fn commit_floors(&self, snap: &Snapshot, floors: &Floors) -> Result<(), Error> {
        match snap {
            Snapshot::User {
                store,
                loaded,
                record,
            } => {
                if record.floors.max(floors) == record.floors {
                    return Ok(());
                }
                let next = record.raise_floors(floors).with_seq(loaded.next_seq);
                store.commit(&*self.fs, loaded, &next, &*self.hasher)?;
            }
            Snapshot::Machine {
                store,
                machine,
                counters,
            } => {
                let base = counters.record.clone().unwrap_or_else(|| {
                    InstallCounters::new(counters.next_seq, self.app_id.clone(), machine.install_id)
                });
                let effective = MachineStore::effective_floors(machine, counters.record.as_ref());
                if counters.record.is_some() && effective.max(floors) == effective {
                    return Ok(());
                }
                let next = base.raise_floors(floors).with_seq(counters.next_seq);
                store.commit_counters(&*self.fs, machine, counters, &next, &*self.hasher)?;
            }
        }
        Ok(())
    }

    /// The current tree per M4-D4: `current_tree`, else `<versions_dir>/<current>`, counted only
    /// as a real directory.
    fn current_tree(&self, current: Option<&Version>) -> Result<Option<PathBuf>, Error> {
        let candidate = match (
            self.layout.current_tree(),
            self.layout.versions_dir(),
            current,
        ) {
            (Some(tree), _, _) => tree.to_path_buf(),
            (None, Some(versions), Some(v)) => versions.join(v.to_string()),
            _ => return Ok(None),
        };
        Ok(is_real_dir(&*self.fs, &candidate)?.then_some(candidate))
    }

    fn cache(&self) -> Cache {
        Cache::new(Arc::clone(&self.fs), self.layout.cache_dir().to_path_buf())
    }
}

/// Whether `path` is a real directory (not a symlink); a missing path or parent is `false`.
fn is_real_dir(fs: &dyn Fs, path: &Path) -> Result<bool, Error> {
    match fs.symlink_metadata(path) {
        Ok(meta) => Ok(meta.is_some_and(|m| m.kind == FileKind::Dir)),
        Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Runs `f` over the updater on a job that holds `lock`, cancellable through `cancel`.
async fn on_job<T, F>(
    inner: &Arc<Inner>,
    lock: Option<&OpLock>,
    cancel: &CancelToken,
    name: &'static str,
    f: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(&Inner, &CancelToken) -> Result<T, Error> + Send + 'static,
{
    let inner = Arc::clone(inner);
    let op_cancel = cancel.clone();
    let future = spawn_job(name, CancelToken::new(), lock.cloned(), move |_| {
        f(&inner, &op_cancel)
    });
    cancellable(cancel, future).await??
}

/// Takes the updater lock on a short job: [`Error::Busy`] when it is held.
async fn take_lock(inner: &Arc<Inner>, cancel: &CancelToken) -> Result<OpLock, Error> {
    on_job(inner, None, cancel, "lock", |inner, _| {
        let dir = inner.layout.lock_dir();
        inner.fs.create_dir_all(dir)?;
        match inner.fs.try_lock(&dir.join("lock"))? {
            Some(guard) => Ok(OpLock::new(guard)),
            None => Err(Error::Busy),
        }
    })
    .await
}

/// Runs `future`, pumping `pump` into `callback` on every poll (and once at the end), so progress
/// callbacks run only on the polling thread.
async fn with_progress<F: Future>(
    pump: &mut ProgressPump,
    callback: &mut Option<ProgressCallback>,
    future: F,
) -> F::Output {
    let mut future = pin!(future);
    poll_fn(|cx| {
        pump.register_waker(cx.waker());
        let out = future.as_mut().poll(cx);
        if let Some(cb) = callback.as_mut() {
            pump.pump(&mut |p: &Progress| cb(p));
        }
        out
    })
    .await
}

/// Forwards a core progress event (a running total) into a sink as deltas.
fn forward(sink: &ProgressSink, last: &AtomicU64, event: &Progress) {
    let before = last.swap(event.done, Ordering::SeqCst);
    sink.add_done(event.done.saturating_sub(before));
    sink.set_file(event.file.clone());
}

fn frames_of(manifest: &VerifiedManifest) -> Vec<(usize, FrameNeed)> {
    manifest
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            VerifiedEntry::File { frame: Some(f), .. } => Some((
                i,
                FrameNeed {
                    offset: f.offset(),
                    length: f.length(),
                    sha256: f.sha256(),
                },
            )),
            _ => None,
        })
        .collect()
}

/// The decoded bytes of every file of `manifest` (a phase total for scan and stage).
fn file_bytes(manifest: &VerifiedManifest) -> u64 {
    manifest.entries().iter().fold(0u64, |sum, e| match e {
        VerifiedEntry::File { frame: Some(f), .. } => sum.saturating_add(f.file_size()),
        _ => sum,
    })
}

impl Updater {
    /// Checks the feed for an update (FORMAT.md 11.1): walks the root from the higher of the stored
    /// and the embedded root, verifies the key set and the feed against the floors, selects the
    /// candidate and fetches and verifies its manifest. Then the floors are raised (user record,
    /// or this user's counters for a machine install). A failing check changes no state.
    pub fn check(
        &self,
    ) -> impl Future<Output = Result<Option<UpdateInfo>, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { check(inner).await }
    }

    /// Downloads what staging `info` needs that the current tree and the cache lack: scan (phase
    /// `Scan`), then Range runs or the full pack (phase `Download`). Resumable: an interrupted
    /// download continues on the next call.
    pub fn download(
        &self,
        info: &UpdateInfo,
        options: DownloadOptions,
    ) -> impl Future<Output = Result<Downloaded, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        let info = info.clone();
        async move { download(inner, info, options).await }
    }

    /// Builds and verifies the version tree from a download (phase `Stage`), fetching what fails by
    /// Range and then by the full pack (D27, M4-D20), and records it as staged. User scope only.
    pub fn stage(
        &self,
        downloaded: Downloaded,
    ) -> impl Future<Output = Result<StagedVersion, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { stage(inner, downloaded).await }
    }

    /// The installed version; `Ok(None)` in a development run (no install state). Takes no lock.
    pub fn installed(&self) -> Result<Option<InstalledVersion>, Error> {
        let snap = match self.inner.load() {
            Ok(snap) => snap,
            Err(Error::NotInstalled) => return Ok(None),
            Err(e) => return Err(e),
        };
        let record = snap.record();
        Ok(record.current.as_ref().map(|c| InstalledVersion {
            version: c.version.clone(),
            issued: c.issued,
            target: record.target,
        }))
    }

    /// The staged version, when it is newer than the installed one, not marked bad, of the
    /// install's target, and its tree is a real directory (M4-D18). Takes no lock.
    pub fn staged(&self) -> Result<Option<StagedVersion>, Error> {
        let snap = match self.inner.load() {
            Ok(snap) => snap,
            Err(Error::NotInstalled) => return Ok(None),
            Err(e) => return Err(e),
        };
        let record = snap.record();
        let Some(staged) = &record.staged else {
            return Ok(None);
        };
        if record
            .current
            .as_ref()
            .is_some_and(|c| staged.version <= c.version)
            || record.bad.contains(&staged.version)
            || staged.target != record.target
        {
            return Ok(None);
        }
        let Some(versions) = self.inner.layout.versions_dir() else {
            return Ok(None);
        };
        let tree = versions.join(&staged.tree);
        Ok(is_real_dir(&*self.inner.fs, &tree)?.then(|| StagedVersion {
            version: staged.version.clone(),
            target: staged.target,
            tree,
        }))
    }
}

async fn check(inner: Arc<Inner>) -> Result<Option<UpdateInfo>, Error> {
    let cancel = CancelToken::new();
    let lock = take_lock(&inner, &cancel).await?;
    let snap = on_job(&inner, Some(&lock), &cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    let record = snap.record().clone();
    let current = record.current.clone().ok_or(Error::NotInstalled)?;
    let floors = snap.floors();
    let clock = ClockReading::read(&*inner.clock, Some(current.issued));
    let hasher = &*inner.hasher;
    let verifier = &*inner.verifier;
    let transport = &*inner.transport;

    // Root walk (FORMAT.md 5.2) from the higher of the stored and the embedded root.
    let mut root = match &floors.root {
        Some(parts) if parts.version > inner.root.version() => {
            parts.to_trusted(inner.app_id.clone(), hasher, verifier)?
        }
        _ => inner.root.clone(),
    };
    for _ in 0..MAX_ROOT_STEPS {
        let url = inner.urls.root(root.version().saturating_add(1))?;
        match fetch::fetch_root_doc(transport, &url, Limits::V1.root_doc_bytes).await? {
            None => break,
            Some(bytes) => root = advance_root(&root, &bytes, hasher, verifier)?,
        }
    }
    if root.app_id() != &inner.app_id {
        return Err(Error::Verify(lunepack_core::Error::AppIdMismatch));
    }
    let floor = floors.to_rollback_floor();
    let keys_bytes =
        fetch::fetch_document(transport, &inner.urls.keys()?, Limits::V1.keys_doc_bytes).await?;
    let keys = verify_key_set(&root, &keys_bytes, &floor, &clock, hasher, verifier)?;
    let feed_bytes =
        fetch::fetch_document(transport, &inner.feed_url, Limits::V1.feed_doc_bytes).await?;
    let feed = verify_feed(
        &keys,
        &feed_bytes,
        &inner.app_id,
        &inner.channel,
        &floor,
        &clock,
        verifier,
    )?;
    let candidate = select_candidate(
        &feed,
        &current.version,
        record.target,
        &record.bad,
        &record.install_id,
        hasher,
    );
    let info = match candidate {
        None => None,
        Some(candidate) => {
            let reference = candidate.entry.reference();
            let url = inner.urls.reference(reference)?;
            let bytes = fetch::fetch_document(transport, &url, reference.size()).await?;
            let manifest = verify_manifest(&keys, &candidate.entry, &bytes, hasher, verifier)?;
            let pack = manifest.pack();
            let pack = PackTarget {
                url: inner.urls.reference(pack)?,
                size: pack.size(),
                sha256: pack.sha256(),
            };
            Some(UpdateInfo {
                version: manifest.version().clone(),
                version_text: candidate.entry.version_text().to_owned(),
                target: manifest.target(),
                issued: manifest.issued(),
                feed_seq: feed.seq(),
                time_checked: feed.time_checked() && keys.expiry_checked(),
                manifest_sha256: reference.sha256(),
                manifest: Arc::new(manifest),
                pack,
            })
        }
    };
    let mut raised = Floors {
        root: Some(RootParts::from_trusted(&root)),
        keyset_version: keys.version(),
        ..Floors::default()
    };
    raised.feed_seq.insert(inner.channel.clone(), feed.seq());
    on_job(
        &inner,
        Some(&lock),
        &cancel,
        "state-commit",
        move |inner, _| inner.commit_floors(&snap, &raised),
    )
    .await?;
    Ok(info)
}

/// Re-loads the state under the lock and refuses an update that is no longer newer, or bad.
async fn load_fresh(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    info: &UpdateInfo,
) -> Result<Snapshot, Error> {
    let snap = on_job(inner, Some(lock), cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    let record = snap.record();
    let stale = record
        .current
        .as_ref()
        .is_some_and(|c| c.version >= info.version)
        || record.bad.contains(&info.version);
    if stale {
        return Err(Error::Stale);
    }
    Ok(snap)
}

fn fetch_ctx(inner: &Inner, lock: &OpLock, cancel: &CancelToken, sink: &ProgressSink) -> FetchCtx {
    FetchCtx {
        transport: Arc::clone(&inner.transport),
        cache: inner.cache(),
        hasher: Arc::clone(&inner.hasher),
        lock: Some(lock.clone()),
        cancel: cancel.clone(),
        progress: Some(sink.clone()),
        policy: inner.policy,
    }
}

async fn download(
    inner: Arc<Inner>,
    info: UpdateInfo,
    mut options: DownloadOptions,
) -> Result<Downloaded, Error> {
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Scan, 0);
    let mut callback = options.progress.take();
    let result = with_progress(&mut pump, &mut callback, async {
        let lock = take_lock(&inner, &cancel).await?;
        let snap = load_fresh(&inner, &lock, &cancel, &info).await?;
        let current = snap.record().current.as_ref().map(|c| c.version.clone());
        let manifest = Arc::clone(&info.manifest);
        let frames = frames_of(&manifest);

        // Cache entries the plan does not name go first (M4-D17).
        let keep_frames: HashSet<Sha256Digest> = frames.iter().map(|(_, f)| f.sha256).collect();
        let keep_packs = HashSet::from([info.pack.sha256]);
        let tree = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "cache-clean",
            move |inner, _| {
                let cache = inner.cache();
                cache.ensure_dirs()?;
                cache.cleanup(&keep_frames, &keep_packs)?;
                inner.current_tree(current.as_ref())
            },
        )
        .await?;

        sink.set_phase(Phase::Scan, file_bytes(&manifest));
        let scan_sink = sink.clone();
        let scan_manifest = Arc::clone(&manifest);
        let unchanged = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "scan",
            move |inner, cancel| {
                let last = AtomicU64::new(0);
                Ok(lunepack_core::scan(
                    &scan_manifest,
                    tree.as_deref(),
                    &*inner.fs,
                    &*inner.hasher,
                    inner.workers,
                    cancel,
                    &|p| forward(&scan_sink, &last, &p),
                )?)
            },
        )
        .await?;

        let needed: Vec<FrameNeed> = frames
            .iter()
            .filter(|(i, _)| unchanged.get(*i).is_none_or(Option::is_none))
            .map(|(_, f)| f.clone())
            .collect();
        let needed_bytes = needed.iter().fold(0u64, |s, f| s.saturating_add(f.length));
        sink.set_phase(Phase::Download, needed_bytes);
        let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
        let fetched = fetch::download(&ctx, &info.pack, &needed).await?;
        let frames: HashMap<Sha256Digest, PathBuf> = needed
            .iter()
            .filter_map(|f| {
                fetched
                    .frame(&f.sha256)
                    .map(|p| (f.sha256, p.to_path_buf()))
            })
            .collect();
        Ok::<_, Error>((unchanged, frames, fetched.pack().map(Path::to_path_buf)))
    })
    .await;
    let (unchanged, frames, pack) = result?;
    options.progress = callback;
    Ok(Downloaded {
        info,
        unchanged,
        frames,
        pack,
        options,
    })
}

/// The stage sources: the matching current file, else the cached frame (its expected path, which
/// the stage reports as `NeedFetch` when missing), else the pack when the entry was moved to it.
fn sources(
    manifest: &VerifiedManifest,
    unchanged: &[Option<PathBuf>],
    frames: &HashMap<Sha256Digest, PathBuf>,
    pack: Option<&Path>,
    use_pack: &HashSet<usize>,
    cache: &Cache,
) -> Vec<SourceFor> {
    manifest
        .entries()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            if let Some(Some(path)) = unchanged.get(i) {
                return SourceFor::Unchanged(path.clone());
            }
            let VerifiedEntry::File {
                frame: Some(frame), ..
            } = e
            else {
                // Directories, symlinks and empty files ignore their source.
                return SourceFor::Frame(PathBuf::new());
            };
            let sha = frame.sha256();
            match (frames.get(&sha), pack) {
                (_, Some(pack)) if use_pack.contains(&i) => SourceFor::Pack(pack.to_path_buf()),
                (Some(path), _) => SourceFor::Frame(path.clone()),
                (None, Some(pack)) => SourceFor::Pack(pack.to_path_buf()),
                (None, None) => SourceFor::Frame(cache.path(CacheKind::Frame, &sha)),
            }
        })
        .collect()
}

async fn stage(inner: Arc<Inner>, downloaded: Downloaded) -> Result<StagedVersion, Error> {
    let Layout::User { versions_dir, .. } = &inner.layout else {
        return Err(Error::MachineScope);
    };
    let versions_dir = versions_dir.clone();
    let Downloaded {
        info,
        mut unchanged,
        mut frames,
        mut pack,
        mut options,
    } = downloaded;
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Stage, 0);
    let mut callback = options.progress.take();
    with_progress(&mut pump, &mut callback, async {
        let lock = take_lock(&inner, &cancel).await?;
        let snap = load_fresh(&inner, &lock, &cancel, &info).await?;
        let manifest = Arc::clone(&info.manifest);
        let all_frames = frames_of(&manifest);
        let mut use_pack: HashSet<usize> = HashSet::new();
        let (mut range_tried, mut pack_tried) = (false, false);
        let staged = loop {
            let input_sources = sources(
                &manifest,
                &unchanged,
                &frames,
                pack.as_deref(),
                &use_pack,
                &inner.cache(),
            );
            sink.set_phase(Phase::Stage, file_bytes(&manifest));
            let stage_sink = sink.clone();
            let stage_manifest = Arc::clone(&manifest);
            let dir = versions_dir.clone();
            let outcome = on_job(
                &inner,
                Some(&lock),
                &cancel,
                "stage",
                move |inner, cancel| {
                    let last = AtomicU64::new(0);
                    let progress = |p: Progress| forward(&stage_sink, &last, &p);
                    let input = StageInput {
                        manifest: &stage_manifest,
                        versions_dir: dir,
                        sources: input_sources,
                    };
                    let env = StageEnv {
                        fs: &*inner.fs,
                        codec: &*inner.codec,
                        hasher: &*inner.hasher,
                        workers: inner.workers,
                        budget_bytes: inner.budget,
                        cancel,
                        progress: &progress,
                    };
                    Ok(lunepack_core::stage(&input, &env))
                },
            )
            .await?;
            let paths = match outcome {
                Ok(staged) => break staged,
                Err(StageError::NeedFetch(paths)) => paths,
                Err(StageError::Cancelled) => return Err(Error::Cancelled),
                Err(StageError::Unsupported) => {
                    return Err(Error::Config("the manifest needs an unsupported source"));
                }
                Err(StageError::Other(e)) => return Err(Error::Verify(e)),
                Err(_) => return Err(Error::Config("stage failed")),
            };
            let failed: Vec<usize> = manifest
                .entries()
                .iter()
                .enumerate()
                .filter(|(_, e)| paths.contains(e.path()))
                .map(|(i, _)| i)
                .collect();
            for &i in &failed {
                if let Some(slot) = unchanged.get_mut(i) {
                    *slot = None;
                }
            }
            let failed_frames: Vec<FrameNeed> = all_frames
                .iter()
                .filter(|(i, _)| failed.contains(i))
                .map(|(_, f)| f.clone())
                .collect();
            let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
            if !range_tried {
                // Rung 2 (D27): the failing frames again, by Range.
                range_tried = true;
                let stale: Vec<Sha256Digest> = failed_frames.iter().map(|f| f.sha256).collect();
                on_job(
                    &inner,
                    Some(&lock),
                    &cancel,
                    "cache-drop",
                    move |inner, _| {
                        let cache = inner.cache();
                        for sha in &stale {
                            cache.remove_entry(CacheKind::Frame, sha)?;
                        }
                        Ok(())
                    },
                )
                .await?;
                for f in &failed_frames {
                    frames.remove(&f.sha256);
                }
                sink.set_phase(Phase::Download, 0);
                let fetched = fetch::download(&ctx, &info.pack, &failed_frames).await?;
                for f in &failed_frames {
                    if let Some(p) = fetched.frame(&f.sha256) {
                        frames.insert(f.sha256, p.to_path_buf());
                    }
                }
                if let Some(p) = fetched.pack() {
                    pack = Some(p.to_path_buf());
                    use_pack.extend(failed.iter().copied());
                }
            } else if !pack_tried {
                // Rung 3: the full pack, fetched fresh.
                pack_tried = true;
                let sha = info.pack.sha256;
                on_job(
                    &inner,
                    Some(&lock),
                    &cancel,
                    "cache-drop",
                    move |inner, _| Ok(inner.cache().remove_entry(CacheKind::Pack, &sha)?),
                )
                .await?;
                sink.set_phase(Phase::Download, info.pack.size);
                pack = Some(fetch::fetch_pack(&ctx, &info.pack, None).await?);
                use_pack.extend(failed.iter().copied());
            } else {
                return Err(Error::NeedFetchExhausted(paths));
            }
        };

        // Record the tree, then drop the version's cache entries (M4-D17).
        let staged_ref =
            StagedRef::new(staged.version.clone(), staged.target, info.manifest_sha256);
        let drop_frames: Vec<Sha256Digest> = all_frames.iter().map(|(_, f)| f.sha256).collect();
        let pack_sha = info.pack.sha256;
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "state-commit",
            move |inner, _| {
                let Snapshot::User {
                    store,
                    loaded,
                    record,
                } = &snap
                else {
                    return Err(Error::MachineScope);
                };
                let next = record
                    .set_staged(Some(staged_ref))
                    .with_seq(loaded.next_seq);
                store.commit(&*inner.fs, loaded, &next, &*inner.hasher)?;
                let cache = inner.cache();
                for sha in &drop_frames {
                    cache.remove_entry(CacheKind::Frame, sha)?;
                }
                cache.remove_entry(CacheKind::Pack, &pack_sha)?;
                Ok(())
            },
        )
        .await?;
        Ok(StagedVersion {
            version: staged.version,
            target: staged.target,
            tree: staged.tree,
        })
    })
    .await
}

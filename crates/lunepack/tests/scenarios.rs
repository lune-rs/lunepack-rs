//! The scenario suite (M4 step 13): check -> download -> stage -> `staged()` over real fixtures
//! (real LZMA packs from the core's `ReleaseLayout`, real Ed25519 signatures from keys generated at
//! test time, a real temporary directory), under five executors, plus cancel at every poll, the
//! progress thread and coalescing checks, and injected-transport and `file:` runs.
//!
//! One scenario (`scenario`) runs under `lunepack::blocking`, `futures::executor::block_on`, tokio
//! current-thread, tokio multi-thread (the operation is `tokio::spawn`ed) and smol, over each
//! transport kind. Every test takes `serial()`: `live_workers()` is process-wide.
//!
//! Cross-process and hard-kill tests are in `cross_process.rs`.

mod common;

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread, ThreadId};
use std::time::{Duration, Instant};

use common::*;
use lunepack::{DownloadOptions, Downloaded, Error, StagedVersion, UpdateInfo, Updater, block_on};
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::fetch::FetchPolicy;
use lunepack_core::{
    Body, BoxFuture, CancelToken, Codec, DecodeReport, FrameView, Phase, Progress, Request,
    Response, Transport, TransportError,
};
use lunepack_testkit::{FakeBlockingTransport, FakeOrigin, FakeTransport, LoopbackServer};

// ---- the five executors --------------------------------------------------------------------------

/// A progress callback that is also told which thread is polling the operation.
type TrackedCallback = Box<dyn FnMut(&Progress, ThreadId) + Send>;

trait Exec {
    fn name(&self) -> &'static str;

    /// Runs `f` to completion the way this executor runs a task.
    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static;

    fn check(&self, u: &Updater) -> Result<Option<UpdateInfo>, Error> {
        self.run(u.check())
    }

    fn download(
        &self,
        u: &Updater,
        info: &UpdateInfo,
        options: DownloadOptions,
    ) -> Result<Downloaded, Error> {
        self.run(u.download(info, options))
    }

    fn stage(&self, u: &Updater, downloaded: Downloaded) -> Result<StagedVersion, Error> {
        self.run(u.stage(downloaded))
    }

    /// `download` with `callback` as the progress callback, which is told the thread that is
    /// polling the operation at the moment of every call.
    fn download_tracked(
        &self,
        u: &Updater,
        info: &UpdateInfo,
        callback: TrackedCallback,
    ) -> Result<Downloaded, Error> {
        let polling = Arc::new(Mutex::new(None::<ThreadId>));
        let seen = Arc::clone(&polling);
        let mut callback = callback;
        let options = DownloadOptions {
            progress: Some(Box::new(move |p| {
                let at = seen
                    .lock()
                    .expect("lock")
                    .expect("polled before a callback");
                callback(p, at);
            })),
            cancel: None,
        };
        self.run(Tracked {
            inner: Box::pin(u.download(info, options)),
            polling,
        })
    }
}

/// Records, at the start of every poll, the thread that polls its inner future.
struct Tracked<T> {
    inner: Pin<Box<dyn Future<Output = T> + Send>>,
    polling: Arc<Mutex<Option<ThreadId>>>,
}

impl<T> Future for Tracked<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        *self.polling.lock().expect("lock") = Some(thread::current().id());
        self.inner.as_mut().poll(cx)
    }
}

/// `lunepack::blocking`: plain calls on this thread.
struct Blocking;

impl Exec for Blocking {
    fn name(&self) -> &'static str {
        "lunepack::blocking"
    }

    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        block_on(f)
    }

    fn check(&self, u: &Updater) -> Result<Option<UpdateInfo>, Error> {
        lunepack::blocking::Updater::from(u.clone()).check(&CancelToken::new())
    }

    fn download(
        &self,
        u: &Updater,
        info: &UpdateInfo,
        options: DownloadOptions,
    ) -> Result<Downloaded, Error> {
        lunepack::blocking::Updater::from(u.clone()).download(info, options, &CancelToken::new())
    }

    fn stage(&self, u: &Updater, downloaded: Downloaded) -> Result<StagedVersion, Error> {
        lunepack::blocking::Updater::from(u.clone()).stage(downloaded, &CancelToken::new())
    }

    fn download_tracked(
        &self,
        u: &Updater,
        info: &UpdateInfo,
        callback: TrackedCallback,
    ) -> Result<Downloaded, Error> {
        // The polling thread of a blocking call is the calling thread.
        let here = thread::current().id();
        let mut callback = callback;
        self.download(
            u,
            info,
            DownloadOptions {
                progress: Some(Box::new(move |p| callback(p, thread::current().id()))),
                cancel: None,
            },
        )
        .inspect(|_| {
            assert_eq!(thread::current().id(), here);
        })
    }
}

struct FuturesExec;

impl Exec for FuturesExec {
    fn name(&self) -> &'static str {
        "futures::executor::block_on"
    }

    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        futures::executor::block_on(f)
    }
}

struct TokioCurrent(tokio::runtime::Runtime);

impl TokioCurrent {
    fn new() -> Self {
        TokioCurrent(
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("tokio current-thread"),
        )
    }
}

impl Exec for TokioCurrent {
    fn name(&self) -> &'static str {
        "tokio current-thread"
    }

    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        self.0.block_on(f)
    }
}

struct TokioMulti(tokio::runtime::Runtime);

impl TokioMulti {
    fn new() -> Self {
        TokioMulti(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .expect("tokio multi-thread"),
        )
    }
}

impl Exec for TokioMulti {
    fn name(&self) -> &'static str {
        "tokio multi-thread"
    }

    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        // Spawned: the operation runs on a runtime worker and may move between workers.
        self.0.block_on(self.0.spawn(f)).expect("task panicked")
    }
}

struct SmolExec;

impl Exec for SmolExec {
    fn name(&self) -> &'static str {
        "smol"
    }

    fn run<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        smol::block_on(smol::spawn(f))
    }
}

/// Runs `$body` (a macro-expanded call with `e` bound) under each of the five executors.
macro_rules! on_every_executor {
    (|$e:ident| $body:expr) => {{
        {
            let $e = &Blocking;
            $body;
        }
        {
            let $e = &FuturesExec;
            $body;
        }
        {
            let $e = &TokioCurrent::new();
            $body;
        }
        {
            let $e = &TokioMulti::new();
            $body;
        }
        {
            let $e = &SmolExec;
            $body;
        }
    }};
}

// ---- transports ----------------------------------------------------------------------------------

/// An injected async transport that is not a `WorkerTransport`: its futures return `Pending` and
/// wake themselves (the request future from another thread, each body chunk inline), so it proves
/// that an app's own transport is polled and woken through the caller's executor.
struct WakingTransport {
    inner: FakeTransport,
    calls: Arc<AtomicUsize>,
}

/// Pending once; woken from a helper thread after 1 ms.
async fn pause_on_thread() {
    let mut paused = false;
    std::future::poll_fn(|cx| {
        if paused {
            return Poll::Ready(());
        }
        paused = true;
        let waker = cx.waker().clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(1));
            waker.wake();
        });
        Poll::Pending
    })
    .await;
}

/// Pending once; woken at once by the poll itself.
async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
}

struct WakingBody(Box<dyn Body>);

impl Body for WakingBody {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            yield_now().await;
            self.0.next_chunk().await
        })
    }
}

impl Transport for WakingTransport {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let inner = self.inner.get(request);
        Box::pin(async move {
            pause_on_thread().await;
            let mut response = inner.await?;
            response.body = Box::new(WakingBody(response.body));
            Ok(response)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// The default transport (ureq through `WorkerTransport`) over a loopback server; the pack is
    /// fetched whole.
    LoopbackFull,
    /// The same, with a policy that never takes the full pack: Range runs.
    LoopbackRanges,
    /// The default transport over a `file:` URL (the directory source).
    FileUrl,
    /// An injected async `Transport` with its own wakers.
    Injected,
    /// An injected `BlockingTransport`, run by `WorkerTransport`.
    WorkerFake,
}

/// An updater over one transport kind, and what keeps its origin alive.
struct Rig {
    updater: Updater,
    server: Option<LoopbackServer>,
    injected_calls: Option<Arc<AtomicUsize>>,
    _dir: Option<tempfile::TempDir>,
}

impl Rig {
    /// An updater for `site` whose origin serves the feed `feed` (1..=3).
    fn new(kind: Kind, site: &Site, feed: usize) -> Rig {
        let fx = fixture();
        let mut rig = Rig {
            updater: site
                .builder("http://unused.invalid/feed.json")
                .build()
                .expect("probe"),
            server: None,
            injected_calls: None,
            _dir: None,
        };
        let builder = match kind {
            Kind::LoopbackFull | Kind::LoopbackRanges => {
                let server = LoopbackServer::start(fx.origin(feed)).expect("loopback server");
                let mut builder = site.builder(&server.url(FEED_NAME));
                if kind == Kind::LoopbackRanges {
                    builder = builder.fetch_policy(FetchPolicy {
                        full_ratio: 101,
                        ..FetchPolicy::default()
                    });
                }
                rig.server = Some(server);
                builder
            }
            Kind::FileUrl => {
                let dir = tempfile::tempdir().expect("tempdir");
                let base = std::fs::canonicalize(dir.path()).expect("canonical");
                fx.write_dir(&base, feed);
                let url = url::Url::from_file_path(base.join(FEED_NAME)).expect("file url");
                rig._dir = Some(dir);
                site.builder(url.as_str())
            }
            Kind::Injected => {
                let calls = Arc::new(AtomicUsize::new(0));
                let transport = WakingTransport {
                    inner: FakeTransport::new(fx.origin(feed)),
                    calls: Arc::clone(&calls),
                };
                rig.injected_calls = Some(calls);
                site.builder(&fake_feed_url())
                    .transport(Arc::new(transport))
            }
            Kind::WorkerFake => site
                .builder(&fake_feed_url())
                .blocking_transport(Arc::new(FakeBlockingTransport::new(fx.origin(feed)))),
        };
        rig.updater = builder.build().expect("build");
        rig
    }

    fn origin(&self) -> &FakeOrigin {
        self.server.as_ref().expect("a loopback rig").origin()
    }
}

// ---- the scenario --------------------------------------------------------------------------------

fn no_leftovers(site: &Site) {
    assert!(
        find_suffix(&site.root, ".lptmp").is_empty(),
        "temporary files remain"
    );
    assert!(
        find_suffix(&site.cache_dir, ".part").is_empty(),
        "partial downloads remain after a completed stage"
    );
}

/// check -> download -> stage -> `staged()` from 1.0.0 to 1.1.0, over `kind`, under `e`.
fn scenario<E: Exec>(e: &E, baseline: &Baseline, kind: Kind) {
    let label = format!("{} / {kind:?}", e.name());
    let site = baseline.fresh();
    let rig = Rig::new(kind, &site, 2);
    let u = &rig.updater;

    let installed = u.installed().expect("installed").expect("an install");
    assert_eq!(installed.version().to_string(), V100, "{label}");
    assert!(u.staged().expect("staged").is_none(), "{label}");

    let info = e
        .check(u)
        .unwrap_or_else(|err| panic!("{label}: check: {err}"))
        .unwrap_or_else(|| panic!("{label}: no update offered"));
    assert_eq!(info.version_text(), V110, "{label}");
    assert_eq!(info.feed_seq(), 2, "{label}");
    assert!(info.time_checked(), "{label}");
    assert_eq!(
        info.download_size_max(),
        fixture().pack_sizes[V110],
        "{label}"
    );

    let events = Arc::new(Mutex::new(Vec::<Progress>::new()));
    let sink = Arc::clone(&events);
    let downloaded = e
        .download(
            u,
            &info,
            DownloadOptions {
                progress: Some(Box::new(move |p| {
                    sink.lock().expect("lock").push(p.clone())
                })),
                cancel: None,
            },
        )
        .unwrap_or_else(|err| panic!("{label}: download: {err}"));
    let staged = e
        .stage(u, downloaded)
        .unwrap_or_else(|err| panic!("{label}: stage: {err}"));

    // The staged tree equals the 1.1.0 input tree byte for byte, with exec bits and symlinks.
    assert_eq!(staged.version().to_string(), V110, "{label}");
    assert_eq!(staged.tree(), site.tree(V110), "{label}");
    assert_tree(staged.tree(), &release_tree(V110));
    // The installed tree is untouched.
    assert_tree(&site.tree(V100), &release_tree(V100));

    // The state names it, and a new handle on the same directories sees it.
    let seen = u.staged().expect("staged").expect("staged() after stage");
    assert_eq!(seen.version().to_string(), V110, "{label}");
    assert_eq!(seen.tree(), site.tree(V110), "{label}");
    let again = site
        .builder("http://unused.invalid/feed.json")
        .build()
        .expect("second handle");
    assert_eq!(
        again
            .staged()
            .expect("staged")
            .map(|s| s.version().to_string()),
        Some(V110.to_owned()),
        "{label}"
    );
    assert_eq!(
        u.installed()
            .expect("installed")
            .expect("install")
            .version()
            .to_string(),
        V100,
        "{label}"
    );

    // Events: phases in order, and the Unchanged file was not downloaded.
    let events = events.lock().expect("lock");
    let first = |phase: Phase| events.iter().position(|p| p.phase == phase);
    let (scan, download, stage) = (
        first(Phase::Scan).unwrap_or_else(|| panic!("{label}: no scan event")),
        first(Phase::Download).unwrap_or_else(|| panic!("{label}: no download event")),
        first(Phase::Stage).unwrap_or_else(|| panic!("{label}: no stage event")),
    );
    assert!(scan < download && download < stage, "{label}: phase order");
    let last = |phase: Phase| events.iter().rev().find(|p| p.phase == phase).cloned();
    let download_end = last(Phase::Download).expect("download event");
    // The total is what the download moved (the plan: the whole pack, or the Range runs) and the
    // bar ends exactly there, never past it.
    assert!(
        download_end.total <= fixture().pack_sizes[V110],
        "{label}: {} bytes planned for a {} byte pack",
        download_end.total,
        fixture().pack_sizes[V110]
    );
    assert_eq!(download_end.done, download_end.total, "{label}");
    for p in events.iter().filter(|p| p.phase == Phase::Download) {
        assert!(p.done <= p.total, "{label}: past 100 %: {p:?}");
    }
    let stage_end = last(Phase::Stage).expect("stage event");
    assert_eq!(
        stage_end.done, stage_end.total,
        "{label}: stage ended short"
    );

    match kind {
        Kind::LoopbackFull | Kind::LoopbackRanges => {
            let pack = format!("/{}", pack_path(V110));
            let requests = rig.origin().requests();
            assert!(
                requests.iter().all(|r| r.accept_encoding.is_none()),
                "{label}: an Accept-Encoding was sent"
            );
            let pack_requests: Vec<_> = requests.iter().filter(|r| r.url == pack).collect();
            assert!(
                !pack_requests.is_empty(),
                "{label}: the pack was not requested"
            );
            if kind == Kind::LoopbackFull {
                assert!(
                    pack_requests.iter().all(|r| r.range.is_none()),
                    "{label}: the whole pack, no Range"
                );
                assert_eq!(download_end.total, fixture().pack_sizes[V110], "{label}");
            } else {
                assert!(
                    pack_requests.iter().all(|r| r.range.is_some()),
                    "{label}: Range runs only"
                );
                let requested: u64 = pack_requests
                    .iter()
                    .filter_map(|r| r.range)
                    .map(|r| r.last.map_or(0, |last| last - r.first + 1))
                    .sum();
                assert_eq!(download_end.total, requested, "{label}: the runs requested");
            }
        }
        Kind::Injected => {
            let calls = rig
                .injected_calls
                .as_ref()
                .expect("calls")
                .load(Ordering::SeqCst);
            assert!(
                calls >= 5,
                "{label}: the injected transport served {calls} requests"
            );
        }
        Kind::FileUrl | Kind::WorkerFake => {}
    }

    workers_stopped();
    no_leftovers(&site);
}

fn scenario_everywhere(kind: Kind) {
    let _s = serial();
    let baseline = Baseline::new();
    on_every_executor!(|e| scenario(e, &baseline, kind));
}

#[test]
fn scenario_over_the_default_transport_and_a_loopback_server() {
    scenario_everywhere(Kind::LoopbackFull);
}

#[test]
fn scenario_over_range_runs_on_a_loopback_server() {
    scenario_everywhere(Kind::LoopbackRanges);
}

#[test]
fn scenario_over_a_file_url() {
    scenario_everywhere(Kind::FileUrl);
}

#[test]
fn scenario_over_an_injected_async_transport() {
    scenario_everywhere(Kind::Injected);
}

#[test]
fn scenario_over_an_injected_blocking_transport() {
    scenario_everywhere(Kind::WorkerFake);
}

#[test]
fn the_fixture_is_made_by_the_real_writers() {
    let f = fixture();
    for id in ["stored", "lzma2", "bcj2"] {
        assert!(
            f.codecs_110.contains(id),
            "no {id} frame in {:?}",
            f.codecs_110
        );
    }
    let tree = release_tree(V110);
    assert!(
        tree.values()
            .any(|n| matches!(n, Node::File { bytes, .. } if bytes.is_empty())),
        "an empty file"
    );
    assert!(
        tree.values()
            .any(|n| matches!(n, Node::File { exec: true, .. }))
    );
    assert!(tree.values().any(|n| matches!(n, Node::Dir)));
    #[cfg(unix)]
    assert!(tree.values().any(|n| matches!(n, Node::Symlink(_))));
    // The renamed file keeps its bytes under another name.
    assert_eq!(
        release_tree(V100)["docs/old.txt"],
        release_tree(V110)["docs/new.txt"]
    );
}

// ---- cancel at every poll ------------------------------------------------------------------------

struct Parker {
    thread: Thread,
    woken: AtomicBool,
}

impl Wake for Parker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
        self.thread.unpark();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Poll `n` times, then drop the future.
    Drop,
    /// Poll `n` times, then cancel the token and keep polling to the end.
    Token,
}

enum Step<T> {
    Done(Result<T, Error>),
    Cut,
}

/// Polls `fut` at most `*budget` times, parking between polls until a wake. When the budget is
/// spent: [`Mode::Drop`] returns `Cut` (the caller drops the future), [`Mode::Token`] cancels
/// `token` and polls on.
fn drive<T, F>(
    fut: &mut Pin<Box<F>>,
    budget: &mut usize,
    mode: Mode,
    token: &CancelToken,
) -> Step<T>
where
    F: Future<Output = Result<T, Error>>,
{
    let parker = Arc::new(Parker {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&parker));
    let mut cx = Context::from_waker(&waker);
    let mut cancelled = token.is_cancelled();
    loop {
        if *budget == 0 {
            match mode {
                Mode::Drop => return Step::Cut,
                Mode::Token => {
                    if !cancelled {
                        token.cancel();
                        cancelled = true;
                    }
                }
            }
        } else {
            *budget -= 1;
        }
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Err(Error::Cancelled)) if cancelled => return Step::Cut,
            Poll::Ready(result) => return Step::Done(result),
            Poll::Pending => {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !parker.woken.swap(false, Ordering::SeqCst) {
                    assert!(Instant::now() < deadline, "the operation made no progress");
                    thread::park_timeout(Duration::from_millis(20));
                }
            }
        }
    }
}

/// What a completed (fresh) run must leave behind.
fn finish_and_verify(rig: &Rig, site: &Site, info: &UpdateInfo, label: &str) {
    let u = &rig.updater;
    let downloaded = block_on(u.download(info, DownloadOptions::default()))
        .unwrap_or_else(|e| panic!("{label}: a fresh download after the cut: {e}"));
    let staged = block_on(u.stage(downloaded))
        .unwrap_or_else(|e| panic!("{label}: a fresh stage after the cut: {e}"));
    assert_eq!(staged.tree(), site.tree(V110), "{label}");
    assert_tree(staged.tree(), &release_tree(V110));
    assert_tree(&site.tree(V100), &release_tree(V100));
    let seen = u.staged().expect("staged").expect("staged()");
    assert_eq!(seen.version().to_string(), V110, "{label}");
    workers_stopped();
    no_leftovers(site);
}

/// Which operation a sweep cuts: the other one runs to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    Download,
    Stage,
}

/// Polls `download` and then `stage` N times and cuts, for every N up to completion. Two sweeps,
/// so that every poll of each operation is a cut point however the other one's poll count varies
/// from run to run: one cuts `download` after N polls (then `stage` runs on), the other runs
/// `download` to its end and cuts `stage` after N polls.
fn cancel_at_every_poll(kind: Kind, mode: Mode) {
    let _s = serial();
    let baseline = Baseline::new();
    for sweep in [Sweep::Download, Sweep::Stage] {
        let mut cuts = 0usize;
        let mut n = 0usize;
        loop {
            assert!(n < 5_000, "the {sweep:?} sweep never completed");
            let label = format!("{kind:?} / {mode:?} / {sweep:?} / N={n}");
            let site = baseline.fresh();
            let rig = Rig::new(kind, &site, 2);
            let u = &rig.updater;
            let info = block_on(u.check())
                .unwrap_or_else(|e| panic!("{label}: check: {e}"))
                .expect("an update");
            let token = CancelToken::new();
            let (mut download_budget, mut stage_budget) = match sweep {
                Sweep::Download => (n, usize::MAX),
                Sweep::Stage => (usize::MAX, n),
            };

            let mut download = Box::pin(u.download(
                &info,
                DownloadOptions {
                    progress: None,
                    cancel: Some(token.clone()),
                },
            ));
            let downloaded = match drive(&mut download, &mut download_budget, mode, &token) {
                Step::Done(result) if !token.is_cancelled() => {
                    result.unwrap_or_else(|e| panic!("{label}: download: {e}"))
                }
                // Cut, or finished in the same instant the token fired (its stage would be
                // cancelled too).
                Step::Cut | Step::Done(_) => {
                    cuts += 1;
                    drop(download);
                    workers_stopped();
                    assert!(u.staged().expect("staged").is_none(), "{label}");
                    finish_and_verify(&rig, &site, &info, &label);
                    n += 1;
                    continue;
                }
            };
            drop(download);
            let mut stage = Box::pin(u.stage(downloaded));
            match drive(&mut stage, &mut stage_budget, mode, &token) {
                Step::Done(result) => {
                    let staged = result.unwrap_or_else(|e| panic!("{label}: stage: {e}"));
                    assert_tree(staged.tree(), &release_tree(V110));
                    assert!(u.staged().expect("staged").is_some(), "{label}");
                    workers_stopped();
                    no_leftovers(&site);
                    break;
                }
                Step::Cut => {
                    cuts += 1;
                    drop(stage);
                    workers_stopped();
                    // A cut after the commit job ran keeps the commit; otherwise nothing is staged.
                    if let Some(seen) = u.staged().expect("staged") {
                        assert_eq!(seen.tree(), site.tree(V110), "{label}");
                        assert_tree(seen.tree(), &release_tree(V110));
                    }
                    finish_and_verify(&rig, &site, &info, &label);
                }
            }
            n += 1;
        }
        // N = 0 cuts before the first poll, so each sweep has cuts; the count is the number of
        // polls the operation took in the run that completed.
        assert!(cuts > 0, "{sweep:?} sweep: no cut");
        println!("{kind:?} / {mode:?} / {sweep:?}: completed at N={n}, {cuts} cuts");
    }
}

#[test]
fn dropping_the_future_after_every_poll_leaves_nothing_behind_injected() {
    cancel_at_every_poll(Kind::Injected, Mode::Drop);
}

#[test]
fn dropping_the_future_after_every_poll_leaves_nothing_behind_worker_transport() {
    cancel_at_every_poll(Kind::WorkerFake, Mode::Drop);
}

#[test]
fn cancelling_the_token_after_every_poll_leaves_nothing_behind_injected() {
    cancel_at_every_poll(Kind::Injected, Mode::Token);
}

#[test]
fn cancelling_the_token_after_every_poll_leaves_nothing_behind_worker_transport() {
    cancel_at_every_poll(Kind::WorkerFake, Mode::Token);
}

/// A real codec that stops inside its first decode until the test lets it go.
struct GateCodec {
    inner: LzmaCodec,
    armed: AtomicBool,
    entered: Arc<AtomicBool>,
    open: Arc<AtomicBool>,
}

impl Codec for GateCodec {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn Write,
    ) -> Result<DecodeReport, lunepack_core::Error> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(10);
            while !self.open.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
        }
        self.inner.decode(frame, out)
    }
}

#[test]
fn dropping_stage_while_a_frame_is_decoding_stops_the_worker_and_a_fresh_call_completes() {
    let _s = serial();
    let baseline = Baseline::new();
    let site = baseline.fresh();
    let (entered, open) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let gate = GateCodec {
        inner: LzmaCodec,
        armed: AtomicBool::new(true),
        entered: Arc::clone(&entered),
        open: Arc::clone(&open),
    };
    let u = site
        .builder(&fake_feed_url())
        .transport(Arc::new(FakeTransport::new(fixture().origin(2))))
        .codec(Arc::new(gate))
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");

    let mut stage = Box::pin(u.stage(downloaded));
    let parker = Arc::new(Parker {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&parker));
    let mut cx = Context::from_waker(&waker);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !entered.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the stage never reached a decode"
        );
        if let Poll::Ready(done) = stage.as_mut().poll(&mut cx) {
            panic!("the stage finished before its decode paused: {done:?}");
        }
        thread::park_timeout(Duration::from_millis(5));
    }
    // A frame is being decoded on a worker now. Drop the future, then let the decode go on.
    drop(stage);
    assert!(
        live_worker_count() > 0,
        "the stage worker is gone before the gate opened"
    );
    open.store(true, Ordering::SeqCst);
    workers_stopped();
    // The drop cancelled the stage: no complete tree was built behind the dropped future's back,
    // and nothing is recorded.
    assert!(
        !site.tree(V110).exists(),
        "the cancelled stage ran to the end and renamed its tree into place"
    );
    assert!(u.staged().expect("staged").is_none());

    // A fresh call resumes or discards what is left, and the result is the uncancelled one.
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let staged = block_on(u.stage(downloaded)).expect("fresh stage");
    assert_tree(staged.tree(), &release_tree(V110));
    workers_stopped();
    no_leftovers(&site);
}

fn live_worker_count() -> usize {
    lunepack::unstable_internals::live_workers()
}

// ---- progress ------------------------------------------------------------------------------------

#[test]
fn the_progress_callback_runs_only_on_the_thread_that_polls() {
    let _s = serial();
    let baseline = Baseline::new();
    on_every_executor!(|e| {
        let site = baseline.fresh();
        let rig = Rig::new(Kind::LoopbackFull, &site, 2);
        let info = e.check(&rig.updater).expect("check").expect("update");
        let calls = Arc::new(AtomicUsize::new(0));
        let wrong = Arc::new(AtomicUsize::new(0));
        let (c, w) = (Arc::clone(&calls), Arc::clone(&wrong));
        e.download_tracked(
            &rig.updater,
            &info,
            Box::new(move |_, polling| {
                c.fetch_add(1, Ordering::SeqCst);
                if thread::current().id() != polling {
                    w.fetch_add(1, Ordering::SeqCst);
                }
            }),
        )
        .unwrap_or_else(|err| panic!("{}: download: {err}", e.name()));
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "{}: no progress event",
            e.name()
        );
        assert_eq!(
            wrong.load(Ordering::SeqCst),
            0,
            "{}: a callback ran on a thread that was not polling",
            e.name()
        );
        // The callback never ran on a lunepack worker.
        workers_stopped();
    });
}

#[test]
fn a_slow_callback_does_not_stall_a_download_and_the_last_event_is_complete() {
    let _s = serial();
    // 1.2.0 has a 1.7 MB stored file; with no current tree every frame is fetched, so the
    // download phase's total equals the pack size. An 8 KiB chunk size gives >= 200 chunks.
    let site = Site::with_090();
    let origin = fixture().origin(3);
    let u = site
        .builder(&fake_feed_url())
        .transport(Arc::new(FakeTransport::new(origin)))
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    assert_eq!(info.version_text(), V120);
    let pack = fixture().pack_sizes[V120];
    let chunks = pack.div_ceil(8192);
    assert!(chunks >= 200, "the pack is only {chunks} chunks");

    let calls = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(None::<Progress>));
    let (c, l) = (Arc::clone(&calls), Arc::clone(&last));
    let started = Instant::now();
    let downloaded = block_on(u.download(
        &info,
        DownloadOptions {
            progress: Some(Box::new(move |p| {
                c.fetch_add(1, Ordering::SeqCst);
                if p.phase == Phase::Download {
                    *l.lock().expect("lock") = Some(p.clone());
                }
                thread::sleep(Duration::from_millis(50));
            })),
            cancel: None,
        },
    ))
    .expect("download");
    let elapsed = started.elapsed();
    drop(downloaded);

    let calls = calls.load(Ordering::SeqCst);
    println!("{chunks} chunks, {calls} callbacks, {elapsed:?}");
    // Without coalescing every chunk would cost one callback of 50 ms.
    assert!(
        elapsed < Duration::from_millis(50) * (chunks as u32) / 2,
        "{calls} callbacks of 50 ms took {elapsed:?} for {chunks} chunks"
    );
    assert!(
        (calls as u64) < chunks / 2,
        "{calls} callbacks for {chunks} chunks"
    );
    let last = last
        .lock()
        .expect("lock")
        .clone()
        .expect("a download event");
    assert_eq!(
        last.done, last.total,
        "the last download event is not complete"
    );
    assert_eq!(last.total, pack);
    workers_stopped();
}

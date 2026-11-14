//! The fetch engine (M4 step 11): documents, URL resolution, the cache, Range runs, full-pack
//! downloads, resume, faults, cancel safety and the lock held by a writer that outlives its future.
//!
//! Every test takes `SERIAL`: `live_workers()` is process-wide.

use std::collections::HashSet;
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use lunepack::{
    ABSENT_ROOT_STATUSES, Cache, CacheKind, Error, FeedUrls, FetchCtx, FrameNeed, PackTarget,
    acquire_op_lock, block_on, download, fetch_document, fetch_pack, fetch_root_doc, live_workers,
};
use lunepack_core::fetch::FetchPolicy;
use lunepack_core::{
    Body, BoxFuture, CancelToken, Channel, DirEntryInfo, FileWrite, Fs, FsError, Hasher, LockGuard,
    Meta, ReadAt, Request, Response, Sha256Digest, Transport, TransportError,
};
use lunepack_testkit::{
    FAKE_BASE_URL, FakeHasher, FakeOrigin, FakeTransport, MemFs, TransportFault,
};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wait_until(limit: Duration, cond: impl Fn() -> bool) -> bool {
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

fn workers_stopped() {
    assert!(
        wait_until(Duration::from_secs(2), || live_workers() == 0),
        "workers still alive: {}",
        live_workers()
    );
}

// ---- fixture -------------------------------------------------------------------------------------

const PACK_LEN: usize = 20_000;
const PACK_NAME: &str = "pack.bin";
const CACHE: &str = "/cache";

fn pack_bytes() -> Vec<u8> {
    (0..PACK_LEN)
        .map(|i| (i.wrapping_mul(131).wrapping_add(7) % 251) as u8)
        .collect()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    FakeHasher.sha256(bytes)
}

fn frame(offset: usize, length: usize) -> FrameNeed {
    let pack = pack_bytes();
    FrameNeed {
        offset: offset as u64,
        length: length as u64,
        sha256: sha(&pack[offset..offset + length]),
    }
}

/// Two adjacent frames, 1000 and 1500 bytes: one run `0-2499` under the default policy.
fn two_frames() -> Vec<FrameNeed> {
    vec![frame(0, 1000), frame(1000, 1500)]
}

fn pack_target() -> PackTarget {
    PackTarget {
        url: format!("{FAKE_BASE_URL}/{PACK_NAME}"),
        size: PACK_LEN as u64,
        sha256: sha(&pack_bytes()),
    }
}

struct Rig {
    origin: FakeOrigin,
    fs: Arc<dyn Fs>,
    ctx: FetchCtx,
}

fn rig_with(fs: Arc<dyn Fs>, transport: Arc<dyn Transport>, origin: FakeOrigin) -> Rig {
    origin.put(PACK_NAME, pack_bytes());
    let ctx = FetchCtx {
        transport,
        cache: Cache::new(Arc::clone(&fs), PathBuf::from(CACHE)),
        hasher: Arc::new(FakeHasher),
        lock: None,
        cancel: CancelToken::new(),
        progress: None,
        policy: FetchPolicy::default(),
    };
    Rig { origin, fs, ctx }
}

fn rig() -> Rig {
    let transport = FakeTransport::new(FakeOrigin::new());
    let origin = transport.origin().clone();
    rig_with(Arc::new(MemFs::new()), Arc::new(transport), origin)
}

fn read(fs: &dyn Fs, path: &Path) -> Vec<u8> {
    fs.read_capped(path, 1 << 30).expect("read")
}

fn exists(fs: &dyn Fs, path: &Path) -> bool {
    fs.symlink_metadata(path).expect("meta").is_some()
}

fn frame_path(f: &FrameNeed) -> PathBuf {
    Path::new(CACHE).join("frames").join(f.sha256.to_hex())
}

fn frame_part(f: &FrameNeed) -> PathBuf {
    Path::new(CACHE)
        .join("frames")
        .join(format!("{}.part", f.sha256.to_hex()))
}

fn pack_path() -> PathBuf {
    Path::new(CACHE)
        .join("packs")
        .join(pack_target().sha256.to_hex())
}

fn pack_part() -> PathBuf {
    Path::new(CACHE)
        .join("packs")
        .join(format!("{}.part", pack_target().sha256.to_hex()))
}

fn assert_frames_cached(fs: &dyn Fs, frames: &[FrameNeed]) {
    let pack = pack_bytes();
    for f in frames {
        let (o, l) = (f.offset as usize, f.length as usize);
        assert_eq!(read(fs, &frame_path(f)), pack[o..o + l], "frame at {o}");
        assert!(
            !exists(fs, &frame_part(f)),
            "a part is left for the frame at {o}"
        );
    }
}

fn names(fs: &dyn Fs, dir: &str) -> Vec<String> {
    match fs.list_dir(&Path::new(CACHE).join(dir)) {
        Ok(entries) => {
            let mut v: Vec<String> = entries
                .into_iter()
                .map(|e| e.name.to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
        Err(_) => Vec::new(),
    }
}

fn is_range_error(e: &Error) -> bool {
    matches!(e, Error::Verify(lunepack_core::Error::Range(_)))
}

fn is_too_large(e: &Error) -> bool {
    matches!(e, Error::Verify(lunepack_core::Error::TooLarge { .. }))
}

// ---- URLs ----------------------------------------------------------------------------------------

#[test]
fn feed_urls_resolve_under_the_feed_directory() {
    let _s = serial();
    let urls = FeedUrls::new("https://cdn.example/app/stable/feed-stable.json?sig=abc#x")
        .expect("feed url");
    assert_eq!(
        urls.root(2).expect("root"),
        "https://cdn.example/app/stable/root-2.json"
    );
    assert_eq!(
        urls.keys().expect("keys"),
        "https://cdn.example/app/stable/keys.json"
    );
    let channel = Channel::parse("stable").expect("channel");
    assert_eq!(
        urls.feed(&channel).expect("feed"),
        "https://cdn.example/app/stable/feed-stable.json"
    );
    assert_eq!(
        urls.join("packs/1.0.0/app.pack").expect("join"),
        "https://cdn.example/app/stable/packs/1.0.0/app.pack"
    );
    // A directory URL keeps its directory.
    let dir = FeedUrls::new("file:///srv/updates/").expect("file url");
    assert_eq!(dir.keys().expect("keys"), "file:///srv/updates/keys.json");
    assert!(FeedUrls::new("http://h/feed.json").is_ok());
}

#[test]
fn feed_urls_refuse_other_schemes_and_escapes() {
    let _s = serial();
    for bad in [
        "ftp://h/feed.json",
        "data:text/plain,x",
        "not a url",
        "mailto:a@b",
    ] {
        assert!(
            matches!(FeedUrls::new(bad), Err(Error::Config(_))),
            "{bad} was accepted"
        );
    }
    let urls = FeedUrls::new("https://cdn.example/app/feed.json").expect("feed url");
    for rel in [
        "../x.json",
        "a/../../x.json",
        "/etc/passwd",
        "//evil.example/x",
        "https://evil.example/x",
        "x?y=1",
        "x#frag",
        "a\\b",
        "%2e%2e/x",
        "",
        ".",
    ] {
        assert!(urls.join(rel).is_err(), "{rel:?} was accepted");
    }
}

// ---- documents -----------------------------------------------------------------------------------

#[test]
fn a_document_of_exactly_cap_bytes_passes_and_one_more_fails() {
    let _s = serial();
    let transport = FakeTransport::new(FakeOrigin::new());
    let origin = transport.origin().clone();
    let cap = 1000u64;
    origin.put("exact.json", vec![b'a'; cap as usize]);
    origin.put("over.json", vec![b'a'; cap as usize + 1]);
    let url = |n: &str| format!("{FAKE_BASE_URL}/{n}");
    let got = block_on(fetch_document(&transport, &url("exact.json"), cap)).expect("exact");
    assert_eq!(got.len() as u64, cap);
    // With content-length: refused before the body.
    let err = block_on(fetch_document(&transport, &url("over.json"), cap)).expect_err("over");
    assert!(is_range_error(&err), "{err:?}");
    // Without content-length (the fault drops it and adds a byte): refused by the body cap.
    origin.set_faults(vec![TransportFault::ExtraBytes(1)]);
    let err = block_on(fetch_document(&transport, &url("exact.json"), cap)).expect_err("extra");
    assert!(is_too_large(&err), "{err:?}");
    // A document needs 200.
    origin.set_faults(vec![TransportFault::Status(206)]);
    assert!(block_on(fetch_document(&transport, &url("exact.json"), cap)).is_err());
}

#[test]
fn a_missing_root_is_absent_only_for_the_decided_statuses() {
    let _s = serial();
    let transport = FakeTransport::new(FakeOrigin::new());
    let origin = transport.origin().clone();
    let url = format!("{FAKE_BASE_URL}/root-2.json");
    // Not served at all: 404.
    assert_eq!(
        block_on(fetch_root_doc(&transport, &url, 65536)).expect("404"),
        None
    );
    origin.put("root-2.json", b"{}".to_vec());
    for status in ABSENT_ROOT_STATUSES {
        origin.set_faults(vec![TransportFault::Status(status)]);
        assert_eq!(
            block_on(fetch_root_doc(&transport, &url, 65536)).expect("absent"),
            None,
            "{status}"
        );
    }
    for status in [500, 401, 416, 200] {
        if status == 200 {
            origin.set_faults(vec![]);
            assert_eq!(
                block_on(fetch_root_doc(&transport, &url, 65536)).expect("present"),
                Some(b"{}".to_vec())
            );
            continue;
        }
        origin.set_faults(vec![TransportFault::Status(status)]);
        assert!(
            block_on(fetch_root_doc(&transport, &url, 65536)).is_err(),
            "{status} counted as absent"
        );
    }
}

// ---- range runs ----------------------------------------------------------------------------------

#[test]
fn range_runs_fetch_and_split_frames() {
    let _s = serial();
    let r = rig();
    let frames = vec![frame(0, 1000), frame(1000, 1500), frame(9000, 800)];
    let fetched = block_on(download(&r.ctx, &pack_target(), &frames)).expect("download");
    assert!(fetched.pack().is_none());
    assert_frames_cached(&*r.fs, &frames);
    for f in &frames {
        assert_eq!(fetched.frame(&f.sha256), Some(frame_path(f).as_path()));
    }
    // One merged run (gap 6500 <= 64 KiB).
    let seen = r.origin.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].range_header.as_deref(), Some("bytes=0-9799"));
    assert_eq!(seen[0].if_range, None);
    // A second call fetches nothing.
    r.origin.clear_requests();
    block_on(download(&r.ctx, &pack_target(), &frames)).expect("again");
    assert!(r.origin.requests().is_empty());
    workers_stopped();
}

#[test]
fn a_run_resumes_after_a_truncated_body() {
    let _s = serial();
    // (truncate after n body bytes, the Range of the resuming request, whether If-Range is sent)
    let cases = [
        (1u64, "bytes=1-2499", true),
        (999, "bytes=999-2499", true),
        (1000, "bytes=1000-2499", false),
        (2499, "bytes=2499-2499", true),
    ];
    for (n, expect_range, expect_if_range) in cases {
        let r = rig();
        let frames = two_frames();
        r.origin.set_faults(vec![TransportFault::TruncateAfter(n)]);
        let err = block_on(download(&r.ctx, &pack_target(), &frames)).expect_err("truncated");
        assert!(matches!(err, Error::Incomplete), "n={n}: {err:?}");
        workers_stopped();
        r.origin.set_faults(vec![]);
        r.origin.clear_requests();
        block_on(download(&r.ctx, &pack_target(), &frames)).expect("resume");
        let seen = r.origin.requests();
        assert_eq!(seen.len(), 1, "n={n}: {seen:?}");
        assert_eq!(seen[0].range_header.as_deref(), Some(expect_range), "n={n}");
        assert_eq!(
            seen[0].if_range.is_some(),
            expect_if_range,
            "n={n}: {seen:?}"
        );
        if let Some(v) = &seen[0].if_range {
            assert!(v.starts_with('"'), "n={n}: a strong ETag is preferred: {v}");
        }
        assert_frames_cached(&*r.fs, &frames);
        workers_stopped();
    }
}

#[test]
fn a_200_to_a_range_request_becomes_the_full_pack_with_no_second_request() {
    let _s = serial();
    let r = rig();
    r.origin.set_faults(vec![TransportFault::IgnoreRange]);
    let fetched = block_on(download(&r.ctx, &pack_target(), &two_frames())).expect("download");
    assert_eq!(fetched.pack(), Some(pack_path().as_path()));
    assert_eq!(read(&*r.fs, &pack_path()), pack_bytes());
    assert_eq!(r.origin.requests().len(), 1, "the 200 body was not reused");
    assert!(!exists(&*r.fs, &pack_part()));
    workers_stopped();
}

#[test]
fn malformed_range_answers_are_range_errors() {
    let _s = serial();
    for fault in [
        TransportFault::GzipEncoded,
        TransportFault::DuplicateHeader("content-range"),
        TransportFault::WrongContentRange,
        TransportFault::NoContentRange,
    ] {
        let r = rig();
        r.origin.set_faults(vec![fault.clone()]);
        let err = block_on(download(&r.ctx, &pack_target(), &two_frames())).expect_err("refused");
        assert!(is_range_error(&err), "{fault:?}: {err:?}");
        assert!(names(&*r.fs, "frames").is_empty(), "{fault:?} wrote a part");
        workers_stopped();
    }
}

#[test]
fn a_frame_with_wrong_bytes_is_reported_and_not_cached() {
    let _s = serial();
    let r = rig();
    let mut frames = two_frames();
    frames[1].sha256 = sha(b"something else");
    let fetched = block_on(download(&r.ctx, &pack_target(), &frames)).expect("download");
    assert_eq!(fetched.bad(), &[frames[1].sha256]);
    assert!(fetched.frame(&frames[1].sha256).is_none());
    assert!(!exists(&*r.fs, &frame_path(&frames[1])));
    assert!(!exists(&*r.fs, &frame_part(&frames[1])));
    assert_frames_cached(&*r.fs, &frames[..1]);
    workers_stopped();
}

// ---- full pack -----------------------------------------------------------------------------------

#[test]
fn a_pack_download_resumes_and_a_changed_etag_restarts_from_zero() {
    let _s = serial();
    let r = rig();
    r.origin
        .set_faults(vec![TransportFault::TruncateAfter(5000)]);
    let err = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect_err("truncated");
    assert!(matches!(err, Error::Incomplete), "{err:?}");
    assert_eq!(read(&*r.fs, &pack_part()).len(), 5000);

    // A plain resume: a matching 206 is appended.
    r.origin
        .set_faults(vec![TransportFault::TruncateAfter(3000)]);
    r.origin.clear_requests();
    let err = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect_err("truncated again");
    assert!(matches!(err, Error::Incomplete), "{err:?}");
    let seen = r.origin.requests();
    assert_eq!(seen[0].range_header.as_deref(), Some("bytes=5000-"));
    assert!(seen[0].if_range.is_some());
    assert_eq!(read(&*r.fs, &pack_part()).len(), 8000);

    // The ETag changes from the next request on: If-Range fails, the 200 restarts at 0.
    r.origin.clear_requests();
    r.origin
        .set_faults(vec![TransportFault::ChangeETagAfter(0)]);
    let path = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("restart");
    let seen = r.origin.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].range_header.as_deref(), Some("bytes=8000-"));
    assert_eq!(read(&*r.fs, &path), pack_bytes());
    assert!(!exists(&*r.fs, &pack_part()));
    workers_stopped();
}

/// Counts body bytes the engine pulls from the transport.
struct Counting {
    inner: FakeTransport,
    pulled: Arc<AtomicU64>,
}

struct CountingBody {
    inner: Box<dyn Body>,
    pulled: Arc<AtomicU64>,
}

impl Body for CountingBody {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            let chunk = self.inner.next_chunk().await?;
            if let Some(c) = &chunk {
                self.pulled.fetch_add(c.len() as u64, Ordering::SeqCst);
            }
            Ok(chunk)
        })
    }
}

impl Transport for Counting {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let future = self.inner.get(request);
        let pulled = Arc::clone(&self.pulled);
        Box::pin(async move {
            let response = future.await?;
            Ok(Response {
                head: response.head,
                body: Box::new(CountingBody {
                    inner: response.body,
                    pulled,
                }),
            })
        })
    }
}

#[test]
fn endless_and_extra_bytes_stop_at_the_cap_and_delete_the_pack_part() {
    let _s = serial();
    for fault in [TransportFault::Endless, TransportFault::ExtraBytes(10)] {
        let fake = FakeTransport::new(FakeOrigin::new());
        let origin = fake.origin().clone();
        let pulled = Arc::new(AtomicU64::new(0));
        let transport = Counting {
            inner: fake,
            pulled: Arc::clone(&pulled),
        };
        let r = rig_with(Arc::new(MemFs::new()), Arc::new(transport), origin);
        r.origin.set_faults(vec![fault.clone()]);
        let err = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect_err("overflow");
        assert!(is_too_large(&err), "{fault:?}: {err:?}");
        assert!(
            !exists(&*r.fs, &pack_part()),
            "{fault:?}: the part was kept"
        );
        assert!(!exists(&*r.fs, &pack_path()));
        let pulled = pulled.load(Ordering::SeqCst);
        assert!(
            pulled <= PACK_LEN as u64 + 8192,
            "{fault:?}: pulled {pulled} bytes"
        );

        // On a range run: an error, and no frame file longer than its frame.
        r.origin.clear_requests();
        let frames = two_frames();
        let err = block_on(download(&r.ctx, &pack_target(), &frames)).expect_err("run overflow");
        assert!(is_too_large(&err), "{fault:?}: {err:?}");
        for f in &frames {
            for p in [frame_path(f), frame_part(f)] {
                if let Some(m) = r.fs.symlink_metadata(&p).expect("meta") {
                    assert!(m.len <= f.length, "{fault:?}: {} bytes", m.len);
                }
            }
        }
        workers_stopped();
    }
}

#[test]
fn a_pack_with_the_wrong_hash_is_retried_once_then_refused() {
    let _s = serial();
    let r = rig();
    let mut target = pack_target();
    target.sha256 = sha(b"not the pack");
    let err = block_on(fetch_pack(&r.ctx, &target, None)).expect_err("bad hash");
    assert!(
        matches!(err, Error::Verify(lunepack_core::Error::ArtifactHash)),
        "{err:?}"
    );
    assert_eq!(r.origin.requests().len(), 2, "exactly one retry");
    assert!(
        names(&*r.fs, "packs").is_empty(),
        "{:?}",
        names(&*r.fs, "packs")
    );
    workers_stopped();
}

/// Rewrites every `ETag` into a weak one.
struct WeakETags(FakeTransport);

impl Transport for WeakETags {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let future = self.0.get(request);
        Box::pin(async move {
            let mut response = future.await?;
            for (name, value) in &mut response.head.headers {
                if name == "etag" {
                    let mut weak = b"W/".to_vec();
                    weak.extend_from_slice(value);
                    *value = weak;
                }
            }
            Ok(response)
        })
    }
}

#[test]
fn a_weak_etag_is_never_sent() {
    let _s = serial();
    let fake = FakeTransport::new(FakeOrigin::new());
    let origin = fake.origin().clone();
    let r = rig_with(Arc::new(MemFs::new()), Arc::new(WeakETags(fake)), origin);
    r.origin
        .set_faults(vec![TransportFault::TruncateAfter(100)]);
    assert!(block_on(fetch_pack(&r.ctx, &pack_target(), None)).is_err());
    assert!(block_on(download(&r.ctx, &pack_target(), &two_frames())).is_err());
    r.origin.set_faults(vec![]);
    block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("pack");
    block_on(download(&r.ctx, &pack_target(), &[frame(3000, 500)])).expect("frames");
    let seen = r.origin.requests();
    assert!(seen.iter().filter(|s| s.if_range.is_some()).count() >= 1);
    for s in seen {
        if let Some(v) = &s.if_range {
            assert!(!v.starts_with("W/"), "a weak ETag was sent: {v}");
        }
    }
    workers_stopped();
}

// ---- cache ---------------------------------------------------------------------------------------

#[test]
fn a_part_longer_than_its_signed_size_is_deleted() {
    let _s = serial();
    let r = rig();
    let frames = two_frames();
    r.ctx.cache.ensure_dirs().expect("dirs");
    let mut w = r.fs.create_new(&frame_part(&frames[0])).expect("part");
    w.write_all(&vec![0u8; 1001]).expect("write");
    w.sync().expect("sync");
    drop(w);
    let mut w = r.fs.create_new(&pack_part()).expect("pack part");
    w.write_all(&vec![0u8; PACK_LEN + 1]).expect("write");
    w.sync().expect("sync");
    drop(w);
    block_on(download(&r.ctx, &pack_target(), &frames)).expect("download");
    assert_eq!(
        r.origin.requests()[0].range_header.as_deref(),
        Some("bytes=0-2499"),
        "the long part was resumed"
    );
    assert_frames_cached(&*r.fs, &frames);
    r.origin.clear_requests();
    block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("pack");
    assert_eq!(r.origin.requests()[0].range_header, None);
    assert_eq!(read(&*r.fs, &pack_path()), pack_bytes());
    workers_stopped();
}

#[test]
fn cache_cleanup_leaves_only_named_entries() {
    let _s = serial();
    let fs: Arc<dyn Fs> = Arc::new(MemFs::new());
    let cache = Cache::new(Arc::clone(&fs), PathBuf::from(CACHE));
    cache.ensure_dirs().expect("dirs");
    let keep_frame = sha(b"keep frame");
    let keep_pack = sha(b"keep pack");
    let other = sha(b"other");
    let touch = |p: PathBuf| {
        fs.create_new(&p).expect("create").sync().expect("sync");
    };
    touch(cache.path(CacheKind::Frame, &keep_frame));
    touch(cache.part_path(CacheKind::Frame, &keep_frame));
    touch(cache.path(CacheKind::Frame, &other));
    touch(cache.part_path(CacheKind::Frame, &other));
    touch(Path::new(CACHE).join("frames").join("junk.tmp"));
    fs.create_dir_all(&Path::new(CACHE).join("frames").join("subdir"))
        .expect("dir");
    touch(cache.part_path(CacheKind::Pack, &keep_pack));
    touch(cache.path(CacheKind::Pack, &other));
    cache
        .cleanup(&HashSet::from([keep_frame]), &HashSet::from([keep_pack]))
        .expect("cleanup");
    assert_eq!(
        names(&*fs, "frames"),
        vec![keep_frame.to_hex(), format!("{}.part", keep_frame.to_hex())]
    );
    assert_eq!(
        names(&*fs, "packs"),
        vec![format!("{}.part", keep_pack.to_hex())]
    );
    // Removing an entry removes all its files.
    cache
        .remove_entry(CacheKind::Frame, &keep_frame)
        .expect("remove");
    assert!(names(&*fs, "frames").is_empty());
}

// ---- cancel safety -------------------------------------------------------------------------------

struct ParkWaker {
    thread: Thread,
    woken: AtomicBool,
}

impl Wake for ParkWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
        self.thread.unpark();
    }
}

/// Polls `future` until it is ready or has been polled `limit` times; `Some` when it finished.
fn poll_at_most<F: Future>(future: F, limit: usize) -> Option<F::Output> {
    let mut future = pin!(future);
    let state = Arc::new(ParkWaker {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&state));
    let mut cx = Context::from_waker(&waker);
    for _ in 0..limit {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return Some(v);
        }
        while !state.woken.swap(false, Ordering::SeqCst) {
            thread::park_timeout(Duration::from_millis(50));
        }
    }
    None
}

fn only_cache_files(fs: &dyn Fs) {
    for dir in ["frames", "packs"] {
        for name in names(fs, dir) {
            let stem = name
                .strip_suffix(".part")
                .or_else(|| name.strip_suffix(".meta"))
                .unwrap_or(&name);
            assert!(
                Sha256Digest::from_hex(stem).is_ok(),
                "unexpected cache file {dir}/{name}"
            );
        }
    }
}

#[test]
fn dropping_a_download_after_any_poll_leaves_a_resumable_cache() {
    let _s = serial();
    let frames = vec![frame(0, 300), frame(300, 200), frame(5000, 100)];
    let mut n = 1;
    loop {
        let r = rig();
        r.origin.set_faults(vec![TransportFault::SlowChunks]);
        let finished = poll_at_most(download(&r.ctx, &pack_target(), &frames), n);
        workers_stopped();
        only_cache_files(&*r.fs);
        let done = finished.is_some();
        if let Some(result) = finished {
            result.expect("uncancelled download");
        }
        block_on(download(&r.ctx, &pack_target(), &frames)).expect("fresh call");
        assert_frames_cached(&*r.fs, &frames);
        workers_stopped();
        if done {
            break;
        }
        n += 1;
        assert!(n < 20_000, "the download never finished");
    }
    assert!(
        n > 10,
        "only {n} polls: the test did not exercise cancellation"
    );
}

#[test]
fn a_cancelled_token_stops_a_download() {
    let _s = serial();
    let mut r = rig();
    r.origin.set_faults(vec![TransportFault::SlowChunks]);
    let cancel = CancelToken::new();
    r.ctx.cancel = cancel.clone();
    let canceller = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        cancel.cancel();
    });
    let result = block_on(fetch_pack(&r.ctx, &pack_target(), None));
    canceller.join().expect("canceller");
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");
    workers_stopped();
    only_cache_files(&*r.fs);
    r.ctx.cancel = CancelToken::new();
    r.origin.set_faults(vec![]);
    block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("resume");
    assert_eq!(read(&*r.fs, &pack_path()), pack_bytes());
}

// ---- a writer that outlives its future keeps the lock ---------------------------------------------

/// A one-shot gate: the first part write blocks until released.
#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool, bool)>, // (armed, blocked, released)
    cond: Condvar,
}

impl Gate {
    fn lock(&self) -> MutexGuard<'_, (bool, bool, bool)> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn pass(&self) {
        let mut s = self.lock();
        if !s.0 {
            return;
        }
        s.0 = false;
        s.1 = true;
        self.cond.notify_all();
        while !s.2 {
            s = self.cond.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }
    fn blocked(&self) -> bool {
        self.lock().1
    }
    fn release(&self) {
        self.lock().2 = true;
        self.cond.notify_all();
    }
}

struct GatedWrite {
    inner: Box<dyn FileWrite>,
    gate: Arc<Gate>,
}

impl Write for GatedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.gate.pass();
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl FileWrite for GatedWrite {
    fn sync(&mut self) -> Result<(), FsError> {
        self.inner.sync()
    }
}

/// `MemFs` whose `.part` writers pass through the gate.
struct GatedFs {
    inner: MemFs,
    gate: Arc<Gate>,
}

impl GatedFs {
    fn wrap(&self, path: &Path, w: Box<dyn FileWrite>) -> Box<dyn FileWrite> {
        if path.extension().is_some_and(|e| e == "part") {
            Box::new(GatedWrite {
                inner: w,
                gate: Arc::clone(&self.gate),
            })
        } else {
            w
        }
    }
}

impl Fs for GatedFs {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        self.inner.read_capped(path, max)
    }
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        self.inner.open_read(path)
    }
    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        Ok(self.wrap(path, self.inner.create_new(path)?))
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        Ok(self.wrap(path, self.inner.open_append(path)?))
    }
    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        self.inner.truncate(path, len)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
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
        self.inner.set_exec(path, exec)
    }
    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        self.inner.symlink(target, link_path)
    }
    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        self.inner.try_lock(path)
    }
}

#[test]
fn a_writer_that_outlives_its_future_keeps_the_lock() {
    let _s = serial();
    let gate = Arc::new(Gate::default());
    gate.lock().0 = true;
    let mem = MemFs::new();
    mem.create_dir_all(Path::new("/state")).expect("state dir");
    let fs: Arc<dyn Fs> = Arc::new(GatedFs {
        inner: mem,
        gate: Arc::clone(&gate),
    });
    let lock_path = PathBuf::from("/state/lock");
    let transport = FakeTransport::new(FakeOrigin::new());
    let origin = transport.origin().clone();
    let mut r = rig_with(Arc::clone(&fs), Arc::new(transport), origin);
    let watch = Arc::clone(&gate);

    let lock = block_on(acquire_op_lock(Arc::clone(&fs), lock_path.clone())).expect("lock");
    r.ctx.lock = Some(lock);
    {
        let ctx = r.ctx.clone();
        let target = pack_target();
        // Poll until the writer job is stuck inside its first write, then drop the future.
        let mut polls = 0;
        let finished = poll_at_most(
            async move {
                let mut future = pin!(fetch_pack(&ctx, &target, None));
                std::future::poll_fn(|cx| {
                    polls += 1;
                    if gate.blocked() {
                        return Poll::Ready(None);
                    }
                    let out = future.as_mut().poll(cx).map(Some);
                    if out.is_pending() {
                        // Re-poll soon: the writer blocking does not wake this task.
                        cx.waker().wake_by_ref();
                    }
                    out
                })
                .await
            },
            100_000,
        );
        assert!(matches!(finished, Some(None)), "the writer never blocked");
    }
    r.ctx.lock = None;
    // The future and the test's clone are gone; the blocked writer still holds the lock.
    let busy = block_on(acquire_op_lock(Arc::clone(&fs), lock_path.clone()));
    assert!(matches!(busy, Err(Error::Busy)), "{busy:?}");
    assert!(live_workers() >= 1);

    // Release it: the writer finishes its write, sees the cancel, syncs and exits.
    watch.release();
    workers_stopped();
    let lock = block_on(acquire_op_lock(Arc::clone(&fs), lock_path)).expect("not busy");
    r.ctx.lock = Some(lock);
    let path = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("resume");
    assert_eq!(read(&*r.fs, &path), pack_bytes());
}

// ---- more resume cases ---------------------------------------------------------------------------

#[test]
fn a_dropped_connection_is_incomplete_and_the_part_survives_a_crash() {
    let _s = serial();
    let mem = MemFs::new();
    let transport = FakeTransport::new(FakeOrigin::new());
    let origin = transport.origin().clone();
    let r = rig_with(Arc::new(mem.clone()), Arc::new(transport), origin);
    r.origin.set_faults(vec![TransportFault::ErrorAfter(7000)]);
    let err = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect_err("dropped");
    assert!(matches!(err, Error::Incomplete), "{err:?}");
    workers_stopped();
    // Synced: a crash that loses every volatile byte and entry keeps the part.
    mem.crash_now();
    let disk = mem.recover(lunepack_testkit::RecoverMode::DropVolatile);
    assert_eq!(read(&disk, &pack_part()), pack_bytes()[..7000]);

    let transport = FakeTransport::new(FakeOrigin::new());
    let origin = transport.origin().clone();
    let r = rig_with(Arc::new(disk), Arc::new(transport), origin);
    let path = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("resume");
    assert_eq!(
        r.origin.requests()[0].range_header.as_deref(),
        Some("bytes=7000-")
    );
    assert_eq!(read(&*r.fs, &path), pack_bytes());
    workers_stopped();
}

#[test]
fn a_full_length_part_is_checked_without_a_request() {
    let _s = serial();
    let r = rig();
    r.ctx.cache.ensure_dirs().expect("dirs");
    let mut w = r.fs.create_new(&pack_part()).expect("part");
    w.write_all(&pack_bytes()).expect("write");
    w.sync().expect("sync");
    drop(w);
    let path = block_on(fetch_pack(&r.ctx, &pack_target(), None)).expect("complete");
    assert!(r.origin.requests().is_empty());
    assert_eq!(read(&*r.fs, &path), pack_bytes());
    workers_stopped();
}

#[test]
fn a_changed_etag_on_a_run_resume_falls_back_to_the_full_pack() {
    let _s = serial();
    let r = rig();
    r.origin
        .set_faults(vec![TransportFault::TruncateAfter(400)]);
    assert!(matches!(
        block_on(download(&r.ctx, &pack_target(), &two_frames())),
        Err(Error::Incomplete)
    ));
    r.origin.clear_requests();
    r.origin
        .set_faults(vec![TransportFault::ChangeETagAfter(0)]);
    let fetched = block_on(download(&r.ctx, &pack_target(), &two_frames())).expect("fallback");
    let seen = r.origin.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].range_header.as_deref(), Some("bytes=400-2499"));
    assert!(seen[0].if_range.is_some());
    assert_eq!(fetched.pack(), Some(pack_path().as_path()));
    assert_eq!(read(&*r.fs, &pack_path()), pack_bytes());
    workers_stopped();
}

#[test]
fn downloaded_bytes_are_reported_to_the_progress_sink() {
    let _s = serial();
    let mut r = rig();
    let (sink, mut pump) = lunepack::progress(lunepack_core::Phase::Download, 0);
    r.ctx.progress = Some(sink);
    block_on(download(&r.ctx, &pack_target(), &two_frames())).expect("download");
    let mut done = None;
    assert!(pump.pump(&mut |p: &lunepack_core::Progress| done = Some(p.done)));
    assert_eq!(done, Some(2500));
    workers_stopped();
}

#[test]
fn the_engine_futures_are_send() {
    let _s = serial();
    fn assert_send<T: Send>(_: &T) {}
    let r = rig();
    let target = pack_target();
    let frames = two_frames();
    let d = download(&r.ctx, &target, &frames);
    assert_send(&d);
    let p = fetch_pack(&r.ctx, &target, None);
    assert_send(&p);
    let t: &dyn Transport = &*r.ctx.transport;
    let doc = fetch_document(t, &target.url, 10);
    assert_send(&doc);
    let root = fetch_root_doc(t, &target.url, 10);
    assert_send(&root);
    let lock = acquire_op_lock(Arc::clone(&r.fs), PathBuf::from("/lock"));
    assert_send(&lock);
    drop((d, p, doc, root, lock));
}

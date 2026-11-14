//! The facade's task plumbing (M4 step 10): jobs, pipes, `block_on`, `WorkerTransport`, progress
//! and the operation lock, under five executors.
//!
//! Every test takes `SERIAL`: `live_workers()` is process-wide, so a test that counts workers must
//! not overlap another test's jobs.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use lunepack::{
    Closed, Error, JobFuture, OpLock, RecvFuture, SendFuture, WORKER_THREAD_NAME, WorkerTransport,
    block_on, from_async, live_workers, progress, spawn_job, to_async,
};
use lunepack_core::{
    CancelToken, FileProgress, Fs, Phase, Progress, RelPath, Request, Response, Source, Transport,
    TransportError,
};
use lunepack_testkit::{
    FAKE_BASE_URL, FakeBlockingTransport, MemFs, TransportFault, TransportFixture,
    run_transport_suite,
};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    // A failed test poisons the lock; the next test still runs alone.
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Polls `cond` every 2 ms until it holds or `limit` passes; whether it held.
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

fn assert_send_static<T: Send + 'static>(_: &T) {}

/// Runs the future `make()` builds to completion under each of the five executors.
fn on_every_executor<F, Fut>(make: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    block_on(make());
    futures::executor::block_on(make());
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio current-thread")
        .block_on(make());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .expect("tokio multi-thread");
    // Spawned, so the future runs on a runtime worker thread, not the test thread.
    rt.block_on(rt.spawn(make())).expect("task panicked");
    smol::block_on(smol::spawn(make()));
}

/// Polls a future exactly once.
struct PollOnce<'a, F>(&'a mut F);

impl<F: Future + Unpin> Future for PollOnce<'_, F> {
    type Output = Poll<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Pin::new(&mut *self.0).poll(cx))
    }
}

fn poll_once<F: Future + Unpin>(f: &mut F) -> PollOnce<'_, F> {
    PollOnce(f)
}

/// A waker that counts its wakes.
#[derive(Default)]
struct CountingWaker(AtomicUsize);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// ---- jobs ----------------------------------------------------------------------------------------

#[test]
fn a_job_result_arrives_on_a_named_worker_thread() {
    let _s = serial();
    on_every_executor(|| async {
        let caller = thread::current().id();
        let (value, name, id) = spawn_job("result", CancelToken::new(), None, |_| {
            let t = thread::current();
            (42u32, t.name().map(str::to_owned), t.id())
        })
        .await
        .expect("job");
        assert_eq!(value, 42);
        assert_eq!(name.as_deref(), Some(WORKER_THREAD_NAME));
        assert_ne!(id, caller, "the job ran on the polling thread");
    });
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

#[test]
fn a_panic_in_a_job_is_worker_panicked() {
    let _s = serial();
    on_every_executor(|| async {
        let result: Result<(), Error> =
            spawn_job("panics", CancelToken::new(), None, |_| panic!("boom")).await;
        assert!(matches!(result, Err(Error::WorkerPanicked)), "{result:?}");
    });
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

#[test]
fn a_dropped_job_future_cancels_its_worker() {
    let _s = serial();
    on_every_executor(|| async {
        let started = Arc::new(AtomicBool::new(false));
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let (s, c) = (Arc::clone(&started), Arc::clone(&saw_cancel));
        let mut job = spawn_job("cancel", CancelToken::new(), None, move |cancel| {
            s.store(true, Ordering::SeqCst);
            while !cancel.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            c.store(true, Ordering::SeqCst);
        });
        assert!(poll_once(&mut job).await.is_pending());
        assert!(wait_until(Duration::from_secs(1), || started.load(Ordering::SeqCst)));
        let t = Instant::now();
        drop(job);
        assert!(t.elapsed() < Duration::from_millis(50), "drop blocked");
        assert!(wait_until(Duration::from_secs(1), || saw_cancel.load(Ordering::SeqCst)));
        assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
    });
}

#[test]
fn live_workers_counts_blocked_jobs() {
    let _s = serial();
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
    let (release, gate) = mpsc::channel::<()>();
    let gate = Arc::new(Mutex::new(gate));
    let jobs: Vec<JobFuture<()>> = (0..3)
        .map(|_| {
            let gate = Arc::clone(&gate);
            spawn_job("blocked", CancelToken::new(), None, move |_| {
                let _ = gate.lock().expect("gate").recv();
            })
        })
        .collect();
    assert_eq!(live_workers(), 3);
    for _ in 0..3 {
        release.send(()).expect("release");
    }
    for job in jobs {
        block_on(job).expect("job");
    }
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

#[test]
fn an_op_lock_held_by_a_job_outlives_the_dropped_future() {
    let _s = serial();
    let fs = MemFs::new();
    fs.create_dir_all(Path::new("/state")).expect("dir");
    let lock_path = Path::new("/state/lock");
    let guard = fs.try_lock(lock_path).expect("lock").expect("free");
    let op = OpLock::new(guard);
    let (release, gate) = mpsc::channel::<()>();
    let job = spawn_job("writer", CancelToken::new(), Some(op.clone()), move |_| {
        // Ignores the token: a writer mid-append finishes its write first.
        let _ = gate.recv();
    });
    drop(op);
    drop(job);
    thread::sleep(Duration::from_millis(50));
    assert!(
        fs.try_lock(lock_path).expect("lock").is_none(),
        "the lock was released while its job still ran"
    );
    release.send(()).expect("release");
    let released = wait_until(Duration::from_millis(100), || {
        fs.try_lock(lock_path).expect("lock").is_some()
    });
    assert!(released, "the lock was not released after the job ended");
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

// ---- pipes ---------------------------------------------------------------------------------------

const CHUNKS: u32 = 10_000;

#[test]
fn a_worker_to_task_pipe_delivers_10000_chunks_in_order() {
    let _s = serial();
    on_every_executor(|| async {
        let cancel = CancelToken::new();
        let (tx, rx) = to_async::<u32>(lunepack::DEFAULT_CAPACITY, cancel.clone());
        let job = spawn_job("producer", cancel, None, move |_| {
            for i in 0..CHUNKS {
                tx.send(i).expect("send");
            }
            tx.finish();
        });
        for i in 0..CHUNKS {
            assert_eq!(rx.recv().await, Ok(Some(i)));
        }
        assert_eq!(rx.recv().await, Ok(None));
        assert_eq!(rx.recv().await, Ok(None));
        job.await.expect("job");
    });
}

#[test]
fn a_task_to_worker_pipe_delivers_10000_chunks_in_order() {
    let _s = serial();
    on_every_executor(|| async {
        let cancel = CancelToken::new();
        let (tx, rx) = from_async::<u32>(lunepack::DEFAULT_CAPACITY, cancel.clone());
        let job = spawn_job("consumer", cancel, None, move |_| {
            let mut got = Vec::new();
            while let Some(i) = rx.recv().expect("recv") {
                got.push(i);
            }
            got
        });
        for i in 0..CHUNKS {
            tx.send(i).await.expect("send");
        }
        tx.finish();
        let got = job.await.expect("job");
        assert_eq!(got, (0..CHUNKS).collect::<Vec<_>>());
    });
}

#[test]
fn a_dropped_consumer_frees_a_blocked_producer() {
    let _s = serial();
    on_every_executor(|| async {
        let cancel = CancelToken::new();
        let (tx, rx) = to_async::<u32>(2, cancel.clone());
        let job = spawn_job("producer", cancel, None, move |_| {
            let mut sent = 0u32;
            while tx.send(sent).is_ok() {
                sent += 1;
            }
            sent
        });
        assert_eq!(rx.recv().await, Ok(Some(0)));
        // Let the producer fill the pipe and block.
        thread::sleep(Duration::from_millis(20));
        let t = Instant::now();
        drop(rx);
        let sent = job.await.expect("job");
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
        assert!(sent >= 3, "{sent}");
    });
}

#[test]
fn a_dropped_async_sender_frees_a_blocked_consumer() {
    let _s = serial();
    on_every_executor(|| async {
        let cancel = CancelToken::new();
        let (tx, rx) = from_async::<u32>(2, cancel.clone());
        let job = spawn_job("consumer", cancel, None, move |_| {
            let mut got = Vec::new();
            loop {
                match rx.recv() {
                    Ok(Some(i)) => got.push(i),
                    other => return (got, other),
                }
            }
        });
        tx.send(7).await.expect("send");
        thread::sleep(Duration::from_millis(20));
        let t = Instant::now();
        // Dropped without finish: an abort, not an end of stream.
        drop(tx);
        let (got, end) = job.await.expect("job");
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(got, vec![7]);
        assert_eq!(end, Err(Closed));
    });
}

#[test]
fn a_cancelled_token_frees_both_blocking_sides_promptly() {
    let _s = serial();
    // Blocked sender: the receiver is alive but never reads.
    let cancel = CancelToken::new();
    let (tx, rx) = to_async::<u32>(1, cancel.clone());
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut result = Ok(());
        for i in 0.. {
            result = tx.send(i);
            if result.is_err() {
                break;
            }
        }
        done_tx.send(result).expect("report");
    });
    thread::sleep(Duration::from_millis(20));
    cancel.cancel();
    let result = done_rx
        .recv_timeout(Duration::from_millis(200))
        .expect("a blocked sender did not see the cancel");
    assert_eq!(result, Err(Closed));
    worker.join().expect("worker");
    // The async side reports the cancel too.
    assert_eq!(block_on(rx.recv()), Err(Closed));

    // Blocked receiver: the sender is alive but never sends.
    let cancel = CancelToken::new();
    let (tx, rx) = from_async::<u32>(1, cancel.clone());
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || done_tx.send(rx.recv()).expect("report"));
    thread::sleep(Duration::from_millis(20));
    cancel.cancel();
    let result = done_rx
        .recv_timeout(Duration::from_millis(200))
        .expect("a blocked receiver did not see the cancel");
    assert_eq!(result, Err(Closed));
    worker.join().expect("worker");
    assert_eq!(block_on(tx.send(1)), Err(Closed));
}

#[test]
fn a_cancel_wakes_a_pending_async_side() {
    let _s = serial();
    let cancel = CancelToken::new();
    let (_tx, rx) = to_async::<u32>(1, cancel.clone());
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    let mut recv = rx.recv();
    assert!(Pin::new(&mut recv).poll(&mut cx).is_pending());
    cancel.cancel();
    assert!(counter.0.load(Ordering::SeqCst) >= 1, "cancel did not wake");
    assert_eq!(Pin::new(&mut recv).poll(&mut cx), Poll::Ready(Err(Closed)));
}

// ---- block_on ------------------------------------------------------------------------------------

/// Pending on the first poll; a thread wakes it once after 20 ms; ready after that.
struct WokenLater {
    polls: Arc<AtomicUsize>,
    woken: Arc<AtomicBool>,
}

impl Future for WokenLater {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let n = self.polls.fetch_add(1, Ordering::SeqCst);
        if self.woken.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        if n == 0 {
            let waker = cx.waker().clone();
            let woken = Arc::clone(&self.woken);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                woken.store(true, Ordering::SeqCst);
                waker.wake();
            });
        }
        Poll::Pending
    }
}

#[test]
fn block_on_parks_between_polls() {
    let _s = serial();
    let polls = Arc::new(AtomicUsize::new(0));
    block_on(WokenLater {
        polls: Arc::clone(&polls),
        woken: Arc::new(AtomicBool::new(false)),
    });
    let n = polls.load(Ordering::SeqCst);
    assert!(n <= 3, "polled {n} times");
}

// ---- WorkerTransport -----------------------------------------------------------------------------

#[test]
fn worker_transport_passes_the_transport_suite() {
    let _s = serial();
    let fake = FakeBlockingTransport::fixture();
    let origin = fake.origin().clone();
    let transport = WorkerTransport::new(fake);
    run_transport_suite(&transport, FAKE_BASE_URL, &|| origin.requests());
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

fn large_url() -> String {
    format!("{FAKE_BASE_URL}/{}", TransportFixture::LARGE)
}

async fn read_all(transport: Arc<dyn Transport>) -> Result<Vec<u8>, TransportError> {
    let mut response = transport
        .get(Request {
            url: large_url(),
            range: None,
            if_range: None,
        })
        .await?;
    assert_eq!(response.head.status, 200);
    let mut body = Vec::new();
    while let Some(chunk) = response.body.next_chunk().await? {
        assert!(!chunk.is_empty() && chunk.len() <= lunepack::CHUNK_SIZE);
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[test]
fn worker_transport_reads_a_body_under_every_executor() {
    let _s = serial();
    let large = TransportFixture::bytes(TransportFixture::LARGE).expect("fixture");
    let transport: Arc<dyn Transport> =
        Arc::new(WorkerTransport::new(FakeBlockingTransport::fixture()));
    on_every_executor(|| {
        let transport = Arc::clone(&transport);
        let large = large.clone();
        async move {
            assert_eq!(read_all(transport).await.expect("get"), large);
        }
    });
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

#[test]
fn dropping_a_worker_response_or_get_future_cancels_the_worker() {
    let _s = serial();
    let transport: Arc<dyn Transport> = Arc::new(WorkerTransport::new(
        FakeBlockingTransport::fixture().with_fault(TransportFault::SlowChunks),
    ));
    on_every_executor(|| {
        let transport = Arc::clone(&transport);
        async move {
            // A response dropped after one chunk.
            let mut response: Response = transport
                .get(Request {
                    url: large_url(),
                    range: None,
                    if_range: None,
                })
                .await
                .expect("get");
            let chunk = response.body.next_chunk().await.expect("chunk");
            assert!(chunk.is_some());
            drop(response);
            assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));

            // A get future dropped before it resolved (or right after one poll).
            let mut get = transport.get(Request {
                url: large_url(),
                range: None,
                if_range: None,
            });
            let _ = poll_once(&mut get).await;
            drop(get);
            assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
        }
    });
}

#[test]
fn worker_transport_holds_the_op_lock_per_request() {
    let _s = serial();
    let fs = MemFs::new();
    fs.create_dir_all(Path::new("/state")).expect("dir");
    let lock_path = Path::new("/state/lock");
    let op = OpLock::new(fs.try_lock(lock_path).expect("lock").expect("free"));
    let base = WorkerTransport::new(
        FakeBlockingTransport::fixture().with_fault(TransportFault::SlowChunks),
    );
    let for_op = base.for_op(&op);
    drop(op);
    let mut response = block_on(for_op.get(Request {
        url: large_url(),
        range: None,
        if_range: None,
    }))
    .expect("get");
    drop(for_op);
    assert!(
        block_on(response.body.next_chunk())
            .expect("chunk")
            .is_some()
    );
    assert!(
        fs.try_lock(lock_path).expect("lock").is_none(),
        "the lock was released while a request job ran"
    );
    drop(response);
    assert!(wait_until(Duration::from_secs(1), || fs
        .try_lock(lock_path)
        .expect("lock")
        .is_some()));
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

// ---- progress ------------------------------------------------------------------------------------

#[test]
fn progress_coalesces_and_wakes_only_on_the_dirty_transition() {
    let _s = serial();
    let (sink, mut pump) = progress(Phase::Download, 1000);
    let counter = Arc::new(CountingWaker::default());
    pump.register_waker(&Waker::from(Arc::clone(&counter)));
    let mut events: Vec<Progress> = Vec::new();
    let mut record = |p: &Progress| events.push(p.clone());

    assert!(!pump.pump(&mut record), "nothing changed yet");

    let worker = {
        let sink = sink.clone();
        thread::spawn(move || {
            for _ in 0..100 {
                sink.add_done(5);
            }
        })
    };
    worker.join().expect("worker");
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "one wake for 100 updates"
    );
    assert!(pump.pump(&mut record));
    assert!(!pump.pump(&mut record), "no change since the last pump");

    let path = RelPath::parse("bin/app").expect("path");
    let file = FileProgress {
        path,
        done: 10,
        total: 20,
        source: Source::Range,
    };
    sink.set_file(Some(file.clone()));
    assert_eq!(counter.0.load(Ordering::SeqCst), 2);
    assert!(pump.pump(&mut record));
    // The same file again: dirty, but the snapshot is unchanged, so no event.
    sink.set_file(Some(file.clone()));
    assert!(!pump.pump(&mut record));

    sink.set_phase(Phase::Stage, 50);
    sink.add_done(50);
    assert!(pump.pump(&mut record));

    assert_eq!(
        events,
        vec![
            Progress {
                phase: Phase::Download,
                done: 500,
                total: 1000,
                file: None,
            },
            Progress {
                phase: Phase::Download,
                done: 500,
                total: 1000,
                file: Some(file),
            },
            Progress {
                phase: Phase::Stage,
                done: 50,
                total: 50,
                file: None,
            },
        ]
    );
}

#[test]
fn progress_wakes_a_task_polling_under_every_executor() {
    let _s = serial();
    on_every_executor(|| async {
        let (sink, mut pump) = progress(Phase::Scan, 3);
        let job = spawn_job("scan", CancelToken::new(), None, move |_| {
            for _ in 0..3 {
                thread::sleep(Duration::from_millis(2));
                sink.add_done(1);
            }
        });
        let mut last = None;
        // Pumps on every poll; ready once `done == 3` has been delivered. It is only re-polled
        // when a worker update wakes it.
        std::future::poll_fn(|cx| {
            pump.register_waker(cx.waker());
            pump.pump(&mut |p: &Progress| last = Some(p.done));
            if last == Some(3) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        job.await.expect("job");
    });
}

// ---- Send + 'static ------------------------------------------------------------------------------

#[test]
fn every_public_future_is_send_and_static() {
    let _s = serial();
    let cancel = CancelToken::new();
    let job: JobFuture<u32> = spawn_job("t", cancel.clone(), None, |_| 1);
    assert_send_static(&job);
    let (_btx, arx) = to_async::<Vec<u8>>(1, cancel.clone());
    let recv: RecvFuture<Vec<u8>> = arx.recv();
    assert_send_static(&recv);
    let (atx, _brx) = from_async::<Vec<u8>>(1, cancel.clone());
    let send: SendFuture<Vec<u8>> = atx.send(Vec::new());
    assert_send_static(&send);
    let transport = WorkerTransport::new(FakeBlockingTransport::fixture());
    let get = transport.get(Request {
        url: large_url(),
        range: None,
        if_range: None,
    });
    assert_send_static(&get);
    let response = block_on(get).expect("get");
    assert_send_static(&response);
    assert_send_static(&transport);
    drop((recv, send, response, arx, atx));
    assert_eq!(block_on(job).expect("job"), 1);
    assert!(wait_until(Duration::from_secs(1), || live_workers() == 0));
}

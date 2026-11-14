//! Worker jobs (M4-D2, M4-D3): blocking work on plain `std::thread`s, awaited as a future.
//!
//! A job runs one closure on its own thread named `lunepack-worker`, never on a caller's runtime.
//! Its [`JobFuture`] resolves to the closure's result. Dropping the future cancels the job's
//! [`CancelToken`] and detaches the thread: nothing ever blocks on or joins a worker. The worker
//! finishes on its own, which is why an operation's lock ([`OpLock`]) is held by every job it
//! spawns and released only when the last of them drops it (M4-D15).

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread;

use lunepack_core::{CancelToken, LockGuard};

use crate::Error;

/// The name of every worker thread.
pub const WORKER_THREAD_NAME: &str = "lunepack-worker";

/// Worker threads alive in this process (see [`live_workers`]).
static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// How many lunepack worker threads are alive in this process. A worker counts from just before
/// it is spawned until after its closure has returned (or panicked), its [`OpLock`] clone has been
/// dropped and its result has been handed over. Test support: a test that cancels an operation
/// waits for this to reach 0 to know every job of it has finished.
#[doc(hidden)]
pub fn live_workers() -> usize {
    LIVE_WORKERS.load(Ordering::SeqCst)
}

/// Decrements [`LIVE_WORKERS`] when dropped; the first local of a worker, so it drops last.
struct LiveGuard;

impl Drop for LiveGuard {
    fn drop(&mut self) {
        LIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The per-operation lock token (M4-D15): a clone of one OS lock guard. The future of an
/// operation holds one clone and each job it spawns holds another; the OS lock is released when
/// the last clone drops, so never while a job of the operation still runs.
#[derive(Clone)]
pub struct OpLock {
    // `LockGuard` is `Send` but not `Sync`; the mutex makes the shared guard `Sync` so clones can
    // move to other threads. It is never locked: the guard is only held and dropped.
    _guard: Arc<Mutex<Box<dyn LockGuard>>>,
}

impl OpLock {
    /// Wraps a held lock guard.
    pub fn new(guard: Box<dyn LockGuard>) -> Self {
        OpLock {
            _guard: Arc::new(Mutex::new(guard)),
        }
    }
}

impl fmt::Debug for OpLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpLock").finish_non_exhaustive()
    }
}

/// The hand-over slot between a worker and its future.
struct Slot<T> {
    /// The closure's outcome, once it has one.
    result: Option<thread::Result<T>>,
    /// The waker of the task that last polled the future.
    waker: Option<Waker>,
}

struct Shared<T> {
    slot: Mutex<Slot<T>>,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, Slot<T>> {
        // Only plain assignments happen under the lock, so a poisoned slot is still consistent.
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn complete(&self, result: thread::Result<T>) {
        let waker = {
            let mut slot = self.lock();
            slot.result = Some(result);
            slot.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The future of a job started with [`spawn_job`]. `Send + 'static` when `T` is `Send + 'static`.
///
/// It resolves to the closure's value, or to [`Error::WorkerPanicked`] when the closure panicked
/// (or no worker thread could be started). Dropping it cancels the job's token and detaches the
/// worker; it never blocks.
#[must_use = "a job future does nothing visible unless polled; dropping it cancels the job"]
pub struct JobFuture<T> {
    shared: Arc<Shared<T>>,
    cancel: CancelToken,
    name: &'static str,
    finished: bool,
}

impl<T> fmt::Debug for JobFuture<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobFuture")
            .field("name", &self.name)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<T> Future for JobFuture<T> {
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.finished, "JobFuture polled after it completed");
        let mut slot = self.shared.lock();
        match slot.result.take() {
            Some(result) => {
                slot.waker = None;
                drop(slot);
                self.finished = true;
                Poll::Ready(result.map_err(panicked))
            }
            None => {
                match &mut slot.waker {
                    Some(held) => held.clone_from(cx.waker()),
                    None => slot.waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
        }
    }
}

impl<T> Drop for JobFuture<T> {
    fn drop(&mut self) {
        if !self.finished {
            // The worker sees the token and stops early; its result, if any, is dropped with the
            // last reference to the slot. Nothing waits for the thread.
            self.cancel.cancel();
            self.shared.lock().waker = None;
        }
    }
}

fn panicked(payload: Box<dyn Any + Send>) -> Error {
    // A panic message may hold user data, so it is never shown; the payload is dropped here.
    drop(payload);
    Error::WorkerPanicked
}

/// Runs `f` on a new worker thread and returns its future.
///
/// - `name` labels the job in `Debug` output; the thread itself is always named
///   [`WORKER_THREAD_NAME`].
/// - `cancel` is handed to `f`; dropping the future before it completes cancels it.
/// - `hold` (the operation's [`OpLock`] clone, if any) is moved into the worker and dropped only
///   after `f` has returned or panicked.
/// - A panic in `f` resolves the future to [`Error::WorkerPanicked`].
pub fn spawn_job<T, F>(
    name: &'static str,
    cancel: CancelToken,
    hold: Option<OpLock>,
    f: F,
) -> JobFuture<T>
where
    T: Send + 'static,
    F: FnOnce(&CancelToken) -> T + Send + 'static,
{
    let shared = Arc::new(Shared {
        slot: Mutex::new(Slot {
            result: None,
            waker: None,
        }),
    });
    let worker_shared = Arc::clone(&shared);
    let token = cancel.clone();
    LIVE_WORKERS.fetch_add(1, Ordering::SeqCst);
    let spawned = thread::Builder::new()
        .name(WORKER_THREAD_NAME.to_owned())
        .spawn(move || {
            // Declared first, dropped last: the worker counts as live until everything below is
            // done.
            let _live = LiveGuard;
            let hold = hold;
            let result = catch_unwind(AssertUnwindSafe(|| f(&token)));
            drop(hold);
            worker_shared.complete(result);
        });
    if spawned.is_err() {
        // The closure (and `hold`) were dropped with the failed spawn; nothing runs.
        LIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
        shared.complete(Err(Box::new("worker thread could not be started")));
    }
    JobFuture {
        shared,
        cancel,
        name,
        finished: false,
    }
}

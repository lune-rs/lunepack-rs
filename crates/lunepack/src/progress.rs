//! Progress coalescing (M4-D3, M4-D19): workers report into a [`ProgressSink`]; the polling task
//! drains a [`ProgressPump`] and calls the app's callback with the latest snapshot.
//!
//! Workers never call the app's callback themselves, so the callback runs on the thread that polls
//! the operation. Updates between two polls collapse into one event. A worker's update wakes the
//! polling task only on the clean-to-dirty transition, so a flood of updates costs one wake.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Waker;

use lunepack_core::{FileProgress, Phase, Progress};

struct Meta {
    phase: Phase,
    total: u64,
    file: Option<FileProgress>,
}

struct Shared {
    done: AtomicU64,
    dirty: AtomicBool,
    meta: Mutex<Meta>,
    waker: Mutex<Option<Waker>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Only plain stores happen under these locks.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn mark_dirty(&self) {
        if !self.dirty.swap(true, Ordering::SeqCst) {
            let waker = lock(&self.waker).clone();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    fn snapshot(&self) -> Progress {
        let meta = lock(&self.meta);
        Progress {
            phase: meta.phase,
            done: self.done.load(Ordering::SeqCst),
            total: meta.total,
            file: meta.file.clone(),
        }
    }
}

/// A new progress channel, starting in `phase` with `total` bytes to do.
pub fn progress(phase: Phase, total: u64) -> (ProgressSink, ProgressPump) {
    let shared = Arc::new(Shared {
        done: AtomicU64::new(0),
        dirty: AtomicBool::new(false),
        meta: Mutex::new(Meta {
            phase,
            total,
            file: None,
        }),
        waker: Mutex::new(None),
    });
    (
        ProgressSink {
            shared: Arc::clone(&shared),
        },
        ProgressPump { shared, last: None },
    )
}

/// The workers' side: cheap updates (an atomic add, or a short lock) that never call back.
#[derive(Clone)]
pub struct ProgressSink {
    shared: Arc<Shared>,
}

impl ProgressSink {
    /// Adds `n` bytes done in the current phase (lock-free).
    pub fn add_done(&self, n: u64) {
        self.shared.done.fetch_add(n, Ordering::SeqCst);
        self.shared.mark_dirty();
    }

    /// Sets the file being worked on (or none).
    pub fn set_file(&self, file: Option<FileProgress>) {
        lock(&self.shared.meta).file = file;
        self.shared.mark_dirty();
    }

    /// Sets the total of the current phase without touching `done` (what is to do became known
    /// after the phase started).
    pub fn set_total(&self, total: u64) {
        lock(&self.shared.meta).total = total;
        self.shared.mark_dirty();
    }

    /// Raises the total of the current phase by `n` bytes (saturating); `done` is untouched.
    pub fn add_total(&self, n: u64) {
        {
            let mut meta = lock(&self.shared.meta);
            meta.total = meta.total.saturating_add(n);
        }
        self.shared.mark_dirty();
    }

    /// Lowers the total of the current phase by `n` bytes (saturating at 0): work that will not be
    /// done after all.
    pub fn sub_total(&self, n: u64) {
        {
            let mut meta = lock(&self.shared.meta);
            meta.total = meta.total.saturating_sub(n);
        }
        self.shared.mark_dirty();
    }

    /// Starts `phase` with `total` bytes to do: `done` goes back to 0 and the file to none.
    pub fn set_phase(&self, phase: Phase, total: u64) {
        {
            let mut meta = lock(&self.shared.meta);
            meta.phase = phase;
            meta.total = total;
            meta.file = None;
            self.shared.done.store(0, Ordering::SeqCst);
        }
        self.shared.mark_dirty();
    }
}

impl std::fmt::Debug for ProgressSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressSink").finish_non_exhaustive()
    }
}

/// The polling side. Call [`ProgressPump::register_waker`] with the polling task's waker, then
/// [`ProgressPump::pump`], on every poll of the operation.
pub struct ProgressPump {
    shared: Arc<Shared>,
    last: Option<Progress>,
}

impl ProgressPump {
    /// Stores the waker a worker's next update wakes (on the clean-to-dirty transition only).
    pub fn register_waker(&self, waker: &Waker) {
        let mut held = lock(&self.shared.waker);
        match &mut *held {
            Some(w) => w.clone_from(waker),
            None => *held = Some(waker.clone()),
        }
    }

    /// Calls `callback` at most once, with the latest snapshot, and only when it differs from the
    /// last one delivered. Returns whether it was called.
    pub fn pump<F: FnMut(&Progress) + ?Sized>(&mut self, callback: &mut F) -> bool {
        if !self.shared.dirty.swap(false, Ordering::SeqCst) {
            return false;
        }
        let snapshot = self.shared.snapshot();
        if self.last.as_ref() == Some(&snapshot) {
            return false;
        }
        callback(&snapshot);
        self.last = Some(snapshot);
        true
    }
}

impl std::fmt::Debug for ProgressPump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressPump").finish_non_exhaustive()
    }
}

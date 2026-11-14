//! Cooperative cancellation (C9): one token the facade hands to every part of an operation. The
//! token holds no clock and starts no thread; a cancel sets a flag and wakes every waker that
//! registered before it.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Waker;

struct Inner {
    cancelled: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

/// A cancellation flag shared by clones. `Clone + Send + Sync`.
#[derive(Clone)]
pub struct CancelToken {
    inner: Arc<Inner>,
}

impl CancelToken {
    /// A fresh token that is not cancelled.
    pub fn new() -> Self {
        CancelToken {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                wakers: Mutex::new(Vec::new()),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Waker>> {
        // A panic while the lock is held cannot leave the list half-edited (push and take only).
        self.inner
            .wakers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Cancels the token and wakes every registered waker once. A second call does nothing.
    pub fn cancel(&self) {
        let wakers = {
            let mut guard = self.lock();
            // Set under the lock, so a `register_waker` either sees the flag or is in the list.
            self.inner.cancelled.store(true, Ordering::SeqCst);
            std::mem::take(&mut *guard)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// Whether [`CancelToken::cancel`] has been called on this token or any clone.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Asks to be woken when the token is cancelled. A token already cancelled wakes `waker` at
    /// once. Registering a waker that wakes the same task as one already held keeps one entry.
    pub fn register_waker(&self, waker: &Waker) {
        let mut guard = self.lock();
        if self.inner.cancelled.load(Ordering::SeqCst) {
            drop(guard);
            waker.wake_by_ref();
            return;
        }
        if let Some(held) = guard.iter_mut().find(|w| w.will_wake(waker)) {
            // Keep the newest waker for the task: an executor may hand out a fresh one per poll.
            held.clone_from(waker);
        } else {
            guard.push(waker.clone());
        }
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        CancelToken::new()
    }
}

impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

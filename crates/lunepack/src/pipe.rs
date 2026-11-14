//! Bounded pipes between a worker thread and the polling task (M4-D2, M4-D3).
//!
//! Two directions over one shared queue:
//!
//! - [`to_async`]: a worker produces with a blocking [`BlockingSender`], the task consumes with an
//!   async [`AsyncReceiver`] (response bodies);
//! - [`from_async`]: the task produces with an async [`AsyncSender`], a worker consumes with a
//!   blocking [`BlockingReceiver`] (cache writes).
//!
//! Each pipe is tied to a [`CancelToken`]. The blocking side never waits forever: it waits on a
//! condition variable for at most [`BLOCKING_RECHECK`] at a time and re-checks the token and the
//! other side, and returns `Err(Closed)` as soon as the async side is dropped or the token is
//! cancelled. The async side is woken on every push, pop, close and cancel.
//!
//! A sending side ends the stream cleanly with `finish`; the receiver then gets every queued item
//! and `Ok(None)`. A sender dropped without `finish` is an abort, and the receiver gets
//! `Err(Closed)` once the queue is empty, so a half-written stream never looks complete.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use lunepack_core::CancelToken;

/// The default capacity of a pipe, in items.
pub const DEFAULT_CAPACITY: usize = 8;

/// The longest a blocking side waits before re-checking the token and the other side.
pub const BLOCKING_RECHECK: Duration = Duration::from_millis(50);

/// The other side is gone, or the pipe's token was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("pipe closed")]
pub struct Closed;

struct State<T> {
    queue: VecDeque<T>,
    capacity: usize,
    sender_alive: bool,
    receiver_alive: bool,
    /// The sender called `finish`.
    finished: bool,
    /// The waker of the async side's task.
    waker: Option<Waker>,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    /// Signalled for the blocking side: an item or space became available, or the async side left.
    cond: Condvar,
    cancel: CancelToken,
}

impl<T> Shared<T> {
    fn new(capacity: usize, cancel: CancelToken) -> Arc<Self> {
        Arc::new(Shared {
            state: Mutex::new(State {
                queue: VecDeque::with_capacity(capacity.max(1)),
                capacity: capacity.max(1),
                sender_alive: true,
                receiver_alive: true,
                finished: false,
                waker: None,
            }),
            cond: Condvar::new(),
            cancel,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // Every update under the lock is a single push, pop or flag store.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the async side's task (outside the lock).
    fn async_waker(state: &State<T>) -> Option<Waker> {
        state.waker.clone()
    }

    /// Stores the async side's waker and registers it with the token, so a cancel wakes it.
    fn park_async(&self, state: &mut State<T>, cx: &Context<'_>) {
        match &mut state.waker {
            Some(held) => held.clone_from(cx.waker()),
            None => state.waker = Some(cx.waker().clone()),
        }
        self.cancel.register_waker(cx.waker());
    }

    fn wait<'a>(&'a self, guard: MutexGuard<'a, State<T>>) -> MutexGuard<'a, State<T>> {
        self.cond
            .wait_timeout(guard, BLOCKING_RECHECK)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }

    /// Blocking push (for [`BlockingSender`]).
    fn push_blocking(&self, item: T) -> Result<(), Closed> {
        let mut state = self.lock();
        loop {
            if self.cancel.is_cancelled() || !state.receiver_alive {
                return Err(Closed);
            }
            if state.queue.len() < state.capacity {
                state.queue.push_back(item);
                let waker = Self::async_waker(&state);
                drop(state);
                if let Some(waker) = waker {
                    waker.wake();
                }
                return Ok(());
            }
            state = self.wait(state);
        }
    }

    /// Blocking pop (for [`BlockingReceiver`]).
    fn pop_blocking(&self) -> Result<Option<T>, Closed> {
        let mut state = self.lock();
        loop {
            if self.cancel.is_cancelled() {
                return Err(Closed);
            }
            if let Some(item) = state.queue.pop_front() {
                let waker = Self::async_waker(&state);
                drop(state);
                if let Some(waker) = waker {
                    waker.wake();
                }
                return Ok(Some(item));
            }
            if state.finished {
                return Ok(None);
            }
            if !state.sender_alive {
                return Err(Closed);
            }
            state = self.wait(state);
        }
    }

    /// Async pop (for [`AsyncReceiver`]).
    fn poll_pop(&self, cx: &Context<'_>) -> Poll<Result<Option<T>, Closed>> {
        let mut state = self.lock();
        if self.cancel.is_cancelled() {
            return Poll::Ready(Err(Closed));
        }
        if let Some(item) = state.queue.pop_front() {
            drop(state);
            self.cond.notify_all();
            return Poll::Ready(Ok(Some(item)));
        }
        if state.finished {
            return Poll::Ready(Ok(None));
        }
        if !state.sender_alive {
            return Poll::Ready(Err(Closed));
        }
        self.park_async(&mut state, cx);
        Poll::Pending
    }

    /// Async push (for [`AsyncSender`]); gives the item back while the queue is full.
    fn poll_push(&self, item: T, cx: &Context<'_>) -> Result<Result<(), T>, Closed> {
        let mut state = self.lock();
        if self.cancel.is_cancelled() || !state.receiver_alive {
            return Err(Closed);
        }
        if state.queue.len() < state.capacity {
            state.queue.push_back(item);
            drop(state);
            self.cond.notify_all();
            return Ok(Ok(()));
        }
        self.park_async(&mut state, cx);
        Ok(Err(item))
    }

    fn finish(&self) {
        self.close_sender(true);
    }

    fn close_sender(&self, finished: bool) {
        let waker = {
            let mut state = self.lock();
            state.finished |= finished;
            state.sender_alive = false;
            Self::async_waker(&state)
        };
        self.cond.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close_receiver(&self) {
        let waker = {
            let mut state = self.lock();
            state.receiver_alive = false;
            // Nobody will read them; drop queued items now rather than with the last handle.
            state.queue.clear();
            Self::async_waker(&state)
        };
        self.cond.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A pipe from a worker (blocking send) to the polling task (async receive), holding at most
/// `capacity` items (at least 1). Cancelling `cancel` closes both sides.
pub fn to_async<T: Send>(
    capacity: usize,
    cancel: CancelToken,
) -> (BlockingSender<T>, AsyncReceiver<T>) {
    let shared = Shared::new(capacity, cancel);
    (
        BlockingSender {
            shared: Arc::clone(&shared),
            done: false,
        },
        AsyncReceiver { shared },
    )
}

/// A pipe from the polling task (async send) to a worker (blocking receive), holding at most
/// `capacity` items (at least 1). Cancelling `cancel` closes both sides.
pub fn from_async<T: Send>(
    capacity: usize,
    cancel: CancelToken,
) -> (AsyncSender<T>, BlockingReceiver<T>) {
    let shared = Shared::new(capacity, cancel);
    (
        AsyncSender {
            shared: Arc::clone(&shared),
            done: false,
        },
        BlockingReceiver { shared },
    )
}

/// The worker's sending side of a [`to_async`] pipe.
pub struct BlockingSender<T> {
    shared: Arc<Shared<T>>,
    done: bool,
}

impl<T> BlockingSender<T> {
    /// Queues `item`, blocking while the pipe is full. `Err(Closed)` when the receiver is gone or
    /// the token is cancelled, within [`BLOCKING_RECHECK`] of either.
    pub fn send(&self, item: T) -> Result<(), Closed> {
        self.shared.push_blocking(item)
    }

    /// Ends the stream cleanly: the receiver gets the queued items and then `Ok(None)`.
    pub fn finish(mut self) {
        self.done = true;
        self.shared.finish();
    }
}

impl<T> Drop for BlockingSender<T> {
    fn drop(&mut self) {
        if !self.done {
            self.shared.close_sender(false);
        }
    }
}

impl<T> fmt::Debug for BlockingSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingSender").finish_non_exhaustive()
    }
}

/// The task's receiving side of a [`to_async`] pipe.
pub struct AsyncReceiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T> AsyncReceiver<T> {
    /// The next item; `Ok(None)` after a clean finish and an empty queue; `Err(Closed)` when the
    /// token is cancelled or the sender was dropped without finishing.
    pub fn recv(&self) -> RecvFuture<T> {
        RecvFuture {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Polls for the next item (the poll form of [`AsyncReceiver::recv`]).
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<T>, Closed>> {
        self.shared.poll_pop(cx)
    }
}

impl<T> Drop for AsyncReceiver<T> {
    fn drop(&mut self) {
        self.shared.close_receiver();
    }
}

impl<T> fmt::Debug for AsyncReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncReceiver").finish_non_exhaustive()
    }
}

/// The future of [`AsyncReceiver::recv`]. `Send + 'static` when `T: Send`.
#[must_use = "futures do nothing unless polled"]
pub struct RecvFuture<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Future for RecvFuture<T> {
    type Output = Result<Option<T>, Closed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.shared.poll_pop(cx)
    }
}

impl<T> fmt::Debug for RecvFuture<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvFuture").finish_non_exhaustive()
    }
}

/// The task's sending side of a [`from_async`] pipe.
pub struct AsyncSender<T> {
    shared: Arc<Shared<T>>,
    done: bool,
}

impl<T> AsyncSender<T> {
    /// Queues `item`, waiting while the pipe is full. `Err(Closed)` when the receiver is gone or
    /// the token is cancelled.
    pub fn send(&self, item: T) -> SendFuture<T> {
        SendFuture {
            shared: Arc::clone(&self.shared),
            item: Some(item),
        }
    }

    /// Ends the stream cleanly: the receiver gets the queued items and then `Ok(None)`.
    pub fn finish(mut self) {
        self.done = true;
        self.shared.finish();
    }
}

impl<T> Drop for AsyncSender<T> {
    fn drop(&mut self) {
        if !self.done {
            self.shared.close_sender(false);
        }
    }
}

impl<T> fmt::Debug for AsyncSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncSender").finish_non_exhaustive()
    }
}

/// The future of [`AsyncSender::send`]. `Send + 'static` when `T: Send + 'static`.
#[must_use = "futures do nothing unless polled"]
pub struct SendFuture<T> {
    shared: Arc<Shared<T>>,
    item: Option<T>,
}

// The future holds the item by value and never pins it.
impl<T> Unpin for SendFuture<T> {}

impl<T> Future for SendFuture<T> {
    type Output = Result<(), Closed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(item) = self.item.take() else {
            return Poll::Ready(Ok(()));
        };
        match self.shared.poll_push(item, cx) {
            Err(Closed) => Poll::Ready(Err(Closed)),
            Ok(Ok(())) => Poll::Ready(Ok(())),
            Ok(Err(item)) => {
                self.item = Some(item);
                Poll::Pending
            }
        }
    }
}

impl<T> fmt::Debug for SendFuture<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendFuture").finish_non_exhaustive()
    }
}

/// The worker's receiving side of a [`from_async`] pipe.
pub struct BlockingReceiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T> BlockingReceiver<T> {
    /// The next item, blocking while the pipe is empty. `Ok(None)` after a clean finish and an
    /// empty queue; `Err(Closed)` when the token is cancelled or the sender was dropped without
    /// finishing, within [`BLOCKING_RECHECK`] of either.
    pub fn recv(&self) -> Result<Option<T>, Closed> {
        self.shared.pop_blocking()
    }
}

impl<T> Drop for BlockingReceiver<T> {
    fn drop(&mut self) {
        self.shared.close_receiver();
    }
}

impl<T> fmt::Debug for BlockingReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingReceiver").finish_non_exhaustive()
    }
}

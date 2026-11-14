//! The built-in executor (M4-D3): [`block_on`] runs one future to completion on the current thread,
//! for callers with no async runtime (`lunepack::blocking`).

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

/// Wakes a parked thread. The flag makes a wake that lands before the park count, and makes a
/// spurious unpark (which `park` allows) not count, so the future is polled only after a wake.
struct ThreadWaker {
    thread: Thread,
    woken: AtomicBool,
}

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.woken.swap(true, Ordering::SeqCst) {
            self.thread.unpark();
        }
    }
}

/// Runs `future` to completion on the current thread. Between polls the thread parks until the
/// future's waker is woken: there is no busy loop and no timer.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let state = Arc::new(ThreadWaker {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&state));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        while !state.woken.swap(false, Ordering::SeqCst) {
            thread::park();
        }
    }
}

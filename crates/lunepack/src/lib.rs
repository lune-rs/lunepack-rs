//! Facade crate: the public Rust API that applications depend on, and the root that wires the
//! default adapters.

use std::time::{SystemTime, UNIX_EPOCH};

use lunepack_core::Clock;

mod executor;
mod pipe;
mod progress;
mod task;
mod worker_transport;

pub use executor::block_on;
pub use pipe::{
    AsyncReceiver, AsyncSender, BLOCKING_RECHECK, BlockingReceiver, BlockingSender, Closed,
    DEFAULT_CAPACITY, RecvFuture, SendFuture, from_async, to_async,
};
pub use progress::{ProgressPump, ProgressSink, progress};
#[doc(hidden)]
pub use task::live_workers;
pub use task::{JobFuture, OpLock, WORKER_THREAD_NAME, spawn_job};
pub use worker_transport::{CHUNK_SIZE, WorkerTransport};

/// Errors of the facade.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The operation was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// A lunepack worker thread panicked (or could not be started); the panic message is not
    /// shown.
    #[error("a lunepack worker thread panicked")]
    WorkerPanicked,
}

/// The wall clock: seconds since the Unix epoch from the operating system (M3-D5).
///
/// A system time before the epoch reads as 0. Core never reaches for the time itself (hard rule 3);
/// it takes a [`Clock`], and this is the one the shipped binaries and embedding apps give it.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

//! Facade crate: the public Rust API that applications depend on, and the root that wires the
//! default adapters.

use std::time::{SystemTime, UNIX_EPOCH};

use lunepack_core::Clock;

mod cache;
mod executor;
mod fetch;
mod pipe;
mod progress;
mod task;
mod worker_transport;

pub use cache::{Cache, CacheKind};
pub use executor::block_on;
pub use fetch::{
    ABSENT_ROOT_STATUSES, FeedUrls, FetchCtx, FetchOutcome, Fetched, FrameNeed, PackTarget,
    acquire_op_lock, download, fetch_artifact_doc, fetch_document, fetch_pack, fetch_root_doc,
    fetch_run,
};
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
    /// Another operation holds the updater lock.
    #[error("another lunepack operation is running")]
    Busy,
    /// A download ended early (a dropped connection, a short body); the part is kept and the next
    /// call resumes it.
    #[error("download incomplete; it resumes on the next call")]
    Incomplete,
    /// Bytes or documents failed verification or a format rule (the core's error).
    #[error("{0}")]
    Verify(#[from] lunepack_core::Error),
    /// A transport failed to produce a response or a body chunk.
    #[error("{0}")]
    Transport(#[from] lunepack_core::TransportError),
    /// A filesystem operation failed.
    #[error("{0}")]
    Fs(#[from] lunepack_core::FsError),
    /// The configuration is unusable (for example a feed URL with an unsupported scheme).
    #[error("configuration: {0}")]
    Config(&'static str),
}

impl From<lunepack_core::RangeError> for Error {
    fn from(e: lunepack_core::RangeError) -> Self {
        Error::Verify(lunepack_core::Error::Range(e))
    }
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

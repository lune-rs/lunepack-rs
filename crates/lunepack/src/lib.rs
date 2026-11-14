//! Facade crate: the public Rust API that applications depend on, and the root that wires the
//! default adapters.

use std::time::{SystemTime, UNIX_EPOCH};

use lunepack_core::Clock;

mod cache;
mod error;
mod executor;
mod fetch;
mod pipe;
mod progress;
mod task;
mod updater;
mod worker_transport;

pub mod blocking;

pub use cache::{Cache, CacheKind};
pub use error::Error;
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
pub use updater::{
    DownloadOptions, Downloaded, InstalledVersion, Layout, ProgressCallback, StagedVersion,
    Timeouts, UpdateInfo, Updater, UpdaterBuilder,
};
pub use worker_transport::{CHUNK_SIZE, WorkerTransport};

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

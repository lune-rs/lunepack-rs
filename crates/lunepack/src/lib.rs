//! Facade crate: the public Rust API that applications depend on, and the root that wires the
//! default adapters.
//!
//! An app checks for an update, downloads it resumably and stages a verified version tree with an
//! [`Updater`]. The futures it returns are `Send + 'static` and run on any async executor, or on
//! none through [`blocking`]: lunepack never spawns onto the caller's executor. File I/O, hashing,
//! decoding and the default HTTP transport run on lunepack's own worker threads.
//!
//! - **Cancel.** Dropping a future cancels it, and a [`CancelToken`] in [`DownloadOptions`]
//!   cancels from elsewhere. Partial downloads stay resumable, a half-built
//!   tree is resumed or discarded by the next call, and state changes only at a commit.
//! - **Progress.** The optional callback runs on the thread that polls the operation, never on a
//!   worker, and sees coalesced counters, so a slow callback does not stall a download.
//! - **Lock.** Every operation takes `<state dir>/lock`; another holder gives [`Error::Busy`]. The
//!   OS releases it when a holder dies.
//! - **Locations.** A [`Layout`] names the state, cache and versions directories; per-OS discovery
//!   comes later. The app compiles its trusted root key in ([`trusted_root`]).
//! - **One dependency.** Every type the API takes or returns is re-exported here (the ones the
//!   adapter traits need included), so an app depends on `lunepack` alone.
//!
//! The examples below build the updater the same way (`# ` lines are hidden). Each is compiled but
//! not run, because it would reach the network.
//!
//! # With tokio
//!
//! ```no_run
//! # use lunepack::{AppId, Channel, DownloadOptions, Layout, TrustedRoot, Updater, UpdaterBuilder};
//! # fn root_of_the_app() -> TrustedRoot { unimplemented!("`lunepack::trusted_root` with the app's keys") }
//! # fn build() -> Result<Updater, lunepack::Error> {
//! let layout = Layout::User {
//!     state_dir: "/home/me/.local/share/org.example.app/state".into(),
//!     cache_dir: "/home/me/.cache/org.example.app".into(),
//!     versions_dir: "/home/me/.local/share/org.example.app/versions".into(),
//!     current_tree: None,
//! };
//! UpdaterBuilder::new(
//!     AppId::parse("org.example.app").expect("app id"),
//!     root_of_the_app(),
//!     "https://updates.example.org/app/feed-stable.json",
//!     Channel::parse("stable").expect("channel"),
//!     layout,
//! )
//! .build()
//! # }
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), lunepack::Error> {
//!     let updater = build()?;
//!     if let Some(info) = updater.check().await? {
//!         let options = DownloadOptions {
//!             progress: Some(Box::new(|p| println!("{:?}: {} of {}", p.phase, p.done, p.total))),
//!             cancel: None,
//!         };
//!         let downloaded = updater.download(&info, options).await?;
//!         let staged = updater.stage(downloaded).await?;
//!         println!("staged {} in {}", staged.version(), staged.tree().display());
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # With smol
//!
//! ```no_run
//! # use lunepack::{DownloadOptions, Updater};
//! # fn build() -> Result<Updater, lunepack::Error> { unimplemented!("as in the tokio example") }
//! fn main() -> Result<(), lunepack::Error> {
//!     smol::block_on(async {
//!         let updater = build()?;
//!         if let Some(info) = updater.check().await? {
//!             let downloaded = updater.download(&info, DownloadOptions::default()).await?;
//!             updater.stage(downloaded).await?;
//!         }
//!         Ok(())
//!     })
//! }
//! ```
//!
//! # Without an async runtime
//!
//! [`blocking::Updater`] runs the same operations as plain calls on the calling thread; a
//! [`CancelToken`] is the only way to cancel. Never call it from inside
//! an async task.
//!
//! ```no_run
//! # use lunepack::{CancelToken, DownloadOptions, Updater};
//! # fn build() -> Result<Updater, lunepack::Error> { unimplemented!("as in the tokio example") }
//! fn main() -> Result<(), lunepack::Error> {
//!     let updater = lunepack::blocking::Updater::from(build()?);
//!     let cancel = CancelToken::new();
//!     if let Some(info) = updater.check(&cancel)? {
//!         let downloaded = updater.download(&info, DownloadOptions::default(), &cancel)?;
//!         updater.stage(downloaded, &cancel)?;
//!     }
//!     Ok(())
//! }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

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

pub use error::Error;
pub use executor::block_on;
pub use updater::{
    DownloadOptions, Downloaded, InstalledVersion, Layout, ProgressCallback, StagedVersion,
    Timeouts, UpdateInfo, Updater, UpdaterBuilder,
};
pub use worker_transport::WorkerTransport;

// The types the public API takes or returns, so an app needs no `lunepack-core` dependency of its
// own (and cannot end up with two versions of these types). The adapter traits are here for apps
// that replace a default adapter.
/// The core's error, the cause inside [`Error::Verify`].
pub use lunepack_core::Error as CoreError;
pub use lunepack_core::fetch::FetchPolicy;
pub use lunepack_core::{
    AppId, BlockingResponse, BlockingTransport, Body, BoxFuture, ByteRange, CancelToken, Channel,
    Clock, Codec, DirEntryInfo, FileKind, FileProgress, FileWrite, Fs, FsError, FsErrorKind,
    Hasher, Head, LockGuard, Meta, Phase, Progress, RangeError, ReadAt, RelPath, Request, Response,
    Sha256Digest, Source, StateError, Target, Transport, TransportError, TransportErrorKind,
    TrustedRoot, Validator, Verifier, Version,
};

/// Plumbing that tests and sibling crates use; not part of the supported API and free to change in
/// any release.
#[doc(hidden)]
pub mod unstable_internals {
    pub use crate::cache::{Cache, CacheKind};
    pub use crate::fetch::{
        ABSENT_ROOT_STATUSES, FeedUrls, FetchCtx, FetchOutcome, Fetched, FrameNeed, PackTarget,
        acquire_op_lock, download, fetch_artifact_doc, fetch_document, fetch_pack, fetch_root_doc,
        fetch_run,
    };
    pub use crate::pipe::{
        AsyncReceiver, AsyncSender, BLOCKING_RECHECK, BlockingReceiver, BlockingSender, Closed,
        DEFAULT_CAPACITY, RecvFuture, SendFuture, from_async, to_async,
    };
    pub use crate::progress::{ProgressPump, ProgressSink, progress};
    pub use crate::task::{JobFuture, OpLock, WORKER_THREAD_NAME, live_workers, spawn_job};
    pub use crate::worker_transport::CHUNK_SIZE;
}

/// The root of trust an app compiles in: its app id, root version, threshold and Ed25519 public
/// keys (FORMAT.md 5.1), checked like a root document, with the default crypto.
///
/// Fails with [`Error::Verify`] when the version is out of range, the threshold does not fit the
/// key count, a key is listed twice or a key is invalid.
pub fn trusted_root(
    app_id: AppId,
    version: u64,
    threshold: u64,
    public_keys: &[[u8; 32]],
) -> Result<TrustedRoot, Error> {
    Ok(TrustedRoot::from_parts(
        app_id,
        version,
        threshold,
        public_keys,
        &lunepack_crypto::Sha256Hasher,
        &lunepack_crypto::Ed25519Verifier,
    )?)
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

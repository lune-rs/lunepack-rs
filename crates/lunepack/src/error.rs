//! The facade's error type (C9).
//!
//! No variant's `Display` holds a URL query, a full user path or key bytes: core errors name only
//! file names and origins, and the facade adds fixed text.

use lunepack_core::{FsError, RangeError, RelPath, StateError, TransportError};

/// Every way an [`Updater`](crate::Updater) operation fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// There is no committed install state (a development run, or before the first install).
    #[error("not installed: no install state")]
    NotInstalled,
    /// Another operation holds the updater lock.
    #[error("another lunepack operation is running")]
    Busy,
    /// The operation was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// The update is no longer applicable: the installed version is at or above it, or it was
    /// marked bad since the check.
    #[error("the update is stale")]
    Stale,
    /// Staging a per-machine install is the privileged engine's job (C8).
    #[error("staging is not available for a per-machine install")]
    MachineScope,
    /// The install state was written by a newer build; nothing is written (M4-D22 c).
    #[error("the install state is from a newer lunepack")]
    StateTooNew,
    /// Bytes or documents failed verification or a format rule (the core's error).
    #[error("{0}")]
    Verify(#[from] lunepack_core::Error),
    /// A transport failed to produce a response or a body chunk.
    #[error("{0}")]
    Transport(#[from] TransportError),
    /// A filesystem operation failed.
    #[error("{0}")]
    Fs(#[from] FsError),
    /// The install-state store failed.
    #[error("install state: {0}")]
    State(StateError),
    /// A download ended early (a dropped connection, a short body); the part is kept and the next
    /// call resumes it.
    #[error("download incomplete; it resumes on the next call")]
    Incomplete,
    /// These files could not be placed after a Range retry and a full-pack try (D27 ladder).
    #[error("{} files could not be staged", .0.len())]
    NeedFetchExhausted(Vec<RelPath>),
    /// A lunepack worker thread panicked (or could not be started); the panic message is not
    /// shown.
    #[error("a lunepack worker thread panicked")]
    WorkerPanicked,
    /// The configuration is unusable (for example a feed URL with an unsupported scheme).
    #[error("configuration: {0}")]
    Config(&'static str),
}

impl From<RangeError> for Error {
    fn from(e: RangeError) -> Self {
        Error::Verify(lunepack_core::Error::Range(e))
    }
}

impl From<StateError> for Error {
    fn from(e: StateError) -> Self {
        match e {
            StateError::NewerFormat => Error::StateTooNew,
            other => Error::State(other),
        }
    }
}

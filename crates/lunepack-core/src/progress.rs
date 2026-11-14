//! Progress event types (M4-D19), shared by the client (C9), the apply engine (C4) and the runtime
//! (C10). The JSON form of an event is M5's; this module only fixes the Rust shape.

use crate::path::RelPath;

/// The phase of an update operation an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// Fetching and verifying the signed documents.
    Check,
    /// Finding files of the current tree that the new version keeps unchanged.
    Scan,
    /// Fetching pack bytes into the cache.
    Download,
    /// Building and verifying the new version tree.
    Stage,
}

/// Where the bytes of one file come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// Copied from the current tree, hash-checked against the manifest.
    Unchanged,
    /// A single frame fetched with an HTTP Range request.
    Range,
    /// Taken from the full pack.
    FullPack,
    /// Reserved: a delta patch against the current file (not produced in v1).
    Patch,
}

/// Progress of one file inside a phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProgress {
    /// The file's path in the release tree.
    pub path: RelPath,
    /// Bytes done for this file.
    pub done: u64,
    /// Bytes this file needs.
    pub total: u64,
    /// Where its bytes come from.
    pub source: Source,
}

/// One progress event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// The phase.
    pub phase: Phase,
    /// Bytes done in the phase.
    pub done: u64,
    /// Bytes the phase needs in all.
    pub total: u64,
    /// The file being worked on, when the phase works file by file.
    pub file: Option<FileProgress>,
}

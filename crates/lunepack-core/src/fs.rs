//! The filesystem behind a trait (hard rule 3): everything the install-state store, the stage
//! engine and the cache read or write goes through [`Fs`], so tests can run on an in-memory fake
//! that models durability and crashes (`lunepack_testkit::MemFs`), and an adapter (`lunepack-fs`)
//! can add the care each OS needs.
//!
//! Every method takes an absolute path. The core never builds a path from untrusted text except
//! through [`crate::RelPath`] joined onto a trusted base. An [`FsError`] names only the file name
//! of the path, never the directories above it (they can hold a user name).
//!
//! Durability: bytes written to a [`FileWrite`] are volatile until [`FileWrite::sync`]; a directory
//! entry created, removed or renamed is volatile until [`Fs::sync_dir`] on its parent. Callers that
//! need a change to survive a crash sync the file, then its directory.

use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use crate::error::Untrusted;

/// What went wrong, in terms a caller can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsErrorKind {
    /// The path (or a parent directory of it) does not exist.
    NotFound,
    /// The path exists (a dangling symlink counts).
    AlreadyExists,
    /// A file is over the size the caller allowed.
    TooLarge,
    /// A component that must be a directory is not one.
    NotADirectory,
    /// A symlink where the operation refuses one.
    IsSymlink,
    /// A lock is held elsewhere.
    Locked,
    /// The (simulated) process crashed; nothing more can be done through this handle.
    Crashed,
    /// Anything else; the cause is in [`FsError::source`].
    Other,
}

impl FsErrorKind {
    /// A fixed description.
    pub const fn describe(self) -> &'static str {
        match self {
            FsErrorKind::NotFound => "not found",
            FsErrorKind::AlreadyExists => "already exists",
            FsErrorKind::TooLarge => "too large",
            FsErrorKind::NotADirectory => "not a directory",
            FsErrorKind::IsSymlink => "is a symlink",
            FsErrorKind::Locked => "locked",
            FsErrorKind::Crashed => "crashed",
            FsErrorKind::Other => "I/O failed",
        }
    }
}

/// A filesystem operation failed. `Display` and `Debug` show the kind and the path's file name
/// only.
pub struct FsError {
    /// The failure class.
    pub kind: FsErrorKind,
    /// The underlying error, kept as the cause (hard rule 4).
    pub source: Option<io::Error>,
    name: String,
}

impl FsError {
    /// An error of `kind` for `path`; only the file name of `path` is kept.
    pub fn new(kind: FsErrorKind, path: &Path, source: Option<io::Error>) -> Self {
        let name = path
            .file_name()
            .map(|n| Untrusted::new(&n.to_string_lossy()).to_string())
            .unwrap_or_default();
        FsError { kind, source, name }
    }

    /// Classifies an `io::Error` by its kind (`NotFound`, `AlreadyExists`; anything else is
    /// [`FsErrorKind::Other`]) and keeps it as the cause.
    ///
    /// An `io::Error` that wraps an [`FsError`] (what a [`FileWrite`] returns after a crash) comes
    /// back as that `FsError`.
    pub fn from_io(path: &Path, err: io::Error) -> Self {
        if err.get_ref().is_some_and(|inner| inner.is::<FsError>()) {
            match err.into_inner().map(|inner| inner.downcast::<FsError>()) {
                Some(Ok(fs_error)) => return *fs_error,
                _ => return FsError::new(FsErrorKind::Other, path, None),
            }
        }
        let kind = match err.kind() {
            io::ErrorKind::NotFound => FsErrorKind::NotFound,
            io::ErrorKind::AlreadyExists => FsErrorKind::AlreadyExists,
            io::ErrorKind::NotADirectory => FsErrorKind::NotADirectory,
            _ => FsErrorKind::Other,
        };
        FsError::new(kind, path, Some(err))
    }

    /// The file name the error is about (escaped, possibly empty).
    pub fn file_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name.is_empty() {
            write!(f, "filesystem: {}", self.kind.describe())
        } else {
            write!(f, "filesystem: {}: {}", self.kind.describe(), self.name)
        }
    }
}

impl fmt::Debug for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The cause is shown by kind only: an OS error message can name a full path.
        f.debug_struct("FsError")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("source_kind", &self.source.as_ref().map(io::Error::kind))
            .finish()
    }
}

impl StdError for FsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| e as &(dyn StdError + 'static))
    }
}

/// What a directory entry or path is. A symlink is never followed when this is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
    /// Anything else (a device, a socket, ...).
    Other,
}

/// `symlink_metadata`: what a path is and how long (0 for a directory, the target's length for a
/// symlink).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// The kind, symlinks not followed.
    pub kind: FileKind,
    /// The length in bytes.
    pub len: u64,
}

/// One entry of [`Fs::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    /// The entry's name (never a path).
    pub name: OsString,
    /// Its kind, symlinks not followed.
    pub kind: FileKind,
}

/// Positional reads of one open file; `Send + Sync` so decoder threads can share one handle.
pub trait ReadAt: Send + Sync {
    /// The file's length now.
    fn size(&self) -> Result<u64, FsError>;

    /// Fills `buf` from `offset`; a read past the end is an error (kind `Other`, cause
    /// `UnexpectedEof`).
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError>;
}

/// An open file that is written at its end. Written bytes are volatile until [`FileWrite::sync`].
/// A `write` or `flush` that fails because the (simulated) process crashed returns an
/// `io::Error` whose source is an [`FsError`] of kind [`FsErrorKind::Crashed`].
pub trait FileWrite: Write + Send {
    /// Makes everything written so far durable (`fsync`).
    fn sync(&mut self) -> Result<(), FsError>;
}

/// A held advisory lock; released when the guard is dropped (or the process dies).
pub trait LockGuard: Send {}

/// The filesystem operations the core's callers need. Object-safe and `Send + Sync`.
pub trait Fs: Send + Sync {
    /// Reads the whole file at `path` (following a final symlink), failing with
    /// [`FsErrorKind::TooLarge`] when it is longer than `max` bytes, without reading more than
    /// `max + 1`.
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError>;

    /// Opens the file at `path` for positional reads.
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError>;

    /// Creates the file at `path`, which must not exist: fails with
    /// [`FsErrorKind::AlreadyExists`] on any existing path, a dangling symlink included. The new
    /// entry is volatile until [`Fs::sync_dir`] on the parent.
    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError>;

    /// Opens the existing file at `path` for appending (also the way to `sync` a file that was
    /// written by [`Fs::copy_file`]).
    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError>;

    /// Sets the length of the file at `path` (zero-filling when it grows).
    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError>;

    /// Renames `from` to `to`, within one directory or one tree; `to` must not exist (callers
    /// ensure it, an adapter fails with `AlreadyExists` where it can). A symlink at `from` is
    /// moved itself. Not used for state commits (D22). Volatile until [`Fs::sync_dir`] of the
    /// parent(s).
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError>;

    /// Removes the file or symlink at `path` (a final symlink is removed, not followed). A
    /// directory is an error.
    fn remove_file(&self, path: &Path) -> Result<(), FsError>;

    /// Removes the directory tree at `path` without ever following a symlink: a symlink inside
    /// the tree is removed itself, and a symlink at `path` is removed itself. A regular file at
    /// `path` is [`FsErrorKind::NotADirectory`].
    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError>;

    /// Creates `path` and its missing parents. Fails if an existing component is a symlink
    /// ([`FsErrorKind::IsSymlink`]) or not a directory ([`FsErrorKind::NotADirectory`]). Succeeds
    /// when `path` is already a directory.
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError>;

    /// The entries of the directory at `path`, in no particular order.
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError>;

    /// What `path` is, without following a final symlink; `None` when it does not exist.
    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError>;

    /// Makes the directory entries of the directory at `path` durable (`fsync` of the directory).
    fn sync_dir(&self, path: &Path) -> Result<(), FsError>;

    /// Copies the file `from` to `to_new`, which must not exist ([`FsErrorKind::AlreadyExists`]);
    /// may clone. The copy keeps the executable bit and is not synced.
    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError>;

    /// Sets or clears the executable permission of the file at `path`. A no-op where the OS has no
    /// such bit.
    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError>;

    /// Creates a symlink at `link_path` holding the text `target`; `link_path` must not exist.
    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError>;

    /// Takes the exclusive advisory lock on the file at `path`, creating it when the adapter needs
    /// one. `Ok(None)` means another holder has it; the lock is released when the guard drops.
    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError>;
}

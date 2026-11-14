//! Filesystem adapter implementing the core filesystem trait ([`lunepack_core::Fs`]) over `std`,
//! plus the OS advisory lock through `fs4` (M4-D15). No `unsafe` code: every call is a safe std or
//! `fs4` API.
//!
//! Care taken beyond plain `std`:
//!
//! - `create_new` never follows a symlink at the final component (`O_CREAT | O_EXCL | O_NOFOLLOW`
//!   on Unix), so a planted dangling link is `AlreadyExists`, not a write through it;
//! - `create_dir_all` refuses a path whose existing component is a symlink or a non-directory, so a
//!   link planted below a trusted directory cannot redirect later writes. Callers pass canonical
//!   base directories (a layout under a symlinked ancestor such as macOS `/var` must be
//!   canonicalised first);
//! - `remove_dir_all_nofollow` removes a symlink itself and never reaches through one;
//! - `copy_file` never overwrites;
//! - errors name only the file name of the path (`lunepack_core::FsError`).
//!
//! Durability: [`Fs::sync_dir`] is `fsync` on the directory on Unix. On Windows it calls
//! `FlushFileBuffers` on a directory handle (opened with `FILE_FLAG_BACKUP_SEMANTICS` and write
//! access); if the OS or the file system refuses that (`ERROR_ACCESS_DENIED` or
//! `ERROR_INVALID_FUNCTION`) the call returns `Ok`. That a Windows directory flush makes a new
//! entry durable is an assumption this crate has not verified: if it is wrong, a commit may be lost
//! on power loss, never corrupted (the install-state store only ever adds whole files).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use lunepack_core::{
    DirEntryInfo, FileKind, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta, ReadAt,
};

/// `FILE_FLAG_BACKUP_SEMANTICS`: needed to open a directory handle on Windows.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `ERROR_ACCESS_DENIED` and `ERROR_INVALID_FUNCTION`.
#[cfg(windows)]
const WINDOWS_DIR_FLUSH_REFUSED: [i32; 2] = [5, 1];

/// The filesystem of the host, through `std`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdFs;

impl StdFs {
    /// A new handle (it holds no state).
    pub fn new() -> StdFs {
        StdFs
    }
}

fn err(path: &Path) -> impl Fn(io::Error) -> FsError + '_ {
    move |e| FsError::from_io(path, e)
}

fn kind_of(ft: fs::FileType) -> FileKind {
    if ft.is_symlink() {
        FileKind::Symlink
    } else if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    }
}

fn lstat(path: &Path) -> Result<Option<fs::Metadata>, FsError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(FsError::from_io(path, e)),
    }
}

fn other(path: &Path, what: &'static str) -> FsError {
    FsError::new(FsErrorKind::Other, path, Some(io::Error::other(what)))
}

struct StdReader {
    file: File,
    path: PathBuf,
}

impl ReadAt for StdReader {
    fn size(&self) -> Result<u64, FsError> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(err(&self.path))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        read_exact_at(&self.file, offset, buf).map_err(err(&self.path))
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

struct StdWriter {
    file: File,
    path: PathBuf,
}

impl Write for StdWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl FileWrite for StdWriter {
    fn sync(&mut self) -> Result<(), FsError> {
        self.file.sync_all().map_err(err(&self.path))
    }
}

/// An exclusive lock on a file; held while the file is open, so dropping the guard (or the
/// process dying) releases it.
struct StdLock {
    _file: File,
}

impl LockGuard for StdLock {}

impl Fs for StdFs {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        let file = File::open(path).map_err(err(path))?;
        let mut bytes = Vec::new();
        file.take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(err(path))?;
        if bytes.len() as u64 > max {
            return Err(FsError::new(FsErrorKind::TooLarge, path, None));
        }
        Ok(bytes)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        let file = File::open(path).map_err(err(path))?;
        Ok(Box::new(StdReader {
            file,
            path: path.to_owned(),
        }))
    }

    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(err(path))?;
        Ok(Box::new(StdWriter {
            file,
            path: path.to_owned(),
        }))
    }

    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(err(path))?;
        Ok(Box::new(StdWriter {
            file,
            path: path.to_owned(),
        }))
    }

    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(err(path))?;
        file.set_len(len).map_err(err(path))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        if lstat(to)?.is_some() {
            return Err(FsError::new(FsErrorKind::AlreadyExists, to, None));
        }
        fs::rename(from, to).map_err(err(from))
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        let Some(meta) = lstat(path)? else {
            return Err(FsError::new(FsErrorKind::NotFound, path, None));
        };
        if meta.is_dir() {
            return Err(other(path, "is a directory"));
        }
        remove_link_or_file(path, &meta)
    }

    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        let Some(meta) = lstat(path)? else {
            return Err(FsError::new(FsErrorKind::NotFound, path, None));
        };
        if meta.file_type().is_symlink() {
            return remove_link_or_file(path, &meta);
        }
        if !meta.is_dir() {
            return Err(FsError::new(FsErrorKind::NotADirectory, path, None));
        }
        // std's `remove_dir_all` does not follow symlinks inside the tree: it unlinks them.
        fs::remove_dir_all(path).map_err(err(path))
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component);
            match lstat(&current)? {
                Some(meta) if meta.file_type().is_symlink() => {
                    return Err(FsError::new(FsErrorKind::IsSymlink, path, None));
                }
                Some(meta) if meta.is_dir() => {}
                Some(_) => return Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
                None => match fs::create_dir(&current) {
                    Ok(()) => {}
                    // Lost a race with another creator: it must be a real directory now.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match lstat(&current)? {
                        Some(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                        _ => return Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
                    },
                    Err(e) => return Err(FsError::from_io(path, e)),
                },
            }
        }
        Ok(())
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(path).map_err(err(path))? {
            let entry = entry.map_err(err(path))?;
            let kind = entry.file_type().map_err(err(path))?;
            out.push(DirEntryInfo {
                name: entry.file_name(),
                kind: kind_of(kind),
            });
        }
        Ok(out)
    }

    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        Ok(lstat(path)?.map(|m| Meta {
            kind: kind_of(m.file_type()),
            len: m.len(),
        }))
    }

    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        sync_dir(path)
    }

    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
        // The destination is a fresh path in a tree this operation owns (under the OS lock), so the
        // gap between this check and the copy is not a race anyone else can win.
        if lstat(to_new)?.is_some() {
            return Err(FsError::new(FsErrorKind::AlreadyExists, to_new, None));
        }
        fs::copy(from, to_new).map(drop).map_err(err(from))
    }

    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
        let meta = fs::metadata(path).map_err(err(path))?;
        set_exec(path, &meta, exec)
    }

    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        symlink(target, link_path).map_err(err(link_path))
    }

    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(err(path))?;
        // By trait path: `std::fs::File` has inherent `try_lock` and `unlock` since Rust 1.89, which
        // would shadow the trait methods. Only `try_lock` is used; the lock ends with the file.
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Some(Box::new(StdLock { _file: file }))),
            Err(fs4::TryLockError::WouldBlock) => Ok(None),
            Err(fs4::TryLockError::Error(e)) => Err(FsError::from_io(path, e)),
        }
    }
}

fn remove_link_or_file(path: &Path, meta: &fs::Metadata) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        // A symlink to a directory is removed with `remove_dir` on Windows.
        use std::os::windows::fs::FileTypeExt;
        if meta.file_type().is_symlink_dir() {
            return fs::remove_dir(path).map_err(err(path));
        }
    }
    let _ = meta;
    fs::remove_file(path).map_err(err(path))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), FsError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(err(path))
}

#[cfg(windows)]
fn sync_dir(path: &Path) -> Result<(), FsError> {
    use std::os::windows::fs::OpenOptionsExt;
    let result = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|dir| dir.sync_all());
    match result {
        Ok(()) => Ok(()),
        // Unverified assumption (module docs): where the OS refuses a directory flush, the commit
        // is not known to be durable, but it is never corrupted.
        Err(e)
            if e.raw_os_error()
                .is_some_and(|c| WINDOWS_DIR_FLUSH_REFUSED.contains(&c)) =>
        {
            Ok(())
        }
        Err(e) => Err(FsError::from_io(path, e)),
    }
}

#[cfg(unix)]
fn set_exec(path: &Path, meta: &fs::Metadata, exec: bool) -> Result<(), FsError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    let new = if exec {
        // x wherever r is set.
        mode | ((mode & 0o444) >> 2)
    } else {
        mode & !0o111
    };
    if new == mode {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(new)).map_err(err(path))
}

#[cfg(windows)]
fn set_exec(_path: &Path, _meta: &fs::Metadata, _exec: bool) -> Result<(), FsError> {
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

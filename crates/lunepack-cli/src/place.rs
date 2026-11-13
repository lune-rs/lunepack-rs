//! Placing a finished document (M3-D9): written to a temporary file in the destination directory,
//! flushed, then moved into place, so a reader sees the old file or the whole new one and never a
//! partial one. Temporary names start with [`TMP_PREFIX`] and are removed on every error path.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};

/// Prefix of every temporary file this module creates.
pub const TMP_PREFIX: &str = ".lunepack-tmp-";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary file that is removed unless it was moved into place.
struct Temp {
    path: PathBuf,
    keep: bool,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.keep {
            // Best effort: this process created the file, nothing else is removed.
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn write_temp(dest: &Path, bytes: &[u8]) -> Result<Temp> {
    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .context("the destination has no usable file name")?;
    // create_new on a unique name: never opens a file this call did not create.
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{TMP_PREFIX}{}-{n}-{name}", std::process::id()));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot create a file in {}", dir.display()));
            }
        };
        let temp = Temp { path, keep: false };
        let written = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        drop::<File>(file);
        written.with_context(|| format!("cannot write {}", dest.display()))?;
        return Ok(temp);
    }
    bail!(
        "cannot find a free temporary name next to {}",
        dest.display()
    );
}

/// Writes `bytes` to `path`, which must not exist (create_new semantics). The file appears whole
/// or not at all: the bytes go to a temporary file first, and a hard link (which fails if `path`
/// exists) puts them in place; where the file system has no hard links the fallback checks that
/// `path` is free and renames, which leaves a window in which a racing writer is overwritten.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = write_temp(path, bytes)?;
    match fs::hard_link(&temp.path, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            bail!("{} already exists", path.display())
        }
        Err(_) => {
            if fs::symlink_metadata(path).is_ok() {
                bail!("{} already exists", path.display());
            }
            let mut temp = temp;
            fs::rename(&temp.path, path)
                .with_context(|| format!("cannot place {}", path.display()))?;
            temp.keep = true;
            Ok(())
        }
    }
}

/// Writes `bytes` to `path`, replacing it if it exists: temporary file in the same directory, then
/// rename.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut temp = write_temp(path, bytes)?;
    fs::rename(&temp.path, path).with_context(|| format!("cannot place {}", path.display()))?;
    temp.keep = true;
    Ok(())
}

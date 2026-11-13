//! Opening a release directory (C2): the trust chain a writer starts from. The compiled-in root of
//! the config is walked forward through `root-<k>.json` files, and `keys.json` is verified under
//! the walked root.
//!
//! Callers that write pass a time-skipping reading (`ClockReading::read(clock, Some(u64::MAX))`,
//! M3-D9) so an expired key set can still be replaced; callers that only read pass the real one.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use lunepack_core::{
    ClockReading, Hasher, Limits, RollbackFloor, TrustedRoot, VerifiedKeySet, Verifier,
    advance_root, verify_key_set,
};

use crate::config::Config;

/// What a release directory's trust chain yields.
pub struct Opened {
    /// The root after the walk.
    pub root: TrustedRoot,
    /// The version of `root` (the `k` of the last `root-<k>.json`, or the config's version).
    pub root_doc_k: u64,
    /// The key set under `root`, when `keys.json` exists.
    pub keys: Option<VerifiedKeySet>,
}

/// The path of `root-<k>.json`.
pub fn root_path(dir: &Path, k: u64) -> PathBuf {
    dir.join(format!("root-{k}.json"))
}

/// The path of `keys.json`.
pub fn keys_path(dir: &Path) -> PathBuf {
    dir.join("keys.json")
}

/// Reads a file of at most `cap` bytes; `None` if it does not exist.
pub fn read_capped(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
    // Classified before opening: Windows cannot open a directory, and a FIFO blocks on open.
    if let Ok(meta) = fs::metadata(path)
        && !meta.is_file()
    {
        bail!("{} is not a regular file", path.display());
    }
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() as u64 > cap {
        bail!("{} is over {cap} bytes", path.display());
    }
    Ok(Some(bytes))
}

/// Opens `dir`: builds the trusted root from `cfg`, walks `root-<k>.json` for `k = version + 1,
/// +2, ...` while the file exists (a gap ends the walk; a file that does not verify fails it), then
/// verifies `keys.json` when present, with the floors at zero.
pub fn open(
    dir: &Path,
    cfg: &Config,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
    reading: &ClockReading,
) -> Result<Opened> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let mut root = cfg.trusted_root(hasher, verifier)?;
    loop {
        let k = root.version() + 1;
        let path = root_path(dir, k);
        let Some(bytes) = read_capped(&path, Limits::V1.root_doc_bytes)? else {
            break;
        };
        root = advance_root(&root, &bytes, hasher, verifier)
            .with_context(|| format!("{} does not verify", path.display()))?;
    }
    let path = keys_path(dir);
    let keys = match read_capped(&path, Limits::V1.keys_doc_bytes)? {
        None => None,
        Some(bytes) => Some(
            verify_key_set(
                &root,
                &bytes,
                &RollbackFloor::default(),
                reading,
                hasher,
                verifier,
            )
            .with_context(|| format!("{} does not verify", path.display()))?,
        ),
    };
    let root_doc_k = root.version();
    Ok(Opened {
        root,
        root_doc_k,
        keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = read_capped(dir.path(), 10).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
        assert!(
            read_capped(&dir.path().join("absent"), 10)
                .unwrap()
                .is_none()
        );
    }
}

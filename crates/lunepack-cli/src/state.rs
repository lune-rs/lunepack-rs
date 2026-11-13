//! The publisher's state file (M3-R2-D1): what this publisher last signed, kept outside the release
//! directory so a writer can tell a replayed older copy of a document from the current one.
//!
//! The writers read the previous `keys.json`, `root-<k>.json` walk and feed from the release
//! directory with time checks skipped (M3-D9), so a genuine but older document there would verify
//! and its values would be re-signed fresh. The state file records, per app id, the root version,
//! the `keys.json` version and threshold, and each channel's feed `seq` last written or accepted.
//! A writer refuses a previous document older than the record unless `--allow-older-previous` is
//! given, and refuses one it has no record of unless `--trust-release-dir` is given.
//!
//! The file holds only these numbers, never a key or a config value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Args;
use lunepack_core::{AppId, VerifiedKeySet};
use serde::{Deserialize, Serialize};

use crate::place;
use crate::release_dir::read_capped;

/// The default state file name, in the config's directory.
pub const DEFAULT_STATE: &str = "lunepack-state.json";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const FORMAT: u64 = 1;

/// The state-check overrides every writer that builds on a previous document takes.
#[derive(Args, Clone, Copy, Debug, Default)]
pub struct StateArgs {
    /// Accept the release directory's current root, keys.json and feed as the baseline when the
    /// state file has no record of them (bootstrap or recovery). This trusts whatever the
    /// directory holds now: use it only on a copy from the publisher's own storage, never one
    /// fetched from the public host.
    #[arg(long = "trust-release-dir")]
    pub trust_release_dir: bool,
    /// Build on a previous document older than the state file records (recovery only). Each such
    /// document is named on stderr, and the new values are recorded.
    #[arg(long = "allow-older-previous")]
    pub allow_older_previous: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
    format: u64,
    #[serde(default)]
    apps: BTreeMap<String, Record>,
}

/// What one app's publisher last signed or accepted. A field that is absent has no record.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The version of the root the last walk ended at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_version: Option<u64>,
    /// The version of the last `keys.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys_version: Option<u64>,
    /// The threshold of the last `keys.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys_threshold: Option<u64>,
    /// The `seq` of each channel's last feed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub feeds: BTreeMap<String, u64>,
}

/// A loaded state file.
pub struct State {
    path: PathBuf,
    existed: bool,
    raw: RawState,
}

/// One previous document compared with the record.
pub struct Compared {
    /// The document, as named to the user (`keys.json`, `feed-stable.json`, ...).
    pub document: String,
    /// `version` or `seq`.
    pub field: &'static str,
    /// The recorded value, if any.
    pub recorded: Option<u64>,
    /// The value in the release directory; `None` when the document is absent.
    pub found: Option<u64>,
}

impl Record {
    /// Records the walked root and the key set `keys` (accepted or just written).
    pub fn set_keys(&mut self, root_version: u64, keys: &VerifiedKeySet) {
        self.root_version = Some(root_version);
        self.keys_version = Some(keys.version());
        self.keys_threshold = Some(keys.threshold() as u64);
    }

    /// The root walk, compared with the record. The config's own root does not come from the
    /// release directory, so when nothing is recorded a walk that read no root file is not
    /// compared.
    pub fn root_compared(&self, walked: u64, config_root: u64) -> Compared {
        let found = if self.root_version.is_none() && walked == config_root {
            None
        } else {
            Some(walked)
        };
        Compared {
            document: "the root (the root-<k>.json walk)".to_owned(),
            field: "version",
            recorded: self.root_version,
            found,
        }
    }

    /// `keys.json`, compared with the record.
    pub fn keys_compared(&self, keys: Option<&VerifiedKeySet>) -> Compared {
        Compared {
            document: "keys.json".to_owned(),
            field: "version",
            recorded: self.keys_version,
            found: keys.map(VerifiedKeySet::version),
        }
    }
}

impl State {
    /// Reads the state file at `path`; a missing file is an empty state.
    pub fn load(path: &Path) -> Result<State> {
        let Some(bytes) = read_capped(path, MAX_STATE_BYTES)? else {
            return Ok(State {
                path: path.to_owned(),
                existed: false,
                raw: RawState {
                    format: FORMAT,
                    apps: BTreeMap::new(),
                },
            });
        };
        // The error names the line only; the file holds numbers, but nothing is echoed.
        let raw: RawState = serde_json::from_slice(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "{}: line {}: not a valid lunepack state file",
                path.display(),
                e.line()
            )
        })?;
        if raw.format != FORMAT {
            bail!(
                "{}: state file format {} is not supported (expected {FORMAT})",
                path.display(),
                raw.format
            );
        }
        Ok(State {
            path: path.to_owned(),
            existed: true,
            raw,
        })
    }

    /// The record of `app` (empty when there is none).
    pub fn record(&self, app: &AppId) -> Record {
        self.raw.apps.get(app.as_str()).cloned().unwrap_or_default()
    }

    /// Sets the record of `app` and writes the file (temporary file, then rename).
    pub fn save(&mut self, app: &AppId, record: Record) -> Result<()> {
        self.raw.apps.insert(app.as_str().to_owned(), record);
        let mut text = serde_json::to_vec_pretty(&self.raw)?;
        text.push(b'\n');
        place::replace(&self.path, &text).map_err(|e| {
            anyhow::anyhow!("the documents were placed, but the state file was not updated: {e:#}")
        })?;
        self.existed = true;
        Ok(())
    }

    /// `init`: creates the state file with an empty record of `app` when it does not exist; an
    /// existing file is checked and left as it is. Returns whether it was created.
    pub fn create_for_init(path: &Path, app: &AppId) -> Result<bool> {
        let state = State::load(path)?;
        if state.existed {
            return Ok(false);
        }
        let mut raw = state.raw;
        raw.apps.insert(app.as_str().to_owned(), Record::default());
        let mut text = serde_json::to_vec_pretty(&raw)?;
        text.push(b'\n');
        place::write_new(path, &text)?;
        Ok(true)
    }

    /// Compares each previous document with the record. A document older than the record is
    /// refused unless `--allow-older-previous`; one with no record is refused unless
    /// `--trust-release-dir`; an absent document is not compared. Returns `true` when every
    /// document matched (equal or newer) without an override.
    pub fn check(&self, docs: &[Compared], over: StateArgs) -> Result<bool> {
        let mut refused = Vec::new();
        let mut clean = true;
        for d in docs {
            let Some(found) = d.found else { continue };
            match d.recorded {
                None if over.trust_release_dir => {
                    eprintln!(
                        "warning: {} has no record of {} ({} {found}); trusting the release directory (--trust-release-dir)",
                        self.path.display(),
                        d.document,
                        d.field
                    );
                    clean = false;
                }
                None => refused.push(format!(
                    "{}: {} {found} in the release directory, and no record of it in the state file",
                    d.document, d.field
                )),
                Some(recorded) if found < recorded => {
                    if over.allow_older_previous {
                        eprintln!(
                            "warning: {} {} {found} is older than the recorded {recorded}; building on it anyway (--allow-older-previous)",
                            d.document, d.field
                        );
                        clean = false;
                    } else {
                        refused.push(format!(
                            "{}: {} {found} in the release directory is older than the recorded {recorded}; the release directory may hold a replayed older copy",
                            d.document, d.field
                        ));
                    }
                }
                Some(_) => {}
            }
        }
        if refused.is_empty() {
            return Ok(clean);
        }
        let lines: String = refused.iter().map(|l| format!("\n  {l}")).collect();
        let about = if self.existed {
            format!(
                "the state file {} records what this publisher last signed",
                self.path.display()
            )
        } else {
            format!(
                "the state file {} does not exist; it records what this publisher last signed and belongs next to the config, kept in the publisher's own storage",
                self.path.display()
            )
        };
        bail!(
            "the release directory does not match the state file (nothing was written):{lines}\n\
             {about}. Restore the release directory (or the state file) from the publisher's own storage; \
             pass --trust-release-dir to accept documents the state file has no record of, or \
             --allow-older-previous to build on an older one"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compared(recorded: Option<u64>, found: Option<u64>) -> Compared {
        Compared {
            document: "keys.json".to_owned(),
            field: "version",
            recorded,
            found,
        }
    }

    fn state() -> State {
        State {
            path: PathBuf::from("s.json"),
            existed: true,
            raw: RawState {
                format: FORMAT,
                apps: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn check_rules() {
        let none = StateArgs::default();
        let s = state();
        assert!(s.check(&[compared(Some(3), Some(3))], none).unwrap());
        assert!(s.check(&[compared(Some(3), Some(4))], none).unwrap());
        assert!(s.check(&[compared(Some(3), None)], none).unwrap());
        assert!(s.check(&[compared(None, None)], none).unwrap());
        let e = s.check(&[compared(Some(3), Some(2))], none).unwrap_err();
        assert!(format!("{e:#}").contains("replayed older copy"), "{e:#}");
        assert!(s.check(&[compared(None, Some(2))], none).is_err());

        let trust = StateArgs {
            trust_release_dir: true,
            ..StateArgs::default()
        };
        assert!(!s.check(&[compared(None, Some(2))], trust).unwrap());
        assert!(s.check(&[compared(Some(3), Some(2))], trust).is_err());

        let older = StateArgs {
            allow_older_previous: true,
            ..StateArgs::default()
        };
        assert!(!s.check(&[compared(Some(3), Some(2))], older).unwrap());
        assert!(s.check(&[compared(None, Some(2))], older).is_err());
    }

    #[test]
    fn round_trip_and_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEFAULT_STATE);
        let app = AppId::parse("example.app").unwrap();
        assert!(State::create_for_init(&path, &app).unwrap());
        assert!(!State::create_for_init(&path, &app).unwrap());
        let mut s = State::load(&path).unwrap();
        assert!(s.existed);
        assert_eq!(s.record(&app), Record::default());
        let mut r = Record {
            keys_version: Some(2),
            keys_threshold: Some(1),
            root_version: Some(1),
            ..Record::default()
        };
        r.feeds.insert("stable".to_owned(), 7);
        s.save(&app, r.clone()).unwrap();
        assert_eq!(State::load(&path).unwrap().record(&app), r);

        std::fs::write(&path, b"{\"format\":1,\"apps\":{},\"x\":1}").unwrap();
        let e = State::load(&path).err().unwrap();
        assert!(format!("{e:#}").contains("line 1"), "{e:#}");
        std::fs::write(&path, b"{\"format\":2}").unwrap();
        assert!(State::load(&path).is_err());
    }
}

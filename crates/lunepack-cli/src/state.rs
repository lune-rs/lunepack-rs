//! The publisher's state file (M3-R2-D1): what this publisher last signed, kept outside the release
//! directory so a writer can tell a replayed older copy of a document from the current one.
//!
//! The writers read the previous `keys.json`, `root-<k>.json` walk and feed from the release
//! directory with time checks skipped (M3-D9), so a genuine but older document there would verify
//! and its values would be re-signed fresh. The state file records, per app id, the root version,
//! the `keys.json` version and threshold, and each channel's feed `seq` last written or accepted.
//! A writer refuses a previous document older than the record, or a recorded `keys.json` or root
//! that is missing, unless `--allow-older-previous` is given, and refuses one it has no record of
//! unless `--trust-release-dir` is given. No update lowers a recorded value without
//! `--allow-older-previous` either.
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
    /// Build on a previous document older than the state file records, or without a recorded
    /// keys.json that is missing (recovery only). Each such document is named on stderr, and the
    /// new values are recorded, even when lower.
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
    /// Whether the document may be absent although the state file records it: only a feed, whose
    /// channel `feed add` may start again (M3-R1-D1) with a `seq` above the recorded one. A recorded
    /// root or `keys.json` that is absent is refused like an older one.
    pub may_be_absent: bool,
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
            may_be_absent: false,
        }
    }

    /// `keys.json`, compared with the record.
    pub fn keys_compared(&self, keys: Option<&VerifiedKeySet>) -> Compared {
        Compared {
            document: "keys.json".to_owned(),
            field: "version",
            recorded: self.keys_version,
            found: keys.map(VerifiedKeySet::version),
            may_be_absent: false,
        }
    }

    /// Every value `next` would lower against `self`, one description each. A recorded value that
    /// `next` drops counts as lowered, and so does a changed threshold without a newer key set.
    pub fn lowered_by(&self, next: &Record) -> Vec<String> {
        fn version(what: &str, old: Option<u64>, new: Option<u64>, out: &mut Vec<String>) {
            match (old, new) {
                (Some(o), Some(n)) if n < o => out.push(format!("{what} {o} -> {n}")),
                (Some(o), None) => out.push(format!("{what} {o} -> none")),
                _ => {}
            }
        }
        let mut out = Vec::new();
        version(
            "root version",
            self.root_version,
            next.root_version,
            &mut out,
        );
        version(
            "keys.json version",
            self.keys_version,
            next.keys_version,
            &mut out,
        );
        let newer_keys = matches!(
            (self.keys_version, next.keys_version),
            (Some(o), Some(n)) if n > o
        ) || (self.keys_version.is_none() && next.keys_version.is_some());
        match (self.keys_threshold, next.keys_threshold) {
            (Some(o), Some(n)) if n != o && !newer_keys => out.push(format!(
                "keys.json threshold {o} -> {n} without a newer keys.json"
            )),
            (Some(o), None) => out.push(format!("keys.json threshold {o} -> none")),
            _ => {}
        }
        for (channel, &o) in &self.feeds {
            version(
                &format!("feed-{channel}.json seq"),
                Some(o),
                next.feeds.get(channel).copied(),
                &mut out,
            );
        }
        out
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

    /// Refuses an update of `app`'s record to `next` that would lower a recorded value (see
    /// [`Record::lowered_by`]), unless `--allow-older-previous`, under which each lowered value is
    /// named on stderr. Writers call it before they place anything.
    pub fn guard_update(&self, app: &AppId, next: &Record, over: StateArgs) -> Result<()> {
        let lowered = self.record(app).lowered_by(next);
        if lowered.is_empty() {
            return Ok(());
        }
        if over.allow_older_previous {
            for l in &lowered {
                eprintln!(
                    "warning: the state file's record is lowered: {l} (--allow-older-previous); clients that already accepted the higher value reject the lower one"
                );
            }
            return Ok(());
        }
        bail!(
            "this would lower what {} records ({}), which only --allow-older-previous may do (nothing was written)",
            self.path.display(),
            lowered.join("; ")
        )
    }

    /// Sets the record of `app` and writes the file (temporary file, then rename). A record that
    /// would lower a recorded value is refused unless `--allow-older-previous` (the writers check
    /// this with [`State::guard_update`] before placing; this is the backstop).
    pub fn save(&mut self, app: &AppId, record: Record, over: StateArgs) -> Result<()> {
        let lowered = self.record(app).lowered_by(&record);
        if !lowered.is_empty() && !over.allow_older_previous {
            bail!(
                "the documents were placed, but the state file was not updated: it would lower what it records ({})",
                lowered.join("; ")
            );
        }
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

    /// Compares each previous document with the record. A document older than the record, or a
    /// recorded one that is absent (unless it [may be](Compared::may_be_absent)), is refused unless
    /// `--allow-older-previous`; one with no record is refused unless `--trust-release-dir`; an
    /// absent document with no record is not compared. Returns `true` when every document matched
    /// (equal or newer) without an override.
    pub fn check(&self, docs: &[Compared], over: StateArgs) -> Result<bool> {
        let mut refused = Vec::new();
        let mut clean = true;
        for d in docs {
            let Some(found) = d.found else {
                match d.recorded {
                    Some(recorded) if !d.may_be_absent => {
                        if over.allow_older_previous {
                            eprintln!(
                                "warning: {} is missing, but the state file records {} {recorded}; building without it (--allow-older-previous)",
                                d.document, d.field
                            );
                            clean = false;
                        } else {
                            refused.push(format!(
                                "{}: missing from the release directory, but the state file records {} {recorded}; the release directory may be incomplete or tampered with (if it was removed on purpose to start over, pass --allow-older-previous)",
                                d.document, d.field
                            ));
                        }
                    }
                    _ => {}
                }
                continue;
            };
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
             --allow-older-previous to build on an older one or without a missing one"
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
            may_be_absent: false,
        }
    }

    fn feed(recorded: Option<u64>, found: Option<u64>) -> Compared {
        Compared {
            document: "feed-stable.json".to_owned(),
            field: "seq",
            recorded,
            found,
            may_be_absent: true,
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
        assert!(s.check(&[compared(None, None)], none).unwrap());
        // A recorded keys.json or root that is missing is refused like an older one (F5, S2); a
        // feed may be absent (its channel restarts above the recorded seq).
        let e = s.check(&[compared(Some(3), None)], none).unwrap_err();
        let e = format!("{e:#}");
        assert!(
            e.contains("keys.json: missing from the release directory, but the state file records version 3"),
            "{e}"
        );
        assert!(s.check(&[feed(Some(3), None)], none).unwrap());
        assert!(s.check(&[feed(None, None)], none).unwrap());
        let e = s.check(&[compared(Some(3), Some(2))], none).unwrap_err();
        assert!(format!("{e:#}").contains("replayed older copy"), "{e:#}");
        assert!(s.check(&[compared(None, Some(2))], none).is_err());

        let trust = StateArgs {
            trust_release_dir: true,
            ..StateArgs::default()
        };
        assert!(!s.check(&[compared(None, Some(2))], trust).unwrap());
        assert!(s.check(&[compared(Some(3), Some(2))], trust).is_err());
        assert!(s.check(&[compared(Some(3), None)], trust).is_err());

        let older = StateArgs {
            allow_older_previous: true,
            ..StateArgs::default()
        };
        assert!(!s.check(&[compared(Some(3), Some(2))], older).unwrap());
        assert!(!s.check(&[compared(Some(3), None)], older).unwrap());
        assert!(s.check(&[compared(None, Some(2))], older).is_err());
    }

    fn rec(root: u64, keys: u64, threshold: u64, seq: Option<u64>) -> Record {
        let mut r = Record {
            root_version: Some(root),
            keys_version: Some(keys),
            keys_threshold: Some(threshold),
            ..Record::default()
        };
        if let Some(q) = seq {
            r.feeds.insert("stable".to_owned(), q);
        }
        r
    }

    #[test]
    fn lowering_rules() {
        let old = rec(2, 5, 2, Some(100));
        assert!(old.lowered_by(&old).is_empty());
        // Rising values, a new channel, and a threshold change with a newer key set are fine.
        let mut up = rec(3, 6, 1, Some(101));
        up.feeds.insert("beta".to_owned(), 1);
        assert!(old.lowered_by(&up).is_empty());
        assert!(Record::default().lowered_by(&old).is_empty());

        let cases = [
            (rec(1, 5, 2, Some(100)), "root version 2 -> 1"),
            (rec(2, 1, 2, Some(100)), "keys.json version 5 -> 1"),
            (
                rec(2, 5, 1, Some(100)),
                "keys.json threshold 2 -> 1 without a newer",
            ),
            (rec(2, 5, 2, Some(99)), "feed-stable.json seq 100 -> 99"),
            (rec(2, 5, 2, None), "feed-stable.json seq 100 -> none"),
            (Record::default(), "keys.json version 5 -> none"),
        ];
        for (next, want) in cases {
            let got = old.lowered_by(&next);
            assert!(got.iter().any(|l| l.contains(want)), "{want}: {got:?}");
        }
    }

    #[test]
    fn updates_never_lower_without_the_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEFAULT_STATE);
        let app = AppId::parse("example.app").unwrap();
        let mut s = State::load(&path).unwrap();
        let none = StateArgs::default();
        s.save(&app, rec(1, 3, 2, Some(100)), none).unwrap();
        let before = std::fs::read(&path).unwrap();

        let lower = rec(1, 1, 1, Some(100));
        let e = s.guard_update(&app, &lower, none).unwrap_err();
        assert!(
            format!("{e:#}").contains("keys.json version 3 -> 1"),
            "{e:#}"
        );
        assert!(s.save(&app, lower.clone(), none).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let trust = StateArgs {
            trust_release_dir: true,
            ..StateArgs::default()
        };
        assert!(s.guard_update(&app, &lower, trust).is_err());
        assert!(s.save(&app, lower.clone(), trust).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let older = StateArgs {
            allow_older_previous: true,
            ..StateArgs::default()
        };
        s.guard_update(&app, &lower, older).unwrap();
        s.save(&app, lower.clone(), older).unwrap();
        assert_eq!(State::load(&path).unwrap().record(&app), lower);
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
        s.save(&app, r.clone(), StateArgs::default()).unwrap();
        assert_eq!(State::load(&path).unwrap().record(&app), r);

        std::fs::write(&path, b"{\"format\":1,\"apps\":{},\"x\":1}").unwrap();
        let e = State::load(&path).err().unwrap();
        assert!(format!("{e:#}").contains("line 1"), "{e:#}");
        std::fs::write(&path, b"{\"format\":2}").unwrap();
        assert!(State::load(&path).is_err());
    }
}

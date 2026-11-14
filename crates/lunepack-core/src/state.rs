//! The install-state store (FORMAT.md 12, M4-D5, M4-D6, M4-D22, M4-D23): what an install knows
//! about itself (its versions, the staged tree, the versions marked bad and the anti-rollback
//! floors), kept as numbered records that survive a crash at any write point.
//!
//! One file per record, `<dir>/<seq, 20 digits>.rec`, created with `create_new`, synced, then its
//! directory synced; a record file is never rewritten. A record is the frame
//! `"LPST" ‖ u8 format ‖ u32_be len ‖ payload ‖ SHA-256(all previous bytes)` around a strict-JSON
//! payload, at most [`MAX_RECORD_BYTES`] in all.
//!
//! [`load`] returns the newest record that was completely written, or fails; it never returns an
//! older record while a newer whole one exists (M4-D23). A file that fails an integrity check
//! (torn, flipped, renamed) is skipped; a whole record that the reader cannot accept stops the load.
//! [`commit`] writes the next record and then prunes old ones, keeping [`KEEP_RECORDS`].
//!
//! Callers hold the install's OS lock around a load and the commit that follows it; the store does
//! no locking of its own. Nothing here reads a clock: `issued` comes from the manifest.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::{Sha256Digest, U53};
use crate::encoding::{hex_decode_array, hex_encode};
use crate::error::{StateError, Untrusted};
use crate::fs::{FileKind, Fs, FsError, FsErrorKind};
use crate::ident::{AppId, Channel};
use crate::json::check_strict;
use crate::limits::{Limits, MAX_JSON_INT};
use crate::path::validate_path;
use crate::policy::INSTALL_ID_BYTES;
use crate::root::TrustedRoot;
use crate::target::Target;
use crate::traits::{Hasher, Verifier};
use crate::trust::{PublicKey, RollbackFloor};
use crate::version::Version;

/// The first bytes of every record file.
pub const RECORD_MAGIC: [u8; 4] = *b"LPST";
/// The frame and payload format this build reads and writes.
pub const RECORD_FORMAT: u8 = 1;
/// Largest record file, frame included.
pub const MAX_RECORD_BYTES: u64 = 1 << 20;
/// Valid records a commit keeps (the new one included).
pub const KEEP_RECORDS: usize = 3;
/// Most versions in `bad`.
pub const MAX_BAD_VERSIONS: usize = 1000;
/// Most channels in `floors.feed_seq`.
pub const MAX_CHANNELS: usize = 64;
/// The reserved top-level key owned by M5's health handshake (C4); kept in `extra`.
pub const HEALTH_KEY: &str = "health";

/// Magic, format byte, payload length.
const HEADER_LEN: usize = 4 + 1 + 4;
const DIGEST_LEN: usize = 32;
/// `<20 digits>.rec`.
const NAME_DIGITS: usize = 20;
const NAME_SUFFIX: &str = ".rec";

const KIND_STATE: &str = "install-state";
const KIND_COUNTERS: &str = "install-counters";

/// Top-level keys every record kind has.
const COMMON_KEYS: [&str; 5] = ["format", "kind", "critical", "seq", "app_id"];
const STATE_KEYS: [&str; 9] = [
    "scope",
    "install_id",
    "target",
    "current",
    "previous",
    "pending",
    "staged",
    "bad",
    "floors",
];
const COUNTERS_KEYS: [&str; 2] = ["install_id", "floors"];

// ---- record contents ------------------------------------------------------------------------------

/// Which install a record describes (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// A per-user install; its state is the user's.
    User,
    /// A per-machine install; its state is read-only for the library.
    Machine,
}

/// The highest verified root, kept as its parts so the rotation walk can start from it
/// (FORMAT.md 5.2, M4-D6).
///
/// Ordered by `version` first, then `threshold`, then the keys' bytes, so the higher root of two
/// always wins a [`Floors::max`] and the maximum does not depend on the order of its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootParts {
    /// The root version, `1 ..= 2^53 - 1`.
    #[serde(deserialize_with = "de_u53")]
    pub version: u64,
    /// The threshold, `1 ..= keys`.
    #[serde(deserialize_with = "de_u53")]
    pub threshold: u64,
    /// The Ed25519 public keys, 1 to 16, none twice.
    pub keys: Vec<PublicKey>,
}

impl RootParts {
    /// The parts of a trusted root.
    pub fn from_trusted(root: &TrustedRoot) -> RootParts {
        RootParts {
            version: root.version(),
            threshold: root.threshold() as u64,
            keys: root.keys().keys().iter().map(|k| *k.public()).collect(),
        }
    }

    /// Rebuilds the trusted root, with every check of [`TrustedRoot::from_parts`].
    pub fn to_trusted(
        &self,
        app_id: AppId,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> crate::Result<TrustedRoot> {
        let keys: Vec<[u8; 32]> = self.keys.iter().map(|k| *k.as_bytes()).collect();
        TrustedRoot::from_parts(
            app_id,
            self.version,
            self.threshold,
            &keys,
            hasher,
            verifier,
        )
    }

    fn check(&self) -> Result<(), StateError> {
        let count = self.keys.len() as u64;
        if self.version == 0 {
            return Err(invalid("root version 0"));
        }
        if self.threshold == 0 || self.threshold > count || self.keys.len() > Limits::V1.root_keys {
            return Err(invalid("root threshold or key count out of range"));
        }
        for (i, key) in self.keys.iter().enumerate() {
            if self.keys[..i].contains(key) {
                return Err(invalid("root key listed twice"));
            }
        }
        Ok(())
    }
}

impl PartialOrd for RootParts {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RootParts {
    fn cmp(&self, other: &Self) -> Ordering {
        self.version
            .cmp(&other.version)
            .then(self.threshold.cmp(&other.threshold))
            .then_with(|| {
                let a = self.keys.iter().map(PublicKey::as_bytes);
                let b = other.keys.iter().map(PublicKey::as_bytes);
                a.cmp(b)
            })
    }
}

/// The anti-rollback floors (FORMAT.md 11.2) as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floors {
    /// The highest verified root; `None` before the first check.
    #[serde(deserialize_with = "nullable")]
    pub root: Option<RootParts>,
    /// The highest verified key-set version (`0`: none).
    #[serde(deserialize_with = "de_u53")]
    pub keyset_version: u64,
    /// The highest verified feed `seq` per channel; at most [`MAX_CHANNELS`].
    #[serde(deserialize_with = "de_u53_map")]
    pub feed_seq: BTreeMap<Channel, u64>,
}

impl Floors {
    /// Field-wise maximum: the higher root (by [`RootParts`]' order, so a lower root version never
    /// replaces a higher one), the higher key-set version, and per channel the higher `seq`.
    /// Commutative, associative and idempotent.
    pub fn max(&self, other: &Floors) -> Floors {
        let root = match (&self.root, &other.root) {
            (Some(a), Some(b)) => Some(if b > a { b.clone() } else { a.clone() }),
            (a, b) => a.clone().or_else(|| b.clone()),
        };
        let mut feed_seq = self.feed_seq.clone();
        for (channel, &seq) in &other.feed_seq {
            let slot = feed_seq.entry(channel.clone()).or_insert(seq);
            *slot = (*slot).max(seq);
        }
        Floors {
            root,
            keyset_version: self.keyset_version.max(other.keyset_version),
            feed_seq,
        }
    }

    /// Whether every floor here is at or above the same floor of `other`.
    pub fn is_at_least(&self, other: &Floors) -> bool {
        self.root >= other.root
            && self.keyset_version >= other.keyset_version
            && other
                .feed_seq
                .iter()
                .all(|(c, &seq)| self.feed_seq.get(c).is_some_and(|&mine| mine >= seq))
    }

    /// The floors in the form the verify chain takes.
    pub fn to_rollback_floor(&self) -> RollbackFloor {
        let root = self.root.as_ref().map_or(0, |r| r.version);
        self.feed_seq.iter().fold(
            RollbackFloor::new(root, self.keyset_version),
            |f, (c, &s)| f.with_feed_seq(c.clone(), s),
        )
    }

    fn check(&self) -> Result<(), StateError> {
        if let Some(root) = &self.root {
            root.check()?;
        }
        if self.feed_seq.len() > MAX_CHANNELS {
            return Err(invalid("too many channels in feed_seq"));
        }
        Ok(())
    }
}

/// The installed version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRef {
    /// Its version.
    pub version: Version,
    /// Its manifest's `issued` (the implausible-clock floor time, FORMAT.md 11.3).
    #[serde(deserialize_with = "de_u53")]
    pub issued: u64,
}

/// The version installed before the current one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousRef {
    /// Its version.
    pub version: Version,
}

/// A version waiting for its health check (written from M5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRef {
    /// Its version.
    pub version: Version,
    /// Start attempts so far.
    #[serde(deserialize_with = "de_u53")]
    pub attempts: u64,
}

/// A staged version tree (M4-D18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedRef {
    /// The staged version.
    pub version: Version,
    /// The manifest's target.
    pub target: Target,
    /// SHA-256 of the manifest the tree was built from.
    pub manifest_sha256: Sha256Digest,
    /// The tree's directory name under the versions directory: one path component equal to the
    /// version text.
    pub tree: String,
}

impl StagedRef {
    /// A staged tree named after its version.
    pub fn new(version: Version, target: Target, manifest_sha256: Sha256Digest) -> StagedRef {
        let tree = version.to_string();
        StagedRef {
            version,
            target,
            manifest_sha256,
            tree,
        }
    }

    fn check(&self) -> Result<(), StateError> {
        let one_component = !self.tree.contains('/') && validate_path(&self.tree).is_ok();
        if !one_component || self.tree != self.version.to_string() {
            return Err(invalid("staged tree is not the version's directory name"));
        }
        Ok(())
    }
}

/// An `install-state` record: the state of one install (M4-D6).
#[derive(Debug, Clone, PartialEq)]
pub struct InstallState {
    /// The record's sequence number (its file name).
    pub seq: u64,
    /// The app id.
    pub app_id: AppId,
    /// Per-user or per-machine.
    pub scope: Scope,
    /// The install id (FORMAT.md 11.5).
    pub install_id: [u8; INSTALL_ID_BYTES],
    /// The host's target the install uses.
    pub target: Target,
    /// The installed version; `None` before the first install completes.
    pub current: Option<CurrentRef>,
    /// The version before it.
    pub previous: Option<PreviousRef>,
    /// A version waiting for its health check (M5).
    pub pending: Option<PendingRef>,
    /// The staged tree.
    pub staged: Option<StagedRef>,
    /// Versions marked bad, sorted by precedence, none twice, at most [`MAX_BAD_VERSIONS`].
    pub bad: Vec<Version>,
    /// The anti-rollback floors.
    pub floors: Floors,
    /// Critical features the record uses (v1: none).
    pub critical: Vec<String>,
    /// Top-level keys this build does not define, kept verbatim (M4-D22 a); `health` included.
    pub extra: BTreeMap<String, Value>,
}

/// An `install-counters` record: the user-scope floors of a per-machine install (C3), kept in
/// `<user dir>/<install id hex>/`.
#[derive(Debug, Clone, PartialEq)]
pub struct InstallCounters {
    /// The record's sequence number.
    pub seq: u64,
    /// The app id.
    pub app_id: AppId,
    /// The machine install's id.
    pub install_id: [u8; INSTALL_ID_BYTES],
    /// The floors this user has verified.
    pub floors: Floors,
    /// Critical features the record uses (v1: none).
    pub critical: Vec<String>,
    /// Top-level keys this build does not define, kept verbatim.
    pub extra: BTreeMap<String, Value>,
}

impl InstallState {
    /// A first record: nothing installed yet, no floors, `health: null`.
    pub fn new(
        seq: u64,
        app_id: AppId,
        scope: Scope,
        install_id: [u8; INSTALL_ID_BYTES],
        target: Target,
    ) -> InstallState {
        InstallState {
            seq,
            app_id,
            scope,
            install_id,
            target,
            current: None,
            previous: None,
            pending: None,
            staged: None,
            bad: Vec::new(),
            floors: Floors::default(),
            critical: Vec::new(),
            extra: BTreeMap::from([(HEALTH_KEY.to_owned(), Value::Null)]),
        }
    }

    /// The same record numbered `seq`. Test hook for building raw payloads: [`commit`] numbers the
    /// record itself.
    #[doc(hidden)]
    pub fn with_seq(mut self, seq: u64) -> InstallState {
        self.seq = seq;
        self
    }

    /// A copy for a transition. Its `seq` is the loaded record's and means nothing until a commit:
    /// [`commit`] gives the written record the store's next seq.
    fn next(&self) -> InstallState {
        self.clone()
    }

    /// The next record with every floor raised to at least `floors` (never lowered).
    pub fn raise_floors(&self, floors: &Floors) -> InstallState {
        let mut out = self.next();
        out.floors = self.floors.max(floors);
        out
    }

    /// The next record with `staged` replaced.
    pub fn set_staged(&self, staged: Option<StagedRef>) -> InstallState {
        let mut out = self.next();
        out.staged = staged;
        out
    }

    /// The next record with `version` in `bad` (kept sorted, never twice).
    pub fn mark_bad(&self, version: Version) -> InstallState {
        let mut out = self.next();
        if let Err(at) = out.bad.binary_search(&version) {
            out.bad.insert(at, version);
        }
        out
    }

    /// The next record after installing `current`: the old current becomes `previous`, and the
    /// target and install id are set. Floors, `bad`, `pending` and `staged` are kept (a staged tree
    /// that is not newer than `current` is ignored by its readers, M4-D18).
    pub fn install(
        &self,
        current: Version,
        issued: u64,
        target: Target,
        install_id: [u8; INSTALL_ID_BYTES],
    ) -> InstallState {
        let mut out = self.next();
        if let Some(old) = &self.current {
            out.previous = Some(PreviousRef {
                version: old.version.clone(),
            });
        }
        out.current = Some(CurrentRef {
            version: current,
            issued,
        });
        out.target = target;
        out.install_id = install_id;
        out
    }
}

impl InstallCounters {
    /// A first record: no floors.
    pub fn new(seq: u64, app_id: AppId, install_id: [u8; INSTALL_ID_BYTES]) -> InstallCounters {
        InstallCounters {
            seq,
            app_id,
            install_id,
            floors: Floors::default(),
            critical: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// The same record numbered `seq`. Test hook: [`commit`] numbers the record itself.
    #[doc(hidden)]
    pub fn with_seq(mut self, seq: u64) -> InstallCounters {
        self.seq = seq;
        self
    }

    /// The next record with every floor raised to at least `floors`.
    pub fn raise_floors(&self, floors: &Floors) -> InstallCounters {
        let mut out = self.clone();
        out.floors = self.floors.max(floors);
        out
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::InstallState {}
    impl Sealed for super::InstallCounters {}
}

/// A record kind of the store: [`InstallState`] or [`InstallCounters`].
pub trait Record: Clone + sealed::Sealed {
    /// The payload's `kind`.
    const KIND: &'static str;

    /// The sequence number.
    fn seq(&self) -> u64;

    #[doc(hidden)]
    fn numbered(&self, seq: u64) -> Self;

    /// The app id.
    fn app_id(&self) -> &AppId;

    /// The floors.
    fn floors(&self) -> &Floors;

    #[doc(hidden)]
    fn to_fields(&self) -> Result<BTreeMap<String, Value>, StateError>;

    #[doc(hidden)]
    fn from_fields(
        seq: u64,
        app_id: AppId,
        critical: Vec<String>,
        fields: Fields,
    ) -> Result<Self, StateError>;
}

impl Record for InstallState {
    const KIND: &'static str = KIND_STATE;

    fn seq(&self) -> u64 {
        self.seq
    }

    fn numbered(&self, seq: u64) -> Self {
        self.clone().with_seq(seq)
    }

    fn app_id(&self) -> &AppId {
        &self.app_id
    }

    fn floors(&self) -> &Floors {
        &self.floors
    }

    fn to_fields(&self) -> Result<BTreeMap<String, Value>, StateError> {
        let mut out = start_fields(
            KIND_STATE,
            self.seq,
            &self.app_id,
            &self.critical,
            &self.extra,
            &STATE_KEYS,
        )?;
        put(&mut out, "scope", &self.scope)?;
        put(&mut out, "install_id", &hex_encode(&self.install_id))?;
        put(&mut out, "target", &self.target)?;
        put(&mut out, "current", &self.current)?;
        put(&mut out, "previous", &self.previous)?;
        put(&mut out, "pending", &self.pending)?;
        put(&mut out, "staged", &self.staged)?;
        put(&mut out, "bad", &self.bad)?;
        put(&mut out, "floors", &self.floors)?;
        Ok(out)
    }

    fn from_fields(
        seq: u64,
        app_id: AppId,
        critical: Vec<String>,
        mut fields: Fields,
    ) -> Result<Self, StateError> {
        let record = InstallState {
            seq,
            app_id,
            scope: fields.take("scope")?,
            install_id: fields.install_id()?,
            target: fields.take("target")?,
            current: fields.take("current")?,
            previous: fields.take("previous")?,
            pending: fields.take("pending")?,
            staged: fields.take("staged")?,
            bad: fields.take("bad")?,
            floors: fields.take("floors")?,
            critical,
            extra: fields.rest(),
        };
        record.check()?;
        Ok(record)
    }
}

impl InstallState {
    fn check(&self) -> Result<(), StateError> {
        if self.bad.len() > MAX_BAD_VERSIONS {
            return Err(invalid("too many bad versions"));
        }
        if self.bad.windows(2).any(|w| w[0] >= w[1]) {
            return Err(invalid("bad versions not sorted and unique"));
        }
        if let Some(staged) = &self.staged {
            staged.check()?;
        }
        check_health(&self.extra)?;
        self.floors.check()
    }
}

impl Record for InstallCounters {
    const KIND: &'static str = KIND_COUNTERS;

    fn seq(&self) -> u64 {
        self.seq
    }

    fn numbered(&self, seq: u64) -> Self {
        self.clone().with_seq(seq)
    }

    fn app_id(&self) -> &AppId {
        &self.app_id
    }

    fn floors(&self) -> &Floors {
        &self.floors
    }

    fn to_fields(&self) -> Result<BTreeMap<String, Value>, StateError> {
        let mut out = start_fields(
            KIND_COUNTERS,
            self.seq,
            &self.app_id,
            &self.critical,
            &self.extra,
            &COUNTERS_KEYS,
        )?;
        put(&mut out, "install_id", &hex_encode(&self.install_id))?;
        put(&mut out, "floors", &self.floors)?;
        Ok(out)
    }

    fn from_fields(
        seq: u64,
        app_id: AppId,
        critical: Vec<String>,
        mut fields: Fields,
    ) -> Result<Self, StateError> {
        let record = InstallCounters {
            seq,
            app_id,
            install_id: fields.install_id()?,
            floors: fields.take("floors")?,
            critical,
            extra: fields.rest(),
        };
        check_health(&record.extra)?;
        record.floors.check()?;
        Ok(record)
    }
}

/// `health`, when present, is an object or `null` (M4-D6 amended).
fn check_health(extra: &BTreeMap<String, Value>) -> Result<(), StateError> {
    match extra.get(HEALTH_KEY) {
        None | Some(Value::Null | Value::Object(_)) => Ok(()),
        Some(_) => Err(invalid("health is neither an object nor null")),
    }
}

fn start_fields(
    kind: &str,
    seq: u64,
    app_id: &AppId,
    critical: &[String],
    extra: &BTreeMap<String, Value>,
    own: &[&str],
) -> Result<BTreeMap<String, Value>, StateError> {
    if extra
        .keys()
        .any(|k| COMMON_KEYS.contains(&k.as_str()) || own.contains(&k.as_str()))
    {
        return Err(invalid("an extra field uses a defined key"));
    }
    let mut out = extra.clone();
    put(&mut out, "format", &RECORD_FORMAT)?;
    put(&mut out, "kind", &kind)?;
    put(&mut out, "critical", &critical)?;
    put(&mut out, "seq", &seq)?;
    put(&mut out, "app_id", app_id)?;
    Ok(out)
}

fn put<T: Serialize + ?Sized>(
    out: &mut BTreeMap<String, Value>,
    key: &str,
    value: &T,
) -> Result<(), StateError> {
    let value = serde_json::to_value(value).map_err(|_| invalid("a field does not serialise"))?;
    out.insert(key.to_owned(), value);
    Ok(())
}

/// The top-level members of a payload not yet taken.
#[doc(hidden)]
pub struct Fields(BTreeMap<String, Value>);

impl Fields {
    /// Removes and parses a required member (`null` where the type is an `Option`).
    fn take<T: DeserializeOwned>(&mut self, key: &'static str) -> Result<T, StateError> {
        let value = self
            .0
            .remove(key)
            .ok_or_else(|| StateError::Invalid(Untrusted::new(&format!("missing field {key}"))))?;
        serde_json::from_value(value)
            .map_err(|e| StateError::Invalid(Untrusted::new(&format!("{key}: {e}"))))
    }

    fn install_id(&mut self) -> Result<[u8; INSTALL_ID_BYTES], StateError> {
        let text: String = self.take("install_id")?;
        hex_decode_array::<INSTALL_ID_BYTES>(&text).map_err(|_| invalid("malformed install_id"))
    }

    fn rest(self) -> BTreeMap<String, Value> {
        self.0
    }
}

fn invalid(what: &str) -> StateError {
    StateError::Invalid(Untrusted::new(what))
}

fn de_u53<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    U53::deserialize(deserializer).map(U53::get)
}

fn de_u53_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<Channel, u64>, D::Error> {
    BTreeMap::<Channel, U53>::deserialize(deserializer)
        .map(|m| m.into_iter().map(|(c, v)| (c, v.get())).collect())
}

/// A required member that may be `null` (a missing one is an error).
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

// ---- the frame ------------------------------------------------------------------------------------

/// What one record file turned out to be.
enum Class<T> {
    /// A whole record this build accepts.
    Valid(T),
    /// An integrity failure (torn, flipped, renamed, over the cap): skipped (M4-D23).
    Torn,
}

/// Frames `payload`: magic, format byte, length, payload, digest.
fn frame(payload: &[u8], hasher: &dyn Hasher) -> Result<Vec<u8>, StateError> {
    let total = HEADER_LEN + payload.len() + DIGEST_LEN;
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| total as u64 <= MAX_RECORD_BYTES);
    let Some(len) = len else {
        return Err(StateError::TooLarge {
            size: total as u64,
            cap: MAX_RECORD_BYTES,
        });
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&RECORD_MAGIC);
    out.push(RECORD_FORMAT);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    let digest = hasher.sha256(&out);
    out.extend_from_slice(digest.as_bytes());
    Ok(out)
}

/// The integrity checks of the frame; the payload when they pass, `None` when the file is torn.
fn unframe<'a>(bytes: &'a [u8], hasher: &dyn Hasher) -> Result<Option<&'a [u8]>, StateError> {
    if bytes.len() as u64 > MAX_RECORD_BYTES || !bytes.starts_with(&RECORD_MAGIC) {
        return Ok(None);
    }
    match bytes.get(4) {
        None | Some(0) => return Ok(None),
        Some(&RECORD_FORMAT) => {}
        Some(_) => return Err(StateError::NewerFormat),
    }
    let Some(len) = bytes.get(5..HEADER_LEN) else {
        return Ok(None);
    };
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    let Some(end) = HEADER_LEN.checked_add(len) else {
        return Ok(None);
    };
    if end.checked_add(DIGEST_LEN) != Some(bytes.len()) {
        return Ok(None);
    }
    let digest = hasher.sha256(&bytes[..end]);
    if digest.as_bytes()[..] != bytes[end..] {
        return Ok(None);
    }
    Ok(Some(&bytes[HEADER_LEN..end]))
}

/// One record file's bytes, judged against the seq of its name and the expected app id.
fn classify<T: Record>(
    bytes: &[u8],
    name_seq: u64,
    app_id: &AppId,
    hasher: &dyn Hasher,
) -> Result<Class<T>, StateError> {
    let Some(payload) = unframe(bytes, hasher)? else {
        return Ok(Class::Torn);
    };
    parse_payload(payload, Some(name_seq), app_id).map(|r| r.map_or(Class::Torn, Class::Valid))
}

/// Parses a payload whose frame passed: `Ok(None)` when its seq is not `name_seq` (an integrity
/// failure); every other failure stops (M4-D23).
fn parse_payload<T: Record>(
    payload: &[u8],
    name_seq: Option<u64>,
    app_id: &AppId,
) -> Result<Option<T>, StateError> {
    check_strict(payload).map_err(|e| StateError::Invalid(Untrusted::new(&e.to_string())))?;
    let map: BTreeMap<String, Value> = serde_json::from_slice(payload)
        .map_err(|e| StateError::Invalid(Untrusted::new(&e.to_string())))?;
    let mut fields = Fields(map);
    let seq: u64 = fields.take::<U53>("seq")?.get();
    if name_seq.is_some_and(|n| n != seq) {
        return Ok(None);
    }
    let format: u64 = fields.take::<U53>("format")?.get();
    match format {
        1 => {}
        f if f > 1 => return Err(StateError::NewerFormat),
        _ => return Err(invalid("format 0")),
    }
    let critical: Vec<String> = fields.take("critical")?;
    if !critical.is_empty() {
        // v1 implements no critical feature, so every name is unknown (M4-D22 a).
        return Err(StateError::NewerFormat);
    }
    let kind: String = fields.take("kind")?;
    if kind != T::KIND {
        return Err(invalid("record kind does not match"));
    }
    let record_app: AppId = fields.take("app_id")?;
    if record_app != *app_id {
        return Err(invalid("app id does not match"));
    }
    T::from_fields(seq, record_app, critical, fields).map(Some)
}

fn encode<T: Record>(record: &T, hasher: &dyn Hasher) -> Result<Vec<u8>, StateError> {
    let fields: BTreeMap<String, Value> = record
        .to_fields()?
        .into_iter()
        .map(|(k, v)| (k, sorted(v)))
        .collect();
    let payload = serde_json::to_vec(&fields).map_err(|_| invalid("record does not serialise"))?;
    frame(&payload, hasher)
}

/// `value` with every object's members in key order, whatever map type `serde_json` was built
/// with, so a record's bytes do not depend on a dependency's feature choice.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let members: BTreeMap<String, Value> =
                map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            Value::Object(members.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

// ---- the store ------------------------------------------------------------------------------------

/// What [`load`] found.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded<T> {
    /// The newest whole record; `None` in an empty or missing directory, or when every record file
    /// is torn.
    pub record: Option<T>,
    /// The seq the next commit must use: the highest record *name* + 1 (1 in an empty directory),
    /// so a torn file's number is never reused.
    pub next_seq: u64,
    /// The app id the records were checked against.
    pub app_id: AppId,
}

/// The seq of a record file name `<20 digits>.rec`, `None` for any other name or a seq above
/// `2^53 - 1` (no record can carry one).
fn name_seq(name: &std::ffi::OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let digits = name.strip_suffix(NAME_SUFFIX)?;
    if digits.len() != NAME_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok().filter(|&s| s <= MAX_JSON_INT)
}

fn record_name(seq: u64) -> String {
    format!("{seq:0width$}{NAME_SUFFIX}", width = NAME_DIGITS)
}

/// The record files of `dir`: `(seq, is a regular file)`, highest seq first. A missing directory
/// has none.
fn record_files(fs: &dyn Fs, dir: &Path) -> Result<Vec<(u64, bool)>, StateError> {
    let entries = match fs.list_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind == FsErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out: Vec<(u64, bool)> = entries
        .iter()
        .filter_map(|e| name_seq(&e.name).map(|seq| (seq, e.kind == FileKind::File)))
        .collect();
    out.sort_by_key(|&(seq, _)| std::cmp::Reverse(seq));
    Ok(out)
}

/// Reads and judges one record file. A file over the cap, one that is not a regular file, or one
/// that vanished is torn; any other read failure stops.
fn read_one<T: Record>(
    fs: &dyn Fs,
    dir: &Path,
    seq: u64,
    is_file: bool,
    app_id: &AppId,
    hasher: &dyn Hasher,
) -> Result<Class<T>, StateError> {
    if !is_file {
        return Ok(Class::Torn);
    }
    match fs.read_capped(&dir.join(record_name(seq)), MAX_RECORD_BYTES) {
        Ok(bytes) => classify(&bytes, seq, app_id, hasher),
        Err(e) if matches!(e.kind, FsErrorKind::TooLarge | FsErrorKind::NotFound) => {
            Ok(Class::Torn)
        }
        Err(e) => Err(e.into()),
    }
}

/// Loads the newest whole record of `dir` (FORMAT.md 12.4).
///
/// Records are tried from the highest seq down. A file failing an integrity check (size cap,
/// magic, format byte 0, length, SHA-256, payload seq different from its name) is skipped. A
/// format byte above 1 or a `critical` entry stops with [`StateError::NewerFormat`]; a whole
/// record failing the strict JSON check, the typed parse, `kind`, `app_id` or a semantic rule
/// stops with [`StateError::Invalid`]. No further record is tried after a stop.
pub fn load<T: Record>(
    fs: &dyn Fs,
    dir: &Path,
    app_id: &AppId,
    hasher: &dyn Hasher,
) -> Result<Loaded<T>, StateError> {
    let files = record_files(fs, dir)?;
    let next_seq = files.first().map_or(1, |&(seq, _)| seq + 1);
    for &(seq, is_file) in &files {
        if let Class::Valid(record) = read_one::<T>(fs, dir, seq, is_file, app_id, hasher)? {
            return Ok(Loaded {
                record: Some(record),
                next_seq,
                app_id: app_id.clone(),
            });
        }
    }
    Ok(Loaded {
        record: None,
        next_seq,
        app_id: app_id.clone(),
    })
}

/// Commits `next` as the record after `loaded` (FORMAT.md 12.5), then prunes. Returns the record
/// as written.
///
/// The store owns the sequence: the record is written as `loaded.next_seq` (at most `2^53 - 1`,
/// else [`StateError::SeqExhausted`]), whatever `next.seq` holds, so a caller cannot commit a wrong
/// number. Its app id must be `loaded`'s and its floors at or above the loaded record's (no writer
/// lowers a floor). The record must pass every check [`load`] runs. The file is created with
/// `create_new` (an existing one is [`StateError::Conflict`]), written, synced and its directory
/// synced; only then old records are pruned, best effort, keeping the [`KEEP_RECORDS`] highest
/// valid ones.
pub fn commit<T: Record>(
    fs: &dyn Fs,
    dir: &Path,
    loaded: &Loaded<T>,
    next: &T,
    hasher: &dyn Hasher,
) -> Result<T, StateError> {
    if loaded.next_seq > MAX_JSON_INT {
        return Err(StateError::SeqExhausted);
    }
    let next = next.numbered(loaded.next_seq);
    if *next.app_id() != loaded.app_id {
        return Err(invalid("app id does not match"));
    }
    if let Some(old) = &loaded.record
        && !next.floors().is_at_least(old.floors())
    {
        return Err(StateError::FloorLowered);
    }
    let bytes = encode(&next, hasher)?;
    // The writer writes only what its own reader accepts.
    match classify::<T>(&bytes, next.seq(), &loaded.app_id, hasher)? {
        Class::Valid(_) => {}
        Class::Torn => return Err(invalid("the record does not read back")),
    }
    write_file(fs, dir, next.seq(), &bytes)?;
    prune::<T>(fs, dir, next.seq(), &loaded.app_id, hasher);
    Ok(next)
}

/// Frames `payload` as record `seq` and writes it the way [`commit`] does, without any check of
/// the payload. Test hook for records a correct writer never produces (M4-D23 tests, fuzz seeds).
#[doc(hidden)]
pub fn commit_raw_payload(
    fs: &dyn Fs,
    dir: &Path,
    seq: u64,
    payload: &[u8],
    hasher: &dyn Hasher,
) -> Result<(), StateError> {
    let bytes = frame(payload, hasher)?;
    write_file(fs, dir, seq, &bytes)
}

/// Creates the missing directories of `dir`, each made durable in its parent.
fn ensure_dir(fs: &dyn Fs, dir: &Path) -> Result<(), StateError> {
    let mut missing: Vec<&Path> = Vec::new();
    let mut at = Some(dir);
    while let Some(path) = at {
        match fs.symlink_metadata(path) {
            Ok(Some(_)) => break,
            Ok(None) => {}
            // A missing parent can be reported either way.
            Err(e) if e.kind == FsErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        missing.push(path);
        at = path.parent();
    }
    if missing.is_empty() {
        return Ok(());
    }
    fs.create_dir_all(dir)?;
    for path in missing.iter().rev() {
        if let Some(parent) = path.parent() {
            fs.sync_dir(parent)?;
        }
    }
    Ok(())
}

fn write_file(fs: &dyn Fs, dir: &Path, seq: u64, bytes: &[u8]) -> Result<(), StateError> {
    ensure_dir(fs, dir)?;
    let path = dir.join(record_name(seq));
    let mut file = match fs.create_new(&path) {
        Ok(file) => file,
        Err(e) if e.kind == FsErrorKind::AlreadyExists => return Err(StateError::Conflict { seq }),
        Err(e) => return Err(e.into()),
    };
    file.write_all(bytes)
        .map_err(|e| FsError::from_io(&path, e))?;
    file.sync()?;
    drop(file);
    fs.sync_dir(dir)?;
    Ok(())
}

/// Removes the record files below `newest` that are torn, and the valid ones beyond the
/// [`KEEP_RECORDS`] highest (the new one counts). A file it cannot classify that way (another
/// kind of stop, a read failure) and any file whose name is not a record name is left alone.
/// Best effort: every failure is ignored.
fn prune<T: Record>(fs: &dyn Fs, dir: &Path, newest: u64, app_id: &AppId, hasher: &dyn Hasher) {
    let Ok(files) = record_files(fs, dir) else {
        return;
    };
    let mut valid_kept = 1usize;
    let mut removed = false;
    for (seq, is_file) in files.into_iter().filter(|&(seq, _)| seq < newest) {
        if !is_file {
            continue;
        }
        let remove = match read_one::<T>(fs, dir, seq, true, app_id, hasher) {
            Ok(Class::Torn) => true,
            Ok(Class::Valid(_)) => {
                valid_kept += 1;
                valid_kept > KEEP_RECORDS
            }
            Err(_) => false,
        };
        if remove && fs.remove_file(&dir.join(record_name(seq))).is_ok() {
            removed = true;
        }
    }
    if removed {
        let _ = fs.sync_dir(dir);
    }
}

// ---- scopes (C3) ----------------------------------------------------------------------------------

/// The state of a per-user install: its records live in `dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserScope {
    /// The state directory.
    pub dir: PathBuf,
    /// The app id every record must carry.
    pub app_id: AppId,
}

impl UserScope {
    /// Loads the install's state; a record of scope `machine` is [`StateError::Invalid`].
    pub fn load(
        &self,
        fs: &dyn Fs,
        hasher: &dyn Hasher,
    ) -> Result<Loaded<InstallState>, StateError> {
        let loaded = load::<InstallState>(fs, &self.dir, &self.app_id, hasher)?;
        expect_scope(&loaded, Scope::User)?;
        Ok(loaded)
    }

    /// Commits the next state record ([`commit`]); it must be of scope `user`.
    pub fn commit(
        &self,
        fs: &dyn Fs,
        loaded: &Loaded<InstallState>,
        next: &InstallState,
        hasher: &dyn Hasher,
    ) -> Result<InstallState, StateError> {
        if next.scope != Scope::User {
            return Err(invalid("record scope does not match"));
        }
        commit(fs, &self.dir, loaded, next, hasher)
    }
}

/// The state of a per-machine install: the machine record in `machine_dir`, read-only for the
/// library (there is no commit for it), and this user's floors for it as `install-counters`
/// records in `user_dir/<install id hex>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineScope {
    /// The machine state directory (written by the privileged engine only).
    pub machine_dir: PathBuf,
    /// This user's state directory.
    pub user_dir: PathBuf,
    /// The app id every record must carry.
    pub app_id: AppId,
}

impl MachineScope {
    /// Loads the machine record; a record of scope `user` is [`StateError::Invalid`].
    pub fn load_machine(
        &self,
        fs: &dyn Fs,
        hasher: &dyn Hasher,
    ) -> Result<Loaded<InstallState>, StateError> {
        let loaded = load::<InstallState>(fs, &self.machine_dir, &self.app_id, hasher)?;
        expect_scope(&loaded, Scope::Machine)?;
        Ok(loaded)
    }

    /// The directory of this user's counters for the machine install `machine`.
    pub fn counters_dir(&self, machine: &InstallState) -> PathBuf {
        self.user_dir.join(hex_encode(&machine.install_id))
    }

    /// Loads this user's counters for `machine`. A counters record whose install id differs from
    /// the machine record's is [`StateError::Invalid`] (fail closed).
    pub fn load_counters(
        &self,
        fs: &dyn Fs,
        machine: &InstallState,
        hasher: &dyn Hasher,
    ) -> Result<Loaded<InstallCounters>, StateError> {
        let loaded =
            load::<InstallCounters>(fs, &self.counters_dir(machine), &self.app_id, hasher)?;
        if loaded
            .record
            .as_ref()
            .is_some_and(|c| c.install_id != machine.install_id)
        {
            return Err(invalid("counters belong to another install"));
        }
        Ok(loaded)
    }

    /// Commits this user's next counters record for `machine`.
    pub fn commit_counters(
        &self,
        fs: &dyn Fs,
        machine: &InstallState,
        loaded: &Loaded<InstallCounters>,
        next: &InstallCounters,
        hasher: &dyn Hasher,
    ) -> Result<InstallCounters, StateError> {
        if next.install_id != machine.install_id {
            return Err(invalid("counters belong to another install"));
        }
        commit(fs, &self.counters_dir(machine), loaded, next, hasher)
    }

    /// The floors a check of the machine install starts from: field-wise the higher of the
    /// machine record's and this user's (C3).
    pub fn effective_floors(machine: &InstallState, counters: Option<&InstallCounters>) -> Floors {
        match counters {
            Some(c) => machine.floors.max(&c.floors),
            None => machine.floors.clone(),
        }
    }
}

fn expect_scope(loaded: &Loaded<InstallState>, scope: Scope) -> Result<(), StateError> {
    match &loaded.record {
        Some(r) if r.scope != scope => Err(invalid("record scope does not match")),
        _ => Ok(()),
    }
}

// ---- fuzz entry -----------------------------------------------------------------------------------

/// The fuzz harness body (`lunepack_core::fuzz::state`): `data` as record file number `name_seq`
/// of both kinds, and as a bare payload of both kinds. `true` when the file reads as a whole valid
/// record of either kind.
pub(crate) fn fuzz_run(data: &[u8], name_seq: u64, app_id: &AppId, hasher: &dyn Hasher) -> bool {
    let state = matches!(
        classify::<InstallState>(data, name_seq, app_id, hasher),
        Ok(Class::Valid(_))
    );
    let counters = matches!(
        classify::<InstallCounters>(data, name_seq, app_id, hasher),
        Ok(Class::Valid(_))
    );
    let _ = parse_payload::<InstallState>(data, None, app_id);
    let _ = parse_payload::<InstallCounters>(data, None, app_id);
    state || counters
}

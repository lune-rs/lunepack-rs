//! The key set, `keys.json` (FORMAT.md 6): the release keys the trusted root delegates to.

use serde::{Deserialize, Serialize};

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, Result, Untrusted};
use crate::ident::AppId;
use crate::limits::Limits;
use crate::root::TrustedRoot;
use crate::traits::{Hasher, Verifier};
use crate::trust::{
    ClockReading, KeyClaim, KeyRing, PublicKey, RollbackFloor, parse_payload, present_u53,
    validate_key_list,
};

/// One release key as written (FORMAT.md 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseKeyEntry {
    /// The key id: SHA-256 of `public`.
    pub id: Sha256Digest,
    /// The algorithm id; only `"ed25519"` is accepted.
    pub alg: String,
    /// The public key.
    pub public: PublicKey,
    /// First second the key is valid.
    pub not_before: U53,
    /// First second the key is no longer valid; after `not_before`.
    pub not_after: U53,
}

/// A key-set payload as written (FORMAT.md 6). The writer serialises whatever it is given;
/// [`verify_key_set`] checks every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySetDocument {
    /// Must be 1.
    pub format: U53,
    /// Must be `"keys"`.
    pub kind: String,
    /// Critical features; v1 accepts only an empty list.
    pub critical: Vec<String>,
    /// Equals the trusted root's app id.
    pub app_id: AppId,
    /// Equals the trusted root's version.
    pub root_version: U53,
    /// The key-set version, at least 1.
    pub version: U53,
    /// When present, the key set is expired at `now >= expires`.
    #[serde(
        default,
        deserialize_with = "present_u53",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires: Option<U53>,
    /// The release threshold.
    pub threshold: U53,
    /// The release keys.
    pub keys: Vec<ReleaseKeyEntry>,
}

impl KeySetDocument {
    /// The payload bytes the writer signs: this document as JSON.
    pub fn to_payload(&self) -> Vec<u8> {
        // Plain strings and integers cannot fail to serialise.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A release key's validity window: valid at `t` when `not_before <= t < not_after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWindow {
    /// First valid second.
    pub not_before: u64,
    /// First second no longer valid.
    pub not_after: u64,
}

impl KeyWindow {
    /// Whether the key is valid at `t`.
    pub fn contains(&self, t: u64) -> bool {
        self.not_before <= t && t < self.not_after
    }
}

/// A key set that passed [`verify_key_set`]; there is no other constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKeySet {
    app_id: AppId,
    root_version: u64,
    version: u64,
    expires: Option<u64>,
    threshold: usize,
    ring: KeyRing,
    windows: Vec<KeyWindow>,
    clock: ClockReading,
}

impl VerifiedKeySet {
    /// The app id.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The root version it was verified under.
    pub fn root_version(&self) -> u64 {
        self.root_version
    }

    /// The key-set version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Its `expires`, if any.
    pub fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// The release threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The release keys in document order.
    pub fn keys(&self) -> &KeyRing {
        &self.ring
    }

    /// The validity window of each release key, in the order of [`VerifiedKeySet::keys`].
    pub fn windows(&self) -> &[KeyWindow] {
        &self.windows
    }

    /// The clock reading the time checks used.
    pub fn clock(&self) -> ClockReading {
        self.clock
    }

    /// Whether the expiry check ran; `false` when the clock was implausible and it was skipped
    /// (FORMAT.md 11.3).
    pub fn expiry_checked(&self) -> bool {
        self.clock.is_plausible()
    }
}

/// Verifies `keys.json` (FORMAT.md 6, 11.1 step 2) against the trusted root (after the walk).
/// Order: the envelope opens and meets the root's threshold; only then the payload is parsed
/// (format, kind, critical, then the fields and the release-key rules); the app id and
/// `root_version` bind it to `root`; the floors (root version, key-set version; equal allowed);
/// finally expiry, skipped and reported when `clock` is implausible.
pub fn verify_key_set(
    root: &TrustedRoot,
    bytes: &[u8],
    floor: &RollbackFloor,
    clock: &ClockReading,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<VerifiedKeySet> {
    let envelope = OpenedEnvelope::open(bytes, PayloadKind::Keys, &Limits::V1)?;
    let payload = envelope.authenticate(root.keys(), root.threshold(), verifier)?;
    let doc: KeySetDocument = parse_payload(payload, PayloadKind::Keys)?;

    if doc.version.get() == 0 {
        return Err(Error::Schema(Untrusted::new(
            "key set version must be at least 1",
        )));
    }
    let ring = validate_key_list(
        doc.keys.iter().map(|k| KeyClaim {
            alg: &k.alg,
            public: k.public,
            id: Some(k.id),
        }),
        doc.threshold.get(),
        Limits::V1.release_keys,
        hasher,
        verifier,
    )?;
    let mut windows = Vec::with_capacity(doc.keys.len());
    for k in &doc.keys {
        if k.not_before >= k.not_after {
            return Err(Error::KeyWindow);
        }
        windows.push(KeyWindow {
            not_before: k.not_before.get(),
            not_after: k.not_after.get(),
        });
    }

    if doc.app_id != *root.app_id() {
        return Err(Error::AppIdMismatch);
    }
    if doc.root_version.get() != root.version() {
        return Err(Error::KeySetRootVersion {
            expected: root.version(),
            found: doc.root_version.get(),
        });
    }

    if root.version() < floor.root_version() {
        return Err(Error::Rollback {
            what: "root version",
            floor: floor.root_version(),
            found: root.version(),
        });
    }
    if doc.version.get() < floor.keyset_version() {
        return Err(Error::Rollback {
            what: "key set version",
            floor: floor.keyset_version(),
            found: doc.version.get(),
        });
    }

    let expires = doc.expires.map(U53::get);
    if clock.is_plausible()
        && let Some(at) = expires
        && clock.now() >= at
    {
        return Err(Error::Expired {
            what: "key set",
            expires: at,
            now: clock.now(),
        });
    }

    Ok(VerifiedKeySet {
        app_id: doc.app_id,
        root_version: root.version(),
        version: doc.version.get(),
        expires,
        threshold: doc.threshold.get() as usize,
        ring,
        windows,
        clock: *clock,
    })
}

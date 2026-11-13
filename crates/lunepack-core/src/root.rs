//! The root of trust (FORMAT.md 5): the root payload, the trusted root and the rotation walk.

use serde::{Deserialize, Serialize};

use crate::digest::U53;
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, Result, Untrusted};
use crate::ident::AppId;
use crate::limits::{Limits, MAX_JSON_INT};
use crate::traits::{Hasher, SignatureAlg, Verifier};
use crate::trust::{KeyClaim, KeyEntry, KeyRing, PublicKey, parse_payload, validate_key_list};

/// A root payload as written (FORMAT.md 5.1). The writer serialises whatever it is given;
/// [`advance_root`] checks every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDocument {
    /// Must be 1.
    pub format: U53,
    /// Must be `"root"`.
    pub kind: String,
    /// Critical features; v1 accepts only an empty list.
    pub critical: Vec<String>,
    /// The app id.
    pub app_id: AppId,
    /// The root version, at least 1.
    pub version: U53,
    /// Distinct keys whose signatures a document needs.
    pub threshold: U53,
    /// The root keys.
    pub keys: Vec<KeyEntry>,
}

impl RootDocument {
    /// The payload bytes the writer signs: this document as JSON.
    pub fn to_payload(&self) -> Vec<u8> {
        // Plain strings and integers cannot fail to serialise.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A root the reader trusts: compiled in, or reached from one by [`advance_root`]. There is no
/// way to build one from a document without that check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRoot {
    app_id: AppId,
    version: u64,
    threshold: usize,
    ring: KeyRing,
}

impl TrustedRoot {
    /// The root compiled into the app: its app id, version, threshold and Ed25519 public keys.
    /// The parts are checked like a root document's (FORMAT.md 5.1, 2.5): version in
    /// `1 ..= 2^53 - 1`, `1 <= threshold <= keys <= 16`, no key twice, every key valid.
    pub fn from_parts(
        app_id: AppId,
        version: u64,
        threshold: u64,
        public_keys: &[[u8; 32]],
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<TrustedRoot> {
        if version == 0 || version > MAX_JSON_INT {
            return Err(Error::Schema(Untrusted::new("root version out of range")));
        }
        let ring = validate_key_list(
            public_keys.iter().map(|k| KeyClaim {
                alg: SignatureAlg::Ed25519.id(),
                public: PublicKey::from_bytes(*k),
                id: None,
            }),
            threshold,
            Limits::V1.root_keys,
            hasher,
            verifier,
        )?;
        Ok(TrustedRoot {
            app_id,
            version,
            threshold: threshold as usize,
            ring,
        })
    }

    /// The app id.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The root version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Distinct keys a document signed by this root needs.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The root keys.
    pub fn keys(&self) -> &KeyRing {
        &self.ring
    }
}

/// One step of the rotation walk (FORMAT.md 5.2): accepts `root-<t+1>.json` from `trusted`
/// (version `t`) and returns the new trusted root. Order: the envelope opens and meets `trusted`'s
/// threshold; only then the payload is parsed (format, kind, critical, then the root fields and key
/// rules); the app id equals `trusted`'s and the version is exactly `t + 1`; finally the same
/// envelope meets the new root's own threshold with the new root's own keys.
pub fn advance_root(
    trusted: &TrustedRoot,
    bytes: &[u8],
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<TrustedRoot> {
    let envelope = OpenedEnvelope::open(bytes, PayloadKind::Root, &Limits::V1)?;
    let payload = envelope.authenticate(&trusted.ring, trusted.threshold, verifier)?;
    let doc: RootDocument = parse_payload(payload, PayloadKind::Root)?;

    let ring = validate_key_list(
        doc.keys.iter().map(|k| KeyClaim {
            alg: &k.alg,
            public: k.public,
            id: Some(k.id),
        }),
        doc.threshold.get(),
        Limits::V1.root_keys,
        hasher,
        verifier,
    )?;
    if doc.app_id != trusted.app_id {
        return Err(Error::AppIdMismatch);
    }
    let expected = trusted.version.saturating_add(1);
    if doc.version.get() != expected {
        return Err(Error::RootVersion {
            expected,
            found: doc.version.get(),
        });
    }
    let threshold = doc.threshold.get() as usize;
    envelope.authenticate(&ring, threshold, verifier)?;
    Ok(TrustedRoot {
        app_id: doc.app_id,
        version: expected,
        threshold,
        ring,
    })
}

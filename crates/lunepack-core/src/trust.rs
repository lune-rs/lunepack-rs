//! Shared pieces of the verify chain: public keys and key lists (FORMAT.md 2.5), the key ring an
//! envelope is authenticated against, the common payload header (FORMAT.md 3.2), the clock
//! reading with its plausibility (FORMAT.md 11.3) and the anti-rollback floors (FORMAT.md 11.2).

use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use crate::digest::{Sha256Digest, U53};
use crate::encoding::{hex_decode_array, hex_encode};
use crate::envelope::PayloadKind;
use crate::error::{Error, Result, SignatureError, Untrusted};
use crate::json::check_strict;
use crate::traits::{Clock, Hasher, SignatureAlg, Verifier};

/// Most entries of a payload's `critical` list (FORMAT.md 3.2).
pub const MAX_CRITICAL: usize = 16;
/// Longest `critical` entry in bytes.
pub const MAX_CRITICAL_BYTES: usize = 64;

/// A 32-byte public key, written as 64 lowercase hex characters (uppercase is rejected). This
/// type checks only the encoding; key validity is the [`Verifier`]'s `check_public_key`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps raw key bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HexVisitor;
        impl Visitor<'_> for HexVisitor {
            type Value = PublicKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 lowercase hex characters")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                hex_decode_array::<32>(v).map(PublicKey).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(HexVisitor)
    }
}

/// One key of a root's key list, as written (FORMAT.md 5.1). The writer writes whatever it is
/// given; readers check every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// The key id: SHA-256 of `public`.
    pub id: Sha256Digest,
    /// The algorithm id; only `"ed25519"` is accepted.
    pub alg: String,
    /// The public key.
    pub public: PublicKey,
}

/// A key a ring holds: id recomputed, algorithm known, key checked by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingKey {
    id: Sha256Digest,
    alg: SignatureAlg,
    public: PublicKey,
}

impl RingKey {
    /// The key id.
    pub fn id(&self) -> Sha256Digest {
        self.id
    }

    /// The algorithm.
    pub fn alg(&self) -> SignatureAlg {
        self.alg
    }

    /// The public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// A validated key list: ids recomputed, no public key twice, every key accepted by the
/// verifier. Built only by the crate, from a compiled-in root or a key list that passed
/// [`validate_key_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRing {
    keys: Vec<RingKey>,
}

impl KeyRing {
    /// The key with id `id`, if the ring holds one.
    pub fn get(&self, id: &Sha256Digest) -> Option<&RingKey> {
        self.keys.iter().find(|k| k.id == *id)
    }

    /// The keys in list order.
    pub fn keys(&self) -> &[RingKey] {
        &self.keys
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the ring is empty (a validated ring never is).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// One key to validate: algorithm id text, public key and the id the document claims.
pub(crate) struct KeyClaim<'a> {
    pub(crate) alg: &'a str,
    pub(crate) public: PublicKey,
    pub(crate) id: Option<Sha256Digest>,
}

/// Checks a key list (FORMAT.md 2.5) and its threshold (`1 <= threshold <= keys <= max`) and
/// builds the ring. Per key, in order: the count and threshold, the algorithm id, no public key
/// seen before (whatever id it is listed under), the id recomputed, then the verifier's key check.
pub(crate) fn validate_key_list<'a>(
    claims: impl ExactSizeIterator<Item = KeyClaim<'a>>,
    threshold: u64,
    max: usize,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<KeyRing> {
    let count = claims.len();
    if threshold == 0 || count > max || threshold > count as u64 {
        return Err(Error::KeyThreshold {
            threshold,
            keys: count,
            max,
        });
    }
    let mut keys: Vec<RingKey> = Vec::with_capacity(count);
    for claim in claims {
        let alg = SignatureAlg::from_id(claim.alg).ok_or(SignatureError::UnsupportedAlgorithm)?;
        if keys.iter().any(|k| k.public == claim.public) {
            return Err(Error::DuplicatePublicKey);
        }
        let id = hasher.sha256(claim.public.as_bytes());
        if claim.id.is_some_and(|claimed| claimed != id) {
            return Err(Error::KeyIdMismatch);
        }
        verifier.check_public_key(alg, claim.public.as_bytes())?;
        keys.push(RingKey {
            id,
            alg,
            public: claim.public,
        });
    }
    Ok(KeyRing { keys })
}

/// The fields every payload has (FORMAT.md 3.2); other fields are ignored here.
#[derive(Deserialize)]
struct Header {
    format: U53,
    kind: String,
    critical: Vec<String>,
}

/// Parses an authenticated payload: strict JSON, then `format == 1`, `kind`, the `critical` list
/// (well formed, then empty: v1 implements no critical feature), and only then the kind's
/// fields as `T`.
pub(crate) fn parse_payload<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    kind: PayloadKind,
) -> Result<T> {
    check_strict(payload)?;
    let header: Header = from_checked(payload)?;
    if header.format.get() != 1 {
        return Err(Error::FormatVersion {
            found: header.format.get(),
        });
    }
    if header.kind.as_bytes() != kind.name().as_bytes() {
        return Err(Error::Kind {
            expected: kind.name(),
        });
    }
    check_critical(&header.critical)?;
    from_checked(payload)
}

fn from_checked<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| Error::Schema(Untrusted::new(&e.to_string())))
}

fn check_critical(critical: &[String]) -> Result<()> {
    if critical.len() > MAX_CRITICAL {
        return Err(Error::Schema(Untrusted::new("too many critical entries")));
    }
    for (i, entry) in critical.iter().enumerate() {
        let ok = !entry.is_empty()
            && entry.len() <= MAX_CRITICAL_BYTES
            && entry
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(Error::Schema(Untrusted::new("malformed critical entry")));
        }
        if critical[..i].contains(entry) {
            return Err(Error::Schema(Untrusted::new("duplicate critical entry")));
        }
    }
    match critical.first() {
        Some(unknown) => Err(Error::UnknownCritical(Untrusted::new(unknown))),
        None => Ok(()),
    }
}

/// Deserialises an optional integer field that, when present, must be an integer: `null` is
/// rejected (FORMAT.md 3.1). Use with `#[serde(default)]`.
pub(crate) fn present_u53<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<U53>, D::Error> {
    U53::deserialize(deserializer).map(Some)
}

/// One reading of the reader's clock with its plausibility (FORMAT.md 11.3). The clock is
/// implausible when `now` is earlier than the caller's floor time (the installed release's
/// manifest `issued`); then expiry checks and release-key windows are skipped, and the verified
/// values report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReading {
    now: u64,
    plausible: bool,
}

impl ClockReading {
    /// Reads `clock` once. `floor_time` is the installed release manifest's `issued`, `None` on a
    /// first install.
    pub fn read(clock: &dyn Clock, floor_time: Option<u64>) -> ClockReading {
        let now = clock.now_unix_secs();
        ClockReading {
            now,
            plausible: floor_time.is_none_or(|floor| now >= floor),
        }
    }

    /// The clock's reading in Unix seconds.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Whether the time checks run (`false`: they were skipped).
    pub fn is_plausible(&self) -> bool {
        self.plausible
    }
}

/// The anti-rollback floors a reader persists per app (FORMAT.md 11.2): the highest root version
/// and key-set version it has verified. Equal values are accepted; lower ones are rollbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RollbackFloor {
    root_version: u64,
    keyset_version: u64,
}

impl RollbackFloor {
    /// Floors loaded from persisted state; `0` means none.
    pub const fn new(root_version: u64, keyset_version: u64) -> Self {
        RollbackFloor {
            root_version,
            keyset_version,
        }
    }

    /// The root-version floor.
    pub const fn root_version(&self) -> u64 {
        self.root_version
    }

    /// The key-set-version floor.
    pub const fn keyset_version(&self) -> u64 {
        self.keyset_version
    }

    /// The floors after `keys` (and the root it was verified under) passed: each floor is raised
    /// to the verified value, never lowered. Pure; the caller persists the result.
    pub fn raised_by(&self, keys: &crate::keyset::VerifiedKeySet) -> RollbackFloor {
        RollbackFloor {
            root_version: self.root_version.max(keys.root_version()),
            keyset_version: self.keyset_version.max(keys.version()),
        }
    }
}

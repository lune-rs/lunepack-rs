//! The feed, `feed-<channel>.json` (FORMAT.md 7), and artifact references (FORMAT.md 7.1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, Result};
use crate::ident::{AppId, Channel};
use crate::keyset::VerifiedKeySet;
use crate::limits::Limits;
use crate::path::validate_path;
use crate::target::Target;
use crate::traits::{Hasher, Verifier};
use crate::trust::{ClockReading, RollbackFloor, parse_payload, present, present_u53};
use crate::version::Version;

/// Largest `rollout.basis_points` (10000 = everyone).
pub const MAX_BASIS_POINTS: u64 = 10_000;

/// An artifact reference `{path, size, sha256}` as written (FORMAT.md 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Relative reference, resolved against the feed's directory.
    pub path: String,
    /// Exact byte length.
    pub size: U53,
    /// SHA-256 of the artifact.
    pub sha256: Sha256Digest,
}

/// A checked artifact reference: path per FORMAT.md 7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRef {
    path: String,
    size: u64,
    sha256: Sha256Digest,
}

impl CheckedRef {
    /// The relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The exact size; a reader never reads more.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The artifact's SHA-256.
    pub fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    /// Checks `bytes` against the reference: exact length, then SHA-256.
    pub fn check_bytes(&self, bytes: &[u8], hasher: &dyn Hasher) -> Result<()> {
        if bytes.len() as u64 != self.size {
            return Err(Error::ArtifactSize {
                expected: self.size,
                actual: bytes.len() as u64,
            });
        }
        if hasher.sha256(bytes) != self.sha256 {
            return Err(Error::ArtifactHash);
        }
        Ok(())
    }
}

impl ArtifactRef {
    /// Checks the path (FORMAT.md 10.1 plus ASCII `[A-Za-z0-9._+-]` per component, so no scheme,
    /// query, fragment, percent sign or absolute form).
    pub fn check(&self) -> Result<CheckedRef> {
        validate_path(&self.path)?;
        let ok = self.path.bytes().all(|b| {
            b == b'/' || b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
        });
        if !ok {
            return Err(Error::ReferenceChar);
        }
        Ok(CheckedRef {
            path: self.path.clone(),
            size: self.size.get(),
            sha256: self.sha256,
        })
    }
}

/// A release's rollout as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutDoc {
    /// `0 ..= 10000`.
    pub basis_points: U53,
    /// 32 bytes as 64 lowercase hex characters.
    pub seed: Sha256Digest,
}

/// One feed release as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDoc {
    /// The version string.
    pub version: String,
    /// Target id → manifest reference; at least one.
    pub targets: BTreeMap<String, ArtifactRef>,
    /// Absent means everyone.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub rollout: Option<RolloutDoc>,
}

/// A feed payload as written (FORMAT.md 7). The writer serialises whatever it is given;
/// [`verify_feed`] checks every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedDocument {
    /// Must be 1.
    pub format: U53,
    /// Must be `"feed"`.
    pub kind: String,
    /// Critical features; v1 accepts only an empty list.
    pub critical: Vec<String>,
    /// The app id.
    pub app_id: AppId,
    /// The channel.
    pub channel: Channel,
    /// Sequence number, strictly increasing per channel.
    pub seq: U53,
    /// When the feed was written.
    pub issued: U53,
    /// When present, expired at `now >= expires`; must be after `issued`.
    #[serde(
        default,
        deserialize_with = "present_u53",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires: Option<U53>,
    /// The releases.
    pub releases: Vec<ReleaseDoc>,
}

impl FeedDocument {
    /// The payload bytes the writer signs: this document as JSON.
    pub fn to_payload(&self) -> Vec<u8> {
        // Plain strings and integers cannot fail to serialise.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A checked rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rollout {
    /// `0 ..= 10000`.
    pub basis_points: u16,
    /// The seed.
    pub seed: [u8; 32],
}

/// One release of a verified feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    version: Version,
    version_text: String,
    targets: BTreeMap<Target, CheckedRef>,
    rollout: Option<Rollout>,
}

impl VerifiedRelease {
    /// The version (precedence order and equality).
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The version exactly as written.
    pub fn version_text(&self) -> &str {
        &self.version_text
    }

    /// The manifest reference per target.
    pub fn targets(&self) -> &BTreeMap<Target, CheckedRef> {
        &self.targets
    }

    /// The rollout; `None` means everyone.
    pub fn rollout(&self) -> Option<Rollout> {
        self.rollout
    }
}

/// A feed that passed [`verify_feed`]; there is no other constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFeed {
    app_id: AppId,
    channel: Channel,
    seq: u64,
    issued: u64,
    expires: Option<u64>,
    releases: Vec<VerifiedRelease>,
    clock: ClockReading,
}

impl VerifiedFeed {
    /// The app id.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// The sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// When the feed was written.
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// Its `expires`, if any.
    pub fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// The releases in feed order.
    pub fn releases(&self) -> &[VerifiedRelease] {
        &self.releases
    }

    /// The clock reading the time checks used.
    pub fn clock(&self) -> ClockReading {
        self.clock
    }

    /// Whether the expiry and key-window checks ran; `false` when the clock was implausible and
    /// they were skipped (FORMAT.md 11.3).
    pub fn time_checked(&self) -> bool {
        self.clock.is_plausible()
    }

    /// The manifest entry of `release` (an index into [`VerifiedFeed::releases`]) for `target`.
    pub fn target_entry(&self, release: usize, target: Target) -> Option<FeedTargetEntry> {
        let r = self.releases.get(release)?;
        let reference = r.targets.get(&target)?.clone();
        Some(FeedTargetEntry {
            app_id: self.app_id.clone(),
            version: r.version.clone(),
            version_text: r.version_text.clone(),
            target,
            reference,
        })
    }
}

/// A verified feed's reference to one manifest: what the manifest is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedTargetEntry {
    app_id: AppId,
    version: Version,
    version_text: String,
    target: Target,
    reference: CheckedRef,
}

impl FeedTargetEntry {
    /// The feed's app id.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The release version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The release version exactly as written in the feed.
    pub fn version_text(&self) -> &str {
        &self.version_text
    }

    /// The target the manifest is for.
    pub fn target(&self) -> Target {
        self.target
    }

    /// The manifest's reference.
    pub fn reference(&self) -> &CheckedRef {
        &self.reference
    }
}

fn check_release(doc: &ReleaseDoc) -> Result<VerifiedRelease> {
    let version = Version::parse(&doc.version)?;
    if doc.targets.is_empty() {
        return Err(Error::Field("release lists no target"));
    }
    let mut targets = BTreeMap::new();
    for (id, reference) in &doc.targets {
        let checked = reference.check()?;
        // FORMAT.md 4: the manifest cap bounds the fetch, so it is enforced before any byte is
        // fetched, not only when the fetched bytes are opened.
        let cap = Limits::V1.manifest_doc_bytes;
        if checked.size > cap {
            return Err(Error::TooLarge {
                what: "manifest reference",
                size: checked.size,
                cap,
            });
        }
        targets.insert(Target::parse(id)?, checked);
    }
    let rollout = match &doc.rollout {
        None => None,
        Some(r) => {
            let bp = r.basis_points.get();
            if bp > MAX_BASIS_POINTS {
                return Err(Error::Field("rollout basis_points above 10000"));
            }
            Some(Rollout {
                basis_points: bp as u16,
                seed: *r.seed.as_bytes(),
            })
        }
    };
    Ok(VerifiedRelease {
        version,
        version_text: doc.version.clone(),
        targets,
        rollout,
    })
}

/// Verifies `feed-<channel>.json` (FORMAT.md 7, 11.1 step 3). Order: the envelope opens and meets
/// the key set's release threshold counting only release keys valid at `now` (all of them when
/// the clock is implausible); only then the payload is parsed (format, kind, critical, fields);
/// releases (at most 10,000, each version, target and reference checked, unique by precedence,
/// rollout in range) and `expires > issued`; app id equal to the key set's and to `app_id`,
/// channel equal to `channel`; the `seq` floor of that channel (equal allowed); finally expiry,
/// skipped and reported when the clock is implausible.
pub fn verify_feed(
    keys: &VerifiedKeySet,
    bytes: &[u8],
    app_id: &AppId,
    channel: &Channel,
    floor: &RollbackFloor,
    clock: &ClockReading,
    verifier: &dyn Verifier,
) -> Result<VerifiedFeed> {
    let envelope = OpenedEnvelope::open(bytes, PayloadKind::Feed, &Limits::V1)?;
    let windows = keys.windows();
    let ring = keys.keys().subset(|i| {
        !clock.is_plausible() || windows.get(i).is_some_and(|w| w.contains(clock.now()))
    });
    let payload = envelope.authenticate(&ring, keys.threshold(), verifier)?;
    let doc: FeedDocument = parse_payload(payload, PayloadKind::Feed)?;

    let max = Limits::V1.releases_per_feed;
    if doc.releases.len() > max {
        return Err(Error::TooMany {
            what: "releases",
            count: doc.releases.len(),
            max,
        });
    }
    let releases = doc
        .releases
        .iter()
        .map(check_release)
        .collect::<Result<Vec<_>>>()?;
    let mut order: Vec<&Version> = releases.iter().map(|r| &r.version).collect();
    order.sort();
    if order.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::DuplicateRelease);
    }
    let issued = doc.issued.get();
    let expires = doc.expires.map(U53::get);
    if expires.is_some_and(|e| e <= issued) {
        return Err(Error::Field("feed expires is not after issued"));
    }

    if doc.app_id != *keys.app_id() || doc.app_id != *app_id {
        return Err(Error::AppIdMismatch);
    }
    if doc.channel != *channel {
        return Err(Error::ChannelMismatch);
    }

    let seq_floor = floor.feed_seq(channel);
    if doc.seq.get() < seq_floor {
        return Err(Error::Rollback {
            what: "feed seq",
            floor: seq_floor,
            found: doc.seq.get(),
        });
    }

    if clock.is_plausible()
        && let Some(at) = expires
        && clock.now() >= at
    {
        return Err(Error::Expired {
            what: "feed",
            expires: at,
            now: clock.now(),
        });
    }

    Ok(VerifiedFeed {
        app_id: doc.app_id,
        channel: doc.channel,
        seq: doc.seq.get(),
        issued,
        expires,
        releases,
        clock: *clock,
    })
}

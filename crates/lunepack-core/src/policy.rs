//! Update policy over a verified feed (FORMAT.md 11.4, 11.5): candidate selection and the rollout
//! bucket.

use crate::feed::{FeedTargetEntry, MAX_BASIS_POINTS, Rollout, VerifiedFeed};
use crate::target::Target;
use crate::traits::Hasher;
use crate::version::Version;

/// Bytes of an install id (FORMAT.md 11.5).
pub const INSTALL_ID_BYTES: usize = 16;

/// `u64_be(SHA-256(install_id ‖ seed)[0..8]) mod 10000` (FORMAT.md 11.5).
pub fn rollout_bucket(
    install_id: &[u8; INSTALL_ID_BYTES],
    seed: &[u8; 32],
    hasher: &dyn Hasher,
) -> u16 {
    let mut state = hasher.sha256_start();
    state.update(install_id);
    state.update(seed);
    let digest = state.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest.as_bytes()[..8]);
    // `mod 10000` fits in u16.
    (u64::from_be_bytes(first) % MAX_BASIS_POINTS) as u16
}

/// Whether the install is inside `rollout`: absent means everyone; otherwise
/// `bucket < basis_points` (0 nobody, 10000 everyone).
pub fn in_rollout(
    rollout: Option<Rollout>,
    install_id: &[u8; INSTALL_ID_BYTES],
    hasher: &dyn Hasher,
) -> bool {
    match rollout {
        None => true,
        Some(r) => rollout_bucket(install_id, &r.seed, hasher) < r.basis_points,
    }
}

/// The selected update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Index of the release in [`VerifiedFeed::releases`].
    pub release: usize,
    /// The manifest to fetch: the host's own target or its first listed fallback.
    pub entry: FeedTargetEntry,
}

/// Selects the update candidate (FORMAT.md 11.4): the release with the highest precedence that
/// is strictly newer than `current` (equal precedence is not newer; never a downgrade), is not in
/// `bad` (by precedence), lists `host` or else its first listed fallback, and whose rollout
/// includes `install_id`. `None`: no update. A pre-release is a candidate only because this feed
/// lists it; there is no channel logic here.
pub fn select_candidate(
    feed: &VerifiedFeed,
    current: &Version,
    host: Target,
    bad: &[Version],
    install_id: &[u8; INSTALL_ID_BYTES],
    hasher: &dyn Hasher,
) -> Option<Candidate> {
    let mut order: Vec<usize> = (0..feed.releases().len()).collect();
    // Precedence order (Version's Ord), highest first; releases are unique by precedence.
    order.sort_by(|&a, &b| {
        feed.releases()[b]
            .version()
            .cmp(feed.releases()[a].version())
    });
    for index in order {
        let release = &feed.releases()[index];
        if release.version() <= current {
            // Everything after is lower still.
            return None;
        }
        if bad.contains(release.version()) {
            continue;
        }
        let Some(target) = std::iter::once(host)
            .chain(host.fallbacks().iter().copied())
            .find(|t| release.targets().contains_key(t))
        else {
            continue;
        };
        if !in_rollout(release.rollout(), install_id, hasher) {
            continue;
        }
        let entry = feed.target_entry(index, target)?;
        return Some(Candidate {
            release: index,
            entry,
        });
    }
    None
}

//! The producing side of the trust chain: envelope signing and the document builders that apply
//! the writer rules (FORMAT.md 5, 6, 7; M3-D12). Pure: signing goes through [`Signer`], hashing
//! through [`Hasher`]; the time comes in as a number.
//!
//! The readers stay the judge. A builder refuses what a reader is certain to refuse, but whatever
//! it returns is only trusted once [`advance_root`](crate::advance_root),
//! [`verify_key_set`](crate::verify_key_set) or [`verify_feed`](crate::verify_feed) accepts the
//! signed bytes.

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{EnvelopeSignature, PayloadKind, pae, write_envelope};
use crate::error::{Error, IntegerError, Result, SignatureError, SignerError};
use crate::feed::{FeedDocument, ReleaseDoc, VerifiedFeed, check_release};
use crate::ident::{AppId, Channel};
use crate::keyset::{KeySetDocument, ReleaseKeyEntry, VerifiedKeySet};
use crate::limits::{Limits, MAX_JSON_INT};
use crate::root::RootDocument;
use crate::traits::{Hasher, SignatureAlg, Signer, Verifier};
use crate::trust::{KeyClaim, KeyEntry, validate_key_list};
use crate::version::Version;

/// Default feed lifetime: 90 days, in seconds (M3-D12).
pub const DEFAULT_FEED_LIFETIME_SECS: u64 = 7_776_000;

/// Signs `payload` as a `kind` envelope with every signer in `signers`.
///
/// Each signature is over `pae(kind.payload_type(), payload)` and is verified with `verifier`
/// under its signer's own public key before it is used, so a signer that returns another key's
/// signature (or garbage) fails with [`SignerError::WrongKey`] instead of producing an envelope a
/// reader would reject. Two signers with one public key are [`SignerError::DuplicateKey`]; a
/// signer that is not Ed25519 is refused. Signatures are written sorted by key id, so the bytes do
/// not depend on the order of `signers`. No signer, or more than the format's cap, is an error.
pub fn sign_envelope(
    kind: PayloadKind,
    payload: &[u8],
    signers: &[&dyn Signer],
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<Vec<u8>> {
    let max = Limits::V1.signatures_per_envelope;
    if signers.is_empty() || signers.len() > max {
        return Err(Error::SignatureCount {
            count: signers.len(),
            max,
        });
    }
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(signers.len());
    for signer in signers {
        if signer.alg() != SignatureAlg::Ed25519 {
            return Err(SignerError::Failed {
                reason: "unsupported signature algorithm",
                source: None,
            }
            .into());
        }
        let public = signer.public_key();
        if seen.contains(&public) {
            return Err(SignerError::DuplicateKey.into());
        }
        seen.push(public);
    }

    let message = pae(kind.payload_type(), payload);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let public = signer.public_key();
        let sig = signer.sign(&message)?;
        verifier
            .verify(signer.alg(), &public, &message, &sig)
            .map_err(|_| SignerError::WrongKey)?;
        signatures.push(EnvelopeSignature {
            keyid: hasher.sha256(&public),
            sig,
        });
    }
    signatures.sort_by(|a, b| a.keyid.as_bytes().cmp(b.keyid.as_bytes()));
    Ok(write_envelope(kind.payload_type(), payload, &signatures))
}

fn u53(value: u64) -> Result<U53> {
    Ok(U53::new(value)?)
}

fn too_large() -> Error {
    IntegerError::TooLarge { max: MAX_JSON_INT }.into()
}

/// The next root document (FORMAT.md 5.2): `current`'s version plus one, the same app id, the new
/// threshold and keys.
///
/// The threshold and key list are checked as far as can be without a hasher: `1 <= threshold <=
/// keys <= 16`, the algorithm id, no public key twice. The caller signs the result with the
/// current root's signers and the new root's signers together (a key in both signs once), because a
/// reader needs `current`'s threshold and the new root's own threshold on the same envelope
/// (FORMAT.md 5.2). Key ids and key validity are checked by [`advance_root`](crate::advance_root).
pub fn rotate_root(
    current: &RootDocument,
    new_threshold: u64,
    new_keys: Vec<KeyEntry>,
) -> Result<RootDocument> {
    let max = Limits::V1.root_keys;
    if new_threshold == 0 || new_keys.len() > max || new_threshold > new_keys.len() as u64 {
        return Err(Error::KeyThreshold {
            threshold: new_threshold,
            keys: new_keys.len(),
            max,
        });
    }
    for (i, key) in new_keys.iter().enumerate() {
        if SignatureAlg::from_id(&key.alg).is_none() {
            return Err(SignatureError::UnsupportedAlgorithm.into());
        }
        if new_keys[..i].iter().any(|k| k.public == key.public) {
            return Err(Error::DuplicatePublicKey);
        }
    }
    let version = current.version.get().checked_add(1).ok_or_else(too_large)?;
    Ok(RootDocument {
        format: u53(1)?,
        kind: "root".to_owned(),
        critical: Vec::new(),
        app_id: current.app_id.clone(),
        version: u53(version)?,
        threshold: u53(new_threshold)?,
        keys: new_keys,
    })
}

/// The next key-set document (FORMAT.md 6): version `prev + 1`, or 1 without a previous one,
/// bound to `root_version`.
///
/// Checks the rules a reader applies before it trusts the list: `1 <= threshold <= keys <= 64`, no
/// public key twice, each id the SHA-256 of its key, each key accepted by `verifier`, and each
/// window non-empty (`not_before < not_after`). A previous key set of another app is refused.
/// (`hasher` and `verifier` are needed for the id and key checks.)
#[allow(clippy::too_many_arguments)]
pub fn next_key_set(
    prev: Option<&VerifiedKeySet>,
    root_version: u64,
    app_id: &AppId,
    keys: Vec<ReleaseKeyEntry>,
    threshold: u64,
    expires: Option<u64>,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<KeySetDocument> {
    if root_version == 0 {
        return Err(Error::Field("root version must be at least 1"));
    }
    if prev.is_some_and(|p| p.app_id() != app_id) {
        return Err(Error::AppIdMismatch);
    }
    validate_key_list(
        keys.iter().map(|k| KeyClaim {
            alg: &k.alg,
            public: k.public,
            id: Some(k.id),
        }),
        threshold,
        Limits::V1.release_keys,
        hasher,
        verifier,
    )?;
    if keys.iter().any(|k| k.not_before >= k.not_after) {
        return Err(Error::KeyWindow);
    }
    let version = match prev {
        Some(p) => p.version().checked_add(1).ok_or_else(too_large)?,
        None => 1,
    };
    Ok(KeySetDocument {
        format: u53(1)?,
        kind: "keys".to_owned(),
        critical: Vec::new(),
        app_id: app_id.clone(),
        root_version: u53(root_version)?,
        version: u53(version)?,
        expires: expires.map(u53).transpose()?,
        threshold: u53(threshold)?,
        keys,
    })
}

/// The next feed document (FORMAT.md 7, M3-D12).
///
/// - `seq = max(prev.seq + 1, now_secs * 1000)`, so it rises with every write and tracks the clock;
///   anything that would pass 2^53 - 1 is an error, never a wrap.
/// - `issued = now_secs`; `expires = issued + expires_after` (default 90 days, see
///   [`DEFAULT_FEED_LIFETIME_SECS`]), which must be after `issued`.
/// - `releases` are sorted by precedence ascending; two with equal precedence (`1.0.0+a`,
///   `1.0.0+b`) are an error, as are more than 10,000, a release listing no target and anything
///   [`verify_feed`](crate::verify_feed) would refuse in a release.
/// - A previous feed of another app or channel is refused.
pub fn next_feed(
    prev: Option<&VerifiedFeed>,
    app_id: &AppId,
    channel: &Channel,
    now_secs: u64,
    releases: Vec<ReleaseDoc>,
    expires_after: Option<u64>,
) -> Result<FeedDocument> {
    if let Some(p) = prev {
        if p.app_id() != app_id {
            return Err(Error::AppIdMismatch);
        }
        if p.channel() != channel {
            return Err(Error::ChannelMismatch);
        }
    }
    let max = Limits::V1.releases_per_feed;
    if releases.len() > max {
        return Err(Error::TooMany {
            what: "releases",
            count: releases.len(),
            max,
        });
    }

    let from_clock = now_secs.checked_mul(1000).ok_or_else(too_large)?;
    let after_prev = match prev {
        Some(p) => p.seq().checked_add(1).ok_or_else(too_large)?,
        None => 0,
    };
    let seq = from_clock.max(after_prev);
    let issued = now_secs;
    let lifetime = expires_after.unwrap_or(DEFAULT_FEED_LIFETIME_SECS);
    if lifetime == 0 {
        return Err(Error::Field("feed expires is not after issued"));
    }
    let expires = issued.checked_add(lifetime).ok_or_else(too_large)?;

    let mut keyed = Vec::with_capacity(releases.len());
    for release in releases {
        check_release(&release)?;
        keyed.push((Version::parse(&release.version)?, release));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::DuplicateRelease);
    }

    Ok(FeedDocument {
        format: u53(1)?,
        kind: "feed".to_owned(),
        critical: Vec::new(),
        app_id: app_id.clone(),
        channel: channel.clone(),
        seq: u53(seq)?,
        issued: u53(issued)?,
        expires: Some(u53(expires)?),
        releases: keyed.into_iter().map(|(_, r)| r).collect(),
    })
}

/// The default rollout seed of a release (M3-D12): SHA-256 of `"lunepack-rollout-v1"`, `0x00`, the
/// app id, `0x00` and the version text. Deterministic, so the same release always gets the same
/// seed and no randomness enters the core.
pub fn rollout_seed(app_id: &AppId, version_text: &str, hasher: &dyn Hasher) -> Sha256Digest {
    let mut state = hasher.sha256_start();
    state.update(b"lunepack-rollout-v1");
    state.update(&[0]);
    state.update(app_id.as_str().as_bytes());
    state.update(&[0]);
    state.update(version_text.as_bytes());
    state.finalize()
}

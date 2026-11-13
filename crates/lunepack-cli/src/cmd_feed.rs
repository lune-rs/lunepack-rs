//! `feed add` and `feed refresh` (M3 step 9): the feed writers. A feed is built with the core
//! writer rules, signed, then verified the way a client verifies it, together with every manifest
//! and pack it references, and only then placed (M3-D9). The previous feed is read with the time
//! checks skipped, so an expired feed can be refreshed.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_core::digest::U53;
use lunepack_core::{
    AppId, ArtifactRef, Channel, Clock, ClockReading, Hasher, Limits, PayloadKind, ReleaseDoc,
    RollbackFloor, RolloutDoc, Sha256Digest, Signer, Target, VerifiedFeed, VerifiedKeySet,
    VerifiedRelease, Version, next_feed, rollout_seed, sign_envelope, verify_feed,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::cmd_pack::check_signers;
use crate::cmd_verify::check_target;
use crate::config::{Config, hex32, resolve_signer, writer_clock};
use crate::place;
use crate::release_dir::{self, read_capped};
use crate::state::{Compared, Record, State, StateArgs};

const SECS_PER_DAY: u64 = 86_400;
/// About a century; a bound so the day count cannot overflow the second count.
const MAX_EXPIRES_DAYS: u64 = 36_500;
const MANIFEST_SUFFIX: &str = ".manifest.json";

/// Arguments of `feed add`.
#[derive(Args)]
pub struct AddArgs {
    /// The release directory.
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// The channel, such as `stable`; the feed is `feed-<channel>.json`.
    #[arg(long)]
    channel: String,
    /// The release version, as written in its directory name.
    #[arg(long)]
    version: String,
    /// Limit the release to this many basis points of installs (0..=10000). Without it, an
    /// existing release keeps its rollout.
    #[arg(long, value_parser = clap::value_parser!(u16).range(0..=10_000))]
    rollout: Option<u16>,
    /// The rollout seed, 64 lowercase hex characters (default: the release's existing seed, else
    /// a deterministic one).
    #[arg(long = "rollout-seed", requires = "rollout")]
    rollout_seed: Option<String>,
    /// Feed lifetime in days (default 90).
    #[arg(long = "expires-after-days", value_parser = clap::value_parser!(u64).range(1..=MAX_EXPIRES_DAYS))]
    expires_after_days: Option<u64>,
    /// A release signer: a name from the config, `file:<path>` or `env:<VAR>`; repeat to reach the
    /// key set's threshold.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
    #[command(flatten)]
    state: StateArgs,
}

/// Arguments of `feed refresh`.
#[derive(Args)]
pub struct RefreshArgs {
    /// The release directory.
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// The channel to re-sign.
    #[arg(long)]
    channel: String,
    /// Feed lifetime in days (default 90).
    #[arg(long = "expires-after-days", value_parser = clap::value_parser!(u64).range(1..=MAX_EXPIRES_DAYS))]
    expires_after_days: Option<u64>,
    /// Remove this release (its version text, as listed in the feed) from the feed; repeat for
    /// several. The release's files stay in the release directory.
    #[arg(long = "drop")]
    drop: Vec<String>,
    /// A release signer: a name from the config, `file:<path>` or `env:<VAR>`.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
    #[command(flatten)]
    state: StateArgs,
}

fn say(line: &str) -> Result<()> {
    writeln!(io::stdout().lock(), "{line}").context("cannot write to stdout")
}

/// What both writers start from.
struct Prepared {
    app_id: AppId,
    channel: Channel,
    clock: Box<dyn Clock>,
    now: u64,
    keys: VerifiedKeySet,
    signers: Vec<Box<dyn Signer>>,
    prev: Option<VerifiedFeed>,
    /// The publisher state file (M3-R2-D1), its record of this app, and the walked root.
    state: State,
    record: Record,
    root_k: u64,
    over: StateArgs,
}

fn feed_file_name(channel: &Channel) -> String {
    format!("feed-{}.json", channel.as_str())
}

fn prepare(
    config_path: &Path,
    dir: &Path,
    channel: &str,
    sign: &[String],
    require_prev: bool,
    over: StateArgs,
) -> Result<Prepared> {
    let config = Config::load(config_path)?;
    let channel = Channel::parse(channel).context("--channel is not a valid channel name")?;
    let clock = writer_clock()?;
    let now = clock.now_unix_secs();
    // Time checks are skipped on everything read (M3-D9); the signers' windows are checked at
    // `now` below, and the new feed is verified at `now`.
    let skip = ClockReading::read(clock.as_ref(), Some(u64::MAX));
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let opened = release_dir::open(dir, &config, &hasher, &verifier, &skip)?;
    let Some(keys) = opened.keys else {
        bail!(
            "{} has no keys.json; run `lunepack keys set` first",
            dir.display()
        );
    };
    let signers = sign
        .iter()
        .map(|s| resolve_signer(config_path, s))
        .collect::<Result<Vec<_>>>()?;
    check_signers(&signers, &keys, now)?;

    let name = feed_file_name(&channel);
    let prev = match read_capped(&dir.join(&name), Limits::V1.feed_doc_bytes)? {
        None => None,
        Some(bytes) => Some(
            verify_feed(
                &keys,
                &bytes,
                &config.app_id,
                &channel,
                &RollbackFloor::default(),
                &skip,
                &verifier,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "the existing {name} does not verify under keys.json: {e}; if it is signed by keys no longer in keys.json, delete it and run `feed add` to start the channel again (its seq restarts from the clock, so publish only with a clock later than the old feed's issue time), or restore the previous keys.json and revoke in two moves"
                )
            })?,
        ),
    };
    if require_prev && prev.is_none() {
        bail!("{name} does not exist; use `feed add` to create the channel");
    }
    // Nothing read above is built on until it matches what this publisher last signed (S1).
    let state = State::load(&config.state_path)?;
    let record = state.record(&config.app_id);
    state.check(
        &[
            record.root_compared(opened.root_doc_k, config.root_version),
            record.keys_compared(Some(&keys)),
            Compared {
                document: name,
                field: "seq",
                recorded: record.feeds.get(channel.as_str()).copied(),
                found: prev.as_ref().map(VerifiedFeed::seq),
            },
        ],
        over,
    )?;
    Ok(Prepared {
        app_id: config.app_id,
        channel,
        clock,
        now,
        keys,
        signers,
        prev,
        state,
        record,
        root_k: opened.root_doc_k,
        over,
    })
}

fn release_doc(r: &VerifiedRelease) -> Result<ReleaseDoc> {
    let mut targets = BTreeMap::new();
    for (t, c) in r.targets() {
        targets.insert(
            t.as_str().to_owned(),
            ArtifactRef {
                path: c.path().to_owned(),
                size: U53::new(c.size())?,
                sha256: c.sha256(),
            },
        );
    }
    let rollout = r
        .rollout()
        .map(|ro| -> Result<RolloutDoc> {
            Ok(RolloutDoc {
                basis_points: U53::new(u64::from(ro.basis_points))?,
                seed: Sha256Digest::from_bytes(ro.seed),
            })
        })
        .transpose()?;
    Ok(ReleaseDoc {
        version: r.version_text().to_owned(),
        targets,
        rollout,
    })
}

/// Builds, signs, verifies and places the feed with `releases`.
fn finish(
    mut p: Prepared,
    dir: &Path,
    releases: Vec<ReleaseDoc>,
    expires_after_days: Option<u64>,
) -> Result<()> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let expires_after = expires_after_days.map(|d| d * SECS_PER_DAY);
    let doc = next_feed(
        p.prev.as_ref(),
        &p.app_id,
        &p.channel,
        p.now,
        releases,
        expires_after,
    )?;
    let refs: Vec<&dyn Signer> = p.signers.iter().map(|s| s.as_ref()).collect();
    let bytes = sign_envelope(
        PayloadKind::Feed,
        &doc.to_payload(),
        &refs,
        &hasher,
        &verifier,
    )?;

    let name = feed_file_name(&p.channel);
    let reading = ClockReading::read(p.clock.as_ref(), None);
    let floor = match &p.prev {
        Some(prev) => RollbackFloor::default().with_feed_seq(p.channel.clone(), prev.seq()),
        None => RollbackFloor::default(),
    };
    let feed = verify_feed(
        &p.keys, &bytes, &p.app_id, &p.channel, &floor, &reading, &verifier,
    )
    .context("the new feed does not verify (nothing was written)")?;
    if p.prev.as_ref().is_some_and(|prev| feed.seq() <= prev.seq()) {
        bail!("the new feed's seq does not rise (nothing was written)");
    }
    // Every release the new feed lists must have a manifest that verifies under the current key
    // set and a pack that decodes (Revision 1, I1), not only the one just added.
    let mut manifests = 0usize;
    for (i, release) in feed.releases().iter().enumerate() {
        for target in release.targets().keys() {
            let entry = feed
                .target_entry(i, *target)
                .context("internal error: a release without its target")?;
            let checked = check_target(dir, &p.keys, &entry).with_context(|| {
                format!(
                    "release {}: {target} (nothing was written)",
                    release.version_text()
                )
            })?;
            say(&format!(
                "verify: {} and its pack ok ({} frame(s))",
                checked.manifest_path, checked.frames
            ))?;
            manifests += 1;
        }
    }

    // A channel restarted after its feed was removed must still rise above the recorded seq.
    let recorded_seq = p.record.feeds.get(p.channel.as_str()).copied();
    if let Some(recorded) = recorded_seq
        && feed.seq() <= recorded
    {
        if !p.over.allow_older_previous {
            bail!(
                "the new {name} would have seq {}, not above the recorded {recorded} (nothing was written); write with a later clock",
                feed.seq()
            );
        }
        eprintln!(
            "warning: the new {name} has seq {}, not above the recorded {recorded} (--allow-older-previous)",
            feed.seq()
        );
    }

    place::replace(&dir.join(&name), &bytes)?;
    let mut record = p.record.clone();
    record.set_keys(p.root_k, &p.keys);
    record
        .feeds
        .insert(p.channel.as_str().to_owned(), feed.seq());
    p.state.save(&p.app_id, record)?;
    say(&format!(
        "placed: {name} (seq {}, {} release(s), {manifests} manifest(s) verified)",
        feed.seq(),
        feed.releases().len()
    ))
}

/// The targets of release `version` in `dir`: every `<version>/<target>.manifest.json`.
fn manifests_of(dir: &Path, version: &str) -> Result<BTreeMap<Target, ArtifactRef>> {
    let vdir = dir.join(version);
    let hasher = Sha256Hasher;
    let mut out = BTreeMap::new();
    let listing = match fs::read_dir(&vdir) {
        Ok(l) => l,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            bail!("{} does not exist: pack the release first", vdir.display())
        }
        Err(e) => return Err(e).with_context(|| format!("cannot list {}", vdir.display())),
    };
    for entry in listing {
        let entry = entry.with_context(|| format!("cannot list {}", vdir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(MANIFEST_SUFFIX) else {
            continue;
        };
        let target = Target::parse(stem).with_context(|| {
            format!(
                "{}: the name does not hold a target id",
                entry.path().display()
            )
        })?;
        let bytes = read_capped(&entry.path(), Limits::V1.manifest_doc_bytes)?
            .with_context(|| format!("{} does not exist", entry.path().display()))?;
        out.insert(
            target,
            ArtifactRef {
                path: format!("{version}/{name}"),
                size: U53::new(bytes.len() as u64)?,
                sha256: hasher.sha256(&bytes),
            },
        );
    }
    if out.is_empty() {
        bail!(
            "{} holds no manifest: pack the release first",
            vdir.display()
        );
    }
    Ok(out)
}

/// `feed add`: adds release `--version` to the channel's feed, or adds targets to it.
pub fn add(config_path: &Path, args: &AddArgs) -> Result<()> {
    let version = Version::parse(&args.version).context("--version is not a SemVer version")?;
    let seed = args
        .rollout_seed
        .as_deref()
        .map(|t| hex32(t, "--rollout-seed"))
        .transpose()?;
    let p = prepare(
        config_path,
        &args.release_dir,
        &args.channel,
        &args.sign,
        false,
        args.state,
    )?;
    let new_targets = manifests_of(&args.release_dir, &args.version)?;

    let mut releases = Vec::new();
    let mut existing: Option<&VerifiedRelease> = None;
    if let Some(prev) = &p.prev {
        for r in prev.releases() {
            if r.version_text() == args.version {
                existing = Some(r);
            } else if *r.version() == version {
                bail!(
                    "the feed already lists {:?}, of equal precedence to {:?}",
                    r.version_text(),
                    args.version
                );
            } else {
                releases.push(release_doc(r)?);
            }
        }
    }

    let mut doc = ReleaseDoc {
        version: args.version.clone(),
        targets: BTreeMap::new(),
        rollout: None,
    };
    for (target, reference) in new_targets {
        doc.targets.insert(target.as_str().to_owned(), reference);
    }
    if let Some(old) = existing {
        let kept = release_doc(old)?;
        for (id, old_ref) in kept.targets {
            match doc.targets.get(&id) {
                Some(new_ref) if *new_ref != old_ref => bail!(
                    "release {} target {id}: the manifest in the release dir differs from the one the feed lists; a listed manifest is never replaced",
                    args.version
                ),
                Some(_) => {}
                None => {
                    doc.targets.insert(id, old_ref);
                }
            }
        }
        doc.rollout = kept.rollout;
    }
    if let Some(bp) = args.rollout {
        let seed = match (seed, &doc.rollout) {
            (Some(s), _) => Sha256Digest::from_bytes(s),
            (None, Some(r)) => r.seed,
            (None, None) => rollout_seed(&p.app_id, &args.version, &Sha256Hasher),
        };
        doc.rollout = Some(RolloutDoc {
            basis_points: U53::new(u64::from(bp))?,
            seed,
        });
    }
    releases.push(doc);
    finish(p, &args.release_dir, releases, args.expires_after_days)
}

/// `feed refresh`: the same releases under a new `seq`, `issued` and `expires`.
pub fn refresh(config_path: &Path, args: &RefreshArgs) -> Result<()> {
    let p = prepare(
        config_path,
        &args.release_dir,
        &args.channel,
        &args.sign,
        true,
        args.state,
    )?;
    let prev = p
        .prev
        .as_ref()
        .context("internal error: no previous feed")?;
    for d in &args.drop {
        if !prev.releases().iter().any(|r| r.version_text() == d) {
            bail!(
                "--drop {d:?}: not a release of {}",
                feed_file_name(&p.channel)
            );
        }
    }
    let releases = prev
        .releases()
        .iter()
        .filter(|r| !args.drop.iter().any(|d| d == r.version_text()))
        .map(release_doc)
        .collect::<Result<Vec<_>>>()?;
    finish(p, &args.release_dir, releases, args.expires_after_days)
}

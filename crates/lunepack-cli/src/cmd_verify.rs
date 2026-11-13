//! `verify` and `inspect` (M3 step 9): the checks a client runs, over a whole release directory.
//!
//! The same function backs both commands, so `inspect` shows nothing that did not verify. The
//! order is the client's (FORMAT.md 11.1): the root walk, `keys.json`, each feed, then for every
//! release and target the manifest through the feed's reference, the pack against the manifest's
//! reference, and every frame through the decoder a client uses. The first failure ends the run
//! (exit 1).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::{
    Channel, Clock, ClockReading, FeedTargetEntry, Limits, RollbackFloor, Target, VerifiedEntry,
    VerifiedFeed, VerifiedKeySet, VerifiedManifest, decode_verified, verify_feed, verify_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::config::{Config, FixedClock};
use crate::release_dir::{self, read_capped};

/// A sink for the one-line reports.
pub type Say<'a> = &'a mut dyn FnMut(&str) -> Result<()>;

/// Arguments of `verify`.
#[derive(Args)]
pub struct VerifyArgs {
    /// The release directory.
    dir: PathBuf,
    /// Check at this Unix time instead of the system clock.
    #[arg(long)]
    at: Option<u64>,
}

/// Arguments of `inspect`.
#[derive(Args)]
pub struct InspectArgs {
    /// The release directory.
    dir: PathBuf,
    /// Check at this Unix time instead of the system clock.
    #[arg(long)]
    at: Option<u64>,
    /// Show only this channel.
    #[arg(long)]
    channel: Option<String>,
    /// Show only this version (the text as written in the feed).
    #[arg(long)]
    version: Option<String>,
    /// Show only this target.
    #[arg(long)]
    target: Option<String>,
    /// List every entry of every shown manifest.
    #[arg(long)]
    entries: bool,
}

/// One manifest and its pack, verified.
pub struct TargetCheck {
    /// The target.
    pub target: Target,
    /// The manifest's path relative to the release directory.
    pub manifest_path: String,
    /// The verified manifest.
    pub manifest: VerifiedManifest,
    /// Distinct frames decoded.
    pub frames: usize,
}

/// One release of a feed with its verified targets.
pub struct ReleaseCheck {
    /// The version as written.
    pub version: String,
    /// The release's rollout, if limited.
    pub rollout: Option<lunepack_core::Rollout>,
    /// Its targets.
    pub targets: Vec<TargetCheck>,
}

/// One feed file, verified.
pub struct FeedCheck {
    /// The file name, `feed-<channel>.json`.
    pub file: String,
    /// The verified feed.
    pub feed: VerifiedFeed,
    /// Its releases, in feed order.
    pub releases: Vec<ReleaseCheck>,
}

/// Everything a release directory held, verified.
pub struct Checked {
    /// The key set.
    pub keys: VerifiedKeySet,
    /// The root version after the walk.
    pub root_version: u64,
    /// The feeds in file-name order.
    pub feeds: Vec<FeedCheck>,
    /// Manifests that no feed references.
    pub unreferenced: Vec<String>,
}

/// The clock of the read-only commands (M3-D5): `--at` or the system clock.
fn reader_clock(at: Option<u64>) -> Box<dyn Clock> {
    match at {
        Some(t) => Box::new(FixedClock(t)),
        None => Box::new(lunepack::SystemClock),
    }
}

/// Reads, verifies and decodes the manifest `entry` names and its pack (M3-D9: the way a client
/// does). A missing file, a wrong size or hash, a bad signature or a frame that does not decode is
/// an error naming the file.
pub fn check_target(
    dir: &Path,
    keys: &VerifiedKeySet,
    entry: &FeedTargetEntry,
) -> Result<TargetCheck> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let reference = entry.reference();
    let bytes = read_capped(&dir.join(reference.path()), reference.size())?
        .with_context(|| format!("{} does not exist", reference.path()))?;
    let manifest = verify_manifest(keys, entry, &bytes, &hasher, &verifier)
        .with_context(|| format!("{} does not verify", reference.path()))?;

    let pack_ref = manifest.pack();
    let pack = read_capped(&dir.join(pack_ref.path()), pack_ref.size())?
        .with_context(|| format!("{} does not exist", pack_ref.path()))?;
    pack_ref
        .check_bytes(&pack, &hasher)
        .with_context(|| format!("{} does not match the manifest", pack_ref.path()))?;

    // Identical files share a frame; each distinct frame is decoded once.
    let mut seen = BTreeSet::new();
    for e in manifest.entries() {
        let VerifiedEntry::File {
            path,
            frame: Some(frame),
            ..
        } = e
        else {
            continue;
        };
        if !seen.insert((frame.offset(), frame.length())) {
            continue;
        }
        let start = usize::try_from(frame.offset())?;
        let end = start + usize::try_from(frame.length())?;
        let slice = pack
            .get(start..end)
            .context("a frame lies outside the pack")?;
        decode_verified(frame, slice, &hasher, &LzmaCodec, &mut io::sink())
            .with_context(|| format!("{}: {path} does not decode", pack_ref.path()))?;
    }
    Ok(TargetCheck {
        target: entry.target(),
        manifest_path: reference.path().to_owned(),
        manifest,
        frames: seen.len(),
    })
}

/// The `feed-<channel>.json` files of `dir`, by file name; any other `feed-*.json` name is an
/// error.
fn feed_files(dir: &Path) -> Result<Vec<(String, Channel)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("feed-") && name.ends_with(".json")) {
            continue;
        }
        let channel = name
            .strip_prefix("feed-")
            .and_then(|n| n.strip_suffix(".json"))
            .unwrap_or_default();
        let channel = Channel::parse(channel)
            .with_context(|| format!("{name}: the name does not hold a valid channel"))?;
        out.push((name, channel));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// `<version>/<target>.manifest.json` files under `dir` that are not in `referenced`.
fn unreferenced_manifests(dir: &Path, referenced: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let version = entry.file_name().to_string_lossy().into_owned();
        let inner = fs::read_dir(entry.path())
            .with_context(|| format!("cannot list {}", entry.path().display()))?;
        for file in inner {
            let file = file.with_context(|| format!("cannot list {}", entry.path().display()))?;
            let name = file.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".manifest.json") {
                continue;
            }
            let rel = format!("{version}/{name}");
            if !referenced.contains(&rel) {
                out.push(rel);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Verifies the whole release directory `dir` at `reading` (first-install floors) and reports one
/// line per document through `say`.
pub fn check_release_dir(
    dir: &Path,
    config: &Config,
    reading: &ClockReading,
    say: Say<'_>,
) -> Result<Checked> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let opened = release_dir::open(dir, config, &hasher, &verifier, reading)?;
    say(&format!("root: version {} ok", opened.root_doc_k))?;
    let Some(keys) = opened.keys else {
        bail!("{} has no keys.json", dir.display());
    };
    say(&format!(
        "keys.json: version {}, {} key(s), threshold {} ok",
        keys.version(),
        keys.keys().len(),
        keys.threshold()
    ))?;

    let mut feeds = Vec::new();
    let mut referenced = BTreeSet::new();
    for (file, channel) in feed_files(dir)? {
        let bytes = read_capped(&dir.join(&file), Limits::V1.feed_doc_bytes)?
            .with_context(|| format!("{file} does not exist"))?;
        let feed = verify_feed(
            &keys,
            &bytes,
            &config.app_id,
            &channel,
            &RollbackFloor::default(),
            reading,
            &verifier,
        )
        .with_context(|| format!("{file} does not verify"))?;
        say(&format!(
            "{file}: seq {}, {} release(s) ok",
            feed.seq(),
            feed.releases().len()
        ))?;
        let mut releases = Vec::new();
        for (i, release) in feed.releases().iter().enumerate() {
            let mut targets = Vec::new();
            for target in release.targets().keys() {
                let entry = feed
                    .target_entry(i, *target)
                    .context("internal error: a release without its target")?;
                let checked = check_target(dir, &keys, &entry)?;
                say(&format!(
                    "{}: manifest and pack ok ({} frame(s) decoded)",
                    checked.manifest_path, checked.frames
                ))?;
                referenced.insert(checked.manifest_path.clone());
                targets.push(checked);
            }
            releases.push(ReleaseCheck {
                version: release.version_text().to_owned(),
                rollout: release.rollout(),
                targets,
            });
        }
        feeds.push(FeedCheck {
            file,
            feed,
            releases,
        });
    }
    let unreferenced = unreferenced_manifests(dir, &referenced)?;
    for path in &unreferenced {
        say(&format!("{path}: unreferenced (no feed lists it)"))?;
    }
    Ok(Checked {
        root_version: opened.root_doc_k,
        keys,
        feeds,
        unreferenced,
    })
}

fn out(line: &str) -> Result<()> {
    writeln!(io::stdout().lock(), "{line}").context("cannot write to stdout")
}

fn open_and_check(
    config_path: &Path,
    dir: &Path,
    at: Option<u64>,
    say: Say<'_>,
) -> Result<(Config, Checked)> {
    let config = Config::load(config_path)?;
    let clock = reader_clock(at);
    let reading = ClockReading::read(clock.as_ref(), None);
    let checked = check_release_dir(dir, &config, &reading, say)?;
    Ok((config, checked))
}

/// `verify`: exit 0 only when every document checked out.
pub fn verify(config_path: &Path, args: &VerifyArgs) -> Result<()> {
    let (_, checked) = open_and_check(config_path, &args.dir, args.at, &mut |l| out(l))?;
    let referenced: usize = checked
        .feeds
        .iter()
        .flat_map(|f| &f.releases)
        .map(|r| r.targets.len())
        .sum();
    out(&format!(
        "verified: {} feed(s), {referenced} manifest(s), {} unreferenced",
        checked.feeds.len(),
        checked.unreferenced.len()
    ))
}

/// Per-mille text of `part / whole`, such as `42.5%`; `n/a` for an empty whole.
fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "n/a".to_owned();
    }
    let tenths = u128::from(part) * 1000 / u128::from(whole);
    format!("{}.{}%", tenths / 10, tenths % 10)
}

fn print_manifest(c: &TargetCheck, entries: bool) -> Result<()> {
    let (mut files, mut dirs, mut links, mut empty, mut input) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut codecs: BTreeMap<&'static str, u64> = BTreeMap::new();
    for e in c.manifest.entries() {
        match e {
            VerifiedEntry::File { size, frame, .. } => {
                files += 1;
                input += size;
                match frame {
                    Some(f) => *codecs.entry(f.codec().id()).or_default() += 1,
                    None => empty += 1,
                }
            }
            VerifiedEntry::Dir { .. } => dirs += 1,
            VerifiedEntry::Symlink { .. } => links += 1,
        }
    }
    let pack = c.manifest.pack().size();
    out(&format!(
        "    {}: issued {}, {files} file(s), {dirs} dir(s), {links} symlink(s)",
        c.target.as_str(),
        c.manifest.issued()
    ))?;
    out(&format!(
        "      input {input} bytes, pack {pack} bytes ({} of input), {empty} empty file(s)",
        percent(pack, input)
    ))?;
    let list: Vec<String> = codecs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    out(&format!(
        "      codecs: {}",
        if list.is_empty() {
            "none".to_owned()
        } else {
            list.join(" ")
        }
    ))?;
    if entries {
        for e in c.manifest.entries() {
            let line = match e {
                VerifiedEntry::File {
                    path,
                    size,
                    exec,
                    frame,
                    ..
                } => {
                    let (codec, len) = match frame {
                        Some(f) => (f.codec().id().to_owned(), f.length().to_string()),
                        None => ("-".to_owned(), "-".to_owned()),
                    };
                    format!(
                        "      {path}  file  size {size}  exec {exec}  codec {codec}  frame {len}"
                    )
                }
                VerifiedEntry::Dir { path } => format!("      {path}  dir"),
                VerifiedEntry::Symlink { path, target } => {
                    format!("      {path}  symlink -> {target}")
                }
            };
            out(&line)?;
        }
    }
    Ok(())
}

/// `inspect`: verifies like `verify` (silently), then prints a summary of what verified.
pub fn inspect(config_path: &Path, args: &InspectArgs) -> Result<()> {
    if let Some(t) = &args.target {
        Target::parse(t).context("--target is not a target id")?;
    }
    let (_, checked) = open_and_check(config_path, &args.dir, args.at, &mut |_| Ok(()))?;
    let k = &checked.keys;
    out(&format!(
        "keys: version {}, root {}, threshold {}, {}",
        k.version(),
        checked.root_version,
        k.threshold(),
        match k.expires() {
            Some(e) => format!("expires {e}"),
            None => "no expiry".to_owned(),
        }
    ))?;
    for (key, w) in k.keys().keys().iter().zip(k.windows()) {
        out(&format!(
            "  key {}: valid {}..{}",
            key.id().to_hex(),
            w.not_before,
            w.not_after
        ))?;
    }
    for f in &checked.feeds {
        if args
            .channel
            .as_deref()
            .is_some_and(|c| c != f.feed.channel().as_str())
        {
            continue;
        }
        out(&format!(
            "feed {} ({}): seq {}, issued {}, {}, {} release(s)",
            f.feed.channel().as_str(),
            f.file,
            f.feed.seq(),
            f.feed.issued(),
            match f.feed.expires() {
                Some(e) => format!("expires {e}"),
                None => "no expiry".to_owned(),
            },
            f.releases.len()
        ))?;
        for r in &f.releases {
            if args.version.as_deref().is_some_and(|v| v != r.version) {
                continue;
            }
            let rollout = match r.rollout {
                Some(ro) => format!("rollout {} of 10000", ro.basis_points),
                None => "rollout everyone".to_owned(),
            };
            out(&format!(
                "  release {}: {rollout}, {} target(s)",
                r.version,
                r.targets.len()
            ))?;
            for t in &r.targets {
                if args
                    .target
                    .as_deref()
                    .is_some_and(|x| x != t.target.as_str())
                {
                    continue;
                }
                print_manifest(t, args.entries)?;
            }
        }
    }
    for path in &checked.unreferenced {
        out(&format!("unreferenced: {path}"))?;
    }
    Ok(())
}

//! `pack` (M3 step 8): C2 stages 1 to 5 over any build-output directory (M3-D13), then the
//! self-verification of M3-D9 and placement: the pack first, the manifest last, neither ever
//! overwritten.
//!
//! The packaged app is opaque: its id comes from the config, its version and target from the
//! flags; nothing here reads a build system's files or runs a toolchain.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::digest::U53;
use lunepack_core::{
    AppId, ArtifactRef, Channel, ClockReading, CodeSign, Hasher, PayloadKind, ReleaseDoc,
    ReleaseLayout, RollbackFloor, Signer, Target, VerifiedEntry, VerifiedKeySet, Version,
    decode_verified, next_feed, sign_envelope, verify_feed, verify_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::config::{Config, resolve_signer, writer_clock};
use crate::pipeline::{self, Settings};
use crate::place;
use crate::release_dir;

/// Prefix of the work dir under the system temp dir.
pub const WORK_PREFIX: &str = "lunepack-pack-";
/// Default memory budget of the pack stage, in MiB.
const DEFAULT_BUDGET_MIB: u64 = 2048;
/// The channel of the throwaway feed the self-check signs; never written anywhere.
const SELF_CHECK_CHANNEL: &str = "pack-self-check";

/// Arguments of `pack`.
#[derive(Args)]
pub struct PackArgs {
    /// The build output to package: any directory (the app's files as they should be installed).
    #[arg(long)]
    input: PathBuf,
    /// The release version (SemVer 2.0.0), used verbatim.
    #[arg(long)]
    version: String,
    /// The target id, such as `windows-x86_64` or `linux-aarch64`.
    #[arg(long)]
    target: String,
    /// The release directory (with `keys.json`).
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// A release signer: a name from the config, `file:<path>` or `env:<VAR>`; repeat to reach
    /// the key set's threshold.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
    /// The app id; when given, it must equal the config's.
    #[arg(long = "app-id")]
    app_id: Option<String>,
    /// Encoder threads (default: the available parallelism). The output does not depend on it.
    #[arg(long)]
    jobs: Option<NonZeroUsize>,
    /// Memory budget of the encoders, in MiB; a file over the whole budget is encoded alone.
    #[arg(long = "memory-budget-mib", default_value_t = DEFAULT_BUDGET_MIB,
          value_parser = clap::value_parser!(u64).range(1..=(1 << 40)))]
    memory_budget_mib: u64,
}

fn say(line: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{line}").context("cannot write to stdout")
}

fn key_id_hex(public: &[u8; 32]) -> String {
    Sha256Hasher.sha256(public).to_hex()
}

/// The `--sign` signers must be distinct release keys, each inside its window at `now`, and reach
/// the key set's threshold.
pub(crate) fn check_signers(
    signers: &[Box<dyn Signer>],
    keys: &VerifiedKeySet,
    now: u64,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for s in signers {
        let public = s.public_key();
        let at = keys
            .keys()
            .keys()
            .iter()
            .position(|k| k.public().as_bytes() == &public);
        let Some(at) = at else {
            bail!(
                "the signer with key id {} is not in keys.json",
                key_id_hex(&public)
            );
        };
        let window = keys
            .windows()
            .get(at)
            .context("internal error: a key without a window")?;
        if !window.contains(now) {
            bail!(
                "the release key with id {} is not valid at {now} (window {}..{})",
                key_id_hex(&public),
                window.not_before,
                window.not_after
            );
        }
        if !seen.insert(public) {
            bail!(
                "the release key with id {} is given twice",
                key_id_hex(&public)
            );
        }
    }
    if seen.len() < keys.threshold() {
        bail!(
            "a manifest needs {} release signer(s), {} given",
            keys.threshold(),
            seen.len()
        );
    }
    Ok(())
}

/// D25: a version directory of equal precedence and other text would be a second name for the
/// same release.
fn check_precedence(dir: &Path, version: &Version, text: &str) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name == text || !entry.path().is_dir() {
            continue;
        }
        if Version::parse(&name).is_ok_and(|v| v == *version) {
            bail!(
                "{} already holds version {name:?}, of equal precedence to {text:?}",
                dir.display()
            );
        }
    }
    Ok(())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// M3-D9: the manifest and pack are checked the way a client checks them, through a throwaway feed
/// signed by the same signers.
#[allow(clippy::too_many_arguments)]
fn self_verify(
    keys: &VerifiedKeySet,
    signers: &[&dyn Signer],
    app_id: &AppId,
    version: &str,
    target: Target,
    now: u64,
    manifest: &[u8],
    pack: &[u8],
) -> Result<usize> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let reference = ArtifactRef {
        path: format!("{version}/{}.manifest.json", target.as_str()),
        size: U53::new(manifest.len() as u64)?,
        sha256: hasher.sha256(manifest),
    };
    let release = ReleaseDoc {
        version: version.to_owned(),
        targets: BTreeMap::from([(target.as_str().to_owned(), reference)]),
        rollout: None,
    };
    let channel = Channel::parse(SELF_CHECK_CHANNEL)?;
    let feed = next_feed(None, app_id, &channel, now, vec![release], None)?;
    let feed_bytes = sign_envelope(
        PayloadKind::Feed,
        &feed.to_payload(),
        signers,
        &hasher,
        &verifier,
    )?;
    let reading = ClockReading::read(&crate::config::FixedClock(now), None);
    let feed = verify_feed(
        keys,
        &feed_bytes,
        app_id,
        &channel,
        &RollbackFloor::default(),
        &reading,
        &verifier,
    )?;
    let entry = feed
        .target_entry(0, target)
        .context("the feed lists no manifest for the target")?;
    let manifest = verify_manifest(keys, &entry, manifest, &hasher, &verifier)?;
    manifest.pack().check_bytes(pack, &hasher)?;
    let mut frames = 0;
    for e in manifest.entries() {
        if let VerifiedEntry::File {
            path,
            frame: Some(frame),
            ..
        } = e
        {
            // check_bytes and verify_manifest bound every frame inside the pack.
            let start = usize::try_from(frame.offset())?;
            let end = start + usize::try_from(frame.length())?;
            decode_verified(
                frame,
                &pack[start..end],
                &hasher,
                &LzmaCodec,
                &mut io::sink(),
            )
            .with_context(|| format!("{path} does not decode"))?;
            frames += 1;
        }
    }
    Ok(frames)
}

/// `pack`: see the module documentation.
pub fn pack(config_path: &Path, args: &PackArgs, code_sign: &dyn CodeSign) -> Result<()> {
    let config = Config::load(config_path)?;
    if let Some(id) = &args.app_id
        && id != config.app_id.as_str()
    {
        bail!(
            "--app-id {id:?} is not the config's app id {:?}",
            config.app_id.as_str()
        );
    }
    let version = Version::parse(&args.version).context("--version is not a SemVer version")?;
    let target = Target::parse(&args.target)?;
    // M3-D10: a Windows host cannot know the exec bits of a Unix target.
    if cfg!(windows) && !target.is_windows() {
        bail!(
            "{} cannot be packed on a Windows host: exec bits are unknowable here",
            target.as_str()
        );
    }

    let clock = writer_clock()?;
    let now = clock.now_unix_secs();
    // Time checks are skipped on the documents read (M3-D9); the signers' windows are checked
    // at `now` below.
    let skip = ClockReading::read(clock.as_ref(), Some(u64::MAX));
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let opened = release_dir::open(&args.release_dir, &config, &hasher, &verifier, &skip)?;
    let Some(keys) = opened.keys else {
        bail!(
            "{} has no keys.json; run `lunepack keys set` first",
            args.release_dir.display()
        );
    };
    let signers = args
        .sign
        .iter()
        .map(|s| resolve_signer(config_path, s))
        .collect::<Result<Vec<_>>>()?;
    check_signers(&signers, &keys, now)?;

    let version_dir = args.release_dir.join(&args.version);
    let pack_path = version_dir.join(format!("{}.pack", target.as_str()));
    let manifest_path = version_dir.join(format!("{}.manifest.json", target.as_str()));
    for path in [&manifest_path, &pack_path] {
        if exists(path) {
            bail!("{} already exists", path.display());
        }
    }
    check_precedence(&args.release_dir, &version, &args.version)?;
    let layout = ReleaseLayout::new(config.app_id.clone(), &args.version, target)?;

    let workers = match args.jobs {
        Some(n) => n.get(),
        None => std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
    };
    let set = Settings {
        workers,
        budget: args.memory_budget_mib.saturating_mul(1024 * 1024),
        code_sign,
        encoder: &LzmaCodec,
        codec: &LzmaCodec,
        hasher: &hasher,
    };
    // Removed on drop: on success and on every error path.
    let work = tempfile::Builder::new()
        .prefix(WORK_PREFIX)
        .tempdir()
        .context("cannot create a work dir under the system temp dir")?;
    let built = pipeline::build(
        &args.input,
        work.path(),
        layout,
        target,
        now,
        &set,
        &mut |line| say(line),
    )?;
    drop(work);

    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s.as_ref()).collect();
    let manifest = sign_envelope(
        PayloadKind::Manifest,
        &built.manifest.to_payload(),
        &refs,
        &hasher,
        &verifier,
    )?;
    say(&format!("sign: manifest signed by {} key(s)", refs.len()))?;
    let frames = self_verify(
        &keys,
        &refs,
        &config.app_id,
        &args.version,
        target,
        now,
        &manifest,
        &built.pack,
    )
    .context("the new release does not verify (nothing was written)")?;
    say(&format!("verify: manifest, pack and {frames} frame(s) ok"))?;

    fs::create_dir_all(&version_dir)
        .with_context(|| format!("cannot create {}", version_dir.display()))?;
    place::write_new(&pack_path, &built.pack)?;
    place::write_new(&manifest_path, &manifest)?;
    say(&format!("placed: {}", pack_path.display()))?;
    say(&format!("placed: {}", manifest_path.display()))?;

    let r = &built.report;
    say(&format!(
        "totals: {} file(s), {} input bytes, {} pack bytes",
        r.files,
        r.input_bytes,
        built.pack.len()
    ))?;
    for (codec, count) in &r.per_codec {
        say(&format!("codec {codec}: {count}"))?;
    }
    for (path, codec, reason) in &r.dropped {
        say(&format!("dropped: {path} {}: {reason}", codec.id()))?;
    }
    Ok(())
}

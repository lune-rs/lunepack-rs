//! `init` and `keys gen|show|set|rotate-root` (M3 step 7). Every document a command writes is built
//! by the core writers, checked with the core readers a client uses, and only then placed (M3-D9).

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_core::digest::U53;
use lunepack_core::encoding::hex_encode;
use lunepack_core::{
    ClockReading, Hasher, KeyEntry, KeyRing, PayloadKind, PublicKey, ReleaseKeyEntry,
    RollbackFloor, RootDocument, Signer, TrustedRoot, VerifiedKeySet, advance_root, next_key_set,
    rotate_root, sign_envelope, verify_key_set,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher, generate_key_file};

use crate::config::{Config, hex32, resolve_signer, writer_clock};
use crate::place;
use crate::release_dir::{self, Opened};

/// Two years, the default length of a new release key's window.
const DEFAULT_KEY_WINDOW_SECS: u64 = 63_072_000;

fn say(line: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").context("cannot write to stdout")
}

fn key_id_hex(public: &[u8; 32]) -> String {
    Sha256Hasher.sha256(public).to_hex()
}

fn print_key(public: &[u8; 32]) -> Result<()> {
    say(&format!("public: {}", hex_encode(public)))?;
    say(&format!("id: {}", key_id_hex(public)))
}

fn signers(config: &Path, specs: &[String]) -> Result<Vec<Box<dyn Signer>>> {
    specs.iter().map(|s| resolve_signer(config, s)).collect()
}

/// Checks that `signers` are distinct keys of `ring` and at least `threshold` of them.
fn check_signers(
    signers: &[Box<dyn Signer>],
    ring: &KeyRing,
    threshold: usize,
    what: &str,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for s in signers {
        let public = s.public_key();
        if !ring.keys().iter().any(|k| k.public().as_bytes() == &public) {
            bail!(
                "the signer with key id {} is not one of the {what} keys",
                key_id_hex(&public)
            );
        }
        if !seen.insert(public) {
            bail!(
                "the {what} key with id {} is given twice",
                key_id_hex(&public)
            );
        }
    }
    if seen.len() < threshold {
        bail!(
            "the {what} needs {threshold} signer(s), {} given",
            seen.len()
        );
    }
    Ok(())
}

// ---- init -----------------------------------------------------------------------------------------

/// Arguments of `init`.
#[derive(Args)]
pub struct InitArgs {
    /// The app id (lowercase letters, digits, `.`, `_`, `-`).
    #[arg(long = "app-id")]
    app_id: String,
    /// A root public key, 64 lowercase hex characters; repeat for several.
    #[arg(long = "root-key", required = true)]
    root_keys: Vec<String>,
    /// Root keys that must sign a root document or key set.
    #[arg(long, default_value_t = 1)]
    threshold: u64,
}

/// `init`: writes a config with the compiled-in root and no signers. Refuses to overwrite.
pub fn init(config_path: &Path, args: &InitArgs) -> Result<()> {
    let keys = args
        .root_keys
        .iter()
        .enumerate()
        .map(|(i, k)| hex32(k, &format!("--root-key #{}", i + 1)))
        .collect::<Result<Vec<_>>>()?;
    // The text, built from validated parts, is parsed back by the loader and the root it names is
    // checked like a root document's before anything is written.
    let list: String = keys
        .iter()
        .map(|k| format!("    \"{}\",\n", hex_encode(k)))
        .collect();
    let text = format!(
        "# lunepack configuration. Holds public keys and signer locations only, never a key.\n\
         app_id = \"{app}\"\n\
         \n\
         [root]\n\
         version = 1\n\
         threshold = {threshold}\n\
         keys = [\n{list}]\n\
         \n\
         # Signers, used as `--sign <name>`. Exactly one of these forms per signer:\n\
         #\n\
         # [signers.root]\n\
         # file = \"root.key\"          # PKCS#8 PEM file, relative to this file\n\
         #\n\
         # [signers.ci]\n\
         # env = \"LUNEPACK_SIGNING_KEY\"  # PKCS#8 PEM in an environment variable\n\
         #\n\
         # [signers.hsm]\n\
         # command = [\"my-signer\", \"--slot\", \"1\"]\n\
         # public = \"<64 lowercase hex characters>\"\n",
        app = args.app_id,
        threshold = args.threshold,
    );
    let config = Config::parse(config_path, &text)?;
    config.trusted_root(&Sha256Hasher, &Ed25519Verifier)?;
    place::write_new(config_path, text.as_bytes())?;
    say(&format!("wrote {}", config_path.display()))
}

// ---- keys gen / show --------------------------------------------------------------------------------

/// Arguments of `keys gen`.
#[derive(Args)]
pub struct GenArgs {
    /// Where to write the private key (PKCS#8 PEM); an extension is added when there is none.
    path: PathBuf,
}

/// `keys gen`: a new key file; prints its public key and key id.
pub fn gen_key(args: &GenArgs) -> Result<()> {
    let generated = generate_key_file(&args.path)?;
    print_key(&generated.public_key)?;
    eprintln!("wrote the private key to {}", generated.path.display());
    Ok(())
}

/// Arguments of `keys show`.
#[derive(Args)]
pub struct ShowArgs {
    /// The signer: a name from the config, `file:<path>` or `env:<VAR>`.
    #[arg(long = "sign")]
    sign: String,
}

/// `keys show`: the public key and key id of a signer.
pub fn show_key(config: &Path, args: &ShowArgs) -> Result<()> {
    let signer = resolve_signer(config, &args.sign)?;
    print_key(&signer.public_key())
}

// ---- keys set ---------------------------------------------------------------------------------------

/// Arguments of `keys set`.
#[derive(Args)]
pub struct SetArgs {
    /// The release directory.
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// A release public key (64 lowercase hex characters); repeat for several. `keys.json` lists
    /// exactly these.
    #[arg(long = "release-key", required = true)]
    release_keys: Vec<String>,
    /// Release keys that must sign a feed or manifest (default: the current value, else 1).
    #[arg(long)]
    threshold: Option<u64>,
    /// First second the keys are valid (Unix time). Applies to new keys, and to existing keys when
    /// given.
    #[arg(long = "not-before")]
    not_before: Option<u64>,
    /// First second the keys are no longer valid (Unix time). New keys default to two years from
    /// now.
    #[arg(long = "not-after")]
    not_after: Option<u64>,
    /// When the key set expires (Unix time); none by default.
    #[arg(long)]
    expires: Option<u64>,
    /// A root signer: a name from the config, `file:<path>` or `env:<VAR>`; repeat to reach the
    /// root's threshold.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
}

/// The release keys of a verified key set, as entries.
fn entries_of(keys: &VerifiedKeySet) -> Vec<ReleaseKeyEntry> {
    keys.keys()
        .keys()
        .iter()
        .zip(keys.windows())
        .map(|(k, w)| ReleaseKeyEntry {
            id: k.id(),
            alg: k.alg().id().to_owned(),
            public: *k.public(),
            not_before: U53::new(w.not_before).unwrap_or(U53::MAX),
            not_after: U53::new(w.not_after).unwrap_or(U53::MAX),
        })
        .collect()
}

fn refs(signers: &[Box<dyn Signer>]) -> Vec<&dyn Signer> {
    signers.iter().map(|s| s.as_ref()).collect()
}

/// `keys set`: writes `keys.json` with exactly the listed keys, signed to the root's threshold.
pub fn set_keys(config_path: &Path, args: &SetArgs) -> Result<()> {
    let config = Config::load(config_path)?;
    let clock = writer_clock()?;
    let now = clock.now_unix_secs();
    // Time checks are skipped on the previous key set so an expired one can be replaced (M3-D9).
    let reading = ClockReading::read(clock.as_ref(), Some(u64::MAX));
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let Opened {
        root,
        root_doc_k,
        keys: prev,
    } = release_dir::open(&args.release_dir, &config, &hasher, &verifier, &reading)?;

    let signers = signers(config_path, &args.sign)?;
    check_signers(&signers, root.keys(), root.threshold(), "root")?;

    let previous = prev.as_ref().map(entries_of).unwrap_or_default();
    let mut entries = Vec::with_capacity(args.release_keys.len());
    for (i, text) in args.release_keys.iter().enumerate() {
        let public = hex32(text, &format!("--release-key #{}", i + 1))?;
        let known = previous.iter().find(|e| e.public.as_bytes() == &public);
        let (nb, na) = match known {
            Some(e) => (
                args.not_before.unwrap_or(e.not_before.get()),
                args.not_after.unwrap_or(e.not_after.get()),
            ),
            None => (
                args.not_before.unwrap_or(now),
                match args.not_after {
                    Some(t) => t,
                    None => now
                        .checked_add(DEFAULT_KEY_WINDOW_SECS)
                        .context("the clock is too far ahead for a default key window")?,
                },
            ),
        };
        entries.push(ReleaseKeyEntry {
            id: hasher.sha256(&public),
            alg: "ed25519".to_owned(),
            public: PublicKey::from_bytes(public),
            not_before: U53::new(nb)?,
            not_after: U53::new(na)?,
        });
    }
    let threshold = args
        .threshold
        .or_else(|| prev.as_ref().map(|p| p.threshold() as u64))
        .unwrap_or(1);

    let doc = next_key_set(
        prev.as_ref(),
        root.version(),
        root.app_id(),
        entries,
        threshold,
        args.expires,
        &hasher,
        &verifier,
    )?;
    let bytes = sign_envelope(
        PayloadKind::Keys,
        &doc.to_payload(),
        &refs(&signers),
        &hasher,
        &verifier,
    )?;
    let verified = verify_key_set(
        &root,
        &bytes,
        &RollbackFloor::default(),
        &reading,
        &hasher,
        &verifier,
    )
    .context("the new keys.json does not verify (nothing was written)")?;
    place::replace(&release_dir::keys_path(&args.release_dir), &bytes)?;
    say(&format!(
        "keys.json: version {}, root {root_doc_k}, {} key(s), threshold {}",
        verified.version(),
        verified.keys().len(),
        verified.threshold()
    ))
}

// ---- keys rotate-root -------------------------------------------------------------------------------

/// Arguments of `keys rotate-root`.
#[derive(Args)]
pub struct RotateArgs {
    /// The release directory.
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// A public key of the new root (64 lowercase hex characters); repeat for several.
    #[arg(long = "new-root-key", required = true)]
    new_root_keys: Vec<String>,
    /// Keys of the new root that must sign.
    #[arg(long = "new-threshold")]
    new_threshold: u64,
    /// A signer of the current root; repeat to reach its threshold.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
    /// A signer of the new root; repeat to reach its threshold. A key in both roots may be given
    /// on either side or both: it signs once.
    #[arg(long = "sign-new", required = true)]
    sign_new: Vec<String>,
}

fn root_document(root: &TrustedRoot) -> Result<RootDocument> {
    Ok(RootDocument {
        format: U53::new(1)?,
        kind: "root".to_owned(),
        critical: Vec::new(),
        app_id: root.app_id().clone(),
        version: U53::new(root.version())?,
        threshold: U53::new(root.threshold() as u64)?,
        keys: root
            .keys()
            .keys()
            .iter()
            .map(|k| KeyEntry {
                id: k.id(),
                alg: k.alg().id().to_owned(),
                public: *k.public(),
            })
            .collect(),
    })
}

/// `keys rotate-root`: writes `root-<k+1>.json` (signed by both roots) and re-signs `keys.json`
/// under the new root. The root file is placed first.
pub fn rotate_root_cmd(config_path: &Path, args: &RotateArgs) -> Result<()> {
    let config = Config::load(config_path)?;
    let clock = writer_clock()?;
    let reading = ClockReading::read(clock.as_ref(), Some(u64::MAX));
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let Opened {
        root, keys: prev, ..
    } = release_dir::open(&args.release_dir, &config, &hasher, &verifier, &reading)?;

    let new_publics = args
        .new_root_keys
        .iter()
        .enumerate()
        .map(|(i, k)| hex32(k, &format!("--new-root-key #{}", i + 1)))
        .collect::<Result<Vec<_>>>()?;
    let new_entries: Vec<KeyEntry> = new_publics
        .iter()
        .map(|p| KeyEntry {
            id: hasher.sha256(p),
            alg: "ed25519".to_owned(),
            public: PublicKey::from_bytes(*p),
        })
        .collect();

    let current = root_document(&root)?;
    let next = rotate_root(&current, args.new_threshold, new_entries.clone())?;

    // Both sides must reach their own threshold before anything is signed.
    let old_side = signers(config_path, &args.sign)?;
    check_signers(&old_side, root.keys(), root.threshold(), "current root")?;
    let new_side = signers(config_path, &args.sign_new)?;
    let new_ring_check = {
        // The new root's ring, as the reader will build it from the document.
        let mut seen = BTreeSet::new();
        for s in &new_side {
            let public = s.public_key();
            if !new_publics.contains(&public) {
                bail!(
                    "the signer with key id {} is not one of the new root keys",
                    key_id_hex(&public)
                );
            }
            if !seen.insert(public) {
                bail!(
                    "the new root key with id {} is given twice",
                    key_id_hex(&public)
                );
            }
        }
        seen.len()
    };
    if (new_ring_check as u64) < args.new_threshold {
        bail!(
            "the new root needs {} signer(s), {new_ring_check} given",
            args.new_threshold
        );
    }

    // One signature per key: a key on both sides signs once.
    let mut union: Vec<&dyn Signer> = refs(&old_side);
    for s in &new_side {
        if !union.iter().any(|u| u.public_key() == s.public_key()) {
            union.push(s.as_ref());
        }
    }
    let root_bytes = sign_envelope(
        PayloadKind::Root,
        &next.to_payload(),
        &union,
        &hasher,
        &verifier,
    )?;
    let new_root = advance_root(&root, &root_bytes, &hasher, &verifier)
        .context("the new root does not verify (nothing was written)")?;

    // keys.json is re-signed under the new root: same keys and windows, version + 1.
    let keys_bytes = match &prev {
        None => None,
        Some(prev) => {
            let doc = next_key_set(
                Some(prev),
                new_root.version(),
                new_root.app_id(),
                entries_of(prev),
                prev.threshold() as u64,
                prev.expires(),
                &hasher,
                &verifier,
            )?;
            let bytes = sign_envelope(
                PayloadKind::Keys,
                &doc.to_payload(),
                &refs(&new_side),
                &hasher,
                &verifier,
            )?;
            verify_key_set(
                &new_root,
                &bytes,
                &RollbackFloor::default(),
                &reading,
                &hasher,
                &verifier,
            )
            .context("the re-signed keys.json does not verify (nothing was written)")?;
            Some(bytes)
        }
    };

    place::write_new(
        &release_dir::root_path(&args.release_dir, new_root.version()),
        &root_bytes,
    )?;
    if let Some(bytes) = &keys_bytes {
        place::replace(&release_dir::keys_path(&args.release_dir), bytes)?;
    }
    say(&format!("root-{}.json written", new_root.version()))?;
    if keys_bytes.is_some() {
        say("keys.json re-signed under the new root")?;
    }
    Ok(())
}

//! `lunepack.toml` (M3 step 7), signer specs and the writer clock.
//!
//! The file is local configuration, not a document anyone signs: it names the app, the compiled-in
//! root (public keys only) and how to reach each signer. It holds no secret, but it may name
//! variables and commands, so a parse error reports the file and the line and never the text of
//! the line.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lunepack_core::encoding::hex_decode_array;
use lunepack_core::limits::MAX_JSON_INT;
use lunepack_core::{AppId, Clock, Hasher, Signer, TrustedRoot, Verifier};
use lunepack_crypto::{CommandSigner, Ed25519Signer};
use serde::Deserialize;

/// The default config path.
pub const DEFAULT_CONFIG: &str = "lunepack.toml";
/// Largest config file read.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    app_id: String,
    root: RawRoot,
    #[serde(default)]
    signers: BTreeMap<String, RawSigner>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoot {
    #[serde(default = "first_root_version")]
    version: u64,
    threshold: u64,
    keys: Vec<String>,
}

fn first_root_version() -> u64 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSigner {
    file: Option<String>,
    env: Option<String>,
    command: Option<Vec<String>>,
    public: Option<String>,
}

/// How to reach one signer, from `[signers.<name>]`.
#[derive(Debug, Clone)]
pub enum SignerSpec {
    /// A PKCS#8 PEM key file, already resolved against the config's directory.
    File(PathBuf),
    /// A PKCS#8 PEM key in an environment variable.
    Env(String),
    /// An external command and the public key it signs for.
    Command {
        /// Program and arguments.
        argv: Vec<String>,
        /// The public key the command must sign for.
        public: [u8; 32],
    },
}

/// A parsed, validated `lunepack.toml`.
#[derive(Debug, Clone)]
pub struct Config {
    /// The app id.
    pub app_id: AppId,
    /// The compiled-in root's version.
    pub root_version: u64,
    /// The compiled-in root's threshold.
    pub root_threshold: u64,
    /// The compiled-in root's public keys.
    pub root_keys: Vec<[u8; 32]>,
    signers: BTreeMap<String, SignerSpec>,
}

/// A 64-character lowercase hex value; the error names `what`, never the text.
pub fn hex32(text: &str, what: &str) -> Result<[u8; 32]> {
    hex_decode_array::<32>(text).map_err(|_| anyhow!("{what} is not 64 lowercase hex characters"))
}

fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

impl Config {
    /// Reads and validates the config at `path`.
    pub fn load(path: &Path) -> Result<Config> {
        let mut text = String::new();
        // Classified before opening: Windows cannot open a directory, and a FIFO blocks on open.
        if let Ok(meta) = fs::metadata(path)
            && !meta.is_file()
        {
            bail!("{} is not a regular file", path.display());
        }
        let file = File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            bail!("{} is over {MAX_CONFIG_BYTES} bytes", path.display());
        }
        Config::parse(path, &text)
    }

    /// Parses `text`, read from `path` (which only labels errors).
    pub fn parse(path: &Path, text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| {
            let message = e.message();
            // Only the messages that name a key, never ones that echo a value.
            let shown = if ["unknown field", "missing field", "duplicate key"]
                .iter()
                .any(|p| message.starts_with(p))
            {
                message
            } else {
                "invalid syntax or value"
            };
            match e.span() {
                Some(span) => anyhow!(
                    "{}: line {}: {shown}",
                    path.display(),
                    line_of(text, span.start)
                ),
                None => anyhow!("{}: {shown}", path.display()),
            }
        })?;
        let ctx = || format!("{}", path.display());

        let app_id = AppId::parse(&raw.app_id).with_context(|| format!("{}: app_id", ctx()))?;
        let root_keys = raw
            .root
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| hex32(k, &format!("{}: root.keys[{i}]", ctx())))
            .collect::<Result<Vec<_>>>()?;
        if raw.root.version == 0 || raw.root.version > MAX_JSON_INT {
            bail!("{}: root.version is out of range", ctx());
        }

        let dir = path.parent().unwrap_or(Path::new(""));
        let mut signers = BTreeMap::new();
        for (name, s) in raw.signers {
            let at = format!("{}: signers.{name}", ctx());
            let spec = match (s.file, s.env, s.command, s.public) {
                (Some(file), None, None, None) => SignerSpec::File(dir.join(file)),
                (None, Some(var), None, None) => SignerSpec::Env(var),
                (None, None, Some(argv), Some(public)) => {
                    if argv.first().is_none_or(String::is_empty) {
                        bail!("{at}: command is empty");
                    }
                    SignerSpec::Command {
                        argv,
                        public: hex32(&public, &format!("{at}.public"))?,
                    }
                }
                (None, None, Some(_), None) => bail!("{at}: a command signer needs `public`"),
                _ => bail!(
                    "{at}: give exactly one of `file`, `env` or `command` (with `public`), and `public` only with `command`"
                ),
            };
            signers.insert(name, spec);
        }
        Ok(Config {
            app_id,
            root_version: raw.root.version,
            root_threshold: raw.root.threshold,
            root_keys,
            signers,
        })
    }

    /// The compiled-in root; checks the version, threshold and keys like a root document's.
    pub fn trusted_root(
        &self,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<TrustedRoot> {
        TrustedRoot::from_parts(
            self.app_id.clone(),
            self.root_version,
            self.root_threshold,
            &self.root_keys,
            hasher,
            verifier,
        )
        .context("the root in the config is not valid")
    }

    fn signer(&self, name: &str) -> Result<Box<dyn Signer>> {
        match self.signers.get(name) {
            None => bail!("no signer named {name:?} in the config"),
            Some(SignerSpec::File(path)) => Ok(Box::new(Ed25519Signer::from_key_file(path)?)),
            Some(SignerSpec::Env(var)) => Ok(Box::new(Ed25519Signer::from_env(var)?)),
            Some(SignerSpec::Command { argv, public }) => {
                Ok(Box::new(CommandSigner::new(argv.clone(), *public)?))
            }
        }
    }
}

/// Resolves a `--sign` spec: `file:<path>`, `env:<VAR>` or a signer name from the config at
/// `config_path` (read only when a name is given).
pub fn resolve_signer(config_path: &Path, spec: &str) -> Result<Box<dyn Signer>> {
    if let Some(path) = spec.strip_prefix("file:") {
        return Ok(Box::new(Ed25519Signer::from_key_file(Path::new(path))?));
    }
    if let Some(var) = spec.strip_prefix("env:") {
        return Ok(Box::new(Ed25519Signer::from_env(var)?));
    }
    Config::load(config_path)?.signer(spec)
}

/// A clock fixed at one instant (`SOURCE_DATE_EPOCH`).
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

/// The clock writers use (M3-D5): `SOURCE_DATE_EPOCH` when set (ASCII decimal digits only, at most
/// 2^53 - 1), the system clock otherwise. A malformed value is an error that names the variable
/// and does not echo it.
pub fn writer_clock() -> Result<Box<dyn Clock>> {
    let Some(value) = std::env::var_os("SOURCE_DATE_EPOCH") else {
        return Ok(Box::new(lunepack::SystemClock));
    };
    let secs = value
        .to_str()
        .filter(|t| !t.is_empty() && t.len() <= 16 && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u64>().ok())
        .filter(|n| *n <= MAX_JSON_INT);
    match secs {
        Some(n) => Ok(Box::new(FixedClock(n))),
        None => bail!("SOURCE_DATE_EPOCH is not a decimal number of seconds in 0..=2^53-1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = Config::load(dir.path()).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
    }
}

//! Key-container file check: a tracked or committed path with a key-container extension fails
//! the gate. gitleaks reads `git log -p`, which prints `Binary files differ` for DER and PKCS#12
//! containers, so a private key stored that way is invisible to its content scan; the path is
//! the only signal left. Test keys are generated at test time (CLAUDE.md hard rule 1), so the
//! allowlist is empty by default and an entry is a deliberate, reviewed exception.
//!
//! Output carries counts and positions only, never a path: a path may hold a denylist term, and
//! this check does not know the denylist. The hint line shows how to list the offenders.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};

/// Extensions (lowercase, with the dot) that mark a key container or a PEM/DER key file.
pub const KEY_EXTENSIONS: &[&str] = &[
    ".pfx",
    ".p12",
    ".p8",
    ".key",
    ".pem",
    ".jks",
    ".keystore",
    ".der",
    ".pk8",
    ".pkcs12",
    ".ppk",
];

/// Paths exempt from the check: an exact path, or a directory prefix ending in `/`.
pub const ALLOWLIST: &[&str] = &[];

/// Command line of `xtask key-files`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Args {
    /// Also check every path changed by the commits in this range.
    pub range: Option<String>,
    /// Also check every path changed by any commit reachable from any ref.
    pub all: bool,
    pub repo: Option<PathBuf>,
}

/// Parse `[--range <a>..<b> | --all] [--repo <dir>]`.
pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut out = Args::default();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--all" => out.all = true,
            "--range" => {
                let v = it.next().filter(|v| !v.is_empty());
                out.range = Some(v.ok_or_else(|| anyhow!("--range needs a value"))?);
            }
            "--repo" => {
                let v = it.next().filter(|v| !v.is_empty());
                out.repo = Some(PathBuf::from(
                    v.ok_or_else(|| anyhow!("--repo needs a value"))?,
                ));
            }
            _ => bail!(
                "unknown argument (usage: key-files [--range <a>..<b> | --all] [--repo <dir>])"
            ),
        }
    }
    if out.all && out.range.is_some() {
        bail!("--all and --range are mutually exclusive");
    }
    Ok(out)
}

/// The key extension a path ends with (case-insensitive), unless the path is allowlisted.
pub fn key_extension(path: &[u8], allowlist: &[&str]) -> Option<&'static str> {
    let lower = String::from_utf8_lossy(path).to_lowercase();
    if allowlist.iter().any(|a| {
        if let Some(prefix) = a.strip_suffix('/') {
            lower.starts_with(&format!("{}/", prefix.to_lowercase()))
        } else {
            lower == a.to_lowercase()
        }
    }) {
        return None;
    }
    KEY_EXTENSIONS.iter().copied().find(|e| lower.ends_with(e))
}

fn git(dir: &PathBuf, what: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("cannot run git {what}"))?;
    if !out.status.success() {
        bail!("git {what} failed ({})", out.status);
    }
    Ok(out.stdout)
}

fn paths(raw: &[u8]) -> impl Iterator<Item = &[u8]> {
    raw.split(|b| *b == 0).filter(|p| !p.is_empty())
}

/// Run the check; returns the report lines (empty = clean). Errors are `Err` (exit 2).
pub fn run(args: &Args, allowlist: &[&str]) -> Result<Vec<String>> {
    let dir = match &args.repo {
        Some(r) => r.clone(),
        None => std::env::current_dir().context("cannot determine the current directory")?,
    };
    let mut report = Vec::new();

    // The index: tracked files, including anything staged.
    let listing = git(&dir, "ls-files", &["ls-files", "-z"])?;
    for (idx, path) in paths(&listing).enumerate() {
        if let Some(ext) = key_extension(path, allowlist) {
            report.push(format!(
                "key-files: tracked path #{} has a key-container extension ({ext})",
                idx + 1
            ));
        }
    }

    let commits: Vec<String> = if let Some(range) = &args.range {
        let list = git(&dir, "rev-list", &["rev-list", "--end-of-options", range])?;
        String::from_utf8_lossy(&list)
            .lines()
            .map(str::to_string)
            .collect()
    } else if args.all {
        let list = git(&dir, "rev-list", &["rev-list", "--all"])?;
        String::from_utf8_lossy(&list)
            .lines()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    for sha in commits.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let names = git(
            &dir,
            "diff-tree",
            &[
                "diff-tree",
                "-r",
                "-m",
                "--root",
                "--no-renames",
                "--no-commit-id",
                "--name-only",
                "-z",
                sha,
            ],
        )?;
        for (idx, path) in paths(&names).enumerate() {
            if let Some(ext) = key_extension(path, allowlist) {
                let short: String = sha.chars().take(12).collect();
                report.push(format!(
                    "key-files: commit {short} changed path #{} with a key-container extension ({ext})",
                    idx + 1
                ));
            }
        }
    }
    report.dedup();
    Ok(report)
}

/// Entry point for `xtask key-files`: exit 0 clean, 1 offenders, 2 error.
pub fn main(args: impl IntoIterator<Item = String>) -> ExitCode {
    let outcome = parse_args(args).and_then(|a| run(&a, ALLOWLIST));
    match outcome {
        Ok(report) if report.is_empty() => {
            eprintln!("key-files: ok");
            ExitCode::SUCCESS
        }
        Ok(report) => {
            for line in &report {
                println!("{line}");
            }
            eprintln!(
                "key-files: {} offending entries; list tracked ones with: git ls-files | grep -n -i -E '\\.({})$'",
                report.len(),
                KEY_EXTENSIONS
                    .iter()
                    .map(|e| &e[1..])
                    .collect::<Vec<_>>()
                    .join("|")
            );
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("key-files: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

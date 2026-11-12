//! Workspace boundary check.
//!
//! Dependencies, sources and package fields come from `cargo metadata --no-deps`
//! (cargo is the authority on what a manifest declares); only the `[lints]` tables
//! and the root `[workspace]` keys, which metadata does not carry, are read with a
//! real TOML parser. Every form this check does not recognise is a violation, and
//! any internal error is distinct from a violation (exit 2, never exit 0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use cargo_metadata::semver::Version;
use cargo_metadata::{Dependency, DependencyKind, Metadata, MetadataCommand, Package};

/// What a workspace member is allowed to depend on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Core,
    Testkit,
    Adapter,
    Facade,
    Binary,
    Tool,
}

/// Role of every workspace member, by exact package name. Adding a crate = one line.
pub const ROLES: &[(&str, Role)] = &[
    ("lunepack-core", Role::Core),
    ("lunepack-testkit", Role::Testkit),
    ("lunepack-crypto", Role::Adapter),
    ("lunepack-codec-zstd", Role::Adapter),
    ("lunepack-fs", Role::Adapter),
    ("lunepack-http", Role::Adapter),
    ("lunepack-os-windows", Role::Adapter),
    ("lunepack-os-macos", Role::Adapter),
    ("lunepack-os-linux", Role::Adapter),
    ("lunepack", Role::Facade),
    ("lunepack-runtime", Role::Binary),
    ("lunepack-cli", Role::Binary),
    ("xtask", Role::Tool),
];

/// Crates that may lift `unsafe_code` (M1-D3); `lunepack-ffi` joins here later.
pub const UNSAFE_ALLOWLIST: &[&str] = &[
    "lunepack-fs",
    "lunepack-os-windows",
    "lunepack-os-macos",
    "lunepack-os-linux",
];

/// External (non-workspace) dependencies `lunepack-core` may have. Empty in M1.
pub const CORE_EXTERNAL_ALLOWLIST: &[&str] = &[];

/// The `source` string cargo metadata reports for a crates.io dependency in this workspace.
pub const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

const EXPECTED_EDITION: &str = "2024";
const EXPECTED_LICENSE: &str = "MIT OR Apache-2.0";
const EXPECTED_MSRV: (u64, u64, u64) = (1, 88, 0);
const WORKSPACE_LABEL: &str = "<workspace>";

fn role_of(name: &str) -> Option<Role> {
    ROLES.iter().find(|(n, _)| *n == name).map(|(_, r)| *r)
}

fn names_with_role(role: Role) -> impl Iterator<Item = &'static str> {
    ROLES
        .iter()
        .filter(move |(_, r)| *r == role)
        .map(|(n, _)| *n)
}

fn allowed_normal(role: Role) -> Vec<&'static str> {
    let roles: &[Role] = match role {
        Role::Core | Role::Tool => &[],
        Role::Testkit | Role::Adapter => &[Role::Core],
        Role::Facade => &[Role::Core, Role::Adapter],
        Role::Binary => &[Role::Core, Role::Adapter, Role::Facade],
    };
    roles.iter().flat_map(|r| names_with_role(*r)).collect()
}

/// One broken rule, printed as `boundaries: <package>: <rule>: <detail>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub package: String,
    pub rule: &'static str,
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boundaries: {}: {}: {}",
            self.package, self.rule, self.detail
        )
    }
}

/// Parsed manifests: the root and each member, keyed by the member's `manifest_path`, plus the
/// workspace's `Cargo.lock` (`None` when there is none, which is itself a violation).
#[derive(Debug, Default)]
pub struct Manifests {
    pub root: toml::Table,
    pub members: BTreeMap<String, toml::Table>,
    pub lock: Option<toml::Table>,
    /// Standalone probe crates under `probes/*/` (outside the workspace): label (`probes/<dir>`),
    /// manifest and lock file. They build on runners with elevated rights, so their sources
    /// are held to the same rule.
    pub probes: Vec<ProbeCrate>,
}

/// A standalone crate under `probes/`.
#[derive(Debug, Default)]
pub struct ProbeCrate {
    pub label: String,
    pub manifest: toml::Table,
    pub lock: Option<toml::Table>,
}

fn read_table(path: &Path) -> Result<toml::Table> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read manifest {}", path.display()))?;
    text.parse::<toml::Table>()
        .with_context(|| format!("cannot parse manifest {}", path.display()))
}

/// Run `cargo metadata --no-deps --offline` for the workspace in `dir`; cargo comes from `CARGO`.
pub fn metadata_json(dir: &Path) -> Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(&cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
        .current_dir(dir)
        .output()
        .with_context(|| format!("cannot run {}", PathBuf::from(&cargo).display()))?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8(out.stdout).context("cargo metadata output is not UTF-8")
}

/// Every `probes/<dir>/Cargo.toml` (a directory without one is ignored: scripts live there too).
fn load_probe_crates(workspace_root: &Path) -> Result<Vec<ProbeCrate>> {
    let dir = workspace_root.join("probes");
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => bail!("cannot read {}: {e}", dir.display()),
    };
    for entry in entries {
        let path = entry
            .with_context(|| format!("cannot read {}", dir.display()))?
            .path();
        let manifest_path = path.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let lock_path = path.join("Cargo.lock");
        out.push(ProbeCrate {
            label: format!("probes/{}", entry_name(&path)),
            manifest: read_table(&manifest_path)?,
            lock: if lock_path.is_file() {
                Some(read_table(&lock_path)?)
            } else {
                None
            },
        });
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}

fn entry_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Read the root manifest and every member manifest named by the metadata.
pub fn load_manifests(metadata_json: &str) -> Result<Manifests> {
    let md = MetadataCommand::parse(metadata_json).context("cannot parse cargo metadata output")?;
    let lock_path = md.workspace_root.join("Cargo.lock");
    let lock = if lock_path.as_std_path().exists() {
        Some(read_table(lock_path.as_std_path())?)
    } else {
        None
    };
    let mut manifests = Manifests {
        root: read_table(md.workspace_root.join("Cargo.toml").as_std_path())?,
        members: BTreeMap::new(),
        lock,
        probes: load_probe_crates(md.workspace_root.as_std_path())?,
    };
    for pkg in &md.packages {
        let table = read_table(pkg.manifest_path.as_std_path())?;
        manifests
            .members
            .insert(pkg.manifest_path.to_string(), table);
    }
    Ok(manifests)
}

fn v(package: &str, rule: &'static str, detail: impl Into<String>) -> Violation {
    Violation {
        package: package.to_string(),
        rule,
        detail: detail.into(),
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    a == b
        || match (a.canonicalize(), b.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
}

/// The pure check: metadata JSON plus parsed manifests in, violations out.
/// An `Err` means the input could not be understood (exit 2), never a clean pass.
pub fn check(metadata_json: &str, manifests: &Manifests) -> Result<Vec<Violation>> {
    let md = MetadataCommand::parse(metadata_json).context("cannot parse cargo metadata output")?;
    let mut out = Vec::new();

    let member_dirs: BTreeMap<&str, PathBuf> = md
        .packages
        .iter()
        .filter_map(|p| {
            p.manifest_path
                .parent()
                .map(|d| (p.name.as_str(), d.as_std_path().to_path_buf()))
        })
        .collect();

    check_root(&md, manifests, &mut out)?;
    check_lock(&md, manifests, &mut out);
    for pkg in &md.packages {
        check_package(pkg, &member_dirs, manifests, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn check_root(md: &Metadata, manifests: &Manifests, out: &mut Vec<Violation>) -> Result<()> {
    let ws = manifests
        .root
        .get("workspace")
        .and_then(|w| w.as_table())
        .ok_or_else(|| anyhow!("root manifest has no [workspace] table"))?;
    let unsafe_code = ws
        .get("lints")
        .and_then(|l| l.get("rust"))
        .and_then(|r| r.get("unsafe_code"))
        .and_then(|u| u.as_str());
    if unsafe_code != Some("forbid") {
        out.push(v(
            WORKSPACE_LABEL,
            "root-lints",
            "workspace.lints.rust.unsafe_code must be \"forbid\"",
        ));
    }
    let excluded = ws
        .get("exclude")
        .and_then(|e| e.as_array())
        .is_some_and(|a| a.iter().any(|x| x.as_str() == Some("probes")));
    if !excluded {
        out.push(v(
            WORKSPACE_LABEL,
            "root-exclude",
            "workspace.exclude must contain \"probes\"",
        ));
    }
    for pkg in &md.packages {
        let under_probes = pkg
            .manifest_path
            .strip_prefix(&md.workspace_root)
            .map(|rel| {
                rel.components()
                    .next()
                    .is_some_and(|c| c.as_str() == "probes")
            })
            .unwrap_or(false);
        if under_probes {
            out.push(v(
                &pkg.name,
                "probes",
                "workspace member lives under probes/",
            ));
        }
    }
    Ok(())
}

/// Every package in a lock file is either crates.io (the exact `CRATES_IO_SOURCE`) or has no
/// `source` and is one of that lock's own members, matched by name and version: the workspace
/// members from `cargo metadata`, or for `probes/<dir>` that probe's own `[package]`. Anything
/// else (a git or other-registry source, or a source-less package that is not a member, which is
/// what a path dependency or a `[patch]` / `[replace]` / `.cargo/config.toml` patch to a path
/// produces) is a violation. `cargo metadata --no-deps` only reports declared dependencies, so a
/// redirection is invisible there; the lock file records what was actually resolved. A missing
/// lock, and a `[patch]` or `[replace]` section in the root or a probe manifest, are violations
/// too. A vendored crate would need an explicit allowlist entry here.
fn check_lock(md: &Metadata, manifests: &Manifests, out: &mut Vec<Violation>) {
    let members: BTreeSet<(String, String)> = md
        .packages
        .iter()
        .map(|p| (p.name.to_string(), p.version.to_string()))
        .collect();
    check_lock_for(
        WORKSPACE_LABEL,
        &manifests.root,
        manifests.lock.as_ref(),
        &members,
        out,
    );
    for probe in &manifests.probes {
        let members = probe_member(&probe.manifest)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if members.is_empty() {
            out.push(v(
                &probe.label,
                "lockfile",
                "the probe manifest has no string `[package] name` / `version`: its own lock entry cannot be identified",
            ));
        }
        check_lock_for(
            &probe.label,
            &probe.manifest,
            probe.lock.as_ref(),
            &members,
            out,
        );
    }
}

/// A probe's own `(name, version)`; an absent `version` is cargo's default `0.0.0`. Any other
/// form (e.g. `version.workspace = true`) yields `None`, so every source-less entry fails.
fn probe_member(manifest: &toml::Table) -> Option<(String, String)> {
    let pkg = manifest.get("package")?.as_table()?;
    let name = pkg.get("name")?.as_str()?;
    let version = match pkg.get("version") {
        None => "0.0.0",
        Some(v) => v.as_str()?,
    };
    Some((name.to_string(), version.to_string()))
}

fn check_lock_for(
    label: &str,
    manifest: &toml::Table,
    lock: Option<&toml::Table>,
    members: &BTreeSet<(String, String)>,
    out: &mut Vec<Violation>,
) {
    for key in ["patch", "replace"] {
        if manifest.contains_key(key) {
            out.push(v(
                label,
                "patch",
                format!("the manifest has a [{key}] section"),
            ));
        }
    }
    let Some(lock) = lock else {
        out.push(v(
            label,
            "lockfile",
            "Cargo.lock is missing: dependency sources cannot be verified",
        ));
        return;
    };
    let Some(packages) = lock.get("package").and_then(|p| p.as_array()) else {
        out.push(v(label, "lockfile", "Cargo.lock has no [[package]] array"));
        return;
    };
    for entry in packages {
        let Some(table) = entry.as_table() else {
            out.push(v(label, "lockfile", "a [[package]] entry is not a table"));
            continue;
        };
        let Some(name) = table.get("name").and_then(|n| n.as_str()) else {
            out.push(v(label, "lockfile", "a [[package]] entry has no name"));
            continue;
        };
        match table.get("source") {
            None => {
                let version = table.get("version").and_then(|x| x.as_str()).unwrap_or("");
                if !members.contains(&(name.to_string(), version.to_string())) {
                    out.push(v(
                        name,
                        "lock-source",
                        format!(
                            "Cargo.lock ({label}) has `{name}` {version} with no source and it is not a member: a path dependency or a patch to a path"
                        ),
                    ));
                }
            }
            Some(toml::Value::String(src)) if src == CRATES_IO_SOURCE => {}
            Some(toml::Value::String(src)) => out.push(v(
                name,
                "lock-source",
                format!(
                    "Cargo.lock ({label}) resolves `{name}` from {src}, not crates.io or a workspace path"
                ),
            )),
            Some(_) => out.push(v(
                name,
                "lock-source",
                "Cargo.lock `source` is not a string",
            )),
        }
    }
}

fn check_package(
    pkg: &Package,
    member_dirs: &BTreeMap<&str, PathBuf>,
    manifests: &Manifests,
    out: &mut Vec<Violation>,
) -> Result<()> {
    let name = pkg.name.as_str();
    let role = role_of(name);
    if role.is_none() {
        out.push(v(
            name,
            "unknown-member",
            "workspace member is not in the role table",
        ));
    }

    // Package fields.
    if pkg.edition.as_str() != EXPECTED_EDITION {
        out.push(v(
            name,
            "edition",
            format!("expected {EXPECTED_EDITION}, got {}", pkg.edition),
        ));
    }
    let (maj, min, pat) = EXPECTED_MSRV;
    if pkg.rust_version.as_ref() != Some(&Version::new(maj, min, pat)) {
        out.push(v(
            name,
            "rust-version",
            format!("expected {maj}.{min}, got {:?}", pkg.rust_version),
        ));
    }
    if pkg.license.as_deref() != Some(EXPECTED_LICENSE) {
        out.push(v(
            name,
            "license",
            format!("expected {EXPECTED_LICENSE:?}, got {:?}", pkg.license),
        ));
    }
    if matches!(role, Some(Role::Testkit | Role::Tool)) && pkg.publish.as_deref() != Some(&[]) {
        out.push(v(name, "publish", "must be `publish = false`"));
    }

    // Dependencies.
    let testkit: Vec<&str> = names_with_role(Role::Testkit).collect();
    for dep in &pkg.dependencies {
        check_dependency(name, role, dep, &testkit, member_dirs, out);
    }

    // Lints.
    let manifest = manifests
        .members
        .get(pkg.manifest_path.as_str())
        .ok_or_else(|| anyhow!("no parsed manifest for {}", pkg.manifest_path))?;
    check_lints(name, manifest, &manifests.root, out);
    Ok(())
}

fn check_dependency(
    package: &str,
    role: Option<Role>,
    dep: &Dependency,
    testkit: &[&str],
    member_dirs: &BTreeMap<&str, PathBuf>,
    out: &mut Vec<Violation>,
) {
    let dname = dep.name.as_str();
    let kind = match dep.kind {
        DependencyKind::Normal => "normal",
        DependencyKind::Development => "dev",
        DependencyKind::Build => "build",
        _ => {
            out.push(v(
                package,
                "dep-kind",
                format!("`{dname}` has an unrecognised dependency kind"),
            ));
            return;
        }
    };

    if let Some(dir) = member_dirs.get(dname) {
        // Workspace edge: must be a path dependency on that exact member.
        let path_ok = dep.source.is_none()
            && dep.registry.is_none()
            && dep
                .path
                .as_ref()
                .is_some_and(|p| same_dir(p.as_std_path(), dir));
        if !path_ok {
            out.push(v(
                package,
                "source",
                format!(
                    "`{dname}` is a workspace crate name but not a path dependency on that member"
                ),
            ));
        }
        if let Some(role) = role {
            let mut allowed = allowed_normal(role);
            if dep.kind == DependencyKind::Development {
                allowed.extend(testkit.iter().copied());
            }
            if !allowed.contains(&dname) {
                out.push(v(
                    package,
                    "edge",
                    format!("{kind} dependency on `{dname}` is not allowed for {role:?}"),
                ));
            }
        }
        return;
    }

    // Not a member: must come from crates.io, and workspace-named crates may not be squatted.
    if role_of(dname).is_some() {
        out.push(v(
            package,
            "source",
            format!("`{dname}` shadows a workspace crate name but is not a member"),
        ));
        return;
    }
    let from_crates_io = dep.registry.is_none()
        && dep.path.is_none()
        && dep.source.as_ref().map(|s| s.repr.as_str()) == Some(CRATES_IO_SOURCE);
    if !from_crates_io {
        let src = dep
            .source
            .as_ref()
            .map_or("none (path)", |s| s.repr.as_str());
        out.push(v(
            package,
            "source",
            format!("`{dname}` is not from crates.io or a workspace path (source {src})"),
        ));
    } else if role == Some(Role::Core) && !CORE_EXTERNAL_ALLOWLIST.contains(&dname) {
        out.push(v(
            package,
            "core-external",
            format!("{kind} dependency on external crate `{dname}` is not allowlisted"),
        ));
    }
}

fn lints_of(manifest: &toml::Table) -> Option<&toml::Value> {
    manifest.get("lints")
}

fn check_lints(
    package: &str,
    manifest: &toml::Table,
    root: &toml::Table,
    out: &mut Vec<Violation>,
) {
    let Some(lints) = lints_of(manifest) else {
        out.push(v(package, "lints", "missing [lints]"));
        return;
    };
    let inherit: toml::Value = toml::Value::Table(toml::Table::from_iter([(
        "workspace".to_string(),
        toml::Value::Boolean(true),
    )]));
    if *lints == inherit {
        return;
    }
    if !UNSAFE_ALLOWLIST.contains(&package) {
        out.push(v(
            package,
            "lints",
            "[lints] must be exactly `workspace = true`",
        ));
        return;
    }
    // Allowlisted crate: a full copy of the workspace lints, differing only as M1-D3 allows.
    let ws_lints = root
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .and_then(|l| l.as_table());
    let (Some(tbl), Some(ws_lints)) = (lints.as_table(), ws_lints) else {
        out.push(v(
            package,
            "lints",
            "[lints] is not a table or the workspace has no lints",
        ));
        return;
    };
    if tbl.contains_key("workspace") {
        out.push(v(
            package,
            "lints",
            "`workspace` key may not be mixed with explicit lints",
        ));
    }
    if let Some(extra) = tbl
        .keys()
        .find(|k| *k != "rust" && *k != "clippy" && *k != "workspace")
    {
        out.push(v(
            package,
            "lints",
            format!("unexpected lint tool table `{extra}`"),
        ));
    }
    let empty = toml::Table::new();
    let sub = |t: &toml::Table, k: &str| -> Option<toml::Table> {
        match t.get(k) {
            None => Some(empty.clone()),
            Some(x) => x.as_table().cloned(),
        }
    };
    let (Some(mut rust), Some(mut ws_rust)) = (sub(tbl, "rust"), sub(ws_lints, "rust")) else {
        out.push(v(package, "lints", "`rust` lints are not a table"));
        return;
    };
    rust.remove("unsafe_code");
    ws_rust.remove("unsafe_code");
    if rust != ws_rust {
        out.push(v(
            package,
            "lints",
            "`rust` lints differ from the workspace beyond `unsafe_code`",
        ));
    }
    let (Some(clippy), Some(mut ws_clippy)) = (sub(tbl, "clippy"), sub(ws_lints, "clippy")) else {
        out.push(v(package, "lints", "`clippy` lints are not a table"));
        return;
    };
    ws_clippy.insert(
        "undocumented_unsafe_blocks".to_string(),
        toml::Value::String("deny".into()),
    );
    if clippy != ws_clippy {
        out.push(v(
            package,
            "lints",
            "`clippy` lints must equal the workspace's plus `undocumented_unsafe_blocks = \"deny\"`",
        ));
    }
}

/// Check the workspace rooted at `dir` end to end.
pub fn check_workspace(dir: &Path) -> Result<(usize, Vec<Violation>)> {
    let json = metadata_json(dir)?;
    let manifests = load_manifests(&json)?;
    let count = MetadataCommand::parse(&json)?.packages.len();
    Ok((count, check(&json, &manifests)?))
}

/// Entry point for `xtask check-boundaries`: exit 0 clean, 1 violations, 2 internal error.
pub fn main() -> ExitCode {
    let result = std::env::current_dir()
        .map_err(anyhow::Error::from)
        .and_then(|dir| check_workspace(&dir));
    match result {
        Ok((count, violations)) if violations.is_empty() => {
            println!("boundaries: ok ({count} packages)");
            ExitCode::SUCCESS
        }
        Ok((_, violations)) => {
            for violation in &violations {
                println!("{violation}");
            }
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("boundaries: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

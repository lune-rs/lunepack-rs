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
    ("lunepack-codec-lzma", Role::Adapter),
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

/// External (non-workspace) dependencies `lunepack-core` may have (M2-D1): the pure parsing,
/// encoding and error crates the format needs. Hashing, signatures, clock and decoding stay
/// behind core traits; nothing here does I/O.
pub const CORE_EXTERNAL_ALLOWLIST: &[&str] = &[
    "serde",
    "serde_json",
    "base64",
    "semver",
    "unicode-normalization",
    "thiserror",
];

/// Confined dependencies (M3-D11): `(crate, packages allowed to depend on it)`. The crate brings
/// unsafe code or asm that docs/DECISIONS.md allows only in the named adapter (D17, D34). Adding a
/// later confined crate is one line. Matched on the package name, never the rename.
pub const CONFINED: &[(&str, &[&str])] = &[("lzma-rust2", &["lunepack-codec-lzma"])];

/// Reach-only-through crates (M4-D16): `(crate, via)`. In the lock graph of the workspace and of
/// `fuzz/`, no workspace member may reach `crate` except through the member `via`. `ring` is the
/// only crypto provider the project allows (D17), and only the HTTP adapter links it.
pub const REACH_ONLY_THROUGH: &[(&str, &str)] = &[("ring", "lunepack-http")];

/// Packages no lock the check reads may contain (D17), matched by exact package name, so
/// `openssl-probe` is not `openssl`.
pub const FORBIDDEN_ANYWHERE: &[&str] = &["aws-lc-rs", "aws-lc-sys", "openssl", "openssl-sys"];

/// Exact version pins: `(package, dependency, requirement string as cargo reports it)`. The
/// package must exist in the workspace and must declare the dependency, always with this
/// requirement.
pub const EXACT_PINS: &[(&str, &str, &str)] = &[("lunepack-codec-lzma", "lzma-rust2", "=0.25.0")];

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
    /// The standalone fuzz project `fuzz/` (outside the workspace, M2-D9): label `fuzz`, its
    /// manifest and lock. `None` when `fuzz/Cargo.toml` does not exist. Held to the probes' lock
    /// rule, plus its path dependencies must be this repository's own workspace members.
    pub fuzz: Option<ProbeCrate>,
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

/// `fuzz/Cargo.toml` and `fuzz/Cargo.lock`, when the manifest exists (a missing lock is reported
/// by the lock rule, not here).
fn load_fuzz_crate(workspace_root: &Path) -> Result<Option<ProbeCrate>> {
    let dir = workspace_root.join("fuzz");
    let manifest_path = dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(None);
    }
    let lock_path = dir.join("Cargo.lock");
    Ok(Some(ProbeCrate {
        label: "fuzz".to_string(),
        manifest: read_table(&manifest_path)?,
        lock: if lock_path.is_file() {
            Some(read_table(&lock_path)?)
        } else {
            None
        },
    }))
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
        fuzz: load_fuzz_crate(md.workspace_root.as_std_path())?,
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
    check_confined_metadata(&md, &mut out);
    check_exact_pins(&md, &mut out);
    if let Some(fuzz) = &manifests.fuzz {
        check_fuzz_deps(&md, fuzz, &member_dirs, &mut out);
    }
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
    if manifests.fuzz.is_some() {
        let fuzz_excluded = ws
            .get("exclude")
            .and_then(|e| e.as_array())
            .is_some_and(|a| a.iter().any(|x| x.as_str() == Some("fuzz")));
        if !fuzz_excluded {
            out.push(v(
                WORKSPACE_LABEL,
                "root-exclude",
                "workspace.exclude must contain \"fuzz\" while fuzz/Cargo.toml exists",
            ));
        }
    }
    for pkg in &md.packages {
        let first_dir = pkg
            .manifest_path
            .strip_prefix(&md.workspace_root)
            .ok()
            .and_then(|rel| rel.components().next().map(|c| c.as_str().to_string()));
        match first_dir.as_deref() {
            Some("probes") => out.push(v(
                &pkg.name,
                "probes",
                "workspace member lives under probes/",
            )),
            Some("fuzz") => out.push(v(&pkg.name, "fuzz", "workspace member lives under fuzz/")),
            _ => {}
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
    check_lock_graph(WORKSPACE_LABEL, manifests.lock.as_ref(), &members, out);
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
    if let Some(fuzz) = &manifests.fuzz {
        // The fuzz lock may hold this workspace's own members (by name and version) plus the fuzz
        // package itself.
        let mut members = members;
        match probe_member(&fuzz.manifest) {
            Some(own) => {
                members.insert(own);
            }
            None => out.push(v(
                &fuzz.label,
                "lockfile",
                "the fuzz manifest has no string `[package] name` / `version`: its own lock entry cannot be identified",
            )),
        }
        check_lock_for(
            &fuzz.label,
            &fuzz.manifest,
            fuzz.lock.as_ref(),
            &members,
            out,
        );
        check_lock_graph(&fuzz.label, fuzz.lock.as_ref(), &members, out);
    }
}

/// One `[[package]]` entry of a lock file, for the graph rules.
struct LockNode {
    name: String,
    version: String,
    /// `None` for a path package (a workspace member in a clean lock).
    source: Option<String>,
}

/// The node a lock `dependencies` string names. The string is `name`, `name version` or
/// `name version (source)`; a bare name resolves only when exactly one entry has that name. An
/// unrecognised form, no match and several matches are all errors (fail closed).
fn resolve_lock_dep(nodes: &[LockNode], dep: &str) -> std::result::Result<usize, String> {
    let parts: Vec<&str> = dep.split(' ').collect();
    let (name, version, source) = match parts.as_slice() {
        [n] => (*n, None, None),
        [n, v] => (*n, Some(*v), None),
        [n, v, src] if src.len() > 2 && src.starts_with('(') && src.ends_with(')') => {
            (*n, Some(*v), Some(&src[1..src.len() - 1]))
        }
        _ => return Err(format!("`{dep}` is not a form this check recognises")),
    };
    let found: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| {
            n.name == name
                && version.is_none_or(|v| n.version == v)
                && source.is_none_or(|s| n.source.as_deref() == Some(s))
        })
        .map(|(i, _)| i)
        .collect();
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("`{dep}` matches no entry of the lock")),
        _ => Err(format!("`{dep}` matches several entries of the lock")),
    }
}

/// Rules `forbidden` and `reach` (M4-D16) over one lock file's package graph. Nodes are
/// `[[package]]` entries; edges are their `dependencies` strings, which cover every platform and
/// every dev edge. Roots are the source-less entries that are members of `members`.
///
/// - `forbidden`: an entry named exactly like a [`FORBIDDEN_ANYWHERE`] package.
/// - `reach`: for each [`REACH_ONLY_THROUGH`] pair, the walk from each root does not enter a
///   member named `via`; reaching `crate` anyway is a violation that names one shortest path.
/// - A `dependencies` value that is not an array of strings, and an edge that matches no entry or
///   several, is a `reach` violation too (the graph cannot be trusted). A missing lock or a
///   malformed `[[package]]` array is reported by [`check_lock_for`], not here.
fn check_lock_graph(
    label: &str,
    lock: Option<&toml::Table>,
    members: &BTreeSet<(String, String)>,
    out: &mut Vec<Violation>,
) {
    let Some(packages) = lock
        .and_then(|l| l.get("package"))
        .and_then(|p| p.as_array())
    else {
        return;
    };
    let mut nodes = Vec::new();
    let mut raw_deps = Vec::new();
    for entry in packages {
        let Some(table) = entry.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        nodes.push(LockNode {
            name: name.to_string(),
            version: table
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            source: table.get("source").map(|s| match s.as_str() {
                Some(text) => text.to_string(),
                None => "<not a string>".to_string(),
            }),
        });
        raw_deps.push(table.get("dependencies"));
    }

    for node in &nodes {
        if FORBIDDEN_ANYWHERE.contains(&node.name.as_str()) {
            out.push(v(
                &node.name,
                "forbidden",
                format!(
                    "Cargo.lock ({label}) contains `{}` {}: no lock may (D17)",
                    node.name, node.version
                ),
            ));
        }
    }

    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (i, deps) in raw_deps.iter().enumerate() {
        let name = &nodes[i].name;
        let Some(deps) = deps else {
            continue;
        };
        let Some(deps) = deps.as_array() else {
            out.push(v(
                name,
                "reach",
                format!("Cargo.lock ({label}): `dependencies` of `{name}` is not an array"),
            ));
            continue;
        };
        for dep in deps {
            let Some(dep) = dep.as_str() else {
                out.push(v(
                    name,
                    "reach",
                    format!(
                        "Cargo.lock ({label}): a `dependencies` entry of `{name}` is not a string"
                    ),
                ));
                continue;
            };
            match resolve_lock_dep(&nodes, dep) {
                Ok(j) => edges[i].push(j),
                Err(why) => out.push(v(
                    name,
                    "reach",
                    format!("Cargo.lock ({label}): `{name}` depends on {why}"),
                )),
            }
        }
    }

    let is_member =
        |n: &LockNode| n.source.is_none() && members.contains(&(n.name.clone(), n.version.clone()));
    for (target, via) in REACH_ONLY_THROUGH {
        let blocked = |i: usize| is_member(&nodes[i]) && nodes[i].name == *via;
        for root in (0..nodes.len()).filter(|&i| is_member(&nodes[i]) && !blocked(i)) {
            // Breadth first, so the first hit has a shortest path.
            let mut parent: Vec<Option<usize>> = vec![None; nodes.len()];
            let mut seen = vec![false; nodes.len()];
            seen[root] = true;
            let mut queue = std::collections::VecDeque::from([root]);
            let mut hit = None;
            while let Some(at) = queue.pop_front() {
                if nodes[at].name == *target {
                    hit = Some(at);
                    break;
                }
                for &next in &edges[at] {
                    if !seen[next] && !blocked(next) {
                        seen[next] = true;
                        parent[next] = Some(at);
                        queue.push_back(next);
                    }
                }
            }
            if let Some(mut at) = hit {
                let mut path = vec![nodes[at].name.clone()];
                while let Some(p) = parent[at] {
                    path.push(nodes[p].name.clone());
                    at = p;
                }
                path.reverse();
                out.push(v(
                    &nodes[root].name,
                    "reach",
                    format!(
                        "Cargo.lock ({label}): `{}` reaches `{target}` other than through `{via}`: {}",
                        nodes[root].name,
                        path.join(" -> ")
                    ),
                ));
            }
        }
    }
}

/// Rule `confined` over the workspace metadata: no package outside a confined crate's allowed list
/// declares it in any dependency kind, target-specific or renamed (cargo reports the real
/// package name in `Dependency::name`). Transitive pulls through third-party crates are caught by
/// [`check_confined_entry`] in the lock files.
fn check_confined_metadata(md: &Metadata, out: &mut Vec<Violation>) {
    for pkg in &md.packages {
        for dep in &pkg.dependencies {
            let Some((_, allowed)) = CONFINED.iter().find(|(c, _)| *c == dep.name.as_str()) else {
                continue;
            };
            if !allowed.contains(&pkg.name.as_str()) {
                out.push(v(
                    &pkg.name,
                    "confined",
                    format!(
                        "depends on the confined crate `{}`; only {} may",
                        dep.name,
                        allowed.join(", ")
                    ),
                ));
            }
        }
    }
}

/// Rule `exact-pin`: each `EXACT_PINS` package that is a workspace member declares the dependency,
/// and every declaration of it carries exactly the pinned requirement.
fn check_exact_pins(md: &Metadata, out: &mut Vec<Violation>) {
    for (package, dependency, req) in EXACT_PINS {
        let Some(pkg) = md.packages.iter().find(|p| p.name.as_str() == *package) else {
            continue;
        };
        let reqs: Vec<String> = pkg
            .dependencies
            .iter()
            .filter(|d| d.name.as_str() == *dependency)
            .map(|d| d.req.to_string())
            .collect();
        if reqs.is_empty() {
            out.push(v(
                package,
                "exact-pin",
                format!("must depend on `{dependency}` with the requirement `{req}`"),
            ));
        }
        for got in reqs.iter().filter(|r| r.as_str() != *req) {
            out.push(v(
                package,
                "exact-pin",
                format!("`{dependency}` requirement is `{got}`, must be exactly `{req}`"),
            ));
        }
    }
}

/// Rule `confined` over one `[[package]]` entry of a lock file: every `dependencies` entry (a
/// string whose first space-separated token is the package name) naming a confined crate must come
/// from an allowed dependent that has no `source` and is a member of that lock. A `dependencies`
/// value that is not an array of strings fails closed.
fn check_confined_entry(
    label: &str,
    name: &str,
    table: &toml::Table,
    members: &BTreeSet<(String, String)>,
    out: &mut Vec<Violation>,
) {
    let Some(deps) = table.get("dependencies") else {
        return;
    };
    let Some(deps) = deps.as_array() else {
        out.push(v(
            name,
            "confined",
            format!("Cargo.lock ({label}): `dependencies` of `{name}` is not an array"),
        ));
        return;
    };
    let version = table.get("version").and_then(|x| x.as_str()).unwrap_or("");
    for dep in deps {
        let Some(dep) = dep.as_str() else {
            out.push(v(
                name,
                "confined",
                format!("Cargo.lock ({label}): a `dependencies` entry of `{name}` is not a string"),
            ));
            continue;
        };
        let token = dep.split(' ').next().unwrap_or("");
        let Some((_, allowed)) = CONFINED.iter().find(|(c, _)| *c == token) else {
            continue;
        };
        let source_less_member = !table.contains_key("source")
            && members.contains(&(name.to_string(), version.to_string()));
        if !(allowed.contains(&name) && source_less_member) {
            out.push(v(
                name,
                "confined",
                format!(
                    "Cargo.lock ({label}): `{name}` {version} depends on the confined crate `{token}`; only {} (a workspace member) may",
                    allowed.join(", ")
                ),
            ));
        }
    }
}

/// The fuzz manifest's dependencies: every one is a crates.io requirement or a `path` dependency
/// on a workspace member of this repository (same package name, same directory). A `git`,
/// `registry` or `workspace` key, a path anywhere else and any form this check does not recognise
/// is a violation.
fn check_fuzz_deps(
    md: &Metadata,
    fuzz: &ProbeCrate,
    member_dirs: &BTreeMap<&str, PathBuf>,
    out: &mut Vec<Violation>,
) {
    let fuzz_dir = md.workspace_root.as_std_path().join("fuzz");
    let mut tables: Vec<(String, &toml::Value)> = Vec::new();
    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = fuzz.manifest.get(kind) {
            tables.push((kind.to_string(), t));
        }
    }
    if let Some(targets) = fuzz.manifest.get("target") {
        match targets.as_table() {
            Some(targets) => {
                for (cfg, body) in targets {
                    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
                        if let Some(t) = body.get(kind) {
                            tables.push((format!("target.{cfg}.{kind}"), t));
                        }
                    }
                }
            }
            None => out.push(v(&fuzz.label, "fuzz-dep", "`target` is not a table")),
        }
    }
    for (table_name, table) in tables {
        let Some(table) = table.as_table() else {
            out.push(v(
                &fuzz.label,
                "fuzz-dep",
                format!("[{table_name}] is not a table"),
            ));
            continue;
        };
        for (key, dep) in table {
            match dep {
                toml::Value::String(_) => {}
                toml::Value::Table(t) => check_fuzz_dep_table(key, t, &fuzz_dir, member_dirs, out),
                _ => out.push(v(
                    key,
                    "fuzz-dep",
                    format!("[{table_name}] `{key}` has a form this check does not recognise"),
                )),
            }
        }
    }
}

fn check_fuzz_dep_table(
    key: &str,
    dep: &toml::Table,
    fuzz_dir: &Path,
    member_dirs: &BTreeMap<&str, PathBuf>,
    out: &mut Vec<Violation>,
) {
    for banned in ["git", "registry", "registry-index", "workspace"] {
        if dep.contains_key(banned) {
            out.push(v(
                key,
                "fuzz-dep",
                format!("fuzz dependency `{key}` uses `{banned}`: only crates.io and workspace paths are allowed"),
            ));
            return;
        }
    }
    let Some(path) = dep.get("path") else {
        return;
    };
    let real_name = match dep.get("package") {
        None => key,
        Some(toml::Value::String(name)) => name.as_str(),
        Some(_) => {
            out.push(v(key, "fuzz-dep", "`package` is not a string"));
            return;
        }
    };
    let Some(path) = path.as_str() else {
        out.push(v(key, "fuzz-dep", "`path` is not a string"));
        return;
    };
    let resolved = fuzz_dir.join(path);
    if !member_dirs
        .get(real_name)
        .is_some_and(|member| same_dir(&resolved, member))
    {
        out.push(v(
            key,
            "fuzz-dep",
            format!("fuzz dependency `{key}` has path `{path}`, which is not the workspace member `{real_name}`"),
        ));
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
        check_confined_entry(label, name, table, members, out);
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

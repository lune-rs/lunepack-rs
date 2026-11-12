//! Denylist scan (D29, M1-D7).
//!
//! A private, per-developer list of fixed strings must not appear in this public repo's
//! tracked content, tracked paths, or commit history. One matcher is used everywhere:
//! a line hits a rule when every `&&`-separated term occurs in it as a case-insensitive
//! fixed substring. This module never prints a term, a rule's text or a matched line:
//! reports carry only locations (`path:line`, commit ids) and rule numbers, and a path
//! that itself matches a rule is shown as `<redacted path #k>`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};

/// Stderr notice when the default denylist path does not exist.
pub const NOTICE_ABSENT: &str = "denylist not found; scan skipped";

/// Command line of `xtask denylist-scan`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Args {
    pub require_denylist: bool,
    pub range: Option<String>,
    pub repo: Option<PathBuf>,
}

/// Parse `[--require-denylist] [--range <a>..<b>] [--repo <dir>]`.
pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut out = Args::default();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--require-denylist" => out.require_denylist = true,
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
                "unknown argument (usage: denylist-scan [--require-denylist] [--range <a>..<b>] [--repo <dir>])"
            ),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Rule {
    /// 1-based physical line number in the denylist file.
    id: usize,
    /// Lowercased, trimmed, non-empty terms; all must occur.
    terms: Vec<String>,
}

/// A parsed denylist.
#[derive(Debug, Clone, Default)]
pub struct Rules(Vec<Rule>);

impl Rules {
    /// Parse a denylist file's bytes. Errors name the line number only.
    pub fn parse(bytes: &[u8]) -> Result<Rules> {
        let text = match std::str::from_utf8(bytes) {
            Ok(t) => t,
            Err(e) => {
                let line = bytes[..e.valid_up_to()]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count()
                    + 1;
                bail!("denylist is not valid UTF-8 (line {line})");
            }
        };
        // A leading byte-order mark would silently break rule 1; drop it.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut rules = Vec::new();
        for (idx, raw) in text.split('\n').enumerate() {
            let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut terms = Vec::new();
            for term in line.split("&&") {
                let term = term.trim();
                if term.is_empty() {
                    bail!("denylist line {}: empty term", idx + 1);
                }
                terms.push(term.to_lowercase());
            }
            rules.push(Rule { id: idx + 1, terms });
        }
        Ok(Rules(rules))
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are no rules.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True when the text contains any single term of any rule (case-insensitively). Used to
    /// decide what may be printed: a text that merely contains one term of a multi-term rule
    /// would still tell the reader which word is on the list.
    pub fn mentions_any_term(&self, text: &str) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let lower = text.to_lowercase();
        let stripped: String = lower.chars().filter(|c| *c != '\0').collect();
        self.0
            .iter()
            .flat_map(|r| r.terms.iter())
            .any(|t| lower.contains(t.as_str()) || stripped.contains(t.as_str()))
    }

    /// Ids of the rules the line hits (every term a substring, case-insensitively).
    pub fn hits(&self, line: &str) -> Vec<usize> {
        if self.0.is_empty() {
            return Vec::new();
        }
        let lower = line.to_lowercase();
        self.0
            .iter()
            .filter(|r| r.terms.iter().all(|t| lower.contains(t.as_str())))
            .map(|r| r.id)
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// Hits and reporting
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Loc {
    Line {
        path: String,
        line: usize,
    },
    Path(String),
    CommitObject {
        sha: String,
        line: usize,
    },
    CommitPath {
        sha: String,
        path: String,
    },
    CommitLine {
        sha: String,
        path: String,
        line: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Hit {
    loc: Loc,
    rule: usize,
}

fn clean(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn shown_path(rules: &Rules, path: &str, k: usize) -> String {
    if !rules.mentions_any_term(path) {
        clean(path)
    } else {
        format!("<redacted path #{k}>")
    }
}

fn render(rules: &Rules, hit: &Hit, k: usize) -> String {
    let loc = match &hit.loc {
        Loc::Line { path, line } => format!("{}:{line}", shown_path(rules, path, k)),
        Loc::Path(path) => format!("path {}", shown_path(rules, path, k)),
        Loc::CommitObject { sha, line } => format!("commit {sha} object line {line}"),
        Loc::CommitPath { sha, path } => {
            format!("commit {sha} path {}", shown_path(rules, path, k))
        }
        Loc::CommitLine { sha, path, line } => {
            format!("commit {sha} {}:{line}", shown_path(rules, path, k))
        }
    };
    format!("denylist: {loc}: rule {}", hit.rule)
}

/// Collects hits in discovery order, without duplicates.
struct Scan<'a> {
    rules: &'a Rules,
    hits: Vec<Hit>,
    seen: HashSet<Hit>,
}

impl<'a> Scan<'a> {
    fn new(rules: &'a Rules) -> Self {
        Scan {
            rules,
            hits: Vec::new(),
            seen: HashSet::new(),
        }
    }

    fn push(&mut self, loc: Loc, rule: usize) {
        let hit = Hit { loc, rule };
        if self.seen.insert(hit.clone()) {
            self.hits.push(hit);
        }
    }

    /// Match one line; record a hit for each rule it satisfies. A line holding NUL bytes is
    /// also matched with the NULs removed, which exposes ASCII text in UTF-16 (LE or BE,
    /// whatever the line splitting) that the lossy UTF-8 view interleaves with NULs.
    fn line(&mut self, text: &str, loc: impl Fn() -> Loc) {
        for rule in self.rules.hits(text) {
            self.push(loc(), rule);
        }
        if text.contains('\0') {
            let stripped: String = text.chars().filter(|c| *c != '\0').collect();
            for rule in self.rules.hits(&stripped) {
                self.push(loc(), rule);
            }
        }
    }

    /// Match every line of `bytes` (split on `\n`, trailing `\r` removed) as lossy UTF-8 plus
    /// the NUL-stripped view of each line (see `line`). Content with a UTF-16 byte-order mark
    /// is also decoded as UTF-16, so non-ASCII terms match there too; both views always run,
    /// so a file that merely starts with those bytes loses nothing.
    fn bytes(&mut self, bytes: &[u8], loc: impl Fn(usize) -> Loc) {
        self.text(&String::from_utf8_lossy(bytes), &loc);
        if let Some(decoded) = decode_utf16_bom(bytes) {
            self.text(&decoded, &loc);
        }
    }

    fn text(&mut self, text: &str, loc: &impl Fn(usize) -> Loc) {
        for (idx, raw) in text.split('\n').enumerate() {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            self.line(line, || loc(idx + 1));
        }
    }
}

/// Decode content that starts with a UTF-16 byte-order mark (`FF FE` little-endian, `FE FF`
/// big-endian); `None` for anything else.
fn decode_utf16_bom(bytes: &[u8]) -> Option<String> {
    let (le, body) = match bytes {
        [0xFF, 0xFE, rest @ ..] => (true, rest),
        [0xFE, 0xFF, rest @ ..] => (false, rest),
        _ => return None,
    };
    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if le {
                u16::from_le_bytes(*c)
            } else {
                u16::from_be_bytes(*c)
            }
        })
        .collect();
    Some(String::from_utf16_lossy(&units))
}

// ---------------------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------------------

struct Git<'a> {
    dir: PathBuf,
    rules: &'a Rules,
}

impl Git<'_> {
    /// Run git (argv only, no shell, no prompts); any failure is an error that never
    /// echoes arguments or unscrubbed stderr.
    fn run(&self, what: &str, args: &[&str]) -> Result<Vec<u8>> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .with_context(|| format!("cannot run git {what}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let first = stderr.lines().next().unwrap_or("").trim();
            let first = if self.rules.mentions_any_term(first) {
                "<suppressed: contains a denylist term>".to_string()
            } else {
                first.chars().take(200).collect::<String>()
            };
            bail!("git {what} failed ({}): {first}", out.status);
        }
        Ok(out.stdout)
    }
}

fn os_path(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

// ---------------------------------------------------------------------------------------
// Denylist location
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The path to try, if any can be derived.
    pub path: Option<PathBuf>,
    /// True when `LUNEPACK_DENYLIST` named it.
    pub explicit: bool,
}

fn non_empty(v: Option<OsString>) -> Option<OsString> {
    v.filter(|v| !v.is_empty())
}

/// Resolve the denylist path from the given environment lookups.
pub fn resolve_location(get: impl Fn(&str) -> Option<OsString>) -> Location {
    if let Some(p) = non_empty(get("LUNEPACK_DENYLIST")) {
        return Location {
            path: Some(PathBuf::from(p)),
            explicit: true,
        };
    }
    let rel = Path::new("lunepack-rs").join("denylist.txt");
    if let Some(x) = non_empty(get("XDG_CONFIG_HOME")) {
        return Location {
            path: Some(PathBuf::from(x).join(rel)),
            explicit: false,
        };
    }
    if let Some(h) = non_empty(get("HOME")) {
        return Location {
            path: Some(PathBuf::from(h).join(".config").join(rel)),
            explicit: false,
        };
    }
    Location {
        path: None,
        explicit: false,
    }
}

// ---------------------------------------------------------------------------------------
// Tree scan
// ---------------------------------------------------------------------------------------

fn scan_tree(git: &Git, top: &Path, scan: &mut Scan) -> Result<()> {
    let listing = git.run("ls-files", &["ls-files", "-s", "-z"])?;
    for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let tab = entry
            .iter()
            .position(|b| *b == b'\t')
            .ok_or_else(|| anyhow!("unrecognised `git ls-files -s` entry"))?;
        let meta = String::from_utf8_lossy(&entry[..tab]).into_owned();
        let path_bytes = &entry[tab + 1..];
        let path = String::from_utf8_lossy(path_bytes).into_owned();
        let mut parts = meta.split(' ');
        let (Some(mode), Some(sha), Some(_stage), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("unrecognised `git ls-files -s` entry");
        };
        if mode == "160000" {
            let shown = if scan.rules.mentions_any_term(&path) {
                "<redacted>".to_string()
            } else {
                clean(&path)
            };
            bail!("tracked gitlink (submodule) entry cannot be scanned: {shown}");
        }

        scan.line(&path, || Loc::Path(path.clone()));

        let fs_path = top.join(os_path(path_bytes));
        let content: Vec<u8> = match std::fs::symlink_metadata(&fs_path) {
            Ok(m) if m.file_type().is_symlink() => {
                let target = std::fs::read_link(&fs_path)
                    .map_err(|e| anyhow!("cannot read a tracked symlink: {}", e.kind()))?;
                target.to_string_lossy().into_owned().into_bytes()
            }
            Ok(m) if m.is_file() => std::fs::read(&fs_path)
                .map_err(|e| anyhow!("cannot read a tracked file: {}", e.kind()))?,
            Ok(_) => git.run("cat-file", &["cat-file", "blob", sha])?,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                git.run("cat-file", &["cat-file", "blob", sha])?
            }
            Err(e) => bail!("cannot stat a tracked file: {}", e.kind()),
        };
        scan.bytes(&content, |line| Loc::Line {
            path: path.clone(),
            line,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Range scan
// ---------------------------------------------------------------------------------------

fn parse_count(spec: &str) -> Option<(usize, usize)> {
    let mut it = spec.splitn(2, ',');
    let start = it.next()?.parse().ok()?;
    let count = match it.next() {
        Some(c) => c.parse().ok()?,
        None => 1,
    };
    Some((start, count))
}

/// `@@ -a[,b] +c[,d] @@ ...` -> (b, c, d)
fn parse_hunk_header(line: &str) -> Option<(usize, usize, usize)> {
    let rest = line.strip_prefix("@@ ")?;
    let end = rest.find(" @@")?;
    let mut it = rest[..end].split(' ');
    let old = it.next()?.strip_prefix('-')?;
    let new = it.next()?.strip_prefix('+')?;
    if it.next().is_some() {
        return None;
    }
    let (_, minus) = parse_count(old)?;
    let (start, plus) = parse_count(new)?;
    Some((minus, start, plus))
}

/// Decode a git C-quoted path (`"..."`) into bytes.
fn unquote_c(s: &[u8]) -> Option<Vec<u8>> {
    let inner = s.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < inner.len() {
        let b = inner[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        i += 1;
        let e = *inner.get(i)?;
        match e {
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'0'..=b'3' => {
                let oct = inner.get(i..i + 3)?;
                if !oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                    return None;
                }
                let v = oct
                    .iter()
                    .fold(0u32, |acc, c| acc * 8 + u32::from(c - b'0'));
                out.push(u8::try_from(v).ok()?);
                i += 2;
            }
            _ => return None,
        }
        i += 1;
    }
    Some(out)
}

/// The new-side path of a `+++ ` header (without the `b/` prefix); `None` for `/dev/null`.
fn parse_new_path(rest: &[u8]) -> Result<Option<String>> {
    // git appends one TAB to the header when the name contains a space, quoted or not; a
    // quoted name never ends in a raw TAB (git writes it as `\t`).
    let rest = rest.strip_suffix(b"\t").unwrap_or(rest);
    if rest == b"/dev/null" {
        return Ok(None);
    }
    let bytes = if rest.starts_with(b"\"") {
        unquote_c(rest).ok_or_else(|| anyhow!("unrecognised quoted path in a diff header"))?
    } else {
        rest.to_vec()
    };
    let bytes = bytes
        .strip_prefix(b"b/")
        .ok_or_else(|| anyhow!("unrecognised path prefix in a diff header"))?;
    Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
}

struct Hunk {
    minus: usize,
    plus: usize,
    next_new_line: usize,
}

/// Parse `git diff-tree -p` output for one commit and match every added line.
fn scan_patch(sha: &str, patch: &[u8], scan: &mut Scan) -> Result<()> {
    const HEADERS: &[&[u8]] = &[
        b"diff --git ",
        b"index ",
        b"old mode ",
        b"new mode ",
        b"new file mode ",
        b"deleted file mode ",
        b"similarity index ",
        b"dissimilarity index ",
        b"rename from ",
        b"rename to ",
        b"copy from ",
        b"copy to ",
        b"Binary files ",
        b"--- ",
    ];
    let mut path: Option<String> = None;
    let mut hunk: Option<Hunk> = None;
    let mut lines: Vec<&[u8]> = patch.split(|b| *b == b'\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    for line in lines {
        if let Some(h) = hunk.as_mut() {
            if line.starts_with(b"\\ ") {
                continue;
            }
            if h.minus > 0 {
                if !line.starts_with(b"-") {
                    bail!("commit {sha}: unrecognised diff line inside a hunk");
                }
                h.minus -= 1;
                continue;
            }
            if h.plus > 0 {
                let Some(content) = line.strip_prefix(b"+") else {
                    bail!("commit {sha}: unrecognised diff line inside a hunk");
                };
                let Some(p) = path.clone() else {
                    bail!("commit {sha}: added line without a file path");
                };
                let n = h.next_new_line;
                h.next_new_line += 1;
                h.plus -= 1;
                let text = String::from_utf8_lossy(content);
                let text = text.strip_suffix('\r').unwrap_or(&text);
                scan.line(text, || Loc::CommitLine {
                    sha: sha.to_string(),
                    path: p.clone(),
                    line: n,
                });
                continue;
            }
            hunk = None;
        }
        if let Some(rest) = line.strip_prefix(b"+++ ") {
            path = parse_new_path(rest).with_context(|| format!("commit {sha}"))?;
        } else if line.starts_with(b"@@ ") {
            let text = String::from_utf8_lossy(line);
            let (minus, start, plus) = parse_hunk_header(&text)
                .ok_or_else(|| anyhow!("commit {sha}: unrecognised hunk header"))?;
            hunk = Some(Hunk {
                minus,
                plus,
                next_new_line: start,
            });
        } else if HEADERS.iter().any(|h| line.starts_with(h)) {
            if line.starts_with(b"diff --git ") {
                path = None;
            }
        } else {
            bail!("commit {sha}: unrecognised diff line");
        }
    }
    Ok(())
}

fn scan_commit(git: &Git, sha: &str, scan: &mut Scan) -> Result<()> {
    let short: String = sha.chars().take(12).collect();

    let object = git.run("cat-file", &["cat-file", "commit", sha])?;
    scan.bytes(&object, |k| Loc::CommitObject {
        sha: short.clone(),
        line: k,
    });

    let names = git.run(
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
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let name = String::from_utf8_lossy(name).into_owned();
        scan.line(&name, || Loc::CommitPath {
            sha: short.clone(),
            path: name.clone(),
        });
    }

    let patch = git.run(
        "diff-tree",
        &[
            "-c",
            "core.quotePath=false",
            "diff-tree",
            "-p",
            "-a",
            "-r",
            "-m",
            "--root",
            "--no-renames",
            "--no-commit-id",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=0",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            sha,
        ],
    )?;
    scan_patch(&short, &patch, scan)
}

fn scan_range(git: &Git, range: &str, scan: &mut Scan) -> Result<()> {
    let list = git.run("rev-list", &["rev-list", "--end-of-options", range])?;
    for sha in String::from_utf8_lossy(&list)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        scan_commit(git, sha, scan)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------------------

/// Outcome of a run: clean/skipped (0) or hits (1). Errors are `Err` (exit 2).
pub fn run(args: &Args, get_env: impl Fn(&str) -> Option<OsString>) -> Result<u8> {
    let location = resolve_location(get_env);

    let Some(path) = location.path.clone() else {
        if args.require_denylist {
            bail!("--require-denylist set but no denylist location can be derived (no HOME)");
        }
        eprintln!("denylist: {NOTICE_ABSENT}");
        return Ok(0);
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if location.explicit || args.require_denylist {
                bail!("denylist not found at {}", path.display());
            }
            eprintln!("denylist: {NOTICE_ABSENT}");
            return Ok(0);
        }
        Err(e) => bail!("cannot read denylist at {}: {}", path.display(), e.kind()),
    };
    warn_if_loose_permissions(&path);
    let rules = Rules::parse(&bytes)?;

    let repo = match &args.repo {
        Some(r) => r.clone(),
        None => std::env::current_dir().context("cannot determine the current directory")?,
    };
    let git = Git {
        dir: repo,
        rules: &rules,
    };
    let top = abs_git_path(&git, "show-toplevel", "--show-toplevel")?;
    let common = abs_git_path(&git, "git-common-dir", "--git-common-dir")?;
    let main_checkout = common
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| common.clone());
    let canon = crate::paths::canonicalize(&path)
        .with_context(|| format!("cannot resolve denylist path {}", path.display()))?;
    if canon.starts_with(&top) || canon.starts_with(&main_checkout) {
        bail!(
            "the denylist at {} lies inside the repository; move it out",
            path.display()
        );
    }

    if rules.is_empty() {
        if args.require_denylist {
            bail!("--require-denylist set but the denylist has no rules");
        }
        eprintln!("denylist: denylist has no rules; scan skipped");
        return Ok(0);
    }

    let git = Git {
        dir: top.clone(),
        rules: &rules,
    };
    let mut scan = Scan::new(&rules);
    scan_tree(&git, &top, &mut scan)?;
    if let Some(range) = &args.range {
        scan_range(&git, range, &mut scan)?;
    }

    for (idx, hit) in scan.hits.iter().enumerate() {
        println!("{}", render(&rules, hit, idx + 1));
    }
    eprintln!("denylist: {} rules, {} hits", rules.len(), scan.hits.len());
    Ok(u8::from(!scan.hits.is_empty()))
}

fn abs_git_path(git: &Git, what: &str, flag: &str) -> Result<PathBuf> {
    let out = git.run(what, &["rev-parse", "--path-format=absolute", flag])?;
    let text = String::from_utf8_lossy(&out);
    let line = text.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        bail!("git rev-parse {what} returned nothing");
    }
    crate::paths::canonicalize(&PathBuf::from(line))
        .with_context(|| format!("cannot resolve the repository {what}"))
}

#[cfg(unix)]
fn warn_if_loose_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        eprintln!("denylist: warning: the denylist is accessible to group/other (chmod 600 it)");
    }
}

#[cfg(not(unix))]
fn warn_if_loose_permissions(_path: &Path) {}

/// Entry point for `xtask denylist-scan`: exit 0 clean or skipped, 1 hits, 2 error.
pub fn main(args: impl IntoIterator<Item = String>) -> ExitCode {
    // Keep panic payloads (which could carry content) out of the output.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("denylist: error: internal error (details suppressed)");
    }));
    let args: Vec<String> = args.into_iter().collect();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let args = parse_args(args)?;
        run(&args, |k| std::env::var_os(k))
    }));
    match outcome {
        Ok(Ok(code)) => ExitCode::from(code),
        Ok(Err(err)) => {
            eprintln!("denylist: error: {err:#}");
            ExitCode::from(2)
        }
        Err(_) => ExitCode::from(2),
    }
}

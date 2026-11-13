//! Differential test of the core path rules (FORMAT.md 10.1, 10.2) against the real filesystem of
//! the host (APFS on macOS, ext4 or tmpfs on Linux, NTFS on Windows).
//!
//! Accepted names must round-trip exactly and never alias each other. Rejected colliding pairs are
//! created only to show what the filesystem does; an over-reject never fails the test. Device names
//! are never created (opening `COM1` on Windows can hang).

#![cfg(any(target_os = "macos", target_os = "linux", windows))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;

use lunepack_core::path::{EntryKind, RelPath, validate_path, validate_tree};
use lunepack_core::target::Target;

#[cfg(target_os = "macos")]
const HOST: (&str, Target) = ("macOS (APFS)", Target::MacosAarch64);
#[cfg(target_os = "linux")]
const HOST: (&str, Target) = ("Linux", Target::LinuxX86_64);
#[cfg(windows)]
const HOST: (&str, Target) = ("Windows (NTFS)", Target::WindowsX86_64);

/// Paths the rules accept; together they form one valid tree.
fn accepted_corpus() -> Vec<String> {
    let mut corpus: Vec<String> = [
        "bin/app",
        "Contents/MacOS/App",
        "a b/c.d.e",
        "ünïcode/文件",
        "CONSOLE",
        "nul1.txt",
        "com10",
        "COM¹x",
        "Straße",
        "café.txt",
        "日本語.txt",
        "emoji 😀",
        ".hidden",
        "a.b c",
        "ǆ",
        "x~y",
        "Ωmega",
        "İstanbul",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    corpus.push("a".repeat(255));
    corpus.push(format!("{}a", "é".repeat(127)));
    corpus
}

/// The corpus as tree entries: every proper prefix a directory, every corpus path a file.
fn entries(corpus: &[String]) -> BTreeMap<String, bool /* is_dir */> {
    let mut out = BTreeMap::new();
    for p in corpus {
        let comps: Vec<&str> = p.split('/').collect();
        for i in 1..comps.len() {
            out.insert(comps[..i].join("/"), true);
        }
        out.insert(p.clone(), false);
    }
    out
}

fn create_new_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(content)
}

/// Names in `dir` exactly as `read_dir` reports them.
fn listed(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let name = e.unwrap().file_name();
            name.into_string()
                .unwrap_or_else(|n| panic!("non-Unicode name read back: {n:?}"))
        })
        .collect()
}

#[test]
fn accepted_names_round_trip_and_never_alias() {
    let corpus = accepted_corpus();
    let tree = entries(&corpus);
    let paths: Vec<(RelPath, bool)> = tree
        .iter()
        .map(|(p, is_dir)| {
            let rel = validate_path(p).unwrap_or_else(|e| panic!("{p:?} rejected: {e}"));
            (rel, *is_dir)
        })
        .collect();
    validate_tree(
        paths.iter().map(|(p, is_dir)| {
            (
                p,
                if *is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
            )
        }),
        HOST.1,
    )
    .expect("the corpus is one valid tree");

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // `create_new` and `create_dir` fail if the name already resolves to an entry, so an alias
    // between two accepted names shows up as `AlreadyExists` here.
    for (p, is_dir) in &tree {
        let full = root.join(p);
        let made = if *is_dir {
            fs::create_dir(&full)
        } else {
            create_new_file(&full, p.as_bytes())
        };
        made.unwrap_or_else(|e| panic!("{}: creating {p:?} failed: {e}", HOST.0));
    }

    // Every directory lists exactly the expected names, byte for byte.
    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    children.insert(String::new(), BTreeSet::new());
    for (p, is_dir) in &tree {
        let (parent, name) = p.rsplit_once('/').unwrap_or(("", p));
        children
            .entry(parent.to_owned())
            .or_default()
            .insert(name.to_owned());
        if *is_dir {
            children.entry(p.clone()).or_default();
        }
    }
    for (dir, want) in &children {
        let got = listed(&root.join(dir));
        assert_eq!(&got, want, "{}: listing of {dir:?}", HOST.0);
    }
    // Every file still holds its own path: nothing was overwritten through an alias.
    for (p, is_dir) in &tree {
        if !is_dir {
            assert_eq!(fs::read(root.join(p)).unwrap(), p.as_bytes(), "{p:?}");
        }
    }
}

/// Pairs the rules reject because they can collide on some filesystem. The second name of each
/// pair is rejected by the path rules or the pair by the tree rules.
const COLLIDING: &[(&str, &str)] = &[
    ("A", "a"),
    ("Straße", "STRASSE"),
    ("k", "\u{212A}"), // KELVIN SIGN: not NFC, folds to `k`
    ("é", "e\u{301}"), // NFC and NFD: APFS treats them as one name
    ("ẞ", "ß"),        // capital sharp s: APFS folds it to ss
    ("ẞ", "ss"),
    ("ß", "ss"),
    ("Ω", "\u{2126}"),                    // OHM SIGN: not NFC
    ("x", "x."),                          // Win32 strips a trailing dot
    ("y", "y "),                          // and a trailing space
    ("longfilename.txt", "LONGFI~1.TXT"), // an 8.3 short name where NTFS makes them
];

fn pair_rejected(a: &str, b: &str) -> bool {
    let (Ok(pa), Ok(pb)) = (validate_path(a), validate_path(b)) else {
        return true;
    };
    validate_tree([(&pa, EntryKind::File), (&pb, EntryKind::File)], HOST.1).is_err()
}

#[test]
fn colliding_pairs_are_rejected_and_their_collisions_are_shown() {
    let tmp = tempfile::tempdir().unwrap();
    for (i, (a, b)) in COLLIDING.iter().enumerate() {
        validate_path(a).unwrap_or_else(|e| panic!("{a:?} should be accepted: {e}"));
        assert!(pair_rejected(a, b), "{a:?} and {b:?} should be rejected");

        // Demonstration only: whatever the filesystem does here, the rules already said no.
        let dir = tmp.path().join(i.to_string());
        fs::create_dir(&dir).unwrap();
        create_new_file(&dir.join(a), b"a").unwrap();
        let outcome = match create_new_file(&dir.join(b), b"b") {
            Ok(()) => format!("distinct ({} entries)", listed(&dir).len()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => "aliases".to_owned(),
            Err(e) => format!("refused: {e}"),
        };
        eprintln!("{}: {a:?} / {b:?}: {outcome}", HOST.0);
    }
}

//! Step 5 contract: the shared rules of FORMAT.md section 10 (paths, trees, versions, targets, app
//! ids, channels).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use lunepack_core::ident::{AppId, Channel, IdentError};
use lunepack_core::path::{
    EntryKind, LinkTargetError, PathError, RelPath, TreeError, fold_key, validate_path,
    validate_tree,
};
use lunepack_core::target::Target;
use lunepack_core::version::{Version, VersionError};
use unicode_normalization::UnicodeNormalization;

// ---- paths (FORMAT.md 10.1) ----

#[track_caller]
fn rejects(path: &str) -> PathError {
    match validate_path(path) {
        Err(e) => e,
        Ok(p) => panic!("{p:?} should be rejected"),
    }
}

#[track_caller]
fn accepts(path: &str) {
    let p = validate_path(path).unwrap_or_else(|e| panic!("{path:?} rejected: {e}"));
    assert_eq!(p.as_str(), path);
}

#[test]
fn path_accepts_the_format_examples() {
    for p in [
        "bin/app",
        "Contents/MacOS/App",
        "a b/c.d.e",
        "ünïcode/文件",
        "CONSOLE",
        "nul1.txt",
        "com10",
        "COM¹x",
        "LPT",
        "~a",
        "a~",
        "a~b1",
        ".hidden",
        "a.b c",
    ] {
        accepts(p);
    }
    accepts(&"a".repeat(255));
    // 255 bytes of multi-byte text.
    accepts(&format!("{}a", "é".repeat(127)));
    // Exactly 1024 bytes: 5 components of 204 bytes and 4 separators.
    let long = vec!["b".repeat(204); 5].join("/");
    assert_eq!(long.len(), 1024);
    accepts(&long);
    // Exactly 32 components.
    accepts(&vec!["d"; 32].join("/"));
}

#[test]
fn path_length_depth_and_component_caps() {
    assert_eq!(rejects(""), PathError::Empty);
    let long = format!("{}/x", vec!["b".repeat(204); 5].join("/"));
    assert!(matches!(rejects(&long), PathError::TooLong { len: 1026 }));
    assert_eq!(rejects(&vec!["d"; 33].join("/")), PathError::TooDeep);
    assert!(matches!(
        rejects(&format!("ok/{}", "a".repeat(256))),
        PathError::ComponentTooLong { index: 1, len: 256 }
    ));
    assert!(matches!(
        rejects(&"é".repeat(128)),
        PathError::ComponentTooLong { len: 256, .. }
    ));
}

#[test]
fn path_rejects_non_nfc() {
    assert_eq!(rejects("e\u{301}"), PathError::NotNfc);
    assert_eq!(rejects("dir/A\u{30A}"), PathError::NotNfc);
}

#[test]
fn path_rejects_absolute_empty_and_dot_components() {
    assert_eq!(rejects("/a"), PathError::Absolute);
    assert_eq!(rejects("/"), PathError::Absolute);
    assert_eq!(rejects("a//b"), PathError::EmptyComponent { index: 1 });
    assert_eq!(rejects("a/"), PathError::EmptyComponent { index: 1 });
    for p in [".", "..", "a/.", "a/..", "a/./b", "a/../b", "../a"] {
        assert!(
            matches!(rejects(p), PathError::DotComponent { .. }),
            "{p:?}"
        );
    }
}

#[test]
fn path_rejects_forbidden_characters() {
    let mut bad: Vec<String> = ["\\", "\u{7f}", "<", ">", ":", "\"", "|", "?", "*"]
        .iter()
        .map(|c| format!("a{c}b"))
        .collect();
    for c in 0u8..0x20 {
        bad.push(format!("a{}b", c as char));
    }
    for p in &bad {
        assert!(
            matches!(rejects(p), PathError::ForbiddenChar { .. }),
            "{p:?}"
        );
    }
    // Drive letters, verbatim and UNC forms, NTFS alternate data streams.
    for p in [
        "C:/x",
        "C:x",
        "c:",
        "\\\\?\\C:\\x",
        "\\\\server\\share\\x",
        "//server/share",
        "file.txt:stream",
        "file.txt::$DATA",
        "dir\\..\\x",
    ] {
        let e = rejects(p);
        assert!(
            matches!(e, PathError::ForbiddenChar { .. } | PathError::Absolute),
            "{p:?}: {e:?}"
        );
    }
}

#[test]
fn path_rejects_trailing_dot_or_space() {
    for p in ["a.", "a ", "dir./x", "dir /x", "x/y..", "a. "] {
        assert!(
            matches!(rejects(p), PathError::TrailingDotOrSpace { .. }),
            "{p:?}"
        );
    }
}

#[test]
fn path_rejects_windows_device_names() {
    let mut names: Vec<String> = [
        "CON",
        "con",
        "Con.txt",
        "CON .txt",
        "CON  .a.b",
        "PRN",
        "aux",
        "NUL",
        "nul.tar.gz",
        "CONIN$",
        "conout$",
        "Conin$.log",
        "COM¹",
        "com²",
        "COM³.txt",
        "LPT¹",
        "lpt².x",
        "lpt¹.log",
        "dir/aux.c",
        "a/b/Com1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for d in 0..=9 {
        names.push(format!("COM{d}"));
        names.push(format!("lpt{d}.bin"));
    }
    for p in &names {
        assert!(matches!(rejects(p), PathError::DeviceName { .. }), "{p:?}");
    }
}

#[test]
fn path_rejects_short_name_look_alikes() {
    for p in ["PROGRA~1", "a~0b", "x/LONGFI~1.TXT", "~9"] {
        assert!(
            matches!(rejects(p), PathError::ShortNameLike { .. }),
            "{p:?}"
        );
    }
}

#[test]
fn path_rejects_compatibility_confusables() {
    for p in [
        "\u{FF0E}\u{FF0E}", // fullwidth full stops
        "\u{FF0E}",
        "\u{2025}",         // two-dot leader -> ".."
        "\u{2024}\u{2024}", // one-dot leaders
        "a\u{FF3C}b",       // fullwidth reverse solidus
        "a\u{FF0F}b",       // fullwidth solidus
        "a\u{FF1A}b",       // fullwidth colon
        "a\u{FE56}",        // small question mark
        "a\u{FF0A}",        // fullwidth asterisk
        "a\u{FF02}",        // fullwidth quotation mark
        "a\u{FF1C}b\u{FF1E}",
        "a\u{FF5C}", // fullwidth vertical line
    ] {
        assert!(
            matches!(rejects(p), PathError::CompatibilityForm { .. }),
            "{p:?}"
        );
    }
}

#[test]
fn path_error_display_is_bounded() {
    let e = rejects(&format!("{}\u{1b}[31m", "x".repeat(10_000)));
    let shown = e.to_string();
    assert!(shown.len() < 100, "{shown}");
    assert!(!shown.contains('\u{1b}'));
    let e = rejects("a\u{1b}b");
    assert!(!e.to_string().contains('\u{1b}'), "{e}");
}

// ---- trees (FORMAT.md 10.2) ----

#[derive(Clone, Copy)]
enum K {
    F,
    D,
    L(&'static str),
}

fn tree(entries: &[(&str, K)], target: Target) -> Result<(), TreeError> {
    let paths: Vec<RelPath> = entries
        .iter()
        .map(|(p, _)| validate_path(p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .collect();
    validate_tree(
        paths.iter().zip(entries).map(|(p, (_, k))| {
            let kind = match k {
                K::F => EntryKind::File,
                K::D => EntryKind::Dir,
                K::L(t) => EntryKind::Symlink { target: t },
            };
            (p, kind)
        }),
        target,
    )
}

const MAC: Target = Target::MacosAarch64;

#[test]
fn tree_accepts_a_normal_tree() {
    tree(
        &[
            ("Contents", K::D),
            ("Contents/MacOS", K::D),
            ("Contents/MacOS/App", K::F),
            ("Versions", K::D),
            ("Versions/A", K::D),
            ("Versions/A/lib", K::F),
            ("Versions/Current", K::L("A")),
            ("lib", K::D),
            ("lib/x.so.1", K::F),
            ("lib/x.so", K::L("x.so.1")),
            ("lib/dangling", K::L("missing/inside")),
            ("lib/up", K::L("../Contents/MacOS/App")),
            ("lib/here", K::L("./x.so.1")),
            ("root", K::L(".")),
            ("a.b", K::F),
            ("a", K::D),
            ("a/b", K::F),
        ],
        MAC,
    )
    .unwrap();
    tree(&[], Target::WindowsX86_64).unwrap();
}

#[test]
fn tree_rejects_case_fold_collisions() {
    for (a, b) in [
        ("A", "a"),
        ("Straße", "STRASSE"),
        ("Straße", "strasse"),
        ("Dir/x", "dir/x"),
        ("dir/X", "Dir/x"),
        ("ǅ", "ǆ"),
        ("ΑΣ", "ας"),
        ("ﬁle", "FILE"),
        ("ẞ", "ß"),
        ("ẞ", "ss"),
        ("Straẞe", "STRASSE"),
        ("Straẞe", "Straße"),
        ("ß", "ss"),
    ] {
        let r = tree(&[(a, K::F), (b, K::F)], MAC);
        assert!(
            matches!(r, Err(TreeError::Collision { .. })),
            "{a:?} {b:?}: {r:?}"
        );
        let r = tree(&[(b, K::D), (a, K::D)], Target::LinuxX86_64);
        assert!(
            matches!(r, Err(TreeError::Collision { .. })),
            "{a:?} {b:?}: {r:?}"
        );
    }
    // U+212A KELVIN SIGN folds to `k`, but it is not NFC, so a tree can never hold it: the path
    // rule rejects it before the tree rule could.
    assert_eq!(fold_key("\u{212A}"), fold_key("k"));
    assert_eq!(fold_key("\u{212A}"), "k");
    assert_eq!(validate_path("\u{212A}"), Err(PathError::NotNfc));
    assert_eq!(validate_path("a/\u{212A}b"), Err(PathError::NotNfc));
    // Exact duplicates collide too.
    assert!(matches!(
        tree(&[("x", K::F), ("x", K::D)], MAC),
        Err(TreeError::Collision { .. })
    ));
}

/// Reference fold: the single pass of FORMAT.md 10.2 repeated until it stops changing.
fn fold_to_fixed_point(text: &str) -> String {
    let mut key = text.to_owned();
    loop {
        let next: String = key.to_uppercase().to_lowercase().nfc().collect();
        if next == key {
            return key;
        }
        key = next;
    }
}

#[test]
fn fold_key_is_idempotent_over_every_char() {
    // Exhaustive: every scalar value alone, and next to a context char (final-sigma, NFC).
    let mut buf = [0u8; 4];
    for c in ('\0'..=char::MAX).filter(|c| !matches!(*c as u32, 0xD800..=0xDFFF)) {
        let s: &str = c.encode_utf8(&mut buf);
        let k = fold_key(s);
        assert_eq!(fold_key(&k), k, "U+{:04X}", c as u32);
    }
    for s in ["ẞ", "ß", "ss", "Σ", "ΑΣ", "ǅ", "ﬁ", "İ", "\u{1E9E}\u{301}"] {
        let k = fold_key(s);
        assert_eq!(fold_key(&k), k, "{s:?}");
    }
    assert_eq!(fold_key("ẞ"), "ss");
    assert_eq!(fold_key("ß"), "ss");
    assert_eq!(fold_key("ss"), "ss");
}

#[test]
fn tree_rejects_the_apfs_eszett_escape() {
    // S1: `a/ß` is the link `a/ẞ` -> `a` on a case-insensitive filesystem, so the link `ẞ` ->
    // `a/ß/../..` would leave the tree; `ss/evil` would then be written through it.
    let r = tree(
        &[
            ("a", K::D),
            ("a/ẞ", K::L(".")),
            ("ẞ", K::L("a/ß/../..")),
            ("ss/evil", K::F),
        ],
        MAC,
    );
    assert!(r.is_err(), "{r:?}");
    // Each defence on its own, by fold key.
    let r = tree(&[("ẞ", K::L("x")), ("ss/evil", K::F)], MAC);
    assert!(
        matches!(r, Err(TreeError::UnderNonDirectory { .. })),
        "{r:?}"
    );
    let e = link_err(&[("ss", K::L(".")), ("l", K::L("ẞ/../x"))]);
    assert!(matches!(e, LinkTargetError::ThroughSymlink(_)), "{e:?}");
}

#[test]
fn fold_key_is_per_component() {
    // The tree check relies on fold(p) being the folds of p's components joined by `/`.
    for p in [
        "ΑΣ/b",
        "ΑΣ.x/ΑΣ",
        "Straße/İx/ǅ",
        "\u{212A}/ﬁ/ΣΑΣ",
        "a.Σ/Σ",
        "Ω/\u{1E9E}",
    ] {
        let whole = fold_to_fixed_point(p);
        let parts: Vec<String> = p.split('/').map(fold_key).collect();
        assert_eq!(fold_key(p), whole, "{p:?}");
        assert_eq!(parts.join("/"), whole, "{p:?}");
        if let Ok(path) = validate_path(p) {
            assert_eq!(path.fold_key(), whole);
        }
    }
}

#[test]
fn tree_rejects_entries_under_non_directories() {
    for entries in [
        vec![("a", K::F), ("a/b", K::F)],
        vec![("a/b", K::F), ("a", K::F)],
        vec![("A", K::F), ("a/b", K::D)],
        vec![("a", K::F), ("A/b/c", K::F)],
        vec![("s", K::L("d")), ("s/x", K::F)],
        vec![("d", K::D), ("S", K::L("d")), ("s/x", K::F)],
        vec![("x", K::F), ("x/y", K::F), ("x.y", K::F), ("x0", K::F)],
    ] {
        let r = tree(&entries, MAC);
        assert!(
            matches!(r, Err(TreeError::UnderNonDirectory { .. })),
            "{r:?}"
        );
    }
    // Siblings sharing a prefix that is not a component are fine.
    tree(&[("x", K::F), ("x.y/z", K::F), ("xy/z", K::F)], MAC).unwrap();
}

#[test]
fn tree_rejects_symlinks_on_windows() {
    for t in [Target::WindowsX86_64, Target::WindowsAarch64] {
        let r = tree(&[("a", K::F), ("l", K::L("a"))], t);
        assert!(matches!(r, Err(TreeError::SymlinkOnWindows(_))), "{r:?}");
    }
    for t in [
        Target::MacosX86_64,
        Target::MacosAarch64,
        Target::MacosUniversal,
        Target::LinuxX86_64,
        Target::LinuxAarch64,
    ] {
        tree(&[("a", K::F), ("l", K::L("a"))], t).unwrap();
    }
}

#[track_caller]
fn link_err(entries: &[(&str, K)]) -> LinkTargetError {
    match tree(entries, Target::LinuxX86_64) {
        Err(TreeError::LinkTarget { source, .. }) => source,
        other => panic!("expected a link target rejection, got {other:?}"),
    }
}

#[test]
fn tree_rejects_bad_symlink_targets() {
    let long: &'static str = Box::leak("a/".repeat(513).into_boxed_str());
    for (target, want) in [
        ("", LinkTargetError::Empty),
        ("/etc/passwd", LinkTargetError::Absolute),
        ("/", LinkTargetError::Absolute),
        ("a//b", LinkTargetError::EmptyComponent),
        ("a/", LinkTargetError::EmptyComponent),
        ("e\u{301}", LinkTargetError::NotNfc),
        ("..", LinkTargetError::Escapes),
        ("../x", LinkTargetError::Escapes),
        ("a/../../x", LinkTargetError::Escapes),
        // `.` must not absorb a `..`: from the root, `./..` is the root's parent.
        ("./..", LinkTargetError::Escapes),
        ("./../x", LinkTargetError::Escapes),
    ] {
        assert_eq!(link_err(&[("l", K::L(target))]), want, "{target:?}");
    }
    assert!(matches!(
        link_err(&[("l", K::L(long))]),
        LinkTargetError::TooLong { len: 1026 }
    ));
    for target in ["a\\b", "a\0b", "a\u{1}", "a\u{1f}b", "a\u{7f}"] {
        let leaked: &'static str = Box::leak(target.to_owned().into_boxed_str());
        assert!(
            matches!(
                link_err(&[("l", K::L(leaked))]),
                LinkTargetError::ForbiddenChar { .. }
            ),
            "{target:?}"
        );
    }
    // Escape from a nested link: two levels up from `d/e` is the root, three is outside.
    tree(&[("d/e/l", K::L("../../x"))], Target::LinuxX86_64).unwrap();
    assert_eq!(
        link_err(&[("d/e/l", K::L("../../../x"))]),
        LinkTargetError::Escapes
    );
}

#[test]
fn tree_rejects_targets_through_another_symlink() {
    // The contract example: `s` -> `.` with `l` -> `s/../x`.
    let e = link_err(&[("s", K::L(".")), ("l", K::L("s/../x"))]);
    assert!(matches!(e, LinkTargetError::ThroughSymlink(_)), "{e:?}");
    // Through a symlink further down, by fold key, and through itself.
    let e = link_err(&[("d", K::D), ("d/s", K::L("..")), ("l", K::L("d/s/x"))]);
    assert!(matches!(e, LinkTargetError::ThroughSymlink(_)), "{e:?}");
    let e = link_err(&[("S", K::L(".")), ("l", K::L("s/x"))]);
    assert!(matches!(e, LinkTargetError::ThroughSymlink(_)), "{e:?}");
    let e = link_err(&[("l", K::L("l/x"))]);
    assert!(matches!(e, LinkTargetError::ThroughSymlink(_)), "{e:?}");
    let e = link_err(&[("s", K::L("a")), ("l", K::L("s/."))]);
    assert!(matches!(e, LinkTargetError::ThroughSymlink(_)), "{e:?}");
    // A symlink as the final component is allowed (chains are checked link by link).
    tree(
        &[("s", K::L(".")), ("l", K::L("s")), ("m", K::L("./l"))],
        Target::LinuxX86_64,
    )
    .unwrap();
}

#[test]
fn tree_error_display_is_bounded() {
    let a = format!("{}A", "x".repeat(250));
    let b = format!("{}a", "x".repeat(250));
    let pa = validate_path(&a).unwrap();
    let pb = validate_path(&b).unwrap();
    let e = validate_tree([(&pa, EntryKind::File), (&pb, EntryKind::File)], MAC).unwrap_err();
    assert!(e.to_string().len() < 200, "{e}");
}

// ---- versions (FORMAT.md 10.3) ----

fn v(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

fn hash_of(x: &Version) -> u64 {
    let mut h = DefaultHasher::new();
    x.hash(&mut h);
    h.finish()
}

#[test]
fn version_precedence_order() {
    let chain = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.1.0",
        "2.0.0",
    ];
    for w in chain.windows(2) {
        assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        assert!(v(w[1]) > v(w[0]));
    }
}

#[test]
fn version_build_metadata_is_ignored_for_equality_but_kept() {
    let a = v("1.0.0+a");
    let b = v("1.0.0+b");
    assert_eq!(a, b);
    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    assert_eq!(hash_of(&a), hash_of(&b));
    assert_eq!(a, v("1.0.0"));
    assert_eq!(a.to_string(), "1.0.0+a");
    assert_eq!(b.as_semver().build.as_str(), "b");
    assert!(v("1.0.0-rc.1+x") < v("1.0.0+0"));
}

#[test]
fn version_rejections() {
    for s in [
        "01.0.0",
        "1.0",
        "1",
        "v1.0.0",
        "1.0.0-01",
        "1.00.0",
        " 1.0.0",
        "1.0.0 ",
        "1.0.0-",
        "1.0.0+",
        "",
        "1.0.0-a_b",
    ] {
        assert!(
            matches!(Version::parse(s), Err(VersionError::Invalid(_))),
            "{s:?}"
        );
    }
    let at_cap = format!("1.0.0-{}", "a".repeat(58));
    assert_eq!(at_cap.len(), 64);
    v(&at_cap);
    let over = format!("1.0.0-{}", "a".repeat(59));
    assert!(matches!(
        Version::parse(&over),
        Err(VersionError::TooLong { len: 65 })
    ));
}

// ---- targets (FORMAT.md 10.4) ----

#[test]
fn targets_are_exactly_the_seven_ids() {
    let ids = [
        "windows-x86_64",
        "windows-aarch64",
        "macos-x86_64",
        "macos-aarch64",
        "macos-universal",
        "linux-x86_64",
        "linux-aarch64",
    ];
    assert_eq!(Target::ALL.len(), 7);
    for (t, id) in Target::ALL.iter().zip(ids) {
        assert_eq!(Target::parse(id).unwrap(), *t);
        assert_eq!(t.as_str(), id);
        assert_eq!(t.to_string(), id);
    }
    for bad in [
        "linux-x86",
        "Windows-x86_64",
        "macos-arm64",
        "",
        "linux-x86_64 ",
        "linux_x86_64",
        "LINUX-X86_64",
        "windows-x64",
    ] {
        assert!(Target::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn target_fallbacks_follow_format() {
    use Target::*;
    assert_eq!(WindowsAarch64.fallbacks(), &[WindowsX86_64]);
    assert_eq!(MacosX86_64.fallbacks(), &[MacosUniversal]);
    assert_eq!(MacosAarch64.fallbacks(), &[MacosUniversal]);
    for t in [WindowsX86_64, MacosUniversal, LinuxX86_64, LinuxAarch64] {
        assert!(t.fallbacks().is_empty(), "{t}");
    }
    assert!(WindowsX86_64.is_windows() && WindowsAarch64.is_windows());
    assert!(!MacosUniversal.is_windows() && !LinuxAarch64.is_windows());
}

// ---- app ids and channels (FORMAT.md 10.5, 10.6) ----

#[test]
fn app_id_rules() {
    for ok in [
        "lunegit",
        "a",
        "0",
        "com.example.app",
        "my_app-2",
        "console",
        "com10",
        "nul1",
        "a.b_c-d",
    ] {
        assert_eq!(AppId::parse(ok).unwrap().as_str(), ok);
    }
    AppId::parse(&"a".repeat(64)).unwrap();
    let cases: &[(&str, IdentError)] = &[
        ("", IdentError::Empty),
        ("Lunegit", IdentError::InvalidByte { offset: 0 }),
        ("-a", IdentError::InvalidByte { offset: 0 }),
        (".a", IdentError::InvalidByte { offset: 0 }),
        ("_a", IdentError::InvalidByte { offset: 0 }),
        ("a/b", IdentError::InvalidByte { offset: 1 }),
        ("a b", IdentError::InvalidByte { offset: 1 }),
        ("aÄ", IdentError::InvalidByte { offset: 1 }),
        ("a..b", IdentError::DotDot),
        ("a.", IdentError::TrailingDot),
        ("con", IdentError::DeviceName),
        ("con.app", IdentError::DeviceName),
        ("com1", IdentError::DeviceName),
        ("lpt9.x", IdentError::DeviceName),
        ("aux", IdentError::DeviceName),
    ];
    for (bad, want) in cases {
        assert_eq!(AppId::parse(bad).unwrap_err(), *want, "{bad:?}");
    }
    assert!(matches!(
        AppId::parse(&"a".repeat(65)),
        Err(IdentError::TooLong { len: 65, max: 64 })
    ));
}

#[test]
fn channel_rules() {
    for ok in ["stable", "beta-2", "0", "a-", "nightly"] {
        assert_eq!(Channel::parse(ok).unwrap().as_str(), ok);
    }
    Channel::parse(&"c".repeat(32)).unwrap();
    for bad in ["", "Stable", "-x", "a_b", "a.b", "a b", "ß"] {
        assert!(Channel::parse(bad).is_err(), "{bad:?}");
    }
    assert!(matches!(
        Channel::parse(&"c".repeat(33)),
        Err(IdentError::TooLong { len: 33, max: 32 })
    ));
}

// ---- serde goes through the same validators ----

#[test]
fn deserialising_uses_the_validators() {
    use lunepack_core::json::parse_strict;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Doc {
        path: RelPath,
        version: Version,
        target: Target,
        app: AppId,
        channel: Channel,
    }
    let ok = br#"{"path":"bin/app","version":"1.2.3+b","target":"linux-x86_64","app":"lunegit","channel":"stable"}"#;
    let doc: Doc = parse_strict(ok).unwrap();
    assert_eq!(doc.path.as_str(), "bin/app");
    for bad in [
        br#"{"path":"a/../b","version":"1.2.3","target":"linux-x86_64","app":"x","channel":"s"}"#
            as &[u8],
        br#"{"path":"a","version":"1.2","target":"linux-x86_64","app":"x","channel":"s"}"#,
        br#"{"path":"a","version":"1.2.3","target":"macos-arm64","app":"x","channel":"s"}"#,
        br#"{"path":"a","version":"1.2.3","target":"linux-x86_64","app":"CON","channel":"s"}"#,
        br#"{"path":"a","version":"1.2.3","target":"linux-x86_64","app":"x","channel":"S"}"#,
    ] {
        assert!(parse_strict::<Doc>(bad).is_err());
    }
}

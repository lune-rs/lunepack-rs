//! `StdFs` against the core's filesystem contract suite and its own host-specific cases. Runs on a
//! temporary directory, canonicalised first (the contract refuses a symlink in the path, and macOS
//! temporary directories live under the `/var` symlink).

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use lunepack_core::{FileKind, Fs, FsErrorKind};
use lunepack_fs::StdFs;
use lunepack_testkit::run_fs_suite;

fn temp_root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = fs::canonicalize(dir.path()).expect("canonicalize");
    (dir, root)
}

#[test]
fn std_fs_passes_the_contract_suite() {
    let (_guard, root) = temp_root();
    run_fs_suite(&StdFs, &root);
    // Nothing left behind.
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn std_fs_passes_the_suite_twice_over_the_same_directory() {
    let (_guard, root) = temp_root();
    run_fs_suite(&StdFs, &root);
    run_fs_suite(&StdFs, &root);
}

#[test]
fn errors_name_only_the_file() {
    let (_guard, root) = temp_root();
    let err = StdFs
        .read_capped(&root.join("only-this-name.bin"), 10)
        .unwrap_err();
    assert_eq!(err.kind, FsErrorKind::NotFound);
    let shown = format!("{err} / {err:?}");
    assert!(shown.contains("only-this-name.bin"));
    assert!(!shown.contains(&*root.to_string_lossy()), "{shown}");
}

#[test]
fn errors_name_the_operation_and_the_os_code() {
    let (_guard, root) = temp_root();
    // A directory read as a file fails differently per OS, but always with an OS code and the
    // operation that failed.
    let err = StdFs.read_capped(&root, 10).unwrap_err();
    let shown = format!("{err} / {err:?}");
    assert!(["open", "read"].contains(&err.operation()), "{shown}");
    assert!(shown.contains(&format!("({})", err.operation())), "{shown}");
    assert!(err.os_code().is_some(), "{shown}");
    assert!(shown.contains("os_code: Some("), "{shown}");
    assert!(!shown.contains(&*root.to_string_lossy()), "{shown}");
}

/// The test root is canonicalised, which on Windows gives a verbatim `\\?\C:\...` path; its bare
/// prefix `\\?\C:` names the volume device and must not be inspected as a directory.
#[cfg(windows)]
#[test]
fn create_dir_all_works_below_a_verbatim_root() {
    let (_guard, root) = temp_root();
    assert!(
        root.to_string_lossy().starts_with(r"\\?\"),
        "{}",
        root.display()
    );
    let deep = root.join("a").join("b").join("c");
    StdFs.create_dir_all(&deep).unwrap();
    StdFs.create_dir_all(&deep).unwrap();
    assert!(deep.is_dir());
}

#[test]
fn rename_and_copy_never_overwrite() {
    let (_guard, root) = temp_root();
    for name in ["a", "b"] {
        let mut f = StdFs.create_new(&root.join(name)).unwrap();
        f.write_all(name.as_bytes()).unwrap();
        f.sync().unwrap();
    }
    assert_eq!(
        StdFs
            .rename(&root.join("a"), &root.join("b"))
            .unwrap_err()
            .kind,
        FsErrorKind::AlreadyExists
    );
    assert_eq!(
        StdFs
            .copy_file(&root.join("a"), &root.join("b"))
            .unwrap_err()
            .kind,
        FsErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(root.join("b")).unwrap(), b"b");
    assert_eq!(fs::read(root.join("a")).unwrap(), b"a");
}

#[test]
fn sync_dir_works_on_a_directory() {
    let (_guard, root) = temp_root();
    StdFs.sync_dir(&root).expect("sync_dir");
    let mut f = StdFs.create_new(&root.join("f")).unwrap();
    f.write_all(b"x").unwrap();
    f.sync().unwrap();
    StdFs.sync_dir(&root).expect("sync_dir after a create");
}

#[test]
fn list_dir_reports_kinds_without_following_links() {
    let (_guard, root) = temp_root();
    fs::create_dir(root.join("d")).unwrap();
    fs::write(root.join("f"), b"x").unwrap();
    let mut got: Vec<_> = StdFs
        .list_dir(&root)
        .unwrap()
        .into_iter()
        .map(|e| (e.name.to_string_lossy().into_owned(), e.kind))
        .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![
            ("d".to_owned(), FileKind::Dir),
            ("f".to_owned(), FileKind::File)
        ]
    );
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn set_exec_adds_x_where_r_is_set_and_clears_every_x() {
        let (_guard, root) = temp_root();
        let file = root.join("f");
        fs::write(&file, b"x").unwrap();
        for (start, on, off) in [
            (0o644, 0o755, 0o644),
            (0o600, 0o700, 0o600),
            (0o640, 0o750, 0o640),
            (0o444, 0o555, 0o444),
            (0o700, 0o700, 0o600),
        ] {
            fs::set_permissions(&file, fs::Permissions::from_mode(start)).unwrap();
            StdFs.set_exec(&file, true).unwrap();
            assert_eq!(mode(&file), on, "set_exec(true) from {start:o}");
            StdFs.set_exec(&file, false).unwrap();
            assert_eq!(mode(&file), off, "set_exec(false) from {on:o}");
        }
        assert_eq!(
            StdFs
                .set_exec(&root.join("missing"), true)
                .unwrap_err()
                .kind,
            FsErrorKind::NotFound
        );
    }

    #[test]
    fn copy_file_keeps_the_mode() {
        let (_guard, root) = temp_root();
        let src = root.join("src");
        fs::write(&src, b"run").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();
        StdFs.copy_file(&src, &root.join("dst")).unwrap();
        assert_eq!(mode(&root.join("dst")), 0o755);
        assert_eq!(fs::read(root.join("dst")).unwrap(), b"run");
    }

    #[test]
    fn create_new_does_not_write_through_a_symlink_even_to_a_free_target() {
        let (_guard, root) = temp_root();
        let target = root.join("target");
        symlink(&target, root.join("link")).unwrap();
        let err = StdFs.create_new(&root.join("link")).err().unwrap();
        assert_eq!(err.kind, FsErrorKind::AlreadyExists);
        assert!(!target.exists(), "the link was followed");
    }

    #[test]
    fn create_dir_all_refuses_a_symlinked_component_and_a_file() {
        let (_guard, root) = temp_root();
        fs::create_dir(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();
        assert_eq!(
            StdFs
                .create_dir_all(&root.join("alias/sub"))
                .unwrap_err()
                .kind,
            FsErrorKind::IsSymlink
        );
        assert!(!root.join("real/sub").exists());
        fs::write(root.join("file"), b"x").unwrap();
        assert_eq!(
            StdFs
                .create_dir_all(&root.join("file/sub"))
                .unwrap_err()
                .kind,
            FsErrorKind::NotADirectory
        );
        StdFs.create_dir_all(&root.join("real/a/b")).unwrap();
        StdFs.create_dir_all(&root.join("real/a/b")).unwrap();
    }

    #[test]
    fn read_capped_reads_at_most_one_byte_past_the_cap() {
        // /dev/zero never ends: a reader that did not stop at max + 1 would hang or exhaust memory.
        let err = StdFs.read_capped(Path::new("/dev/zero"), 10).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::TooLarge);
        assert_eq!(StdFs.read_capped(Path::new("/dev/null"), 0).unwrap(), b"");
    }

    #[test]
    fn remove_dir_all_nofollow_leaves_a_linked_directory_alone() {
        let (_guard, root) = temp_root();
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"k").unwrap();
        let tree = root.join("tree");
        fs::create_dir_all(tree.join("in")).unwrap();
        symlink(&outside, tree.join("in/escape")).unwrap();
        StdFs.remove_dir_all_nofollow(&tree).unwrap();
        assert!(!tree.exists());
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
        // A top-level link to the directory is removed, not followed.
        symlink(&outside, root.join("top")).unwrap();
        StdFs.remove_dir_all_nofollow(&root.join("top")).unwrap();
        assert!(!root.join("top").exists() && outside.join("keep").exists());
    }

    #[test]
    fn positional_reads_work_from_many_threads() {
        let (_guard, root) = temp_root();
        let bytes: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        fs::write(root.join("big"), &bytes).unwrap();
        let reader: std::sync::Arc<dyn lunepack_core::ReadAt> =
            StdFs.open_read(&root.join("big")).unwrap().into();
        std::thread::scope(|s| {
            for t in 0..8usize {
                let (reader, bytes) = (reader.clone(), &bytes);
                s.spawn(move || {
                    for i in 0..200usize {
                        let off = (t * 7919 + i * 331) % (bytes.len() - 64);
                        let mut buf = [0u8; 64];
                        reader.read_exact_at(off as u64, &mut buf).unwrap();
                        assert_eq!(&buf[..], &bytes[off..off + 64]);
                    }
                });
            }
        });
    }
}

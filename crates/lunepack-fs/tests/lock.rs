//! The OS lock of `StdFs::try_lock` (M4-D15), with real processes. Own `main` (see Cargo.toml):
//! the test re-runs this binary as a child that takes the lock and waits on stdin, and checks that
//! the parent cannot take it, that killing the child releases it, and that a second lock in one
//! process fails while the first guard lives.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lunepack_core::Fs;
use lunepack_fs::StdFs;

type TestFn = fn();

const TESTS: &[(&str, TestFn)] = &[
    ("same_process_second_lock_is_refused", same_process),
    ("a_killed_holder_releases_the_lock", killed_holder),
    ("a_held_lock_is_refused_across_processes", cross_process),
    (
        "locks_on_different_paths_are_independent",
        independent_paths,
    ),
    ("a_missing_directory_is_an_error", missing_directory),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--hold") {
        return hold(Path::new(&args[1]));
    }
    let filter = args.iter().find(|a| !a.starts_with('-'));
    let mut failed = 0;
    for (name, test) in TESTS {
        if filter.is_some_and(|f| !name.contains(f.as_str())) {
            continue;
        }
        match std::panic::catch_unwind(*test) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

/// Child: take the lock, say so, and wait for stdin to close (or be killed).
fn hold(path: &Path) {
    let guard = StdFs.try_lock(path).expect("child try_lock");
    if guard.is_none() {
        println!("busy");
        return;
    }
    println!("locked");
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

fn temp() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let lock = std::fs::canonicalize(dir.path()).unwrap().join("lock");
    (dir, lock)
}

fn spawn_holder(lock: &Path) -> std::process::Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--hold")
        .arg(lock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the holder");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "locked", "the child did not get the lock");
    child
}

fn same_process() {
    let (_dir, lock) = temp();
    let first = StdFs.try_lock(&lock).unwrap().expect("first lock");
    assert!(
        StdFs.try_lock(&lock).unwrap().is_none(),
        "a second lock in one process"
    );
    drop(first);
    assert!(
        StdFs.try_lock(&lock).unwrap().is_some(),
        "the lock after the guard dropped"
    );
}

fn cross_process() {
    let (_dir, lock) = temp();
    let mut child = spawn_holder(&lock);
    assert!(
        StdFs.try_lock(&lock).unwrap().is_none(),
        "the parent took a held lock"
    );
    // The holder exits cleanly when stdin closes, and the lock is free again.
    drop(child.stdin.take());
    child.wait().unwrap();
    assert!(StdFs.try_lock(&lock).unwrap().is_some());
}

fn killed_holder() {
    let (_dir, lock) = temp();
    let mut child = spawn_holder(&lock);
    assert!(StdFs.try_lock(&lock).unwrap().is_none());
    child.kill().expect("kill the holder");
    child.wait().expect("wait for the holder");
    let started = Instant::now();
    loop {
        if StdFs.try_lock(&lock).unwrap().is_some() {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the lock was not released within 2 s of the holder dying"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn independent_paths() {
    let (dir, lock) = temp();
    let other = dir.path().join("other-lock");
    let a = StdFs.try_lock(&lock).unwrap().expect("a");
    let b = StdFs.try_lock(&other).unwrap().expect("b");
    drop((a, b));
}

fn missing_directory() {
    let (_dir, lock) = temp();
    let err = StdFs
        .try_lock(&lock.parent().unwrap().join("no-such-dir/lock"))
        .err()
        .expect("an error");
    assert_eq!(err.kind, lunepack_core::FsErrorKind::NotFound);
}

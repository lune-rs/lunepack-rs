//! Cross-process behaviour (M4 step 13): a staged version outlives the process that staged it, and
//! the OS lock of a hard-killed process does not stay held.
//!
//! This test has its own `main` (see Cargo.toml), like `lunepack-crypto`'s signer test: the tests
//! re-run this binary as a child process (`--child-staged`, `--child-download`) and talk to it over
//! a line protocol on stdout, which the libtest harness would interleave with its own output. The
//! child gets a root public key (not a secret) and a directory; no key material is passed.
//!
//! Tests run one after another on one thread, so no `serial()` is needed.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::panic::catch_unwind;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use lunepack::{DownloadOptions, Error, Layout, UpdaterBuilder, block_on};
use lunepack_core::{Phase, TrustedRoot};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::{FakeClock, LoopbackServer, SUITE_T0, TransportFault};

type TestFn = fn();

const TESTS: &[(&str, TestFn)] = &[
    (
        "a_staged_version_is_seen_by_a_new_handle_and_a_child_process",
        staged_across_processes,
    ),
    (
        "a_hard_killed_download_leaves_no_lock_and_resumes_its_parts",
        hard_kill,
    ),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--child-staged") => return child_staged(&args[1..]),
        Some("--child-download") => return child_download(&args[1..]),
        _ => {}
    }
    let filters: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let mut failed = Vec::new();
    let mut run = 0;
    for (name, test) in TESTS {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        run += 1;
        match catch_unwind(test) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(*name);
            }
        }
    }
    println!(
        "test result: {}. {} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        run - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(1);
    }
}

// ---- the child side ------------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

/// An updater for `<root dir> <feed url> <root public key hex>`, every adapter a default.
fn child_updater(args: &[String]) -> lunepack::Updater {
    let (state_dir, cache_dir, versions_dir) = Site::at(Path::new(&args[0]));
    let root = TrustedRoot::from_parts(
        app_id(),
        1,
        1,
        &[from_hex(&args[2])],
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .expect("root");
    UpdaterBuilder::new(
        app_id(),
        root,
        &args[1],
        channel(),
        Layout::User {
            state_dir,
            cache_dir,
            versions_dir,
            current_tree: None,
        },
    )
    .clock(Arc::new(FakeClock::new(SUITE_T0 + 3600)))
    .workers(2)
    .build()
    .expect("child updater")
}

fn say(line: &str) {
    println!("{line}");
    std::io::stdout().flush().expect("flush");
}

fn child_staged(args: &[String]) {
    let u = child_updater(args);
    match u.staged() {
        Ok(Some(s)) => say(&format!("staged {}", s.version())),
        Ok(None) => say("staged none"),
        Err(e) => say(&format!("error {e}")),
    }
}

/// check, say `checked`, wait for `go` on stdin, download; say `downloading` at the first byte.
fn child_download(args: &[String]) {
    let u = child_updater(args);
    let info = block_on(u.check()).expect("check").expect("an update");
    say("checked");
    let mut go = String::new();
    std::io::stdin().read_line(&mut go).expect("stdin");
    let told = Arc::new(AtomicBool::new(false));
    let options = DownloadOptions {
        progress: Some(Box::new(move |p| {
            // Download events come after the lock was taken, so the lock is held now.
            if p.phase == Phase::Download && p.done > 0 && !told.swap(true, Ordering::SeqCst) {
                say("downloading");
            }
        })),
        cancel: None,
    };
    match block_on(u.download(&info, options)) {
        Ok(_) => say("finished"),
        Err(e) => say(&format!("failed {e}")),
    }
}

// ---- the parent side -----------------------------------------------------------------------------

fn child_args(mode: &str, site: &Site, feed: &str) -> Vec<String> {
    vec![
        mode.to_owned(),
        site.root.to_string_lossy().into_owned(),
        feed.to_owned(),
        to_hex(&fixture().root_public),
    ]
}

fn run_child_staged(site: &Site, feed: &str) -> String {
    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args(child_args("--child-staged", site, feed))
        .stderr(Stdio::inherit())
        .output()
        .expect("spawn child");
    assert!(out.status.success(), "the child failed: {}", out.status);
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .trim()
        .to_owned()
}

fn staged_across_processes() {
    let baseline = Baseline::new();
    let site = baseline.fresh();
    let server = LoopbackServer::start(fixture().origin(2)).expect("server");
    let feed = server.url(FEED_NAME);

    // Process A (this one): check, download, stage over the default transport.
    let u = site.builder(&feed).build().expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_tree(staged.tree(), &release_tree(V110));

    // (1) A fresh handle in the same process.
    let fresh = site.builder(&feed).build().expect("fresh handle");
    let seen = fresh
        .staged()
        .expect("staged")
        .expect("staged() in a new handle");
    assert_eq!(seen.version().to_string(), V110);
    assert_eq!(seen.tree(), site.tree(V110));
    // (2) A child process.
    assert_eq!(run_child_staged(&site, &feed), format!("staged {V110}"));

    // After mark_bad, both see nothing.
    site.commit(|r| r.expect("state").mark_bad(version(V110)));
    assert!(
        fresh.staged().expect("staged").is_none(),
        "a bad version is not staged"
    );
    assert_eq!(run_child_staged(&site, &feed), "staged none");
}

/// A thread that forwards the child's stdout lines.
fn lines_of(child: &mut Child) -> Receiver<String> {
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn expect_line(rx: &Receiver<String>, want: &str, limit: Duration) {
    match rx.recv_timeout(limit) {
        Ok(line) => assert_eq!(line, want, "the child said {line:?}, not {want:?}"),
        Err(e) => panic!("no {want:?} from the child within {limit:?}: {e}"),
    }
}

/// The size of the pack part in the cache, if there is one.
fn pack_part_len(cache_dir: &Path) -> u64 {
    find_suffix(&cache_dir.join("packs"), ".part")
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .max()
        .unwrap_or(0)
}

fn hard_kill() {
    let baseline = Baseline::new();
    let site = baseline.fresh();
    let server = LoopbackServer::start(fixture().origin(2)).expect("server");
    let feed = server.url(FEED_NAME);
    let u = site.builder(&feed).build().expect("build");
    let info = block_on(u.check()).expect("check").expect("update");

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args(child_args("--child-download", &site, &feed))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child");
    let rx = lines_of(&mut child);
    let outcome = catch_unwind(std::panic::AssertUnwindSafe(|| {
        expect_line(&rx, "checked", Duration::from_secs(120));
        // From here the pack arrives one byte per segment: the child cannot finish before it is
        // killed, and the cache holds a part.
        server.origin().add_fault(TransportFault::SlowChunks);
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(b"go\n")
            .expect("tell the child to go");
        expect_line(&rx, "downloading", Duration::from_secs(120));

        // The child holds the lock: another process gets Busy.
        match block_on(u.download(&info, DownloadOptions::default())) {
            Err(Error::Busy) => {}
            other => panic!("expected Busy while the child holds the lock, got {other:?}"),
        }

        // Wait until the part holds bytes worth resuming.
        let deadline = Instant::now() + Duration::from_secs(60);
        while pack_part_len(&site.cache_dir) < 4096 {
            assert!(Instant::now() < deadline, "the child wrote no pack part");
            thread::sleep(Duration::from_millis(20));
        }
    }));
    // Always kill (a failed assertion above must not leave the child running).
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    let part = pack_part_len(&site.cache_dir);
    assert!(part >= 4096, "the part is {part} bytes");

    // The child's request was the whole pack (no Range); remember how many requests it made.
    let pack_url = format!("/{}", pack_path(V110));
    let before = server.origin().requests();
    assert!(
        before
            .iter()
            .any(|r| r.url == pack_url && r.range.is_none()),
        "the child did not start the pack from byte 0"
    );
    server.origin().set_faults(Vec::new());

    // The OS released the dead process's lock, and the parts resume.
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).unwrap_or_else(|e| {
        panic!("a download after the kill must not be Busy and must work: {e}")
    });
    let after = server.origin().requests();
    let resumed: Vec<_> = after[before.len()..]
        .iter()
        .filter(|r| r.url == pack_url)
        .collect();
    assert!(
        resumed
            .iter()
            .any(|r| r.range.is_some_and(|range| range.first > 0)),
        "no Range request starting past byte 0 after the kill: {resumed:?}"
    );
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_tree(staged.tree(), &release_tree(V110));
    assert!(u.staged().expect("staged").is_some());
    assert!(find_suffix(&site.root, ".lptmp").is_empty());
    assert!(find_suffix(&site.cache_dir, ".part").is_empty());
}

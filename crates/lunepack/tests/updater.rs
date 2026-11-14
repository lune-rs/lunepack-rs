//! The `Updater` (M4 step 12): check, download, stage, staged, installed, the lock, the scopes and
//! the D27 ladder, over the testkit fakes and MemFs.

mod common;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use common::*;
use lunepack::{DownloadOptions, Error, Layout, block_on};
use lunepack_core::fetch::FetchPolicy;
use lunepack_core::state::{
    InstallCounters, InstallState, MachineScope, Record, Scope, StagedRef, commit,
    commit_raw_payload, load,
};
use lunepack_core::{
    BoxFuture, DirEntryInfo, FileWrite, Fs, FsError, LockGuard, Meta, ReadAt, Request, Response,
    StateError, Target, Transport, TransportError,
};
use lunepack_testkit::{FakeHasher, FakeTransport, MemFs, SUITE_T0};

fn records(w: &World, dir: &Path) -> BTreeMap<String, Vec<u8>> {
    match w.fs.list_dir(dir) {
        Ok(entries) => entries
            .into_iter()
            .filter_map(|e| {
                let name = e.name.to_string_lossy().into_owned();
                name.ends_with(".rec")
                    .then(|| (name.clone(), w.read(&dir.join(&name))))
            })
            .collect(),
        Err(_) => BTreeMap::new(),
    }
}

fn names(fs: &dyn Fs, dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs
        .list_dir(dir)
        .map(|es| {
            es.into_iter()
                .map(|e| e.name.to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn ranges_ratio_never() -> FetchPolicy {
    FetchPolicy {
        full_ratio: 101,
        ..FetchPolicy::default()
    }
}

// ---- happy path ----------------------------------------------------------------------------------

#[test]
fn check_download_stage_builds_the_tree_and_records_it() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = w.updater();
    assert_eq!(
        u.installed()
            .expect("installed")
            .map(|i| i.version().clone()),
        Some(version("1.0.0"))
    );
    let info = block_on(u.check()).expect("check").expect("an update");
    assert_eq!(info.version_text(), "1.1.0");
    assert_eq!(info.target(), TARGET);
    assert_eq!(info.feed_seq(), 1);
    assert!(info.time_checked());
    assert_eq!(info.issued(), SUITE_T0);
    assert_eq!(info.download_size_max(), w.pack("1.1.0").bytes.len() as u64);

    let progress = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&progress);
    let options = DownloadOptions {
        progress: Some(Box::new(move |p| {
            seen.lock().expect("progress").push(p.clone())
        })),
        cancel: None,
    };
    let downloaded = block_on(u.download(&info, options)).expect("download");
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_eq!(staged.version(), &version("1.1.0"));
    assert_eq!(staged.tree(), w.versions_dir.join("1.1.0"));
    for (path, bytes) in files("1.1.0") {
        assert_eq!(w.read(&staged.tree().join(path)), bytes);
    }
    assert_eq!(u.staged().expect("staged"), Some(staged));
    // The version's cache entries are gone.
    assert!(names(&w.fs, &w.cache_dir.join("frames")).is_empty());
    assert!(names(&w.fs, &w.cache_dir.join("packs")).is_empty());
    let events = progress.lock().expect("progress");
    assert!(
        events
            .iter()
            .any(|p| p.phase == lunepack_core::Phase::Download),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|p| p.phase == lunepack_core::Phase::Stage)
    );
    drop(events);
    workers_stopped();
}

#[test]
fn a_dev_run_is_not_installed_without_a_panic() {
    let _s = serial();
    let w = World::new();
    w.publish(1, "1.1.0");
    let u = w.updater();
    assert!(matches!(block_on(u.check()), Err(Error::NotInstalled)));
    assert_eq!(u.installed().expect("installed"), None);
    assert_eq!(u.staged().expect("staged"), None);
    workers_stopped();
}

// ---- floors and clock ----------------------------------------------------------------------------

#[test]
fn floors_rise_after_a_check_and_a_replayed_feed_is_refused() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(3, "1.1.0");
    let old_feed = w.feed_bytes();
    w.publish(5, "1.1.0");
    let u = w.updater();
    block_on(u.check()).expect("check");
    let record = w.user_state().record.expect("record");
    assert_eq!(record.floors.feed_seq.get(&channel()), Some(&5));
    assert_eq!(record.floors.keyset_version, 1);
    assert_eq!(record.floors.root.as_ref().map(|r| r.version), Some(1));

    let before = records(&w, &w.state_dir);
    w.origin.put("feed-stable.json", old_feed);
    let err = block_on(u.check()).expect_err("replay");
    assert!(
        matches!(err, Error::Verify(lunepack_core::Error::Rollback { .. })),
        "{err:?}"
    );
    assert_eq!(
        records(&w, &w.state_dir),
        before,
        "a failed check wrote state"
    );
    workers_stopped();
}

#[test]
fn an_implausible_clock_skips_expiry_and_says_so() {
    let _s = serial();
    let w = World::new();
    // The installed version was issued after "now": the clock is implausible.
    w.install("1.0.0", SUITE_T0 + 100 * DAY);
    w.publish(1, "1.1.0");
    let info = block_on(w.updater().check())
        .expect("check")
        .expect("update");
    assert!(!info.time_checked());
    workers_stopped();
}

#[test]
fn an_expired_feed_after_400_days_is_an_error_and_changes_nothing() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let before = records(&w, &w.state_dir);
    w.clock.advance_400_days();
    let err = block_on(w.updater().check()).expect_err("expired");
    assert!(matches!(err, Error::Verify(_)), "{err:?}");
    assert_eq!(records(&w, &w.state_dir), before);
    workers_stopped();
}

// ---- state evolution -----------------------------------------------------------------------------

#[test]
fn a_semantically_invalid_newest_record_stops_the_check() {
    let _s = serial();
    let w = World::new();
    let record = w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let mut fields = record.clone().with_seq(2).to_fields().expect("fields");
    fields.insert("bad".to_owned(), serde_json::json!("not a list"));
    let payload = serde_json::to_vec(&fields).expect("json");
    commit_raw_payload(&w.fs, &w.state_dir, 2, &payload, &FakeHasher).expect("raw");
    let err = block_on(w.updater().check()).expect_err("invalid");
    assert!(
        matches!(err, Error::State(StateError::Invalid(_))),
        "{err:?}"
    );
    assert!(matches!(
        w.updater().installed(),
        Err(Error::State(StateError::Invalid(_)))
    ));
    workers_stopped();
}

/// Writes record `seq` in the frame layout with format byte 2.
fn write_format_2(w: &World, record: &InstallState, seq: u64) {
    let fields = record.clone().with_seq(seq).to_fields().expect("fields");
    let payload = serde_json::to_vec(&fields).expect("json");
    let mut bytes = b"LPST".to_vec();
    bytes.push(2);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    let digest = sha(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    let mut f =
        w.fs.create_new(&w.state_dir.join(format!("{seq:020}.rec")))
            .expect("create");
    f.write_all(&bytes).expect("write");
    f.sync().expect("sync");
}

#[test]
fn a_newer_format_record_is_state_too_new_everywhere() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = w.updater();
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let loaded = w.user_state();
    write_format_2(&w, loaded.record.as_ref().expect("record"), loaded.next_seq);
    let before = records(&w, &w.state_dir);
    assert!(matches!(block_on(u.check()), Err(Error::StateTooNew)));
    assert!(matches!(
        block_on(u.download(&info, DownloadOptions::default())),
        Err(Error::StateTooNew)
    ));
    assert!(matches!(
        block_on(u.stage(downloaded)),
        Err(Error::StateTooNew)
    ));
    assert!(matches!(u.installed(), Err(Error::StateTooNew)));
    assert_eq!(records(&w, &w.state_dir), before);
    workers_stopped();
}

#[test]
fn unknown_fields_and_health_survive_a_check_commit() {
    let _s = serial();
    let w = World::new();
    let mut record = InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET).install(
        version("1.0.0"),
        SUITE_T0 - 10 * DAY,
        TARGET,
        INSTALL_ID,
    );
    record
        .extra
        .insert("health".to_owned(), serde_json::json!({"token": "abc"}));
    record
        .extra
        .insert("x_future".to_owned(), serde_json::json!([1, 2, 3]));
    let committed = w.commit_user(record);
    w.publish(4, "1.1.0");
    block_on(w.updater().check()).expect("check");
    let after = w.user_state().record.expect("record");
    assert!(after.seq > committed.seq, "the check did not commit");
    assert_eq!(after.extra, committed.extra);
    assert_eq!(after.critical, committed.critical);
    workers_stopped();
}

// ---- lock ----------------------------------------------------------------------------------------

#[test]
fn a_held_lock_is_busy_for_the_same_and_another_handle() {
    let _s = serial();
    let fake = FakeTransport::new(lunepack_testkit::FakeOrigin::new());
    let origin = fake.origin().clone();
    let entered = Arc::new(AtomicBool::new(false));
    let open = Arc::new(AtomicBool::new(false));
    let gate = GateTransport {
        inner: Arc::new(fake),
        entered: Arc::clone(&entered),
        open: Arc::clone(&open),
    };
    let w = World::with_transport(origin, Arc::new(gate));
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = w.updater();
    let first = {
        let u = u.clone();
        thread::spawn(move || block_on(u.check()))
    };
    assert!(wait_until(std::time::Duration::from_secs(5), || entered
        .load(Ordering::SeqCst)));
    assert!(matches!(block_on(u.check()), Err(Error::Busy)));
    let other_process = w
        .builder(w.user_layout(None), Arc::new(w.fs.process()))
        .build()
        .expect("build");
    assert!(matches!(block_on(other_process.check()), Err(Error::Busy)));
    open.store(true, Ordering::SeqCst);
    first.join().expect("thread").expect("first check");
    workers_stopped();
    block_on(other_process.check()).expect("free again");
    workers_stopped();
}

// ---- current tree --------------------------------------------------------------------------------

fn download_with(w: &World, layout: Layout) -> (Vec<String>, Vec<String>) {
    let u = w
        .builder(layout, Arc::new(w.fs.clone()))
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    block_on(u.download(&info, DownloadOptions::default())).expect("download");
    workers_stopped();
    (
        names(&w.fs, &w.cache_dir.join("frames")),
        names(&w.fs, &w.cache_dir.join("packs")),
    )
}

#[test]
fn the_current_tree_rule_picks_the_tree_to_scan() {
    let _s = serial();
    // <versions>/<current>: three of four files are unchanged; one frame is fetched.
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    w.write_tree(&w.versions_dir.join("1.0.0"), "1.0.0");
    let (frames, packs) = download_with(&w, w.user_layout(None));
    assert_eq!((frames.len(), packs.len()), (1, 0), "{frames:?} {packs:?}");

    // An explicit current_tree elsewhere is scanned instead.
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let live = PathBuf::from("/opt/app");
    w.write_tree(&live, "1.0.0");
    let (frames, packs) = download_with(&w, w.user_layout(Some(live)));
    assert_eq!((frames.len(), packs.len()), (1, 0), "{frames:?} {packs:?}");

    // A symlink at <versions>/<current> does not count: everything is fetched (the full pack).
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let real = PathBuf::from("/real/tree");
    w.write_tree(&real, "1.0.0");
    w.fs.create_dir_all(&w.versions_dir).expect("dir");
    w.fs.symlink("/real/tree", &w.versions_dir.join("1.0.0"))
        .expect("symlink");
    let (frames, packs) = download_with(&w, w.user_layout(None));
    assert_eq!((frames.len(), packs.len()), (0, 1), "{frames:?} {packs:?}");
}

// ---- machine scope -------------------------------------------------------------------------------

/// MemFs that records the path of every mutating call.
struct RecordingFs {
    inner: MemFs,
    writes: Arc<Mutex<Vec<PathBuf>>>,
}

impl RecordingFs {
    fn note(&self, path: &Path) {
        self.writes.lock().expect("log").push(path.to_path_buf());
    }
}

impl Fs for RecordingFs {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        self.inner.read_capped(path, max)
    }
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        self.inner.open_read(path)
    }
    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.note(path);
        self.inner.create_new(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.note(path);
        self.inner.open_append(path)
    }
    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        self.note(path);
        self.inner.truncate(path, len)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.note(from);
        self.note(to);
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.note(path);
        self.inner.remove_file(path)
    }
    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        self.note(path);
        self.inner.remove_dir_all_nofollow(path)
    }
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.note(path);
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        self.inner.list_dir(path)
    }
    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        self.inner.symlink_metadata(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(path)
    }
    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
        self.note(to_new);
        self.inner.copy_file(from, to_new)
    }
    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
        self.note(path);
        self.inner.set_exec(path, exec)
    }
    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        self.note(link_path);
        self.inner.symlink(target, link_path)
    }
    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        self.note(path);
        self.inner.try_lock(path)
    }
}

const MACHINE_STATE: &str = "/machine/state";
const MACHINE_VERSIONS: &str = "/machine/versions";
const USER_STATE: &str = "/user/state";

fn machine_world(machine_seq: u64, user_seq: u64) -> World {
    let w = World::new();
    let dir = Path::new(MACHINE_STATE);
    let loaded = load::<InstallState>(&w.fs, dir, &app_id(), &FakeHasher).expect("load");
    let mut machine = InstallState::new(1, app_id(), Scope::Machine, INSTALL_ID, TARGET)
        .install(version("1.0.0"), SUITE_T0 - 10 * DAY, TARGET, INSTALL_ID)
        .with_seq(loaded.next_seq);
    machine.floors.feed_seq.insert(channel(), machine_seq);
    commit(&w.fs, dir, &loaded, &machine, &FakeHasher).expect("machine commit");
    let store = MachineScope {
        machine_dir: dir.to_path_buf(),
        user_dir: PathBuf::from(USER_STATE),
        app_id: app_id(),
    };
    let counters = store
        .load_counters(&w.fs, &machine, &FakeHasher)
        .expect("counters");
    let mut next = InstallCounters::new(counters.next_seq, app_id(), INSTALL_ID);
    next.floors.feed_seq.insert(channel(), user_seq);
    store
        .commit_counters(&w.fs, &machine, &counters, &next, &FakeHasher)
        .expect("counters commit");
    w
}

fn machine_layout(w: &World, versions: Option<PathBuf>) -> Layout {
    Layout::Machine {
        machine_state_dir: PathBuf::from(MACHINE_STATE),
        user_state_dir: PathBuf::from(USER_STATE),
        cache_dir: w.cache_dir.clone(),
        versions_dir: versions,
        current_tree: None,
    }
}

#[test]
fn machine_scope_uses_the_higher_floor_and_never_writes_the_machine_dir() {
    let _s = serial();
    let w = machine_world(5, 3);
    let writes = Arc::new(Mutex::new(Vec::new()));
    let fs = Arc::new(RecordingFs {
        inner: w.fs.clone(),
        writes: Arc::clone(&writes),
    });
    let u = w
        .builder(machine_layout(&w, None), fs.clone())
        .build()
        .expect("build");
    // Above the user floor (3) but below the machine floor (5): refused.
    w.publish(4, "1.1.0");
    let err = block_on(u.check()).expect_err("rollback");
    assert!(
        matches!(err, Error::Verify(lunepack_core::Error::Rollback { .. })),
        "{err:?}"
    );
    // At or above both: accepted; the user's counters rise.
    w.publish(6, "1.1.0");
    let info = block_on(u.check()).expect("check").expect("update");
    let store = MachineScope {
        machine_dir: PathBuf::from(MACHINE_STATE),
        user_dir: PathBuf::from(USER_STATE),
        app_id: app_id(),
    };
    let machine = store
        .load_machine(&w.fs, &FakeHasher)
        .expect("machine")
        .record
        .expect("record");
    let counters = store
        .load_counters(&w.fs, &machine, &FakeHasher)
        .expect("counters")
        .record
        .expect("counters record");
    assert_eq!(counters.floors.feed_seq.get(&channel()), Some(&6));
    assert_eq!(machine.floors.feed_seq.get(&channel()), Some(&5));

    // Without a readable tree: nothing scanned, every frame fetched (the full pack here).
    block_on(u.download(&info, DownloadOptions::default())).expect("download");
    assert_eq!(names(&w.fs, &w.cache_dir.join("packs")).len(), 1);
    // Staging is the privileged engine's.
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("again");
    assert!(matches!(
        block_on(u.stage(downloaded)),
        Err(Error::MachineScope)
    ));
    workers_stopped();

    let log = writes.lock().expect("log");
    assert!(
        log.iter().all(|p| !p.starts_with("/machine")),
        "the library wrote the machine dirs: {log:?}"
    );
}

#[test]
fn machine_scope_reads_the_machine_tree_for_unchanged_files() {
    let _s = serial();
    let w = machine_world(1, 1);
    w.write_tree(&Path::new(MACHINE_VERSIONS).join("1.0.0"), "1.0.0");
    w.publish(2, "1.1.0");
    let writes = Arc::new(Mutex::new(Vec::new()));
    let fs = Arc::new(RecordingFs {
        inner: w.fs.clone(),
        writes: Arc::clone(&writes),
    });
    let u = w
        .builder(
            machine_layout(&w, Some(PathBuf::from(MACHINE_VERSIONS))),
            fs,
        )
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    block_on(u.download(&info, DownloadOptions::default())).expect("download");
    assert_eq!(names(&w.fs, &w.cache_dir.join("frames")).len(), 1);
    assert!(names(&w.fs, &w.cache_dir.join("packs")).is_empty());
    workers_stopped();
    assert!(
        writes
            .lock()
            .expect("log")
            .iter()
            .all(|p| !p.starts_with("/machine"))
    );
}

// ---- the D27 ladder ------------------------------------------------------------------------------

fn requests_since(w: &World, from: usize) -> Vec<Option<String>> {
    w.origin.requests()[from..]
        .iter()
        .map(|r| r.range_header.clone())
        .collect()
}

#[test]
fn a_corrupted_cached_frame_is_refetched_by_range() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = w
        .builder(w.user_layout(None), Arc::new(w.fs.clone()))
        .fetch_policy(ranges_ratio_never())
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let frames_dir = w.cache_dir.join("frames");
    let frames = names(&w.fs, &frames_dir);
    assert_eq!(frames.len(), 4, "{frames:?}");
    // Damage one cached frame (same length, other bytes).
    let victim = frames_dir.join(&frames[0]);
    let len = w.read(&victim).len();
    w.fs.remove_file(&victim).expect("remove");
    let mut f = w.fs.create_new(&victim).expect("create");
    f.write_all(&vec![0xAB; len]).expect("write");
    f.sync().expect("sync");
    drop(f);
    let before = w.origin.requests().len();
    let staged = block_on(u.stage(downloaded)).expect("stage");
    let extra = requests_since(&w, before);
    assert_eq!(extra.len(), 1, "{extra:?}");
    assert!(extra[0].is_some(), "the refetch was not a range: {extra:?}");
    for (path, bytes) in files("1.1.0") {
        assert_eq!(w.read(&staged.tree().join(path)), bytes);
    }
    workers_stopped();
}

/// Corrupts the first byte of every `206` body.
struct BadRanges(FakeTransport);

impl Transport for BadRanges {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let future = self.0.get(request);
        Box::pin(async move {
            let response = future.await?;
            if response.head.status != 206 {
                return Ok(response);
            }
            Ok(Response {
                head: response.head,
                body: Box::new(FlipFirst {
                    inner: response.body,
                    first: true,
                }),
            })
        })
    }
}

struct FlipFirst {
    inner: Box<dyn lunepack_core::Body>,
    first: bool,
}

impl lunepack_core::Body for FlipFirst {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            let mut chunk = self.inner.next_chunk().await?;
            if let Some(c) = chunk.as_mut()
                && self.first
            {
                c[0] ^= 0xFF;
                self.first = false;
            }
            Ok(chunk)
        })
    }
}

#[test]
fn a_server_that_serves_a_bad_frame_twice_is_healed_by_the_full_pack() {
    let _s = serial();
    let fake = FakeTransport::new(lunepack_testkit::FakeOrigin::new());
    let origin = fake.origin().clone();
    let w = World::with_transport(origin, Arc::new(BadRanges(fake)));
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = w
        .builder(w.user_layout(None), Arc::new(w.fs.clone()))
        .fetch_policy(ranges_ratio_never())
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let before = w.origin.requests().len();
    let staged = block_on(u.stage(downloaded)).expect("stage");
    let extra = requests_since(&w, before);
    assert_eq!(extra.len(), 2, "{extra:?}");
    assert!(extra[0].is_some(), "rung 2 is a range: {extra:?}");
    assert_eq!(extra[1], None, "rung 3 is the full pack: {extra:?}");
    for (path, bytes) in files("1.1.0") {
        assert_eq!(w.read(&staged.tree().join(path)), bytes);
    }
    workers_stopped();
}

#[test]
fn a_bad_publisher_frame_exhausts_the_ladder_naming_the_file() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    let mut pack = w.pack("1.1.0");
    // The manifest promises other bytes than the frame decodes to.
    pack.entries[0].sha256 = Some(sha(b"something the frame does not hold"));
    w.publish_pack(1, "1.1.0", &pack);
    let u = w
        .builder(w.user_layout(None), Arc::new(w.fs.clone()))
        .fetch_policy(ranges_ratio_never())
        .build()
        .expect("build");
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let before = w.origin.requests().len();
    let err = block_on(u.stage(downloaded)).expect_err("exhausted");
    match &err {
        Error::NeedFetchExhausted(paths) => {
            let shown: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
            assert_eq!(shown, vec!["bin/app".to_owned()]);
        }
        other => panic!("expected NeedFetchExhausted, got {other:?}"),
    }
    let extra = requests_since(&w, before);
    assert_eq!(
        extra.len(),
        2,
        "one range retry and one full-pack try: {extra:?}"
    );
    assert!(extra[0].is_some());
    assert_eq!(extra[1], None);
    assert_eq!(u.staged().expect("staged"), None);
    workers_stopped();
}

// ---- staged() ------------------------------------------------------------------------------------

fn with_staged(w: &World, staged: StagedRef, bad: &[&str]) {
    let loaded = w.user_state();
    let mut next = loaded.record.expect("record").set_staged(Some(staged));
    for b in bad {
        next = next.mark_bad(version(b));
    }
    w.commit_user(next);
}

/// (name, staged version, staged target, tree present, bad versions, expected Some)
type StagedCase = (
    &'static str,
    &'static str,
    Target,
    bool,
    &'static [&'static str],
    bool,
);

#[test]
fn staged_is_none_unless_newer_good_same_target_and_a_real_tree() {
    let _s = serial();
    let digest = sha(b"manifest");
    let cases: [StagedCase; 5] = [
        (
            "newer, good, tree present",
            "1.2.0",
            TARGET,
            true,
            &[],
            true,
        ),
        ("not newer than current", "1.0.0", TARGET, true, &[], false),
        ("marked bad", "1.2.0", TARGET, true, &["1.2.0"], false),
        ("tree missing", "1.2.0", TARGET, false, &[], false),
        (
            "target mismatch",
            "1.2.0",
            Target::MacosAarch64,
            true,
            &[],
            false,
        ),
    ];
    for (name, staged_version, target, tree, bad, expect) in cases {
        let w = World::new();
        w.install("1.0.0", SUITE_T0 - 10 * DAY);
        with_staged(
            &w,
            StagedRef::new(version(staged_version), target, digest),
            bad,
        );
        if tree {
            w.fs.create_dir_all(&w.versions_dir.join(staged_version))
                .expect("tree");
        }
        let got = w.updater().staged().expect("staged");
        assert_eq!(got.is_some(), expect, "{name}: {got:?}");
    }
}

// ---- construction, futures, blocking -------------------------------------------------------------

#[test]
fn a_root_of_another_app_is_refused_at_build() {
    let _s = serial();
    let w = World::new();
    let other = lunepack_core::AppId::parse("org.example.other").expect("app id");
    let result = lunepack::UpdaterBuilder::new(
        other,
        w.root(),
        &w.feed_url(),
        channel(),
        w.user_layout(None),
    )
    .fs(Arc::new(w.fs.clone()))
    .build();
    assert!(matches!(
        result,
        Err(Error::Verify(lunepack_core::Error::AppIdMismatch))
    ));
    let bad_url = lunepack::UpdaterBuilder::new(
        app_id(),
        w.root(),
        "ftp://example.invalid/feed.json",
        channel(),
        w.user_layout(None),
    )
    .build();
    assert!(matches!(bad_url, Err(Error::Config(_))));
}

#[test]
fn the_default_adapters_build_and_a_dev_run_reports_not_installed() {
    let _s = serial();
    let w = World::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path();
    std::fs::write(base.join("keys.json"), w.served("keys.json")).expect("keys");
    let feed_url = url::Url::from_file_path(base.join("feed-stable.json"))
        .expect("file url")
        .to_string();
    // Default StdFs, DirSource, codec, crypto and clock; the temp dir may sit under a symlinked
    // ancestor (macOS /var), which the builder resolves.
    let u = lunepack::UpdaterBuilder::new(
        app_id(),
        w.root(),
        &feed_url,
        channel(),
        Layout::User {
            state_dir: base.join("state"),
            cache_dir: base.join("cache"),
            versions_dir: base.join("versions"),
            current_tree: None,
        },
    )
    .build()
    .expect("build");
    assert_eq!(u.installed().expect("installed"), None);
    assert!(matches!(block_on(u.check()), Err(Error::NotInstalled)));
    workers_stopped();
}

#[test]
fn the_public_futures_are_send_and_static() {
    let _s = serial();
    fn assert_send_static<T: Send + 'static>(_: &T) {}
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = w.updater();
    let check = u.check();
    assert_send_static(&check);
    let info = block_on(check).expect("check").expect("update");
    let download = u.download(&info, DownloadOptions::default());
    assert_send_static(&download);
    let downloaded = block_on(download).expect("download");
    let stage = u.stage(downloaded);
    assert_send_static(&stage);
    drop(stage);
    assert_send_static(&u);
    workers_stopped();
}

#[test]
fn the_blocking_updater_runs_and_honours_its_cancel_token() {
    let _s = serial();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = lunepack::blocking::Updater::from(w.updater());
    let cancelled = lunepack_core::CancelToken::new();
    cancelled.cancel();
    assert!(matches!(u.check(&cancelled), Err(Error::Cancelled)));
    let cancel = lunepack_core::CancelToken::new();
    let info = u.check(&cancel).expect("check").expect("update");
    let downloaded = u
        .download(&info, DownloadOptions::default(), &cancel)
        .expect("download");
    let staged = u.stage(downloaded, &cancel).expect("stage");
    assert_eq!(u.staged().expect("staged"), Some(staged));
    workers_stopped();
}

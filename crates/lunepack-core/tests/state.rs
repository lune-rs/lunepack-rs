//! The install-state store (FORMAT.md 12, M4 step 5) over the crash-injecting `MemFs`: round trips,
//! transitions, scopes, the read-failure classes of M4-D23, record evolution (M4-D22), a crash at
//! every write point of a commit, and the golden example in `docs/FORMAT.md`.
//!
//! Every fixture is a file written by `commit` (or, for records a correct writer never produces,
//! a payload taken from a `commit` file, edited, and framed by the real framing code through
//! `commit_raw_payload`); no record bytes are typed by hand.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lunepack_core::state::{
    self, KEEP_RECORDS, MAX_BAD_VERSIONS, MAX_CHANNELS, MAX_RECORD_BYTES, commit,
    commit_raw_payload, load,
};
use lunepack_core::trust::PublicKey;
use lunepack_core::{
    AppId, Channel, CurrentRef, DirEntryInfo, FileWrite, Floors, Fs, FsError, Hasher,
    InstallCounters, InstallState, Loaded, LockGuard, MachineScope, Meta, PreviousRef, ReadAt,
    RootParts, Scope, StagedRef, StateError, Target, UserScope, Version,
};
use lunepack_testkit::{FakeHasher, MemFs, RecoverMode};
use serde_json::{Map, Value, json};

const H: FakeHasher = FakeHasher;
const MAX_U53: u64 = (1 << 53) - 1;

fn app() -> AppId {
    AppId::parse("org.example.hello").unwrap()
}

fn dir() -> PathBuf {
    PathBuf::from("/home/state")
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn key(label: &str) -> PublicKey {
    PublicKey::from_bytes(*H.sha256(label.as_bytes()).as_bytes())
}

fn chan(text: &str) -> Channel {
    Channel::parse(text).unwrap()
}

const INSTALL_ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// A record with every field set (the golden example).
fn sample(seq: u64) -> InstallState {
    let mut r = InstallState::new(seq, app(), Scope::User, INSTALL_ID, Target::LinuxX86_64);
    r.current = Some(CurrentRef {
        version: v("1.0.0"),
        issued: 1_790_000_000,
    });
    r.previous = Some(PreviousRef {
        version: v("0.9.0"),
    });
    r.staged = Some(StagedRef::new(
        v("1.1.0"),
        Target::LinuxX86_64,
        H.sha256(b"the 1.1.0 manifest"),
    ));
    r.bad = vec![v("1.0.1")];
    r.floors = Floors {
        root: Some(RootParts {
            version: 2,
            threshold: 1,
            keys: vec![key("root key 1"), key("root key 2")],
        }),
        keyset_version: 3,
        feed_seq: [(chan("stable"), 42)].into_iter().collect(),
    };
    r
}

fn floors(keyset: u64, stable: u64) -> Floors {
    Floors {
        root: None,
        keyset_version: keyset,
        feed_seq: [(chan("stable"), stable)].into_iter().collect(),
    }
}

fn load_state(fs: &dyn Fs) -> Result<Loaded<InstallState>, StateError> {
    load::<InstallState>(fs, &dir(), &app(), &H)
}

fn path_of(seq: u64) -> PathBuf {
    dir().join(format!("{seq:020}.rec"))
}

fn bytes_of(fs: &dyn Fs, seq: u64) -> Vec<u8> {
    fs.read_capped(&path_of(seq), MAX_RECORD_BYTES).unwrap()
}

/// Replaces the file at `path` (durably).
fn put_file(fs: &dyn Fs, path: &Path, bytes: &[u8]) {
    if fs.symlink_metadata(path).unwrap().is_some() {
        fs.remove_file(path).unwrap();
    }
    let mut f = fs.create_new(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync().unwrap();
    drop(f);
    fs.sync_dir(path.parent().unwrap()).unwrap();
}

fn names(fs: &dyn Fs) -> Vec<String> {
    let mut out: Vec<String> = fs
        .list_dir(&dir())
        .unwrap()
        .into_iter()
        .map(|e| e.name.to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// Commits the first record and then each transition of the previous one; returns the store and
/// the records in order.
fn store_with(steps: &[&dyn Fn(&InstallState) -> InstallState]) -> (MemFs, Vec<InstallState>) {
    let fs = MemFs::new();
    let first = InstallState::new(1, app(), Scope::User, INSTALL_ID, Target::LinuxX86_64);
    commit(&fs, &dir(), &load_state(&fs).unwrap(), &first, &H).unwrap();
    let mut records = vec![first];
    for step in steps {
        let loaded = load_state(&fs).unwrap();
        let next = step(loaded.record.as_ref().unwrap()).with_seq(loaded.next_seq);
        commit(&fs, &dir(), &loaded, &next, &H).unwrap();
        records.push(next);
    }
    (fs, records)
}

fn two_records() -> (MemFs, Vec<InstallState>) {
    store_with(&[&|r| r.raise_floors(&floors(1, 7))])
}

/// The JSON payload of a record file.
fn payload(file: &[u8]) -> Map<String, Value> {
    let len = u32::from_be_bytes([file[5], file[6], file[7], file[8]]) as usize;
    serde_json::from_slice(&file[9..9 + len]).unwrap()
}

/// Writes `edited` (a payload from a `commit` file) as record `seq` through the real framing.
fn raw(fs: &dyn Fs, seq: u64, edited: &Map<String, Value>) {
    let bytes = serde_json::to_vec(edited).unwrap();
    commit_raw_payload(fs, &dir(), seq, &bytes, &H).unwrap();
}

/// Record 3 written raw from record 2's payload after `edit`, over a store holding records 1, 2.
fn newest_edited(edit: impl FnOnce(&mut Map<String, Value>)) -> (MemFs, Vec<InstallState>) {
    let (fs, records) = two_records();
    let mut p = payload(&bytes_of(&fs, 2));
    p.insert("seq".into(), json!(3));
    edit(&mut p);
    raw(&fs, 3, &p);
    (fs, records)
}

// ---- basics ---------------------------------------------------------------------------------------

#[test]
fn a_missing_or_empty_dir_has_no_record() {
    let fs = MemFs::new();
    let loaded = load_state(&fs).unwrap();
    assert!(loaded.record.is_none());
    assert_eq!(loaded.next_seq, 1);
    fs.create_dir_all(&dir()).unwrap();
    let loaded = load_state(&fs).unwrap();
    assert!(loaded.record.is_none());
    assert_eq!(loaded.next_seq, 1);
}

#[test]
fn a_committed_record_loads_back_equal() {
    let fs = MemFs::new();
    let record = sample(1);
    commit(&fs, &dir(), &load_state(&fs).unwrap(), &record, &H).unwrap();
    let loaded = load_state(&fs).unwrap();
    assert_eq!(loaded.record.as_ref(), Some(&record));
    assert_eq!(loaded.next_seq, 2);
    assert_eq!(names(&fs), vec!["00000000000000000001.rec"]);
}

#[test]
fn transitions_number_the_next_record_and_keep_the_rest() {
    let r = sample(4);
    let staged = r.set_staged(None);
    assert_eq!(staged.seq, 5);
    assert!(staged.staged.is_none());
    assert_eq!(staged.floors, r.floors);
    let bad = r
        .mark_bad(v("1.0.3"))
        .mark_bad(v("0.5.0"))
        .mark_bad(v("1.0.3"));
    assert_eq!(bad.seq, 7);
    assert_eq!(bad.bad, vec![v("0.5.0"), v("1.0.1"), v("1.0.3")]);
    let installed = r.install(v("1.1.0"), 1_800_000_000, Target::LinuxAarch64, [9; 16]);
    assert_eq!(installed.seq, 5);
    assert_eq!(installed.previous.as_ref().unwrap().version, v("1.0.0"));
    assert_eq!(installed.current.as_ref().unwrap().version, v("1.1.0"));
    assert_eq!(installed.current.as_ref().unwrap().issued, 1_800_000_000);
    assert_eq!(
        (installed.target, installed.install_id),
        (Target::LinuxAarch64, [9; 16])
    );
    for t in [&staged, &bad, &installed] {
        assert_eq!(t.floors, r.floors, "a transition changed the floors");
        assert_eq!((&t.critical, &t.extra), (&r.critical, &r.extra));
    }
}

#[test]
fn commit_checks_the_seq() {
    let (fs, _) = two_records();
    let loaded = load_state(&fs).unwrap();
    let record = loaded.record.clone().unwrap();
    // A transition of record 2 is 3, the next seq: accepted. Any other is refused.
    let wrong = record.set_staged(None).with_seq(9);
    assert!(matches!(
        commit(&fs, &dir(), &loaded, &wrong, &H),
        Err(StateError::Seq {
            expected: 3,
            found: 9
        })
    ));
    let exhausted = Loaded {
        next_seq: MAX_U53 + 1,
        ..loaded.clone()
    };
    let over = record.set_staged(None).with_seq(MAX_U53 + 1);
    assert!(matches!(
        commit(&fs, &dir(), &exhausted, &over, &H),
        Err(StateError::SeqExhausted)
    ));
    commit(&fs, &dir(), &loaded, &record.set_staged(None), &H).unwrap();
}

#[test]
fn a_name_above_2_pow_53_is_not_a_record_name() {
    let (fs, records) = two_records();
    put_file(&fs, &dir().join(format!("{:020}.rec", MAX_U53 + 1)), b"x");
    let loaded = load_state(&fs).unwrap();
    assert_eq!(loaded.record.as_ref(), Some(&records[1]));
    assert_eq!(loaded.next_seq, 3);
}

#[test]
fn a_second_writer_with_the_same_seq_gets_conflict() {
    let (fs, _) = two_records();
    let loaded = load_state(&fs).unwrap();
    let next = loaded.record.as_ref().unwrap().set_staged(None);
    commit(&fs, &dir(), &loaded, &next, &H).unwrap();
    let again = loaded.record.as_ref().unwrap().mark_bad(v("2.0.0"));
    assert!(matches!(
        commit(&fs, &dir(), &loaded, &again, &H),
        Err(StateError::Conflict { seq: 3 })
    ));
}

#[test]
fn commit_refuses_a_record_its_reader_would_refuse() {
    let (fs, _) = two_records();
    let loaded = load_state(&fs).unwrap();
    let base = loaded.record.clone().unwrap();
    let refuse = |next: InstallState, what: &str| {
        let got = commit(&fs, &dir(), &loaded, &next, &H);
        assert!(
            matches!(got, Err(StateError::Invalid(_))),
            "{what}: {got:?}"
        );
    };
    let mut tree = base.set_staged(Some(StagedRef::new(
        v("1.2.0"),
        Target::LinuxX86_64,
        H.sha256(b"m"),
    )));
    tree.staged.as_mut().unwrap().tree = "1.2.1".into();
    refuse(tree, "tree is not the version text");
    let mut nested = base.set_staged(Some(StagedRef::new(
        v("1.2.0"),
        Target::LinuxX86_64,
        H.sha256(b"m"),
    )));
    nested.staged.as_mut().unwrap().tree = "a/1.2.0".into();
    refuse(nested, "tree is two components");
    let mut unsorted = base.set_staged(None);
    unsorted.bad = vec![v("2.0.0"), v("1.0.0")];
    refuse(unsorted, "bad not sorted");
    let mut twice = base.set_staged(None);
    twice.bad = vec![v("1.0.0"), v("1.0.0+build")];
    refuse(twice, "bad has one precedence twice");
    let mut many = base.set_staged(None);
    many.bad = (0..=MAX_BAD_VERSIONS as u64)
        .map(|i| v(&format!("0.0.{i}")))
        .collect();
    refuse(many, "too many bad");
    let mut channels = base.set_staged(None);
    for i in 0..=MAX_CHANNELS {
        channels.floors.feed_seq.insert(chan(&format!("c{i}")), 1);
    }
    refuse(channels, "too many channels");
    let mut root = base.set_staged(None);
    root.floors.root = Some(RootParts {
        version: 1,
        threshold: 2,
        keys: vec![key("k")],
    });
    refuse(root, "threshold above the key count");
    let mut health = base.set_staged(None);
    health.extra.insert("health".into(), json!(3));
    refuse(health, "health is a number");
    let mut collide = base.set_staged(None);
    collide.extra.insert("floors".into(), json!({}));
    refuse(collide, "extra uses a defined key");
    let mut other_app = base.set_staged(None);
    other_app.app_id = AppId::parse("org.example.other").unwrap();
    refuse(other_app, "another app id");
    assert_eq!(load_state(&fs).unwrap().next_seq, 3, "nothing was written");
}

#[test]
fn commit_refuses_to_lower_a_floor() {
    let (fs, _) = two_records();
    let loaded = load_state(&fs).unwrap();
    let mut lower = loaded.record.as_ref().unwrap().set_staged(None);
    lower.floors.feed_seq.insert(chan("stable"), 6);
    assert!(matches!(
        commit(&fs, &dir(), &loaded, &lower, &H),
        Err(StateError::FloorLowered)
    ));
}

#[test]
fn prune_keeps_the_three_newest_and_unknown_files() {
    let fs = MemFs::new();
    fs.create_dir_all(&dir()).unwrap();
    put_file(&fs, &dir().join("notes.txt"), b"not a record");
    put_file(&fs, &dir().join("1.rec"), b"not a record name");
    let first = InstallState::new(1, app(), Scope::User, INSTALL_ID, Target::LinuxX86_64);
    commit(&fs, &dir(), &load_state(&fs).unwrap(), &first, &H).unwrap();
    for i in 1..=5 {
        let loaded = load_state(&fs).unwrap();
        let next = loaded.record.as_ref().unwrap().raise_floors(&floors(i, i));
        commit(&fs, &dir(), &loaded, &next, &H).unwrap();
    }
    let recs: Vec<String> = names(&fs).into_iter().filter(|n| n.len() == 24).collect();
    assert_eq!(recs.len(), KEEP_RECORDS);
    assert_eq!(
        recs,
        vec![
            "00000000000000000004.rec",
            "00000000000000000005.rec",
            "00000000000000000006.rec"
        ]
    );
    assert!(names(&fs).contains(&"notes.txt".to_owned()));
    assert!(names(&fs).contains(&"1.rec".to_owned()));
    assert_eq!(load_state(&fs).unwrap().record.unwrap().seq, 6);
}

#[test]
fn prune_removes_torn_files_but_not_a_stop() {
    let (fs, _) = two_records();
    // A torn file below the newest, and a whole-but-invalid one: only the torn one goes.
    let torn = bytes_of(&fs, 1);
    put_file(&fs, &path_of(1), &torn[..torn.len() - 1]);
    let mut p = payload(&bytes_of(&fs, 2));
    p.insert("seq".into(), json!(0));
    p.insert("bad".into(), json!(["2.0.0", "1.0.0"]));
    raw(&fs, 0, &p);
    let loaded = load_state(&fs).unwrap();
    let next = loaded.record.as_ref().unwrap().set_staged(None);
    commit(&fs, &dir(), &loaded, &next, &H).unwrap();
    assert_eq!(
        names(&fs),
        vec![
            "00000000000000000000.rec",
            "00000000000000000002.rec",
            "00000000000000000003.rec"
        ]
    );
}

// ---- integrity failures skip (M4-D23) -----------------------------------------------------------

#[test]
fn a_flipped_byte_in_payload_length_or_checksum_is_skipped() {
    let (fs0, _) = two_records();
    let len = bytes_of(&fs0, 2).len();
    for (what, at) in [
        ("magic", 0),
        ("length", 7),
        ("payload", 20),
        ("payload end", len - 33),
        ("checksum", len - 1),
    ] {
        let (fs, records) = two_records();
        let mut bytes = bytes_of(&fs, 2);
        bytes[at] ^= 0x01;
        put_file(&fs, &path_of(2), &bytes);
        let loaded = load_state(&fs).unwrap();
        assert_eq!(loaded.record.as_ref(), Some(&records[0]), "{what}");
        assert_eq!(
            loaded.next_seq, 3,
            "{what}: the torn file's seq is not reused"
        );
    }
}

#[test]
fn torn_prefixes_and_format_byte_0_are_skipped() {
    let (fs0, _) = two_records();
    let full = bytes_of(&fs0, 2);
    for cut in [0, 1, 4, 5, 8, 9, 40, full.len() - 32, full.len() - 1] {
        let (fs, records) = two_records();
        put_file(&fs, &path_of(2), &full[..cut]);
        assert_eq!(
            load_state(&fs).unwrap().record.as_ref(),
            Some(&records[0]),
            "cut {cut}"
        );
    }
    let (fs, records) = two_records();
    let mut zero = full.clone();
    zero[4] = 0;
    put_file(&fs, &path_of(2), &zero);
    assert_eq!(load_state(&fs).unwrap().record.as_ref(), Some(&records[0]));
}

#[test]
fn a_valid_record_under_another_name_is_skipped() {
    let (fs, records) = two_records();
    put_file(&fs, &path_of(3), &bytes_of(&fs, 1));
    let loaded = load_state(&fs).unwrap();
    assert_eq!(loaded.record.as_ref(), Some(&records[1]));
    assert_eq!(loaded.next_seq, 4);
}

/// An `Fs` over a `MemFs` that records the `max` of every `read_capped` and the op count right
/// after the first `sync_dir` of the state dir.
struct Capped<'a> {
    inner: &'a MemFs,
    maxes: Mutex<Vec<u64>>,
    dir_synced_at: Mutex<Option<u64>>,
}

impl<'a> Capped<'a> {
    fn new(inner: &'a MemFs) -> Self {
        Capped {
            inner,
            maxes: Mutex::new(Vec::new()),
            dir_synced_at: Mutex::new(None),
        }
    }
}

impl Fs for Capped<'_> {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        self.maxes.lock().unwrap().push(max);
        self.inner.read_capped(path, max)
    }
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        self.inner.open_read(path)
    }
    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.inner.create_new(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.inner.open_append(path)
    }
    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        self.inner.truncate(path, len)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_dir_all_nofollow(path)
    }
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        self.inner.list_dir(path)
    }
    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        self.inner.symlink_metadata(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(path)?;
        let mut at = self.dir_synced_at.lock().unwrap();
        if path == dir() && at.is_none() {
            *at = Some(self.inner.op_count());
        }
        Ok(())
    }
    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
        self.inner.copy_file(from, to_new)
    }
    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
        self.inner.set_exec(path, exec)
    }
    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        self.inner.symlink(target, link_path)
    }
    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        self.inner.try_lock(path)
    }
}

#[test]
fn a_file_over_the_cap_is_skipped_and_every_read_is_capped() {
    let (fs, records) = two_records();
    let mut big = bytes_of(&fs, 2);
    big.resize(MAX_RECORD_BYTES as usize + 1, b' ');
    put_file(&fs, &path_of(3), &big);
    let capped = Capped::new(&fs);
    let loaded = load::<InstallState>(&capped, &dir(), &app(), &H).unwrap();
    assert_eq!(loaded.record.as_ref(), Some(&records[1]));
    assert_eq!(loaded.next_seq, 4);
    let maxes = capped.maxes.lock().unwrap().clone();
    assert_eq!(maxes, vec![MAX_RECORD_BYTES, MAX_RECORD_BYTES]);
}

// ---- whole records that are refused stop (M4-D23) -----------------------------------------------

#[test]
fn a_whole_but_invalid_newest_record_stops_the_load() {
    type Edit = Box<dyn FnOnce(&mut Map<String, Value>)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "bad not sorted",
            Box::new(|p| {
                p.insert("bad".into(), json!(["2.0.0", "1.0.0"]));
            }),
        ),
        (
            "unknown key in floors",
            Box::new(|p| {
                p["floors"]
                    .as_object_mut()
                    .unwrap()
                    .insert("x_future".into(), json!(1));
            }),
        ),
        (
            "unknown key in current",
            Box::new(|p| {
                p.insert(
                    "current".into(),
                    json!({"version": "1.0.0", "issued": 1, "x": 1}),
                );
            }),
        ),
        (
            "missing field",
            Box::new(|p| {
                p.remove("pending");
            }),
        ),
        (
            "floors.root missing",
            Box::new(|p| {
                p["floors"].as_object_mut().unwrap().remove("root");
            }),
        ),
        (
            "integer above 2^53 - 1",
            Box::new(|p| {
                p["floors"]["keyset_version"] = json!(MAX_U53 + 1);
            }),
        ),
        (
            "app id",
            Box::new(|p| {
                p.insert("app_id".into(), json!("org.example.other"));
            }),
        ),
        (
            "kind",
            Box::new(|p| {
                p.insert("kind".into(), json!("install-counters"));
            }),
        ),
        (
            "format 0",
            Box::new(|p| {
                p.insert("format".into(), json!(0));
            }),
        ),
        (
            "scope",
            Box::new(|p| {
                p.insert("scope".into(), json!("everyone"));
            }),
        ),
        (
            "install id uppercase",
            Box::new(|p| {
                p.insert(
                    "install_id".into(),
                    json!("000102030405060708090A0B0C0D0E0F"),
                );
            }),
        ),
        (
            "health a string",
            Box::new(|p| {
                p.insert("health".into(), json!("ok"));
            }),
        ),
    ];
    for (what, edit) in cases {
        let (fs, _) = newest_edited(edit);
        let got = load_state(&fs);
        assert!(
            matches!(got, Err(StateError::Invalid(_))),
            "{what}: an older record must not be returned, got {got:?}"
        );
    }
}

#[test]
fn a_duplicate_key_in_a_whole_record_stops_the_load() {
    let (fs, _) = two_records();
    let p = payload(&bytes_of(&fs, 2));
    let mut text = serde_json::to_string(&p).unwrap();
    text = text.replacen("\"seq\":2", "\"seq\":3,\"seq\":3", 1);
    commit_raw_payload(&fs, &dir(), 3, text.as_bytes(), &H).unwrap();
    assert!(matches!(load_state(&fs), Err(StateError::Invalid(_))));
}

#[test]
fn newer_formats_stop_the_load() {
    let (fs, _) = two_records();
    let mut bytes = bytes_of(&fs, 2);
    bytes[4] = 2;
    put_file(&fs, &path_of(2), &bytes);
    assert!(matches!(load_state(&fs), Err(StateError::NewerFormat)));

    let (fs, _) = newest_edited(|p| {
        p.insert("critical".into(), json!(["x_future"]));
    });
    assert!(matches!(load_state(&fs), Err(StateError::NewerFormat)));

    let (fs, _) = newest_edited(|p| {
        p.insert("format".into(), json!(2));
    });
    assert!(matches!(load_state(&fs), Err(StateError::NewerFormat)));
}

// ---- evolution (M4-D22) ---------------------------------------------------------------------------

#[test]
fn unknown_top_level_fields_are_kept_through_transitions() {
    let x_future = json!({"a": [1, 2]});
    let health = json!({"t": "token"});
    let (fs, _) = newest_edited(|p| {
        p.insert("x_future".into(), x_future.clone());
        p.insert("health".into(), health.clone());
    });
    let loaded = load_state(&fs).unwrap();
    let record = loaded.record.clone().unwrap();
    assert_eq!(record.seq, 3);
    assert_eq!(record.extra.get("x_future"), Some(&x_future));
    assert_eq!(record.extra.get("health"), Some(&health));
    let next = record.raise_floors(&floors(9, 9));
    commit(&fs, &dir(), &loaded, &next, &H).unwrap();
    let written = payload(&bytes_of(&fs, 4));
    assert_eq!(written.get("x_future"), Some(&x_future));
    assert_eq!(written.get("health"), Some(&health));
    assert_eq!(load_state(&fs).unwrap().record, Some(next));
}

#[test]
fn a_new_record_writes_health_null() {
    let fs = MemFs::new();
    let first = InstallState::new(1, app(), Scope::User, INSTALL_ID, Target::LinuxX86_64);
    commit(&fs, &dir(), &load_state(&fs).unwrap(), &first, &H).unwrap();
    assert_eq!(payload(&bytes_of(&fs, 1)).get("health"), Some(&Value::Null));
}

// ---- floors -------------------------------------------------------------------------------------

/// xorshift64*: deterministic pseudo-random pairs without a dependency.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % n
    }

    fn floors(&mut self) -> Floors {
        let root = match self.below(4) {
            0 => None,
            _ => Some(RootParts {
                version: 1 + self.below(3),
                threshold: 1 + self.below(2),
                keys: (0..2)
                    .map(|_| key(&format!("k{}", self.below(3))))
                    .collect(),
            }),
        };
        let mut feed_seq = BTreeMap::new();
        for c in ["stable", "beta", "nightly"] {
            if self.below(2) == 0 {
                feed_seq.insert(chan(c), self.below(5));
            }
        }
        Floors {
            root,
            keyset_version: self.below(5),
            feed_seq,
        }
    }
}

#[test]
fn raising_floors_commutes_and_never_lowers() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2000 {
        let mut base = sample(1);
        base.floors = rng.floors();
        let a = rng.floors();
        let b = rng.floors();
        let ab = base.raise_floors(&a).raise_floors(&b);
        let ba = base.raise_floors(&b).raise_floors(&a);
        assert_eq!(ab, ba);
        for (what, other) in [("base", &base.floors), ("a", &a), ("b", &b)] {
            assert!(ab.floors.is_at_least(other), "below {what}");
        }
        let lower_root = a
            .root
            .as_ref()
            .zip(b.root.as_ref())
            .map(|(x, y)| x.version.min(y.version));
        if let (Some(low), Some(root)) = (lower_root, &ab.floors.root) {
            assert!(root.version >= low);
        }
        assert_eq!(a.max(&a), a, "idempotent");
        assert_eq!(
            a.max(&b).max(&base.floors),
            a.max(&b.max(&base.floors)),
            "associative"
        );
    }
}

#[test]
fn a_lower_root_version_never_replaces_a_higher_one() {
    let high = RootParts {
        version: 5,
        threshold: 1,
        keys: vec![key("a")],
    };
    let low = RootParts {
        version: 4,
        threshold: 3,
        keys: vec![key("x"), key("y"), key("z")],
    };
    let with = |r: &RootParts| Floors {
        root: Some(r.clone()),
        ..Floors::default()
    };
    assert_eq!(with(&high).max(&with(&low)).root, Some(high.clone()));
    assert_eq!(with(&low).max(&with(&high)).root, Some(high.clone()));
    assert_eq!(with(&high).max(&Floors::default()).root, Some(high));
}

// ---- scopes (C3) ----------------------------------------------------------------------------------

fn machine_record(fs: &MemFs, scope: &MachineScope) -> InstallState {
    let mut machine = InstallState::new(1, app(), Scope::Machine, [7; 16], Target::LinuxX86_64);
    machine.floors = floors(4, 10);
    let loaded = load::<InstallState>(fs, &scope.machine_dir, &app(), &H).unwrap();
    commit(fs, &scope.machine_dir, &loaded, &machine, &H).unwrap();
    machine
}

fn machine_scope() -> MachineScope {
    MachineScope {
        machine_dir: PathBuf::from("/machine/state"),
        user_dir: PathBuf::from("/home/state"),
        app_id: app(),
    }
}

#[test]
fn user_scope_loads_and_commits_user_records_only() {
    let fs = MemFs::new();
    let scope = UserScope {
        dir: dir(),
        app_id: app(),
    };
    let loaded = scope.load(&fs, &H).unwrap();
    let machine = InstallState::new(1, app(), Scope::Machine, INSTALL_ID, Target::LinuxX86_64);
    assert!(matches!(
        scope.commit(&fs, &loaded, &machine, &H),
        Err(StateError::Invalid(_))
    ));
    scope.commit(&fs, &loaded, &sample(1), &H).unwrap();
    assert_eq!(scope.load(&fs, &H).unwrap().record, Some(sample(1)));
    // A machine record in a user dir is refused.
    let ms = MachineScope {
        machine_dir: dir(),
        ..machine_scope()
    };
    assert!(matches!(
        ms.load_machine(&fs, &H),
        Err(StateError::Invalid(_))
    ));
}

#[test]
fn machine_scope_keeps_counters_per_install_and_takes_the_higher_floors() {
    let fs = MemFs::new();
    let scope = machine_scope();
    let machine = machine_record(&fs, &scope);
    let loaded_machine = scope.load_machine(&fs, &H).unwrap();
    assert_eq!(loaded_machine.record.as_ref(), Some(&machine));
    assert_eq!(
        scope.counters_dir(&machine),
        PathBuf::from("/home/state/07070707070707070707070707070707")
    );

    let loaded = scope.load_counters(&fs, &machine, &H).unwrap();
    assert!(loaded.record.is_none());
    let mut counters = InstallCounters::new(loaded.next_seq, app(), machine.install_id);
    counters.floors = Floors {
        root: None,
        keyset_version: 2,
        feed_seq: [(chan("stable"), 12), (chan("beta"), 3)]
            .into_iter()
            .collect(),
    };
    scope
        .commit_counters(&fs, &machine, &loaded, &counters, &H)
        .unwrap();
    let loaded = scope.load_counters(&fs, &machine, &H).unwrap();
    assert_eq!(loaded.record.as_ref(), Some(&counters));
    let raised = counters.raise_floors(&floors(5, 1));
    assert_eq!(raised.seq, 2);
    scope
        .commit_counters(&fs, &machine, &loaded, &raised, &H)
        .unwrap();

    let effective = MachineScope::effective_floors(&machine, Some(&raised));
    assert_eq!(effective.keyset_version, 5);
    assert_eq!(effective.feed_seq.get(&chan("stable")), Some(&12));
    assert_eq!(effective.feed_seq.get(&chan("beta")), Some(&3));
    assert_eq!(
        MachineScope::effective_floors(&machine, None),
        machine.floors
    );

    let other = InstallCounters::new(3, app(), [8; 16]);
    let loaded = scope.load_counters(&fs, &machine, &H).unwrap();
    assert!(matches!(
        scope.commit_counters(&fs, &machine, &loaded, &other, &H),
        Err(StateError::Invalid(_))
    ));
}

#[test]
fn counters_of_another_install_are_refused() {
    let fs = MemFs::new();
    let scope = machine_scope();
    let machine = machine_record(&fs, &scope);
    // Counters for install [8; 16], written where install [7; 16]'s belong.
    let dir = scope.counters_dir(&machine);
    let wrong = InstallCounters::new(1, app(), [8; 16]);
    let loaded = load::<InstallCounters>(&fs, &dir, &app(), &H).unwrap();
    commit(&fs, &dir, &loaded, &wrong, &H).unwrap();
    assert!(matches!(
        scope.load_counters(&fs, &machine, &H),
        Err(StateError::Invalid(_))
    ));
}

// ---- crash at every write point -----------------------------------------------------------------

fn modes(len: usize) -> Vec<RecoverMode> {
    let mut out = vec![RecoverMode::DropVolatile, RecoverMode::KeepVolatile];
    for n in [0, 1, 4, 5, 9, len / 2, len - 33, len - 1, len, len + 100] {
        out.push(RecoverMode::TornVolatile(n));
    }
    out
}

/// One commit, crashed at each of its ops in turn and recovered under every mode: the store holds
/// the old record or the new one, the new one once its directory sync ran, and the next commit
/// works and uses a fresh seq.
fn crash_every_op(
    expect_durable: u64,
    setup: &dyn Fn() -> MemFs,
    change: &dyn Fn(Option<&InstallState>, u64) -> InstallState,
) {
    // Learn the op counts: the whole commit, and the commit up to and including the sync of the
    // record's directory (the first `sync_dir(dir)`; earlier ones sync new parent directories).
    let fs = setup();
    let loaded = load_state(&fs).unwrap();
    let old = loaded.record.clone();
    let new = change(old.as_ref(), loaded.next_seq);
    let base = fs.op_count();
    let probe = Capped::new(&fs);
    commit(&probe, &dir(), &loaded, &new, &H).unwrap();
    let total = fs.op_count() - base;
    let durable = probe
        .dir_synced_at
        .lock()
        .unwrap()
        .expect("the commit synced its dir")
        - base;
    let len = bytes_of(&fs, new.seq).len();
    // Pinned, so a commit that dropped its own directory sync (and leaned on prune's) fails here.
    assert_eq!(
        durable, expect_durable,
        "ops through the directory sync (total {total})"
    );

    for n in 0..=total {
        let fs = setup();
        let loaded = load_state(&fs).unwrap();
        fs.crash_after(fs.op_count() + n);
        let _ = commit(&fs, &dir(), &loaded, &new, &H);
        for mode in modes(len) {
            let disk = fs.recover(mode);
            let got = load_state(&disk).unwrap_or_else(|e| panic!("op {n} {mode:?}: {e}"));
            let record = got.record.clone();
            if n >= durable {
                assert_eq!(
                    record.as_ref(),
                    Some(&new),
                    "op {n} {mode:?}: new record lost"
                );
            } else {
                assert!(
                    record == old || record.as_ref() == Some(&new),
                    "op {n} {mode:?}: neither old nor new: {record:?}"
                );
            }
            let present = matches!(disk.symlink_metadata(&path_of(new.seq)), Ok(Some(_)));
            if present {
                assert!(got.next_seq > new.seq, "op {n} {mode:?}: seq reused");
            }
            let after = change(record.as_ref(), got.next_seq);
            commit(&disk, &dir(), &got, &after, &H)
                .unwrap_or_else(|e| panic!("op {n} {mode:?}: next commit: {e}"));
            assert_eq!(
                load_state(&disk).unwrap().record,
                Some(after),
                "op {n} {mode:?}"
            );
        }
    }
}

fn next_of(old: Option<&InstallState>, seq: u64) -> InstallState {
    match old {
        Some(r) => r.raise_floors(&floors(seq, seq)).with_seq(seq),
        None => InstallState::new(seq, app(), Scope::User, INSTALL_ID, Target::LinuxX86_64),
    }
}

#[test]
fn a_crash_at_any_op_of_a_commit_leaves_the_old_or_the_new_record() {
    // Four records, so the commit also prunes.
    let setup = || {
        let (fs, _) = store_with(&[
            &|r| r.raise_floors(&floors(1, 1)),
            &|r| r.mark_bad(v("0.1.0")),
            &|r| r.raise_floors(&floors(2, 2)),
        ]);
        put_file(&fs, &dir().join("notes.txt"), b"kept");
        fs
    };
    // create_new, write, sync, sync_dir.
    crash_every_op(4, &setup, &next_of);
}

#[test]
fn a_crash_at_any_op_of_the_first_commit_leaves_nothing_or_the_record() {
    // create_dir_all, sync_dir of `/` and of `/home`, then the four above.
    crash_every_op(7, &MemFs::new, &next_of);
}

// ---- FORMAT.md 12 golden example ----------------------------------------------------------------

const GOLDEN_MARK: &str =
    "<!-- golden: install-state, generated by crates/lunepack-core/tests/state.rs -->";

#[test]
fn the_format_md_example_is_what_commit_writes() {
    let fs = MemFs::new();
    commit(&fs, &dir(), &load_state(&fs).unwrap(), &sample(1), &H).unwrap();
    let file = bytes_of(&fs, 1);
    let generated = serde_json::to_string_pretty(&Value::Object(payload(&file))).unwrap();

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/FORMAT.md");
    let text = std::fs::read_to_string(&path).unwrap();
    let after = text
        .split_once(GOLDEN_MARK)
        .unwrap_or_else(|| panic!("docs/FORMAT.md has no line {GOLDEN_MARK}"))
        .1;
    let body = after
        .trim_start()
        .strip_prefix("```json\n")
        .expect("a ```json block right after the golden mark");
    let (block, _) = body
        .split_once("\n```")
        .expect("an end to the golden block");
    assert_eq!(
        block, generated,
        "docs/FORMAT.md 12's example differs from what commit writes; replace it with:\n{generated}"
    );
    // The documented frame header matches the file.
    assert_eq!(&file[..5], b"LPST\x01");
    assert_eq!(
        u32::from_be_bytes([file[5], file[6], file[7], file[8]]) as usize,
        file.len() - 9 - 32
    );
}

#[test]
fn the_golden_check_rejects_a_changed_example() {
    // The instrument: a changed record must not match the generated text of the original.
    let fs = MemFs::new();
    commit(&fs, &dir(), &load_state(&fs).unwrap(), &sample(1), &H).unwrap();
    let a = serde_json::to_string_pretty(&Value::Object(payload(&bytes_of(&fs, 1)))).unwrap();
    let loaded = load_state(&fs).unwrap();
    let next = loaded.record.as_ref().unwrap().mark_bad(v("3.0.0"));
    commit(&fs, &dir(), &loaded, &next, &H).unwrap();
    let b = serde_json::to_string_pretty(&Value::Object(payload(&bytes_of(&fs, 2)))).unwrap();
    assert_ne!(a, b);
}

#[test]
fn state_module_reads_no_clock() {
    let source = include_str!("../src/state.rs");
    for needle in ["Clock", "SystemTime", "Instant", "now_unix_secs"] {
        assert!(!source.contains(needle), "state.rs mentions {needle}");
    }
    let _ = state::HEALTH_KEY;
}

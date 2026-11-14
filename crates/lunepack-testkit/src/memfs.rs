//! An in-memory [`Fs`] with a durability model and crash injection (M4 step 3), for testing code
//! whose point is to survive a crash at any write point (the install-state store, the stage
//! engine).
//!
//! Durability model:
//!
//! - a file's written bytes are volatile until [`FileWrite::sync`] (a `truncate` is volatile too);
//! - a directory entry created, removed or renamed is volatile until [`Fs::sync_dir`] on its
//!   parent directory (a rename between two directories needs both synced);
//! - symlinks are entries like any other.
//!
//! Crashes: every mutating call is a numbered op (`create_new`, each `write`, `sync`, `truncate`,
//! `rename`, `remove_file`, `remove_dir_all_nofollow`, `create_dir_all`, `sync_dir`, `copy_file`,
//! `set_exec`, `symlink`; `open_append` and the reads are not). [`MemFs::crash_after`]`(n)` makes op
//! number `n` (zero-based) and everything after it, reads and locks included, fail with
//! [`FsErrorKind::Crashed`]; op `n` has no effect. [`MemFs::op_count`] says how many ops ran, so a
//! test runs an operation once to learn its op count `k` and then once per crash point `0..k`.
//! [`MemFs::recover`] builds the disk a restart would find, as a new [`MemFs`], under a
//! [`RecoverMode`]. The bytes of an op that was cut short are modelled by the mode, not by the op.
//!
//! Locks: [`Fs::try_lock`] is a table keyed by path (it creates no file). Handles from
//! [`MemFs::process`] stand for other processes on the same disk; [`MemFs::kill_process`] releases
//! every lock one of them holds, as the OS does when a process dies.
//!
//! Every path is resolved from one root: prefix and root components are ignored, `..` is applied
//! lexically, so `/a/b` and `C:\a\b` name the same entry.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lunepack_core::{
    DirEntryInfo, FileKind, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta, ReadAt,
};

const ROOT: u64 = 0;
/// Most symlinks followed in one resolution.
const MAX_LINKS: u32 = 40;

/// What the disk holds after a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverMode {
    /// Everything volatile is lost: files hold their last synced bytes, directory entries their
    /// last synced state.
    DropVolatile,
    /// Everything volatile reached the disk: the image equals the live state.
    KeepVolatile,
    /// Directory entries reached the disk, and of the volatile bytes a file gained since its last
    /// sync only the first `n` survive (a file written, appended to, and not synced). A file whose
    /// content was cut or rewritten since its last sync keeps its last synced bytes.
    TornVolatile(usize),
}

enum Node {
    File {
        live: Vec<u8>,
        durable: Vec<u8>,
        exec: bool,
    },
    Dir {
        live: BTreeMap<OsString, u64>,
        durable: BTreeMap<OsString, u64>,
    },
    Symlink(String),
}

impl Node {
    /// The node as a recovered disk holds it (a directory starts empty, its entries are copied
    /// when it is visited).
    fn image(&self, mode: RecoverMode) -> Node {
        match self {
            Node::File {
                live,
                durable,
                exec,
            } => {
                let bytes = match mode {
                    RecoverMode::DropVolatile => durable.clone(),
                    RecoverMode::KeepVolatile => live.clone(),
                    RecoverMode::TornVolatile(n) if live.starts_with(durable) => {
                        live[..live.len().min(durable.len().saturating_add(n))].to_vec()
                    }
                    RecoverMode::TornVolatile(_) => durable.clone(),
                };
                Node::File {
                    live: bytes.clone(),
                    durable: bytes,
                    exec: *exec,
                }
            }
            Node::Symlink(target) => Node::Symlink(target.clone()),
            Node::Dir { .. } => Node::Dir {
                live: BTreeMap::new(),
                durable: BTreeMap::new(),
            },
        }
    }

    fn kind(&self) -> FileKind {
        match self {
            Node::File { .. } => FileKind::File,
            Node::Dir { .. } => FileKind::Dir,
            Node::Symlink(_) => FileKind::Symlink,
        }
    }
}

struct State {
    nodes: HashMap<u64, Node>,
    next_id: u64,
    ops: u64,
    crash_at: Option<u64>,
    crashed: bool,
    /// Lock table: path -> (process id, lock id).
    locks: BTreeMap<Vec<OsString>, (u64, u64)>,
    next_lock: u64,
    next_process: u64,
}

impl State {
    fn new() -> State {
        let mut nodes = HashMap::new();
        nodes.insert(
            ROOT,
            Node::Dir {
                live: BTreeMap::new(),
                durable: BTreeMap::new(),
            },
        );
        State {
            nodes,
            next_id: 1,
            ops: 0,
            crash_at: None,
            crashed: false,
            locks: BTreeMap::new(),
            next_lock: 1,
            next_process: 1,
        }
    }

    fn crashed_err(path: &Path) -> FsError {
        FsError::new(FsErrorKind::Crashed, path, None)
    }

    fn alive(&self, path: &Path) -> Result<(), FsError> {
        if self.crashed {
            Err(Self::crashed_err(path))
        } else {
            Ok(())
        }
    }

    /// Starts a mutating op: crashes instead when it is the op the test chose.
    fn begin_op(&mut self, path: &Path) -> Result<(), FsError> {
        self.alive(path)?;
        if self.crash_at == Some(self.ops) {
            self.crashed = true;
            return Err(Self::crashed_err(path));
        }
        self.ops += 1;
        Ok(())
    }

    fn add(&mut self, node: Node) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, node);
        id
    }

    fn dir_live(&self, id: u64, path: &Path) -> Result<&BTreeMap<OsString, u64>, FsError> {
        match self.nodes.get(&id) {
            Some(Node::Dir { live, .. }) => Ok(live),
            _ => Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
        }
    }

    fn dir_live_mut(
        &mut self,
        id: u64,
        path: &Path,
    ) -> Result<&mut BTreeMap<OsString, u64>, FsError> {
        match self.nodes.get_mut(&id) {
            Some(Node::Dir { live, .. }) => Ok(live),
            _ => Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
        }
    }

    /// Resolves `path`. With `follow_final` a final symlink is followed; intermediate symlinks
    /// always are. The result names the entry's directory and name (`None` for the root) and the
    /// node when it exists.
    fn walk(&self, path: &Path, follow_final: bool) -> Result<Walk, FsError> {
        let mut pending: VecDeque<Comp> = comps_of_path(path);
        let mut stack: Vec<u64> = vec![ROOT];
        let mut links = 0u32;
        let mut entry: Option<(u64, OsString)> = None;
        let mut node = Some(ROOT);
        while let Some(comp) = pending.pop_front() {
            let name = match comp {
                Comp::Parent => {
                    if stack.len() > 1 {
                        stack.pop();
                    }
                    entry = None;
                    node = stack.last().copied();
                    continue;
                }
                Comp::Name(name) => name,
            };
            let dir = *stack.last().unwrap_or(&ROOT);
            let is_last = pending.is_empty();
            let live = self.dir_live(dir, path)?;
            let Some(&id) = live.get(&name) else {
                if is_last {
                    return Ok(Walk {
                        entry: Some((dir, name)),
                        node: None,
                    });
                }
                return Err(FsError::new(FsErrorKind::NotFound, path, None));
            };
            match self.nodes.get(&id) {
                Some(Node::Symlink(target)) if !is_last || follow_final => {
                    links += 1;
                    if links > MAX_LINKS {
                        return Err(FsError::new(
                            FsErrorKind::Other,
                            path,
                            Some(io::Error::other("too many levels of symbolic links")),
                        ));
                    }
                    if target.starts_with(['/', '\\']) {
                        stack.truncate(1);
                    }
                    let mut next = comps_of_text(target);
                    next.append(&mut pending);
                    pending = next;
                    if pending.is_empty() {
                        // A link to "/" or "..": the walk ends on a directory.
                        entry = None;
                        node = stack.last().copied();
                    }
                }
                _ => {
                    if is_last {
                        return Ok(Walk {
                            entry: Some((dir, name)),
                            node: Some(id),
                        });
                    }
                    stack.push(id);
                    entry = Some((dir, name));
                    node = Some(id);
                }
            }
        }
        Ok(Walk { entry, node })
    }

    /// The existing node at `path` (final symlink followed), or `NotFound`.
    fn existing(&self, path: &Path) -> Result<u64, FsError> {
        self.walk(path, true)?
            .node
            .ok_or_else(|| FsError::new(FsErrorKind::NotFound, path, None))
    }

    /// The directory and name for a new entry at `path`; `AlreadyExists` when anything is there.
    fn new_entry(&self, path: &Path) -> Result<(u64, OsString), FsError> {
        let walk = self.walk(path, false)?;
        match (walk.entry, walk.node) {
            (Some(entry), None) => Ok(entry),
            _ => Err(FsError::new(FsErrorKind::AlreadyExists, path, None)),
        }
    }

    /// Reachable nodes of the image, copied under `mode`, as a fresh state.
    fn image(&self, mode: RecoverMode) -> State {
        let mut out = State::new();
        out.next_process = self.next_process;
        let mut map: HashMap<u64, u64> = HashMap::new();
        map.insert(ROOT, ROOT);
        let mut queue = vec![ROOT];
        while let Some(old) = queue.pop() {
            let new = map[&old];
            let Some(Node::Dir { live, durable }) = self.nodes.get(&old) else {
                continue;
            };
            let entries = match mode {
                RecoverMode::DropVolatile => durable,
                _ => live,
            };
            let mut copied = BTreeMap::new();
            for (name, &child) in entries {
                let Some(node) = self.nodes.get(&child) else {
                    continue;
                };
                let id = match map.entry(child) {
                    Entry::Occupied(known) => *known.get(),
                    Entry::Vacant(slot) => {
                        let id = out.next_id;
                        out.next_id += 1;
                        slot.insert(id);
                        if matches!(node, Node::Dir { .. }) {
                            queue.push(child);
                        }
                        out.nodes.insert(id, node.image(mode));
                        id
                    }
                };
                copied.insert(name.clone(), id);
            }
            out.nodes.insert(
                new,
                Node::Dir {
                    live: copied.clone(),
                    durable: copied,
                },
            );
        }
        out
    }
}

struct Walk {
    /// The directory holding the entry and the entry's name; `None` for the root.
    entry: Option<(u64, OsString)>,
    node: Option<u64>,
}

enum Comp {
    Name(OsString),
    Parent,
}

fn comps_of_path(path: &Path) -> VecDeque<Comp> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(Comp::Name(n.to_owned())),
            Component::ParentDir => Some(Comp::Parent),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn comps_of_text(text: &str) -> VecDeque<Comp> {
    text.split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|p| {
            if p == ".." {
                Comp::Parent
            } else {
                Comp::Name(OsString::from(p))
            }
        })
        .collect()
}

fn key_of(path: &Path) -> Vec<OsString> {
    comps_of_path(path)
        .into_iter()
        .filter_map(|c| match c {
            Comp::Name(n) => Some(n),
            Comp::Parent => None,
        })
        .collect()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The in-memory filesystem. Clones are the same process on the same disk; [`MemFs::process`]
/// gives another process.
#[derive(Clone)]
pub struct MemFs {
    state: Arc<Mutex<State>>,
    process: u64,
}

impl Default for MemFs {
    fn default() -> Self {
        MemFs::new()
    }
}

impl MemFs {
    /// An empty disk (just the root directory) and its first process.
    pub fn new() -> MemFs {
        MemFs {
            state: Arc::new(Mutex::new(State::new())),
            process: 0,
        }
    }

    /// A handle for another process on the same disk (its locks are its own).
    pub fn process(&self) -> MemFs {
        let mut state = lock(&self.state);
        let process = state.next_process;
        state.next_process += 1;
        MemFs {
            state: self.state.clone(),
            process,
        }
    }

    /// Releases every lock held through `handle` (the process died). Guards it handed out stay
    /// valid objects but no longer hold anything.
    pub fn kill_process(&self, handle: &MemFs) {
        let mut state = lock(&self.state);
        state
            .locks
            .retain(|_, (process, _)| *process != handle.process);
    }

    /// Makes op number `n` (zero-based, counting from the start of this disk) and every later call
    /// fail with `Crashed`. Call it before the work under test.
    pub fn crash_after(&self, n: u64) {
        lock(&self.state).crash_at = Some(n);
    }

    /// Crashes now: every later call fails.
    pub fn crash_now(&self) {
        lock(&self.state).crashed = true;
    }

    /// Whether a crash has happened.
    pub fn is_crashed(&self) -> bool {
        lock(&self.state).crashed
    }

    /// The mutating ops that ran so far (the crashed one is not counted).
    pub fn op_count(&self) -> u64 {
        lock(&self.state).ops
    }

    /// The disk a restart finds, as a new, healthy [`MemFs`]: no locks held, op count 0.
    pub fn recover(&self, mode: RecoverMode) -> MemFs {
        let image = lock(&self.state).image(mode);
        MemFs {
            state: Arc::new(Mutex::new(image)),
            process: 0,
        }
    }
}

fn io_crashed(path: &Path) -> io::Error {
    io::Error::other(State::crashed_err(path))
}

impl Fs for MemFs {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        let st = lock(&self.state);
        st.alive(path)?;
        let id = st.existing(path)?;
        match st.nodes.get(&id) {
            Some(Node::File { live, .. }) => {
                if live.len() as u64 > max {
                    Err(FsError::new(FsErrorKind::TooLarge, path, None))
                } else {
                    Ok(live.clone())
                }
            }
            _ => Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("not a regular file")),
            )),
        }
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        let st = lock(&self.state);
        st.alive(path)?;
        let id = st.existing(path)?;
        match st.nodes.get(&id) {
            Some(Node::File { .. }) => Ok(Box::new(MemReader {
                state: self.state.clone(),
                id,
                name: path.to_owned(),
            })),
            _ => Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("not a regular file")),
            )),
        }
    }

    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let (dir, name) = st.new_entry(path)?;
        let id = st.add(Node::File {
            live: Vec::new(),
            durable: Vec::new(),
            exec: false,
        });
        st.dir_live_mut(dir, path)?.insert(name, id);
        Ok(Box::new(MemWriter {
            state: self.state.clone(),
            id,
            name: path.to_owned(),
        }))
    }

    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        let st = lock(&self.state);
        st.alive(path)?;
        let id = st.existing(path)?;
        match st.nodes.get(&id) {
            Some(Node::File { .. }) => Ok(Box::new(MemWriter {
                state: self.state.clone(),
                id,
                name: path.to_owned(),
            })),
            _ => Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("not a regular file")),
            )),
        }
    }

    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let id = st.existing(path)?;
        let len =
            usize::try_from(len).map_err(|_| FsError::new(FsErrorKind::TooLarge, path, None))?;
        match st.nodes.get_mut(&id) {
            Some(Node::File { live, .. }) => {
                live.resize(len, 0);
                Ok(())
            }
            _ => Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("not a regular file")),
            )),
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(from)?;
        let src = st.walk(from, false)?;
        let (Some((src_dir, src_name)), Some(id)) = (src.entry, src.node) else {
            return Err(FsError::new(FsErrorKind::NotFound, from, None));
        };
        let (dst_dir, dst_name) = st.new_entry(to)?;
        st.dir_live_mut(src_dir, from)?.remove(&src_name);
        st.dir_live_mut(dst_dir, to)?.insert(dst_name, id);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let walk = st.walk(path, false)?;
        let (Some((dir, name)), Some(id)) = (walk.entry, walk.node) else {
            return Err(FsError::new(FsErrorKind::NotFound, path, None));
        };
        if matches!(st.nodes.get(&id), Some(Node::Dir { .. })) {
            return Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("is a directory")),
            ));
        }
        st.dir_live_mut(dir, path)?.remove(&name);
        Ok(())
    }

    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let walk = st.walk(path, false)?;
        let (Some((dir, name)), Some(id)) = (walk.entry, walk.node) else {
            return Err(FsError::new(FsErrorKind::NotFound, path, None));
        };
        if matches!(st.nodes.get(&id), Some(Node::File { .. })) {
            return Err(FsError::new(FsErrorKind::NotADirectory, path, None));
        }
        // Unlinking the top entry drops the whole subtree (symlinks inside are just entries).
        st.dir_live_mut(dir, path)?.remove(&name);
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let mut dir = ROOT;
        for comp in comps_of_path(path) {
            let Comp::Name(name) = comp else { continue };
            let existing = st.dir_live(dir, path)?.get(&name).copied();
            dir = match existing {
                Some(id) => match st.nodes.get(&id) {
                    Some(Node::Dir { .. }) => id,
                    Some(Node::Symlink(_)) => {
                        return Err(FsError::new(FsErrorKind::IsSymlink, path, None));
                    }
                    _ => return Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
                },
                None => {
                    let id = st.add(Node::Dir {
                        live: BTreeMap::new(),
                        durable: BTreeMap::new(),
                    });
                    st.dir_live_mut(dir, path)?.insert(name, id);
                    id
                }
            };
        }
        Ok(())
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        let st = lock(&self.state);
        st.alive(path)?;
        let id = st.existing(path)?;
        let live = st.dir_live(id, path)?;
        Ok(live
            .iter()
            .map(|(name, child)| DirEntryInfo {
                name: name.clone(),
                kind: st.nodes.get(child).map_or(FileKind::Other, Node::kind),
            })
            .collect())
    }

    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        let st = lock(&self.state);
        st.alive(path)?;
        let walk = st.walk(path, false)?;
        Ok(walk.node.and_then(|id| st.nodes.get(&id)).map(|n| Meta {
            kind: n.kind(),
            len: match n {
                Node::File { live, .. } => live.len() as u64,
                Node::Symlink(t) => t.len() as u64,
                Node::Dir { .. } => 0,
            },
        }))
    }

    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let id = st.existing(path)?;
        match st.nodes.get_mut(&id) {
            Some(Node::Dir { live, durable }) => {
                *durable = live.clone();
                Ok(())
            }
            _ => Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
        }
    }

    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(from)?;
        let src = st.existing(from)?;
        let (bytes, exec) = match st.nodes.get(&src) {
            Some(Node::File { live, exec, .. }) => (live.clone(), *exec),
            _ => {
                return Err(FsError::new(
                    FsErrorKind::Other,
                    from,
                    Some(io::Error::other("not a regular file")),
                ));
            }
        };
        let (dir, name) = st.new_entry(to_new)?;
        let id = st.add(Node::File {
            live: bytes,
            durable: Vec::new(),
            exec,
        });
        st.dir_live_mut(dir, to_new)?.insert(name, id);
        Ok(())
    }

    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(path)?;
        let id = st.existing(path)?;
        match st.nodes.get_mut(&id) {
            Some(Node::File { exec: bit, .. }) => {
                *bit = exec;
                Ok(())
            }
            _ => Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("not a regular file")),
            )),
        }
    }

    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(link_path)?;
        let (dir, name) = st.new_entry(link_path)?;
        let id = st.add(Node::Symlink(target.to_owned()));
        st.dir_live_mut(dir, link_path)?.insert(name, id);
        Ok(())
    }

    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        let mut st = lock(&self.state);
        st.alive(path)?;
        // The directory must exist, as it must for a real lock file.
        let walk = st.walk(path, true)?;
        if let Some((dir, _)) = &walk.entry {
            st.dir_live(*dir, path)?;
        }
        if let Some(id) = walk.node
            && !matches!(st.nodes.get(&id), Some(Node::File { .. }))
        {
            return Err(FsError::new(
                FsErrorKind::Other,
                path,
                Some(io::Error::other("not a regular file")),
            ));
        }
        let key = key_of(path);
        if st.locks.contains_key(&key) {
            return Ok(None);
        }
        let lock_id = st.next_lock;
        st.next_lock += 1;
        st.locks.insert(key.clone(), (self.process, lock_id));
        Ok(Some(Box::new(MemLock {
            state: self.state.clone(),
            key,
            lock_id,
        })))
    }
}

struct MemReader {
    state: Arc<Mutex<State>>,
    id: u64,
    name: std::path::PathBuf,
}

impl ReadAt for MemReader {
    fn size(&self) -> Result<u64, FsError> {
        let st = lock(&self.state);
        st.alive(&self.name)?;
        match st.nodes.get(&self.id) {
            Some(Node::File { live, .. }) => Ok(live.len() as u64),
            _ => Err(FsError::new(FsErrorKind::NotFound, &self.name, None)),
        }
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        let st = lock(&self.state);
        st.alive(&self.name)?;
        let Some(Node::File { live, .. }) = st.nodes.get(&self.id) else {
            return Err(FsError::new(FsErrorKind::NotFound, &self.name, None));
        };
        let eof = || {
            FsError::new(
                FsErrorKind::Other,
                &self.name,
                Some(io::Error::from(io::ErrorKind::UnexpectedEof)),
            )
        };
        let start = usize::try_from(offset).map_err(|_| eof())?;
        let end = start.checked_add(buf.len()).ok_or_else(eof)?;
        if end > live.len() {
            return Err(eof());
        }
        buf.copy_from_slice(&live[start..end]);
        Ok(())
    }
}

struct MemWriter {
    state: Arc<Mutex<State>>,
    id: u64,
    name: std::path::PathBuf,
}

impl Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut st = lock(&self.state);
        st.begin_op(&self.name)
            .map_err(|_| io_crashed(&self.name))?;
        match st.nodes.get_mut(&self.id) {
            Some(Node::File { live, .. }) => {
                live.extend_from_slice(buf);
                Ok(buf.len())
            }
            _ => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let st = lock(&self.state);
        st.alive(&self.name).map_err(|_| io_crashed(&self.name))
    }
}

impl FileWrite for MemWriter {
    fn sync(&mut self) -> Result<(), FsError> {
        let mut st = lock(&self.state);
        st.begin_op(&self.name)?;
        match st.nodes.get_mut(&self.id) {
            Some(Node::File { live, durable, .. }) => {
                durable.clone_from(live);
                Ok(())
            }
            _ => Err(FsError::new(FsErrorKind::NotFound, &self.name, None)),
        }
    }
}

struct MemLock {
    state: Arc<Mutex<State>>,
    key: Vec<OsString>,
    lock_id: u64,
}

impl LockGuard for MemLock {}

impl Drop for MemLock {
    fn drop(&mut self) {
        let mut st = lock(&self.state);
        if st
            .locks
            .get(&self.key)
            .is_some_and(|(_, id)| *id == self.lock_id)
        {
            st.locks.remove(&self.key);
        }
    }
}

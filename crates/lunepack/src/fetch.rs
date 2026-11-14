//! The fetch engine (M4-D8, M4-D9, M4-D17): signed documents, Range runs and full-pack downloads
//! with resume, over any [`Transport`].
//!
//! The network loop runs on the polling task (M4-D2): the engine awaits the transport's futures and
//! body chunks itself, so a transport bound to the app's runtime runs in its context. Every byte that
//! reaches the cache goes through a cache-writer job (a worker thread fed by a bounded pipe), and
//! every job holds the operation's [`OpLock`] clone, so the lock outlives a dropped future for as
//! long as a writer still appends (M4-D15).
//!
//! Every response passes the core's response rules ([`ResponseInfo::from_head`], [`classify`],
//! [`check_document`]) before a body byte is read, and every body is cut at the byte count its
//! request calls for: a hostile server can make a fetch fail or fall back to the full pack, never
//! make it write more than the signed sizes.

use std::collections::{HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use lunepack_core::fetch::{FetchPlan, FetchPolicy, Outcome, Run, check_document, classify};
use lunepack_core::{
    ByteRange, CancelToken, Channel, CheckedRef, Fs, Hasher, Request, Response, ResponseInfo,
    Sha256Digest, Transport, plan_fetch,
};
use url::Url;

use crate::Error;
use crate::cache::{Cache, CacheKind, PackWriter, PartTools, RunTarget, RunWriter, WriteReport};
use crate::pipe::{self, AsyncSender, Closed};
use crate::progress::ProgressSink;
use crate::task::{OpLock, spawn_job};

/// The statuses that make `root-<k>.json` "absent", ending the root walk (M4-D10, decided by the
/// user: 404, 410 and 403). Every other status, and every transport error, fails the check.
pub const ABSENT_ROOT_STATUSES: [u16; 3] = [404, 410, 403];

// ---- URLs ----------------------------------------------------------------------------------------

/// Where the signed documents and artifacts of one feed live: the feed URL's directory.
#[derive(Clone, PartialEq, Eq)]
pub struct FeedUrls {
    base: Url,
}

impl std::fmt::Debug for FeedUrls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URL may carry userinfo; only the scheme is shown.
        f.debug_struct("FeedUrls")
            .field("scheme", &self.base.scheme())
            .finish_non_exhaustive()
    }
}

impl FeedUrls {
    /// The base for `feed_url`: an `https:`, `http:` or `file:` URL with its last path segment,
    /// query and fragment removed.
    pub fn new(feed_url: &str) -> Result<FeedUrls, Error> {
        let mut base =
            Url::parse(feed_url).map_err(|_| Error::Config("feed URL is not a valid URL"))?;
        if !matches!(base.scheme(), "https" | "http" | "file") {
            return Err(Error::Config("feed URL scheme must be https, http or file"));
        }
        if base.cannot_be_a_base() {
            return Err(Error::Config("feed URL has no path"));
        }
        base.set_query(None);
        base.set_fragment(None);
        {
            let mut segments = base
                .path_segments_mut()
                .map_err(|()| Error::Config("feed URL has no path"))?;
            segments.pop();
            segments.push("");
        }
        Ok(FeedUrls { base })
    }

    /// `rel` resolved under the base. A result that leaves the base (another scheme, host, port
    /// or user, a path outside the base path, or a query or fragment) is refused (defence in
    /// depth: a [`CheckedRef`] path can express none of these).
    pub fn join(&self, rel: &str) -> Result<String, Error> {
        let leaves = || Error::Verify(lunepack_core::Error::Field("URL leaves the feed directory"));
        if rel.is_empty() || rel.starts_with('/') || rel.contains(['?', '#', '\\', ':', '%']) {
            return Err(leaves());
        }
        let url = self.base.join(rel).map_err(|_| leaves())?;
        let same_origin = url.scheme() == self.base.scheme()
            && url.host() == self.base.host()
            && url.port_or_known_default() == self.base.port_or_known_default()
            && url.username() == self.base.username()
            && url.password() == self.base.password();
        if !same_origin
            || !url.path().starts_with(self.base.path())
            || url.path().len() == self.base.path().len()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(leaves());
        }
        Ok(url.into())
    }

    /// `root-<version>.json`.
    pub fn root(&self, version: u64) -> Result<String, Error> {
        self.join(&format!("root-{version}.json"))
    }

    /// `keys.json`.
    pub fn keys(&self) -> Result<String, Error> {
        self.join("keys.json")
    }

    /// `feed-<channel>.json`.
    pub fn feed(&self, channel: &Channel) -> Result<String, Error> {
        self.join(&format!("feed-{}.json", channel.as_str()))
    }

    /// A signed artifact reference (manifest, pack).
    pub fn reference(&self, reference: &CheckedRef) -> Result<String, Error> {
        self.join(reference.path())
    }
}

// ---- documents -----------------------------------------------------------------------------------

fn plain_get(url: &str) -> Request {
    Request {
        url: url.to_owned(),
        range: None,
        if_range: None,
    }
}

/// Reads a document body, refusing more than `cap` bytes (no chunk is pulled after the cap is
/// passed).
async fn read_document(mut response: Response, cap: u64) -> Result<Vec<u8>, Error> {
    let info = ResponseInfo::from_head(&response.head)?;
    check_document(&info, cap)?;
    let mut out = Vec::new();
    while let Some(chunk) = response.body.next_chunk().await? {
        let size = (out.len() as u64).saturating_add(chunk.len() as u64);
        if size > cap {
            return Err(Error::Verify(lunepack_core::Error::TooLarge {
                what: "document",
                size,
                cap,
            }));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Fetches a signed document: status `200`, a `Content-Length` (when present) at most `cap`, and
/// at most `cap` body bytes (`TooLarge` past it). Caps: root and keys 64 KiB, feed 8 MiB
/// (`Limits::V1`); a manifest goes through [`fetch_artifact_doc`].
pub async fn fetch_document(
    transport: &dyn Transport,
    url: &str,
    cap: u64,
) -> Result<Vec<u8>, Error> {
    let response = transport.get(plain_get(url)).await?;
    read_document(response, cap).await
}

/// Fetches `root-<k>.json`: `Ok(None)` when the answer is one of [`ABSENT_ROOT_STATUSES`], else as
/// [`fetch_document`].
pub async fn fetch_root_doc(
    transport: &dyn Transport,
    url: &str,
    cap: u64,
) -> Result<Option<Vec<u8>>, Error> {
    let response = transport.get(plain_get(url)).await?;
    if ABSENT_ROOT_STATUSES.contains(&response.head.status) {
        return Ok(None);
    }
    read_document(response, cap).await.map(Some)
}

/// Fetches an artifact named by a signed reference (a manifest), capped at its signed size, then
/// checked against it ([`CheckedRef::check_bytes`]: exact length, then SHA-256).
pub async fn fetch_artifact_doc(
    transport: &dyn Transport,
    url: &str,
    reference: &CheckedRef,
    hasher: &dyn Hasher,
) -> Result<Vec<u8>, Error> {
    let bytes = fetch_document(transport, url, reference.size()).await?;
    reference.check_bytes(&bytes, hasher)?;
    Ok(bytes)
}

// ---- downloads -----------------------------------------------------------------------------------

/// What one download operation runs with. Cheap to clone.
#[derive(Clone)]
pub struct FetchCtx {
    /// The transport, polled on the caller's task.
    pub transport: Arc<dyn Transport>,
    /// The cache.
    pub cache: Cache,
    /// SHA-256.
    pub hasher: Arc<dyn Hasher>,
    /// The operation's lock; every job gets a clone.
    pub lock: Option<OpLock>,
    /// The operation's cancel token.
    pub cancel: CancelToken,
    /// Where downloaded bytes are reported (`add_done` per chunk written).
    pub progress: Option<ProgressSink>,
    /// The fetch strategy (M4-D8).
    pub policy: FetchPolicy,
}

impl FetchCtx {
    /// Adds `total` bytes to the download's total and `done` of them to its done count: the part of
    /// the work that is on disk already, or about to be requested (`done` = 0).
    fn progress_have(&self, total: u64, done: u64) {
        if let Some(p) = &self.progress {
            p.add_total(total);
            if done > 0 {
                p.add_done(done);
            }
        }
    }
}

impl std::fmt::Debug for FetchCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchCtx")
            .field("holds_lock", &self.lock.is_some())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// The pack of a release: its URL and signed size and hash.
#[derive(Clone, PartialEq, Eq)]
pub struct PackTarget {
    /// The resolved URL.
    pub url: String,
    /// The signed size.
    pub size: u64,
    /// The signed SHA-256.
    pub sha256: Sha256Digest,
}

impl std::fmt::Debug for PackTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackTarget")
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

/// A frame the stage needs from the pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameNeed {
    /// Offset in the pack.
    pub offset: u64,
    /// Signed length, at least 1.
    pub length: u64,
    /// Signed SHA-256.
    pub sha256: Sha256Digest,
}

/// What a range run ended with.
#[derive(Debug)]
pub enum FetchOutcome {
    /// The run's body was written; frames whose bytes did not hash to their signed SHA-256 are in
    /// `bad` (deleted, not cached).
    Done {
        /// Frames whose bytes failed their hash.
        bad: Vec<Sha256Digest>,
    },
    /// The server answered `200` (it ignored the range, or `If-Range` no longer matched): the open
    /// body is the whole pack, which the caller continues as the full-pack download from byte 0
    /// ([`fetch_pack`] with `reuse`), with no second request.
    RangeIgnored(Response),
}

/// The result of [`download`]: where each needed frame, or the pack, now is in the cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fetched {
    pack: Option<PathBuf>,
    frames: HashMap<Sha256Digest, PathBuf>,
    bad: Vec<Sha256Digest>,
}

impl Fetched {
    /// The complete pack file, when the pack was fetched (or already cached).
    pub fn pack(&self) -> Option<&Path> {
        self.pack.as_deref()
    }

    /// The complete cache file of a frame, when it is there.
    pub fn frame(&self, sha256: &Sha256Digest) -> Option<&Path> {
        self.frames.get(sha256).map(PathBuf::as_path)
    }

    /// Frames a range response delivered with the wrong bytes (not cached).
    pub fn bad(&self) -> &[Sha256Digest] {
        &self.bad
    }
}

/// Resolves to `Err(Cancelled)` as soon as `cancel` is cancelled, else to `future`'s output.
pub(crate) async fn cancellable<F: Future>(
    cancel: &CancelToken,
    future: F,
) -> Result<F::Output, Error> {
    let mut future = pin!(future);
    poll_fn(|cx| {
        if cancel.is_cancelled() {
            return Poll::Ready(Err(Error::Cancelled));
        }
        cancel.register_waker(cx.waker());
        future.as_mut().poll(cx).map(Ok)
    })
    .await
}

/// Runs `f` on a job that holds the operation's lock, cancellable through the operation's token.
async fn job<T, F>(ctx: &FetchCtx, name: &'static str, f: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Error> + Send + 'static,
{
    let future = spawn_job(name, CancelToken::new(), ctx.lock.clone(), move |_| f());
    cancellable(&ctx.cancel, future).await??
}

/// [`job`] for work that checks its token: it is cancelled when the operation's token fires or the
/// future is dropped, so a long read stops at its next check instead of running to the end while
/// it holds the lock.
async fn job_with_cancel<T, F>(ctx: &FetchCtx, name: &'static str, f: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(&CancelToken) -> Result<T, Error> + Send + 'static,
{
    let future = spawn_job(name, CancelToken::new(), ctx.lock.clone(), move |token| {
        f(token)
    });
    cancellable(&ctx.cancel, future).await??
}

/// Takes the exclusive lock on `path` on a short job: [`Error::Busy`] when another holder has it.
pub async fn acquire_op_lock(fs: Arc<dyn Fs>, path: PathBuf) -> Result<OpLock, Error> {
    spawn_job("lock", CancelToken::new(), None, move |_| {
        match fs.try_lock(&path)? {
            Some(guard) => Ok(OpLock::new(guard)),
            None => Err(Error::Busy),
        }
    })
    .await?
}

/// Downloads what `needed` (frames of `pack`) lacks in the cache: by Range runs, or as the full
/// pack per the policy (M4-D8). Frames already complete are not fetched; a complete cached pack
/// satisfies everything. Shared frames (equal SHA-256) are fetched once.
///
/// An early end of a body is [`Error::Incomplete`]: parts are kept and synced, and the next call
/// resumes them.
pub async fn download(
    ctx: &FetchCtx,
    pack: &PackTarget,
    needed: &[FrameNeed],
) -> Result<Fetched, Error> {
    let mut frames: Vec<FrameNeed> = needed.to_vec();
    frames.sort_by_key(|f| (f.offset, f.length));
    let mut seen = HashSet::new();
    frames.retain(|f| seen.insert(f.sha256));

    let cache = ctx.cache.clone();
    let (pack_ready, complete) = {
        let frames = frames.clone();
        let pack = pack.clone();
        let hasher = Arc::clone(&ctx.hasher);
        job_with_cancel(ctx, "cache-state", move |cancel| {
            cache.ensure_dirs()?;
            // A cached pack is used only after its SHA-256 matches (M4-D17); a mismatch deletes it
            // and the download goes on as if it were absent.
            let pack_ready = cache.is_complete(CacheKind::Pack, &pack.sha256, pack.size)?
                && cache.verify_complete(CacheKind::Pack, &pack.sha256, &*hasher, cancel)?;
            let complete = frames
                .iter()
                .map(|f| cache.is_complete(CacheKind::Frame, &f.sha256, f.length))
                .collect::<Result<Vec<bool>, _>>()?;
            Ok((pack_ready, complete))
        })
        .await?
    };
    let mut fetched = Fetched::default();
    if pack_ready {
        // Bytes already on disk count as done up front, so total and done agree (F1).
        ctx.progress_have(pack.size, pack.size);
        fetched.pack = Some(ctx.cache.path(CacheKind::Pack, &pack.sha256));
        return Ok(fetched);
    }
    let mut missing = Vec::new();
    for (frame, done) in frames.into_iter().zip(complete) {
        if done {
            ctx.progress_have(frame.length, frame.length);
            fetched.frames.insert(
                frame.sha256,
                ctx.cache.path(CacheKind::Frame, &frame.sha256),
            );
        } else {
            missing.push(frame);
        }
    }
    if missing.is_empty() {
        return Ok(fetched);
    }
    let spans: Vec<(u64, u64)> = missing.iter().map(|f| (f.offset, f.length)).collect();
    match plan_fetch(&spans, pack.size, ctx.policy) {
        FetchPlan::FullPack => {
            fetched.pack = Some(fetch_pack(ctx, pack, None).await?);
        }
        FetchPlan::Runs(runs) => {
            // The request is the runs, gaps merged into them included.
            let run_bytes: Vec<u64> = runs.iter().map(|r| r.last - r.first + 1).collect();
            ctx.progress_have(run_bytes.iter().fold(0, |s, b| s.saturating_add(*b)), 0);
            for (k, run) in runs.into_iter().enumerate() {
                let run_frames: Vec<FrameNeed> =
                    run.frames.iter().map(|&i| missing[i].clone()).collect();
                match fetch_run(ctx, pack, &run, &run_frames).await? {
                    FetchOutcome::Done { bad } => {
                        for frame in &run_frames {
                            if !bad.contains(&frame.sha256) {
                                fetched.frames.insert(
                                    frame.sha256,
                                    ctx.cache.path(CacheKind::Frame, &frame.sha256),
                                );
                            }
                        }
                        fetched.bad.extend(bad);
                    }
                    FetchOutcome::RangeIgnored(response) => {
                        // The runs not fetched are replaced by the whole pack, which
                        // `fetch_pack` adds to the total.
                        if let Some(p) = &ctx.progress {
                            p.sub_total(run_bytes[k..].iter().fold(0, |s, b| s.saturating_add(*b)));
                        }
                        fetched.pack = Some(fetch_pack(ctx, pack, Some(response)).await?);
                        return Ok(fetched);
                    }
                }
            }
        }
    }
    Ok(fetched)
}

/// What the poll side tells a writer job.
enum WriteMsg {
    Data(Vec<u8>),
    /// The response broke its cap: drop the parts this writer owns (the pack part), or keep
    /// them synced (frame parts: every byte in them lies inside its signed frame).
    Discard,
}

/// The two writers behind one job.
enum Writer {
    Run(RunWriter),
    Pack(PackWriter),
}

impl Writer {
    fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        match self {
            Writer::Run(w) => w.write(chunk),
            Writer::Pack(w) => w.write(chunk),
        }
    }

    fn end(self) -> Result<WriteReport, Error> {
        match self {
            Writer::Run(w) => w.end(),
            Writer::Pack(w) => w.end(),
        }
    }

    fn abort(self) -> WriteReport {
        match self {
            Writer::Run(w) => w.abort(),
            Writer::Pack(w) => w.abort(),
        }
    }

    fn discard(self) -> Result<WriteReport, Error> {
        match self {
            Writer::Run(w) => Ok(w.abort()),
            Writer::Pack(w) => w.discard(),
        }
    }
}

/// Streams `response`'s body (which must hold exactly `expected` bytes) into the writer `make`
/// builds on a cache-writer job, and returns the writer's report. More than `expected` bytes is a
/// `TooLarge` error after which nothing more is written; fewer is [`Error::Incomplete`].
async fn stream_body<M>(
    ctx: &FetchCtx,
    mut response: Response,
    expected: u64,
    make: M,
) -> Result<WriteReport, Error>
where
    M: FnOnce(&CancelToken) -> Result<Writer, Error> + Send + 'static,
{
    let writer_cancel = CancelToken::new();
    let (tx, rx) = pipe::from_async::<WriteMsg>(pipe::DEFAULT_CAPACITY, writer_cancel.clone());
    let writer = spawn_job(
        "cache-writer",
        writer_cancel,
        ctx.lock.clone(),
        move |token| {
            // The token reaches the writer so hashing a resumed prefix stops when the job is cancelled.
            let mut writer = make(token)?;
            loop {
                match rx.recv() {
                    Ok(Some(WriteMsg::Data(chunk))) => {
                        if let Err(e) = writer.write(&chunk) {
                            writer.abort();
                            return Err(e);
                        }
                    }
                    Ok(Some(WriteMsg::Discard)) => return writer.discard(),
                    Ok(None) => return writer.end(),
                    Err(Closed) => return Ok(writer.abort()),
                }
            }
        },
    );
    let mut got = 0u64;
    loop {
        let next = cancellable(&ctx.cancel, response.body.next_chunk()).await?;
        let chunk = match next {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            // A dropped connection: what arrived is kept for a resume.
            Err(_) => break,
        };
        let size = got.saturating_add(chunk.len() as u64);
        if size > expected {
            let _ = send(ctx, &tx, WriteMsg::Discard).await;
            tx.finish();
            cancellable(&ctx.cancel, writer).await???;
            return Err(Error::Verify(lunepack_core::Error::TooLarge {
                what: "response body",
                size,
                cap: expected,
            }));
        }
        let len = chunk.len() as u64;
        if send(ctx, &tx, WriteMsg::Data(chunk)).await.is_err() {
            // The writer stopped: its own error says why.
            drop(tx);
            return match cancellable(&ctx.cancel, writer).await?? {
                Err(e) => Err(e),
                Ok(_) => Err(Error::Incomplete),
            };
        }
        got = size;
        if let Some(progress) = &ctx.progress {
            progress.add_done(len);
        }
    }
    tx.finish();
    let report = cancellable(&ctx.cancel, writer).await???;
    if got < expected {
        return Ok(match report {
            WriteReport::Complete { bad } => WriteReport::Incomplete { bad },
            other => other,
        });
    }
    Ok(report)
}

async fn send(ctx: &FetchCtx, tx: &AsyncSender<WriteMsg>, msg: WriteMsg) -> Result<(), Error> {
    cancellable(&ctx.cancel, tx.send(msg))
        .await?
        .map_err(|Closed| Error::Incomplete)
}

/// Fetches one range run (M4-D8): one request for the run's bytes, resumed at the first frame's
/// part length (with `If-Range` from its sidecar, M4-D9), split at frame boundaries into
/// `frames/<sha>.part`, each completed only when its length and SHA-256 match. `frames` are the
/// run's frames, sorted by offset.
pub async fn fetch_run(
    ctx: &FetchCtx,
    pack: &PackTarget,
    run: &Run,
    frames: &[FrameNeed],
) -> Result<FetchOutcome, Error> {
    let Some(first) = frames.first().cloned() else {
        return Ok(FetchOutcome::Done { bad: Vec::new() });
    };
    if first.offset != run.first {
        return Err(Error::Config("run does not start at its first frame"));
    }
    let url_sha256 = ctx.hasher.sha256(pack.url.as_bytes());
    let (have, validator) = {
        let cache = ctx.cache.clone();
        let first = first.clone();
        job(ctx, "cache-state", move || {
            cache.ensure_dirs()?;
            let have = cache.part_len(CacheKind::Frame, &first.sha256, first.length)?;
            let validator = (have > 0)
                .then(|| cache.stored_validator(CacheKind::Frame, &first.sha256, &url_sha256))
                .flatten();
            Ok((have, validator))
        })
        .await?
    };
    // Resume only inside the first frame, and only when no other frame of the run starts before
    // the resume point (overlapping frames would miss bytes).
    let resume = have > 0
        && have < first.length
        && frames[1..]
            .iter()
            .all(|f| f.offset >= first.offset.saturating_add(have));
    let have = if resume { have } else { 0 };
    let start = run.first + have;
    let range = ByteRange {
        first: start,
        last: Some(run.last),
    };
    let request = Request {
        url: pack.url.clone(),
        range: Some(range),
        if_range: if resume { validator } else { None },
    };
    let response = cancellable(&ctx.cancel, ctx.transport.get(request)).await??;
    let info = ResponseInfo::from_head(&response.head)?;
    let expected = run.last - start + 1;
    match classify(Some(range), &info, pack.size, expected)? {
        Outcome::Full => return Ok(FetchOutcome::RangeIgnored(response)),
        Outcome::Partial { .. } => {}
    }
    // The run's total includes the resumed bytes, which are on disk already.
    if let Some(p) = &ctx.progress {
        p.add_done(have);
    }
    let targets: Vec<RunTarget> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| RunTarget {
            sha: f.sha256,
            offset: f.offset,
            length: f.length,
            resume_from: if i == 0 { have } else { 0 },
        })
        .collect();
    let cache = ctx.cache.clone();
    let hasher = Arc::clone(&ctx.hasher);
    let fresh_validator = info.validator.clone();
    let report = stream_body(ctx, response, expected, move |token| {
        Ok(Writer::Run(RunWriter::new(
            cache,
            hasher,
            targets,
            start,
            fresh_validator,
            url_sha256,
            token.clone(),
        )))
    })
    .await?;
    match report {
        WriteReport::Complete { bad } => Ok(FetchOutcome::Done { bad }),
        WriteReport::Incomplete { .. } => Err(Error::Incomplete),
        WriteReport::PackHashMismatch | WriteReport::Stopped => Err(Error::Cancelled),
    }
}

/// Downloads the whole pack into `packs/<sha>.part` and completes it as `packs/<sha>`.
///
/// - `reuse`: the open `200` body of a range request ([`FetchOutcome::RangeIgnored`]); it is the
///   pack from byte 0, so the part starts empty and no new request is made.
/// - Otherwise an existing part is resumed with `Range: bytes=<len>-` (and `If-Range`); it is
///   appended to only on a matching `206`, and a `200` empties it first.
/// - At most `pack.size` bytes are ever written: one more is a `TooLarge` error and the part is
///   deleted. A complete part whose SHA-256 is not `pack.sha256` is deleted and the download
///   retried from 0 once, then `ArtifactHash`.
pub async fn fetch_pack(
    ctx: &FetchCtx,
    pack: &PackTarget,
    reuse: Option<Response>,
) -> Result<PathBuf, Error> {
    let url_sha256 = ctx.hasher.sha256(pack.url.as_bytes());
    let mut reuse = reuse;
    let mut retried = false;
    loop {
        let (response, resume_from) = match reuse.take() {
            Some(response) => {
                // Already classified as the full pack by the range request's rules.
                (Some(response), 0)
            }
            None => {
                let (have, validator) = {
                    let cache = ctx.cache.clone();
                    let pack = pack.clone();
                    job(ctx, "cache-state", move || {
                        cache.ensure_dirs()?;
                        let have = cache.part_len(CacheKind::Pack, &pack.sha256, pack.size)?;
                        let validator = (have > 0)
                            .then(|| {
                                cache.stored_validator(CacheKind::Pack, &pack.sha256, &url_sha256)
                            })
                            .flatten();
                        Ok((have, validator))
                    })
                    .await?
                };
                if have > 0 && have == pack.size {
                    // Every byte is there but the part was never completed: check it.
                    (None, have)
                } else {
                    let range = (have > 0).then_some(ByteRange {
                        first: have,
                        last: None,
                    });
                    let request = Request {
                        url: pack.url.clone(),
                        range,
                        if_range: range.and(validator),
                    };
                    let response = cancellable(&ctx.cancel, ctx.transport.get(request)).await??;
                    let info = ResponseInfo::from_head(&response.head)?;
                    match classify(range, &info, pack.size, pack.size - have)? {
                        Outcome::Partial { .. } => (Some(response), have),
                        Outcome::Full => (Some(response), 0),
                    }
                }
            }
        };
        let expected = pack.size - resume_from;
        // The whole pack is this download's work, the resumed part already done (F1).
        ctx.progress_have(pack.size, resume_from);
        let validator = match &response {
            Some(r) => ResponseInfo::from_head(&r.head)?.validator,
            None => None,
        };
        let cache = ctx.cache.clone();
        let hasher = Arc::clone(&ctx.hasher);
        let target = pack.clone();
        let make = move |token: &CancelToken| {
            let tools = PartTools {
                hasher: &*hasher,
                cancel: token,
            };
            Ok(Writer::Pack(PackWriter::new(
                cache,
                &tools,
                target.sha256,
                target.size,
                resume_from,
                validator,
                url_sha256,
            )?))
        };
        let report = match response {
            Some(response) => stream_body(ctx, response, expected, make).await?,
            None => job_with_cancel(ctx, "cache-check", move |token| make(token)?.end()).await?,
        };
        match report {
            WriteReport::Complete { .. } => {
                return Ok(ctx.cache.path(CacheKind::Pack, &pack.sha256));
            }
            WriteReport::Incomplete { .. } => return Err(Error::Incomplete),
            WriteReport::PackHashMismatch if !retried => retried = true,
            WriteReport::PackHashMismatch => {
                return Err(Error::Verify(lunepack_core::Error::ArtifactHash));
            }
            WriteReport::Stopped => return Err(Error::Cancelled),
        }
    }
}

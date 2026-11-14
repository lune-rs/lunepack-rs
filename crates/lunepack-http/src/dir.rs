//! [`DirSource`]: `file:` URLs under one directory, answered like a small HTTP server would.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, PathBuf};

use lunepack_core::{
    BlockingResponse, BlockingTransport, CancelToken, Head, Request, TransportError,
    TransportErrorKind,
};

use crate::ureq_transport::wrap;

/// Serves `file:` URLs whose path lies under one root directory, for a local mirror of a release
/// directory and for tests.
///
/// - The path must lie under the root after a lexical check (no `.` or `..` component). A symlink
///   inside the root is followed: the publisher owns the directory and every byte is hash-checked
///   by the core anyway.
/// - A missing file (or a directory) is a `404` head, not an error.
/// - `Range` is answered `206` with a correct `content-range`, by positional reads; a range that
///   starts at or after the end is `416` with `content-range: bytes */<len>`.
/// - There is no validator (`etag`, `last-modified`), so `If-Range` is ignored: the file is
///   served as it is now.
#[derive(Debug, Clone)]
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    /// A source serving under `root`. A relative root is made absolute against the current
    /// directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let root = std::path::absolute(&root).unwrap_or(root);
        DirSource { root }
    }

    /// The local path for `url`, or why it is refused.
    fn path_for(&self, url: &str) -> Result<PathBuf, TransportError> {
        let refuse = |why: &'static str| {
            TransportError::new(TransportErrorKind::Unsupported, url, Some(why.into()))
        };
        if !url
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file:"))
        {
            return Err(refuse("only file: URLs are served"));
        }
        let parsed = url::Url::parse(url).map_err(|_| refuse("the URL could not be parsed"))?;
        let path = parsed
            .to_file_path()
            .map_err(|()| refuse("not a local file path"))?;
        let clean = path
            .components()
            .all(|c| !matches!(c, Component::ParentDir | Component::CurDir));
        if !clean || !path.starts_with(&self.root) {
            return Err(refuse("the path is outside the served directory"));
        }
        Ok(path)
    }
}

impl BlockingTransport for DirSource {
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError> {
        if cancel.is_cancelled() {
            return Err(TransportError::new(
                TransportErrorKind::Cancelled,
                &request.url,
                None,
            ));
        }
        let path = self.path_for(&request.url)?;
        let io_failure = |e: io::Error| {
            TransportError::new(TransportErrorKind::Io, &request.url, Some(Box::new(e)))
        };
        let metadata = match fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => return Ok(status_only(404)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(status_only(404)),
            Err(e) => return Err(io_failure(e)),
        };
        let len = metadata.len();

        let (status, first, count, mut headers) = match request.range {
            None => (200, 0, len, Vec::new()),
            Some(range) => {
                let unsatisfiable = len == 0 || range.first >= len;
                let last = match range.last {
                    Some(last) => last.min(len.saturating_sub(1)),
                    None => len.saturating_sub(1),
                };
                if unsatisfiable || last < range.first {
                    let mut head = status_only(416);
                    head.head
                        .headers
                        .push(header("content-range", format!("bytes */{len}")));
                    return Ok(head);
                }
                let count = last - range.first + 1;
                let headers = vec![header(
                    "content-range",
                    format!("bytes {}-{last}/{len}", range.first),
                )];
                (206, range.first, count, headers)
            }
        };
        headers.push(header("content-length", count.to_string()));
        headers.push(header("accept-ranges", "bytes".to_owned()));

        let file = File::open(&path).map_err(io_failure)?;
        Ok(BlockingResponse {
            head: Head { status, headers },
            body: Box::new(FileRange {
                file,
                pos: first,
                remaining: count,
                cancel: cancel.clone(),
                url: request.url.clone(),
            }),
        })
    }
}

fn header(name: &str, value: String) -> (String, Vec<u8>) {
    (name.to_owned(), value.into_bytes())
}

fn status_only(status: u16) -> BlockingResponse {
    BlockingResponse {
        head: Head {
            status,
            headers: vec![header("content-length", "0".to_owned())],
        },
        body: Box::new(io::empty()),
    }
}

/// A body reading `remaining` bytes from `pos` by positional reads (no seek, so the position is
/// this value alone). Checks the token before every read.
struct FileRange {
    file: File,
    pos: u64,
    remaining: u64,
    cancel: CancelToken,
    url: String,
}

impl Read for FileRange {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(wrap(TransportError::new(
                TransportErrorKind::Cancelled,
                &self.url,
                None,
            )));
        }
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let n = read_at(&self.file, &mut buf[..want], self.pos).map_err(|e| {
            wrap(TransportError::new(
                TransportErrorKind::Io,
                &self.url,
                Some(Box::new(e)),
            ))
        })?;
        self.pos += n as u64;
        self.remaining -= n as u64;
        Ok(n)
    }
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

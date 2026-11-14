//! [`WorkerTransport`]: any [`BlockingTransport`] presented as an async [`Transport`] (M4-D1).
//!
//! One worker job per request: it calls [`BlockingTransport::get`], sends the head, then reads the
//! body in chunks of at most [`CHUNK_SIZE`] and sends each through a bounded pipe to the polling
//! task. Dropping the `get` future, or the [`Response`] (its body), cancels the job's token and
//! closes the pipe, so the worker stops at its next read or send.

use std::fmt;
use std::io::{self, ErrorKind, Read};
use std::sync::Arc;

use lunepack_core::{
    BlockingTransport, Body, BoxFuture, CancelToken, Head, Request, Response, Transport,
    TransportError, TransportErrorKind,
};

use crate::pipe::{self, AsyncReceiver, BlockingSender, Closed};
use crate::task::{JobFuture, OpLock, spawn_job};

/// The most bytes one body chunk carries.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// What the worker sends the polling task.
enum Msg {
    Head(Head),
    Chunk(Vec<u8>),
    Failed(TransportError),
}

/// A [`BlockingTransport`] run on lunepack worker threads. Cheap to clone.
pub struct WorkerTransport<T> {
    inner: Arc<T>,
    hold: Option<OpLock>,
}

impl<T> Clone for WorkerTransport<T> {
    fn clone(&self) -> Self {
        WorkerTransport {
            inner: Arc::clone(&self.inner),
            hold: self.hold.clone(),
        }
    }
}

impl<T> fmt::Debug for WorkerTransport<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerTransport")
            .field("holds_lock", &self.hold.is_some())
            .finish_non_exhaustive()
    }
}

impl<T: BlockingTransport + 'static> WorkerTransport<T> {
    /// Wraps `inner`; its requests hold no operation lock.
    pub fn new(inner: T) -> Self {
        WorkerTransport::from_arc(Arc::new(inner))
    }

    /// Wraps a shared `inner`.
    pub fn from_arc(inner: Arc<T>) -> Self {
        WorkerTransport { inner, hold: None }
    }

    /// A handle for one operation: every request job it starts holds a clone of `lock` until the
    /// job ends (M4-D15). Used by the updater; not part of the supported API.
    #[doc(hidden)]
    pub fn for_op(&self, lock: &OpLock) -> Self {
        WorkerTransport {
            inner: Arc::clone(&self.inner),
            hold: Some(lock.clone()),
        }
    }
}

impl<T: BlockingTransport + 'static> Transport for WorkerTransport<T> {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let url = request.url.clone();
        let cancel = CancelToken::new();
        let (tx, rx) = pipe::to_async::<Msg>(pipe::DEFAULT_CAPACITY, cancel.clone());
        let inner = Arc::clone(&self.inner);
        let job = spawn_job("transport", cancel, self.hold.clone(), move |cancel| {
            run_request(&*inner, &request, cancel, tx);
        });
        Box::pin(async move {
            match rx.recv().await {
                Ok(Some(Msg::Head(head))) => Ok(Response {
                    head,
                    body: Box::new(WorkerBody {
                        rx,
                        _job: job,
                        url,
                        ended: false,
                    }),
                }),
                Ok(Some(Msg::Failed(e))) => Err(e),
                Ok(Some(Msg::Chunk(_)) | None) => Err(protocol(&url)),
                Err(Closed) => Err(stopped(&url)),
            }
        })
    }
}

/// The worker's side of one request.
fn run_request<T: BlockingTransport + ?Sized>(
    inner: &T,
    request: &Request,
    cancel: &CancelToken,
    tx: BlockingSender<Msg>,
) {
    let response = match inner.get(request, cancel) {
        Ok(response) => response,
        Err(e) => {
            let _ = tx.send(Msg::Failed(e));
            return;
        }
    };
    if tx.send(Msg::Head(response.head)).is_err() {
        return;
    }
    let mut body = response.body;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match body.read(&mut buf) {
            Ok(0) => {
                tx.finish();
                return;
            }
            Ok(n) => {
                if tx.send(Msg::Chunk(buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                let _ = tx.send(Msg::Failed(from_io(e, &request.url)));
                return;
            }
        }
    }
}

/// A body read failure as a [`TransportError`]: the adapter's own error when it wrapped one
/// (`io::Error::other(TransportError)`), else an I/O error with the cause kept.
fn from_io(e: io::Error, url: &str) -> TransportError {
    if e.get_ref()
        .is_some_and(|inner| inner.is::<TransportError>())
    {
        if let Some(inner) = e.into_inner() {
            match inner.downcast::<TransportError>() {
                Ok(te) => return *te,
                Err(other) => {
                    return TransportError::new(TransportErrorKind::Io, url, Some(other));
                }
            }
        }
        return TransportError::new(TransportErrorKind::Io, url, None);
    }
    TransportError::new(TransportErrorKind::Io, url, Some(Box::new(e)))
}

fn stopped(url: &str) -> TransportError {
    TransportError::new(
        TransportErrorKind::Io,
        url,
        Some(Box::new(io::Error::other("transport worker stopped"))),
    )
}

fn protocol(url: &str) -> TransportError {
    TransportError::new(
        TransportErrorKind::Protocol,
        url,
        Some(Box::new(io::Error::other("transport worker sent no head"))),
    )
}

/// The body of a [`WorkerTransport`] response. Holds the job: dropping it cancels the worker.
struct WorkerBody {
    rx: AsyncReceiver<Msg>,
    _job: JobFuture<()>,
    url: String,
    ended: bool,
}

impl Body for WorkerBody {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            if self.ended {
                return Ok(None);
            }
            match self.rx.recv().await {
                Ok(Some(Msg::Chunk(chunk))) => Ok(Some(chunk)),
                Ok(None) => {
                    self.ended = true;
                    Ok(None)
                }
                Ok(Some(Msg::Failed(e))) => Err(e),
                Ok(Some(Msg::Head(_))) => Err(protocol(&self.url)),
                Err(Closed) => Err(stopped(&self.url)),
            }
        })
    }
}

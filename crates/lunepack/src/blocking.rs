//! A blocking face of the same [`Updater`](crate::Updater), for apps without an async runtime.
//!
//! Every method runs the async operation to completion on the calling thread with the built-in
//! [`block_on`]. Never call these inside an async task: they park the thread the executor needs.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

use lunepack_core::CancelToken;

use crate::{
    DownloadOptions, Downloaded, Error, InstalledVersion, StagedVersion, UpdateInfo, block_on,
};

/// The blocking updater: a wrapper over the same cheap handle.
#[derive(Debug, Clone)]
pub struct Updater {
    inner: crate::Updater,
}

impl From<crate::Updater> for Updater {
    fn from(inner: crate::Updater) -> Self {
        Updater { inner }
    }
}

/// Runs `future` until it completes or `cancel` is cancelled (then the future is dropped, which
/// cancels its workers).
fn run<T>(
    cancel: &CancelToken,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let mut future = pin!(future);
    block_on(poll_fn(|cx| {
        if cancel.is_cancelled() {
            return Poll::Ready(Err(Error::Cancelled));
        }
        cancel.register_waker(cx.waker());
        future.as_mut().poll(cx)
    }))
}

impl Updater {
    /// The async handle.
    pub fn as_async(&self) -> &crate::Updater {
        &self.inner
    }

    /// [`crate::Updater::check`], blocking.
    pub fn check(&self, cancel: &CancelToken) -> Result<Option<UpdateInfo>, Error> {
        run(cancel, self.inner.check())
    }

    /// [`crate::Updater::download`], blocking; `cancel` replaces the options' token.
    pub fn download(
        &self,
        info: &UpdateInfo,
        mut options: DownloadOptions,
        cancel: &CancelToken,
    ) -> Result<Downloaded, Error> {
        options.cancel = Some(cancel.clone());
        run(cancel, self.inner.download(info, options))
    }

    /// [`crate::Updater::stage`], blocking.
    pub fn stage(
        &self,
        downloaded: Downloaded,
        cancel: &CancelToken,
    ) -> Result<StagedVersion, Error> {
        run(cancel, self.inner.stage(downloaded))
    }

    /// [`crate::Updater::installed`].
    pub fn installed(&self) -> Result<Option<InstalledVersion>, Error> {
        self.inner.installed()
    }

    /// [`crate::Updater::staged`].
    pub fn staged(&self) -> Result<Option<StagedVersion>, Error> {
        self.inner.staged()
    }
}

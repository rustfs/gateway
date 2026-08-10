// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Progress-sensitive transport I/O.
//!
//! Responsible for: write-stall and connection-idle deadlines that reset on successful I/O.
//! NOT responsible for: request-body or handler progress, which belong above the transport.
//! Upstream: a plaintext or TLS stream. Downstream: Hyper's Tokio adapter.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep};

pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    Instant::now() + timeout
}

pub(crate) fn deadline_remaining(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_nanos(1))
}

pub(crate) trait Transport: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> Transport for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type BoxTransport = Box<dyn Transport>;

pub(crate) struct ProgressIo<I> {
    inner: I,
    in_flight: Arc<AtomicUsize>,
    request_seen: Arc<AtomicBool>,
    idle_timeout: Duration,
    write_timeout: Duration,
    idle_sleep: Pin<Box<Sleep>>,
    write_sleep: Pin<Box<Sleep>>,
    write_waiting: bool,
    first_request_observed: bool,
}

impl<I> ProgressIo<I> {
    pub(crate) fn new(
        inner: I,
        in_flight: Arc<AtomicUsize>,
        request_seen: Arc<AtomicBool>,
        header_deadline: Instant,
        idle_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            in_flight,
            request_seen,
            idle_timeout,
            write_timeout,
            idle_sleep: Box::pin(tokio::time::sleep_until(header_deadline)),
            write_sleep: Box::pin(sleep(write_timeout)),
            write_waiting: false,
            first_request_observed: false,
        }
    }

    fn reset_idle(&mut self) {
        self.idle_sleep.as_mut().reset(Instant::now() + self.idle_timeout);
    }

    fn reset_write(&mut self) {
        self.write_sleep.as_mut().reset(Instant::now() + self.write_timeout);
        self.write_waiting = false;
    }

    fn check_idle(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if !self.request_seen.load(Ordering::Acquire) {
            if self.idle_sleep.as_mut().poll(context).is_ready() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "request header timeout"));
            }
            return Ok(());
        }
        if !self.first_request_observed {
            self.first_request_observed = true;
            self.reset_idle();
        }
        if self.in_flight.load(Ordering::Relaxed) != 0 {
            self.reset_idle();
            return Ok(());
        }
        if self.idle_sleep.as_mut().poll(context).is_ready() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout"))
        } else {
            Ok(())
        }
    }

    fn mark_write_pending(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if !self.write_waiting {
            self.write_sleep.as_mut().reset(Instant::now() + self.write_timeout);
            self.write_waiting = true;
        }
        if self.write_sleep.as_mut().poll(context).is_ready() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "response write made no progress"))
        } else {
            Ok(())
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for ProgressIo<I> {
    fn poll_read(self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check_idle(context) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let result = ready!(Pin::new(&mut this.inner).poll_read(context, buffer));
        if result.is_ok() && buffer.filled().len() > before && this.request_seen.load(Ordering::Acquire) {
            this.reset_idle();
        }
        Poll::Ready(result)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for ProgressIo<I> {
    fn poll_write(self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, bytes) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.reset_idle();
                    this.reset_write();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.mark_write_pending(context) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(context) {
            Poll::Ready(Ok(())) => {
                this.reset_idle();
                this.reset_write();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.mark_write_pending(context) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(context, buffers) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.reset_idle();
                    this.reset_write();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.mark_write_pending(context) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    use tokio::io::AsyncWriteExt;

    struct StalledWriter;

    impl AsyncWrite for StalledWriter {
        fn poll_write(self: Pin<&mut Self>, _context: &mut Context<'_>, _bytes: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PacedWriter {
        delay: Duration,
        max_write: usize,
        written: Arc<AtomicUsize>,
        sleep: Pin<Box<Sleep>>,
    }

    impl PacedWriter {
        fn new(delay: Duration, max_write: usize, written: Arc<AtomicUsize>) -> Self {
            Self {
                delay,
                max_write,
                written,
                sleep: Box::pin(sleep(delay)),
            }
        }
    }

    impl AsyncWrite for PacedWriter {
        fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            if self.sleep.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            let written = bytes.len().min(self.max_write);
            self.written.fetch_add(written, Ordering::Relaxed);
            let delay = self.delay;
            self.sleep.as_mut().reset(Instant::now() + delay);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_transport_fails_after_one_write_progress_gap() {
        let in_flight = Arc::new(AtomicUsize::new(1));
        let mut io = ProgressIo::new(
            StalledWriter,
            in_flight,
            Arc::new(AtomicBool::new(true)),
            deadline_after(Duration::from_secs(60)),
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        let write = tokio::spawn(async move { io.write_all(b"x").await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(11)).await;
        tokio::task::yield_now().await;
        assert!(write.is_finished(), "the progress deadline must wake the pending writer");
        let error = write
            .await
            .expect("write task joins")
            .expect_err("a stalled write must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_srv_0012_one_hundred_mib_of_continuous_progress_outlives_the_interval() {
        const BODY_LEN: usize = 100 * 1024 * 1024;
        let in_flight = Arc::new(AtomicUsize::new(1));
        let written = Arc::new(AtomicUsize::new(0));
        let mut io = ProgressIo::new(
            PacedWriter::new(Duration::from_millis(9), 1024 * 1024, Arc::clone(&written)),
            in_flight,
            Arc::new(AtomicBool::new(true)),
            deadline_after(Duration::from_secs(60)),
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        let started = Instant::now();
        io.write_all(&vec![b'x'; BODY_LEN])
            .await
            .expect("every sub-interval write makes progress");
        assert_eq!(written.load(Ordering::Relaxed), BODY_LEN);
        assert!(started.elapsed() >= Duration::from_millis(900));
    }
}

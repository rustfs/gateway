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
//! Responsible for: write-stall and connection-idle deadlines that reset on successful I/O, and
//! the lingering read that ends a connection with a close rather than a reset.
//! NOT responsible for: request-body or handler progress, which belong above the transport; and
//! not for deciding *that* a connection ends — Hyper does that, from the `Connection: close` the
//! service above it wrote.
//! Upstream: a plaintext or TLS stream. Downstream: Hyper's Tokio adapter.

use std::io;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use std::os::fd::{AsFd, BorrowedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use tokio::io::Interest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep, sleep};

/// How long the drain waits for the *next* block once it has started reading.
///
/// `ServerConfig::lingering_close_time` alone would let a peer that pauses mid-body hold a
/// connection slot for the whole budget. This is nginx's `lingering_timeout` in the same role: it
/// is reset by every block that arrives, so a peer that keeps sending is bounded by the outer
/// budget and a peer that stops sending is bounded by this. A block arriving in the last instant
/// of the outer budget can therefore extend the drain by one more grace: the effective bound is
/// the budget plus this, and it is left that way rather than clamped so that the budget is
/// expressed in exactly one place — a second expression of the same bound is a second place for it
/// to be wrong, and one no test could reach. It is a constant and the outer bound
/// is not, because the outer bound is the one a deployment has a reason to argue about: it is how
/// patient the service is with a peer that still owes it a body.
///
/// Both are *times* and neither is a byte count, and that distinction is the substance of
/// rustfs/gateway#211. What the ceilings above this layer refuse to spend is **memory** —
/// aggregating a body before deciding about it is the out-of-memory condition — and reading a
/// block into a stack buffer and dropping it costs no memory at all, so the resource a drain has
/// to be bounded in is time. A byte budget has the opposite of the wanted effect: a refusal that
/// fires *because* a body is too large leaves more than any such budget in flight by construction,
/// so the drain would stop early on exactly the connections it exists for.
///
/// These are deliberately **not** `rustfs_gateway_http::MAX_LINGER_DRAIN_BYTES` and deliberately
/// not `rustfs-gateway-conformance`'s own linger constants. That crate's numbers bound a blocking
/// thread per connection in a test harness; these bound a Tokio task on a listener that may be
/// holding ten thousand connections, and the two may disagree without either being wrong.
const LINGER_QUIET: Duration = Duration::from_millis(100);

/// Blocks discarded in one `poll_shutdown` before the drain yields to the runtime.
///
/// A peer sending as fast as this loop reads would otherwise own a worker thread until the outer
/// budget expired. The yield is a self-wake, so the drain resumes on the next poll and the bound
/// is unaffected.
const LINGER_BLOCKS_PER_POLL: usize = 16;

/// One discarded block. Stack-allocated per poll, never retained: a drain that grew with the
/// remainder would be the memory cost the refusal was avoiding.
const LINGER_BLOCK: usize = 8 * 1024;

pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    Instant::now() + timeout
}

pub(crate) fn deadline_remaining(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_nanos(1))
}

pub(crate) fn deadline_reached(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

pub(crate) trait Transport: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> Transport for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type BoxTransport = Box<dyn Transport>;

#[cfg(test)]
pub(crate) type HeaderPendingObserver = Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
pub(crate) fn test_deadline_now() -> Instant {
    Instant::now()
}

pub(crate) struct ProgressIo<I> {
    inner: I,
    in_flight: Arc<AtomicUsize>,
    request_seen: Arc<AtomicBool>,
    idle_timeout: Duration,
    write_timeout: Duration,
    idle_sleep: Pin<Box<Sleep>>,
    write_sleep: Pin<Box<Sleep>>,
    write_waiting: bool,
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    send_file_retry_ready: bool,
    first_request_observed: bool,
    transport_read: Arc<AtomicU64>,
    linger: Linger,
    #[cfg(test)]
    header_pending_observer: Option<HeaderPendingObserver>,
}

/// State of the lingering read, which exists only between the half-close and the drop.
struct Linger {
    /// `ServerConfig::lingering_close_time`, the outer bound on the whole drain.
    budget: Duration,
    /// Whether the write side has already been shut down. `poll_shutdown` is re-entrant.
    write_shut: bool,
    /// When the whole drain gives up, armed at the half-close from [`Linger::budget`].
    deadline: Instant,
    /// Rearmed by every block that arrives; see [`LINGER_QUIET`].
    quiet: Pin<Box<Sleep>>,
    /// Whether any block was ever ready. See [`ProgressIo::poll_drain`] for why this gates the
    /// drain rather than merely reporting on it.
    started: bool,
    /// Whether the application proved that it stopped before the request body reached its end.
    body_unfinished: Arc<AtomicBool>,
    /// Where the octets this drain discards are reported, so that what the drain accepted is
    /// observable from the server rather than inferred from how much a peer got out of its own
    /// send buffer. Wired to `ServerMetrics::lingering_octets_drained`; a `ProgressIo` built
    /// without a listener behind it (the unit tests below) keeps the unshared counter it is born
    /// with, which nothing reads.
    drained: Arc<AtomicU64>,
}

impl<I> ProgressIo<I> {
    pub(crate) fn new(
        inner: I,
        in_flight: Arc<AtomicUsize>,
        request_seen: Arc<AtomicBool>,
        header_deadline: Instant,
        idle_timeout: Duration,
        write_timeout: Duration,
        lingering_close_time: Duration,
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
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
            send_file_retry_ready: false,
            first_request_observed: false,
            transport_read: Arc::new(AtomicU64::new(0)),
            linger: Linger {
                budget: lingering_close_time,
                write_shut: false,
                deadline: Instant::now(),
                quiet: Box::pin(sleep(LINGER_QUIET)),
                started: false,
                body_unfinished: Arc::new(AtomicBool::new(false)),
                drained: Arc::new(AtomicU64::new(0)),
            },
            #[cfg(test)]
            header_pending_observer: None,
        }
    }

    /// Points this connection's octet counts at the listener's shared ones — everything read off
    /// the transport, and the part of it the lingering drain discarded.
    ///
    /// Separate from [`ProgressIo::new`] rather than more parameters to it: these are observed,
    /// not configured, and `new` is already at the argument count where one more is a lint.
    pub(crate) fn count_octets_into(mut self, transport_read: Arc<AtomicU64>, drained: Arc<AtomicU64>) -> Self {
        self.transport_read = transport_read;
        self.linger.drained = drained;
        self
    }

    /// Points this connection's lingering start decision at the application-owned body state.
    pub(crate) fn request_body_unfinished(mut self, body_unfinished: Arc<AtomicBool>) -> Self {
        self.linger.body_unfinished = body_unfinished;
        self
    }

    pub(crate) fn mark_request_body_unfinished(&self) {
        self.linger.body_unfinished.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn observe_header_pending(mut self, observer: HeaderPendingObserver) -> Self {
        self.header_pending_observer = Some(observer);
        self
    }

    fn reset_idle(&mut self) {
        self.idle_sleep.as_mut().reset(Instant::now() + self.idle_timeout);
    }

    fn reset_write(&mut self) {
        self.write_sleep.as_mut().reset(Instant::now() + self.write_timeout);
        self.write_waiting = false;
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            self.send_file_retry_ready = false;
        }
    }

    fn record_write_progress(&mut self, written: usize) {
        if written > 0 {
            self.reset_idle();
            self.reset_write();
        }
    }

    fn check_idle(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if !self.request_seen.load(Ordering::Acquire) {
            let deadline = self.idle_sleep.as_mut().poll(context);
            #[cfg(test)]
            if deadline.is_pending()
                && let Some(observer) = self.header_pending_observer.take()
            {
                observer();
            }
            if deadline.is_ready() {
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
        self.begin_write_wait();
        self.check_write_wait(context)
    }

    fn begin_write_wait(&mut self) {
        if !self.write_waiting {
            self.write_sleep.as_mut().reset(Instant::now() + self.write_timeout);
            self.write_waiting = true;
        }
    }

    fn check_write_wait(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if self.write_sleep.as_mut().poll(context).is_ready() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "response write made no progress"))
        } else {
            Ok(())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn writable_repoll_needs_retry<T>(poll: Poll<io::Result<T>>) -> io::Result<bool> {
    match poll {
        Poll::Ready(Ok(_)) => Ok(true),
        Poll::Pending => Ok(false),
        Poll::Ready(Err(error)) => Err(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn send_file_level_after_poll(result: nix::Result<i32>, ready: bool) -> bool {
    match result {
        Ok(_) => ready,
        Err(_) => false,
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl ProgressIo<TcpStream> {
    pub(crate) fn poll_send_file_ready(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.send_file_retry_ready {
            this.send_file_retry_ready = false;
        } else if !writable_repoll_needs_retry(this.inner.poll_write_ready(context))? {
            this.mark_write_pending(context)?;
            return Poll::Pending;
        }
        if this.write_waiting {
            this.check_write_wait(context)?;
        }
        Poll::Ready(Ok(()))
    }

    pub(crate) fn socket_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }

    pub(crate) fn begin_send_file_wait(&mut self) -> Instant {
        self.begin_write_wait();
        self.write_sleep.deadline()
    }

    pub(crate) fn record_send_file_progress(&mut self, written: usize) {
        self.record_write_progress(written);
    }

    pub(crate) fn record_send_file_would_block(&mut self) {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

        let _ = self
            .inner
            .try_io(Interest::WRITABLE, || Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock)));
        let mut readiness = [PollFd::new(self.inner.as_fd(), PollFlags::POLLOUT)];
        let result = poll(&mut readiness, PollTimeout::ZERO);
        self.send_file_retry_ready = send_file_level_after_poll(result, readiness[0].any().unwrap_or(false));
        self.begin_write_wait();
    }

    pub(crate) fn record_send_file_retry(&mut self) {
        self.begin_write_wait();
    }
}

impl<I: AsyncRead + Unpin> ProgressIo<I> {
    /// Reads what the peer is still sending and throws it away, so that the drop that follows is a
    /// close and not a reset.
    ///
    /// # Why this is here at all
    ///
    /// Dropping a socket that still holds unread received octets sends `RST` instead of finishing
    /// the `FIN` exchange, and RFC 9112 §9.6 says what that costs: the reset can discard the
    /// peer's receive buffer before its HTTP parser has read it, so a client that was about to
    /// learn *why* it was refused gets `ECONNRESET` instead of the refusal. Every refusal this
    /// runtime makes before draining the body — an over-cap body, an authentication failure, a
    /// framing verdict — is by construction a refusal with octets still arriving, so this is the
    /// ordinary case and not the exotic one. Measured on a real socket before it was fixed: a
    /// `400` answered over a one-mebibyte body that the service never read reached the client, and
    /// the next read on that socket returned `ECONNRESET` rather than end of stream.
    ///
    /// # Why a read that is not ready usually ends it
    ///
    /// The first poll decides whether there is a drain at all. Like nginx's `lingering_close on`
    /// default, an already-ready read starts it; this runtime also accepts the independently known
    /// unfinished-body condition nginx documents beside that readiness check. A close with nothing
    /// in flight has nothing to linger over, and lingering anyway would hold a connection slot —
    /// and its `active_connections()` seat — for a budget it cannot spend. The exception is an
    /// application that attached [`crate::UnfinishedRequestBody`] to its response:
    /// then an initially pending read gets the same quiet grace as a drain that already consumed a
    /// block. Every keep-alive expiry and graceful shutdown reaches this function, so the unmarked
    /// common path still costs nothing.
    fn poll_drain(&mut self, context: &mut Context<'_>) -> Poll<()> {
        let mut buffer = [0_u8; LINGER_BLOCK];
        for _ in 0..LINGER_BLOCKS_PER_POLL {
            if Instant::now() >= self.linger.deadline {
                return Poll::Ready(());
            }
            let mut read = ReadBuf::new(&mut buffer);
            match Pin::new(&mut self.inner).poll_read(context, &mut read) {
                // End of stream, or a transport that will not talk to us any more. Either way
                // there is nothing left to be reset over.
                Poll::Ready(Err(_)) => return Poll::Ready(()),
                Poll::Ready(Ok(())) if read.filled().is_empty() => return Poll::Ready(()),
                Poll::Ready(Ok(())) => {
                    self.linger.started = true;
                    let block = read.filled().len() as u64;
                    self.transport_read.fetch_add(block, Ordering::Relaxed);
                    self.linger.drained.fetch_add(block, Ordering::Relaxed);
                    self.linger.quiet.as_mut().reset(Instant::now() + LINGER_QUIET);
                }
                Poll::Pending => {
                    if !self.linger.started && !self.linger.body_unfinished.load(Ordering::Acquire) {
                        return Poll::Ready(());
                    }
                    return if self.linger.quiet.as_mut().poll(context).is_ready() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
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
        if result.is_ok() && buffer.filled().len() > before {
            this.transport_read
                .fetch_add((buffer.filled().len() - before) as u64, Ordering::Relaxed);
            if this.request_seen.load(Ordering::Acquire) {
                this.reset_idle();
            }
        }
        Poll::Ready(result)
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ProgressIo<I> {
    fn poll_write(self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, bytes) {
            Poll::Ready(Ok(written)) => {
                this.record_write_progress(written);
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

    /// Half-closes, then lingers.
    ///
    /// The order is the whole of it: `FIN` first, so the peer learns there is no more to read and
    /// stops pipelining, and only then the read that keeps the drop from becoming a reset. The
    /// drain never fails the shutdown — a peer that went silent, a peer that keeps writing past
    /// its budget, and a transport that errors are all "we are done here", and reporting them
    /// as a shutdown error would only turn a finished connection into a logged one.
    ///
    /// What a drain in progress holds is the connection: its `max_connections` permit, its per-IP
    /// lease, and its seat in `ServerMetrics::active_connections`. It does **not** hold a request
    /// permit — `ConnectionBody` releases that when the response body ends, which is before
    /// anything here runs — so a lingering close cannot starve the global in-flight ceiling.
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.linger.write_shut {
            ready!(Pin::new(&mut this.inner).poll_shutdown(context))?;
            this.linger.write_shut = true;
            this.linger.deadline = Instant::now() + this.linger.budget;
            let quiet_deadline = if this.linger.body_unfinished.load(Ordering::Acquire) {
                Instant::now() + LINGER_QUIET
            } else {
                this.linger.deadline
            };
            this.linger.quiet.as_mut().reset(quiet_deadline);
        }
        ready!(this.poll_drain(context));
        Poll::Ready(Ok(()))
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

    struct DelayedReader {
        ready: Pin<Box<Sleep>>,
        body: Option<&'static [u8]>,
    }

    impl DelayedReader {
        fn new(delay: Duration, body: &'static [u8]) -> Self {
            Self {
                ready: Box::pin(sleep(delay)),
                body: Some(body),
            }
        }
    }

    impl AsyncRead for DelayedReader {
        fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if self.ready.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            if let Some(body) = self.body.take() {
                buffer.put_slice(body);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DelayedReader {
        fn poll_write(self: Pin<&mut Self>, _context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn delayed_lingering_io(
        delay: Duration,
        body: &'static [u8],
        body_unfinished: bool,
        drained: Arc<AtomicU64>,
    ) -> ProgressIo<DelayedReader> {
        ProgressIo::new(
            DelayedReader::new(delay, body),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(true)),
            deadline_after(Duration::from_secs(60)),
            Duration::from_secs(60),
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .request_body_unfinished(Arc::new(AtomicBool::new(body_unfinished)))
        .count_octets_into(Arc::new(AtomicU64::new(0)), drained)
    }

    /// Positive — an early refusal waits for a body already known to be unfinished even when the
    /// first transport read loses the arrival race.
    #[tokio::test(start_paused = true)]
    async fn a_known_unfinished_body_that_arrives_after_shutdown_starts_is_drained() {
        let drained = Arc::new(AtomicU64::new(0));
        let mut io = delayed_lingering_io(LINGER_QUIET / 2, b"late body", true, Arc::clone(&drained));
        let shutdown = tokio::spawn(async move { io.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished(), "the initial Pending abandoned a body known to be unfinished");
        tokio::time::advance(LINGER_QUIET / 2).await;
        shutdown.await.expect("shutdown task joins").expect("shutdown succeeds");
        assert_eq!(drained.load(Ordering::Relaxed), 9);
    }

    /// Negative — an ordinary close with no unfinished-body proof still retires immediately.
    #[tokio::test(start_paused = true)]
    async fn an_initially_pending_transport_without_body_proof_does_not_linger() {
        let started = Instant::now();
        let mut io = delayed_lingering_io(Duration::from_secs(60), b"not owed", false, Arc::new(AtomicU64::new(0)));
        io.shutdown().await.expect("a bodyless close retires immediately");
        assert_eq!(started.elapsed(), Duration::ZERO, "the bodyless close spent a linger interval");
    }

    /// Negative — an unfinished peer that sends nothing gets only the existing quiet grace, not
    /// the whole outer linger budget.
    #[tokio::test(start_paused = true)]
    async fn a_known_unfinished_body_that_stays_silent_is_bounded_by_the_quiet_grace() {
        let started = Instant::now();
        let mut io = delayed_lingering_io(Duration::from_secs(60), b"never arrives", true, Arc::new(AtomicU64::new(0)));
        let shutdown = tokio::spawn(async move { io.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished(), "the unfinished body was abandoned without its quiet grace");
        tokio::time::advance(LINGER_QUIET + Duration::from_millis(1)).await;
        shutdown.await.expect("shutdown task joins").expect("shutdown succeeds");
        assert_eq!(
            started.elapsed(),
            LINGER_QUIET + Duration::from_millis(1),
            "the silent body was charged more than the existing quiet grace"
        );
    }

    struct StalledWriter;

    /// Neither writer below has a peer, so "the peer sent nothing and never will" is the honest
    /// read side for both: end of stream. It also keeps the drain out of the way of the cases
    /// below, which are about the write-progress deadline.
    impl AsyncRead for StalledWriter {
        fn poll_read(self: Pin<&mut Self>, _context: &mut Context<'_>, _buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for PacedWriter {
        fn poll_read(self: Pin<&mut Self>, _context: &mut Context<'_>, _buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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
            Duration::from_secs(2),
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
            Duration::from_secs(2),
        );
        let started = Instant::now();
        io.write_all(&vec![b'x'; BODY_LEN])
            .await
            .expect("every sub-interval write makes progress");
        assert_eq!(written.load(Ordering::Relaxed), BODY_LEN);
        assert!(started.elapsed() >= Duration::from_millis(900));
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
#[allow(clippy::expect_used, clippy::panic)] // Test-only real-socket setup must terminate on fixture failure.
#[path = "io_sendfile_tests.rs"]
mod sendfile_tests;

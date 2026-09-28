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

//! Accepted-connection ownership and driver selection.
//!
//! Responsible for: selecting one driver per listener and transferring each owned socket to it.
//! NOT responsible for: HTTP parsing, response encoding or protocol-specific transport policy.
//! Upstream: `Server::serve_with`. Downstream: the built-in Hyper driver or an external driver.

use std::future::Future;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream as StdTcpStream};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tower::Service as TowerService;

use crate::config::ServerConfig;
use crate::conn::{BoxError, ConnectionLifecycle, ConnectionState, run_connection};
use crate::connection_service::ConnectionService;
use crate::io::ProgressIo;
use crate::sendfile_task::BlockingFileTransferExecutor;

/// A startup refusal reported by a connection driver before the listener is bound.
pub type DriverValidationError = Box<dyn std::error::Error + Send + Sync>;

/// An owned connection-driver task.
pub type ConnectionFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Drives one accepted connection with one clone of the configured service.
///
/// A server selects the driver once for the listener. The returned future owns the connection
/// until it completes; connection admission is not released before then.
pub trait ConnectionDriver<S>: Clone + Send + 'static {
    /// Validates that this driver can honor the selected listener transport.
    ///
    /// The default accepts every valid server configuration. A specialized driver overrides this
    /// when a mismatch would otherwise make it silently discard accepted sockets.
    fn validate(&self, _config: &ServerConfig, _tls_configured: bool) -> Result<(), DriverValidationError> {
        Ok(())
    }

    /// Starts driving one accepted connection.
    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture;
}

/// Cleartext socket I/O with the server's progress deadlines, lingering close and counters.
///
/// A self-held protocol driver receives this instead of the raw socket so taking ownership does
/// not bypass listener-wide timeout or close behavior.
pub struct PlaintextConnection {
    inner: ProgressIo<TcpStream>,
    file_transfer_executor: BlockingFileTransferExecutor,
    lifecycle: ConnectionLifecycle,
}

/// Progress observed between entering a file transfer and returning a transfer observation.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTransferProgress {
    bytes: usize,
    blocking_handoffs: usize,
    kernel_calls: usize,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl FileTransferProgress {
    /// Bytes returned by successful kernel-transfer calls in this progress interval.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Detached-thread handoffs attempted before this progress was returned.
    #[must_use]
    pub const fn blocking_handoffs(self) -> usize {
        self.blocking_handoffs
    }

    /// Kernel-transfer syscall attempts made before this progress was returned.
    #[must_use]
    pub const fn kernel_calls(self) -> usize {
        self.kernel_calls
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[derive(Default)]
struct FileTransferState {
    blocking_handoffs: usize,
    kernel_calls: usize,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl FileTransferState {
    fn record_calls(&mut self, calls: usize) {
        self.blocking_handoffs = self.blocking_handoffs.saturating_add(1);
        self.kernel_calls = self.kernel_calls.saturating_add(calls);
    }

    fn finish(self, bytes: usize) -> FileTransferProgress {
        FileTransferProgress {
            bytes,
            blocking_handoffs: self.blocking_handoffs,
            kernel_calls: self.kernel_calls,
        }
    }

    fn observe_handoff(&mut self, result: Result<SendFileBatchProgress, SendFileBatchError>) -> io::Result<SendFileHandoff> {
        match result {
            Ok(progress) => {
                self.record_calls(progress.calls);
                Ok(SendFileHandoff::Progress(progress))
            }
            Err(failure) if failure.kind() == io::ErrorKind::Interrupted => {
                self.record_calls(failure.calls);
                Ok(SendFileHandoff::Interrupted)
            }
            Err(failure) => Err(failure.error),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
enum SendFileHandoff {
    Progress(SendFileBatchProgress),
    Interrupted,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
const MAX_SEND_FILE_ATTEMPTS_PER_HANDOFF: usize = 16;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[derive(Debug)]
struct SendFileBatchProgress {
    bytes: usize,
    calls: usize,
    needs_write_ready: bool,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[derive(Debug)]
struct SendFileBatchError {
    error: io::Error,
    calls: usize,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl SendFileBatchError {
    fn kind(&self) -> io::ErrorKind {
        self.error.kind()
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn send_file_batch<F>(offset: u64, count: usize, mut attempt: F) -> Result<SendFileBatchProgress, SendFileBatchError>
where
    F: FnMut(u64, usize) -> io::Result<usize>,
{
    let mut progress = SendFileBatchProgress {
        bytes: 0,
        calls: 0,
        needs_write_ready: false,
    };
    let mut next_offset = offset;
    let mut remaining = count;
    let mut last_interruption = None;

    for _ in 0..MAX_SEND_FILE_ATTEMPTS_PER_HANDOFF {
        if remaining == 0 {
            break;
        }
        progress.calls = progress.calls.saturating_add(1);
        match attempt(next_offset, remaining) {
            Ok(0) => break,
            Ok(written) if written <= remaining => {
                let written_u64 = u64::try_from(written).map_err(|error| SendFileBatchError {
                    error: io::Error::other(error),
                    calls: progress.calls,
                })?;
                next_offset = next_offset.checked_add(written_u64).ok_or_else(|| SendFileBatchError {
                    error: io::Error::other("sendfile batch offset overflowed"),
                    calls: progress.calls,
                })?;
                remaining -= written;
                progress.bytes = progress.bytes.checked_add(written).ok_or_else(|| SendFileBatchError {
                    error: io::Error::other("sendfile batch progress overflowed"),
                    calls: progress.calls,
                })?;
                last_interruption = None;
            }
            Ok(_) => {
                return Err(SendFileBatchError {
                    error: io::Error::new(io::ErrorKind::InvalidData, "sendfile reported progress beyond the requested region"),
                    calls: progress.calls,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                last_interruption = Some(error);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                progress.needs_write_ready = true;
                return Ok(progress);
            }
            Err(_error) if progress.bytes > 0 => return Ok(progress),
            Err(error) => {
                return Err(SendFileBatchError {
                    error,
                    calls: progress.calls,
                });
            }
        }
    }

    if progress.bytes == 0
        && let Some(error) = last_interruption
    {
        return Err(SendFileBatchError {
            error,
            calls: progress.calls,
        });
    }
    Ok(progress)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
struct SocketAbortGuard {
    socket: StdTcpStream,
    armed: bool,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl SocketAbortGuard {
    fn new(socket: BorrowedFd<'_>) -> io::Result<Self> {
        Ok(Self {
            socket: StdTcpStream::from(socket.try_clone_to_owned()?),
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
impl Drop for SocketAbortGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn finish_socket_handoff<T>(mut guard: SocketAbortGuard, result: io::Result<T>) -> io::Result<T> {
    if result.is_ok() {
        guard.disarm();
    }
    result
}

impl PlaintextConnection {
    /// Records transport-owned proof that request octets remain before an orderly close.
    ///
    /// A self-held parser has stronger information than an application response: it owns the
    /// framing state and can see that the peer still owes body bytes. Recording that fact makes
    /// shutdown linger after its write-side FIN instead of dropping unread octets with a reset.
    pub fn mark_request_body_unfinished(&self) {
        self.inner.mark_request_body_unfinished();
    }

    /// Attempts one file-to-socket transfer without copying its bytes through user space, while
    /// retaining the connection's write-progress deadline.
    ///
    /// The borrowed descriptor is duplicated for the blocking handoff. Call
    /// [`Self::send_file_owned_once`] when the caller can transfer ownership across repeated calls.
    ///
    /// # Cancellation
    ///
    /// This method has the same cancellation behavior as [`Self::send_file_owned_once`]: dropping
    /// it after a blocking handoff starts shuts down the connection.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    pub async fn send_file_once(&mut self, file: BorrowedFd<'_>, offset: u64, len: u64) -> io::Result<usize> {
        let file = file.try_clone_to_owned()?;
        let (_file, progress) = self.send_file_owned_once(file, offset, len).await?;
        Ok(progress.bytes())
    }

    /// Attempts one owned file-to-socket transfer and returns the descriptor with successful progress.
    ///
    /// Returning ownership lets a response reuse one descriptor across blocking handoffs. HTTP
    /// framing and payload policy remain the caller's responsibility.
    ///
    /// # Cancellation
    ///
    /// Dropping this future after its blocking handoff starts shuts down the connection. The
    /// syscall may already have made partial progress, so continuing HTTP on that socket would be
    /// ambiguous.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    pub async fn send_file_owned_once(
        &mut self,
        file: OwnedFd,
        offset: u64,
        len: u64,
    ) -> io::Result<(OwnedFd, FileTransferProgress)> {
        use std::future::poll_fn;

        if len == 0 {
            return Ok((
                file,
                FileTransferProgress {
                    bytes: 0,
                    blocking_handoffs: 0,
                    kernel_calls: 0,
                },
            ));
        }
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file region end overflows"))?;
        let _ = nix::libc::off_t::try_from(end)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file region end exceeds sendfile range"))?;
        let count = usize::try_from(len.min(crate::sendfile::MAX_CHUNK)).map_err(io::Error::other)?;
        let mut file = file;
        let mut transfer = FileTransferState::default();
        loop {
            poll_fn(|context| Pin::new(&mut self.inner).poll_send_file_ready(context)).await?;
            let queue_deadline = self.inner.begin_send_file_wait();
            let reservation = self.file_transfer_executor.reserve_until(queue_deadline).await?;
            let worker_socket = self.inner.socket_fd().try_clone_to_owned()?;
            let lifecycle = self.lifecycle.clone();
            let cancel = SocketAbortGuard::new(self.inner.socket_fd())?;
            let handoff = reservation
                .run_until(queue_deadline, move |permit| {
                    let _lifecycle = lifecycle;
                    let result = send_file_batch(offset, count, |next_offset, next_count| {
                        crate::sendfile::send_file(&permit, worker_socket.as_fd(), file.as_fd(), next_offset, next_count)
                    });
                    Ok((file, result))
                })
                .await;
            let (next_file, result) = finish_socket_handoff(cancel, handoff)?;
            file = next_file;
            match transfer.observe_handoff(result)? {
                SendFileHandoff::Progress(progress) => {
                    // Progress first: it resets the write deadline, and that reset also discards the
                    // writable level recorded below. Probed in the other order, a partial send that
                    // ended in `EAGAIN` forgot a writable edge another worker had already consumed,
                    // and the transfer then waited for an edge that never came until the
                    // write-progress deadline closed the connection.
                    self.inner.record_send_file_progress(progress.bytes);
                    if progress.needs_write_ready {
                        self.inner.record_send_file_would_block();
                    }
                    if progress.bytes > 0 || !progress.needs_write_ready {
                        return Ok((file, transfer.finish(progress.bytes)));
                    }
                }
                SendFileHandoff::Interrupted => {
                    self.inner.record_send_file_retry();
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

impl AsyncRead for PlaintextConnection {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PlaintextConnection {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }
}

/// One accepted socket and the generic server facts captured with it.
///
/// The value is owned and `'static`. Drivers may copy the observed facts and then consume the
/// socket with [`Self::into_plaintext`].
pub struct AcceptedConnection<S> {
    state: ConnectionState,
    service: S,
}

impl<S> AcceptedConnection<S> {
    pub(crate) fn new(state: ConnectionState, service: S) -> Self {
        Self { state, service }
    }

    pub(crate) fn into_parts(self) -> (ConnectionState, S) {
        (self.state, self.service)
    }

    /// Returns the peer address observed by the listener.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.state.peer_addr
    }

    /// Returns the accepted socket's observed `TCP_NODELAY` value.
    #[must_use]
    pub const fn tcp_nodelay(&self) -> bool {
        self.state.tcp_nodelay
    }

    /// Returns the listener configuration used for this connection.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.state.config
    }

    /// Returns whether this listener has TLS material configured.
    #[must_use]
    pub const fn tls_configured(&self) -> bool {
        self.state.tls.is_some()
    }

    /// Returns a receiver that changes when graceful shutdown starts.
    #[must_use]
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.state.shutdown.clone()
    }

    /// Returns the accept-to-header deadline shared by every connection driver.
    #[must_use]
    pub const fn header_deadline(&self) -> tokio::time::Instant {
        self.state.header_deadline
    }

    /// Consumes a cleartext connection into its socket and mandatory lifecycle service.
    ///
    /// The service is the only supported route from a parsed request to the configured
    /// application. It enforces the same capacity, cancellation, panic and shutdown contracts as
    /// the default Hyper driver.
    ///
    /// # Errors
    ///
    /// Returns [`PlaintextTakeoverError`] when TLS is configured. TLS and HTTP/2 remain owned by
    /// [`HyperConnectionDriver`].
    pub fn into_plaintext(self) -> Result<(PlaintextConnection, ConnectionService<S>), PlaintextTakeoverError> {
        if self.state.tls.is_some() {
            return Err(PlaintextTakeoverError);
        }
        let connection = ConnectionInfo {
            peer_addr: self.state.peer_addr,
            transport: TransportKind::Plaintext,
            tcp_nodelay: self.state.tcp_nodelay,
        };
        let service = ConnectionService::new(
            self.service,
            connection,
            Arc::clone(&self.state.request_seen),
            Arc::clone(&self.state.request_capacity),
            Arc::clone(&self.state.request_stats),
            Arc::clone(&self.state.connection_in_flight),
            Arc::clone(&self.state.request_body_unfinished),
        );
        let inner = ProgressIo::new(
            self.state.stream,
            Arc::clone(&self.state.connection_in_flight),
            Arc::clone(&self.state.request_seen),
            self.state.header_deadline,
            self.state.config.keep_alive_idle,
            self.state.config.write_progress_timeout,
            self.state.config.lingering_close_time,
        )
        .request_body_unfinished(Arc::clone(&self.state.request_body_unfinished))
        .count_octets_into(
            Arc::clone(&self.state.metrics.transport_read),
            Arc::clone(&self.state.metrics.lingering_drained),
        );
        Ok((
            PlaintextConnection {
                inner,
                file_transfer_executor: self.state.file_transfer_executor,
                lifecycle: self.state.lifecycle,
            },
            service,
        ))
    }
}

/// A self-held plaintext driver was selected for a TLS-configured listener.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("plaintext connection takeover is unavailable when TLS is configured")]
pub struct PlaintextTakeoverError;

/// Transport facts observed at accept and inserted into every request's extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub(crate) peer_addr: SocketAddr,
    pub(crate) transport: TransportKind,
    pub(crate) tcp_nodelay: bool,
}

impl ConnectionInfo {
    /// Returns the peer socket address observed by the listener.
    #[must_use]
    pub const fn peer_addr(self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns whether this connection completed TLS or was explicitly cleartext.
    #[must_use]
    pub const fn transport(self) -> TransportKind {
        self.transport
    }

    /// Returns the accepted socket's observed `TCP_NODELAY` value.
    #[must_use]
    pub const fn tcp_nodelay(self) -> bool {
        self.tcp_nodelay
    }
}

/// Security of the accepted transport, independent of any forwarded header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// Cleartext was explicitly enabled in [`ServerConfig`].
    Plaintext,
    /// A Rustls server handshake completed before Hyper saw the connection.
    Tls,
}

#[cfg(all(test, any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
#[allow(clippy::expect_used)] // Test-only local socket setup has no external failure path to recover from.
mod send_file_cancellation_tests {
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::fd::AsFd;

    use super::{
        FileTransferState, MAX_SEND_FILE_ATTEMPTS_PER_HANDOFF, SendFileBatchError, SendFileBatchProgress, SendFileHandoff,
        SocketAbortGuard, StdTcpStream, finish_socket_handoff, send_file_batch,
    };

    fn socket_pair() -> (StdTcpStream, StdTcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("test listener binds");
        let client =
            StdTcpStream::connect(listener.local_addr().expect("test listener has an address")).expect("test client connects");
        let (server, _) = listener.accept().expect("test server accepts");
        (server, client)
    }

    #[test]
    fn armed_cancellation_guard_prevents_a_duplicate_from_writing_late_bytes() {
        let (server, mut client) = socket_pair();
        let mut worker = server.try_clone().expect("worker duplicates the socket");
        let guard = SocketAbortGuard::new(server.as_fd()).expect("cancellation guard duplicates the socket");

        drop(guard);

        assert!(worker.write_all(b"late").is_err(), "shutdown reaches the worker duplicate");
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).expect("peer observes shutdown"), 0);
    }

    #[test]
    fn disarmed_cancellation_guard_leaves_the_completed_connection_writable() {
        let (server, mut client) = socket_pair();
        let mut worker = server.try_clone().expect("worker duplicates the socket");
        let mut guard = SocketAbortGuard::new(server.as_fd()).expect("cancellation guard duplicates the socket");

        guard.disarm();
        drop(guard);
        worker.write_all(b"x").expect("completed handoff keeps the socket writable");
        let mut byte = [0_u8; 1];
        client.read_exact(&mut byte).expect("peer reads the completed byte");
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn timed_out_handoff_shuts_down_the_socket_before_reporting_the_error() {
        let (server, mut client) = socket_pair();
        let mut worker = server.try_clone().expect("worker duplicates the socket");
        let guard = SocketAbortGuard::new(server.as_fd()).expect("cancellation guard duplicates the socket");

        let error = finish_socket_handoff(guard, Err::<(), _>(std::io::ErrorKind::TimedOut.into()))
            .expect_err("deadline expiry remains an error");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(worker.write_all(b"late").is_err(), "timed-out work cannot write after its waiter exits");
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).expect("peer observes timeout shutdown"), 0);
    }

    #[test]
    fn batch_retries_without_skipping_offsets_and_stops_at_socket_backpressure() {
        let mut results = VecDeque::from([
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
            Ok(3),
            Ok(2),
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        ]);
        let mut observed = Vec::new();

        let progress = send_file_batch(11, 10, |offset, count| {
            observed.push((offset, count));
            results.pop_front().expect("script has one result per attempt")
        })
        .expect("positive progress is preserved before backpressure");

        assert_eq!(progress.bytes, 5);
        assert_eq!(progress.calls, 4);
        assert!(progress.needs_write_ready);
        assert_eq!(observed, [(11, 10), (11, 10), (14, 7), (16, 5)]);
    }

    #[test]
    fn zero_progress_handoffs_and_syscalls_remain_observable() {
        let mut transfer = FileTransferState::default();
        assert!(matches!(
            transfer
                .observe_handoff(Ok(SendFileBatchProgress {
                    bytes: 0,
                    calls: 1,
                    needs_write_ready: true,
                }))
                .expect("would-block handoff remains a retry"),
            SendFileHandoff::Progress(_)
        ));
        assert!(matches!(
            transfer
                .observe_handoff(Err(SendFileBatchError {
                    error: std::io::ErrorKind::Interrupted.into(),
                    calls: MAX_SEND_FILE_ATTEMPTS_PER_HANDOFF,
                }))
                .expect("interrupted handoff remains a retry"),
            SendFileHandoff::Interrupted
        ));
        assert!(matches!(
            transfer
                .observe_handoff(Ok(SendFileBatchProgress {
                    bytes: 5,
                    calls: 2,
                    needs_write_ready: false,
                }))
                .expect("positive handoff remains progress"),
            SendFileHandoff::Progress(_)
        ));

        let progress = transfer.finish(5);
        assert_eq!(progress.bytes(), 5);
        assert_eq!(progress.blocking_handoffs(), 3);
        assert_eq!(progress.kernel_calls(), MAX_SEND_FILE_ATTEMPTS_PER_HANDOFF + 3);
    }

    #[test]
    fn repeated_interruptions_are_bounded_without_fabricating_progress() {
        let mut attempts = 0;
        let error = send_file_batch(7, 9, |offset, count| {
            attempts += 1;
            assert_eq!((offset, count), (7, 9));
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        })
        .expect_err("an interruption-only batch yields back to the runtime");

        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(attempts, MAX_SEND_FILE_ATTEMPTS_PER_HANDOFF);
    }
}

/// The default driver backed by Hyper's HTTP/1.1 and HTTP/2 connection state machines.
#[derive(Clone, Copy, Debug, Default)]
pub struct HyperConnectionDriver;

impl<S, B> ConnectionDriver<S> for HyperConnectionDriver
where
    S: TowerService<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture {
        let (state, service) = accepted.into_parts();
        Box::pin(run_connection(state, service))
    }
}

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

//! Accept admission, TLS-before-HTTP, Hyper connection driving and graceful shutdown.
//!
//! Responsible for: the runtime state machine around one generic tower service.
//! NOT responsible for: S3 semantics, host handling, request-body intervals or handler deadlines.
//! Upstream: `ServerConfig`, optional `TlsHandle`, and a tower service. Downstream: sockets.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use pin_project_lite::pin_project;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;
use tower_http::catch_panic::CatchPanic;

use crate::config::{ConfigError, ServerConfig, WriteStrategy};
use crate::io::{BoxTransport, ProgressIo, deadline_after, deadline_remaining};
use crate::listener::Listener;
use crate::shutdown::{MetricsInner, RunningServer, ServerMetrics, ShutdownCommand, ShutdownReport, ShutdownTrigger};
use crate::tls::TlsHandle;

#[path = "request_capacity.rs"]
mod request_capacity;
use request_capacity::{RequestCapacity, RequestPermitBody};

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only synchronization failures terminate the scenario; no value comes from external input.
mod deadline_test;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Generic HTTP server runtime for a cloneable tower service.
pub struct Server<S> {
    config: ServerConfig,
    service: S,
    tls: Option<TlsHandle>,
    #[cfg(test)]
    deadline_observer: Option<deadline_test::DeadlineArmObserver>,
}

/// Transport facts observed at accept and inserted into every request's extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    peer_addr: SocketAddr,
    transport: TransportKind,
    tcp_nodelay: bool,
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

impl<S> Server<S> {
    /// Creates an unstarted server. TLS remains required unless `config.plaintext` is true.
    #[must_use]
    pub fn new(config: ServerConfig, service: S) -> Self {
        Self {
            config,
            service,
            tls: None,
            #[cfg(test)]
            deadline_observer: None,
        }
    }

    /// Installs the atomically reloadable TLS handle used by new connections.
    #[must_use]
    pub fn with_tls(mut self, tls: TlsHandle) -> Self {
        self.tls = Some(tls);
        self
    }

    #[cfg(test)]
    fn observe_deadline_arm(mut self, observer: deadline_test::DeadlineArmObserver) -> Self {
        self.deadline_observer = Some(observer);
        self
    }
}

impl<S, B> Server<S>
where
    S: TowerService<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    /// Binds the listener and starts the accept loop on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] for invalid configuration or listener setup failure. No task is
    /// spawned after either failure.
    pub fn serve(self) -> Result<RunningServer, ServerError> {
        self.config.validate(self.tls.is_some())?;
        let listener = Listener::bind(&self.config)?;
        let local_addr = listener.local_addr()?;
        let listener = listener.into_tokio()?;
        let metrics = ServerMetrics::default();
        let (command_sender, command_receiver) = oneshot::channel();
        let task_metrics = metrics.clone();
        let task = tokio::spawn(run_server(
            listener,
            self.config,
            self.service,
            self.tls,
            task_metrics,
            #[cfg(test)]
            self.deadline_observer,
            command_receiver,
        ));
        Ok(RunningServer {
            local_addr,
            task,
            shutdown: ShutdownTrigger { sender: command_sender },
            metrics,
        })
    }
}

/// Server startup or listener error.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Configuration would weaken a transport invariant or contains an invalid bound.
    #[error("server configuration is invalid")]
    Config(#[from] ConfigError),
    /// Listener setup or accept failed.
    #[error("server I/O failed")]
    Io(#[from] std::io::Error),
}

async fn run_server<S, B>(
    listener: tokio::net::TcpListener,
    config: ServerConfig,
    service: S,
    tls: Option<TlsHandle>,
    metrics: ServerMetrics,
    #[cfg(test)] deadline_observer: Option<deadline_test::DeadlineArmObserver>,
    command_receiver: oneshot::Receiver<ShutdownCommand>,
) -> Result<(), ServerError>
where
    S: TowerService<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let (request_capacity, mut request_capacity_receiver) = RequestCapacity::new(config.max_global_inflight_requests);
    let ip_counts = Arc::new(IpCounts::new(config.max_connections_per_ip));
    let request_stats = Arc::new(RequestStats::default());
    let (shutdown_sender, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut command_receiver = Some(command_receiver);

    let command = 'server: loop {
        let permit = if let Some(receiver) = &mut command_receiver {
            tokio::select! {
                command = receiver => match command {
                    Ok(command) => break Some(command),
                    Err(_) => {
                        command_receiver = None;
                        continue;
                    }
                },
                permit = Arc::clone(&semaphore).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break None,
                },
            }
        } else {
            match Arc::clone(&semaphore).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break None,
            }
        };
        while *request_capacity_receiver.borrow_and_update() == 0 {
            if let Some(receiver) = &mut command_receiver {
                tokio::select! {
                    command = receiver => match command {
                        Ok(command) => {
                            drop(permit);
                            break 'server Some(command);
                        }
                        Err(_) => {
                            command_receiver = None;
                            continue;
                        }
                    },
                    changed = request_capacity_receiver.changed() => {
                        if changed.is_err() {
                            drop(permit);
                            break 'server None;
                        }
                    },
                }
            } else if request_capacity_receiver.changed().await.is_err() {
                drop(permit);
                break 'server None;
            }
        }
        let accepted = if let Some(receiver) = &mut command_receiver {
            tokio::select! {
                biased;
                command = receiver => match command {
                    Ok(command) => {
                        drop(permit);
                        break Some(command);
                    }
                    Err(_) => {
                        command_receiver = None;
                        drop(permit);
                        continue;
                    }
                },
                changed = request_capacity_receiver.changed() => {
                    if changed.is_err() {
                        drop(permit);
                        break None;
                    }
                    drop(permit);
                    continue;
                },
                accepted = listener.accept() => accepted?,
            }
        } else {
            tokio::select! {
                biased;
                changed = request_capacity_receiver.changed() => {
                    if changed.is_err() {
                        drop(permit);
                        break None;
                    }
                    drop(permit);
                    continue;
                },
                accepted = listener.accept() => accepted?,
            }
        };
        let (stream, peer) = accepted;
        let header_deadline = deadline_after(config.header_read_timeout);
        #[cfg(test)]
        let accepted_ordinal = metrics.inner.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        #[cfg(not(test))]
        metrics.inner.accepted.fetch_add(1, Ordering::Relaxed);
        let Some(ip_lease) = ip_counts.try_acquire(peer.ip()) else {
            metrics.inner.per_ip_rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            drop(permit);
            continue;
        };
        metrics.inner.active.fetch_add(1, Ordering::Relaxed);
        let active = ActiveConnection {
            metrics: Arc::clone(&metrics.inner),
            _permit: permit,
            _ip: ip_lease,
        };
        let connection_config = config.clone();
        let connection = run_connection(
            ConnectionState {
                stream,
                peer_addr: peer,
                config: connection_config.clone(),
                tls: tls.clone(),
                shutdown: shutdown_sender.subscribe(),
                request_stats: Arc::clone(&request_stats),
                request_capacity: Arc::clone(&request_capacity),
                header_deadline,
                #[cfg(test)]
                deadline_observer: deadline_observer
                    .as_ref()
                    .filter(|observer| observer.target_accepted() == accepted_ordinal)
                    .cloned(),
                _active: active,
            },
            service.clone(),
        );
        connections.spawn(async move {
            if let Some(lifetime) = connection_config.connection_lifetime {
                let _ = tokio::time::timeout(lifetime, connection).await;
            } else {
                connection.await;
            }
        });
    };

    drop(listener);
    let Some(command) = command else {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        return Ok(());
    };

    request_stats.shutting_down.store(true, Ordering::Release);
    let _ = shutdown_sender.send(true);
    let drained = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(command.grace, drained).await.is_err() {
        request_stats.force_abort.store(true, Ordering::Release);
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let report = ShutdownReport {
        drained: request_stats.drained.load(Ordering::Relaxed),
        aborted: request_stats.aborted.load(Ordering::Relaxed),
    };
    let _ = command.reply.send(report);
    Ok(())
}

struct ConnectionState {
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: ServerConfig,
    tls: Option<TlsHandle>,
    shutdown: watch::Receiver<bool>,
    request_stats: Arc<RequestStats>,
    request_capacity: Arc<RequestCapacity>,
    header_deadline: tokio::time::Instant,
    #[cfg(test)]
    deadline_observer: Option<deadline_test::DeadlineArmObserver>,
    _active: ActiveConnection,
}

async fn run_connection<S, B>(state: ConnectionState, service: S)
where
    S: TowerService<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let ConnectionState {
        stream,
        peer_addr,
        config,
        tls,
        mut shutdown,
        request_stats,
        request_capacity,
        header_deadline,
        #[cfg(test)]
        deadline_observer,
        _active,
    } = state;
    if stream.set_nodelay(config.tcp_nodelay).is_err() {
        return;
    }
    let Ok(tcp_nodelay) = stream.nodelay() else {
        return;
    };
    let (transport, transport_kind): (BoxTransport, TransportKind) = match tls {
        Some(tls) => {
            let acceptor = TlsAcceptor::from(tls.begin_handshake());
            let accepted = tokio::select! {
                result = tokio::time::timeout_at(header_deadline, acceptor.accept(stream)) => match result {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::debug!("TLS handshake exceeded the accept-to-header deadline");
                        return;
                    }
                },
                changed = shutdown.changed() => {
                    let _ = changed;
                    return;
                }
            };
            match accepted {
                Ok(stream) => (Box::new(stream), TransportKind::Tls),
                Err(error) => {
                    tracing::debug!(error = %error, "TLS handshake failed");
                    return;
                }
            }
        }
        None => (Box::new(stream), TransportKind::Plaintext),
    };

    let per_connection = Arc::new(AtomicUsize::new(0));
    let request_seen = Arc::new(AtomicBool::new(false));
    let io = ProgressIo::new(
        transport,
        Arc::clone(&per_connection),
        Arc::clone(&request_seen),
        header_deadline,
        config.keep_alive_idle,
        config.write_progress_timeout,
    );
    #[cfg(test)]
    let io = match &deadline_observer {
        Some(observer) => io.observe_header_pending(observer.progress_callback()),
        None => io,
    };
    let io = TokioIo::new(io);
    let tracked = TrackedService::new(CatchPanic::new(service), request_stats, per_connection);
    let service = TowerToHyper {
        inner: tracked,
        connection: ConnectionInfo {
            peer_addr,
            transport: transport_kind,
            tcp_nodelay,
        },
        request_seen,
        request_capacity,
    };
    let mut builder = auto::Builder::new(TokioExecutor::new());
    #[cfg(test)]
    match &deadline_observer {
        Some(observer) => {
            builder
                .http1()
                .timer(deadline_test::ObservedTimer::new(observer.hyper_pending()));
        }
        None => {
            builder.http1().timer(TokioTimer::new());
        }
    }
    #[cfg(not(test))]
    builder.http1().timer(TokioTimer::new());
    builder
        .http1()
        .header_read_timeout(deadline_remaining(header_deadline))
        .max_buf_size(config.h1_max_buf_size)
        .keep_alive(config.h1_keep_alive)
        .pipeline_flush(config.h1_pipeline_flush);
    match config.write_strategy {
        WriteStrategy::Auto => {}
        WriteStrategy::Enabled => {
            builder.http1().writev(true);
        }
        WriteStrategy::Disabled => {
            builder.http1().writev(false);
        }
    }
    builder
        .http2()
        .timer(TokioTimer::new())
        .initial_stream_window_size(config.h2_initial_stream_window_size)
        .initial_connection_window_size(config.h2_initial_connection_window_size)
        .max_concurrent_streams(config.h2_max_concurrent_streams)
        .max_frame_size(config.h2_max_frame_size)
        .keep_alive_interval(config.h2_keep_alive_interval)
        .keep_alive_timeout(config.h2_keep_alive_timeout)
        .max_header_list_size(config.h2_max_header_list_size);

    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => log_connection_result(result),
        changed = shutdown.changed() => {
            let _ = changed;
            connection.as_mut().graceful_shutdown();
            log_connection_result(connection.await);
        }
    }
}

fn log_connection_result(result: Result<(), BoxError>) {
    if let Err(error) = result {
        tracing::debug!(error = %error, "HTTP connection closed with an error");
    }
}

#[derive(Clone)]
struct TowerToHyper<S> {
    inner: S,
    connection: ConnectionInfo,
    request_seen: Arc<AtomicBool>,
    request_capacity: Arc<RequestCapacity>,
}

impl<S, RequestBody, ResponseBody> hyper::service::Service<Request<RequestBody>> for TowerToHyper<S>
where
    S: TowerService<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + Send + 'static,
    RequestBody: Send + 'static,
    ResponseBody: Body + Send + 'static,
{
    type Response = Response<RequestPermitBody<ResponseBody>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut request: Request<RequestBody>) -> Self::Future {
        self.request_seen.store(true, Ordering::Release);
        request.extensions_mut().insert(self.connection);
        let mut service = self.inner.clone();
        let request_capacity = Arc::clone(&self.request_capacity);
        Box::pin(async move {
            let permit = request_capacity
                .acquire()
                .await
                .map_err(|error| Box::new(error) as BoxError)?;
            poll_fn(|context| service.poll_ready(context)).await.map_err(Into::into)?;
            let response = service.call(request).await.map_err(Into::into)?;
            Ok(response.map(|body| RequestPermitBody::new(body, permit)))
        })
    }
}

#[derive(Default)]
struct RequestStats {
    shutting_down: AtomicBool,
    force_abort: AtomicBool,
    drained: AtomicUsize,
    aborted: AtomicUsize,
}

#[derive(Clone)]
struct TrackedService<S> {
    inner: S,
    stats: Arc<RequestStats>,
    connection_in_flight: Arc<AtomicUsize>,
}

impl<S> TrackedService<S> {
    fn new(inner: S, stats: Arc<RequestStats>, connection_in_flight: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            stats,
            connection_in_flight,
        }
    }
}

impl<S, R, B> TowerService<R> for TrackedService<S>
where
    S: TowerService<R, Response = Response<B>>,
{
    type Response = Response<TrackedBody<B>>;
    type Error = S::Error;
    type Future = TrackedFuture<S::Future>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: R) -> Self::Future {
        self.connection_in_flight.fetch_add(1, Ordering::Relaxed);
        TrackedFuture {
            future: self.inner.call(request),
            guard: Some(RequestGuard {
                stats: Arc::clone(&self.stats),
                connection_in_flight: Arc::clone(&self.connection_in_flight),
                completed: false,
            }),
        }
    }
}

pin_project! {
    struct TrackedFuture<F> {
        #[pin]
        future: F,
        guard: Option<RequestGuard>,
    }
}

impl<F, B, E> Future for TrackedFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<TrackedBody<B>>, E>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        match ready!(this.future.as_mut().poll(context)) {
            Ok(response) => {
                let guard = this.guard.take();
                Poll::Ready(Ok(response.map(|body| TrackedBody { body, guard })))
            }
            Err(error) => {
                if let Some(mut guard) = this.guard.take() {
                    guard.complete();
                }
                Poll::Ready(Err(error))
            }
        }
    }
}

pin_project! {
    struct TrackedBody<B> {
        #[pin]
        body: B,
        guard: Option<RequestGuard>,
    }
}

impl<B: Body> Body for TrackedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let frame = ready!(this.body.as_mut().poll_frame(context));
        if (frame.is_none() || this.body.is_end_stream())
            && let Some(mut guard) = this.guard.take()
        {
            guard.complete();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

struct RequestGuard {
    stats: Arc<RequestStats>,
    connection_in_flight: Arc<AtomicUsize>,
    completed: bool,
}

impl RequestGuard {
    fn complete(&mut self) {
        self.completed = true;
        self.connection_in_flight.fetch_sub(1, Ordering::Relaxed);
        if self.stats.shutting_down.load(Ordering::Acquire) {
            self.stats.drained.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.connection_in_flight.fetch_sub(1, Ordering::Relaxed);
        if self.stats.force_abort.load(Ordering::Acquire) {
            self.stats.aborted.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct IpCounts {
    limit: Option<usize>,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl IpCounts {
    fn new(limit: Option<usize>) -> Self {
        Self {
            limit,
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<IpLease> {
        let Some(limit) = self.limit else {
            return Some(IpLease { ip, counts: None });
        };
        let mut counts = lock_recover(&self.counts);
        let count = counts.entry(ip).or_default();
        if *count >= limit {
            return None;
        }
        *count = count.saturating_add(1);
        Some(IpLease {
            ip,
            counts: Some(Arc::clone(&self.counts)),
        })
    }
}

struct IpLease {
    ip: IpAddr,
    counts: Option<Arc<Mutex<HashMap<IpAddr, usize>>>>,
}

impl Drop for IpLease {
    fn drop(&mut self) {
        let Some(counts) = &self.counts else { return };
        let mut counts = lock_recover(counts);
        let remove = if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove {
            counts.remove(&self.ip);
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct ActiveConnection {
    metrics: Arc<MetricsInner>,
    _permit: OwnedSemaphorePermit,
    _ip: IpLease,
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
    }
}

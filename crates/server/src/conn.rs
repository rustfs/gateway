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
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::Service as TowerService;

use crate::config::{ConfigError, ServerConfig, WriteStrategy};
use crate::connection_service::{ConnectionError, ConnectionService, RequestStats};
use crate::driver::{AcceptedConnection, ConnectionDriver, ConnectionInfo, HyperConnectionDriver, TransportKind};
use crate::io::{BoxTransport, ProgressIo, deadline_after, deadline_remaining};
use crate::listener::Listener;
use crate::shutdown::{MetricsInner, RunningServer, ServerMetrics, ShutdownCommand, ShutdownReport, ShutdownTrigger};
use crate::tls::TlsHandle;

use crate::request_capacity::RequestCapacity;

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only synchronization failures terminate the scenario; no value comes from external input.
mod deadline_test;

pub(crate) type BoxError = ConnectionError;

/// Generic HTTP server runtime for a cloneable tower service.
pub struct Server<S> {
    config: ServerConfig,
    service: S,
    tls: Option<TlsHandle>,
    #[cfg(test)]
    deadline_observer: Option<deadline_test::DeadlineArmObserver>,
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
        self.serve_with(HyperConnectionDriver)
    }
}

impl<S> Server<S>
where
    S: Clone + Send + 'static,
{
    /// Binds the listener and starts it with one explicit driver for every accepted connection.
    ///
    /// The driver is selected once for this server. Each returned driver future owns its
    /// connection admission permit until that future exits.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] for invalid configuration or listener setup failure. No task is
    /// spawned after either failure.
    pub fn serve_with<D>(self, driver: D) -> Result<RunningServer, ServerError>
    where
        D: ConnectionDriver<S>,
    {
        self.config.validate(self.tls.is_some())?;
        driver
            .validate(&self.config, self.tls.is_some())
            .map_err(ServerError::Driver)?;
        let listener = Listener::bind(&self.config)?;
        let local_addr = listener.local_addr()?;
        let listener = listener.into_tokio()?;
        let metrics = ServerMetrics::default();
        let (command_sender, command_receiver) = oneshot::channel();
        let task_metrics = metrics.clone();
        let task = tokio::spawn(run_server(
            listener,
            ServerTask {
                config: self.config,
                service: self.service,
                tls: self.tls,
                driver,
                metrics: task_metrics,
                #[cfg(test)]
                deadline_observer: self.deadline_observer,
            },
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
    /// The selected connection driver cannot honor the listener transport.
    #[error("connection driver rejected the server configuration")]
    Driver(#[source] crate::driver::DriverValidationError),
    /// Listener setup or accept failed.
    #[error("server I/O failed")]
    Io(#[from] std::io::Error),
}

struct ServerTask<S, D> {
    config: ServerConfig,
    service: S,
    tls: Option<TlsHandle>,
    driver: D,
    metrics: ServerMetrics,
    #[cfg(test)]
    deadline_observer: Option<deadline_test::DeadlineArmObserver>,
}

async fn run_server<S, D>(
    listener: tokio::net::TcpListener,
    task: ServerTask<S, D>,
    command_receiver: oneshot::Receiver<ShutdownCommand>,
) -> Result<(), ServerError>
where
    S: Clone + Send + 'static,
    D: ConnectionDriver<S>,
{
    let ServerTask {
        config,
        service,
        tls,
        driver,
        metrics,
        #[cfg(test)]
        deadline_observer,
    } = task;
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
        if stream.set_nodelay(config.tcp_nodelay).is_err() {
            drop(stream);
            drop(permit);
            continue;
        }
        let Ok(tcp_nodelay) = stream.nodelay() else {
            drop(stream);
            drop(permit);
            continue;
        };
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
        let connection_in_flight = Arc::new(AtomicUsize::new(0));
        let request_seen = Arc::new(AtomicBool::new(false));
        let request_body_unfinished = Arc::new(AtomicBool::new(false));
        let connection = driver.clone().drive(AcceptedConnection::new(
            ConnectionState {
                stream,
                peer_addr: peer,
                tcp_nodelay,
                config: connection_config.clone(),
                tls: tls.clone(),
                shutdown: shutdown_sender.subscribe(),
                request_stats: Arc::clone(&request_stats),
                request_capacity: Arc::clone(&request_capacity),
                connection_in_flight,
                request_seen,
                request_body_unfinished,
                header_deadline,
                metrics: Arc::clone(&metrics.inner),
                #[cfg(test)]
                deadline_observer: deadline_observer
                    .as_ref()
                    .filter(|observer| observer.target_accepted() == accepted_ordinal)
                    .cloned(),
            },
            service.clone(),
        ));
        connections.spawn(async move {
            let _active = active;
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

    request_stats.begin_shutdown();
    let _ = shutdown_sender.send(true);
    let drained = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(command.grace, drained).await.is_err() {
        request_stats.force_abort();
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let report = ShutdownReport {
        drained: request_stats.drained(),
        aborted: request_stats.aborted(),
    };
    let _ = command.reply.send(report);
    Ok(())
}

pub(crate) struct ConnectionState {
    pub(crate) stream: TcpStream,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) tcp_nodelay: bool,
    pub(crate) config: ServerConfig,
    pub(crate) tls: Option<TlsHandle>,
    pub(crate) shutdown: watch::Receiver<bool>,
    pub(crate) request_stats: Arc<RequestStats>,
    pub(crate) request_capacity: Arc<RequestCapacity>,
    pub(crate) connection_in_flight: Arc<AtomicUsize>,
    pub(crate) request_seen: Arc<AtomicBool>,
    pub(crate) request_body_unfinished: Arc<AtomicBool>,
    pub(crate) header_deadline: tokio::time::Instant,
    /// The listener's counters, so the lingering drain can report the octets it discards.
    pub(crate) metrics: Arc<MetricsInner>,
    #[cfg(test)]
    deadline_observer: Option<deadline_test::DeadlineArmObserver>,
}

pub(crate) async fn run_connection<S, B>(state: ConnectionState, service: S)
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
        tcp_nodelay,
        config,
        tls,
        mut shutdown,
        request_stats,
        request_capacity,
        connection_in_flight,
        request_seen,
        request_body_unfinished,
        header_deadline,
        metrics,
        #[cfg(test)]
        deadline_observer,
    } = state;
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

    let io = ProgressIo::new(
        transport,
        Arc::clone(&connection_in_flight),
        Arc::clone(&request_seen),
        header_deadline,
        config.keep_alive_idle,
        config.write_progress_timeout,
        config.lingering_close_time,
    )
    .request_body_unfinished(Arc::clone(&request_body_unfinished))
    .count_octets_into(Arc::clone(&metrics.transport_read), Arc::clone(&metrics.lingering_drained));
    #[cfg(test)]
    let io = match &deadline_observer {
        Some(observer) => io.observe_header_pending(observer.progress_callback()),
        None => io,
    };
    let io = TokioIo::new(io);
    let service = ConnectionService::new(
        service,
        ConnectionInfo {
            peer_addr,
            transport: transport_kind,
            tcp_nodelay,
        },
        request_seen,
        request_capacity,
        request_stats,
        connection_in_flight,
        request_body_unfinished,
    );
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

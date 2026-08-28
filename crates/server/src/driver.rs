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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tower::Service as TowerService;

use crate::config::ServerConfig;
use crate::conn::{BoxError, ConnectionState, run_connection};
use crate::connection_service::ConnectionService;

/// An owned connection-driver task.
pub type ConnectionFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Drives one accepted connection with one clone of the configured service.
///
/// A server selects the driver once for the listener. The returned future owns the connection
/// until it completes; connection admission is not released before then.
pub trait ConnectionDriver<S>: Clone + Send + 'static {
    /// Starts driving one accepted connection.
    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture;
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
    pub fn into_plaintext(self) -> Result<(TcpStream, ConnectionService<S>), PlaintextTakeoverError> {
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
        );
        Ok((self.state.stream, service))
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

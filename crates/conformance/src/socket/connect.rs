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

//! Deadline-aware client connection setup.
//!
//! Responsible for: opening plain and TLS client sockets, including bounded TCP connect and eager
//! TLS handshake variants for external endpoints. NOT responsible for: DNS resolution, HTTP
//! framing, or response deadlines. Upstream: `crate::conn`; downstream: `super::stream` and
//! `std::net::TcpStream`.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use super::Connection;
use super::stream::ConnectionStream;
use crate::sut::SutError;

impl Connection {
    /// Opens a plain connection before an absolute setup deadline.
    pub(crate) fn open_before(addr: SocketAddr, deadline: Instant) -> Result<Connection, SutError> {
        let socket = connect_before(addr, deadline)?;
        Ok(Self::plain(socket))
    }

    /// Opens a certificate-verified TLS connection to a listener.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when TCP setup or TLS client construction fails. The
    /// handshake is driven by the first read or write, and any failure remains an environment
    /// error rather than a conformance finding.
    pub fn open_tls(
        addr: SocketAddr,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> Result<Connection, SutError> {
        let socket = TcpStream::connect(addr).map_err(|error| SutError::Environment(format!("cannot connect: {error}")))?;
        Self::tls(socket, server_name, config)
    }

    /// Opens TCP and completes certificate-verified TLS before an absolute setup deadline.
    pub(crate) fn open_tls_before(
        addr: SocketAddr,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
        deadline: Instant,
    ) -> Result<Connection, SutError> {
        let socket = connect_before(addr, deadline)?;
        let mut connection = Self::tls(socket, server_name, config)?;
        connection.stream.complete_tls_handshake_before(deadline).map_err(|error| {
            if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) || Instant::now() >= deadline {
                SutError::Environment(format!("external TLS handshake exceeded the setup deadline: {error}"))
            } else {
                SutError::Environment(format!("external TLS handshake failed: {error}"))
            }
        })?;
        Ok(connection)
    }

    fn plain(socket: TcpStream) -> Self {
        Self {
            stream: ConnectionStream::Plain(socket),
            body_written: 0,
            torn_down: false,
        }
    }

    fn tls(socket: TcpStream, server_name: ServerName<'static>, config: Arc<ClientConfig>) -> Result<Self, SutError> {
        let stream = ConnectionStream::tls(socket, server_name, config)
            .map_err(|error| SutError::Environment(format!("cannot configure TLS connection: {error}")))?;
        Ok(Self {
            stream,
            body_written: 0,
            torn_down: false,
        })
    }
}

fn connect_before(addr: SocketAddr, deadline: Instant) -> Result<TcpStream, SutError> {
    connect_before_with(addr, deadline, TcpStream::connect_timeout)
}

fn connect_before_with<C>(addr: SocketAddr, deadline: Instant, connector: C) -> Result<TcpStream, SutError>
where
    C: FnOnce(&SocketAddr, Duration) -> std::io::Result<TcpStream>,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| SutError::Environment("external endpoint setup deadline expired before TCP connect".to_owned()))?;
    connector(&addr, remaining).map_err(|error| {
        SutError::Environment(format!("cannot connect to external address `{addr}` before setup deadline: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn tcp_connector_receives_only_the_remaining_absolute_budget() {
        let address = SocketAddr::from(([192, 0, 2, 1], 443));
        let budget = Duration::from_millis(50);
        let deadline = Instant::now() + budget;
        let mut observed = None;

        let error = connect_before_with(address, deadline, |received_address, timeout| {
            observed = Some((*received_address, timeout));
            Err(std::io::Error::new(ErrorKind::TimedOut, "scripted timeout"))
        })
        .expect_err("scripted connector times out");
        let (received_address, timeout) = observed.expect("connector was invoked");

        assert_eq!(received_address, address);
        assert!(!timeout.is_zero());
        assert!(timeout <= budget, "connector received more than the absolute budget: {timeout:?}");
        assert!(error.to_string().contains("before setup deadline"));
    }

    #[test]
    fn an_expired_tcp_deadline_starts_no_connection_attempt() {
        let address = SocketAddr::from(([192, 0, 2, 1], 443));
        let mut called = false;

        let error = connect_before_with(address, Instant::now(), |_, _| {
            called = true;
            Err(std::io::Error::other("must not run"))
        })
        .expect_err("expired setup deadline");

        assert!(!called);
        assert!(error.to_string().contains("expired before TCP connect"));
    }

    #[test]
    fn the_production_entry_point_honours_an_expired_deadline_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind connection observer");
        listener.set_nonblocking(true).expect("nonblocking accept");
        let address = listener.local_addr().expect("listener address");

        let error = match Connection::open_before(address, Instant::now()) {
            Ok(_) => panic!("an expired setup deadline must open no production connection"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("expired before TCP connect"));
        match listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => panic!("unexpected accept error: {error}"),
            Ok(_) => panic!("production connect ignored the expired setup deadline"),
        }
    }
}

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

//! Socket2 listener construction and read-back observations.
//!
//! Responsible for: applying address-family, keepalive, buffer, backlog and reuse settings before accept.
//! NOT responsible for: connection admission, TLS or protocol handling.
//! Upstream: `ServerConfig`. Downstream: Tokio's accept loop.

use std::io;
use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};

use crate::ServerConfig;

/// Applied listener options observed with `getsockopt` before conversion to Tokio.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerOptions {
    /// Whether address reuse is active.
    pub reuse_address: bool,
    /// Whether TCP keepalive is active.
    pub keepalive: bool,
    /// Whether Nagle coalescing is disabled on accepted sockets.
    pub tcp_nodelay: bool,
    /// Kernel-reported receive-buffer bytes.
    pub recv_buffer_size: usize,
    /// Kernel-reported send-buffer bytes.
    pub send_buffer_size: usize,
    /// Whether the IPv6 socket is restricted to IPv6.
    pub only_v6: Option<bool>,
}

/// A configured nonblocking TCP listener ready for Tokio.
pub struct Listener {
    inner: TcpListener,
    options: ListenerOptions,
}

impl Listener {
    /// Creates, configures, binds and starts a socket2 listener.
    ///
    /// # Errors
    ///
    /// Returns the first operating-system socket error, or `InvalidInput` for an oversized backlog.
    pub fn bind(config: &ServerConfig) -> io::Result<Self> {
        let domain = Domain::for_address(config.bind_addr);
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(config.reuse_address)?;
        if config.bind_addr.is_ipv6() {
            socket.set_only_v6(!config.dual_stack)?;
        }
        if let Some(size) = config.so_rcvbuf {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = config.so_sndbuf {
            socket.set_send_buffer_size(size)?;
        }
        if let Some(interval) = config.tcp_keepalive {
            socket.set_keepalive(true)?;
            socket.set_tcp_keepalive(&TcpKeepalive::new().with_time(interval).with_interval(interval))?;
        } else {
            socket.set_keepalive(false)?;
        }
        socket.set_tcp_nodelay(config.tcp_nodelay)?;
        socket.bind(&config.bind_addr.into())?;
        let backlog = i32::try_from(config.backlog)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "listener backlog exceeds i32"))?;
        socket.listen(backlog)?;

        let options = ListenerOptions {
            reuse_address: socket.reuse_address()?,
            keepalive: socket.keepalive()?,
            tcp_nodelay: socket.tcp_nodelay()?,
            recv_buffer_size: socket.recv_buffer_size()?,
            send_buffer_size: socket.send_buffer_size()?,
            only_v6: if config.bind_addr.is_ipv6() {
                Some(socket.only_v6()?)
            } else {
                None
            },
        };
        let inner: TcpListener = socket.into();
        inner.set_nonblocking(true)?;
        Ok(Self { inner, options })
    }

    /// Returns the kernel-selected local address.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if the socket address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the socket options observed after configuration.
    #[must_use]
    pub const fn options(&self) -> ListenerOptions {
        self.options
    }

    pub(crate) fn into_tokio(self) -> io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::from_std(self.inner)
    }
}

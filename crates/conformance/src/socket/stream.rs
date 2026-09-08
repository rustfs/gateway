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

//! The client transport underneath one connection: a plain socket, or a TLS session over one.
//!
//! Responsible for: carrying authored bytes in both directions and keeping the socket underneath
//! reachable, so connection-state observation stays a fact about the wire. NOT responsible for:
//! HTTP framing, trust configuration, or judging an observation — the TLS half moves opaque
//! records and never rewrites the bytes a case authored. Upstream: `super::Connection`.
//! Downstream: `std::net::TcpStream` and `rustls`.

use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

/// Which transport one [`super::Connection`] writes through.
pub(super) enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl ConnectionStream {
    /// Wraps an already-connected socket in a client TLS session.
    ///
    /// # Errors
    ///
    /// Returns the rustls error when the session cannot be constructed. No handshake runs here:
    /// it is driven by the first read or write, so a rejected certificate surfaces at the exchange.
    pub(super) fn tls(
        socket: TcpStream,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> Result<Self, rustls::Error> {
        let client = ClientConnection::new(config, server_name)?;
        Ok(Self::Tls(Box::new(StreamOwned::new(client, socket))))
    }

    /// Completes a TLS handshake without allowing any I/O step to outlive `deadline`.
    pub(super) fn complete_tls_handshake_before(&mut self, deadline: Instant) -> std::io::Result<()> {
        let Self::Tls(stream) = self else {
            return Ok(());
        };
        let handshake: std::io::Result<()> = (|| {
            while stream.conn.is_handshaking() || stream.conn.wants_write() {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|duration| !duration.is_zero())
                    .ok_or_else(|| Error::new(ErrorKind::TimedOut, "external TLS setup deadline expired"))?;
                if stream.conn.wants_write() {
                    stream.sock.set_write_timeout(Some(remaining))?;
                    if stream.conn.write_tls(&mut stream.sock)? == 0 {
                        return Err(Error::new(ErrorKind::WriteZero, "TLS handshake write made no progress"));
                    }
                    continue;
                }
                if stream.conn.wants_read() {
                    stream.sock.set_read_timeout(Some(remaining))?;
                    if stream.conn.read_tls(&mut stream.sock)? == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "TLS peer closed during handshake"));
                    }
                    stream
                        .conn
                        .process_new_packets()
                        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
                    continue;
                }
                return Err(Error::new(ErrorKind::InvalidData, "TLS handshake requested no socket progress"));
            }
            if Instant::now() >= deadline {
                return Err(Error::new(ErrorKind::TimedOut, "external TLS setup deadline expired"));
            }
            Ok(())
        })();
        let clear_read = stream.sock.set_read_timeout(None);
        let clear_write = stream.sock.set_write_timeout(None);
        handshake?;
        clear_read?;
        clear_write
    }

    /// The socket underneath either half, so close and reuse stay observed on the real wire.
    pub(super) fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        }
    }
}

impl Read for ConnectionStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(bytes),
            Self::Tls(stream) => stream.read(bytes),
        }
    }
}

impl Write for ConnectionStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(bytes),
            Self::Tls(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

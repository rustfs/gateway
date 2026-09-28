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

//! `[connection.tls]` for an authored HTTP/2 script against the production Hyper listener.
//! Responsible for: reading `enabled` and `alpn`, refusing by name the TLS fields this transport
//! does not apply, starting the case's TLS listener, and opening a verified TLS session that must
//! have negotiated `h2` before a frame is written.
//! NOT responsible for: writing or reading frames (`super::duplex`), or external https endpoints
//! (`crate::conn::external_tls`).
//! Upstream: `crate::conn::Conn::exchange`. Downstream: `crate::production::ProductionServer`.

#[cfg(feature = "production-transports")]
use std::sync::Arc;
#[cfg(feature = "production-transports")]
use std::time::Instant;

#[cfg(feature = "production-transports")]
use rustls::pki_types::ServerName;

use super::{Conn, SutError, refused};
#[cfg(feature = "production-transports")]
use crate::socket::Connection;
use crate::value::Value;

/// What a case's `[connection.tls]` asks of the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::conn) struct TlsRequest {
    /// The ALPN protocols offered, in order; `h2` when the case lists none.
    alpn: Vec<Vec<u8>>,
}

/// Separates `[connection.tls]` from the rest of `[connection]`: the TLS request when enabled, and
/// the remaining block for the ordinary connection reader.
pub(in crate::conn) fn split_tls(connection: Option<&Value>) -> Result<(Option<Value>, Option<TlsRequest>), SutError> {
    let Some(connection) = connection else { return Ok((None, None)) };
    let Some(tls) = connection.read("connection.tls") else {
        return Ok((Some(connection.clone()), None));
    };
    for field in ["sni", "min_version", "close_notify"] {
        let present = match field {
            "sni" => tls.read("connection.tls.sni").is_some(),
            "min_version" => tls.read("connection.tls.min_version").is_some(),
            _ => tls.read("connection.tls.close_notify").is_some(),
        };
        if present {
            return Err(refused(format!(
                "`connection.tls.{field}` is not applied by this transport: it offers `localhost` as the \
                 server name, lets rustls choose the version, and always ends a session cleanly"
            )));
        }
    }
    let enabled = tls.read("connection.tls.enabled").and_then(Value::as_bool).unwrap_or(true);
    let alpn = tls.read("connection.tls.alpn");
    let rest = Value::Table(
        connection
            .as_table()
            .unwrap_or_default()
            .iter()
            .filter(|(key, _)| key != "tls")
            .cloned()
            .collect(),
    );
    if !enabled {
        return Ok((Some(rest), None));
    }
    // An absent list offers `h2`, the protocol a frame script speaks; an empty one offers nothing.
    let alpn = match alpn.map(Value::as_array) {
        None => vec![b"h2".to_vec()],
        Some(Some(list)) => list
            .iter()
            .map(|protocol| protocol.as_str().map(|name| name.as_bytes().to_vec()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| refused("`connection.tls.alpn` is not a list of protocol names".to_owned()))?,
        Some(None) => return Err(refused("`connection.tls.alpn` is not a list of protocol names".to_owned())),
    };
    Ok((Some(rest), Some(TlsRequest { alpn })))
}

impl Conn {
    /// Opens a verified TLS session with this case's production TLS listener, starting it on
    /// first use, and refuses unless the listener selected `h2`.
    #[cfg(feature = "production-transports")]
    pub(super) fn open_h2_tls(
        &mut self,
        request: &TlsRequest,
        at_unix_seconds: i64,
        skew_ms: i64,
        profile: crate::sut::Profile,
        deadline: Instant,
    ) -> Result<Connection, SutError> {
        let (addr, certificate) = self.tls_listener(at_unix_seconds, skew_ms, profile)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate)
            .map_err(|error| refused(format!("the listener certificate is not a trust anchor: {error}")))?;
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols.clone_from(&request.alpn);
        let name =
            ServerName::try_from("localhost").map_err(|error| refused(format!("`localhost` is not a server name: {error}")))?;
        let connection = Connection::open_tls_before(addr, name, Arc::new(config), deadline)?;
        match connection.alpn_protocol() {
            Some(protocol) if protocol == b"h2" => Ok(connection),
            Some(protocol) => Err(refused(format!(
                "the listener selected ALPN `{}`, not `h2`; the authored frames were not written",
                String::from_utf8_lossy(&protocol)
            ))),
            None => Err(refused(
                "the listener selected no ALPN protocol, not `h2`; the authored frames were not written".to_owned(),
            )),
        }
    }

    #[cfg(feature = "production-transports")]
    fn tls_listener(
        &mut self,
        at_unix_seconds: i64,
        skew_ms: i64,
        profile: crate::sut::Profile,
    ) -> Result<(std::net::SocketAddr, rustls::pki_types::CertificateDer<'static>), SutError> {
        if self.production_tls.is_none() {
            let service = self.inner.assemble(at_unix_seconds, skew_ms, profile)?;
            self.production_tls = Some(crate::production::ProductionServer::start_tls(service)?);
        }
        let (server, certificate) = self
            .production_tls
            .as_ref()
            .ok_or_else(|| refused("the TLS production listener vanished after starting".to_owned()))?;
        Ok((server.addr()?, certificate.clone()))
    }
}

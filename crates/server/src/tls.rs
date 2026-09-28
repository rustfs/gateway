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

//! Fail-closed TLS configuration and atomic reload.
//!
//! Responsible for: validating certificate material, the ALPN protocols a listener advertises, and
//! swapping one config for new connections.
//! NOT responsible for: file watching, retry policy or changing established TLS sessions.
//! Upstream: operator-provided DER material. Downstream: the connection acceptor.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// The ALPN protocols a listener advertises unless configured otherwise, in server preference
/// order: HTTP/2 over TLS is identified only by `h2` (RFC 9113 section 3.2).
pub const DEFAULT_ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Owned DER certificate chain, private key and advertised ALPN protocols for one TLS configuration.
pub struct TlsMaterial {
    certificates: Vec<Vec<u8>>,
    private_key: Vec<u8>,
    alpn_protocols: Vec<Vec<u8>>,
}

impl TlsMaterial {
    /// Creates TLS material from a leaf-first certificate chain and one PKCS#8, PKCS#1 or SEC1 key.
    #[must_use]
    pub fn from_der(certificates: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        Self {
            certificates,
            private_key,
            alpn_protocols: DEFAULT_ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect(),
        }
    }

    /// Replaces the ALPN protocols the listener advertises, in preference order. A client that
    /// offers none of them fails the handshake with `no_application_protocol`; an empty list
    /// advertises nothing, and every connection is then served by prior knowledge.
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    fn into_config(self) -> Result<RustlsServerConfig, TlsReloadError> {
        if self.certificates.is_empty() {
            return Err(TlsReloadError::EmptyCertificateChain);
        }
        let certificates = self.certificates.into_iter().map(CertificateDer::from).collect();
        let private_key = PrivateKeyDer::try_from(self.private_key).map_err(|_| TlsReloadError::InvalidPrivateKey)?;
        let mut config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(TlsReloadError::InvalidMaterial)?;
        config.alpn_protocols = self.alpn_protocols;
        Ok(config)
    }
}

/// Atomically reloadable TLS configuration shared by server instances.
#[derive(Clone)]
pub struct TlsHandle {
    inner: Arc<ArcSwap<RustlsServerConfig>>,
    handshakes: Arc<AtomicUsize>,
}

impl TlsHandle {
    /// Builds the initial configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TlsReloadError`] if the certificate chain or key cannot build a Rustls config.
    pub fn new(material: TlsMaterial) -> Result<Self, TlsReloadError> {
        let config = material.into_config()?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
            handshakes: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Validates and installs material for future connections.
    ///
    /// A failed validation leaves the previous configuration installed. It never enables
    /// cleartext and never terminates the process.
    ///
    /// # Errors
    ///
    /// Returns [`TlsReloadError`] when the new certificate chain or key is invalid.
    pub fn reload(&self, material: TlsMaterial) -> Result<(), TlsReloadError> {
        match material.into_config() {
            Ok(config) => {
                self.inner.store(Arc::new(config));
                Ok(())
            }
            Err(error) => {
                tracing::error!(error = %error, "TLS reload rejected; the previous configuration remains active");
                Err(error)
            }
        }
    }

    /// Loads the one configuration a new connection must retain through its handshake.
    #[must_use]
    pub fn current(&self) -> Arc<RustlsServerConfig> {
        self.inner.load_full()
    }

    /// Returns the number of TLS handshakes started after admission.
    #[must_use]
    pub fn handshake_count(&self) -> usize {
        self.handshakes.load(Ordering::Relaxed)
    }

    pub(crate) fn begin_handshake(&self) -> Arc<RustlsServerConfig> {
        self.handshakes.fetch_add(1, Ordering::Relaxed);
        self.current()
    }
}

/// TLS material could not produce a server configuration.
#[derive(Debug, Error)]
pub enum TlsReloadError {
    /// No certificate was supplied.
    #[error("certificate chain is empty")]
    EmptyCertificateChain,
    /// The key was not recognized as PKCS#8, PKCS#1 or SEC1 DER.
    #[error("private key encoding is invalid")]
    InvalidPrivateKey,
    /// Rustls rejected the relation between the certificate chain and key.
    #[error("certificate material is invalid")]
    InvalidMaterial(#[source] rustls::Error),
}

/// The connection builder for the protocol ALPN negotiated: a negotiated protocol is the only one
/// the connection speaks, and without ALPN both remain available by prior knowledge.
pub(crate) fn protocol_builder(negotiated: Option<&[u8]>) -> auto::Builder<TokioExecutor> {
    let builder = auto::Builder::new(TokioExecutor::new());
    match negotiated {
        Some(b"h2") => builder.http2_only(),
        Some(b"http/1.1") => builder.http1_only(),
        _ => builder,
    }
}

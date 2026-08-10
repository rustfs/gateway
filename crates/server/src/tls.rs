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
//! Responsible for: validating certificate material and swapping one config for new connections.
//! NOT responsible for: file watching, retry policy or changing established TLS sessions.
//! Upstream: operator-provided DER material. Downstream: the connection acceptor.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// Owned DER certificate chain and private key for one TLS configuration.
pub struct TlsMaterial {
    certificates: Vec<Vec<u8>>,
    private_key: Vec<u8>,
}

impl TlsMaterial {
    /// Creates TLS material from a leaf-first certificate chain and one PKCS#8, PKCS#1 or SEC1 key.
    #[must_use]
    pub fn from_der(certificates: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        Self {
            certificates,
            private_key,
        }
    }

    fn into_config(self) -> Result<RustlsServerConfig, TlsReloadError> {
        if self.certificates.is_empty() {
            return Err(TlsReloadError::EmptyCertificateChain);
        }
        let certificates = self.certificates.into_iter().map(CertificateDer::from).collect();
        let private_key = PrivateKeyDer::try_from(self.private_key).map_err(|_| TlsReloadError::InvalidPrivateKey)?;
        RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(TlsReloadError::InvalidMaterial)
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

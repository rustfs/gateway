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
//! Responsible for: validating certificate material, zeroizing private key bytes on drop,
//! applying configurable TLS policy (minimum protocol version, cipher suites, client auth,
//! OCSP stapling, custom certificate resolvers, and custom Rustls configs), advertised ALPN
//! protocols, and swapping one config atomically for new connections.
//! NOT responsible for: file watching, retry policy or changing established TLS sessions.
//! Upstream: operator-provided DER material or Rustls configuration. Downstream: the connection acceptor.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use hyper_util::server::conn::auto;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::SupportedCipherSuite;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::server::danger::ClientCertVerifier;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::ServerConfig;
use crate::send_deadline::StreamExecutor;
use crate::task_tracker::TaskTracker;

/// The ALPN protocols a listener advertises unless configured otherwise, in server preference
/// order: HTTP/2 over TLS is identified only by `h2` (RFC 9113 section 3.2).
pub const DEFAULT_ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Minimum TLS protocol version accepted by the listener.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TlsMinVersion {
    /// Accept TLS 1.2 and TLS 1.3 (Rustls default).
    #[default]
    Tls12,
    /// Accept TLS 1.3 only, rejecting TLS 1.2 handshakes.
    Tls13,
}

enum CertificateSource {
    SingleCert {
        certificates: Vec<Vec<u8>>,
        private_key: Zeroizing<Vec<u8>>,
        ocsp_response: Option<Vec<u8>>,
    },
    Resolver(Arc<dyn ResolvesServerCert>),
}

/// Owned TLS certificate source, policy knobs, and advertised ALPN protocols for one TLS
/// configuration.
///
/// Private key bytes are held inside [`Zeroizing`] so they are scrubbed from memory on drop,
/// including when validation fails or the material is discarded.
pub struct TlsMaterial {
    source: CertificateSource,
    alpn_protocols: Vec<Vec<u8>>,
    min_version: TlsMinVersion,
    cipher_suites: Option<Vec<SupportedCipherSuite>>,
    crypto_provider: Option<Arc<CryptoProvider>>,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            CertificateSource::SingleCert {
                certificates,
                ocsp_response,
                ..
            } => format!("SingleCert(certificates={}, ocsp={})", certificates.len(), ocsp_response.is_some()),
            CertificateSource::Resolver(_) => "Resolver(<custom>)".to_owned(),
        };
        f.debug_struct("TlsMaterial")
            .field("source", &source)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("min_version", &self.min_version)
            .field("custom_cipher_suites", &self.cipher_suites.is_some())
            .field("custom_crypto_provider", &self.crypto_provider.is_some())
            .field("client_auth", &self.client_cert_verifier.is_some())
            .finish()
    }
}

impl TlsMaterial {
    /// Creates TLS material from a leaf-first certificate chain and one PKCS#8, PKCS#1 or SEC1 key.
    #[must_use]
    pub fn from_der(certificates: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        Self::from_der_zeroizing(certificates, Zeroizing::new(private_key))
    }

    /// Creates TLS material from a leaf-first certificate chain and a [`Zeroizing`] private key
    /// buffer so callers can preserve zeroization end-to-end.
    #[must_use]
    pub fn from_der_zeroizing(certificates: Vec<Vec<u8>>, private_key: Zeroizing<Vec<u8>>) -> Self {
        Self {
            source: CertificateSource::SingleCert {
                certificates,
                private_key,
                ocsp_response: None,
            },
            alpn_protocols: DEFAULT_ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect(),
            min_version: TlsMinVersion::default(),
            cipher_suites: None,
            crypto_provider: None,
            client_cert_verifier: None,
        }
    }

    /// Creates TLS material backed by a custom SNI / dynamic [`ResolvesServerCert`] implementation.
    #[must_use]
    pub fn from_cert_resolver(resolver: Arc<dyn ResolvesServerCert>) -> Self {
        Self {
            source: CertificateSource::Resolver(resolver),
            alpn_protocols: DEFAULT_ALPN_PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect(),
            min_version: TlsMinVersion::default(),
            cipher_suites: None,
            crypto_provider: None,
            client_cert_verifier: None,
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

    /// Sets the minimum TLS protocol version accepted during handshakes.
    #[must_use]
    pub fn with_min_version(mut self, min_version: TlsMinVersion) -> Self {
        self.min_version = min_version;
        self
    }

    /// Restricts the allowed TLS cipher suites. Supplying an empty list fails closed with
    /// [`TlsReloadError::EmptyCipherSuites`].
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: Vec<SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Installs a custom Rustls [`CryptoProvider`] for key exchange, signatures, and cipher suites.
    #[must_use]
    pub fn with_crypto_provider(mut self, provider: Arc<CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Enables mutual TLS (mTLS) by verifying client certificates with `verifier`.
    #[must_use]
    pub fn with_client_cert_verifier(mut self, verifier: Arc<dyn ClientCertVerifier>) -> Self {
        self.client_cert_verifier = Some(verifier);
        self
    }

    /// Attaches a DER-encoded OCSP stapling response when configured from a single certificate chain.
    #[must_use]
    pub fn with_ocsp_response(mut self, ocsp: Vec<u8>) -> Self {
        if let CertificateSource::SingleCert { ocsp_response, .. } = &mut self.source {
            *ocsp_response = Some(ocsp);
        }
        self
    }

    fn into_config(self) -> Result<RustlsServerConfig, TlsReloadError> {
        let versions: &[&'static rustls::SupportedProtocolVersion] = match self.min_version {
            TlsMinVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
            TlsMinVersion::Tls13 => &[&rustls::version::TLS13],
        };
        let provider = match (self.crypto_provider, self.cipher_suites) {
            (_, Some(suites)) if suites.is_empty() => return Err(TlsReloadError::EmptyCipherSuites),
            (Some(base), Some(suites)) => {
                let mut customized = (*base).clone();
                customized.cipher_suites = suites;
                Arc::new(customized)
            }
            (None, Some(suites)) => {
                let mut customized = rustls::crypto::ring::default_provider();
                customized.cipher_suites = suites;
                Arc::new(customized)
            }
            (Some(provider), None) => provider,
            (None, None) => Arc::new(rustls::crypto::ring::default_provider()),
        };

        let builder = RustlsServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(TlsReloadError::InvalidMaterial)?;
        let builder = match self.client_cert_verifier {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };

        let mut config = match self.source {
            CertificateSource::SingleCert {
                certificates,
                private_key,
                ocsp_response,
            } => {
                if certificates.is_empty() {
                    return Err(TlsReloadError::EmptyCertificateChain);
                }
                let certificates = certificates.into_iter().map(CertificateDer::from).collect();
                // Parse from borrowed slice so `private_key: Zeroizing<Vec<u8>>` always scrubs
                // its buffer on drop, including when key decoding fails.
                let parsed_key = PrivateKeyDer::try_from(private_key.as_slice())
                    .map(|key| key.clone_key())
                    .map_err(|_| TlsReloadError::InvalidPrivateKey)?;
                match ocsp_response {
                    Some(ocsp) => builder
                        .with_single_cert_with_ocsp(certificates, parsed_key, ocsp)
                        .map_err(TlsReloadError::InvalidMaterial)?,
                    None => builder
                        .with_single_cert(certificates, parsed_key)
                        .map_err(TlsReloadError::InvalidMaterial)?,
                }
            }
            CertificateSource::Resolver(resolver) => builder.with_cert_resolver(resolver),
        };
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
    /// Returns [`TlsReloadError`] if the certificate chain, key, or TLS policy cannot build a Rustls config.
    pub fn new(material: TlsMaterial) -> Result<Self, TlsReloadError> {
        let config = material.into_config()?;
        Ok(Self::from_server_config(config))
    }

    /// Creates a handle from an already constructed [`rustls::ServerConfig`].
    ///
    /// Use this when advanced Rustls controls (such as custom session storage, ticket keys, or
    /// custom resolvers) are constructed directly by the host.
    #[must_use]
    pub fn from_server_config(config: RustlsServerConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
            handshakes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Validates and installs material for future connections.
    ///
    /// A failed validation leaves the previous configuration installed. It never enables
    /// cleartext and never terminates the process.
    ///
    /// # Errors
    ///
    /// Returns [`TlsReloadError`] when the new certificate chain, key, or TLS policy is invalid.
    pub fn reload(&self, material: TlsMaterial) -> Result<(), TlsReloadError> {
        match material.into_config() {
            Ok(config) => {
                self.reload_server_config(config);
                Ok(())
            }
            Err(error) => {
                tracing::error!(error = %error, "TLS reload rejected; the previous configuration remains active");
                Err(error)
            }
        }
    }

    /// Atomically installs a pre-validated [`rustls::ServerConfig`] for future connections.
    pub fn reload_server_config(&self, config: RustlsServerConfig) {
        self.inner.store(Arc::new(config));
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
    /// The configured cipher-suite list contained no suites.
    #[error("cipher suite list must not be empty")]
    EmptyCipherSuites,
    /// Rustls rejected the certificate chain, key, or TLS policy combination.
    #[error("certificate material is invalid")]
    InvalidMaterial(#[source] rustls::Error),
}

/// The connection builder for the protocol ALPN negotiated: a negotiated protocol is the only one
/// the connection speaks. Without ALPN, both remain available by prior knowledge when
/// [`ServerConfig::h2_prior_knowledge`] allows it, and only HTTP/1.1 otherwise.
///
/// Every HTTP/2 stream runs under its send-progress deadline of
/// [`ServerConfig::write_progress_timeout`] (`crate::send_deadline`).
pub(crate) fn protocol_builder(
    negotiated: Option<&[u8]>,
    config: &ServerConfig,
    background_tasks: TaskTracker,
) -> auto::Builder<StreamExecutor> {
    let builder = auto::Builder::new(StreamExecutor::new(config.write_progress_timeout, background_tasks));
    match negotiated {
        Some(b"h2") => builder.http2_only(),
        Some(b"http/1.1") => builder.http1_only(),
        _ if config.h2_prior_knowledge => builder,
        _ => builder.http1_only(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Negative — private key bytes are stored in `Zeroizing` and never exposed in `Debug`.
    #[test]
    fn n_tls_material_holds_zeroizing_key_and_redacts_debug() {
        const SENTINEL: &[u8] = b"SECRET_KEY_MATERIAL_DO_NOT_LOG";
        let material = TlsMaterial::from_der(vec![vec![1, 2, 3]], SENTINEL.to_vec());
        let debug = format!("{material:?}");
        assert!(!debug.contains("SECRET_KEY_MATERIAL"), "Debug must redact private key: {debug}");
        let CertificateSource::SingleCert { private_key, .. } = &material.source else {
            panic!("expected single cert source");
        };
        let typed_check: &Zeroizing<Vec<u8>> = private_key;
        assert_eq!(typed_check.as_slice(), SENTINEL);
    }

    /// Negative — an empty cipher-suite list is rejected fail-closed.
    #[test]
    fn n_empty_cipher_suites_are_rejected() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("cert");
        let material = TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der())
            .with_cipher_suites(Vec::new());
        assert!(matches!(TlsHandle::new(material), Err(TlsReloadError::EmptyCipherSuites)));
    }

    /// Negative — TLS 1.3-only policy paired with only TLS 1.2 cipher suites fails closed.
    #[test]
    fn n_tls13_with_only_tls12_cipher_suites_is_rejected() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("cert");
        let tls12_only = vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let material = TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der())
            .with_min_version(TlsMinVersion::Tls13)
            .with_cipher_suites(tls12_only);
        assert!(matches!(TlsHandle::new(material), Err(TlsReloadError::InvalidMaterial(_))));
    }
}

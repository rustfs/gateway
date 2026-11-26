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

//! TLS hardening contracts: SNI multi-domain resolution, mTLS client-cert verification, and
//! custom `rustls::ServerConfig` seam with atomic reload (rustfs/gateway#1632).
//!
//! Responsible for: proving `TlsMaterial::from_cert_resolver`, `TlsMaterial::with_client_cert_verifier`,
//! `TlsHandle::from_server_config`, and `TlsHandle::reload_server_config` enforce their positive
//! and negative handshake boundaries on live loopback sockets.
//! NOT responsible for: HTTP/2 multiplexing or accept-to-header deadlines (`tls_h2.rs`).
//! Upstream: `rustfs-gateway-server` TLS API, `rcgen`, `rustls`. Downstream: Cargo test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, TlsHandle, TlsMaterial};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower::service_fn;

fn config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    }
}

type EchoFuture = Ready<Result<Response<Full<Bytes>>, Infallible>>;
type EchoService = tower::util::ServiceFn<fn(Request<hyper::body::Incoming>) -> EchoFuture>;

fn echo(_request: Request<hyper::body::Incoming>) -> EchoFuture {
    ready(Ok(Response::new(Full::new(Bytes::from_static(b"ok")))))
}

fn service() -> EchoService {
    service_fn(echo as fn(Request<hyper::body::Incoming>) -> EchoFuture)
}

struct GeneratedCert {
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
}

fn generate_self_signed(domain: &str) -> GeneratedCert {
    let certified = rcgen::generate_simple_self_signed([domain.to_owned()]).expect("self-signed cert builds");
    GeneratedCert {
        cert_der: CertificateDer::from(certified.cert.der().to_vec()),
        key_der: certified.signing_key.serialize_der(),
    }
}

fn generate_ca_and_leaf(domain: &str) -> (CertificateDer<'static>, GeneratedCert) {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
    let ca_key = rcgen::KeyPair::generate().expect("CA key generates");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert signs");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = rcgen::KeyPair::generate().expect("leaf key generates");
    let mut leaf_params = rcgen::CertificateParams::new(vec![domain.to_owned()]).expect("leaf params valid");
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf cert signed by CA");
    (
        CertificateDer::from(ca_cert.der().to_vec()),
        GeneratedCert {
            cert_der: CertificateDer::from(leaf_cert.der().to_vec()),
            key_der: leaf_key.serialize_der(),
        },
    )
}

fn certified_key(generated: &GeneratedCert) -> Arc<CertifiedKey> {
    let private_key = PrivateKeyDer::try_from(generated.key_der.as_slice())
        .expect("valid key DER")
        .clone_key();
    let signing_key = any_supported_type(&private_key).expect("supported signing key");
    Arc::new(CertifiedKey::new(vec![generated.cert_der.clone()], signing_key))
}

#[derive(Debug)]
struct SniMapResolver {
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniMapResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        self.by_name.get(sni).cloned()
    }
}

async fn exchange_once(
    addr: SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
    server_name: &str,
) -> std::io::Result<Vec<u8>> {
    let connector = TlsConnector::from(client_config);
    let name = ServerName::try_from(server_name.to_owned()).expect("valid DNS name");
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = connector.connect(name, tcp).await?;
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n").as_bytes())
        .await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok(response)
}

/// Positive & negative — `TlsMaterial::from_cert_resolver` serves distinct certificates per SNI
/// hostname and rejects unknown SNI hostnames fail-closed.
#[tokio::test]
async fn sni_cert_resolver_serves_matching_domains_and_refuses_unknown_domain() {
    let alpha = generate_self_signed("alpha.example.test");
    let beta = generate_self_signed("beta.example.test");

    let mut by_name = HashMap::new();
    by_name.insert("alpha.example.test".to_owned(), certified_key(&alpha));
    by_name.insert("beta.example.test".to_owned(), certified_key(&beta));
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(SniMapResolver { by_name });

    let handle = TlsHandle::new(TlsMaterial::from_cert_resolver(resolver)).expect("resolver material builds");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle)
        .serve()
        .expect("server starts");

    // Alpha client trusts ONLY alpha's cert.
    let mut alpha_roots = rustls::RootCertStore::empty();
    alpha_roots.add(alpha.cert_der.clone()).expect("alpha trust anchor");
    let alpha_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(alpha_roots)
            .with_no_client_auth(),
    );
    let alpha_resp = exchange_once(local_addr, alpha_client, "alpha.example.test")
        .await
        .expect("alpha SNI handshake succeeds");
    assert!(alpha_resp.starts_with(b"HTTP/1.1 200"));

    // Beta client trusts ONLY beta's cert.
    let mut beta_roots = rustls::RootCertStore::empty();
    beta_roots.add(beta.cert_der.clone()).expect("beta trust anchor");
    let beta_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(beta_roots)
            .with_no_client_auth(),
    );
    let beta_resp = exchange_once(local_addr, beta_client, "beta.example.test")
        .await
        .expect("beta SNI handshake succeeds");
    assert!(beta_resp.starts_with(b"HTTP/1.1 200"));

    // Negative: unknown SNI fails handshake because resolver returns None.
    let mut both_roots = rustls::RootCertStore::empty();
    both_roots.add(alpha.cert_der).expect("alpha anchor");
    both_roots.add(beta.cert_der).expect("beta anchor");
    let unknown_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(both_roots)
            .with_no_client_auth(),
    );
    assert!(
        exchange_once(local_addr, unknown_client, "unknown.example.test")
            .await
            .is_err(),
        "unknown SNI hostname must fail TLS handshake"
    );

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

/// Positive & negative — `TlsMaterial::with_client_cert_verifier` enforces mTLS: accepts a client
/// presenting a certificate signed by the trusted CA and rejects both missing and untrusted
/// client certificates.
#[tokio::test]
async fn mtls_client_cert_verifier_accepts_trusted_client_and_refuses_missing_or_untrusted() {
    let server_cert = generate_self_signed("localhost");
    let (client_ca_der, trusted_client_cert) = generate_ca_and_leaf("client.example.test");
    let untrusted_client_cert = generate_self_signed("rogue.example.test");

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(client_ca_der).expect("client CA anchor");
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("mTLS client verifier builds");

    let material =
        TlsMaterial::from_der(vec![server_cert.cert_der.to_vec()], server_cert.key_der).with_client_cert_verifier(verifier);
    let handle = TlsHandle::new(material).expect("mTLS material builds");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle)
        .serve()
        .expect("server starts");

    let mut server_roots = rustls::RootCertStore::empty();
    server_roots.add(server_cert.cert_der).expect("server anchor");

    // Positive: trusted client cert succeeds.
    let trusted_key = PrivateKeyDer::try_from(trusted_client_cert.key_der.as_slice())
        .expect("trusted client key")
        .clone_key();
    let trusted_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(server_roots.clone())
            .with_client_auth_cert(vec![trusted_client_cert.cert_der], trusted_key)
            .expect("client auth config"),
    );
    let ok_resp = exchange_once(local_addr, trusted_client, "localhost")
        .await
        .expect("trusted mTLS client succeeds");
    assert!(ok_resp.starts_with(b"HTTP/1.1 200"));

    // Negative: client presenting no cert is rejected.
    let no_cert_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(server_roots.clone())
            .with_no_client_auth(),
    );
    assert!(
        exchange_once(local_addr, no_cert_client, "localhost").await.is_err(),
        "missing client certificate must fail mTLS handshake"
    );

    // Negative: client presenting an untrusted cert is rejected.
    let untrusted_key = PrivateKeyDer::try_from(untrusted_client_cert.key_der.as_slice())
        .expect("untrusted client key")
        .clone_key();
    let untrusted_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(server_roots)
            .with_client_auth_cert(vec![untrusted_client_cert.cert_der], untrusted_key)
            .expect("untrusted client auth config"),
    );
    assert!(
        exchange_once(local_addr, untrusted_client, "localhost").await.is_err(),
        "untrusted client certificate must fail mTLS handshake"
    );

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

/// Positive & negative — an optional client-certificate verifier admits unauthenticated clients
/// and trusted client certificates while still refusing untrusted client certificates.
#[tokio::test]
async fn optional_client_cert_verifier_admits_unauthenticated_and_trusted_but_refuses_untrusted() {
    let server_cert = generate_self_signed("localhost");
    let (client_ca_der, trusted_client_cert) = generate_ca_and_leaf("client.example.test");
    let untrusted_client_cert = generate_self_signed("rogue.example.test");

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(client_ca_der).expect("client CA anchor");
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .allow_unauthenticated()
        .build()
        .expect("optional mTLS verifier builds");

    let material =
        TlsMaterial::from_der(vec![server_cert.cert_der.to_vec()], server_cert.key_der).with_client_cert_verifier(verifier);
    let handle = TlsHandle::new(material).expect("optional mTLS material builds");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle)
        .serve()
        .expect("server starts");

    let mut server_roots = rustls::RootCertStore::empty();
    server_roots.add(server_cert.cert_der).expect("server anchor");

    // Positive: no client certificate succeeds under allow_unauthenticated().
    let no_cert_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(server_roots.clone())
            .with_no_client_auth(),
    );
    let anon_resp = exchange_once(local_addr, no_cert_client, "localhost")
        .await
        .expect("unauthenticated client succeeds under optional mTLS");
    assert!(anon_resp.starts_with(b"HTTP/1.1 200"));

    // Positive: trusted client certificate succeeds.
    let trusted_key = PrivateKeyDer::try_from(trusted_client_cert.key_der.as_slice())
        .expect("trusted client key")
        .clone_key();
    let trusted_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(server_roots.clone())
            .with_client_auth_cert(vec![trusted_client_cert.cert_der], trusted_key)
            .expect("trusted client auth config"),
    );
    let auth_resp = exchange_once(local_addr, trusted_client, "localhost")
        .await
        .expect("trusted client succeeds under optional mTLS");
    assert!(auth_resp.starts_with(b"HTTP/1.1 200"));

    // Negative: untrusted client certificate is still rejected.
    let untrusted_key = PrivateKeyDer::try_from(untrusted_client_cert.key_der.as_slice())
        .expect("untrusted client key")
        .clone_key();
    let untrusted_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(server_roots)
            .with_client_auth_cert(vec![untrusted_client_cert.cert_der], untrusted_key)
            .expect("untrusted client auth config"),
    );
    assert!(
        exchange_once(local_addr, untrusted_client, "localhost").await.is_err(),
        "untrusted client certificate must still fail optional mTLS handshake"
    );

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

/// Positive & negative — `TlsHandle::from_server_config` and `TlsHandle::reload_server_config`
/// accept a caller-built `rustls::ServerConfig` (e.g. TLS 1.3-only) and atomically swap configs
/// for new connections.
#[tokio::test]
async fn custom_server_config_enforces_tls13_only_and_reloads_atomically() {
    let first = generate_self_signed("localhost");
    let first_key = PrivateKeyDer::try_from(first.key_der.as_slice())
        .expect("first key")
        .clone_key();
    let mut tls13_only = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![first.cert_der.clone()], first_key)
        .expect("TLS 1.3-only server config builds");
    tls13_only.alpn_protocols = vec![b"http/1.1".to_vec()];

    let handle = TlsHandle::from_server_config(Arc::new(tls13_only));
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle.clone())
        .serve()
        .expect("server starts");

    let mut first_roots = rustls::RootCertStore::empty();
    first_roots.add(first.cert_der).expect("first anchor");

    // Negative: TLS 1.2-only client is rejected by the custom TLS 1.3-only server config.
    let tls12_client = Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates(first_roots.clone())
            .with_no_client_auth(),
    );
    assert!(
        exchange_once(local_addr, tls12_client, "localhost").await.is_err(),
        "TLS 1.2-only client must be refused by TLS 1.3-only ServerConfig"
    );

    // Positive: TLS 1.3 client succeeds.
    let tls13_client = Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(first_roots)
            .with_no_client_auth(),
    );
    let first_resp = exchange_once(local_addr, tls13_client, "localhost")
        .await
        .expect("TLS 1.3 client succeeds");
    assert!(first_resp.starts_with(b"HTTP/1.1 200"));

    // Atomic reload to a new custom ServerConfig with a fresh cert.
    let second = generate_self_signed("localhost");
    let second_key = PrivateKeyDer::try_from(second.key_der.as_slice())
        .expect("second key")
        .clone_key();
    let mut second_cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![second.cert_der.clone()], second_key)
        .expect("second custom server config builds");
    second_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    handle.reload_server_config(Arc::new(second_cfg));

    let mut second_roots = rustls::RootCertStore::empty();
    second_roots.add(second.cert_der).expect("second anchor");
    let second_client = Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(second_roots)
            .with_no_client_auth(),
    );
    let second_resp = exchange_once(local_addr, second_client, "localhost")
        .await
        .expect("reloaded custom ServerConfig serves new connections");
    assert!(second_resp.starts_with(b"HTTP/1.1 200"));

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

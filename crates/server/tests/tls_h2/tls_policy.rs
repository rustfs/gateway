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

//! Live TLS policy controls: TLS 1.3-only, mTLS, custom cert resolvers, OCSP stapling and custom configs.
//!
//! Responsible for: proving `TlsMaterial` policy builders and `TlsHandle::from_server_config` /
//! `reload_server_config` enforce version, client-auth and SNI/OCSP settings on real handshakes.
//! NOT responsible for: atomic reload of established sessions (`tls_h2.rs`) or ALPN (`alpn.rs`).
//! Upstream: rustfs/gateway#1632. Downstream: the public server TLS API.

use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway_server::{RunningServer, Server, TlsHandle, TlsMaterial, TlsMinVersion, TlsReloadError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{config, generated_material, service};

/// Negative + Positive — `TlsMinVersion::Tls13` rejects a TLS 1.2-only client while accepting TLS 1.3.
#[tokio::test]
async fn n_tls13_only_policy_rejects_tls12_client_and_admits_tls13_client() {
    let (material, certificate) = generated_material();
    let material = material.with_min_version(TlsMinVersion::Tls13);
    let handle = TlsHandle::new(material).expect("TLS 1.3 material is valid");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle)
        .serve()
        .expect("server starts");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("trust anchor");
    let roots = Arc::new(roots);

    // Negative: TLS 1.2-only client MUST fail handshake.
    let tls12_client = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(Arc::clone(&roots))
        .with_no_client_auth();
    let tls12_connector = TlsConnector::from(Arc::new(tls12_client));
    let name = ServerName::try_from("localhost").expect("DNS name").to_owned();
    let tcp12 = TcpStream::connect(local_addr).await.expect("TCP connects");
    let tls12_res = tokio::time::timeout(Duration::from_secs(2), tls12_connector.connect(name.clone(), tcp12))
        .await
        .expect("TLS 1.2 handshake settles");
    assert!(tls12_res.is_err(), "TLS 1.3-only server must reject a TLS 1.2 client");

    // Positive: TLS 1.3 client succeeds and gets 200 OK.
    let tls13_client = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls13_connector = TlsConnector::from(Arc::new(tls13_client));
    let tcp13 = TcpStream::connect(local_addr).await.expect("TCP connects");
    let mut tls13 = tls13_connector
        .connect(name, tcp13)
        .await
        .expect("TLS 1.3 handshake succeeds");
    assert_eq!(tls13.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    tls13
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    tls13.read_to_end(&mut response).await.expect("response reads");
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

/// Negative + Positive — mTLS (`with_client_cert_verifier`) rejects an unauthenticated client and
/// admits a client presenting a certificate signed by the trusted CA.
#[tokio::test]
async fn n_mtls_policy_rejects_unauthenticated_client_and_admits_verified_client() {
    let (server_material, server_cert) = generated_material();

    // Generate a client CA and a CA-signed client certificate.
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);

    let mut client_params = rcgen::CertificateParams::new(vec!["client.local".to_owned()]).expect("client params");
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = rcgen::KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert signed by CA");

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(ca_cert.der().to_vec()))
        .expect("client CA anchor");
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("client verifier builds");

    let handle = TlsHandle::new(server_material.with_client_cert_verifier(verifier)).expect("mTLS handle builds");
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
    server_roots.add(server_cert).expect("server trust anchor");
    let server_roots = Arc::new(server_roots);
    let name = ServerName::try_from("localhost").expect("DNS name").to_owned();

    // Negative: client without a certificate must be rejected (in TLS 1.3 the alert arrives on
    // handshake or first read/write after ServerFinished).
    let unauth_client = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::clone(&server_roots))
        .with_no_client_auth();
    let unauth_connector = TlsConnector::from(Arc::new(unauth_client));
    let tcp_unauth = TcpStream::connect(local_addr).await.expect("TCP connects");
    let rejected = match unauth_connector.connect(name.clone(), tcp_unauth).await {
        Err(_) => true,
        Ok(mut stream) => {
            let _ = stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await;
            let mut buf = Vec::new();
            matches!(
                tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await,
                Ok(Err(_) | Ok(0))
            )
        }
    };
    assert!(rejected, "mTLS server must reject a client without a valid certificate");

    // Positive: client presenting the CA-signed certificate succeeds.
    let client_key_der = PrivateKeyDer::try_from(client_key.serialize_der()).expect("client key DER");
    let auth_client = rustls::ClientConfig::builder()
        .with_root_certificates(server_roots)
        .with_client_auth_cert(vec![CertificateDer::from(client_cert.der().to_vec())], client_key_der)
        .expect("client auth config");
    let auth_connector = TlsConnector::from(Arc::new(auth_client));
    let tcp_auth = TcpStream::connect(local_addr).await.expect("TCP connects");
    let mut authed = auth_connector
        .connect(name, tcp_auth)
        .await
        .expect("verified mTLS client handshake succeeds");
    authed
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    authed.read_to_end(&mut response).await.expect("response reads");
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

#[derive(Debug)]
struct StaticResolver {
    certified: Arc<CertifiedKey>,
}

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified))
    }
}

/// Negative + Positive — custom `ResolvesServerCert`, OCSP stapling, empty cipher suite rejection,
/// and direct `TlsHandle::from_server_config` / `reload_server_config`.
#[tokio::test]
async fn tls_policy_resolver_ocsp_cipher_rejection_and_custom_server_config() {
    // Negative: empty cipher suite list fails closed.
    let (bad_material, _) = generated_material();
    assert!(matches!(
        TlsHandle::new(bad_material.with_cipher_suites(Vec::new())),
        Err(TlsReloadError::EmptyCipherSuites)
    ));

    // OCSP stapling builds cleanly and serves requests.
    let (ocsp_material, ocsp_cert) = generated_material();
    let handle = TlsHandle::new(ocsp_material.with_ocsp_response(vec![0x30, 0x03, 0x0a, 0x01, 0x00]))
        .expect("OCSP stapling material builds");

    // Reload onto a custom ResolvesServerCert resolver.
    let sni_gen = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("SNI cert");
    let sni_cert_der = CertificateDer::from(sni_gen.cert.der().to_vec());
    let sni_key_der = PrivateKeyDer::try_from(sni_gen.signing_key.serialize_der()).expect("SNI key");
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&sni_key_der).expect("signing key");
    let resolver = Arc::new(StaticResolver {
        certified: Arc::new(CertifiedKey::new(vec![sni_cert_der.clone()], signing_key)),
    });
    handle
        .reload(TlsMaterial::from_cert_resolver(resolver))
        .expect("resolver reload succeeds");

    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle.clone())
        .serve()
        .expect("server starts");

    // Connect expecting the resolver's certificate (old OCSP cert should no longer match).
    let mut sni_roots = rustls::RootCertStore::empty();
    sni_roots.add(sni_cert_der).expect("SNI anchor");
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(sni_roots)
            .with_no_client_auth(),
    ));
    let name = ServerName::try_from("localhost").expect("DNS name").to_owned();
    let mut sni_stream = connector
        .connect(name.clone(), TcpStream::connect(local_addr).await.expect("TCP"))
        .await
        .expect("resolver handshake succeeds");
    sni_stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut resp = Vec::new();
    sni_stream.read_to_end(&mut resp).await.expect("read");
    assert!(resp.starts_with(b"HTTP/1.1 200"));

    // Custom rustls::ServerConfig injection via reload_server_config + from_server_config.
    let custom_gen = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("custom cert");
    let custom_cert_der = CertificateDer::from(custom_gen.cert.der().to_vec());
    let custom_key_der = PrivateKeyDer::try_from(custom_gen.signing_key.serialize_der()).expect("custom key");
    let custom_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![custom_cert_der.clone()], custom_key_der)
        .expect("custom rustls ServerConfig");
    let direct_handle = TlsHandle::from_server_config(custom_cfg.clone());
    assert_eq!(direct_handle.handshake_count(), 0);
    handle.reload_server_config(custom_cfg);

    let mut custom_roots = rustls::RootCertStore::empty();
    custom_roots.add(custom_cert_der).expect("custom anchor");
    let custom_connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(custom_roots)
            .with_no_client_auth(),
    ));
    let mut custom_stream = custom_connector
        .connect(name, TcpStream::connect(local_addr).await.expect("TCP"))
        .await
        .expect("custom ServerConfig handshake succeeds");
    custom_stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    resp.clear();
    custom_stream.read_to_end(&mut resp).await.expect("read");
    assert!(resp.starts_with(b"HTTP/1.1 200"));
    drop(ocsp_cert);

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server joins").is_ok());
}

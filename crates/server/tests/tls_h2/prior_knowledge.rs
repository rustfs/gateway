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

//! A listener that refuses HTTP/2 by prior knowledge (rustfs/gateway#1206).
//!
//! Responsible for: `ServerConfig::h2_prior_knowledge = false` refusing h2c and prior-knowledge
//! HTTP/2 over TLS without ALPN, while HTTP/1.1 and ALPN-negotiated `h2` are still served.
//! NOT responsible for: the default, which keeps prior knowledge and is pinned in `alpn.rs` and the
//! parent's cleartext HTTP/2 cases.
//! Upstream: `crates/server/src/tls.rs`'s protocol selection. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, TlsHandle, TlsMaterial};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tower::service_fn;

/// Answers with the HTTP version it was asked in.
fn start(plaintext: bool) -> (RunningServer, Option<CertificateDer<'static>>) {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext,
        header_read_timeout: Duration::from_secs(1),
        h2_prior_knowledge: false,
        ..ServerConfig::default()
    };
    let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("{:?}", request.version())))))
    });
    let server = Server::new(config, service);
    if plaintext {
        return (server.serve().expect("server starts"), None);
    }
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    let material = TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der());
    let running = server
        .with_tls(TlsHandle::new(material).expect("material is valid"))
        .serve()
        .expect("server starts");
    (running, Some(certificate))
}

async fn tls(addr: SocketAddr, certificate: CertificateDer<'static>, offered: &[&[u8]]) -> TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("fixture certificate is a valid trust anchor");
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = offered.iter().map(|protocol| protocol.to_vec()).collect();
    let name = ServerName::try_from("localhost").expect("fixture DNS name").to_owned();
    TlsConnector::from(Arc::new(client))
        .connect(name, TcpStream::connect(addr).await.expect("TCP connects"))
        .await
        .expect("TLS handshake succeeds")
}

/// The version an HTTP/2 request over `io` was served as, or the error that refused it.
async fn h2_version<I>(io: I) -> Result<String, hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(io))
        .await?;
    tokio::spawn(connection);
    let request = Request::get("http://localhost/")
        .body(Empty::<Bytes>::new())
        .expect("request");
    let response = sender.send_request(request).await?;
    let body = response.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn h1_answer<I: AsyncRead + AsyncWrite + Unpin>(mut io: I) -> Vec<u8> {
    io.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    let _ = io.read_to_end(&mut response).await;
    response
}

/// Negative — h2c by prior knowledge is not served; the connection is HTTP/1.1 only.
#[tokio::test]
async fn a_cleartext_listener_without_prior_knowledge_refuses_h2c() {
    let (server, _) = start(true);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let refused = tokio::time::timeout(Duration::from_secs(10), h2_version(io))
        .await
        .expect("the refusal is prompt");
    assert!(refused.is_err(), "h2c was served: {refused:?}");
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Negative — over TLS without ALPN, HTTP/2 by prior knowledge is not served either.
#[tokio::test]
async fn a_tls_client_without_alpn_cannot_speak_h2_by_prior_knowledge() {
    let (server, certificate) = start(false);
    let certificate = certificate.expect("a TLS listener has a certificate");
    let io = tls(server.local_addr, certificate, &[]).await;
    let refused = tokio::time::timeout(Duration::from_secs(10), h2_version(io))
        .await
        .expect("the refusal is prompt");
    assert!(refused.is_err(), "prior-knowledge h2 was served over TLS: {refused:?}");
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Positive — HTTP/1.1 is still served on both, and `h2` negotiated by ALPN still is too.
#[tokio::test]
async fn http1_and_alpn_negotiated_h2_are_still_served() {
    let (cleartext, _) = start(true);
    let io = TcpStream::connect(cleartext.local_addr).await.expect("TCP connects");
    assert!(h1_answer(io).await.starts_with(b"HTTP/1.1 200"));
    let _ = cleartext.shutdown.trigger(Duration::from_secs(1)).await;

    let (encrypted, certificate) = start(false);
    let certificate = certificate.expect("a TLS listener has a certificate");
    let without_alpn = tls(encrypted.local_addr, certificate.clone(), &[]).await;
    assert!(h1_answer(without_alpn).await.starts_with(b"HTTP/1.1 200"));
    let negotiated = tls(encrypted.local_addr, certificate, &[b"h2"]).await;
    assert_eq!(h2_version(negotiated).await.expect("negotiated h2 is served"), "HTTP/2.0");
    let _ = encrypted.shutdown.trigger(Duration::from_secs(1)).await;
}

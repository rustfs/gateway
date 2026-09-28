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
//! ALPN negotiation on the TLS listener and the protocol it selects for the connection.
//!
//! Responsible for: proving the listener advertises `h2` and `http/1.1` by default, that the
//! advertised list is configurable, and that a negotiated protocol is the only one the connection
//! then speaks.
//! NOT responsible for: certificate reload or admission (`tls_h2.rs`).
//! Upstream: rustfs/gateway#972. Downstream: the public server API.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-3.2 — over TLS, HTTP/2 is used
//! only after both sides agree on the `h2` token through ALPN.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::convert::Infallible;
use std::future::{Ready, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, TlsHandle, TlsMaterial};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tower::service_fn;

type EchoFuture = Ready<Result<Response<Full<Bytes>>, Infallible>>;

fn echo(request: Request<hyper::body::Incoming>) -> EchoFuture {
    ready(Ok(Response::new(Full::new(Bytes::from(format!("{:?}", request.version()))))))
}

fn material() -> (TlsMaterial, CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    (
        TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der()),
        certificate,
    )
}

fn start(material: TlsMaterial) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        header_read_timeout: Duration::from_secs(1),
        ..ServerConfig::default()
    };
    Server::new(config, service_fn(echo as fn(Request<hyper::body::Incoming>) -> EchoFuture))
        .with_tls(TlsHandle::new(material).expect("material is valid"))
        .serve()
        .expect("server starts")
}

async fn connect(
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    offered: &[&[u8]],
) -> std::io::Result<TlsStream<TcpStream>> {
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
}

fn negotiated(stream: &TlsStream<TcpStream>) -> Option<Vec<u8>> {
    stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
}

async fn h2_version(stream: TlsStream<TcpStream>) -> Result<String, hyper::Error> {
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await?;
    tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::get("https://localhost/")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        )
        .await?;
    let body = response.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn h1_answer(mut stream: TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    response
}

#[tokio::test]
async fn the_listener_selects_h2_when_the_client_offers_it() {
    let (material, certificate) = material();
    let server = start(material);
    let stream = connect(server.local_addr, certificate, &[b"h2", b"http/1.1"])
        .await
        .expect("handshake");
    assert_eq!(negotiated(&stream).as_deref(), Some(b"h2".as_slice()));
    assert_eq!(h2_version(stream).await.expect("an h2 request is served"), "HTTP/2.0");
}

#[tokio::test]
async fn the_listener_selects_http1_when_the_client_offers_only_http1() {
    let (material, certificate) = material();
    let server = start(material);
    let stream = connect(server.local_addr, certificate, &[b"http/1.1"])
        .await
        .expect("handshake");
    assert_eq!(negotiated(&stream).as_deref(), Some(b"http/1.1".as_slice()));
    assert!(h1_answer(stream).await.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn a_connection_that_negotiated_http1_does_not_speak_h2() {
    let (material, certificate) = material();
    let server = start(material);
    let stream = connect(server.local_addr, certificate, &[b"http/1.1"])
        .await
        .expect("handshake");
    assert!(
        h2_version(stream).await.is_err(),
        "an h2 preface after negotiating http/1.1 is not served"
    );
}

#[tokio::test]
async fn a_connection_that_negotiated_h2_does_not_speak_http1() {
    let (material, certificate) = material();
    let server = start(material);
    let stream = connect(server.local_addr, certificate, &[b"h2"]).await.expect("handshake");
    assert!(
        !h1_answer(stream).await.starts_with(b"HTTP/1.1 200"),
        "an HTTP/1.1 request after negotiating h2 is not served"
    );
}

#[tokio::test]
async fn a_configured_http1_only_listener_refuses_a_client_offering_only_h2() {
    let (material, certificate) = material();
    let server = start(material.with_alpn_protocols(vec![b"http/1.1".to_vec()]));
    let error = connect(server.local_addr, certificate.clone(), &[b"h2"])
        .await
        .expect_err("no protocol in common");
    assert!(error.to_string().contains("NoApplicationProtocol"), "{error}");
    let stream = connect(server.local_addr, certificate, &[b"h2", b"http/1.1"])
        .await
        .expect("handshake");
    assert_eq!(negotiated(&stream).as_deref(), Some(b"http/1.1".as_slice()));
}

#[tokio::test]
async fn a_client_offering_no_alpn_keeps_both_protocols_by_prior_knowledge() {
    let (material, certificate) = material();
    let server = start(material);
    let h1 = connect(server.local_addr, certificate.clone(), &[]).await.expect("handshake");
    assert_eq!(negotiated(&h1), None);
    assert!(h1_answer(h1).await.starts_with(b"HTTP/1.1 200"));
    let h2 = connect(server.local_addr, certificate, &[]).await.expect("handshake");
    assert_eq!(h2_version(h2).await.expect("prior-knowledge h2 is served"), "HTTP/2.0");
}

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

//! Live TLS replacement, pre-handshake admission and HTTP/2 multiplexing contracts.
//!
//! Responsible for: proving new TLS handshakes load one atomic config while established sessions
//! keep theirs, per-IP rejection precedes TLS, and HTTP/2 excess streams queue successfully.
//! NOT responsible for: certificate file watching or client policy.
//! Upstream: rustfs/backlog#1739. Downstream: the public server API.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::convert::Infallible;
use std::future::{Ready, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

fn config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        header_read_timeout: Duration::from_secs(1),
        ..ServerConfig::default()
    }
}

fn generated_material() -> (TlsMaterial, CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    (
        TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der()),
        certificate,
    )
}

type EchoFuture = Ready<Result<Response<Full<Bytes>>, Infallible>>;
type EchoService = tower::util::ServiceFn<fn(Request<hyper::body::Incoming>) -> EchoFuture>;

fn echo(_request: Request<hyper::body::Incoming>) -> EchoFuture {
    ready(Ok(Response::new(Full::new(Bytes::from_static(b"ok")))))
}

fn service() -> EchoService {
    service_fn(echo as fn(Request<hyper::body::Incoming>) -> EchoFuture)
}

async fn tls_connect(addr: SocketAddr, certificate: CertificateDer<'static>) -> TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("fixture certificate is a valid trust anchor");
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client));
    let name = ServerName::try_from("localhost").expect("fixture DNS name").to_owned();
    connector
        .connect(name, TcpStream::connect(addr).await.expect("TCP connects"))
        .await
        .expect("TLS handshake succeeds")
}

async fn client_hello_bytes() -> Vec<u8> {
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client));
    let name = ServerName::try_from("localhost").expect("fixture DNS name").to_owned();
    let (client_stream, mut capture_stream) = tokio::io::duplex(16 * 1024);
    let handshake = tokio::spawn(async move { connector.connect(name, client_stream).await });

    let mut record_header = [0_u8; 5];
    capture_stream
        .read_exact(&mut record_header)
        .await
        .expect("rustls emits a TLS record header");
    assert_eq!(record_header[0], 0x16, "the first TLS record carries a handshake");
    let record_len = usize::from(u16::from_be_bytes([record_header[3], record_header[4]]));
    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&record_header);
    client_hello.resize(5 + record_len, 0);
    capture_stream
        .read_exact(&mut client_hello[5..])
        .await
        .expect("rustls emits the complete ClientHello record");
    handshake.abort();
    client_hello
}

async fn request_keep_alive(stream: &mut TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    loop {
        let mut chunk = [0_u8; 256];
        let read = stream.read(&mut chunk).await.expect("response reads");
        assert_ne!(read, 0, "connection closed before the complete response");
        response.extend_from_slice(&chunk[..read]);
        if response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_some_and(|head| response.len() >= head + 6)
        {
            break;
        }
    }
    response
}

#[tokio::test]
async fn a_srv_0004_tls_reload_changes_new_connections_and_preserves_established_sessions() {
    let (old_material, old_certificate) = generated_material();
    let handle = TlsHandle::new(old_material).expect("old material is valid");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle.clone())
        .serve()
        .expect("server starts");

    let mut established = tls_connect(local_addr, old_certificate).await;
    assert!(request_keep_alive(&mut established).await.starts_with(b"HTTP/1.1 200"));

    let (new_material, new_certificate) = generated_material();
    handle.reload(new_material).expect("new material is valid");
    assert!(request_keep_alive(&mut established).await.starts_with(b"HTTP/1.1 200"));

    let mut replacement = tls_connect(local_addr, new_certificate).await;
    replacement
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    replacement.read_to_end(&mut response).await.expect("response reads");
    assert!(response.starts_with(b"HTTP/1.1 200"));

    drop(established);
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0005_h2_excess_streams_queue_and_eventually_complete() {
    let mut server_config = config();
    server_config.plaintext = true;
    server_config.h2_max_concurrent_streams = 2;
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let service = service_fn({
        let active = active.clone();
        let peak = peak.clone();
        move |_request: Request<hyper::body::Incoming>| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(server_config, service).serve().expect("server starts");
    let stream = TokioIo::new(TcpStream::connect(local_addr).await.expect("TCP connects"));
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(stream)
        .await
        .expect("h2 handshake succeeds");
    let connection_task = tokio::spawn(connection);
    let warmup = Request::builder()
        .uri("http://localhost/")
        .body(Empty::<Bytes>::new())
        .expect("fixture request");
    let warmup = sender.send_request(warmup).await.expect("warmup stream opens");
    let _ = warmup.into_body().collect().await.expect("warmup body reads");
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let mut sender = sender.clone();
        requests.spawn(async move {
            let request = Request::builder()
                .uri("http://localhost/")
                .body(Empty::<Bytes>::new())
                .expect("fixture request");
            sender.ready().await.expect("stream capacity eventually opens");
            let response = sender.send_request(request).await.expect("stream eventually opens");
            assert_eq!(response.into_body().collect().await.expect("body reads").to_bytes(), b"ok"[..]);
        });
    }
    while let Some(result) = requests.join_next().await {
        result.expect("request task joins");
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2, "the h2 stream limit is observed on the server");
    let shutdown_task = tokio::spawn(shutdown.trigger(Duration::from_secs(1)));
    assert!(connection_task.await.expect("connection task joins").is_ok());
    let after_goaway = Request::builder()
        .uri("http://localhost/")
        .body(Empty::<Bytes>::new())
        .expect("fixture request");
    assert!(sender.send_request(after_goaway).await.is_err(), "GOAWAY prevents a new h2 stream");
    let _ = shutdown_task.await.expect("shutdown task joins");
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0009_invalid_tls_reload_keeps_old_tls_and_never_opens_plaintext() {
    let (old_material, old_certificate) = generated_material();
    let handle = TlsHandle::new(old_material).expect("old material is valid");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config(), service())
        .with_tls(handle.clone())
        .serve()
        .expect("server starts");
    assert!(handle.reload(TlsMaterial::from_der(Vec::new(), vec![1, 2, 3])).is_err());

    let mut tls = tls_connect(local_addr, old_certificate).await;
    assert!(request_keep_alive(&mut tls).await.starts_with(b"HTTP/1.1 200"));

    let mut plaintext = TcpStream::connect(local_addr).await.expect("TCP connects");
    plaintext
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("cleartext probe writes");
    let mut response = [0_u8; 32];
    let read = tokio::time::timeout(Duration::from_secs(1), plaintext.read(&mut response))
        .await
        .expect("TLS listener closes cleartext promptly")
        .unwrap_or(0);
    assert!(read == 0 || !response[..read].starts_with(b"HTTP/1.1"));

    drop(tls);
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0015_per_ip_limit_rejects_before_starting_a_third_tls_handshake() {
    let mut server_config = config();
    server_config.max_connections_per_ip = Some(2);
    let (material, _) = generated_material();
    let tls = TlsHandle::new(material).expect("material is valid");
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = Server::new(server_config, service())
        .with_tls(tls.clone())
        .serve()
        .expect("server starts");
    let first = TcpStream::connect(local_addr).await.expect("first TCP connection succeeds");
    let second = TcpStream::connect(local_addr).await.expect("second TCP connection succeeds");
    let third = TcpStream::connect(local_addr)
        .await
        .expect("third TCP handshake reaches the listener");
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.per_ip_rejections() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("third connection is rejected");
    assert_eq!(tls.handshake_count(), 2, "the rejected connection did not start TLS work");
    drop(first);
    drop(second);
    drop(third);
    let _ = shutdown.trigger(Duration::from_millis(20)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_half_tls_handshake_releases_its_admission_permit_at_the_header_deadline() {
    let mut server_config = config();
    server_config.header_read_timeout = Duration::from_millis(50);
    let (material, _) = generated_material();
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = Server::new(server_config, service())
        .with_tls(TlsHandle::new(material).expect("material is valid"))
        .serve()
        .expect("server starts");
    let mut peer = TcpStream::connect(local_addr).await.expect("TCP connects");
    let client_hello = client_hello_bytes().await;
    peer.write_all(&client_hello[..client_hello.len() / 2])
        .await
        .expect("half of a real rustls ClientHello writes");
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.active_connections() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection owns an admission permit");
    tokio::time::timeout(Duration::from_millis(250), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the accept-to-header deadline releases a stalled TLS handshake");
    let mut byte = [0_u8; 1];
    assert_eq!(peer.read(&mut byte).await.expect("close is observable"), 0);
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

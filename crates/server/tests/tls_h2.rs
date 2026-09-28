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
use std::future::{Future, Ready, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, TlsHandle, TlsMaterial};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
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

struct DelayedBody {
    release: oneshot::Receiver<()>,
    sent: bool,
}

impl Body for DelayedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.sent {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.release).poll(context) {
            Poll::Ready(_) => {
                this.sent = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"ok")))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.sent
    }
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
async fn c_lim_0038_one_h2_connection_obeys_the_global_request_limit() {
    let mut server_config = config();
    server_config.plaintext = true;
    server_config.h2_max_concurrent_streams = 4;
    server_config.max_global_inflight_requests = 1;
    let (entered_sender, mut entered_receiver) = mpsc::unbounded_channel();
    let service = service_fn({
        let entered_sender = entered_sender.clone();
        move |_request: Request<hyper::body::Incoming>| {
            let (release, released) = oneshot::channel();
            entered_sender.send(release).expect("test receiver remains active");
            async move {
                Ok::<_, Infallible>(Response::new(DelayedBody {
                    release: released,
                    sent: false,
                }))
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
    let first_request = Request::builder()
        .uri("http://localhost/")
        .body(Empty::<Bytes>::new())
        .expect("fixture request");
    let first_response = sender.send_request(first_request).await.expect("first response head arrives");
    let first_release = entered_receiver.recv().await.expect("first handler enters");

    let mut second_sender = sender.clone();
    let second = tokio::spawn(async move {
        second_sender.ready().await.expect("second stream capacity opens");
        let request = Request::builder()
            .uri("http://localhost/")
            .body(Empty::<Bytes>::new())
            .expect("fixture request");
        second_sender
            .send_request(request)
            .await
            .expect("second response head arrives")
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), entered_receiver.recv())
            .await
            .is_err(),
        "the second h2 handler waits while the first response body owns the global permit"
    );

    first_release.send(()).expect("first response body releases");
    assert_eq!(
        first_response
            .into_body()
            .collect()
            .await
            .expect("first body reads")
            .to_bytes(),
        b"ok"[..]
    );
    let second_release = tokio::time::timeout(Duration::from_secs(1), entered_receiver.recv())
        .await
        .expect("second handler enters after the first body completes")
        .expect("second release handle exists");
    let second_response = second.await.expect("second request task joins");
    second_release.send(()).expect("second response body releases");
    assert_eq!(
        second_response
            .into_body()
            .collect()
            .await
            .expect("second body reads")
            .to_bytes(),
        b"ok"[..]
    );

    let shutdown_task = tokio::spawn(shutdown.trigger(Duration::from_secs(1)));
    assert!(connection_task.await.expect("connection task joins").is_ok());
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

std::thread_local! {
    /// A deliberate runtime stall injected into c-lim-0062 after both half-open connections are
    /// admitted. Thread-local so the stall control can reuse the one c-lim-0062 body the timeout
    /// ownership guard reads, on the same thread its `#[tokio::test]` runtime runs on.
    static C_LIM_0062_STALL: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
}

/// #886: a host stall longer than the 50ms header deadline after both half-open connections are
/// admitted must not expire them before the third connection meets the per-IP limit.
#[test]
fn c_lim_0062_per_ip_half_open_limit_survives_a_scheduling_stall_before_the_third_connection() {
    C_LIM_0062_STALL.with(|stall| stall.set(Duration::from_millis(250)));
    c_lim_0062_a_srv_0015_per_ip_half_open_limit_and_header_deadline_recover();
}

#[tokio::test]
async fn c_lim_0062_a_srv_0015_per_ip_half_open_limit_and_header_deadline_recover() {
    let stall = C_LIM_0062_STALL.with(std::cell::Cell::get);
    let mut server_config = config();
    server_config.max_connections_per_ip = Some(2);
    server_config.header_read_timeout = Duration::from_millis(50);
    let (material, certificate) = generated_material();
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
    // Admission is observed on a frozen fixture clock: a stall past the 50ms header deadline must
    // not expire the two half-open connections before the third meets the per-IP limit. The clock
    // resumes before the deadline assertions below, which still observe real expiry and recovery.
    let (mut first, mut second, third) = crate::server_runtime::frozen_clock::with_header_clock_frozen(async {
        let first = TcpStream::connect(local_addr).await.expect("first TCP connection succeeds");
        let second = TcpStream::connect(local_addr).await.expect("second TCP connection succeeds");
        while metrics.active_connections() != 2 {
            tokio::task::yield_now().await;
        }
        // Blocks the whole current-thread runtime, as a descheduled test process would.
        std::thread::sleep(stall);
        let third = TcpStream::connect(local_addr)
            .await
            .expect("third TCP handshake reaches the listener");
        while metrics.per_ip_rejections() != 1 {
            tokio::task::yield_now().await;
        }
        assert_eq!(metrics.active_connections(), 2, "both half-open connections still hold their permits");
        assert_eq!(tls.handshake_count(), 2, "the rejected connection did not start TLS work");
        (first, second, third)
    })
    .await;
    tokio::time::timeout(Duration::from_millis(250), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the header deadline releases both half-open connection permits");
    let mut byte = [0_u8; 1];
    assert_eq!(first.read(&mut byte).await.expect("first close is observable"), 0);
    assert_eq!(second.read(&mut byte).await.expect("second close is observable"), 0);

    let mut recovered = tls_connect(local_addr, certificate).await;
    assert!(request_keep_alive(&mut recovered).await.starts_with(b"HTTP/1.1 200"));
    assert_eq!(tls.handshake_count(), 3, "a healthy handshake succeeds after deadline recovery");
    drop(recovered);
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

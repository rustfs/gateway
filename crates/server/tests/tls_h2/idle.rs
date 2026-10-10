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

//! An idle HTTP/2 connection reaches `keep_alive_idle` (rustfs/gateway#1209).
//!
//! Responsible for: an HTTP/2 connection with no request in flight closing at `keep_alive_idle`
//! while PING traffic keeps flowing — the server's, the client's, over cleartext and TLS — and the
//! controls that a request in flight, a request queued for a permit, and requests arriving inside
//! the interval keep it open.
//! NOT responsible for: HTTP/1.1 idleness (`c_lim_0036` in `server_runtime.rs`) or the PING
//! liveness timeout itself (Hyper's).
//! Upstream: `crates/server/src/io.rs`'s idle deadline. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Empty, Full};
use hyper::client::conn::http2::{Connection, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ServerMetrics, TlsHandle, TlsMaterial};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tower::service_fn;

const IDLE: Duration = Duration::from_millis(300);

/// A listener whose connections idle out after [`IDLE`], PINGing every `server_ping` when given,
/// answering each request after `handler` of handler time.
fn config(server_ping: Option<Duration>) -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        keep_alive_idle: IDLE,
        h2_keep_alive_interval: server_ping,
        ..ServerConfig::default()
    }
}

fn serve(config: ServerConfig, handler: Duration, tls: Option<TlsHandle>) -> RunningServer {
    let service = service_fn(move |_request: Request<hyper::body::Incoming>| async move {
        tokio::time::sleep(handler).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
    });
    let server = Server::new(config, service);
    match tls {
        Some(tls) => server.with_tls(tls),
        None => server,
    }
    .serve()
    .expect("server starts")
}

/// An HTTP/2 client over `io`, PINGing every `client_ping` when given, even with no stream open.
async fn client<I>(io: I, client_ping: Option<Duration>) -> (SendRequest<Empty<Bytes>>, JoinHandle<hyper::Result<()>>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    if let Some(interval) = client_ping {
        builder.keep_alive_interval(interval).keep_alive_while_idle(true);
    }
    let (sender, connection): (_, Connection<TokioIo<I>, Empty<Bytes>, TokioExecutor>) =
        builder.handshake(TokioIo::new(io)).await.expect("h2 handshake succeeds");
    (sender, tokio::spawn(connection))
}

async fn get(sender: &mut SendRequest<Empty<Bytes>>) {
    sender.ready().await.expect("the connection accepts a stream");
    let request = Request::get("http://localhost/").body(Empty::new()).expect("fixture request");
    let response = sender.send_request(request).await.expect("the stream is answered");
    let body = response.into_body().collect().await.expect("the body arrives").to_bytes();
    assert_eq!(body, b"ok"[..]);
}

/// Waits, boundedly, for the server to end the connection and give its admission seat back.
async fn closes_idle(connection: JoinHandle<hyper::Result<()>>, metrics: &ServerMetrics) {
    tokio::time::timeout(Duration::from_secs(10), connection)
        .await
        .expect("the idle HTTP/2 connection is closed by the server")
        .expect("the client connection task joins")
        .ok();
    tokio::time::timeout(Duration::from_secs(10), async {
        while metrics.active_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the idle connection releases its admission seat");
}

/// Negative — the server's own keep-alive PING, acknowledged by every client, is read traffic;
/// before #1209 each acknowledgement restarted the idle deadline and the connection never idled.
#[tokio::test]
async fn an_idle_h2_connection_closes_while_the_server_pings_it() {
    let server = serve(config(Some(Duration::from_millis(50))), Duration::ZERO, None);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let (mut sender, connection) = client(io, None).await;
    get(&mut sender).await;
    closes_idle(connection, &server.metrics).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Negative — a client that PINGs on its own keeps no connection open either.
#[tokio::test]
async fn an_idle_h2_connection_closes_while_the_client_pings_it() {
    let server = serve(config(None), Duration::ZERO, None);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let (mut sender, connection) = client(io, Some(Duration::from_millis(50))).await;
    get(&mut sender).await;
    closes_idle(connection, &server.metrics).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Negative — the same over TLS with `h2` negotiated by ALPN.
#[tokio::test]
async fn an_idle_tls_h2_connection_closes_while_both_sides_ping_it() {
    observed_idle_tls_h2(|| {}).await;
}

/// Runs the real TLS idle fixture with checkpoints before setup and after shutdown.
pub(crate) async fn observed_idle_tls_h2(mut checkpoint: impl FnMut()) {
    let _exclusive_load_lease = crate::server_load::exclusive_server_load_lease().await;
    checkpoint();
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    let material = TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der());
    let mut tls_config = config(Some(Duration::from_millis(50)));
    tls_config.plaintext = false;
    let server = serve(tls_config, Duration::ZERO, Some(TlsHandle::new(material).expect("material is valid")));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("fixture certificate is a valid trust anchor");
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let name = ServerName::try_from("localhost").expect("fixture DNS name").to_owned();
    let io = TlsConnector::from(Arc::new(tls))
        .connect(name, TcpStream::connect(server.local_addr).await.expect("TCP connects"))
        .await
        .expect("TLS handshake succeeds");
    let (mut sender, connection) = client(io, Some(Duration::from_millis(50))).await;
    get(&mut sender).await;
    closes_idle(connection, &server.metrics).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    checkpoint();
}

/// Negative, and a positive control in one — a request whose handler runs four intervals is not
/// cut, and the connection still idles out once it has been answered.
#[tokio::test]
async fn a_request_in_flight_is_not_idle_and_the_connection_idles_after_it() {
    let server = serve(config(Some(Duration::from_millis(50))), IDLE * 4, None);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let (mut sender, connection) = client(io, None).await;
    get(&mut sender).await;
    closes_idle(connection, &server.metrics).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Positive control — a request that waits four intervals for the listener's only request permit,
/// held by another connection, is still in flight on its own connection and is answered.
#[tokio::test]
async fn a_request_queued_for_a_permit_is_not_idle() {
    let mut queued_config = config(Some(Duration::from_millis(50)));
    queued_config.max_global_inflight_requests = 1;
    let server = serve(queued_config, IDLE * 4, None);
    let (mut waiting, _waiting_connection) =
        client(TcpStream::connect(server.local_addr).await.expect("TCP connects"), None).await;
    let (mut holding, _holding_connection) =
        client(TcpStream::connect(server.local_addr).await.expect("TCP connects"), None).await;
    let holder = tokio::spawn(async move { get(&mut holding).await });
    // Let the holder's request take the permit before the waiting connection asks for one.
    tokio::time::sleep(IDLE / 3).await;
    tokio::time::timeout(Duration::from_secs(10), get(&mut waiting))
        .await
        .expect("the queued request is answered once the permit is free");
    holder.await.expect("the holding request is answered");
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Positive control — requests arriving well inside the interval keep one connection open. The
/// interval here is ten gaps long, so a stalled host does not read as an idle client.
#[tokio::test]
async fn requests_inside_the_interval_keep_the_connection() {
    let mut frequent = config(Some(Duration::from_millis(50)));
    frequent.keep_alive_idle = IDLE * 10;
    let server = serve(frequent, Duration::ZERO, None);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let (mut sender, connection) = client(io, None).await;
    for _ in 0..12 {
        get(&mut sender).await;
        tokio::time::sleep(IDLE).await;
    }
    assert!(!connection.is_finished(), "the connection closed although requests kept arriving");
    assert_eq!(server.metrics.accepted_connections(), 1);
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Positive control, then negative — with no PING on either side, nothing reads the socket while
/// a long request runs, so the idle interval must start when the request ends, not when it
/// arrived: the connection is still open just after the answer, and idles out after it.
#[tokio::test]
async fn the_idle_interval_starts_when_the_last_request_ends() {
    let mut quiet = config(None);
    quiet.keep_alive_idle = IDLE * 3;
    let server = serve(quiet, IDLE * 8, None);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let (mut sender, connection) = client(io, None).await;
    get(&mut sender).await;
    tokio::time::sleep(IDLE / 2).await;
    assert!(
        !connection.is_finished(),
        "the connection was closed as idle right after a long request ended"
    );
    closes_idle(connection, &server.metrics).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

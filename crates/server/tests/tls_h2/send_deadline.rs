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

//! An HTTP/2 response whose peer grants it no send capacity gives its request permit back
//! (rustfs/gateway#1206).
//!
//! Responsible for: a zero-window client holding the listener's permits over cleartext and over
//! TLS, and the listener recovering at `write_progress_timeout`; and the controls that time spent
//! producing a response or a body frame is not charged.
//! NOT responsible for: HTTP/1.1 write stalls (`io.rs`'s own cases) or HTTP/2 by prior knowledge
//! (`prior_knowledge.rs`).
//! Upstream: `crates/server/src/send_deadline.rs`. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, TlsHandle};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Sleep;
use tokio_rustls::TlsConnector;
use tower::service_fn;

/// A streamed response body: `chunks` in order, each after `pause`, and its end reported only when
/// polled once more — as any stream reports it, the gateway's own in-memory documents included.
struct Streamed {
    chunks: Vec<&'static [u8]>,
    pause: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Streamed {
    fn new(chunks: Vec<&'static [u8]>, pause: Duration) -> Self {
        Self {
            chunks,
            pause,
            sleep: None,
        }
    }
}

impl Body for Streamed {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.chunks.is_empty() {
            return Poll::Ready(None);
        }
        let pause = self.pause;
        let sleep = self.sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(pause)));
        if sleep.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        self.sleep = None;
        let chunk = self.chunks.remove(0);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(chunk)))))
    }
}

/// Answers every request with `Streamed`, after `before_response` of handler time.
fn serve(config: ServerConfig, chunks: Vec<&'static [u8]>, pause: Duration, before_response: Duration) -> RunningServer {
    let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
        let chunks = chunks.clone();
        async move {
            tokio::time::sleep(before_response).await;
            Ok::<_, Infallible>(Response::new(Streamed::new(chunks, pause)))
        }
    });
    Server::new(config, service).serve().expect("server starts")
}

fn config(write_progress_timeout: Duration) -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        max_global_inflight_requests: 2,
        write_progress_timeout,
        ..ServerConfig::default()
    }
}

/// An HTTP/2 client over `io`, advertising `window` as its initial stream window when given.
async fn h2_client<I>(io: I, window: Option<u32>) -> SendRequest<Empty<Bytes>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    if let Some(window) = window {
        builder.initial_stream_window_size(window);
    }
    let (sender, connection) = builder.handshake(TokioIo::new(io)).await.expect("h2 handshake succeeds");
    tokio::spawn(connection);
    sender
}

fn get() -> Request<Empty<Bytes>> {
    Request::get("http://localhost/").body(Empty::new()).expect("fixture request")
}

/// A fresh cleartext HTTP/1.1 exchange; it is only served once a request permit is free, because
/// the listener stops accepting while there is none.
async fn fresh_http1(addr: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("TCP connects");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("response reads");
    response
}

/// Opens two streams whose heads arrive and whose bodies cannot, then shows the listener serves a
/// fresh client again once those two give their permits back, and that they ended in a reset.
async fn starve_and_recover(starved: SendRequest<Empty<Bytes>>, addr: SocketAddr) {
    let mut heads = Vec::new();
    for _ in 0..2 {
        let mut starved = starved.clone();
        starved.ready().await.expect("the connection accepts a stream");
        heads.push(starved.send_request(get()).await.expect("the response head arrives"));
    }
    let fresh = tokio::time::timeout(Duration::from_secs(10), fresh_http1(addr))
        .await
        .expect("a fresh client is served once the starved streams give their permits back");
    assert!(fresh.starts_with(b"HTTP/1.1 200"), "{fresh:?}");
    for head in heads {
        let body = tokio::time::timeout(Duration::from_secs(10), head.into_body().collect())
            .await
            .expect("the starved stream ends");
        assert!(body.is_err(), "a stream that was never granted capacity ended in a reset, not a body");
    }
}

/// Negative — before #1206 two zero-window streams held both permits of this listener forever:
/// its accept loop stopped, and the fresh client below was never served.
#[tokio::test]
async fn a_zero_window_h2c_peer_gives_the_request_permits_back() {
    let server = serve(config(Duration::from_millis(300)), vec![b"ok"], Duration::ZERO, Duration::ZERO);
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    starve_and_recover(h2_client(io, Some(0)).await, server.local_addr).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Negative — a peer that grants capacity for the first frames and then stops is charged from the
/// frame it stopped at: with a four-octet window, the stream sends `ok` and two octets of the second
/// frame, then waits for the third with nothing left to grant it.
#[tokio::test]
async fn a_peer_that_stops_granting_capacity_partway_through_a_body_gives_the_permit_back() {
    let server = serve(
        config(Duration::from_millis(300)),
        vec![b"ok", b"sixteen octets!!", b"more"],
        Duration::ZERO,
        Duration::ZERO,
    );
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    starve_and_recover(h2_client(io, Some(4)).await, server.local_addr).await;
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Negative — the same attack over TLS with `h2` negotiated by ALPN, and the same recovery: a fresh
/// TLS client, whose handshake itself waits for the listener to accept again, is served.
#[tokio::test]
async fn a_zero_window_tls_h2_peer_gives_the_request_permits_back() {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("certificate generation succeeds");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    let material =
        rustfs_gateway_server::TlsMaterial::from_der(vec![certified.cert.der().to_vec()], certified.signing_key.serialize_der());
    let mut tls_config = config(Duration::from_millis(300));
    tls_config.plaintext = false;
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(Response::new(Streamed::new(vec![b"ok"], Duration::ZERO)))
    });
    let server = Server::new(tls_config, service)
        .with_tls(TlsHandle::new(material).expect("material is valid"))
        .serve()
        .expect("server starts");
    let connect = || async {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.clone())
            .expect("fixture certificate is a valid trust anchor");
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let name = ServerName::try_from("localhost").expect("fixture DNS name").to_owned();
        TlsConnector::from(Arc::new(client))
            .connect(name, TcpStream::connect(server.local_addr).await.expect("TCP connects"))
            .await
            .expect("TLS handshake succeeds")
    };
    let starved = h2_client(connect().await, Some(0)).await;
    let mut heads = Vec::new();
    for _ in 0..2 {
        let mut starved = starved.clone();
        starved.ready().await.expect("the connection accepts a stream");
        heads.push(starved.send_request(get()).await.expect("the response head arrives"));
    }
    let served = tokio::time::timeout(Duration::from_secs(10), async move {
        // The listener accepts nothing while no permit is free, so even the handshake waits.
        let mut fresh = h2_client(connect().await, None).await;
        fresh.ready().await.expect("the fresh connection accepts a stream");
        let response = fresh.send_request(get()).await.expect("the fresh stream is answered");
        response
            .into_body()
            .collect()
            .await
            .expect("the fresh body arrives")
            .to_bytes()
    })
    .await
    .expect("a fresh TLS client is served once the starved streams give their permits back");
    assert_eq!(served, b"ok"[..]);
    for head in heads {
        assert!(head.into_body().collect().await.is_err(), "a starved stream ended in a reset");
    }
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Positive control — a body the service takes longer than the deadline to produce is served whole:
/// only the wait for the peer is charged, never the wait for the next frame.
#[tokio::test]
async fn time_producing_a_body_frame_is_not_charged() {
    let server = serve(
        config(Duration::from_millis(100)),
        vec![b"first,", b"second"],
        Duration::from_millis(400),
        Duration::ZERO,
    );
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let mut client = h2_client(io, None).await;
    let response = client.send_request(get()).await.expect("the head arrives");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the whole body arrives")
        .to_bytes();
    assert_eq!(body, b"first,second"[..]);
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

/// Positive control — a handler that takes longer than the deadline to answer is not charged
/// either: the deadline starts only once there is a response to send.
#[tokio::test]
async fn time_producing_the_response_is_not_charged() {
    let server = serve(
        config(Duration::from_millis(100)),
        vec![b"ok"],
        Duration::ZERO,
        Duration::from_millis(400),
    );
    let io = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    let mut client = h2_client(io, None).await;
    let response = client.send_request(get()).await.expect("the head arrives");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the whole body arrives")
        .to_bytes();
    assert_eq!(body, b"ok"[..]);
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
}

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

//! Live ownership controls for the accepted-connection driver seam.
//!
//! Responsible for: proving a configured driver owns each accepted socket until its future exits.
//! NOT responsible for: HTTP parsing or response encoding, which belong to concrete drivers.
//! Upstream: the `server_runtime` harness. Downstream: the gateway self-held HTTP/1.1 transport.

#![allow(clippy::expect_used, clippy::panic)]

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use rustfs_gateway_server::{
    AcceptedConnection, ConnectionDriver, ConnectionFuture, ConnectionInfo, RequestCancellation, Server, ServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tower::Service;

fn plaintext_config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        tcp_nodelay: true,
        ..ServerConfig::default()
    }
}

#[derive(Clone)]
struct ProbeDriver {
    calls: Arc<AtomicUsize>,
    saw_shutdown: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl ProbeDriver {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            saw_shutdown: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        }
    }
}

impl ConnectionDriver<()> for ProbeDriver {
    fn drive(&self, accepted: AcceptedConnection<()>) -> ConnectionFuture {
        let calls = Arc::clone(&self.calls);
        let saw_shutdown = Arc::clone(&self.saw_shutdown);
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        let peer_addr = accepted.peer_addr();
        let tcp_nodelay = accepted.tcp_nodelay();
        let tls_configured = accepted.tls_configured();
        let mut shutdown = accepted.shutdown_receiver();
        let (mut stream, _service) = accepted.into_plaintext().expect("probe listener is plaintext");
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            assert!(peer_addr.ip().is_loopback());
            assert!(tcp_nodelay);
            assert!(!tls_configured);
            entered.notify_one();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .expect("probe response writes");
            tokio::select! {
                changed = shutdown.changed() => {
                    assert!(changed.is_ok(), "server shutdown sender remains alive");
                    saw_shutdown.store(true, Ordering::Release);
                }
                () = release.notified() => {}
            }
        })
    }
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("observation arrives before the test deadline");
}

#[derive(Clone, Copy)]
enum ServiceBehavior {
    Respond,
    Panic,
    BlockFirst,
}

#[derive(Clone)]
struct LifecycleService {
    behavior: ServiceBehavior,
    calls: Arc<AtomicUsize>,
    saw_context: Arc<AtomicBool>,
    first_entered: Arc<Notify>,
    release_first: Arc<Notify>,
}

impl LifecycleService {
    fn new(behavior: ServiceBehavior) -> Self {
        Self {
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
            saw_context: Arc::new(AtomicBool::new(false)),
            first_entered: Arc::new(Notify::new()),
            release_first: Arc::new(Notify::new()),
        }
    }
}

impl Service<Request<Full<Bytes>>> for LifecycleService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
        if matches!(self.behavior, ServiceBehavior::Panic) {
            panic!("connection service must isolate application panics");
        }
        let ordinal = self.calls.fetch_add(1, Ordering::Relaxed);
        self.saw_context.store(
            request.extensions().get::<ConnectionInfo>().is_some() && request.extensions().get::<RequestCancellation>().is_some(),
            Ordering::Release,
        );
        let behavior = self.behavior;
        let first_entered = Arc::clone(&self.first_entered);
        let release_first = Arc::clone(&self.release_first);
        Box::pin(async move {
            if matches!(behavior, ServiceBehavior::BlockFirst) && ordinal == 0 {
                first_entered.notify_one();
                release_first.notified().await;
            }
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .expect("static response is valid"))
        })
    }
}

#[derive(Clone, Default)]
struct ManagedRequestDriver;

impl ConnectionDriver<LifecycleService> for ManagedRequestDriver {
    fn drive(&self, accepted: AcceptedConnection<LifecycleService>) -> ConnectionFuture {
        let (mut stream, mut service) = accepted.into_plaintext().expect("managed test listener is plaintext");
        Box::pin(async move {
            let request = Request::new(Full::new(Bytes::new()));
            let response = Service::call(&mut service, request)
                .await
                .expect("lifecycle service is infallible");
            let status = response.status().as_u16();
            let _ = response
                .into_body()
                .collect()
                .await
                .expect("managed response body is readable");
            let wire = format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n");
            stream.write_all(wire.as_bytes()).await.expect("managed response writes");
        })
    }
}

/// Positive control: the configured driver, rather than Hyper, writes the accepted socket.
#[tokio::test]
async fn custom_driver_owns_the_plaintext_socket() {
    let driver = ProbeDriver::new();
    let running = Server::new(plaintext_config(), ())
        .serve_with(driver.clone())
        .expect("custom-driver server starts");
    let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
    let mut response = vec![0_u8; 46];
    client.read_exact(&mut response).await.expect("probe response is complete");
    assert_eq!(response, b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
    assert_eq!(driver.calls.load(Ordering::Relaxed), 1);
    driver.release.notify_one();
    wait_until(|| running.metrics.active_connections() == 0).await;
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: an active custom driver must observe explicit shutdown before it is aborted.
#[tokio::test]
async fn shutdown_signal_reaches_the_custom_driver() {
    let driver = ProbeDriver::new();
    let running = Server::new(plaintext_config(), ())
        .serve_with(driver.clone())
        .expect("custom-driver server starts");
    let _client = TcpStream::connect(running.local_addr).await.expect("client connects");
    driver.entered.notified().await;
    let report = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert_eq!(report.drained, 0);
    assert_eq!(report.aborted, 0);
    assert!(driver.saw_shutdown.load(Ordering::Acquire));
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: connection admission must not be released while the driver future is alive.
#[tokio::test]
async fn driver_future_holds_the_connection_permit_until_exit() {
    let driver = ProbeDriver::new();
    let mut config = plaintext_config();
    config.max_connections = 1;
    let running = Server::new(config, ())
        .serve_with(driver.clone())
        .expect("custom-driver server starts");
    let _first = TcpStream::connect(running.local_addr).await.expect("first client connects");
    driver.entered.notified().await;
    let _second = TcpStream::connect(running.local_addr)
        .await
        .expect("second client reaches the backlog");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(running.metrics.accepted_connections(), 1, "second socket is not accepted early");
    assert_eq!(running.metrics.active_connections(), 1, "first driver still owns admission");
    driver.release.notify_one();
    wait_until(|| running.metrics.accepted_connections() == 2).await;
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive control: a takeover driver dispatches through the same connection context as Hyper.
#[tokio::test]
async fn custom_driver_uses_the_managed_connection_service() {
    let service = LifecycleService::new(ServiceBehavior::Respond);
    let running = Server::new(plaintext_config(), service.clone())
        .serve_with(ManagedRequestDriver)
        .expect("managed-driver server starts");
    let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("managed response is complete");
    assert!(response.starts_with(b"HTTP/1.1 204\r\n"));
    assert!(service.saw_context.load(Ordering::Acquire));
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: application panics cannot escape a takeover driver's managed service.
#[tokio::test]
async fn custom_driver_cannot_bypass_panic_isolation() {
    let service = LifecycleService::new(ServiceBehavior::Panic);
    let running = Server::new(plaintext_config(), service)
        .serve_with(ManagedRequestDriver)
        .expect("managed-driver server starts");
    let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("panic response is complete");
    assert!(response.starts_with(b"HTTP/1.1 500\r\n"));
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: takeover drivers cannot dispatch past the global request-capacity limit.
#[tokio::test]
async fn custom_driver_cannot_bypass_request_capacity() {
    let service = LifecycleService::new(ServiceBehavior::BlockFirst);
    let mut config = plaintext_config();
    config.max_global_inflight_requests = 1;
    let running = Server::new(config, service.clone())
        .serve_with(ManagedRequestDriver)
        .expect("managed-driver server starts");
    let mut first = TcpStream::connect(running.local_addr).await.expect("first client connects");
    service.first_entered.notified().await;
    let mut second = TcpStream::connect(running.local_addr).await.expect("second client connects");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(service.calls.load(Ordering::Relaxed), 1, "second request remains outside the application");
    service.release_first.notify_one();
    let mut first_response = Vec::new();
    first
        .read_to_end(&mut first_response)
        .await
        .expect("first response completes");
    let mut second_response = Vec::new();
    second
        .read_to_end(&mut second_response)
        .await
        .expect("second response completes");
    assert!(first_response.starts_with(b"HTTP/1.1 204\r\n"));
    assert!(second_response.starts_with(b"HTTP/1.1 204\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 2);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

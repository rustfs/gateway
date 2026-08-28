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

//! Real-socket controls for file-backed responses on the self-held HTTP/1.1 driver.
//!
//! Responsible for: proving a selected file range reaches a cleartext client through the
//! production connection owner. NOT responsible for: syscall profiling or Hyper fallback, which
//! have separate deterministic controls. Upstream: a file-backed application response.
//! Downstream: the production self-held plaintext HTTP/1.1 socket.

#![allow(clippy::expect_used)]

#[cfg(unix)]
mod unix {
    use std::convert::Infallible;
    use std::fs::{File, OpenOptions};
    use std::future::{Ready, ready};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::OwnedFd;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use http::{Request, Response, header};
    use rustfs_gateway::{Body, ResponseFallbackReason, ResponseTransportMetrics, SelfHeldHttp1Driver, SelfHeldRequestBody};
    use rustfs_gateway_server::{Server, ServerConfig};
    use rustfs_gateway_stream::{FileRegion, NoZeroCopy, Payload, StreamMetrics};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tower::Service;
    use tower::service_fn;

    #[derive(Clone)]
    struct FileService {
        path: Arc<PathBuf>,
        offset: u64,
        len: u64,
        metrics: Arc<StreamMetrics>,
    }

    impl Service<Request<SelfHeldRequestBody>> for FileService {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<SelfHeldRequestBody>) -> Self::Future {
            let file = File::open(self.path.as_ref()).expect("fixture file remains openable");
            let region = FileRegion::new(OwnedFd::from(file), self.offset, self.len).expect("fixture range does not overflow");
            ready(Ok(Response::builder()
                .header(header::CONTENT_LENGTH, self.len)
                .body(Body::from_payload_with_metrics(Payload::File(region), Arc::clone(&self.metrics)))
                .expect("fixture response is valid")))
        }
    }

    struct FixtureFile {
        path: Arc<PathBuf>,
    }

    impl FixtureFile {
        fn new(bytes: &[u8]) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("rustfs-gateway-file-transfer-{}-{sequence}", std::process::id()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("fixture path is unique");
            file.write_all(bytes).expect("fixture bytes are written");
            Self { path: Arc::new(path) }
        }
    }

    impl Drop for FixtureFile {
        fn drop(&mut self) {
            std::fs::remove_file(self.path.as_ref()).expect("fixture file is removed");
        }
    }

    /// Positive control: the selected half-open range, rather than the whole file, reaches the wire.
    #[tokio::test]
    async fn production_driver_transfers_the_selected_file_region() {
        let fixture = FixtureFile::new(b"abcdefghij");
        let metrics = Arc::new(StreamMetrics::new());
        let transport_metrics = Arc::new(ResponseTransportMetrics::new());
        let service = FileService {
            path: Arc::clone(&fixture.path),
            offset: 2,
            len: 5,
            metrics: Arc::clone(&metrics),
        };
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            tcp_nodelay: true,
            ..ServerConfig::default()
        };
        let running = Server::new(config, service)
            .serve_with(SelfHeldHttp1Driver::with_metrics(Arc::clone(&transport_metrics)))
            .expect("self-held server starts");
        let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
        client
            .write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request writes");
        let first = read_until(&mut client, b"cdefg").await;
        assert!(first.starts_with(b"HTTP/1.1 200 OK\r\n"));

        client
            .write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("second request writes on the same connection");
        let mut second = Vec::new();
        client
            .read_to_end(&mut second)
            .await
            .expect("second response reaches an observable close");
        assert!(second.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(second.ends_with(b"cdefg"));
        assert_eq!(transport_metrics.selected_connections(), 1);
        assert_eq!(transport_metrics.kernel_transfer_calls(), 2);
        assert_eq!(transport_metrics.kernel_transferred_bytes(), 10);
        assert_eq!(transport_metrics.fallback_responses_total(), 0);
        assert_eq!(transport_metrics.copied_payload_bytes(), 0);
        assert_eq!(metrics.adapt_copies_total(), 0);
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    /// Negative control: a file that shrinks below the declared region closes instead of hanging.
    #[tokio::test]
    async fn production_driver_closes_an_incomplete_file_region() {
        let fixture = FixtureFile::new(b"abc");
        let metrics = Arc::new(StreamMetrics::new());
        let service = FileService {
            path: Arc::clone(&fixture.path),
            offset: 0,
            len: 5,
            metrics: Arc::clone(&metrics),
        };
        let (running, transport_metrics) = start(service);
        let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
        client
            .write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request writes");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("incomplete response closes before the deadline")
            .expect("client observes an orderly close");
        let separator = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response contains a head terminator");
        let body = &response[separator + 4..];
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(body, b"abc");
        assert_eq!(transport_metrics.kernel_transfer_calls(), 1);
        assert_eq!(transport_metrics.kernel_transferred_bytes(), 3);
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    /// Negative control: an unrepresentable syscall range is rejected before any response head.
    #[tokio::test]
    async fn production_driver_rejects_an_unrepresentable_file_region_before_commit() {
        let fixture = FixtureFile::new(b"x");
        let service = FileService {
            path: Arc::clone(&fixture.path),
            offset: 0,
            len: (i64::MAX as u64) + 1,
            metrics: Arc::new(StreamMetrics::new()),
        };
        let (running, transport_metrics) = start(service);
        let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
        client
            .write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request writes");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("rejection closes the connection");
        assert!(response.is_empty(), "no response head is committed before range validation");
        assert_eq!(transport_metrics.kernel_transfer_calls(), 0);
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    /// Negative control: a non-file response takes one named, byte-counted fallback and no kernel path.
    #[tokio::test]
    async fn production_driver_observes_a_non_file_fallback() {
        let stream_metrics = Arc::new(StreamMetrics::new());
        let service_metrics = Arc::clone(&stream_metrics);
        let service = service_fn(move |_request: Request<SelfHeldRequestBody>| {
            let service_metrics = Arc::clone(&service_metrics);
            async move {
                Ok::<_, Infallible>(Response::new(Body::from_payload_with_metrics(
                    Payload::Bytes(bytes::Bytes::from_static(b"fallback")),
                    service_metrics,
                )))
            }
        });
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            tcp_nodelay: true,
            ..ServerConfig::default()
        };
        let metrics = Arc::new(ResponseTransportMetrics::new());
        let running = Server::new(config, service)
            .serve_with(SelfHeldHttp1Driver::with_metrics(Arc::clone(&metrics)))
            .expect("self-held server starts");
        let mut client = TcpStream::connect(running.local_addr).await.expect("client connects");
        client
            .write_all(b"GET /memory HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request writes");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("response reaches an observable close");
        assert!(response.ends_with(b"fallback"));
        assert_eq!(metrics.fallback_responses(ResponseFallbackReason::NotFileBacked), 1);
        assert_eq!(metrics.fallback_responses_total(), 1);
        assert_eq!(metrics.copied_payload_bytes(), 8);
        assert_eq!(metrics.kernel_transfer_calls(), 0);
        assert_eq!(stream_metrics.zero_copy_refusals(NoZeroCopy::NotFileBacked), 1);
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    fn start(service: FileService) -> (rustfs_gateway_server::RunningServer, Arc<ResponseTransportMetrics>) {
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            tcp_nodelay: true,
            ..ServerConfig::default()
        };
        let metrics = Arc::new(ResponseTransportMetrics::new());
        let running = Server::new(config, service)
            .serve_with(SelfHeldHttp1Driver::with_metrics(Arc::clone(&metrics)))
            .expect("self-held server starts");
        (running, metrics)
    }

    async fn read_until(stream: &mut TcpStream, suffix: &[u8]) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut response = Vec::new();
            let mut chunk = [0_u8; 256];
            while !response.ends_with(suffix) {
                let read = stream.read(&mut chunk).await.expect("response read succeeds");
                assert_ne!(read, 0, "connection stays open until the file region is complete");
                response.extend_from_slice(&chunk[..read]);
            }
            response
        })
        .await
        .expect("response arrives before the test deadline")
    }
}

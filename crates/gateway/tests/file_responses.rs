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

//! A `GetObject` handler that answers with a file region, served by every driver.
//!
//! Responsible for: rustfs/backlog#1740 a-zc-0002 through the real `S3Service` (the self-held
//! driver sends the handler's file region with `sendfile`), a-zc-0012 / a-pf-0010 (the Hyper
//! driver serves the same response completely by copying it once, and counts that copy with its
//! reason), and the in-process caller, which has no transport and copies too
//! (rustfs/gateway#949). NOT responsible for: the TLS and HTTP/2 reasons, whose selection is
//! unit-tested beside the adapter, or 1 GiB volumes, which `perf_evidence.rs` measures.
//! Upstream: `ByteStream::from_file_region`, `S3Service`. Downstream: both production drivers.

#![allow(clippy::expect_used, clippy::panic)]

#[cfg(unix)]
mod unix {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::OwnedFd;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use rustfs_gateway::dto;
    use rustfs_gateway::{
        ByteStream, Handler, HandlerResult, Req, Resp, ResponseTransportMetrics, S3Service, SelfHeldHttp1Driver,
    };
    use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
    use rustfs_gateway_stream::{FileRegion, NoZeroCopy, StreamMetrics};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use crate::support;

    /// Larger than any socket buffer, so both drivers make many writes or transfers.
    const LEN: usize = 4 * 1024 * 1024;

    struct Fixture {
        path: PathBuf,
        bytes: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "rustfs-gateway-file-responses-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let bytes: Vec<u8> = (0..LEN).map(|index| (index % 251) as u8 ^ (index >> 16) as u8).collect();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("the fixture path is unique")
                .write_all(&bytes)
                .expect("the fixture is written");
            Self { path, bytes }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Answers every `GetObject` with the whole fixture as a file region.
    struct FileBackend {
        path: PathBuf,
        metrics: Arc<StreamMetrics>,
    }

    impl Handler<dto::GetObject> for FileBackend {
        async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
            let file = File::open(&self.path).expect("the fixture is readable");
            let region = FileRegion::new(OwnedFd::from(file), 0, LEN as u64).expect("the range fits");
            Ok(Resp::new(dto::GetObjectOutput {
                body: Some(ByteStream::from_file_region(region, Arc::clone(&self.metrics))),
                content_length: Some(LEN as i64),
                ..dto::GetObjectOutput::default()
            }))
        }
    }

    fn service(fixture: &Fixture, metrics: &Arc<StreamMetrics>) -> S3Service {
        support::wired_at_signed_time()
            .register::<dto::GetObject, _>(Arc::new(FileBackend {
                path: fixture.path.clone(),
                metrics: Arc::clone(metrics),
            }))
            .build()
            .expect("a complete assembly")
    }

    fn config() -> ServerConfig {
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            tcp_nodelay: true,
            ..ServerConfig::default()
        }
    }

    /// One signed GET, written onto a socket as HTTP/1.1, and the body read back to the close.
    async fn get(running: &RunningServer) -> (u16, Vec<u8>) {
        let signed = support::signed(http::Method::GET, "/bucket/key");
        let mut head = format!("GET {} HTTP/1.1\r\n", signed.uri());
        for (name, value) in signed.headers() {
            head.push_str(&format!("{name}: {}\r\n", value.to_str().expect("an ASCII header")));
        }
        head.push_str("connection: close\r\n\r\n");
        let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
        client.write_all(head.as_bytes()).await.expect("the request writes");
        let mut response = Vec::with_capacity(LEN + 1024);
        tokio::time::timeout(Duration::from_secs(60), client.read_to_end(&mut response))
            .await
            .expect("the response ends inside the outer bound")
            .expect("the response reads");
        let end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a response head");
        let status = std::str::from_utf8(&response[9..12])
            .expect("a status")
            .parse()
            .expect("a status");
        (status, response[end + 4..].to_vec())
    }

    async fn stop(running: RunningServer) {
        let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
        let _ = running.task.await;
    }

    /// a-zc-0012 / a-pf-0010. Negative — the Hyper driver has no kernel path, so the handler's
    /// file region is copied exactly once, the whole object still arrives, and the copy is counted
    /// with the transport's reason. Before rustfs/gateway#949 the client read nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_hyper_driver_copies_a_file_region_once_and_says_why() {
        let fixture = Fixture::new();
        let metrics = Arc::new(StreamMetrics::new());
        let running = Server::new(config(), service(&fixture, &metrics))
            .serve()
            .expect("the server starts");
        let (status, body) = get(&running).await;
        stop(running).await;
        assert_eq!(status, 200);
        assert!(
            body == fixture.bytes,
            "the Hyper driver delivered {} of {LEN} bytes, or the wrong ones",
            body.len()
        );
        assert_eq!(metrics.adapt_copies_total(), 1);
        assert_eq!(metrics.adapt_copied_bytes_total(), LEN as u64);
        assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::TransportLacksSendfile), 1);
        assert_eq!(metrics.zero_copy_refusals_total(), 1);
    }

    /// a-zc-0002. Positive — the same handler behind the self-held driver is sent by the kernel:
    /// every byte through `sendfile`, none copied, nothing refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_self_held_driver_sends_a_handlers_file_region_with_the_kernel() {
        let fixture = Fixture::new();
        let metrics = Arc::new(StreamMetrics::new());
        let transport = Arc::new(ResponseTransportMetrics::new());
        let running = Server::new(config(), service(&fixture, &metrics))
            .serve_with(SelfHeldHttp1Driver::with_metrics(Arc::clone(&transport)))
            .expect("the server starts");
        let (status, body) = get(&running).await;
        stop(running).await;
        assert_eq!(status, 200);
        assert!(
            body == fixture.bytes,
            "the self-held driver delivered {} of {LEN} bytes, or the wrong ones",
            body.len()
        );
        assert_eq!(transport.kernel_transferred_bytes(), LEN as u64);
        assert_eq!(transport.copied_payload_bytes(), 0);
        assert_eq!(transport.fallback_responses_total(), 0);
        assert_eq!(metrics.adapt_copies_total(), 0);
        assert_eq!(metrics.zero_copy_refusals_total(), 0);
    }

    /// Negative — an in-process caller has no transport at all; it gets the bytes, copied and
    /// counted, rather than an error frame where the body should be.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_in_process_caller_receives_a_copied_file_region() {
        let fixture = Fixture::new();
        let metrics = Arc::new(StreamMetrics::new());
        let service = service(&fixture, &metrics);
        let response = rustfs_gateway::collect(service.call_bytes(support::signed(http::Method::GET, "/bucket/key")).await)
            .await
            .expect("the copied body collects");
        assert_eq!(response.status().as_u16(), 200);
        assert!(response.body().as_ref() == fixture.bytes.as_slice());
        assert_eq!(metrics.adapt_copies_total(), 1);
        assert_eq!(metrics.zero_copy_refusals(NoZeroCopy::TransportLacksSendfile), 1);
    }
}

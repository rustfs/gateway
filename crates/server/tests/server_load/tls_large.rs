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

//! A 1 GiB streamed response over TLS and over cleartext, with Hyper's write strategy left to
//! choose and forced to flatten.
//!
//! Responsible for: rustfs/backlog#1766 a-pf-0024 — what flattening costs on a TLS large-object
//! GET, beside the cleartext figure, for `docs/capacity-planning.md`. `forced_flatten` reports the
//! configuration, not an observation of Hyper's internal choice: under `Auto`, Hyper flattens only
//! a transport that is not vectored, and the TLS stream the server hands it reports vectored writes
//! (tokio-rustls 0.26), so `Auto` on TLS queues; the `Disabled` row is the flattened cost. Every figure is printed on a `perf-evidence:` line; what is
//! asserted is that each transfer delivered exactly one gibibyte.
//! NOT responsible for: file-region responses, which leave through the gateway's self-held driver
//! on cleartext and are copied on TLS (`perf_evidence.rs`), or certificate handling (`tls_h2.rs`).
//! Upstream: `server_load.rs`. Downstream: `perf-evidence.yml`.

use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;

async fn drain<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(stream: S, expected: u64) -> u64 {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("the client connection starts");
    let connection = tokio::spawn(connection);
    let request = http::Request::builder()
        .uri("/object")
        .header("Host", "localhost")
        .header("Connection", "close")
        .body(Empty::<bytes::Bytes>::new())
        .expect("the fixture request is valid");
    let response = sender.send_request(request).await.expect("the response head reads");
    assert_eq!(response.status(), http::StatusCode::OK, "the transfer must succeed");
    let mut body = response.into_body();
    let mut received = 0_u64;
    while let Some(frame) = body.frame().await {
        if let Some(data) = frame.expect("the complete response body reads").data_ref() {
            received += data.len() as u64;
        }
    }
    assert_eq!(received, expected, "the transfer must deliver exactly its payload");
    let _ = connection.await;
    received
}

#[cfg(not(debug_assertions))]
mod release {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Instant;

    use http_body::Frame;
    use rustfs_gateway_server::{TlsHandle, TlsMaterial, WriteStrategy};
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::TlsConnector;

    use super::super::*;
    use super::drain;

    const GIB: u64 = 1 << 30;
    const CHUNK: usize = 64 * 1024;

    /// A gibibyte in 64 KiB frames, each a clone of one buffer: what is measured is the transport.
    struct Gibibyte {
        chunk: Bytes,
        remaining: u64,
    }

    impl http_body::Body for Gibibyte {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            let take = self.remaining.min(CHUNK as u64);
            self.remaining -= take;
            Poll::Ready(Some(Ok(Frame::data(self.chunk.slice(..take as usize)))))
        }

        fn size_hint(&self) -> http_body::SizeHint {
            http_body::SizeHint::with_exact(self.remaining)
        }
    }

    fn cpu() -> Option<Duration> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let fields: Vec<&str> = stat[stat.rfind(')')? + 2..].split_whitespace().collect();
        let ticks: u64 = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
        Some(Duration::from_millis(ticks * 10))
    }

    fn start(strategy: WriteStrategy, tls: Option<TlsHandle>) -> RunningServer {
        let chunk = Bytes::from(vec![b'g'; CHUNK]);
        let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
            let body = Gibibyte {
                chunk: chunk.clone(),
                remaining: GIB,
            };
            async move { Ok::<_, Infallible>(Response::new(body)) }
        });
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: tls.is_none(),
            write_strategy: strategy,
            ..ServerConfig::default()
        };
        let server = Server::new(config, service);
        match tls {
            Some(handle) => server.with_tls(handle).serve(),
            None => server.serve(),
        }
        .expect("server starts")
    }

    /// a-pf-0024. Records GiB/s and CPU per byte for each (transport, write strategy) pair and
    /// asserts that each one delivered exactly its gibibyte of payload.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pf_0024_one_gib_over_tls_records_the_flatten_cost() {
        const TEST_NAME: &str = "tls_large::release::a_pf_0024_one_gib_over_tls_records_the_flatten_cost";
        if !run_isolated(TEST_NAME).await {
            return;
        }
        let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).expect("a certificate");
        let certificate = CertificateDer::from(certified.cert.der().to_vec());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("a trust anchor");
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        for (transport, strategy) in [
            ("plaintext", WriteStrategy::Auto),
            ("tls", WriteStrategy::Auto),
            ("tls", WriteStrategy::Disabled),
        ] {
            let tls = (transport == "tls").then(|| {
                TlsHandle::new(TlsMaterial::from_der(
                    vec![certified.cert.der().to_vec()],
                    certified.signing_key.serialize_der(),
                ))
                .expect("valid material")
            });
            let running = start(strategy, tls);
            let cpu_before = cpu();
            let started = Instant::now();
            let tcp = TcpStream::connect(running.local_addr).await.expect("the client connects");
            let received = if transport == "tls" {
                let name = ServerName::try_from("localhost").expect("a name").to_owned();
                drain(connector.connect(name, tcp).await.expect("the handshake succeeds"), GIB).await
            } else {
                drain(tcp, GIB).await
            };
            let elapsed = started.elapsed();
            let cpu_ns_per_byte = cpu_before
                .zip(cpu())
                .map(|(before, after)| format!("{:.3}", (after - before).as_nanos() as f64 / GIB as f64));
            println!(
                "perf-evidence: a-pf-0024 transport={transport} write_strategy={strategy:?} payload_bytes={received} forced_flatten={} gib_s={:.2} cpu_ns_per_byte={} (client and server share this process)",
                strategy == WriteStrategy::Disabled,
                GIB as f64 / elapsed.as_secs_f64() / GIB as f64,
                cpu_ns_per_byte.unwrap_or_else(|| "unavailable".to_owned())
            );
            let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
            let _ = running.task.await;
        }
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn observe(response: Vec<u8>, fragment: usize) -> Result<u64, tokio::task::JoinError> {
        let (client, mut peer) = tokio::io::duplex(128);
        let observer = tokio::spawn(drain(client, 16));
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            peer.read_exact(&mut byte).await.expect("the fixture request arrives");
            request.push(byte[0]);
        }
        for bytes in response.chunks(fragment) {
            if peer.write_all(bytes).await.is_err() {
                break;
            }
        }
        drop(peer);
        observer.await
    }

    async fn refuses(response: Vec<u8>, reason: &str) {
        let failure = observe(response, 3)
            .await
            .expect_err("the observer must refuse this response");
        let message = failure.to_string();
        assert!(message.contains(reason), "the observer failed for the wrong reason: {message}");
    }

    fn fixed(status: &str, declared: usize, payload: usize) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n").into_bytes();
        response.extend(std::iter::repeat_n(b'g', payload));
        response
    }

    #[tokio::test]
    async fn counts_only_fragmented_http_payload() {
        for fragment in [1, 3, 128] {
            let received = observe(fixed("200 OK", 16, 16), fragment).await.expect("a complete response");
            assert_eq!(received, 16, "headers must not count as payload");
        }
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\ngggggggg\r\n8\r\ngggggggg\r\n0\r\n\r\n";
        assert_eq!(
            observe(chunked.to_vec(), 1).await.expect("a complete chunked response"),
            16,
            "chunk framing must not count as payload"
        );
    }

    #[tokio::test]
    async fn refuses_one_byte_short() {
        refuses(fixed("200 OK", 15, 15), "the transfer must deliver exactly its payload").await;
    }

    #[tokio::test]
    async fn refuses_one_byte_extra() {
        refuses(fixed("200 OK", 17, 17), "the transfer must deliver exactly its payload").await;
    }

    #[tokio::test]
    async fn refuses_truncated_fixed_body() {
        refuses(fixed("200 OK", 16, 15), "the complete response body reads").await;
    }

    #[tokio::test]
    async fn refuses_non_success_response() {
        refuses(fixed("403 Forbidden", 16, 16), "the transfer must succeed").await;
    }

    #[tokio::test]
    async fn refuses_missing_response_head() {
        refuses(vec![b'g'; 32], "the response head reads").await;
    }

    #[tokio::test]
    async fn refuses_incomplete_response_head() {
        refuses(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n".to_vec(), "the response head reads").await;
    }

    #[tokio::test]
    async fn refuses_invalid_chunk_framing() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nX\r\ngggggggggggggggg\r\n";
        refuses(response.to_vec(), "the complete response body reads").await;
    }
}

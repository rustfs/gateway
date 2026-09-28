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

    async fn drain<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: S) -> u64 {
        stream
            .write_all(b"GET /object HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("the request writes");
        let mut buffer = vec![0_u8; 256 * 1024];
        let mut total = 0_u64;
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => return total,
                Ok(read) => total += read as u64,
                // A TLS peer that closes without close_notify still delivered what was counted.
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return total,
                Err(error) => panic!("the response read failed: {error}"),
            }
        }
    }

    /// a-pf-0024. Records GiB/s and CPU per byte for each (transport, write strategy) pair and
    /// asserts that each one delivered its gibibyte plus a response head.
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
                drain(connector.connect(name, tcp).await.expect("the handshake succeeds")).await
            } else {
                drain(tcp).await
            };
            let elapsed = started.elapsed();
            let cpu_ns_per_byte = cpu_before
                .zip(cpu())
                .map(|(before, after)| format!("{:.3}", (after - before).as_nanos() as f64 / GIB as f64));
            assert!(
                received > GIB && received < GIB + 4096,
                "{transport} {strategy:?} delivered {received} bytes"
            );
            println!(
                "perf-evidence: a-pf-0024 transport={transport} write_strategy={strategy:?} forced_flatten={} gib_s={:.2} cpu_ns_per_byte={} (client and server share this process)",
                strategy == WriteStrategy::Disabled,
                GIB as f64 / elapsed.as_secs_f64() / GIB as f64,
                cpu_ns_per_byte.unwrap_or_else(|| "unavailable".to_owned())
            );
            let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
            let _ = running.task.await;
        }
    }
}

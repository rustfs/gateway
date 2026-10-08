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

//! The rustfs/backlog#1766 macro scenarios that no other evidence suite already measures.
//!
//! Responsible for: 4 KiB signed GET and PUT under 64 keep-alive connections, `ListObjectsV2` of
//! 1,000 keys under 512 concurrent connections, a 10,000-part `CompleteMultipartUpload` whose
//! client never reads the answer (a-pf-0017), and a 1 GiB `aws-chunked` signed PUT beside the
//! same gibibyte unsigned, so the share of server CPU that chunk verification costs can be read.
//! Every figure — QPS, p50/p99/p999, CPU per request or per byte — is printed on a
//! `perf-evidence:` line and never asserted; what is asserted is that every exchange succeeded and
//! the backend saw every byte and part.
//! NOT responsible for: 1 GiB GETs, PUT memory, slow clients, 1,000-connection RSS or the 4 GiB
//! chunk refusal, which `perf_evidence.rs`, `slow_clients.rs`, `server_load.rs` and the ingest
//! suites already record; or TLS, which the server crate measures.
//! Upstream: `S3Service` over the Hyper driver. Downstream: `perf-evidence.yml`.
//!
//! Release builds only, like `perf_evidence.rs`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)] // Scenario fixtures panic when setup or an exchange fails.

#[cfg(not(debug_assertions))]
mod release {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http_body_util::BodyExt;
    use rustfs_gateway::dto;
    use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
    use rustfs_gateway::{ByteStream, Handler, HandlerError, HandlerResult, Req, Resp, S3Service};
    use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use crate::support;
    use crate::support::streaming::{StreamingOutput, StreamingPut, streaming_dialect};

    const SMALL: usize = 4 * 1024;
    const GIB: usize = 1 << 30;

    // -----------------------------------------------------------------------------------------
    // Instruments
    // -----------------------------------------------------------------------------------------

    /// User plus system CPU time this process has used, from `/proc/self/stat` (Linux only).
    fn cpu() -> Option<Duration> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let after_name = &stat[stat.rfind(')')? + 2..];
        let fields: Vec<&str> = after_name.split_whitespace().collect();
        let ticks: u64 = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
        // USER_HZ is 100 on every Linux ABI this runs on.
        Some(Duration::from_millis(ticks * 10))
    }

    fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
        sorted[(sorted.len() * per_mille / 1000).min(sorted.len() - 1)]
    }

    fn latencies(mut samples: Vec<Duration>) -> String {
        samples.sort_unstable();
        format!(
            "p50_us={} p99_us={} p999_us={}",
            percentile(&samples, 500).as_micros(),
            percentile(&samples, 990).as_micros(),
            percentile(&samples, 999).as_micros()
        )
    }

    fn server(service: S3Service) -> RunningServer {
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            tcp_nodelay: true,
            max_connections: 4_096,
            max_connections_per_ip: None,
            backlog: 1_024,
            ..ServerConfig::default()
        };
        Server::new(config, service).serve().expect("the scenario server starts")
    }

    async fn stop(running: RunningServer) {
        let _ = running.shutdown.trigger(Duration::from_secs(5)).await;
        let _ = running.task.await;
    }

    /// Serialises a signed in-memory request as one keep-alive HTTP/1.1 exchange.
    fn wire(request: &http::Request<Bytes>) -> Vec<u8> {
        let mut out = format!("{} {} HTTP/1.1\r\n", request.method(), request.uri()).into_bytes();
        for (name, value) in request.headers() {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if request.headers().get(http::header::CONTENT_LENGTH).is_none() {
            out.extend_from_slice(format!("content-length: {}\r\n", request.body().len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(request.body());
        out
    }

    /// Reads one `Content-Length`-framed response and returns its status and body length.
    async fn read_response(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> (u16, usize) {
        let mut chunk = [0_u8; 64 * 1024];
        let head_end = loop {
            if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
            let read = stream.read(&mut chunk).await.expect("the response reads");
            assert!(read > 0, "the connection closed before a response head");
            buffer.extend_from_slice(&chunk[..read]);
        };
        let head = std::str::from_utf8(&buffer[..head_end])
            .expect("an ASCII head")
            .to_ascii_lowercase();
        let status = head[9..12].parse().expect("a status code");
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map_or(0, |value| value.trim().parse().expect("a content length"));
        while buffer.len() < head_end + length {
            let read = stream.read(&mut chunk).await.expect("the body reads");
            assert!(read > 0, "the connection closed inside a response body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        buffer.drain(..head_end + length);
        (status, length)
    }

    /// `connections` keep-alive clients each sending `request` `rounds` times; every answer must
    /// be `200`. Returns one line of figures.
    async fn load(addr: SocketAddr, request: Arc<Vec<u8>>, connections: usize, rounds: usize) -> String {
        let cpu_before = cpu();
        let started = Instant::now();
        // Connected one after another before any request is sent: a burst of hundreds of
        // simultaneous SYNs measures the host's listen backlog, not the gateway.
        let mut streams = Vec::with_capacity(connections);
        for _ in 0..connections {
            let stream = TcpStream::connect(addr).await.expect("a client connects");
            stream.set_nodelay(true).expect("nodelay");
            streams.push(stream);
        }
        let mut clients = Vec::with_capacity(connections);
        for mut stream in streams {
            let request = Arc::clone(&request);
            clients.push(tokio::spawn(async move {
                let mut buffer = Vec::with_capacity(64 * 1024);
                let mut samples = Vec::with_capacity(rounds);
                let mut bytes = 0;
                for _ in 0..rounds {
                    let sent = Instant::now();
                    stream.write_all(&request).await.expect("the request writes");
                    let (status, length) = read_response(&mut stream, &mut buffer).await;
                    assert_eq!(status, 200, "a scenario exchange failed");
                    samples.push(sent.elapsed());
                    bytes += length;
                }
                (samples, bytes)
            }));
        }
        let mut samples = Vec::with_capacity(connections * rounds);
        let mut bytes = 0;
        for client in clients {
            let (mine, received) = client.await.expect("a client task joins");
            samples.extend(mine);
            bytes += received;
        }
        let elapsed = started.elapsed();
        let requests = samples.len();
        let cpu_per_request = cpu_before
            .zip(cpu())
            .map(|(before, after)| format!("{}", (after - before).as_micros() as f64 / requests as f64));
        format!(
            "requests={requests} connections={connections} qps={:.0} {} response_bytes={bytes} cpu_us_per_request={} (client and server share this process)",
            requests as f64 / elapsed.as_secs_f64(),
            latencies(samples),
            cpu_per_request.unwrap_or_else(|| "unavailable".to_owned())
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime")
    }

    // -----------------------------------------------------------------------------------------
    // Backends
    // -----------------------------------------------------------------------------------------

    struct Objects {
        put_bytes: AtomicU64,
        listed: Vec<dto::Object>,
    }

    impl Objects {
        fn new() -> Arc<Self> {
            let listed = (0..1_000)
                .map(|index| dto::Object {
                    key: rustfs_gateway::ObjectKey::new(format!("photos/2026/09/{index:06}.jpg")).expect("a key"),
                    last_modified: rustfs_gateway::Timestamp::from_secs(1_767_225_600 + index),
                    e_tag: rustfs_gateway::ETag::new(format!("\"{index:032x}\"")).expect("an entity tag"),
                    size: 4096,
                    ..dto::Object::default()
                })
                .collect();
            Arc::new(Self {
                put_bytes: AtomicU64::new(0),
                listed,
            })
        }
    }

    impl Handler<dto::GetObject> for Objects {
        async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
            static BODY: [u8; SMALL] = [0x5a; SMALL];
            Ok(Resp::new(dto::GetObjectOutput {
                body: Some(ByteStream::from_bytes(Bytes::from_static(&BODY))),
                content_length: Some(SMALL as i64),
                ..dto::GetObjectOutput::default()
            }))
        }
    }

    impl Handler<dto::PutObject> for Objects {
        async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
            let body = request.into_input().body;
            let mut body = body.ok_or_else(|| HandlerError::internal_error("no body"))?.into_body();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the body failed"))?;
                if let Ok(data) = frame.into_data() {
                    self.put_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }

    impl Handler<dto::ListObjectsV2> for Objects {
        async fn call(&self, request: Req<dto::ListObjectsV2>) -> HandlerResult<dto::ListObjectsV2> {
            Ok(Resp::new(dto::ListObjectsV2Output {
                name: request.input().bucket.clone(),
                max_keys: 1_000,
                key_count: 1_000,
                contents: self.listed.clone(),
                ..dto::ListObjectsV2Output::default()
            }))
        }
    }

    struct Completer {
        parts: AtomicUsize,
        completed: AtomicUsize,
    }

    impl Handler<dto::CompleteMultipartUpload> for Completer {
        async fn call(&self, request: Req<dto::CompleteMultipartUpload>) -> HandlerResult<dto::CompleteMultipartUpload> {
            let parts = request.input().multipart_upload.parts.len();
            self.parts.store(parts, Ordering::SeqCst);
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(Resp::new(dto::CompleteMultipartUploadOutput::default()))
        }
    }

    struct Counting {
        bytes: AtomicU64,
    }

    impl Handler<StreamingPut> for Counting {
        async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
            let mut body = request.into_input().body.into_body();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the body failed"))?;
                if let Ok(data) = frame.into_data() {
                    self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            Ok(Resp::new(StreamingOutput))
        }
    }

    fn objects_service(objects: &Arc<Objects>) -> S3Service {
        support::wired_at_signed_time()
            .register::<dto::GetObject, _>(Arc::clone(objects))
            .register::<dto::PutObject, _>(Arc::clone(objects))
            .register::<dto::ListObjectsV2, _>(Arc::clone(objects))
            .framework_governor_rates(rustfs_gateway::GovernorRates {
                aggregate: rustfs_gateway::Rate::new(u32::MAX, u32::MAX),
                per_ip: rustfs_gateway::Rate::new(u32::MAX, u32::MAX),
                credential_lookup: rustfs_gateway::Rate::new(u32::MAX, u32::MAX),
                cors_preflight: rustfs_gateway::Rate::new(u32::MAX, u32::MAX),
                unauthenticated: rustfs_gateway::Rate::new(u32::MAX, u32::MAX),
                ..rustfs_gateway::GovernorRates::default()
            })
            .build()
            .expect("a complete assembly")
    }

    // -----------------------------------------------------------------------------------------
    // Scenarios
    // -----------------------------------------------------------------------------------------

    /// Small objects: 4 KiB signed GET and PUT, 64 keep-alive connections × 250 requests each.
    #[test]
    fn small_object_get_and_put_under_keep_alive_load() {
        runtime().block_on(async {
            let objects = Objects::new();
            let running = server(objects_service(&objects));
            let get = Arc::new(wire(&support::signed(http::Method::GET, "/bucket/key")));
            let body = Bytes::from(vec![0x33_u8; SMALL]);
            let put = Arc::new(wire(&support::signed_target_with_body_and_headers(
                http::Method::PUT,
                "/bucket/key",
                &[("content-length", "4096")],
                body,
            )));
            let _ = load(running.local_addr, Arc::clone(&get), 8, 20).await;
            println!("perf-evidence: macro/small_get_4k {}", load(running.local_addr, get, 64, 250).await);
            println!("perf-evidence: macro/small_put_4k {}", load(running.local_addr, put, 64, 250).await);
            assert_eq!(
                objects.put_bytes.load(Ordering::Relaxed),
                (64 * 250 * SMALL) as u64,
                "every PUT byte arrived"
            );
            stop(running).await;
        });
    }

    /// `ListObjectsV2` of 1,000 keys, 512 concurrent connections × 4 requests each.
    #[test]
    fn list_objects_v2_of_a_thousand_keys_under_512_connections() {
        runtime().block_on(async {
            let objects = Objects::new();
            let running = server(objects_service(&objects));
            let list = Arc::new(wire(&support::signed(http::Method::GET, "/bucket?list-type=2")));
            let _ = load(running.local_addr, Arc::clone(&list), 8, 4).await;
            println!(
                "perf-evidence: macro/list_objects_v2_1000x512 {}",
                load(running.local_addr, list, 512, 4).await
            );
            stop(running).await;
        });
    }

    /// a-pf-0017: a 10,000-part `CompleteMultipartUpload` whose client never reads the answer
    /// still reaches the backend with every part: completion is not held hostage to the response
    /// being consumed.
    #[test]
    fn a_ten_thousand_part_completion_proceeds_while_the_client_reads_nothing() {
        runtime().block_on(async {
            let completer = Arc::new(Completer {
                parts: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
            });
            let service = support::wired_at_signed_time()
                .register::<dto::CompleteMultipartUpload, _>(Arc::clone(&completer))
                .build()
                .expect("a complete assembly");
            let running = server(service);
            let mut document = String::from("<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
            for part in 1..=10_000 {
                document.push_str(&format!("<Part><PartNumber>{part}</PartNumber><ETag>\"{part:032x}\"</ETag></Part>"));
            }
            document.push_str("</CompleteMultipartUpload>");
            let length = document.len().to_string();
            let request = wire(&support::signed_target_with_body_and_headers(
                http::Method::POST,
                "/bucket/key?uploadId=upload-1",
                &[("content-length", length.as_str())],
                Bytes::from(document),
            ));
            let started = Instant::now();
            let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
            stream.write_all(&request).await.expect("the request writes");
            // From here the client never reads a byte.
            let deadline = Instant::now() + Duration::from_secs(60);
            while completer.completed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let reached = started.elapsed();
            assert_eq!(completer.completed.load(Ordering::SeqCst), 1, "the backend never completed the upload");
            assert_eq!(completer.parts.load(Ordering::SeqCst), 10_000, "the backend saw every part");
            println!(
                "perf-evidence: macro/complete_multipart_10000_unread backend_completed_ms={} request_bytes={} client_read_bytes=0",
                reached.as_millis(),
                request.len()
            );
            drop(stream);
            stop(running).await;
        });
    }

    /// A header-signed `PUT /` of `wire_len` wire bytes under `payload`, and the signer that made it.
    fn signed_put(
        payload: PayloadMode,
        wire_len: usize,
        decoded_len: Option<usize>,
    ) -> (rustfs_gateway::sig::SignedRequest, SigV4Signer) {
        let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
        let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
        let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
        let mut signer = SigV4Signer::new(credentials, scope);
        let probe = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/")
            .header("host", "localhost")
            .body(())
            .expect("a valid request");
        let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("a host");
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_static("localhost"));
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_len));
        let mut signing =
            SigningRequest::new(&http::Method::PUT, "/", "", &headers, accepted.host().raw_for_signing(), payload, stamp)
                .with_wire_content_length(wire_len as u64);
        if let Some(decoded_len) = decoded_len {
            signing = signing.with_decoded_content_length(decoded_len as u64);
        }
        let signed = signer.sign_headers(&signing).expect("a signable request");
        (signed, signer)
    }

    /// The signed `aws-chunked` wire for `decoded` bytes in 64 KiB chunks, and its request head.
    fn signed_chunked(decoded: &[u8]) -> (Vec<u8>, Vec<u8>) {
        const CHUNK: usize = 64 * 1024;
        let wire_len = decoded
            .chunks(CHUNK)
            .map(|chunk| chunk.len() + format!("{:x}", chunk.len()).len() + 17 + 64 + 4)
            .sum::<usize>()
            + 1
            + 17
            + 64
            + 4;
        let (signed, mut signer) = signed_put(
            PayloadMode::StreamingSigned {
                trailer: rustfs_gateway::sig::TrailerSet::None,
            },
            wire_len,
            Some(decoded.len()),
        );
        let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
        let mut body = Vec::with_capacity(wire_len);
        for chunk in decoded.chunks(CHUNK) {
            body.extend_from_slice(&chain.encode_chunk(chunk));
        }
        body.extend_from_slice(&chain.encode_chunk(b""));
        assert_eq!(body.len(), wire_len);
        (head(&signed.headers().clone()), body)
    }

    fn head(headers: &http::HeaderMap) -> Vec<u8> {
        let mut out = b"PUT / HTTP/1.1\r\n".to_vec();
        for (name, value) in headers {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"connection: close\r\n\r\n");
        out
    }

    /// Sends a prepared head and body once and returns elapsed time and process CPU used.
    async fn upload(addr: SocketAddr, head: &[u8], body: &[u8]) -> (Duration, Option<Duration>) {
        let cpu_before = cpu();
        let started = Instant::now();
        let mut stream = TcpStream::connect(addr).await.expect("the client connects");
        stream.write_all(head).await.expect("the head writes");
        stream.write_all(body).await.expect("the body writes");
        let mut buffer = Vec::new();
        let (status, _) = read_response(&mut stream, &mut buffer).await;
        assert_eq!(status, 200, "the upload was refused");
        (started.elapsed(), cpu_before.zip(cpu()).map(|(before, after)| after - before))
    }

    /// 1 GiB `aws-chunked` signed PUT beside the same gibibyte `UNSIGNED-PAYLOAD`. Both bodies are
    /// prepared before the clock starts, so the CPU difference between the two is the server's
    /// chunk decoding and verification, not the client's signing.
    #[test]
    fn one_gib_aws_chunked_signed_put_and_its_verification_cost() {
        runtime().block_on(async {
            let counting = Arc::new(Counting { bytes: AtomicU64::new(0) });
            let service = support::wired_at_signed_time()
                .register::<StreamingPut, _>(Arc::clone(&counting))
                .dialect(&streaming_dialect())
                .build()
                .expect("a complete assembly");
            let running = server(service);
            let decoded: Vec<u8> = (0..GIB).map(|index| (index % 251) as u8).collect();
            let (signed_head, signed_body) = signed_chunked(&decoded);
            let (unsigned, _) = signed_put(PayloadMode::Unsigned, GIB, None);
            let unsigned_head = head(unsigned.headers());

            let (signed_time, signed_cpu) = upload(running.local_addr, &signed_head, &signed_body).await;
            assert_eq!(counting.bytes.swap(0, Ordering::SeqCst), GIB as u64, "every signed byte arrived");
            let (unsigned_time, unsigned_cpu) = upload(running.local_addr, &unsigned_head, &decoded).await;
            assert_eq!(counting.bytes.swap(0, Ordering::SeqCst), GIB as u64, "every unsigned byte arrived");
            let gib_per_s = |time: Duration| GIB as f64 / time.as_secs_f64() / GIB as f64;
            let share = signed_cpu.zip(unsigned_cpu).map(|(signed, unsigned)| {
                format!("{:.3}", signed.saturating_sub(unsigned).as_secs_f64() / signed.as_secs_f64().max(f64::MIN_POSITIVE))
            });
            println!(
                "perf-evidence: macro/put_1gib_aws_chunked_signed signed_gib_s={:.2} unsigned_gib_s={:.2} signed_cpu_ms={} unsigned_cpu_ms={} verification_cpu_share={}",
                gib_per_s(signed_time),
                gib_per_s(unsigned_time),
                signed_cpu.map_or_else(|| "unavailable".to_owned(), |cpu| cpu.as_millis().to_string()),
                unsigned_cpu.map_or_else(|| "unavailable".to_owned(), |cpu| cpu.as_millis().to_string()),
                share.unwrap_or_else(|| "unavailable".to_owned())
            );
            stop(running).await;
        });
    }
}

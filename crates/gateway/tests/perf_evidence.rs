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

//! One-gibibyte transfers observed from outside the code that performs them.
//!
//! Responsible for: what a 1 GiB GET and a 1 GiB PUT actually cost on both production drivers —
//! which syscalls moved the bytes (`strace`), how far the resident set rose (`VmHWM` after a
//! reset), how many bytes the allocator handed out, and whether the transport counters agree
//! with all three (rustfs/backlog#1740 a-zc-0002..0004, rustfs/backlog#1766 a-pf-0005, 0006,
//! 0010, 0013). The copying controls are the same driver forced onto its read-and-copy path by a
//! verification obligation, and a real `GetObject` handler's file region served by the default
//! Hyper driver, which copies it once on the blocking pool (rustfs/gateway#949).
//! NOT responsible for: throughput thresholds. Elapsed time is printed as a record and never
//! asserted; the release-only `perf-evidence.yml` workflow runs this file, and the PR gate does not.
//! Upstream: `SelfHeldHttp1Driver`, the default Hyper driver, `rustfs-gateway-stream` payloads.
//! Downstream: the numbers recorded on the backlog issues and `docs/capacity-planning.md`.
//!
//! Every case re-executes this binary alone, optionally under `strace -f`, because a resident-set
//! or allocator reading taken beside other tests measures the other tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)] // Probe fixtures panic when setup or a measured invariant fails.

#[cfg(not(debug_assertions))]
mod release {
    use std::convert::Infallible;
    use std::fs::{File, OpenOptions};
    use std::future::{Ready, ready};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use http::{Request, Response, StatusCode, header};
    use http_body_util::BodyExt;
    use rustfs_gateway::{Body, ResponseTransportMetrics, SelfHeldHttp1Driver};
    use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
    use rustfs_gateway_stream::{FileRegion, Payload, StreamMetrics};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tower::Service;

    const GIB: u64 = 1024 * 1024 * 1024;
    const BLOCK: usize = 1024 * 1024;
    const CHILD_ENV: &str = "RUSTFS_GATEWAY_PERF_EVIDENCE_CHILD";
    const FIXTURE_ENV: &str = "RUSTFS_GATEWAY_PERF_EVIDENCE_FIXTURE";
    /// Set by the workflow: a missing `strace` fails the case instead of skipping the syscall half.
    const REQUIRE_STRACE_ENV: &str = "RUSTFS_GATEWAY_PERF_EVIDENCE_REQUIRE_STRACE";
    const SENTINEL: &str = "perf-evidence: ";
    /// a-zc-0004: what a transfer may add to the resident set. A driver that read the file into user
    /// space in 64 KiB pieces and dropped each one would still fit; one that buffered any meaningful
    /// fraction of a gibibyte would not.
    const RESIDENT_BUDGET: u64 = 8 * 1024 * 1024;
    /// a-zc-0003: every byte a `write`-family syscall may carry while the body goes through
    /// `sendfile`: the response head and the client's request line, nothing of the body.
    const HEAD_WRITE_BUDGET: u64 = 64 * 1024;

    /// The byte at `offset` of every fixture. A function of position, so a reordered, repeated or
    /// shifted block is caught by the reader and not only a short one.
    fn pattern(offset: u64) -> u8 {
        (offset % 251) as u8 ^ (offset >> 20) as u8
    }

    fn fill(block: &mut [u8], base: u64) {
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = pattern(base + index as u64);
        }
    }

    /// A 1 GiB file written by the parent, so the child's resident set never held it.
    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!("rustfs-gateway-perf-evidence-{}", std::process::id()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("the fixture path is unique");
            let mut block = vec![0_u8; BLOCK];
            let mut base = 0;
            while base < GIB {
                fill(&mut block, base);
                file.write_all(&block).expect("fixture bytes are written");
                base += BLOCK as u64;
            }
            file.sync_all().expect("the fixture reaches the page cache and disk");
            Self { path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Serves the whole fixture as a file-backed payload for any GET, and drains a PUT body.
    #[derive(Clone)]
    struct EvidenceService {
        path: Arc<PathBuf>,
        stream_metrics: Arc<StreamMetrics>,
        /// Marks the GET body as still owing verification, which forbids the kernel path.
        copy: bool,
    }

    impl<B> Service<Request<B>> for EvidenceService
    where
        B: http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
        B::Error: std::fmt::Debug,
    {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<B>) -> Self::Future {
            if request.method() == http::Method::PUT {
                return Box::pin(drain_put(request.into_body()));
            }
            let response: Ready<Result<Response<Body>, Infallible>> = {
                let file = File::open(self.path.as_ref()).expect("the fixture remains openable");
                let region = FileRegion::new(OwnedFd::from(file), 0, GIB).expect("the fixture range does not overflow");
                let body = Body::from_payload_with_metrics(Payload::File(region), Arc::clone(&self.stream_metrics));
                let body = if self.copy { body.requiring_verification() } else { body };
                ready(Ok(Response::builder()
                    .header(header::CONTENT_LENGTH, GIB)
                    .body(body)
                    .expect("the fixture response is valid")))
            };
            Box::pin(response)
        }
    }

    /// Reads a PUT body frame by frame and checks every byte against the fixture pattern, holding no
    /// frame longer than it takes to check it.
    async fn drain_put<B>(mut body: B) -> Result<Response<Body>, Infallible>
    where
        B: http_body::Body<Data = bytes::Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        let mut offset = 0_u64;
        let mut frames = 0_u64;
        while let Some(frame) = body.frame().await {
            let frame = frame.expect("the PUT body reads without error");
            let Ok(data) = frame.into_data() else { continue };
            frames += 1;
            for byte in data.iter() {
                assert_eq!(*byte, pattern(offset), "PUT byte {offset} arrived wrong");
                offset += 1;
            }
        }
        let status = if offset == GIB {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        };
        let summary = format!("received={offset} frames={frames}");
        Ok(Response::builder()
            .status(status)
            .header(header::CONTENT_LENGTH, summary.len())
            .body(Body::from_bytes(bytes::Bytes::from(summary)))
            .expect("the PUT summary response is valid"))
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Driver {
        SelfHeld,
        Hyper,
    }

    fn start(driver: Driver, service: EvidenceService, transport: &Arc<ResponseTransportMetrics>) -> RunningServer {
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            tcp_nodelay: true,
            ..ServerConfig::default()
        };
        match driver {
            Driver::SelfHeld => Server::new(config, service).serve_with(SelfHeldHttp1Driver::with_metrics(Arc::clone(transport))),
            Driver::Hyper => Server::new(config, service).serve(),
        }
        .expect("the evidence server starts")
    }

    /// `VmRSS` and `VmHWM` in bytes, from `/proc/self/status`.
    fn resident() -> Option<(u64, u64)> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|kib| kib.parse::<u64>().ok())
                .map(|kib| kib * 1024)
        };
        Some((field("VmRSS:")?, field("VmHWM:")?))
    }

    /// Resets the peak so `VmHWM` afterwards is the peak of the transfer alone (Linux 4.0+).
    fn reset_peak() -> bool {
        std::fs::write("/proc/self/clear_refs", "5").is_ok()
    }

    async fn read_head(client: &mut TcpStream, buffer: &mut Vec<u8>) -> (StatusCode, usize) {
        let mut chunk = [0_u8; 4096];
        loop {
            let read = client.read(&mut chunk).await.expect("the response head reads");
            assert!(read > 0, "the connection closed before a response head");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let status = std::str::from_utf8(&buffer[9..12])
                    .expect("a status code")
                    .parse::<u16>()
                    .expect("a status code");
                return (StatusCode::from_u16(status).expect("a valid status"), end + 4);
            }
        }
    }

    /// How a GET case serves the fixture.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum GetMode {
        /// A raw service on the self-held driver.
        Kernel,
        /// The same, with a verification obligation that forbids the kernel path.
        ForcedCopy,
        /// A real `GetObject` handler answering with a file region, through `S3Service` on Hyper.
        HyperS3,
    }

    /// Answers every signed `GetObject` with the whole fixture as a file region.
    struct FileObject {
        path: PathBuf,
        metrics: Arc<StreamMetrics>,
    }

    impl rustfs_gateway::Handler<rustfs_gateway::dto::GetObject> for FileObject {
        async fn call(
            &self,
            _request: rustfs_gateway::Req<rustfs_gateway::dto::GetObject>,
        ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::GetObject> {
            let file = File::open(&self.path).expect("the fixture remains openable");
            let region = FileRegion::new(OwnedFd::from(file), 0, GIB).expect("the fixture range does not overflow");
            Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::GetObjectOutput {
                body: Some(rustfs_gateway::ByteStream::from_file_region(region, Arc::clone(&self.metrics))),
                content_length: Some(GIB as i64),
                ..rustfs_gateway::dto::GetObjectOutput::default()
            }))
        }
    }

    fn signed_get_head() -> Vec<u8> {
        let signed = crate::support::signed(http::Method::GET, "/bucket/object");
        let mut head = format!("GET {} HTTP/1.1\r\n", signed.uri());
        for (name, value) in signed.headers() {
            head.push_str(&format!("{name}: {}\r\n", value.to_str().expect("an ASCII header")));
        }
        head.push_str("connection: close\r\n\r\n");
        head.into_bytes()
    }

    /// Child role: one GET of the whole fixture, verified byte by byte on arrival.
    async fn get_once(mode: GetMode, fixture: &Path) -> Vec<(&'static str, String)> {
        let stream_metrics = Arc::new(StreamMetrics::new());
        let transport = Arc::new(ResponseTransportMetrics::new());
        let (running, request) = if mode == GetMode::HyperS3 {
            let service = crate::support::wired_at_signed_time()
                .register::<rustfs_gateway::dto::GetObject, _>(Arc::new(FileObject {
                    path: fixture.to_owned(),
                    metrics: Arc::clone(&stream_metrics),
                }))
                .build()
                .expect("a complete assembly");
            let config = ServerConfig {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                plaintext: true,
                tcp_nodelay: true,
                ..ServerConfig::default()
            };
            (
                Server::new(config, service).serve().expect("the evidence server starts"),
                signed_get_head(),
            )
        } else {
            let service = EvidenceService {
                path: Arc::new(fixture.to_owned()),
                stream_metrics: Arc::clone(&stream_metrics),
                copy: mode == GetMode::ForcedCopy,
            };
            (
                start(Driver::SelfHeld, service, &transport),
                b"GET /object HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            )
        };
        let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
        let mut buffer = Vec::with_capacity(256 * 1024);
        let mut chunk = vec![0_u8; 256 * 1024];
        let peak_reset = reset_peak();
        let before = resident();
        let started = Instant::now();
        client.write_all(&request).await.expect("the request writes");
        let (status, head_len) = read_head(&mut client, &mut buffer).await;
        assert_eq!(status, StatusCode::OK);
        let mut offset = 0_u64;
        for byte in &buffer[head_len..] {
            assert_eq!(*byte, pattern(offset), "GET byte {offset} arrived wrong");
            offset += 1;
        }
        loop {
            let read = client.read(&mut chunk).await.expect("the body reads");
            if read == 0 {
                break;
            }
            for byte in &chunk[..read] {
                assert_eq!(*byte, pattern(offset), "GET byte {offset} arrived wrong");
                offset += 1;
            }
        }
        let elapsed = started.elapsed();
        let after = resident();
        assert_eq!(offset, GIB, "the GET body is exactly the fixture, not {offset} bytes");
        let _ = running.shutdown.trigger(Duration::from_secs(5)).await;
        let _ = running.task.await;
        let mut fields = vec![
            ("body_bytes", offset.to_string()),
            ("elapsed_ms", elapsed.as_millis().to_string()),
            ("mib_per_s", format!("{:.1}", GIB as f64 / 1_048_576.0 / elapsed.as_secs_f64())),
            ("kernel_transfer_calls", transport.kernel_transfer_calls().to_string()),
            ("kernel_transferred_bytes", transport.kernel_transferred_bytes().to_string()),
            ("copied_payload_bytes", transport.copied_payload_bytes().to_string()),
            ("fallback_responses", transport.fallback_responses_total().to_string()),
            ("adapt_copies_total", stream_metrics.adapt_copies_total().to_string()),
            ("adapt_copied_bytes_total", stream_metrics.adapt_copied_bytes_total().to_string()),
            ("zero_copy_refusals_total", stream_metrics.zero_copy_refusals_total().to_string()),
        ];
        push_resident(&mut fields, peak_reset, before, after);
        fields
    }

    /// Child role: one PUT of 1 GiB, streamed from a reused 1 MiB buffer and checked by the service.
    async fn put_once(driver: Driver, fixture: &Path) -> Vec<(&'static str, String)> {
        let service = EvidenceService {
            path: Arc::new(fixture.to_owned()),
            stream_metrics: Arc::new(StreamMetrics::new()),
            copy: false,
        };
        let transport = Arc::new(ResponseTransportMetrics::new());
        let running = start(driver, service, &transport);
        let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
        let mut block = vec![0_u8; BLOCK];
        let mut buffer = Vec::with_capacity(4096);
        let peak_reset = reset_peak();
        let before = resident();
        let profiler = dhat::Profiler::builder().testing().build();
        let heap_before = dhat::HeapStats::get();
        let started = Instant::now();
        client
            .write_all(
                format!("PUT /object HTTP/1.1\r\nHost: localhost\r\nContent-Length: {GIB}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("the request head writes");
        let mut base = 0;
        while base < GIB {
            fill(&mut block, base);
            client.write_all(&block).await.expect("the request body writes");
            base += BLOCK as u64;
        }
        let (status, head_len) = read_head(&mut client, &mut buffer).await;
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.expect("the summary reads");
        let elapsed = started.elapsed();
        let heap_after = dhat::HeapStats::get();
        drop(profiler);
        let after = resident();
        buffer.extend_from_slice(&rest);
        let summary = String::from_utf8_lossy(&buffer[head_len..]).into_owned();
        assert_eq!(status, StatusCode::OK, "the PUT was not received whole: {summary}");
        let _ = running.shutdown.trigger(Duration::from_secs(5)).await;
        let _ = running.task.await;
        let frames = summary
            .split_whitespace()
            .find_map(|field| field.strip_prefix("frames="))
            .unwrap_or("0")
            .to_owned();
        let mut fields = vec![
            ("body_bytes", GIB.to_string()),
            ("frames", frames),
            ("elapsed_ms", elapsed.as_millis().to_string()),
            ("mib_per_s", format!("{:.1}", GIB as f64 / 1_048_576.0 / elapsed.as_secs_f64())),
            ("heap_blocks", (heap_after.total_blocks - heap_before.total_blocks).to_string()),
            ("heap_bytes", (heap_after.total_bytes - heap_before.total_bytes).to_string()),
            ("heap_peak_bytes", heap_after.max_bytes.to_string()),
        ];
        push_resident(&mut fields, peak_reset, before, after);
        fields
    }

    fn push_resident(
        fields: &mut Vec<(&'static str, String)>,
        peak_reset: bool,
        before: Option<(u64, u64)>,
        after: Option<(u64, u64)>,
    ) {
        if let (true, Some((rss_before, _)), Some((rss_after, peak))) = (peak_reset, before, after) {
            fields.push(("rss_before", rss_before.to_string()));
            fields.push(("rss_after", rss_after.to_string()));
            fields.push(("rss_peak", peak.to_string()));
            fields.push(("rss_peak_growth", peak.saturating_sub(rss_before).to_string()));
        }
    }

    /// What `strace -f` saw the child do: bytes returned per syscall family.
    #[derive(Debug, Default)]
    struct Syscalls {
        sendfile_calls: u64,
        sendfile_bytes: u64,
        write_calls: u64,
        write_bytes: u64,
    }

    fn parse_trace(trace: &str) -> Syscalls {
        let mut syscalls = Syscalls::default();
        for line in trace.lines() {
            let body = line.split_once(' ').map_or(line, |(_, rest)| rest).trim_start();
            let name = match body.strip_prefix("<... ") {
                Some(resumed) => resumed.split_whitespace().next().unwrap_or(""),
                None => body.split('(').next().unwrap_or(""),
            };
            let Some(result) = body.rsplit_once(" = ").map(|(_, result)| result) else { continue };
            let Ok(bytes) = result.split_whitespace().next().unwrap_or("").parse::<i64>() else { continue };
            let Ok(bytes) = u64::try_from(bytes) else { continue };
            match name {
                "sendfile" | "sendfile64" => {
                    syscalls.sendfile_calls += 1;
                    syscalls.sendfile_bytes += bytes;
                }
                "write" | "writev" | "pwrite64" | "pwritev" | "sendto" | "sendmsg" => {
                    syscalls.write_calls += 1;
                    syscalls.write_bytes += bytes;
                }
                _ => {}
            }
        }
        syscalls
    }

    fn strace_available() -> bool {
        cfg!(target_os = "linux")
            && Command::new("strace")
                .arg("-V")
                .output()
                .is_ok_and(|output| output.status.success())
    }

    /// Parent role: runs `test` as a child against a fresh fixture, under `strace` when it can.
    fn run_child(test: &str, fixture: &Fixture) -> (Vec<(String, String)>, Option<Syscalls>) {
        let executable = std::env::current_exe().expect("the test binary has a path");
        let traced = strace_available();
        if !traced && std::env::var_os(REQUIRE_STRACE_ENV).is_some() {
            panic!("{REQUIRE_STRACE_ENV} is set but strace is not runnable on this host");
        }
        let trace_path = fixture.path.with_extension("strace");
        let mut command = if traced {
            let mut command = Command::new("strace");
            command
                .args(["-f", "-qq", "-e", "signal=none", "-e"])
                .arg("trace=sendfile,sendfile64,write,writev,pwrite64,pwritev,sendto,sendmsg")
                .arg("-o")
                .arg(&trace_path)
                .arg(&executable);
            command
        } else {
            Command::new(&executable)
        };
        let output = command
            .args(["--exact", test, "--nocapture", "--test-threads", "1"])
            .env(CHILD_ENV, test)
            .env(FIXTURE_ENV, &fixture.path)
            .output()
            .expect("the evidence child starts");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "the evidence child failed:\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = stdout
            .lines()
            .find_map(|line| line.find(SENTINEL).map(|start| &line[start + SENTINEL.len()..]))
            .unwrap_or_else(|| panic!("the evidence child printed no observation:\n{stdout}"));
        println!("{SENTINEL}{test} {line}");
        let fields = line
            .split_whitespace()
            .filter_map(|field| field.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        let syscalls = traced.then(|| {
            let trace = std::fs::read_to_string(&trace_path).expect("strace wrote its trace");
            let _ = std::fs::remove_file(&trace_path);
            let syscalls = parse_trace(&trace);
            println!("{SENTINEL}{test} syscalls {syscalls:?}");
            syscalls
        });
        if !traced {
            eprintln!("SKIP {test} syscall half: strace is not runnable here; the counter and memory halves still ran");
        }
        (fields, syscalls)
    }

    fn value(fields: &[(String, String)], key: &str) -> u64 {
        fields
            .iter()
            .find(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("the observation has no {key}: {fields:?}"))
            .1
            .parse()
            .unwrap_or_else(|_| panic!("{key} is not a number: {fields:?}"))
    }

    fn assert_resident(test: &str, fields: &[(String, String)]) {
        if fields.iter().any(|(name, _)| name == "rss_peak_growth") {
            let growth = value(fields, "rss_peak_growth");
            assert!(
                growth <= RESIDENT_BUDGET,
                "{test}: a 1 GiB transfer raised the resident peak by {growth} bytes, past {RESIDENT_BUDGET}: {fields:?}"
            );
        } else {
            eprintln!("SKIP {test} resident set: this host has no resettable /proc/self peak; nothing about memory was asserted");
        }
    }

    /// Runs the child half of `test` when this process is that child. Returns whether it did.
    fn child(test: &str, work: impl FnOnce(&Path) -> Vec<(&'static str, String)>) -> bool {
        if std::env::var(CHILD_ENV).as_deref() != Ok(test) {
            return false;
        }
        let fixture = PathBuf::from(std::env::var_os(FIXTURE_ENV).expect("the parent names the fixture"));
        let fields = work(&fixture);
        let line = fields
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("{SENTINEL}{line}");
        true
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime")
    }

    /// a-zc-0002, a-zc-0003, a-zc-0004, a-pf-0005: a 1 GiB file leaves the self-held driver through
    /// the kernel. Every body byte is returned by `sendfile`, `write`-family syscalls carry only heads,
    /// no payload byte is copied through user space, and the resident peak barely moves.
    #[test]
    fn one_gib_get_on_the_self_held_driver_moves_no_byte_through_user_space() {
        const TEST: &str = "perf_evidence::release::one_gib_get_on_the_self_held_driver_moves_no_byte_through_user_space";
        if child(TEST, |fixture| runtime().block_on(get_once(GetMode::Kernel, fixture))) {
            return;
        }
        let fixture = Fixture::create();
        let (fields, syscalls) = run_child(TEST, &fixture);
        assert_eq!(value(&fields, "body_bytes"), GIB);
        assert_eq!(value(&fields, "kernel_transferred_bytes"), GIB, "{fields:?}");
        assert!(value(&fields, "kernel_transfer_calls") > 0, "{fields:?}");
        assert_eq!(value(&fields, "copied_payload_bytes"), 0, "{fields:?}");
        assert_eq!(value(&fields, "fallback_responses"), 0, "{fields:?}");
        assert_eq!(value(&fields, "adapt_copies_total"), 0, "{fields:?}");
        assert_eq!(value(&fields, "zero_copy_refusals_total"), 0, "{fields:?}");
        assert_resident(TEST, &fields);
        if let Some(syscalls) = syscalls {
            assert_eq!(syscalls.sendfile_bytes, GIB, "sendfile did not return exactly the body: {syscalls:?}");
            assert!(
                syscalls.write_bytes < HEAD_WRITE_BUDGET,
                "write-family syscalls carried {} bytes, more than heads alone: {syscalls:?}",
                syscalls.write_bytes
            );
        }
    }

    /// a-pf-0013: the control for the case above. The same file on the same driver, forced onto the
    /// read-and-copy path by a verification obligation, is seen copying by every instrument the kernel
    /// case reads as zero: one named fallback, every body byte in `copied_payload_bytes`, no
    /// `sendfile`, a gibibyte through `write`-family syscalls. The resident peak stays bounded too —
    /// the copy loop reuses one 64 KiB buffer — so memory alone could never have told the paths apart.
    #[test]
    fn one_gib_get_forced_to_copy_is_seen_copying() {
        const TEST: &str = "perf_evidence::release::one_gib_get_forced_to_copy_is_seen_copying";
        if child(TEST, |fixture| runtime().block_on(get_once(GetMode::ForcedCopy, fixture))) {
            return;
        }
        let fixture = Fixture::create();
        let (fields, syscalls) = run_child(TEST, &fixture);
        assert_eq!(value(&fields, "body_bytes"), GIB);
        assert_eq!(value(&fields, "fallback_responses"), 1, "{fields:?}");
        assert_eq!(value(&fields, "copied_payload_bytes"), GIB, "{fields:?}");
        assert_eq!(value(&fields, "kernel_transferred_bytes"), 0, "{fields:?}");
        assert_eq!(value(&fields, "adapt_copies_total"), 1, "{fields:?}");
        assert_eq!(value(&fields, "adapt_copied_bytes_total"), GIB, "{fields:?}");
        assert_resident(TEST, &fields);
        if let Some(syscalls) = syscalls {
            assert_eq!(syscalls.sendfile_bytes, 0, "a copied body used the kernel path: {syscalls:?}");
            assert!(
                syscalls.write_bytes >= GIB,
                "the copied body must appear in write-family syscalls: {syscalls:?}"
            );
        }
    }

    /// a-pf-0010 / a-zc-0012: a real `GetObject` handler answering with a 1 GiB file region,
    /// served by the default Hyper driver. Hyper has no kernel path, so the region is copied once
    /// on the blocking pool — counted as one adaptation of exactly a gibibyte with a named reason —
    /// and the resident peak stays inside the same budget, because the copy is streamed in 64 KiB
    /// reads rather than held.
    #[test]
    fn one_gib_get_on_the_hyper_driver_copies_once_and_counts_it() {
        const TEST: &str = "perf_evidence::release::one_gib_get_on_the_hyper_driver_copies_once_and_counts_it";
        if child(TEST, |fixture| runtime().block_on(get_once(GetMode::HyperS3, fixture))) {
            return;
        }
        let fixture = Fixture::create();
        let (fields, syscalls) = run_child(TEST, &fixture);
        assert_eq!(value(&fields, "body_bytes"), GIB);
        assert_eq!(value(&fields, "adapt_copies_total"), 1, "{fields:?}");
        assert_eq!(value(&fields, "adapt_copied_bytes_total"), GIB, "{fields:?}");
        assert_eq!(value(&fields, "zero_copy_refusals_total"), 1, "{fields:?}");
        assert_resident(TEST, &fields);
        if let Some(syscalls) = syscalls {
            assert_eq!(syscalls.sendfile_bytes, 0, "the Hyper driver has no kernel path: {syscalls:?}");
            assert!(
                syscalls.write_bytes >= GIB,
                "the copied body must appear in write-family syscalls: {syscalls:?}"
            );
        }
    }

    /// a-pf-0006: a 1 GiB PUT streams through each driver without being held or copied. Both drivers
    /// read the socket into buffers they reuse, so receiving a gibibyte allocates kilobytes in total;
    /// an extra copy of each frame, or a body collected before the handler sees it, allocates a
    /// gibibyte and fails the first bound by two orders of magnitude.
    fn put_case(test: &'static str, driver: Driver) {
        if child(test, |fixture| runtime().block_on(put_once(driver, fixture))) {
            return;
        }
        let fixture = Fixture::create();
        let (fields, _) = run_child(test, &fixture);
        assert_eq!(value(&fields, "body_bytes"), GIB);
        let heap_bytes = value(&fields, "heap_bytes");
        assert!(
            heap_bytes <= RESIDENT_BUDGET,
            "{test}: receiving 1 GiB allocated {heap_bytes} bytes in total, so frames are being copied or collected: {fields:?}"
        );
        assert!(
            value(&fields, "heap_peak_bytes") <= RESIDENT_BUDGET,
            "{test}: the live heap peaked above {RESIDENT_BUDGET} bytes, so the body was held: {fields:?}"
        );
        assert_resident(test, &fields);
    }

    #[test]
    fn one_gib_put_on_the_self_held_driver_streams_without_holding_the_body() {
        put_case(
            "perf_evidence::release::one_gib_put_on_the_self_held_driver_streams_without_holding_the_body",
            Driver::SelfHeld,
        );
    }

    #[test]
    fn one_gib_put_on_the_hyper_driver_streams_without_holding_the_body() {
        put_case(
            "perf_evidence::release::one_gib_put_on_the_hyper_driver_streams_without_holding_the_body",
            Driver::Hyper,
        );
    }
}

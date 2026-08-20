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

//! What one `aws-chunked` upload costs, measured rather than described.
//!
//! Responsible for: proving the streaming path holds one copy of the body it is delivering and not
//! two — the wire body beside the decoded one.
//! NOT responsible for: how long the decode takes.
//! Upstream: `rustfs-gateway`, `dhat`. Downstream: nothing.

use crate::support;

use std::collections::VecDeque;
use std::process::Command;

use bytes::Bytes;
use rustfs_gateway::{ClockSkewAck, S3Service};
use support::{Ping, ping_route, wired};

/// The two decoded sizes, and the ratio between them is the instrument.
const SMALL: usize = 64 * 1024;
/// Sixteen times the smaller body.
const LARGE: usize = 16 * SMALL;

/// The decoded bytes one `aws-chunked` chunk carries.
const CHUNK: usize = 32 * 1024;

/// The wire frame size the body is fed in, held constant across both runs.
const FRAME: usize = 8 * 1024;

const PROBE_ENV: &str = "RUSTFS_GATEWAY_CHUNKED_ALLOCATION_PROBE";
const PROBE_SENTINEL: &str = "rustfs-gateway chunked allocation probe: ";
const PROBE_TEST: &str = "chunked_allocations::an_aws_chunked_upload_holds_one_copy_of_its_body";

/// A body that hands over pre-sliced frames and allocates nothing while it is being read.
struct FramedBody {
    frames: VecDeque<Bytes>,
}

impl http_body::Body for FramedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.frames.pop_front() {
            Some(bytes) => core::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes)))),
            None => core::task::Poll::Ready(None),
        }
    }
}

fn service() -> S3Service {
    wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(std::sync::Arc::new(support::Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly")
}

/// One signed `aws-chunked` request of `len` decoded bytes, and the wire body it carries.
fn request(len: usize) -> (http::request::Parts, Bytes) {
    use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};

    let decoded: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();

    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");

    // The wire length has to be known before the request is signed, because it is a signed header,
    // so the framing is built first and its own signature chain is seeded afterwards.
    let chunks = len.div_ceil(CHUNK);
    let wire_len = len + chunks * (format!("{CHUNK:x}").len() + 17 + 64 + 4) + 1 + 17 + 64 + 4;

    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    map.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire_len.to_string()).expect("a digit run"),
    );
    let signing = SigningRequest::new(
        &http::Method::POST,
        "/",
        "",
        &map,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: rustfs_gateway::sig::TrailerSet::None,
        },
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(len as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");

    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut wire = Vec::with_capacity(wire_len);
    for chunk in decoded.chunks(CHUNK) {
        wire.extend_from_slice(&chain.encode_chunk(chunk));
    }
    wire.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(wire.len(), wire_len, "the signed wire length must be the one that was signed");

    let mut builder = http::Request::builder().method(http::Method::POST).uri("/");
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    let (parts, ()) = builder.body(()).expect("a valid request").into_parts();
    (parts, Bytes::from(wire))
}

/// Sends one prepared request and returns the status.
fn exchange(
    service: &S3Service,
    runtime: &tokio::runtime::Runtime,
    parts: http::request::Parts,
    frames: VecDeque<Bytes>,
) -> http::StatusCode {
    let request = http::Request::from_parts(parts, FramedBody { frames });
    runtime.block_on(async {
        let response = service.call(request).await;
        let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
        collected.status()
    })
}

/// Splits the wire body into fixed-size frames, before the profiler exists.
fn frames(wire: &Bytes) -> VecDeque<Bytes> {
    let mut frames = VecDeque::with_capacity(wire.len().div_ceil(FRAME));
    let mut cursor = 0;
    while cursor < wire.len() {
        let take = FRAME.min(wire.len() - cursor);
        frames.push_back(wire.slice(cursor..cursor + take));
        cursor += take;
    }
    frames
}

/// What one `len`-byte upload costs: blocks, bytes allocated, and peak bytes held.
fn cost(len: usize) -> (u64, u64, u64) {
    let service = service();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    let (parts, wire) = request(len);

    let warm = exchange(&service, &runtime, parts.clone(), frames(&wire));
    assert_eq!(warm, http::StatusCode::OK, "the {len}-byte upload was not accepted");

    let ready = frames(&wire);
    let profiler = dhat::Profiler::builder().testing().build();
    let status = exchange(&service, &runtime, parts, ready);
    let stats = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(status, http::StatusCode::OK, "the measured {len}-byte upload was not accepted");
    (stats.total_blocks, stats.total_bytes, stats.max_bytes as u64)
}

/// Runs one isolated probe process at `len` and reads back what it measured.
fn measure(len: usize) -> (u64, u64, u64) {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let output = Command::new(executable)
        .args(["--exact", PROBE_TEST, "--nocapture"])
        .env(PROBE_ENV, len.to_string())
        .output()
        .expect("the isolated allocation probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the {len}-byte allocation probe failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix(PROBE_SENTINEL))
        .unwrap_or_else(|| panic!("the {len}-byte allocation probe measured nothing:\n{stdout}"));
    let mut parts = line.split_whitespace();
    let blocks = parts.next().and_then(|text| text.parse().ok());
    let bytes = parts.next().and_then(|text| text.parse().ok());
    let peak = parts.next().and_then(|text| text.parse().ok());
    match (blocks, bytes, peak) {
        (Some(blocks), Some(bytes), Some(peak)) => (blocks, bytes, peak),
        _ => panic!("the {len}-byte allocation probe printed `{line}`, which is not three numbers"),
    }
}

/// How many copies of the body may be **resident at once** at the peak of an upload.
///
/// One: the decoded body, which is what the caller is handed. The wire body is not a second one —
/// it is pulled frame by frame into the pipeline's window, so the octets a frame carried are gone
/// before the next frame arrives.
///
/// Before rustfs/gateway#229 this was three. The whole wire body was collected into a `BytesMut`
/// first and the decode ran over it, so at the moment the decoded collector last grew the process
/// held the wire body, the decoded body and the decoded body's replacement buffer: the same probe
/// read a peak growth of 2,981,888 bytes for 983,040 bytes of extra body. Reinstating that
/// collect-then-decode is the mutation the pull request records against this line.
const COPIES_HELD: u64 = 1;

/// How many copies of the body the whole upload may **allocate**, resident or not.
///
/// Two, and the second one is not a copy of the body: a `BytesMut` that grows by doubling
/// allocates a little under twice its final size across the growth steps that get it there, and
/// the decoded collector is the one buffer left that grows. Before #229 this read 6.03.
const COPIES_ALLOCATED: u64 = 2;

/// Allocator and per-request bookkeeping that does not scale with the body, so it cancels between
/// the two runs but not exactly. Small next to a single copy of even the smaller body, and smaller
/// than the pipeline's own 64 KiB window is not required — the window is the same size in both
/// runs, so it cancels.
const BYTES_HEADROOM: u64 = 64 * 1024;

/// How many more heap *blocks* the larger upload may take than the smaller one.
///
/// Reasoned rather than measured. Both runs allocate the same fixed set — the window, the drain
/// buffer, the decoded collector's growth steps, the response — and nothing in the frame loop is
/// supposed to allocate at all. Sixteen is slack for the growth steps a sixteen-times-larger
/// collector takes and for bookkeeping that does not cancel exactly.
///
/// What sixteen does not leave room for is the thing this line exists to catch. The larger run
/// pulls 129 frames against the smaller run's 9, so one allocation per frame puts it 124 blocks
/// above; that is the second mutation the pull request records.
const BLOCK_HEADROOM: u64 = 16;

/// What a run that measured nothing looks like, and the floor that refuses it.
///
/// `dhat::HeapStats::get()` does not panic when no `dhat::Alloc` is installed as the global
/// allocator — it answers zero — and two zeroes compared against each other satisfy every bound on
/// their difference. The declaration this file reads through lives in a sibling module of the same
/// test binary, so it can be removed without anything here failing to compile. A signed
/// `aws-chunked` exchange verifies a signature chain, decodes a body and encodes a response, which
/// costs tens of kibibytes across a hundred blocks; these floors sit an order of magnitude under
/// that.
const MEASURED_BLOCKS_FLOOR: u64 = 32;
/// The byte counterpart of [`MEASURED_BLOCKS_FLOOR`].
const MEASURED_BYTES_FLOOR: u64 = 4096;

/// Negative — an `aws-chunked` upload sixteen times larger does not hold sixteen times as much
/// heap *twice over*.
///
/// # What this proves that no status assertion can
///
/// `c-ing-0063` says the ingest pipeline works on a bounded window. That assertion is satisfied by
/// a caller which has already materialised the entire request beside the window: the status, the
/// decoded bytes and every log line are identical either way, and the pipeline's own counters —
/// `window_bytes`, `bytes_moved_total` — report the window truthfully while saying nothing about
/// what the caller is holding. A limit enforced on an inner loop and not on its caller is not a
/// limit, and the difference between the two lives on the heap. So that is where this looks.
///
/// # Why a ratio and not a number
///
/// "An upload allocates at most N bytes" is a gate against a constant somebody measured on one
/// machine, and the first platform whose allocator rounds differently turns it red for no defect.
/// These two runs are compared against each other, on whatever machine is running them, so what is
/// pinned is a shape: *the heap an `aws-chunked` upload holds is one copy of the object, not the
/// object plus the framing it arrived in*.
#[test]
fn an_aws_chunked_upload_holds_one_copy_of_its_body() {
    if let Some(len) = std::env::var_os(PROBE_ENV) {
        let len: usize = len.to_string_lossy().parse().expect("a body size");
        let (blocks, bytes, peak) = cost(len);
        println!("{PROBE_SENTINEL}{blocks} {bytes} {peak}");
        return;
    }

    let (small_blocks, small_bytes, small_peak) = measure(SMALL);
    let (large_blocks, large_bytes, large_peak) = measure(LARGE);
    println!("small body {SMALL}: {small_blocks} blocks, {small_bytes} bytes, {small_peak} peak");
    println!("large body {LARGE}: {large_blocks} blocks, {large_bytes} bytes, {large_peak} peak");

    // First: that anything was measured at all. Everything below is a statement about the
    // difference between two numbers, and two zeroes have no difference.
    for (label, blocks, bytes) in [("small", small_blocks, small_bytes), ("large", large_blocks, large_bytes)] {
        assert!(
            blocks >= MEASURED_BLOCKS_FLOOR && bytes >= MEASURED_BYTES_FLOOR,
            "the {label} probe recorded {blocks} blocks and {bytes} bytes, which is less than a \
             signed aws-chunked upload can possibly cost: the profiler saw nothing, so every bound \
             below is comparing one unmeasured run against another. Check that a \
             `#[global_allocator]` of `dhat::Alloc` is still declared somewhere in this test binary."
        );
    }

    let payload_growth = (LARGE - SMALL) as u64;
    let block_growth = large_blocks.saturating_sub(small_blocks);
    let byte_growth = large_bytes.saturating_sub(small_bytes);
    let peak_growth = large_peak.saturating_sub(small_peak);

    assert!(
        peak_growth <= payload_growth * COPIES_HELD + BYTES_HEADROOM,
        "a body {}x larger held {peak_growth} more bytes at its peak ({small_peak} -> {large_peak}) \
         for {payload_growth} more body, which is more than the {COPIES_HELD} copy this gate \
         allows. The wire body is resident beside the decoded one again, and the ingest window is \
         bounding only half of what the request costs.",
        LARGE / SMALL
    );
    assert!(
        byte_growth <= payload_growth * COPIES_ALLOCATED + BYTES_HEADROOM,
        "the aws-chunked path allocated {byte_growth} more bytes for {payload_growth} more body \
         ({small_bytes} -> {large_bytes}), which is more than the {COPIES_ALLOCATED} copies a \
         single doubling collector costs"
    );
    assert!(
        block_growth <= BLOCK_HEADROOM,
        "a body {}x larger cost {block_growth} more allocations ({small_blocks} -> {large_blocks}), \
         not at most {BLOCK_HEADROOM}: something on the streaming path allocates per frame or per \
         chunk",
        LARGE / SMALL
    );
}

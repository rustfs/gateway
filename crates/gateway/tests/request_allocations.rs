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

//! What one request costs, measured rather than described.
//!
//! Responsible for: proving that the heap a request consumes does not grow with the size of its
//! body, over a path that genuinely reads every byte of that body.
//! NOT responsible for: how long a request takes. Time on a shared runner is noise, and a gate that
//! is noise gets turned off.
//! Upstream: `rustfs-gateway`, `dhat`. Downstream: nothing.

use crate::support;

use std::process::Command;

use bytes::Bytes;
use rustfs_gateway::{ClockSkewAck, S3Service};
use support::{Ping, ping_route, wired};

/// The two sizes, and the ratio between them is the instrument.
///
/// A gate written as "a request allocates at most N blocks" is a gate against a constant somebody
/// measured on one machine, and the first platform whose allocator rounds differently turns it red
/// for no defect. These two runs are compared against *each other*, on whatever machine is running
/// them, so the assertion is about a shape rather than about a number.
const SMALL: usize = 4 * 1024;
const LARGE: usize = 256 * SMALL;

/// The digest of [`payload`] at each size, so the request is one the signature actually admits.
///
/// Computed once and written down, because nothing in this workspace's public API hashes bytes for
/// a caller. A wrong constant is not a silent problem: the exchange answers `400
/// XAmzContentSHA256Mismatch` instead of `200`, and the status is asserted before anything is
/// measured.
const SMALL_SHA256: &str = "d67c656e01756650d77717b0839985a056ec28ffe174601d690fc407a2ceffca";
const LARGE_SHA256: &str = "631b84027d6b9e52b539c4e8373622d23032dfadc64d60af87339c9037e4f769";

/// Names the body size one isolated probe process measures.
///
/// One process per size, and not two windows in one process. `dhat` profiles a whole process and
/// the tests in this binary run in parallel threads, so a window opened here would count whatever
/// the tests beside it were allocating at the time — and a second window opened after the first has
/// been dropped is a question about `dhat`'s own bookkeeping that this file should not have to
/// answer. Two processes, each measuring one thing, is the arrangement with no such question in it.
const PROBE_ENV: &str = "RUSTFS_GATEWAY_REQUEST_ALLOCATION_PROBE";
const PROBE_SENTINEL: &str = "rustfs-gateway request allocation probe: ";
const PROBE_TEST: &str = "request_allocations::a_requests_heap_does_not_grow_with_its_body";

/// A body whose bytes are a function of their position, so both sizes are reproducible and neither
/// is a run of one repeated byte.
fn payload(len: usize) -> Bytes {
    Bytes::from((0..len).map(|index| (index % 251) as u8).collect::<Vec<u8>>())
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

/// One accepted exchange whose payload digest is verified over every byte sent.
fn exchange(service: &S3Service, runtime: &tokio::runtime::Runtime, body: Bytes, sha256: &str) -> http::StatusCode {
    let payload_mode =
        rustfs_gateway::sig::PayloadMode::parse(sha256, rustfs_gateway::sig::TrailerSet::None).expect("a lowercase SHA-256");
    let request = support::presigned_with_body(body, payload_mode);
    runtime.block_on(async {
        let response = service.call_bytes(request).await;
        let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
        collected.status()
    })
}

/// What one exchange of `len` bytes costs: blocks allocated, and bytes allocated.
///
/// Everything that is not the exchange itself — the service, the runtime, the body, and one warm-up
/// exchange at the same size — happens before the profiler exists, so what the window holds is the
/// request and nothing else.
fn cost(len: usize, sha256: &str) -> (u64, u64) {
    let service = service();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    let body = payload(len);

    let warm = exchange(&service, &runtime, body.clone(), sha256);
    assert_eq!(warm, http::StatusCode::OK, "the {len}-byte exchange was not accepted");

    let profiler = dhat::Profiler::builder().testing().build();
    let status = exchange(&service, &runtime, body, sha256);
    let stats = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(status, http::StatusCode::OK, "the measured {len}-byte exchange was not accepted");
    (stats.total_blocks, stats.total_bytes)
}

/// Runs one isolated probe process at `len` and reads back what it measured.
fn measure(len: usize) -> (u64, u64) {
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
    // Parsed rather than assumed. A probe that crashed before it measured anything, or one whose
    // name no longer selects a test, exits successfully with no line to find — which is the shape
    // that would turn this whole file into two zeroes compared against each other.
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix(PROBE_SENTINEL))
        .unwrap_or_else(|| panic!("the {len}-byte allocation probe measured nothing:\n{stdout}"));
    let mut parts = line.split_whitespace();
    let blocks = parts.next().and_then(|text| text.parse().ok());
    let bytes = parts.next().and_then(|text| text.parse().ok());
    match (blocks, bytes) {
        (Some(blocks), Some(bytes)) => (blocks, bytes),
        _ => panic!("the {len}-byte allocation probe printed `{line}`, which is not two numbers"),
    }
}

/// How many more heap *blocks* the larger request may allocate than the smaller one.
///
/// Not zero, and the bound is reasoned rather than measured: a collector that doubles crosses one
/// growth step per doubling of the body, so the larger run crosses `log2(LARGE / SMALL)` = eight
/// more of them at worst, and a handful of allocations that belong to the runtime rather than to
/// the request do not cancel exactly between two separately built services. Sixteen leaves room
/// for both — this run has been observed at one and at six, depending on what else the test binary
/// had already initialised.
///
/// What sixteen does not leave room for is the thing this line exists to catch: an allocation
/// taken *inside* the loop that walks the body. Both sizes arrive here as a single frame — a
/// `Full<Bytes>` yields one — so this is not a bound on frame count; it is a bound on anything the
/// read path does per chunk, per kibibyte, or per anything else that is a function of length.
/// Reinstating one small allocation per four kibibytes of body puts the larger run 255 blocks
/// above the smaller and takes this line red, which is the mutation the pull request records.
const BLOCK_HEADROOM: u64 = 16;

/// How many times the request path may copy a body that arrived as one frame.
///
/// Zero. Not an aspiration: `crate::gate` hands each frame to the collector whole instead of
/// walking it into one, and a `BytesMut` with no capacity yet takes the frame's allocation rather
/// than copying into a new one — so a body handed over as a single `Bytes`, which is every body
/// given to `S3Service::call_bytes`, leaves the read path as the memory it arrived in. Before that
/// change this was one, and the difference was a whole mebibyte on the larger of the two runs
/// below. That is what makes the bound something the instrument has been shown to resolve, rather
/// than a zero nobody has watched become a one.
///
/// It is deliberately not a claim about a socket. Over hyper a large body arrives as many frames,
/// and every frame after the first is copied into a collector that now has capacity. Pinning the
/// multi-frame path needs a transport in the loop and belongs with the rest of
/// rustfs/backlog#1701.
const COPIES_ALLOWED: u64 = 0;

/// Allocator bookkeeping that does not scale with the payload, so it cancels between the two runs
/// but not exactly. Small next to a single copy of even the smaller body.
const BYTES_HEADROOM: u64 = 1024;

/// What a run that measured nothing looks like, and the floor that refuses it.
///
/// The `#[global_allocator]` this file reads through is declared in a sibling module, not here —
/// one test binary has one allocator, so `service_clone_allocations` owns the declaration and every
/// other module borrows it. If that line is ever removed, renamed, or put behind a feature,
/// `dhat::HeapStats::get()` keeps working and answers zero, both probes report `0 0`, and every
/// bound on the *difference* between them holds. The gate would be green and would be measuring
/// nothing, which is the one failure the assertions it exists for cannot see.
///
/// So each run is required to have observed a plausible request first. An exchange that verifies a
/// SHA-256, parses a presigned query, resolves a credential and encodes a response allocates tens
/// of kibibytes across hundreds of blocks; these floors are an order of magnitude under that, low
/// enough never to be the reason a legitimate tightening goes red and far enough above zero to
/// catch an allocator that is not installed.
const MEASURED_BLOCKS_FLOOR: u64 = 32;
/// The byte counterpart of [`MEASURED_BLOCKS_FLOOR`].
const MEASURED_BYTES_FLOOR: u64 = 4096;

/// Negative — a request two hundred and fifty-six times larger does not cost two hundred and
/// fifty-six times as much heap.
///
/// # Why this is measured as a ratio and not as a number
///
/// "A request allocates at most N blocks" is a gate against a constant somebody measured on one
/// machine. The first platform whose allocator rounds differently turns it red with no defect
/// behind it, and a gate that goes red for no reason is a gate somebody turns off. These two runs
/// are compared against each other, on whatever machine is running them, so what is pinned is a
/// shape: *the heap a request consumes is a function of the request, not of the size of its body*.
///
/// # Why this path and not a cheaper one
///
/// The exchange is presigned with an exact SHA-256 of the body, so the service reads every byte and
/// verifies the digest before the handler runs — `c_sig_0430_tampered_presigned_body_is_refused…`
/// is the case that proves that reading really happens. A path that ignored the body would satisfy
/// any zero-copy assertion trivially, which is the failure mode this whole file is trying not to
/// become: a stable number that measures nothing.
///
/// # What the instrument is shown to see
///
/// The two runs now print the same numbers, which is the whole point and also the danger: an
/// instrument that had stopped working would print the same numbers too. Three things stand
/// against that. The bound was approached before this branch — on `origin/main` the same probe read
/// 1,078,095 bytes for the larger body against 33,423 for the smaller, so a mebibyte of copying is
/// something this measurement has actually resolved. Restoring the old loop takes the byte
/// assertion red at exactly one copy, and an allocation per four kibibytes of body takes the block
/// assertion red at 255; both are recorded as mutations on the pull request. And the floor below
/// refuses a run in which nothing was measured at all, which is the failure the other two cannot
/// see: `dhat::HeapStats::get()` does not panic when no `dhat::Alloc` is installed as the global
/// allocator — it answers zero — and two zeroes compared against each other satisfy any bound on
/// their difference.
#[test]
fn a_requests_heap_does_not_grow_with_its_body() {
    if let Some(len) = std::env::var_os(PROBE_ENV) {
        let len: usize = len.to_string_lossy().parse().expect("a body size");
        let sha256 = if len == SMALL { SMALL_SHA256 } else { LARGE_SHA256 };
        let (blocks, bytes) = cost(len, sha256);
        println!("{PROBE_SENTINEL}{blocks} {bytes}");
        return;
    }

    let (small_blocks, small_bytes) = measure(SMALL);
    let (large_blocks, large_bytes) = measure(LARGE);
    println!("small body {SMALL}: {small_blocks} blocks, {small_bytes} bytes");
    println!("large body {LARGE}: {large_blocks} blocks, {large_bytes} bytes");

    // First: that anything was measured at all. Everything below is a statement about the
    // difference between two numbers, and two zeroes have no difference.
    for (label, blocks, bytes) in [("small", small_blocks, small_bytes), ("large", large_blocks, large_bytes)] {
        assert!(
            blocks >= MEASURED_BLOCKS_FLOOR && bytes >= MEASURED_BYTES_FLOOR,
            "the {label} probe recorded {blocks} blocks and {bytes} bytes, which is less than a \
             signed request can possibly cost: the profiler saw nothing, so every bound below is \
             comparing one unmeasured run against another. Check that a `#[global_allocator]` of \
             `dhat::Alloc` is still declared somewhere in this test binary."
        );
    }

    let payload_growth = (LARGE - SMALL) as u64;
    let block_growth = large_blocks.saturating_sub(small_blocks);
    let byte_growth = large_bytes.saturating_sub(small_bytes);

    assert!(
        block_growth <= BLOCK_HEADROOM,
        "a body {}x larger cost {block_growth} more allocations, not at most {BLOCK_HEADROOM}: \
         something on the request path allocates per frame or per chunk",
        LARGE / SMALL
    );
    assert!(
        byte_growth <= payload_growth * COPIES_ALLOWED + BYTES_HEADROOM,
        "the request path allocated {byte_growth} more bytes for {payload_growth} more body, which \
         is more than the {COPIES_ALLOWED} copy this gate allows"
    );
}

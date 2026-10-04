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

//! What one page of a listing costs, measured rather than described.
//!
//! Responsible for: `c-list-0040`'s property — *one page costs one page, whatever the bucket
//! costs* — as an allocation measurement over the reference backend, with a positive control and
//! a floor that refuses a run in which nothing was measured.
//! NOT responsible for: how long a listing takes. `c-list-0040` bounds the response time and that
//! bound is the half that fails first in production, but time on a shared runner is noise and a
//! gate that is noise gets turned off. It is also not responsible for the response *encoding*:
//! the document the gateway writes is a function of the page it was handed, so a page that is
//! bounded bounds it.
//! Upstream: the published API of `rustfs_gateway_conformance` and `dhat`. Downstream: nothing.
//!
//! # Why this file exists and `c-list-0040` alone is not enough
//!
//! `c-list-0040` declares 2,400 objects, asks for 1,000 of them, and bounds the response body and
//! the response time. All three are things it can express in the frozen case schema, and none of
//! them is a memory observation: a body of a thousand entries is a thousand entries whether the
//! server touched a thousand keys or two million, and ten seconds is a budget a fast machine meets
//! while doing the wrong amount of work. Its green could not support the claim in its own title.
//!
//! # Why allocations, and not RSS
//!
//! This repository has measured this class before and written down what does not work. `ps -o
//! rss=` held 164 MB of live leaked heap while reporting RSS *falling*, and 64 MiB of retained
//! incompressible memory read as exactly zero from six seconds on. Allocation counts have no such
//! blind window: rustfs/gateway#225 established `dhat` as the instrument for this class, always
//! with a positive control, and rustfs/gateway#233 used it to pin a POST form at 30 blocks and
//! 20,998 bytes across a 256-fold change in input size.
//!
//! # What the instrument is shown to see
//!
//! The two probes print nearly the same numbers, which is the point and also the danger: an
//! instrument that had stopped working would print the same numbers too. Three things stand
//! against that. The bound was *crossed* before this branch — the backend enumerated every key in
//! the bucket, sorted them, and sliced the page, so the 64,000-key probe allocated on the order of
//! a hundred thousand blocks against the 1,000-key probe's handful; that is the positive control,
//! and it is recorded on the pull request. Reinstating that enumeration takes both assertions red.
//! And [`MEASURED_BLOCKS_FLOOR`] refuses a run in which nothing was measured at all, which is the
//! failure the other two cannot see: `dhat::HeapStats::get()` does not panic when no `dhat::Alloc`
//! is installed as the global allocator — rustfs/gateway#225 found that it answers zero — and two
//! zeroes compared against each other satisfy any bound on their difference.

use std::process::Command;

use bytes::Bytes;
use rustfs_gateway::dto;
use rustfs_gateway::{
    BucketName, Handler, Limits, MetaView, Req, SseConfig, SseEnforced, TargetKind, TransportSecurity, WireRequest,
};

use rustfs_gateway_conformance::exec::block_on;
use rustfs_gateway_conformance::fixture::{Fixture, StoredObject, Stub};

fn sse_proof() -> SseEnforced {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("valid proof fixture");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted proof fixture");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("service proof fixture");
    rustfs_gateway::enforce_sse(&meta, TransportSecurity::Encrypted, &SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}

/// The profiler must be the global allocator for `dhat::HeapStats` to mean anything.
///
/// This target isolates the process-wide instrument from the library and ordinary integration
/// harnesses. Even with no active profiling window, `dhat::Alloc` serializes unrelated allocations
/// through its global lock. The original integration placement cost 27s → 69s; the later library
/// placement exceeded the 30-second crate loop as that suite grew (rustfs/gateway#1257).
///
/// Both this target and the complete library suite remain in the same crate verification budget.
/// The profiling window is opened only in the exact child probe below, with no other tests running.
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// The two bucket sizes. The ratio between them is the instrument: the assertion is that the cost
/// of one page does not move when the bucket underneath it grows sixty-four-fold.
const SMALL_BUCKET: usize = 1_000;
/// The larger bucket, sixty-four times the smaller.
const LARGE_BUCKET: usize = 64 * SMALL_BUCKET;

/// The page both probes ask for. Identical on both sides, because the page is the thing whose cost
/// is allowed to matter.
const PAGE: i32 = 100;

/// Names the bucket size one isolated probe process measures.
///
/// One process per size, and not two windows in one process. `dhat` profiles a whole process and
/// the tests in a binary run in parallel threads, so a window opened here would count whatever the
/// tests beside it were allocating at the time. rustfs/gateway#225 settled this arrangement.
const PROBE_ENV: &str = "RUSTFS_GATEWAY_LIST_ALLOCATION_PROBE";
const PROBE_SENTINEL: &str = "rustfs-gateway list allocation probe: ";
const PROBE_TEST: &str = "one_page_costs_one_page_whatever_the_bucket_costs";

/// A bucket of `count` keys, in the shape `c-list-0040` uses.
///
/// The keys are zero-padded so that their lexicographic order is their numeric order, which is what
/// makes the requested page the same *entries* at both sizes: a probe that returned different keys
/// on each side would be comparing two different amounts of work and calling the difference a leak.
fn bucket(count: usize) -> Stub {
    let mut fixture = Fixture::at(1_767_323_045);
    fixture.declare_bucket("conf-list-big", false);
    for index in 0..count {
        fixture.put_object("conf-list-big", &format!("k/{index:08}.bin"), StoredObject::new(vec![7], None, 0));
    }
    Stub::new(std::sync::Arc::new(std::sync::Mutex::new(fixture)))
}

/// One `ListObjectsV2` for the first page of the bucket.
fn request() -> Req<dto::ListObjectsV2> {
    Req::new(
        dto::ListObjectsV2Input {
            bucket: BucketName::new("conf-list-big".to_owned()).expect("a valid bucket name"),
            max_keys: Some(PAGE),
            ..dto::ListObjectsV2Input::default()
        },
        sse_proof(),
    )
}

/// What one page out of a bucket of `count` keys costs: blocks allocated, and bytes allocated.
///
/// Everything that is not the listing itself — the fixture, the keys, and one warm-up listing at
/// the same size — happens before the profiler exists, so what the window holds is one page and
/// nothing else.
fn cost(count: usize) -> (u64, u64) {
    let stub = bucket(count);

    let warm = block_on(Handler::call(&stub, request())).expect("the warm-up listing succeeds");
    let warm = warm.output().expect("the warm-up listing produced an output");
    assert_eq!(warm.contents.len(), PAGE as usize, "the {count}-key warm-up did not return a full page");

    let profiler = dhat::Profiler::builder().testing().build();
    let answer = block_on(Handler::call(&stub, request()));
    let stats = dhat::HeapStats::get();
    drop(profiler);

    let page = answer.expect("the measured listing succeeds");
    let page = page.output().expect("the measured listing produced an output");
    // Asserted after the window and before anything is reported: a probe that measured a refusal,
    // or a short page, measured something other than what this file claims to measure.
    assert_eq!(
        page.contents.len(),
        PAGE as usize,
        "the measured {count}-key listing did not return a full page"
    );
    assert!(page.is_truncated, "a page out of {count} keys must be truncated");
    (stats.total_blocks, stats.total_bytes)
}

/// Runs one isolated probe process at `count` and reads back what it measured.
fn measure(count: usize) -> (u64, u64) {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let output = Command::new(executable)
        .args(["--exact", PROBE_TEST, "--nocapture"])
        .env(PROBE_ENV, count.to_string())
        .output()
        .expect("the isolated allocation probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the {count}-key allocation probe failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Parsed rather than assumed. A probe that crashed before it measured anything, or one whose
    // name no longer selects a test, exits successfully with no line to find — which is the shape
    // that would turn this whole file into two zeroes compared against each other.
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix(PROBE_SENTINEL))
        .unwrap_or_else(|| {
            panic!(
                "the {count}-key allocation probe measured nothing. If the child reports `running \
                 0 tests`, PROBE_TEST ({PROBE_TEST}) no longer names this test — it is a string, \
                 and renaming the module or the function does not update it:\n{stdout}"
            )
        });
    let mut parts = line.split_whitespace();
    let blocks = parts.next().and_then(|text| text.parse().ok());
    let bytes = parts.next().and_then(|text| text.parse().ok());
    match (blocks, bytes) {
        (Some(blocks), Some(bytes)) => (blocks, bytes),
        _ => panic!("the {count}-key allocation probe printed `{line}`, which is not two numbers"),
    }
}

/// How many more heap blocks the larger bucket's page may cost than the smaller bucket's.
///
/// Not zero, and reasoned rather than measured. The two probes walk different numbers of *stored*
/// keys before the page is full only in the sense that the map is bigger; the page itself is the
/// same hundred entries, so the allocations that differ are the ones a collector takes as it grows
/// and a handful that belong to neither run in particular. Sixty-four leaves room for that and no
/// room at all for the thing this line exists to catch: an allocation taken per key in the bucket.
/// At one allocation per key the larger probe sits 63,000 blocks above the smaller, which is three
/// orders of magnitude past this bound.
const BLOCK_HEADROOM: u64 = 64;

/// The byte counterpart, on the same reasoning.
///
/// One `String` per key in a 64,000-key bucket is over a megabyte before anything is sorted; this
/// bound is four orders of magnitude below that and comfortably above the difference two
/// separately built maps produce.
const BYTE_HEADROOM: u64 = 16 * 1024;

/// What a run that measured nothing looks like, and the floor that refuses it.
///
/// A listing that walks a hundred keys, builds a hundred owned key strings, a hundred entity tags
/// and a hundred DTO entries allocates hundreds of blocks and tens of kibibytes. These floors are
/// well under that and far above zero: low enough never to be the reason a legitimate tightening
/// goes red, high enough to catch an allocator that is not installed.
const MEASURED_BLOCKS_FLOOR: u64 = 100;
/// The byte counterpart of [`MEASURED_BLOCKS_FLOOR`].
const MEASURED_BYTES_FLOOR: u64 = 4096;

/// Negative — a bucket sixty-four times larger does not make one page of it cost sixty-four times
/// as much heap.
///
/// This is `c-list-0040`'s title as an assertion. The case can express the page's *contents* and
/// its arrival time; it cannot express what the server spent, and "the natural implementation
/// enumerates the bucket, sorts it and slices the page" — which is what the case's own rationale
/// warns about, and what this backend did until this measurement was written — satisfies every
/// functional assertion in the list family while turning each listing into a cost proportional to
/// the bucket.
///
/// # Why a ratio and not a number
///
/// "A listing allocates at most N blocks" is a gate against a constant somebody measured on one
/// machine, and the first platform whose allocator rounds differently turns it red with no defect
/// behind it. These two runs are compared against each other, on whatever machine is running them,
/// so what is pinned is a shape.
#[test]
fn one_page_costs_one_page_whatever_the_bucket_costs() {
    if let Some(count) = std::env::var_os(PROBE_ENV) {
        let count: usize = count.to_string_lossy().parse().expect("a bucket size");
        let (blocks, bytes) = cost(count);
        println!("{PROBE_SENTINEL}{blocks} {bytes}");
        return;
    }

    let (small_blocks, small_bytes) = measure(SMALL_BUCKET);
    let (large_blocks, large_bytes) = measure(LARGE_BUCKET);
    println!("bucket of {SMALL_BUCKET}: {small_blocks} blocks, {small_bytes} bytes");
    println!("bucket of {LARGE_BUCKET}: {large_blocks} blocks, {large_bytes} bytes");

    // First: that anything was measured at all. Everything below is a statement about the
    // difference between two numbers, and two zeroes have no difference.
    for (label, blocks, bytes) in [("small", small_blocks, small_bytes), ("large", large_blocks, large_bytes)] {
        assert!(
            blocks >= MEASURED_BLOCKS_FLOOR && bytes >= MEASURED_BYTES_FLOOR,
            "the {label} probe recorded {blocks} blocks and {bytes} bytes, which is less than a \
             hundred-entry page can possibly cost: the profiler saw nothing, so every bound below \
             is comparing one unmeasured run against another. Check that a `#[global_allocator]` \
             of `dhat::Alloc` is still declared in this test binary."
        );
    }

    let block_growth = large_blocks.saturating_sub(small_blocks);
    let byte_growth = large_bytes.saturating_sub(small_bytes);

    assert!(
        block_growth <= BLOCK_HEADROOM,
        "one page out of a bucket {}x larger cost {block_growth} more allocations, not at most \
         {BLOCK_HEADROOM}: the listing allocates per key in the bucket rather than per key in the \
         page",
        LARGE_BUCKET / SMALL_BUCKET
    );
    assert!(
        byte_growth <= BYTE_HEADROOM,
        "one page out of a bucket {}x larger cost {byte_growth} more bytes, not at most \
         {BYTE_HEADROOM}: the listing holds memory proportional to the bucket",
        LARGE_BUCKET / SMALL_BUCKET
    );
}

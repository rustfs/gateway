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

//! How many heap blocks one warm in-memory request costs, end to end.
//!
//! Responsible for: rustfs/backlog#1766 a-pf-0002 / a-pf-0003 / a-pf-0011 — the allocations of a
//! signed `GetObject` and a signed `PutObject` through the whole assembled service (acceptance,
//! routing, SigV4 verification, authorization, handler, response encoding, body collection),
//! counted over many warm requests and held to a committed per-request ceiling.
//! NOT responsible for: body-size scaling, which `request_allocations.rs` owns, or time.
//! Upstream: `rustfs-gateway`, the binary's `dhat` allocator. Downstream: nothing.
//!
//! # Why a number here, when `request_allocations.rs` refuses one
//!
//! That file compares two body sizes against each other so that no platform's allocator rounding
//! can turn it red. Block *counts* do not round: a path that allocates `n` blocks per request on one
//! allocator allocates `n` on another, because the count is a property of the code, not of the
//! allocator. What would make it platform-dependent is lazily initialised state — an OS lock boxed
//! on first use, a thread-local — and the warm-up below pays for all of that before the window.
//! So the ceiling is a ratchet: it may only be lowered, and a change that adds one allocation to
//! every request fails it.

use crate::support;

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use rustfs_gateway::dto;
use rustfs_gateway::{ByteStream, Handler, HandlerError, HandlerResult, Req, Resp, S3Service};

const PROBE_ENV: &str = "RUSTFS_GATEWAY_STEADY_STATE_ALLOCATION_PROBE";
const PROBE_SENTINEL: &str = "rustfs-gateway steady-state allocation probe: ";
const PROBE_TEST: &str = "steady_state_allocations::a_warm_request_allocates_at_most_its_committed_budget";

/// Requests in the short and the long window. The long window's cost minus the short one's is
/// `MEASURED` requests' worth with every per-window constant cancelled.
const SHORT: u64 = 16;
const LONG: u64 = SHORT + MEASURED;
const MEASURED: u64 = 128;
/// Requests exchanged before the window opens, to pay every first-use cost.
const WARM_UP: usize = 16;
const BODY: &[u8] = b"a small object body, sixty-four bytes long, for both directions.";

/// a-pf-0002 / a-pf-0003: heap blocks one warm signed `GetObject` and `PutObject` may allocate,
/// end to end, where CI runs. The original Linux ceilings were 148 / 195 (#955); borrowing the
/// header chunk seed removes four blocks (#1297), and metadata lookup names remove another
/// 16 / 36 (#1301). Single-buffer string-to-sign construction removes six from both (#1313).
/// Static metadata names remove 13 / 33 more (#1317); copy-source SSE names remove three from both (#1319).
/// The plan's targets remain 3 / 4, and this ceiling only moves down.
#[cfg(target_os = "linux")]
const BLOCKS_PER_REQUEST: Option<(u64, u64)> = Some((106, 113));
/// macOS's standard library and runtime allocate a few more blocks per request, and not the same
/// number every window. The combined repairs retain the previous block of room for runtime
/// drift, so they refuse two new allocations per request but not reliably one; Linux is exact.
#[cfg(target_os = "macos")]
const BLOCKS_PER_REQUEST: Option<(u64, u64)> = Some((113, 131));
/// No platform other than the two above has been measured, so there is no ceiling to hold it to.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const BLOCKS_PER_REQUEST: Option<(u64, u64)> = None;

struct InMemory;

impl Handler<dto::GetObject> for InMemory {
    async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        Ok(Resp::new(dto::GetObjectOutput {
            body: Some(ByteStream::from_bytes(Bytes::from_static(BODY))),
            content_length: Some(BODY.len() as i64),
            ..dto::GetObjectOutput::default()
        }))
    }
}

impl Handler<dto::PutObject> for InMemory {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let body = request.into_input().body;
        async move {
            let mut body = body
                .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
                .into_body();
            let mut received = 0;
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
                if let Ok(data) = frame.into_data() {
                    received += data.len();
                }
            }
            if received != BODY.len() {
                return Err(HandlerError::internal_error("the handler did not receive the whole body"));
            }
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

fn service() -> S3Service {
    let unbounded = rustfs_gateway::Rate::new(u32::MAX, u32::MAX);
    support::wired_at_signed_time()
        .framework_governor_rates(rustfs_gateway::GovernorRates {
            aggregate: unbounded,
            per_ip: unbounded,
            credential_lookup: unbounded,
            cors_preflight: unbounded,
            unauthenticated: unbounded,
            ..rustfs_gateway::GovernorRates::default()
        })
        .register::<dto::GetObject, _>(Arc::new(InMemory))
        .register::<dto::PutObject, _>(Arc::new(InMemory))
        .build()
        .expect("a complete assembly")
}

#[derive(Clone, Copy)]
enum Kind {
    Get,
    Put,
}

fn request(kind: Kind) -> http::Request<Bytes> {
    match kind {
        Kind::Get => support::signed(http::Method::GET, "/bucket/key"),
        Kind::Put => support::signed_target_with_body_and_headers(
            http::Method::PUT,
            "/bucket/key",
            &[("content-length", "64")],
            Bytes::from_static(BODY),
        ),
    }
}

async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> (http::StatusCode, usize) {
    let response = service.call_bytes(request).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    (collected.status(), collected.body().len())
}

/// Blocks and bytes allocated by `count` warm exchanges of `kind`. Every request is signed and
/// built before the window opens; what the window holds is the exchanges and nothing else.
fn window(service: &S3Service, runtime: &tokio::runtime::Runtime, kind: Kind, count: u64) -> (u64, u64) {
    let expected_body = match kind {
        Kind::Get => BODY.len(),
        Kind::Put => 0,
    };
    let requests: Vec<_> = (0..count).map(|_| request(kind)).collect();
    let mut outcomes = Vec::with_capacity(requests.len());
    let profiler = dhat::Profiler::builder().testing().build();
    runtime.block_on(async {
        for request in requests {
            outcomes.push(exchange(service, request).await);
        }
    });
    let stats = dhat::HeapStats::get();
    drop(profiler);
    assert!(
        outcomes
            .iter()
            .all(|outcome| *outcome == (http::StatusCode::OK, expected_body)),
        "a measured exchange failed: {outcomes:?}"
    );
    (stats.total_blocks, stats.total_bytes)
}

/// What `MEASURED` warm requests of `kind` cost: the long window minus the short one.
fn cost(kind: Kind) -> (u64, u64) {
    let service = service();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    for _ in 0..WARM_UP {
        let (status, _) = runtime.block_on(exchange(&service, request(kind)));
        assert_eq!(status, http::StatusCode::OK, "a warm-up exchange failed");
    }
    let short = window(&service, &runtime, kind, SHORT);
    let long = window(&service, &runtime, kind, LONG);
    (long.0.saturating_sub(short.0), long.1.saturating_sub(short.1))
}

/// a-pf-0002 / a-pf-0003 / a-pf-0011. A warm signed request allocates no more heap blocks than
/// its committed ceiling, and a request that has started allocating one more is refused here.
#[test]
fn a_warm_request_allocates_at_most_its_committed_budget() {
    if let Some(kinds) = support::allocations::requested_sizes(PROBE_ENV) {
        for kind in kinds {
            let kind = if kind == 0 { Kind::Get } else { Kind::Put };
            let (blocks, bytes) = cost(kind);
            println!("{PROBE_SENTINEL}{blocks} {bytes}");
        }
        return;
    }
    let Some((get_budget, put_budget)) = BLOCKS_PER_REQUEST else {
        eprintln!("SKIP a-pf-0002/0003: no per-request allocation ceiling has been measured on this platform");
        return;
    };
    let rows = support::allocations::measure(PROBE_TEST, PROBE_ENV, PROBE_SENTINEL, &[0, 1], 2);
    for ((label, budget), row) in [("GetObject", get_budget), ("PutObject", put_budget)].into_iter().zip(&rows) {
        let (blocks, bytes) = (row[0], row[1]);
        println!(
            "{label}: {blocks} blocks, {bytes} bytes over {MEASURED} warm requests; {} blocks per request, ceiling {budget}",
            blocks as f64 / MEASURED as f64
        );
        assert!(
            blocks >= MEASURED,
            "{label}: {blocks} blocks over {MEASURED} requests is less than one per request, which a signed exchange cannot be: the allocator is not observing this binary"
        );
        // Half a block of slack per request: the runtime's own bookkeeping moves the total by a
        // handful of blocks between otherwise identical windows, never by one per request.
        assert!(
            blocks <= budget * MEASURED + MEASURED / 2,
            "{label}: warm requests allocated {:.2} heap blocks each, past the committed ceiling of {budget}",
            blocks as f64 / MEASURED as f64
        );
    }
}

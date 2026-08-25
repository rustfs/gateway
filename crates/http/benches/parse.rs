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

//! Responsible for: allocation assertions for the two request-head parsing paths named by P3-01.
//! NOT responsible for: transport setup, body ingestion, or wall-clock throughput.
//! Upstream: `http` fixtures and `dhat`.
//! Downstream: the HTTP crate's CI benchmark gate.

use std::hint::black_box;
use std::time::Instant;

use http::Request;
use http::header::HOST;
use rustfs_gateway_http::{Limits, QueryIndex, SignedHeaderList, WireRequest};

const ITERATIONS: u32 = 100_000;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn assert_zero_allocations(name: &str, action: impl FnOnce()) {
    let profiler = dhat::Profiler::builder().testing().build();
    action();
    let stats = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(stats.total_blocks, 0, "{name} allocated {} heap blocks", stats.total_blocks);
    assert_eq!(stats.total_bytes, 0, "{name} allocated {} heap bytes", stats.total_bytes);
    println!("{name}: 0 allocs");
}

fn record_time(name: &str, iterations: u32, mut action: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        action();
    }
    let elapsed = started.elapsed();
    let nanos_per_iteration = elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(iterations);
    println!("{name}: {nanos_per_iteration:.3} ns/iteration ({iterations} iterations; record-only, non-blocking)");
}

fn query_request() -> Request<()> {
    Request::builder()
        .uri(concat!(
            "/bucket?list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1000",
            "&continuation-token=abc&encoding-type=url&fetch-owner=true&start-after=x"
        ))
        .header(HOST, "b.example.com")
        .body(())
        .expect("the benchmark fixture is a valid request")
}

fn canonical_request() -> Request<()> {
    Request::builder()
        .method("PUT")
        .uri("/bucket/key")
        .header(HOST, "b.example.com")
        .header("content-type", "application/octet-stream")
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .header("x-amz-date", "20260805T000000Z")
        .body(())
        .expect("the benchmark fixture is a valid request")
}

fn main() {
    let limits = Limits::default();
    let request = query_request();
    assert_zero_allocations("parse/query_view_8params", || {
        let accepted = WireRequest::accept(request, &limits).expect("the query fixture is accepted");
        assert_eq!(accepted.query().len(), 8);
        assert!(accepted.query().is_inline());
        std::hint::black_box(accepted);
    });

    let accepted = WireRequest::accept(canonical_request(), &limits).expect("the header fixture is accepted");
    let signed = SignedHeaderList::parse("content-type;host;x-amz-content-sha256;x-amz-date")
        .expect("the signed-header fixture is ordered");
    let mut output = String::with_capacity(512);
    let capacity = output.capacity();
    // c-fast-0006: the exact host-override writer used by SigV4 allocates no heap blocks.
    assert_zero_allocations("parse/canonical_headers_signed", || {
        accepted
            .headers()
            .write_canonical_headers_with_host(&signed, &"b.example.com", &mut output)
            .expect("every signed header is present");
    });
    assert_eq!(output.capacity(), capacity);
    assert!(!output.is_empty());

    let query = concat!(
        "list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1000",
        "&continuation-token=abc&encoding-type=url&fetch-owner=true&start-after=x"
    );
    record_time("parse/query_view_8params", ITERATIONS, || {
        black_box(QueryIndex::parse(black_box(query), black_box(&limits)).expect("the query fixture is accepted"));
    });
    record_time("parse/canonical_headers_signed", ITERATIONS, || {
        output.clear();
        accepted
            .headers()
            .write_canonical_headers_with_host(&signed, &"b.example.com", &mut output)
            .expect("every signed header is present");
        black_box(output.as_str());
    });
}

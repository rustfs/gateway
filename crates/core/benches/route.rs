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

//! Allocation gates and reviewable timing records for compiled route lookup.
//!
//! Responsible for: proving the two named route shapes allocate no heap blocks during lookup and
//! printing their non-blocking wall-clock observations for `benches/baseline.json`.
//! NOT responsible for: routing semantics, query parsing, or a time-based CI threshold.
//! Upstream: the generated route entries and borrowed HTTP views. Downstream: benchmark evidence.

use std::hint::black_box;
use std::time::Instant;

use http::{HeaderMap, Method};
use rustfs_gateway_core::route::{
    CompiledRouter, HostClass, RouteRequestParts, RouteTable, SHADOWING, TargetKind, generated_entries,
};
use rustfs_gateway_http::{HeaderView, Limits, QueryIndex, QueryView};

const ITERATIONS: u32 = 1_000_000;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

struct RequestFixture {
    method: Method,
    path: &'static str,
    target: TargetKind,
    query: &'static str,
    index: QueryIndex,
    headers: HeaderMap,
}

impl RequestFixture {
    fn new(method: Method, path: &'static str, target: TargetKind, query: &'static str) -> Self {
        let index = QueryIndex::parse(query, &Limits::default()).expect("the benchmark query is valid");
        Self {
            method,
            path,
            target,
            query,
            index,
            headers: HeaderMap::new(),
        }
    }

    fn parts(&self) -> RouteRequestParts<'_> {
        RouteRequestParts {
            method: &self.method,
            path: self.path,
            target: self.target,
            host_class: HostClass::Standard,
            arn_form: None,
            query: QueryView::new(self.query, &self.index),
            headers: HeaderView::new(&self.headers),
        }
    }
}

fn router() -> CompiledRouter {
    let entries = generated_entries().expect("the generated route entries parse");
    let table = RouteTable::build(entries, &SHADOWING).expect("the generated route table builds");
    CompiledRouter::compile(&table).expect("the generated route table compiles")
}

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

fn main() {
    let router = router();
    let object = RequestFixture::new(Method::GET, "/bucket/key", TargetKind::Object, "");
    let listing = RequestFixture::new(
        Method::GET,
        "/bucket",
        TargetKind::Bucket,
        "list-type=2&prefix=x&max-keys=1000&delimiter=%2F&encoding-type=url&continuation-token=t",
    );

    assert_zero_allocations("route/get_object_no_query", || {
        let op = router.resolve(&object.parts()).expect("the object request routes");
        assert_eq!(router.op_name(op), Some("GetObject"));
    });
    assert_zero_allocations("route/list_objects_v2_6params", || {
        let op = router.resolve(&listing.parts()).expect("the listing request routes");
        assert_eq!(router.op_name(op), Some("ListObjectsV2"));
    });

    record_time("route/get_object_no_query", ITERATIONS, || {
        black_box(router.resolve(black_box(&object.parts())));
    });
    record_time("route/list_objects_v2_6params", ITERATIONS, || {
        black_box(router.resolve(black_box(&listing.parts())));
    });
}

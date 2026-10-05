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

//! Metadata header-lookup allocation controls.
//!
//! Responsible for: comparing metadata lookup with parsing the same name, checking measured
//! values, heap sentinels and a deliberately allocating control. NOT responsible for: full request
//! costs or time.
//! Upstream: core MetaView and the isolated allocator harness. Downstream: the lookup resource gate.

use crate::support;

use rustfs_gateway::{Limits, MetaView, TargetKind, WireRequest};

const ENV: &str = "RUSTFS_GATEWAY_HEADER_LOOKUP_ALLOCATION_PROBE";
const SENTINEL: &str = "rustfs-gateway header lookup allocations: ";
const TEST: &str = "header_lookup_allocations::metadata_lookup_does_not_copy_its_parsed_name";
const CALLS: u64 = 1024;
const FIRST: &str = "x-gateway-first-allocation-probe";
const SECOND: &str = "x-gateway-second-allocation-probe";
const MISSING: &str = "x-gateway-absent-allocation-probe";

fn accepted() -> WireRequest<()> {
    let request = http::Request::builder()
        .uri("/bucket/key")
        .header("host", "localhost")
        .header(FIRST, "first")
        .header(SECOND, "second")
        .body(())
        .expect("a static request head");
    WireRequest::accept(request, &Limits::default()).expect("an accepted request head")
}

fn cost(kind: usize) -> (u64, u64, u64) {
    let request = accepted();
    let view = MetaView::of(&request, TargetKind::Object).expect("an object view");
    let profiler = dhat::Profiler::builder().testing().build();
    let mut matched = 0_u64;
    for index in 0..CALLS {
        // The same measured sentinel in both paths makes an unobserved window fail even if a
        // future lookup removes every allocation of its own. Its cost cancels in the comparison.
        std::hint::black_box(Box::new([0_u8; 1]));
        let name = if index % 2 == 0 { FIRST } else { SECOND };
        let correct = match kind {
            0 => http::HeaderName::from_bytes(std::hint::black_box(name.as_bytes()))
                .is_ok_and(|parsed| std::hint::black_box(parsed).as_str() == name),
            1 => {
                let expected = if index % 2 == 0 { "first" } else { "second" };
                view.header(std::hint::black_box(name)).as_deref() == Some(expected)
            }
            2 => view.header(std::hint::black_box(MISSING)).is_none(),
            3 => http::HeaderName::from_bytes(std::hint::black_box(name.as_bytes())).is_ok_and(|parsed| {
                let copied = std::hint::black_box(parsed.clone());
                copied.as_str() == name
            }),
            _ => panic!("an unknown probe kind"),
        };
        matched = matched.saturating_add(u64::from(correct));
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    (stats.total_blocks, stats.total_bytes, matched)
}

/// Negative resource ceiling: reading or missing a nonstandard name adds no copy beyond the
/// same parser control. Observed values and a mandatory heap sentinel guard the measurement.
#[test]
fn metadata_lookup_does_not_copy_its_parsed_name() {
    if let Some(kinds) = support::allocations::requested_sizes(ENV) {
        for kind in kinds {
            let (blocks, bytes, matched) = cost(kind);
            println!("{SENTINEL}{blocks} {bytes} {matched}");
        }
        return;
    }
    let rows = support::allocations::measure(TEST, ENV, SENTINEL, &[0, 1, 2, 3], 3);
    for row in &rows {
        assert_eq!(row.get(2), Some(&CALLS), "every requested lookup must evaluate its actual value");
        assert!(
            row.first().is_some_and(|blocks| *blocks >= CALLS),
            "the allocation window did not observe its mandatory heap sentinels: {row:?}"
        );
    }
    let control = rows
        .first()
        .and_then(|row| row.first())
        .copied()
        .expect("the parser control exists");
    let amplified = rows
        .last()
        .and_then(|row| row.first())
        .copied()
        .expect("the copying control exists");
    assert!(
        amplified > control,
        "the deliberately copying control did not cost more than parsing: {amplified} <= {control}"
    );
    for (label, row) in ["present", "absent"].into_iter().zip(rows.iter().skip(1).take(2)) {
        let blocks = row.first().copied().expect("the measured block count exists");
        println!("{label}: {blocks} blocks for {CALLS} lookups; parser control {control}");
        assert!(
            blocks <= control,
            "{label} lookup allocated {blocks} blocks past its parser control {control}"
        );
    }
}

/// Negative lookup inputs remain absent; borrowing must not reinterpret an invalid name.
#[test]
fn invalid_lookup_names_remain_absent() {
    let request = accepted();
    let view = MetaView::of(&request, TargetKind::Object).expect("an object view");
    for name in ["", "bad name", "bad:name", "bad\r\nname", "badé"] {
        assert_eq!(view.header(name), None, "an invalid lookup name became present");
    }
}

/// Healthy duplicate values keep their wire order and ignore an unrelated field.
#[test]
fn repeated_header_values_keep_their_order() {
    let request = http::Request::builder()
        .uri("/bucket/key")
        .header("host", "localhost")
        .header(FIRST, "first")
        .header(SECOND, "unrelated")
        .header(FIRST, "second")
        .body(())
        .expect("a static request head");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an accepted request head");
    let view = MetaView::of(&wire, TargetKind::Object).expect("an object view");
    assert_eq!(view.header(FIRST).as_deref(), Some("first, second"));
}

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

//! Fixed metadata-name allocation and lookup controls.
//!
//! Responsible for: holding each measured fixed name to borrowed lookup cost, observing both
//! value directions, and preserving fallback, empty and repeated inputs. NOT responsible for:
//! interning arbitrary external names, whole-request cost or time.
//! Upstream: core MetaView and the isolated allocator harness. Downstream: the allocation gate.

use crate::support;

use rustfs_gateway::{Limits, MetaView, TargetKind, WireRequest};

const ENV: &str = "RUSTFS_GATEWAY_STATIC_HEADER_ALLOCATION_PROBE";
const SENTINEL: &str = "rustfs-gateway static header allocations: ";
const TEST: &str = "static_header_allocations::fixed_names_cost_only_borrowed_lookup";
// Independently selected from the GetObject/PutObject binding census before the repair.
const NAMES: &[&str] = &[
    "content-md5",
    "x-amz-acl",
    "x-amz-checksum-mode",
    "x-amz-expected-bucket-owner",
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
    "x-amz-object-lock-event-hold",
    "x-amz-object-lock-event-hold-duration-days",
    "x-amz-object-lock-event-hold-duration-years",
    "x-amz-object-lock-legal-hold",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-request-payer",
    "x-amz-sdk-checksum-algorithm",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-storage-class",
    "x-amz-tagging",
    "x-amz-website-redirect-location",
    "x-amz-write-offset-bytes",
];
const CALLS: u64 = NAMES.len() as u64 * 32;

fn accepted(present: bool, values: &[String]) -> WireRequest<()> {
    let mut request = http::Request::builder().uri("/bucket/key").header("host", "localhost");
    if present {
        for (&name, value) in NAMES.iter().zip(values) {
            request = request.header(name, value);
        }
    }
    WireRequest::accept(request.body(()).expect("a static head"), &Limits::default()).expect("an accepted head")
}

fn cost(kind: usize) -> (u64, u64, u64) {
    let values: Vec<_> = (0..NAMES.len()).map(|index| format!("field-{index}")).collect();
    let present = !matches!(kind, 2 | 4 | 6);
    let wire = accepted(present, &values);
    let view = MetaView::of(&wire, TargetKind::Object).expect("an object view");
    let profiler = dhat::Profiler::builder().testing().build();
    let mut matched = 0_u64;
    for index in 0..CALLS {
        std::hint::black_box(Box::new([0_u8; 1]));
        let field = index as usize % NAMES.len();
        let name = std::hint::black_box(NAMES[field]);
        let expected = values[field].as_str();
        let correct = match kind {
            0 => wire.headers().get_str(&http::HeaderName::from_static(name)) == Some(expected),
            1 => view.header(name).as_deref() == Some(expected),
            2 => view.header(name).is_none(),
            3 => view.has_header(name),
            4 => !view.has_header(name),
            5 => http::HeaderName::from_bytes(name.as_bytes())
                .is_ok_and(|parsed| wire.headers().get_str(&parsed) == Some(expected)),
            6 => wire.headers().get_str(&http::HeaderName::from_static(name)).is_none(),
            7 => wire.headers().get_str(&http::HeaderName::from_static(name)) == Some("deliberately-wrong"),
            _ => panic!("an unknown probe kind"),
        };
        matched = matched.saturating_add(u64::from(correct));
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    (stats.total_blocks, stats.total_bytes, matched)
}

/// Negative resource cases: every fixed name's read, miss and presence check owes no owned parse.
#[test]
fn fixed_names_cost_only_borrowed_lookup() {
    if let Some(kinds) = support::allocations::requested_sizes(ENV) {
        for kind in kinds {
            let (blocks, bytes, matched) = cost(kind);
            println!("{SENTINEL}{blocks} {bytes} {matched}");
        }
        return;
    }
    let rows = support::allocations::measure(TEST, ENV, SENTINEL, &[0, 1, 2, 3, 4, 5, 6, 7], 3);
    for (kind, row) in rows.iter().enumerate() {
        let expected = if kind == 7 { 0 } else { CALLS };
        assert_eq!(row[2], expected, "the value observer did not measure probe {kind}");
        assert!(row[0] >= CALLS, "probe {kind} missed its heap block sentinels: {row:?}");
        assert!(row[1] >= CALLS, "probe {kind} missed its heap byte sentinels: {row:?}");
    }
    assert!(rows[5][0] > rows[0][0], "the parser's extra block was not observed: {rows:?}");
    assert!(rows[5][1] > rows[0][1], "the parser's extra bytes were not observed: {rows:?}");
    for (label, kind, control) in [
        ("present", 1, 0),
        ("absent", 2, 6),
        ("has present", 3, 0),
        ("has absent", 4, 6),
    ] {
        println!("{label}: {:?}; static control {:?}", rows[kind], rows[control]);
        assert!(rows[kind][0] <= rows[control][0], "{label} lookup owned its fixed name: {rows:?}");
        assert!(rows[kind][1] <= rows[control][1], "{label} lookup copied its fixed name bytes: {rows:?}");
    }
}

/// Differently cased and unknown names are still valid; malformed names stay absent.
#[test]
fn other_spellings_and_invalid_inputs_keep_their_meaning() {
    let values: Vec<_> = (0..NAMES.len()).map(|index| format!("field-{index}")).collect();
    let wire = accepted(true, &values);
    let view = MetaView::of(&wire, TargetKind::Object).expect("an object view");
    for (&name, value) in NAMES.iter().zip(&values) {
        let uppercase = name.to_ascii_uppercase();
        assert_eq!(view.header(&uppercase).as_deref(), Some(value.as_str()));
        assert!(view.has_header(&uppercase));
    }
    for name in ["", "bad name", "bad:name", "bad\r\nname", "bad\u{e9}"] {
        assert_eq!(view.header(name), None, "an invalid lookup became present");
        assert!(!view.has_header(name), "an invalid lookup became present");
    }
    let request = http::Request::builder()
        .uri("/bucket/key")
        .header("host", "localhost")
        .header("x-gateway-unknown-fixed-name", "unknown")
        .body(())
        .expect("a static head");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an accepted head");
    let view = MetaView::of(&wire, TargetKind::Object).expect("an object view");
    assert_eq!(view.header("x-gateway-unknown-fixed-name").as_deref(), Some("unknown"));
    assert!(view.has_header("x-gateway-unknown-fixed-name"));
}

/// Static names retain the one-empty-line rule in both lookup methods.
#[test]
fn an_empty_fixed_name_obeys_the_selected_policy() {
    let values = vec![String::new(); NAMES.len()];
    let wire = accepted(true, &values);
    let ordinary = MetaView::of(&wire, TargetKind::Object).expect("an object view");
    let absent = MetaView::of(&wire, TargetKind::Object)
        .expect("an object view")
        .with_empty_headers_absent();
    for &name in NAMES {
        assert_eq!(ordinary.header(name).as_deref(), Some(""));
        assert!(ordinary.has_header(name));
        assert_eq!(absent.header(name), None);
        assert!(!absent.has_header(name));
    }
}

/// Joining retains order and an empty first line even under the empty-header policy.
#[test]
fn repeated_fixed_names_keep_both_lines() {
    for &name in NAMES.iter().filter(|name| **name != "content-md5") {
        let request = http::Request::builder()
            .uri("/bucket/key")
            .header("host", "localhost")
            .header(name, "")
            .header("x-gateway-unrelated-fixed-name", "unrelated")
            .header(name, "second")
            .body(())
            .expect("a static head");
        let wire = WireRequest::accept(request, &Limits::default()).expect("an accepted head");
        let view = MetaView::of(&wire, TargetKind::Object)
            .expect("an object view")
            .with_empty_headers_absent();
        assert_eq!(view.header(name).as_deref(), Some(", second"));
        assert!(view.has_header(name));
    }
}

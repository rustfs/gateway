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

//! The allocation budget the acceptance layer promises, asserted rather than claimed.
//!
//! Responsible for: proving that indexing a realistic query string and writing canonical headers
//! for a realistic signed-header list allocate nothing beyond the buffer the caller brought.
//! NOT responsible for: wall-clock timing, and any statement about allocations made by the
//! transport before this layer is reached.
//! Upstream: `support`. Downstream: nothing.
//!
//! The obvious instrument — a counting global allocator — cannot be used here: the workspace
//! *forbids* `unsafe_code`, and `GlobalAlloc` cannot be implemented without it, so a counting
//! allocator would mean lifting a prohibition to measure a performance property. These assertions
//! are the structural equivalent: every buffer this layer owns reports whether it stayed inline,
//! and a writer that allocated would have grown the caller's pre-sized `String`.

use crate::support::{accept, raw_value};
use http::{HeaderName, Request, header::HOST};
use rustfs_gateway_http::SignedHeaderList;

#[test]
fn indexing_an_eight_parameter_query_stays_off_the_heap() {
    let request = Request::builder()
        .uri(
            "/bucket?list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1000\
             &continuation-token=abc&encoding-type=url&fetch-owner=true&start-after=x",
        )
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    let accepted = accept(request).expect("valid fixture");
    assert_eq!(accepted.query().len(), 8);
    assert!(
        accepted.query().is_inline(),
        "eight parameters is the inline capacity; spilling here would be one malloc per request"
    );
}

#[test]
fn a_normal_host_stays_off_the_heap_in_both_its_forms() {
    let accepted = accept(crate::support::origin_form("/bucket/key")).expect("valid fixture");
    assert!(
        accepted.host().is_inline(),
        "the raw and the normalised host both fit inline for any realistic name"
    );
}

#[test]
fn writing_canonical_headers_does_not_grow_the_callers_buffer() {
    let mut request = Request::builder()
        .method("PUT")
        .uri("/bucket/key")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    for (name, value) in [
        ("x-amz-date", "20260805T000000Z"),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ("content-type", "application/octet-stream"),
    ] {
        request
            .headers_mut()
            .append(HeaderName::from_static(name), raw_value(value.as_bytes()));
    }
    let accepted = accept(request).expect("valid fixture");
    let signed = SignedHeaderList::parse("content-type;host;x-amz-content-sha256;x-amz-date").expect("ascending list");

    let mut out = String::with_capacity(512);
    let capacity_before = out.capacity();
    accepted
        .headers()
        .write_canonical_headers_with_host(&signed, &"b.example.com", &mut out)
        .expect("every signed header is present");
    assert_eq!(
        out.capacity(),
        capacity_before,
        "the writer must not allocate; the caller's buffer is the only storage involved"
    );
    assert!(!out.is_empty());
    // And nothing was sorted: the output order is the signed-header order, verbatim.
    let names: Vec<&str> = out.lines().filter_map(|line| line.split(':').next()).collect();
    assert_eq!(names, signed.iter().collect::<Vec<&str>>());
}

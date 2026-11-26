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

//! Unit controls for route predicate matching on `selector.rs`.
//!
//! Responsible for: verifying ASCII case-insensitive `Predicate::HeaderPrefix` matching against
//! accepted `WireRequest` headers.
//! NOT responsible for: full route-table resolution (`crates/core/tests/route_table.rs`) or
//! lattice overlap checks (`lattice.rs`).
//! Upstream: the parent `selector` module. Downstream: nothing; this is a leaf test module.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use http::Request;
use rustfs_gateway_http::{Limits, WireRequest};

fn accept_with_content_type(content_type: Option<&str>) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("http://host.invalid/bucket")
        .header("host", "host.invalid");
    if let Some(value) = content_type {
        builder = builder.header("content-type", value);
    }
    WireRequest::accept(builder.body(()).expect("valid request"), &Limits::default()).expect("accepted")
}

fn parts_of(wire: &WireRequest<()>) -> RouteRequestParts<'_> {
    RouteRequestParts {
        method: wire.method(),
        path: wire.raw_path().as_str(),
        target: TargetKind::Bucket,
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
        host_named_bucket: false,
    }
}

#[test]
fn n_header_prefix_matches_ascii_case_insensitively() {
    let predicate = Predicate::HeaderPrefix("content-type", "multipart/form-data");
    for matching in [
        "multipart/form-data; boundary=x",
        "Multipart/Form-Data; boundary=x",
        "MULTIPART/FORM-DATA; boundary=x",
        "mUlTiPaRt/FoRm-DaTa",
    ] {
        let wire = accept_with_content_type(Some(matching));
        assert!(predicate.matches(&parts_of(&wire)), "failed for {matching}");
    }
    for non_matching in ["text/plain", "multipart/mixed; boundary=x", "multipart/form", ""] {
        let wire = accept_with_content_type(Some(non_matching));
        assert!(!predicate.matches(&parts_of(&wire)), "unexpectedly matched {non_matching}");
    }
    let absent = accept_with_content_type(None);
    assert!(!predicate.matches(&parts_of(&absent)));
}

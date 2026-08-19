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

//! The compiled router: fast, and still the same answer.
//!
//! Responsible for: the cost of the hot shapes, the derivation of the subresource bits, the
//! sixty-four-key ceiling, and — the only reason the compiled router is allowed to exist — that
//! it agrees with the readable table on every request anybody can generate.
//! NOT responsible for: wall-clock timing. Nothing here measures nanoseconds. Time is flaky on a
//! shared runner; a predicate-evaluation count and a `size_of` are not, and they are what actually
//! distinguishes an array index from a linear scan.
//! Upstream: `support`, `proptest`. Downstream: nothing.
//!
//! # Why allocations are asserted structurally
//!
//! The obvious instrument is a counting global allocator, and the workspace *forbids* `unsafe`, so
//! `GlobalAlloc` cannot be implemented — measuring a performance property would mean lifting a
//! safety prohibition. The structural equivalent is used instead, as in
//! `crates/http/tests/allocation_budget.rs`: `resolve` takes borrowed views and returns a `Copy`
//! id, every buffer it touches reports whether it stayed inline, and the evaluation counter proves
//! the loop it would have allocated for never ran.

use crate::support;

use http::Method;
use proptest::prelude::*;
use rustfs_gateway_core::route::{
    ArnForm, CompileError, CompiledRouter, HostClass, MAX_SUBRESOURCE_KEYS, Predicate, RouteBucket, RouteTable, ShadowingDecls,
    ShadowingPolicy, TargetKind,
};
use support::{Req, entry, fixture_table};

/// One differential case: a request line, an optional target override, a host class, an optional
/// ARN form, and an optional header.
type Case = (
    &'static str,
    Option<TargetKind>,
    HostClass,
    Option<ArnForm>,
    Option<(&'static str, &'static str)>,
);

/// What the generator draws: indices into the tables below, plus a query and a header list.
type GeneratedRequest = (usize, usize, usize, usize, Vec<(usize, usize)>, Vec<usize>);

fn compiled() -> (RouteTable, CompiledRouter) {
    let table = fixture_table();
    let compiled = CompiledRouter::compile(&table).expect("the fixture table compiles");
    (table, compiled)
}

fn name_of(table: &RouteTable, id: Option<u16>) -> Option<&'static str> {
    id.and_then(|id| table.entries().get(usize::from(id)))
        .map(|entry| entry.op_name)
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// c-fast-0001 — the shape that is most of the traffic costs nothing to route.
#[test]
fn an_object_get_with_no_query_costs_zero_predicate_evaluations() {
    let (table, router) = compiled();
    let request = Req::new("GET /bucket/key");
    let (id, evaluations) = router.resolve_counted(&request.parts());
    assert_eq!(name_of(&table, id), Some("GetObject"));
    assert_eq!(
        evaluations, 0,
        "an object read must be an array index; any evaluation here means the shortcut was not installed"
    );

    let bucket = router.bucket(&Method::GET, TargetKind::Object).expect("a bucket");
    assert!(bucket.default_op().is_some(), "the shortcut must be precomputed");
}

/// The same is true of the other three data-plane verbs that carry no query.
#[test]
fn head_and_delete_take_the_same_shortcut() {
    let entries = vec![
        entry(
            "HeadObject",
            820,
            vec![Predicate::Method(Method::HEAD), Predicate::Target(TargetKind::Object)],
        ),
        entry(
            "DeleteObject",
            830,
            vec![Predicate::Method(Method::DELETE), Predicate::Target(TargetKind::Object)],
        ),
    ];
    let table = RouteTable::build(entries, &ShadowingDecls::NONE).expect("a table");
    let router = CompiledRouter::compile(&table).expect("compiles");
    for (line, expected) in [("HEAD /bucket/key", "HeadObject"), ("DELETE /bucket/key", "DeleteObject")] {
        let request = Req::new(line);
        let (id, evaluations) = router.resolve_counted(&request.parts());
        assert_eq!(name_of(&table, id), Some(expected));
        assert_eq!(evaluations, 0, "{line} must be an array index");
    }
}

/// c-fast-0002 — a `PUT` still routes correctly even though a header decides the answer.
#[test]
fn an_object_put_routes_correctly_through_the_header_test() {
    let (table, router) = compiled();
    let plain = Req::new("PUT /bucket/key");
    let (id, evaluations) = router.resolve_counted(&plain.parts());
    assert_eq!(name_of(&table, id), Some("PutObject"));
    assert!(evaluations <= 4, "a bounded constant, not a scan of the table; got {evaluations}");

    let copy = Req::new("PUT /bucket/key").header("x-amz-copy-source", "/other/key");
    assert_eq!(name_of(&table, router.resolve(&copy.parts())), Some("CopyObject"));
}

/// c-fast-0003
#[test]
fn analytics_with_an_id_goes_through_the_mask_bucket() {
    let (table, router) = compiled();
    let request = Req::new("GET /bucket?analytics&id=x");
    assert_eq!(name_of(&table, router.resolve(&request.parts())), Some("GetBucketAnalyticsConfiguration"));
    assert!(router.bits().mask_for("analytics") != 0, "analytics carries a bit");
    assert!(router.bits().mask_for("id") != 0, "so does its discriminator");
}

/// c-fast-0004
#[test]
fn analytics_without_an_id_is_the_listing() {
    let (table, router) = compiled();
    let request = Req::new("GET /bucket?analytics");
    assert_eq!(
        name_of(&table, router.resolve(&request.parts())),
        Some("ListBucketAnalyticsConfigurations")
    );
}

/// c-fast-0005 — a realistic listing routes, and its query index never reaches the heap.
#[test]
fn a_six_parameter_listing_stays_off_the_heap() {
    let (table, router) = compiled();
    let request = Req::new("GET /bucket?list-type=2&prefix=x&max-keys=1000&delimiter=%2F&encoding-type=url&start-after=t");
    assert!(request.query_is_inline(), "six parameters is under the inline capacity");
    assert_eq!(name_of(&table, router.resolve(&request.parts())), Some("ListObjectsV2"));
}

/// The bit table is derived from the route table, so it cannot drift from it.
#[test]
fn the_subresource_keys_are_exactly_the_keys_the_table_routes_on() {
    let (table, router) = compiled();
    let mut from_table: Vec<&str> = table
        .entries()
        .iter()
        .flat_map(|entry| entry.selector.predicates().iter().filter_map(query_key))
        .collect();
    from_table.sort_unstable();
    from_table.dedup();

    let from_bits: Vec<&str> = router.bits().keys().iter().map(|(key, _)| *key).collect();
    assert_eq!(from_bits, from_table, "the bit table has no independent source");
    assert!(from_bits.contains(&"analytics") && from_bits.contains(&"list-type"));
    assert!(!from_bits.contains(&"prefix"), "a key nothing routes on must not occupy a bit");
}

fn query_key(predicate: &Predicate) -> Option<&'static str> {
    match *predicate {
        Predicate::QueryPresent(key) | Predicate::QueryEquals(key, _) | Predicate::QueryAbsent(key) => Some(key),
        _ => None,
    }
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// c-fast-1001 — the two implementations agree on every case the route tests cover.
#[test]
fn both_implementations_agree_on_every_route_case() {
    let (table, router) = compiled();
    let cases: &[Case] = &[
        ("GET /bucket/key", None, HostClass::Standard, None, None),
        ("GET /bucket?analytics&id=x", None, HostClass::Standard, None, None),
        ("GET /bucket?analytics", None, HostClass::Standard, None, None),
        ("PUT /bucket/key?x-id=PutObject", None, HostClass::Standard, None, None),
        (
            "POST /bucket",
            None,
            HostClass::Standard,
            None,
            Some(("content-type", "multipart/form-data; boundary=----abc")),
        ),
        (
            "POST /WriteGetObjectResponse",
            Some(TargetKind::Bucket),
            HostClass::ObjectLambda,
            None,
            None,
        ),
        (
            "GET /arn:aws:s3:us-west-2:1:accesspoint/ap/key",
            Some(TargetKind::Object),
            HostClass::Standard,
            Some(ArnForm::AccessPoint),
            None,
        ),
        ("GET /bucket?acl&tagging", None, HostClass::Standard, None, None),
        ("GET /bucket?uploads&acl", None, HostClass::Standard, None, None),
        ("GET /bucket?list-type=2", None, HostClass::Standard, None, None),
        ("GET /bucket?list-type=3", None, HostClass::Standard, None, None),
        ("POST /bucket/key?select-type=2", None, HostClass::Standard, None, None),
        ("GET /", Some(TargetKind::Service), HostClass::Standard, None, None),
        ("POST /WriteGetObjectResponse", Some(TargetKind::Bucket), HostClass::Standard, None, None),
        ("PUT /bucket/key", None, HostClass::Standard, None, Some(("x-amz-copy-source", "/b/k"))),
    ];

    for (line, target, host_class, arn, header) in cases {
        let mut request = Req::new(line).host_class(*host_class);
        if let Some(target) = target {
            request = request.target(*target);
        }
        if let Some(form) = arn {
            request = request.arn(*form);
        }
        if let Some((name, value)) = header {
            request = request.header(name, value);
        }
        let parts = request.parts();
        let readable = table.resolve(&parts).map(|entry| entry.op_name);
        let fast = name_of(&table, router.resolve(&parts));
        assert_eq!(readable, fast, "the two implementations disagree about {line}");
    }
}

/// c-fast-1004 — a table over the ceiling fails to compile rather than losing keys.
#[test]
fn a_table_routing_on_more_than_sixty_four_keys_will_not_compile() {
    // Each entry gets its own key, and each key claims a bit.
    let keys: Vec<String> = (0..=MAX_SUBRESOURCE_KEYS).map(|index| format!("k{index:04}")).collect();
    let entries = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let leaked: &'static str = Box::leak(key.clone().into_boxed_str());
            let name: &'static str = Box::leak(format!("Op{index:04}").into_boxed_str());
            entry(
                name,
                u16::try_from(index).unwrap_or(u16::MAX),
                vec![
                    Predicate::Method(Method::GET),
                    Predicate::Target(TargetKind::Bucket),
                    Predicate::QueryPresent(leaked),
                ],
            )
        })
        .collect();
    let table = RouteTable::build(entries, &ShadowingDecls::NONE.with_policy(ShadowingPolicy::TotalOnly))
        .expect("the entries themselves are fine");
    let error = CompiledRouter::compile(&table).expect_err("sixty-five keys do not fit in sixty-four bits");
    let CompileError::TooManySubresourceKeys { count, overflow } = &error else {
        panic!("expected the ceiling, got {error}");
    };
    assert_eq!(*count, MAX_SUBRESOURCE_KEYS + 1);
    assert!(!overflow.is_empty(), "the report must name the key that did not fit");
    assert!(
        error.to_string().contains("do not drop keys"),
        "silent truncation must be refused in so many words"
    );
}

/// c-fast-1010 — the bucket stays small enough to be worth indexing.
#[test]
fn the_bucket_is_small_enough_to_index() {
    assert!(
        size_of::<RouteBucket>() <= 64,
        "a bucket is copied per request; {} bytes is too many",
        size_of::<RouteBucket>()
    );
}

/// c-fast-1011 — a query past the inline capacity still routes correctly.
#[test]
fn a_twelve_parameter_query_still_routes_correctly() {
    let (table, router) = compiled();
    let mut query = String::from("analytics&id=x");
    for index in 0..10 {
        query.push_str(&format!("&extra{index}=v"));
    }
    let request = Req::new(&format!("GET /bucket?{query}"));
    assert!(!request.query_is_inline(), "twelve parameters spill, and that is allowed");
    assert_eq!(
        name_of(&table, router.resolve(&request.parts())),
        Some("GetBucketAnalyticsConfiguration"),
        "spilling may cost an allocation in the wire layer; it may never change the answer"
    );
}

/// The shortcut must not be installed where a header decides the answer.
#[test]
fn no_shortcut_is_installed_where_a_header_decides() {
    let (_, router) = compiled();
    let post_bucket = router.bucket(&Method::POST, TargetKind::Bucket).expect("a bucket");
    assert_eq!(
        post_bucket.default_op(),
        None,
        "a form upload is decided by content-type, so there is nothing to precompute"
    );
    let put_object = router.bucket(&Method::PUT, TargetKind::Object).expect("a bucket");
    assert_eq!(put_object.default_op(), None, "PutObject and CopyObject differ only by a header");
}

/// A method the array does not index has no route, and costs nothing to refuse.
#[test]
fn an_unindexed_method_has_no_route() {
    let (_, router) = compiled();
    let request = Req::new("PATCH /bucket/key");
    let (id, evaluations) = router.resolve_counted(&request.parts());
    assert_eq!(id, None);
    assert_eq!(evaluations, 0);
}

/// Unknown query keys carry no bit, so they do not push a request off the fast path.
#[test]
fn unknown_query_keys_do_not_cost_the_shortcut() {
    let (table, router) = compiled();
    let request = Req::new("GET /bucket/key?x-id=GetObject&response-content-type=text%2Fplain&partNumber=1");
    let (id, evaluations) = router.resolve_counted(&request.parts());
    assert_eq!(name_of(&table, id), Some("GetObject"));
    assert_eq!(evaluations, 0, "a key nothing routes on must be free");
}

/// The readable implementation is still here, and is still the reference.
#[test]
fn the_readable_implementation_is_not_deleted() {
    let table = fixture_table();
    let request = Req::new("GET /bucket?acl");
    let (hit, evaluations) = table.resolve_counted(&request.parts());
    assert_eq!(hit.map(|entry| entry.op_name), Some("GetBucketAcl"));
    assert!(
        evaluations > 0,
        "the readable implementation evaluates predicates; that is the point of keeping it"
    );
}

// ── the differential generator ────────────────────────────────────────────────────────────────

/// The keys and headers the generator draws from: enough to reach every rule in the fixture.
const QUERY_KEYS: &[&str] = &[
    "acl",
    "tagging",
    "analytics",
    "id",
    "uploads",
    "list-type",
    "select-type",
    "x-id",
    "prefix",
];
const QUERY_VALUES: &[&str] = &["", "2", "3", "x"];
const METHODS: &[&str] = &["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "PATCH"];
const PATHS: &[&str] = &["/", "/bucket", "/bucket/key", "/WriteGetObjectResponse"];
const HEADERS: &[(&str, &str)] = &[
    ("content-type", "multipart/form-data; boundary=abc"),
    ("content-type", "application/xml"),
    ("x-amz-copy-source", "/other/key"),
];

fn a_request() -> impl Strategy<Value = GeneratedRequest> {
    (
        0..METHODS.len(),
        0..PATHS.len(),
        0..TargetKind::ALL.len(),
        0..HostClass::ALL.len(),
        proptest::collection::vec((0..QUERY_KEYS.len(), 0..QUERY_VALUES.len()), 0..5),
        proptest::collection::vec(0..HEADERS.len(), 0..3),
    )
}

proptest! {
    /// c-fast-1002 — no generated request separates the two implementations.
    ///
    /// This is the differential fuzz the issue asks for, in the only form this task can add: `fuzz/`
    /// is outside its file scope, so the generator runs under `proptest` in the ordinary test run.
    /// A maintainer adding `fuzz/fuzz_targets/route_compiled_equiv.rs` later can lift the body
    /// verbatim.
    #[test]
    fn no_generated_request_separates_the_two_implementations(
        (method, path, target, host, query, headers) in a_request()
    ) {
        let table = fixture_table();
        let router = CompiledRouter::compile(&table).expect("compiles");

        let mut seen: Vec<usize> = Vec::new();
        let mut query_string = String::new();
        for (key, value) in &query {
            if seen.contains(key) {
                continue;   // a repeated parameter is refused by acceptance, so never routed
            }
            seen.push(*key);
            if !query_string.is_empty() {
                query_string.push('&');
            }
            query_string.push_str(QUERY_KEYS.get(*key).copied().unwrap_or("acl"));
            let value = QUERY_VALUES.get(*value).copied().unwrap_or("");
            if !value.is_empty() {
                query_string.push('=');
                query_string.push_str(value);
            }
        }

        let method = METHODS.get(method).copied().unwrap_or("GET");
        let path = PATHS.get(path).copied().unwrap_or("/bucket");
        let line = if query_string.is_empty() {
            format!("{method} {path}")
        } else {
            format!("{method} {path}?{query_string}")
        };

        let mut request = Req::new(&line)
            .target(TargetKind::ALL.get(target).copied().unwrap_or(TargetKind::Bucket))
            .host_class(HostClass::ALL.get(host).copied().unwrap_or(HostClass::Standard));
        for index in &headers {
            if let Some((name, value)) = HEADERS.get(*index) {
                request = request.header(name, value);
            }
        }

        let parts = request.parts();
        let readable = table.resolve(&parts).map(|entry| entry.op_name);
        let fast = name_of(&table, router.resolve(&parts));
        prop_assert_eq!(readable, fast, "the two implementations disagree about {}", line);
    }

    /// c-route-1011, generated: no precedence ever matches twice.
    ///
    /// Structurally true while the fixture's precedences stay pairwise distinct, so it is not the
    /// case's evidence — `route_table.rs`'s
    /// `two_selectors_the_lattice_called_disjoint_never_both_match` and
    /// `fuzz/fuzz_targets/route_disjoint.rs` state the property where it can fail. What this adds
    /// is that a row sharing a precedence is caught by a generated request rather than by review.
    #[test]
    fn no_precedence_matches_twice_for_a_generated_request(
        (method, path, target, host, query, headers) in a_request()
    ) {
        let table = fixture_table();

        let mut seen: Vec<usize> = Vec::new();
        let mut query_string = String::new();
        for (key, value) in &query {
            if seen.contains(key) {
                continue;
            }
            seen.push(*key);
            if !query_string.is_empty() {
                query_string.push('&');
            }
            query_string.push_str(QUERY_KEYS.get(*key).copied().unwrap_or("acl"));
            let value = QUERY_VALUES.get(*value).copied().unwrap_or("");
            if !value.is_empty() {
                query_string.push('=');
                query_string.push_str(value);
            }
        }

        let method = METHODS.get(method).copied().unwrap_or("GET");
        let path = PATHS.get(path).copied().unwrap_or("/bucket");
        let line = if query_string.is_empty() {
            format!("{method} {path}")
        } else {
            format!("{method} {path}?{query_string}")
        };

        let mut request = Req::new(&line)
            .target(TargetKind::ALL.get(target).copied().unwrap_or(TargetKind::Bucket))
            .host_class(HostClass::ALL.get(host).copied().unwrap_or(HostClass::Standard));
        for index in &headers {
            if let Some((name, value)) = HEADERS.get(*index) {
                request = request.header(name, value);
            }
        }

        let parts = request.parts();
        let mut precedences: Vec<u16> = table
            .entries()
            .iter()
            .filter(|entry| entry.selector.matches(&parts))
            .map(|entry| entry.precedence)
            .collect();
        let matched = precedences.len();
        precedences.sort_unstable();
        precedences.dedup();
        prop_assert_eq!(matched, precedences.len(), "two entries at one precedence matched {}", line);
    }
}

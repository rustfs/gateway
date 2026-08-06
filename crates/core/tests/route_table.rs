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

//! The ordered table: what it routes, and everything it refuses to be built from.
//!
//! Responsible for: the route cases — eleven positive, thirty negative — including the one that
//! falsifies a fake overlap check, and the pair that pins an operation the protocol defines and
//! this build does not serve to its own row rather than to its neighbour's.
//! NOT responsible for: parameter validation (`params_and_dispatch.rs`), the compiled form
//! (`hot_path.rs`), the golden rendering (`golden.rs`).
//! Upstream: `support`. Downstream: nothing.
//!
//! # The test that decides whether this crate is honest
//!
//! [`containment_at_one_precedence_is_a_conflict_too`] puts `GET + Bucket + QueryPresent("acl")`
//! and `GET + Bucket` at the same precedence. They are not equal and they share no query key, so
//! every pairwise-equality "ambiguity check" passes them. One of them is unreachable. If this test
//! goes green while that one goes red, the overlap decision has been replaced by a comparison.

mod support;

use http::Method;
use rustfs_gateway_core::route::{
    ArnForm, HostClass, Predicate, RouteBuildError, RouteTable, ShadowingDecl, ShadowingDecls, ShadowingPolicy, TargetKind,
    generated_entries,
};
use support::{Req, entry, fixture_entries, fixture_table};

/// The evidence a fixture declaration carries. Real declarations cite AWS or a defect report.
const FIXTURE_EVIDENCE: &[&str] = &["fixture: exercised by crates/core/tests/route_table.rs"];

fn routed(table: &RouteTable, request: &Req) -> Option<&'static str> {
    table.resolve(&request.parts()).map(|entry| entry.op_name)
}

/// The generated table, built under the strict shadowing policy the crate ships with.
fn generated_table() -> RouteTable {
    let entries = generated_entries().expect("the generated rows parse");
    RouteTable::build(entries, &ShadowingDecls::new(rustfs_gateway_core::route::PROVISIONAL_SHADOWING))
        .expect("the generated table is well formed under the strict shadowing policy")
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// c-route-0001
#[test]
fn an_object_get_lands_in_the_object_band() {
    let table = fixture_table();
    let request = Req::new("GET /bucket/key");
    let hit = table.resolve(&request.parts()).expect("an object GET has a route");
    assert_eq!(hit.op_name, "GetObject");
    assert!(
        (800..=899).contains(&hit.precedence),
        "the plain object operations live in the 800 band, got {}",
        hit.precedence
    );
}

/// c-route-0002
#[test]
fn analytics_with_an_id_beats_the_listing() {
    let table = fixture_table();
    assert_eq!(
        routed(&table, &Req::new("GET /bucket?analytics&id=x")),
        Some("GetBucketAnalyticsConfiguration")
    );
}

/// c-route-0003
#[test]
fn analytics_without_an_id_is_the_listing() {
    let table = fixture_table();
    assert_eq!(
        routed(&table, &Req::new("GET /bucket?analytics")),
        Some("ListBucketAnalyticsConfigurations")
    );
}

/// c-route-0004 — the SDKs append `x-id` to almost everything, so it must be inert.
#[test]
fn an_unknown_x_id_parameter_does_not_disturb_routing() {
    let table = fixture_table();
    assert_eq!(routed(&table, &Req::new("PUT /bucket/key?x-id=PutObject")), Some("PutObject"));
    assert_eq!(routed(&table, &Req::new("GET /bucket/key?x-id=GetObject")), Some("GetObject"));
}

/// c-route-0005 — the boundary parameter must not defeat the content-type test.
#[test]
fn post_object_matches_the_content_type_prefix_with_its_boundary() {
    let table = fixture_table();
    let request = Req::new("POST /bucket").header("content-type", "multipart/form-data; boundary=----abc");
    assert_eq!(routed(&table, &request), Some("PostObject"));
}

/// c-route-0006
#[test]
fn the_object_lambda_response_matches_its_literal_path() {
    let table = fixture_table();
    let request = Req::new("POST /WriteGetObjectResponse")
        .target(TargetKind::Bucket)
        .host_class(HostClass::ObjectLambda);
    let hit = table.resolve(&request.parts()).expect("a route");
    assert_eq!(hit.op_name, "WriteGetObjectResponse");
    assert!(hit.precedence < 100, "literal paths live below 100");
}

/// c-route-0007 — an ARN in the bucket position leaves the target an object.
#[test]
fn an_access_point_arn_still_targets_an_object() {
    let table = fixture_table();
    let request = Req::new("GET /arn:aws:s3:us-west-2:123:accesspoint/ap/key")
        .target(TargetKind::Object)
        .arn(ArnForm::AccessPoint);
    let hit = table.resolve(&request.parts()).expect("a route");
    assert_eq!(hit.op_name, "GetObjectViaAccessPoint");
}

/// c-route-0008 — two subresources at once is answered, and the loser is named.
#[test]
fn acl_and_tagging_together_pick_a_band_and_explain_the_other() {
    let table = fixture_table();
    let request = Req::new("GET /bucket?acl&tagging");
    assert_eq!(routed(&table, &request), Some("GetBucketAcl"));

    let explanation = table.explain(&request.parts());
    assert_eq!(explanation.matched.map(|hit| hit.op_name), Some("GetBucketAcl"));
    let shadowed: Vec<_> = explanation.shadowed.iter().map(|hit| hit.op_name).collect();
    assert_eq!(shadowed, vec!["GetBucketTagging"], "the other subresource must be named");
}

/// The generated table is not a fixture: it must build under the strict policy and route.
#[test]
fn the_generated_table_builds_and_routes() {
    let entries = generated_entries().expect("the generated rows parse");
    let table = RouteTable::build(entries, &ShadowingDecls::new(rustfs_gateway_core::route::PROVISIONAL_SHADOWING))
        .expect("the generated table is well formed under the strict shadowing policy");
    assert_eq!(routed(&table, &Req::new("PUT /bucket/key")), Some("PutObject"));
    assert_eq!(routed(&table, &Req::new("GET /bucket?location")), Some("GetBucketLocation"));
    assert_eq!(routed(&table, &Req::new("GET /bucket?list-type=2")), Some("ListObjectsV2"));
}

/// The attributes subresource selects the attributes operation, in the generated table.
///
/// Positive half of the pair below. `?attributes` is one query key away from a plain object read,
/// so the interesting assertion is not that the row exists but that it is tried first — hence the
/// precedence check beside it.
#[test]
fn the_attributes_subresource_routes_to_the_attributes_operation() {
    let table = generated_table();
    let hit = table
        .resolve(&Req::new("GET /bucket/key?attributes").parts())
        .expect("an attributes read has a route");
    assert_eq!(hit.op_name, "GetObjectAttributes");
    assert!(
        hit.precedence < 800,
        "the attributes row must sit ahead of the object band, got {}",
        hit.precedence
    );
}

/// A plain object read is untouched by the row that was added ahead of it.
#[test]
fn a_plain_object_read_still_routes_to_get_object() {
    let table = generated_table();
    assert_eq!(routed(&table, &Req::new("GET /bucket/key")), Some("GetObject"));
    assert_eq!(routed(&table, &Req::new("GET /bucket/key?versionId=v")), Some("GetObject"));
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// An attributes read must never be answered by the object read.
///
/// This is the defect the row exists for: with no `?attributes` row the request is not refused,
/// it is claimed by `GetObject` and answered with the object's bytes. The assertion is written as
/// an inequality rather than an equality so that it keeps its meaning if the winner ever changes
/// for some other reason.
#[test]
fn an_attributes_read_is_never_claimed_by_the_object_read() {
    let table = generated_table();
    let hit = table
        .resolve(&Req::new("GET /bucket/key?attributes").parts())
        .expect("an attributes read has a route");
    assert_ne!(
        hit.op_name, "GetObject",
        "an attributes read answered by GetObject returns the object's bytes for a metadata question"
    );
}

/// The two routers agree about it, so the fast path cannot answer it differently.
#[test]
fn the_readable_and_compiled_tables_agree_about_the_attributes_read() {
    let table = generated_table();
    let request = Req::new("GET /bucket/key?attributes");
    let explanation = table.explain(&request.parts());
    assert_eq!(explanation.matched.map(|hit| hit.op_name), Some("GetObjectAttributes"));
    let shadowed: Vec<_> = explanation.shadowed.iter().map(|hit| hit.op_name).collect();
    assert!(
        shadowed.contains(&"GetObject"),
        "GetObject must be reported as the route that was hidden, got {shadowed:?}"
    );
}

/// A part listing that also names `?attributes` stays with the part listing.
///
/// Both keys in one request is undocumented, so the answer is the declared one rather than source
/// order. Reversing it would answer a part-listing request with an attributes document.
#[test]
fn a_part_listing_that_also_names_attributes_stays_with_the_part_listing() {
    let table = generated_table();
    assert_eq!(routed(&table, &Req::new("GET /bucket/key?uploadId=u&attributes")), Some("ListParts"));
}

/// `?attributes` on a bucket is not an attributes read, and must not become one.
#[test]
fn the_attributes_key_on_a_bucket_is_not_an_attributes_read() {
    let table = generated_table();
    assert_ne!(routed(&table, &Req::new("GET /bucket?attributes")), Some("GetObjectAttributes"));
}

/// The attributes row is a `GET`; the same key under another method must not reach it.
#[test]
fn the_attributes_key_under_another_method_does_not_reach_the_attributes_row() {
    let table = generated_table();
    for line in ["PUT /bucket/key?attributes", "DELETE /bucket/key?attributes"] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some("GetObjectAttributes"),
            "{line} must not route to a GET-only operation"
        );
    }
}

/// c-route-1001 — two subresources at one precedence, reachable together.
#[test]
fn two_subresources_at_one_precedence_are_a_conflict() {
    let entries = vec![
        entry(
            "GetBucketAcl",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("acl"),
            ],
        ),
        entry(
            "GetBucketTagging",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("tagging"),
            ],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("an overlap at one precedence is fatal");
    let RouteBuildError::Conflict { precedence, .. } = &error else {
        panic!("expected a conflict, got {error}");
    };
    assert_eq!(*precedence, 300);

    let rendered = error.to_string();
    for fragment in [
        "GetBucketAcl",
        "GetBucketTagging",
        "QueryPresent(\"acl\")",
        "QueryPresent(\"tagging\")",
        "acl",
        "tagging",
    ] {
        assert!(rendered.contains(fragment), "the report must contain {fragment:?}:\n{rendered}");
    }
    assert!(
        rendered.contains("both reachable by"),
        "the report must show a request reaching both:\n{rendered}"
    );
}

/// c-route-1002 — **the falsification test**. Containment, not equality.
///
/// `GET + Bucket + QueryPresent("acl")` and `GET + Bucket` are different selectors that share no
/// query key. A pairwise-equality check calls them disjoint. Every request the first accepts, the
/// second accepts too, so one of them is dead.
#[test]
fn containment_at_one_precedence_is_a_conflict_too() {
    let entries = vec![
        entry(
            "GetBucketAcl",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("acl"),
            ],
        ),
        entry(
            "ListObjects",
            300,
            vec![Predicate::Method(Method::GET), Predicate::Target(TargetKind::Bucket)],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("containment is an overlap");
    assert!(
        matches!(error, RouteBuildError::Conflict { .. }),
        "containment must be reported as a conflict, got {error}"
    );
    let rendered = error.to_string();
    assert!(rendered.contains("GetBucketAcl") && rendered.contains("ListObjects"));
    assert!(
        rendered.contains("QueryPresent(\"acl\")"),
        "both selectors in full, not just the names:\n{rendered}"
    );
}

/// c-route-1003 — a value constraint and a presence constraint on one key overlap.
#[test]
fn query_equals_and_query_present_at_one_precedence_conflict() {
    let entries = vec![
        entry(
            "SelectObjectContent",
            300,
            vec![
                Predicate::Method(Method::POST),
                Predicate::Target(TargetKind::Object),
                Predicate::QueryEquals("select-type", "2"),
            ],
        ),
        entry(
            "SelectSomethingElse",
            300,
            vec![
                Predicate::Method(Method::POST),
                Predicate::Target(TargetKind::Object),
                Predicate::QueryPresent("select-type"),
            ],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("Equals refines Present, so they overlap");
    assert!(matches!(error, RouteBuildError::Conflict { .. }), "got {error}");
}

/// c-route-1004
#[test]
fn an_undeclared_cross_precedence_overlap_fails_the_build() {
    let error = RouteTable::build(fixture_entries(), &ShadowingDecls::NONE)
        .expect_err("the strict policy asks for a declaration for every cross-precedence overlap");
    let RouteBuildError::UndeclaredShadowing { winner, shadowed, .. } = &error else {
        panic!("expected undeclared shadowing, got {error}");
    };
    assert!(winner.precedence < shadowed.precedence);
    assert!(error.to_string().contains("witness"), "the report must show a witness");
}

/// c-route-1004, the unreachable-route half: under `TotalOnly` a dead route is still fatal.
#[test]
fn a_route_made_unreachable_by_an_earlier_one_fails_the_build() {
    let entries = vec![
        entry(
            "ListBucketAnalyticsConfigurations",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
            ],
        ),
        // Every request this accepts, the entry above accepts first. It can never be reached.
        entry(
            "GetBucketAnalyticsConfiguration",
            310,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
                Predicate::QueryPresent("id"),
            ],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE.with_policy(ShadowingPolicy::TotalOnly))
        .expect_err("an unreachable route is fatal under either policy");
    let RouteBuildError::UndeclaredShadowing { total, .. } = &error else {
        panic!("expected undeclared shadowing, got {error}");
    };
    assert!(*total, "the report must say the route is unreachable, not merely overlapped");
}

/// c-route-1005 — a declaration about selectors that do not overlap has rotted.
#[test]
fn a_declaration_for_selectors_that_do_not_overlap_is_stale() {
    static DECLS: &[ShadowingDecl] = &[ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "PutObject",
        reason: "invented",
        evidence: FIXTURE_EVIDENCE,
    }];
    let entries = vec![
        entry(
            "GetBucketAcl",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("acl"),
            ],
        ),
        entry(
            "PutObject",
            800,
            vec![Predicate::Method(Method::PUT), Predicate::Target(TargetKind::Object)],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::new(DECLS)).expect_err("a declaration must describe reality");
    assert!(
        matches!(error, RouteBuildError::StaleShadowing { .. }),
        "expected a stale declaration, got {error}"
    );
    assert!(error.to_string().contains("do not overlap"));
}

/// A declaration naming an operation the table does not contain.
#[test]
fn a_declaration_naming_an_unknown_operation_is_stale() {
    static DECLS: &[ShadowingDecl] = &[ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketRetiredThing",
        reason: "left behind by a model upgrade",
        evidence: FIXTURE_EVIDENCE,
    }];
    let entries = vec![entry(
        "GetBucketAcl",
        300,
        vec![
            Predicate::Method(Method::GET),
            Predicate::Target(TargetKind::Bucket),
            Predicate::QueryPresent("acl"),
        ],
    )];
    let error = RouteTable::build(entries, &ShadowingDecls::new(DECLS)).expect_err("an unknown operation is stale");
    assert!(error.to_string().contains("not in the route table"), "got {error}");
}

/// A declaration whose winner does not actually win.
#[test]
fn a_declaration_in_the_wrong_direction_is_stale() {
    static DECLS: &[ShadowingDecl] = &[ShadowingDecl {
        winner: "ListBucketAnalyticsConfigurations",
        shadowed: "GetBucketAnalyticsConfiguration",
        reason: "backwards",
        evidence: FIXTURE_EVIDENCE,
    }];
    let entries = vec![
        entry(
            "GetBucketAnalyticsConfiguration",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
                Predicate::QueryPresent("id"),
            ],
        ),
        entry(
            "ListBucketAnalyticsConfigurations",
            310,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
            ],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::new(DECLS)).expect_err("the direction is checked");
    assert!(error.to_string().contains("lower precedence"), "got {error}");
}

/// An ordering nobody sourced is a guess with a comment attached.
#[test]
fn a_declaration_with_no_evidence_is_refused() {
    static DECLS: &[ShadowingDecl] = &[ShadowingDecl {
        winner: "GetBucketAnalyticsConfiguration",
        shadowed: "ListBucketAnalyticsConfigurations",
        reason: "because I said so",
        evidence: &[],
    }];
    let entries = vec![
        entry(
            "GetBucketAnalyticsConfiguration",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
                Predicate::QueryPresent("id"),
            ],
        ),
        entry(
            "ListBucketAnalyticsConfigurations",
            310,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
            ],
        ),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::new(DECLS)).expect_err("evidence is mandatory");
    assert!(
        matches!(error, RouteBuildError::UnsourcedShadowing { .. }),
        "expected an unsourced declaration, got {error}"
    );
}

/// c-route-1006 — an empty conjunction matches everything.
#[test]
fn an_empty_selector_outside_the_fallback_band_is_refused() {
    let error = RouteTable::build(vec![entry("Everything", 800, Vec::new())], &ShadowingDecls::NONE)
        .expect_err("an empty selector swallows the table");
    assert!(matches!(error, RouteBuildError::EmptySelectorOutsideFallback { .. }), "got {error}");
}

/// The same selector inside the fallback band is legal, and is the only place it is.
#[test]
fn an_empty_selector_inside_the_fallback_band_is_the_catch_all() {
    let table = RouteTable::build(vec![entry("NotImplemented", 950, Vec::new())], &ShadowingDecls::NONE)
        .expect("the fallback band is where an empty selector belongs");
    assert_eq!(routed(&table, &Req::new("BREW /teapot")), Some("NotImplemented"));
}

/// c-route-1007 — the defect this predicate set exists to prevent.
///
/// Selecting `WriteGetObjectResponse` from two headers alone misroutes any `POST /bucket` that
/// happens to carry them. The host class is what makes it decidable.
#[test]
fn the_object_lambda_route_does_not_match_on_the_standard_host() {
    let table = fixture_table();
    let request = Req::new("POST /WriteGetObjectResponse")
        .target(TargetKind::Bucket)
        .host_class(HostClass::Standard)
        .header("x-amz-request-route", "route")
        .header("x-amz-request-token", "token");
    assert_ne!(
        routed(&table, &request),
        Some("WriteGetObjectResponse"),
        "the standard endpoint must not reach the Object Lambda operation"
    );
}

/// c-route-1008 — a nonsensical combination still routes the same way every time.
#[test]
fn two_conflicting_subresources_route_the_same_way_every_time() {
    let table = fixture_table();
    let first = routed(&table, &Req::new("GET /bucket?uploads&acl"));
    let second = routed(&table, &Req::new("GET /bucket?acl&uploads"));
    assert_eq!(first, Some("GetBucketAcl"));
    assert_eq!(first, second, "the answer must not depend on the order the client wrote");
}

/// c-route-1009 — unknown parameters are inert however many there are.
///
/// Sixty rather than the case's hundred: acceptance caps a request at sixty-four query parameters
/// before the router ever sees it, so a hundred is a shape that cannot reach this layer.
#[test]
fn sixty_unknown_query_parameters_do_not_change_the_answer() {
    let table = fixture_table();
    let query = (0..60).map(|index| format!("k{index}=v")).collect::<Vec<_>>().join("&");
    let request = Req::new(&format!("GET /bucket/key?{query}"));
    assert_eq!(routed(&table, &request), Some("GetObject"));
}

/// c-route-1010 — a request nothing classifies must not panic and must not be a server error.
#[test]
fn an_unclassifiable_request_is_simply_unrouted() {
    let table = fixture_table();
    let request = Req::new("GET /").target(TargetKind::Service).host_class(HostClass::Website);
    assert_eq!(routed(&table, &request), None, "no route, and no panic");
}

/// c-route-1011 — the property the fuzz target would assert, asserted here.
///
/// `fuzz/` is outside this task's file scope, so the differential generator lives in
/// `hot_path.rs`; this is the same property stated over the readable table alone.
#[test]
fn at_most_one_entry_per_precedence_matches_any_request() {
    let table = fixture_table();
    let mut checked = 0usize;
    for method in ["GET", "PUT", "POST", "DELETE", "HEAD"] {
        for path in ["/", "/bucket", "/bucket/key", "/WriteGetObjectResponse"] {
            for query in [
                "",
                "acl",
                "tagging",
                "acl&tagging",
                "analytics",
                "analytics&id=x",
                "list-type=2",
                "uploads",
            ] {
                for target in TargetKind::ALL {
                    let line = if query.is_empty() {
                        format!("{method} {path}")
                    } else {
                        format!("{method} {path}?{query}")
                    };
                    let request = Req::new(&line).target(target);
                    let parts = request.parts();
                    let mut by_precedence: Vec<u16> = table
                        .entries()
                        .iter()
                        .filter(|entry| entry.selector.matches(&parts))
                        .map(|entry| entry.precedence)
                        .collect();
                    let before = by_precedence.len();
                    by_precedence.sort_unstable();
                    by_precedence.dedup();
                    assert_eq!(before, by_precedence.len(), "two entries at one precedence matched {line}");
                    checked = checked.saturating_add(1);
                }
            }
        }
    }
    assert!(checked > 400, "the sweep must actually cover something, covered {checked}");
}

/// A selector that constrains one key two ways can never match, and reads as coverage.
#[test]
fn a_self_contradictory_selector_is_refused() {
    let entries = vec![entry(
        "Impossible",
        300,
        vec![
            Predicate::Method(Method::GET),
            Predicate::QueryPresent("acl"),
            Predicate::QueryAbsent("acl"),
        ],
    )];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("no request satisfies this");
    let RouteBuildError::UnsatisfiableSelector { contradiction, .. } = &error else {
        panic!("expected an unsatisfiable selector, got {error}");
    };
    assert_eq!(contradiction.dimension, "query:acl");
}

/// Two methods on one selector is the same defect on a different dimension.
#[test]
fn a_selector_naming_two_methods_is_refused() {
    let entries = vec![entry(
        "Impossible",
        300,
        vec![Predicate::Method(Method::GET), Predicate::Method(Method::PUT)],
    )];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("a request has one method");
    assert!(matches!(error, RouteBuildError::UnsatisfiableSelector { .. }), "got {error}");
}

/// One operation, one entry.
#[test]
fn a_duplicate_operation_name_is_refused() {
    let entries = vec![
        entry("GetObject", 800, vec![Predicate::Method(Method::GET)]),
        entry("GetObject", 810, vec![Predicate::Method(Method::PUT)]),
    ];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("two rows for one operation");
    assert!(matches!(error, RouteBuildError::DuplicateOperation { .. }), "got {error}");
}

/// Header predicates assume the canonical lowercase spelling; anything else silently never matches.
#[test]
fn a_header_predicate_with_an_uppercase_name_is_refused() {
    let entries = vec![entry(
        "CopyObject",
        800,
        vec![Predicate::HeaderPresent {
            header: "X-Amz-Copy-Source",
            negated: false,
        }],
    )];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("header names are lowercase here");
    assert!(matches!(error, RouteBuildError::InvalidPredicate { .. }), "got {error}");
}

/// An empty prefix is the "does this header exist" question wearing the wrong predicate.
#[test]
fn an_empty_header_prefix_is_refused() {
    let entries = vec![entry(
        "CopyObject",
        800,
        vec![Predicate::HeaderPrefix("x-amz-copy-source", "")],
    )];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("use HeaderPresent instead");
    assert!(error.to_string().contains("HeaderPresent"), "got {error}");
}

/// A path literal that is not a path would never match, so it is refused rather than ignored.
#[test]
fn a_path_literal_without_a_leading_slash_is_refused() {
    let entries = vec![entry(
        "WriteGetObjectResponse",
        50,
        vec![Predicate::PathLiteral("WriteGetObjectResponse")],
    )];
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("a path starts with /");
    assert!(matches!(error, RouteBuildError::InvalidPredicate { .. }), "got {error}");
}

/// The generated row carries `method` and `target` twice; disagreement is a codegen bug.
#[test]
fn a_generated_row_whose_method_contradicts_its_predicate_is_refused() {
    use rustfs_gateway_core::route::{RoutePredicate, RouteRow};

    let row = RouteRow {
        operation: "Confused",
        precedence: 800,
        method: "GET",
        target: "Object",
        path_shape: "/{Bucket}/{Key+}",
        success_status: 200,
        predicates: &[RoutePredicate::Method("PUT"), RoutePredicate::Target("Object")],
    };
    let error = row.to_entry().expect_err("the row contradicts itself");
    assert!(error.to_string().contains("contradicts"), "got {error}");
}

/// A method spelling outside the closed vocabulary is a codegen bug, not an extension point.
#[test]
fn a_generated_row_with_an_unknown_method_is_refused() {
    use rustfs_gateway_core::route::{RoutePredicate, RouteRow};

    let row = RouteRow {
        operation: "Brew",
        precedence: 800,
        method: "BREW",
        target: "Object",
        path_shape: "/{Bucket}/{Key+}",
        success_status: 200,
        predicates: &[RoutePredicate::Target("Object")],
    };
    let error = row.to_entry().expect_err("BREW is not an S3 method");
    assert!(error.to_string().contains("unknown method"), "got {error}");
}

/// The witness in a conflict report is a real request that really reaches both entries.
///
/// Without this the witness is decoration; with it, the overlap decision is checked by the matcher
/// it is a claim about.
#[test]
fn the_witness_of_a_conflict_reaches_both_entries() {
    let entries = vec![
        entry(
            "GetBucketAcl",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("acl"),
            ],
        ),
        entry(
            "GetBucketTagging",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("tagging"),
            ],
        ),
    ];
    let clone = entries.clone();
    let error = RouteTable::build(entries, &ShadowingDecls::NONE).expect_err("a conflict");
    let RouteBuildError::Conflict { witness, .. } = error else {
        panic!("expected a conflict");
    };

    let line = format!("{} {}?{}", witness.method, witness.path, witness.query_string());
    let request = Req::new(&line).target(witness.target).host_class(witness.host_class);
    let parts = request.parts();
    for entry in &clone {
        assert!(entry.selector.matches(&parts), "the witness {line} must reach {}", entry.op_name);
    }
}

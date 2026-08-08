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
//! Responsible for: the route cases — sixteen positive, forty-three negative — including the one
//! that falsifies a fake overlap check, the three blocks that pin an operation the protocol
//! defines and this build does not serve to its own row rather than to its neighbour's
//! (`?attributes`, the three-method object `?tagging` band whose absence was a write and a delete
//! of the object, and the bucket `?tagging` band whose GET was answered by `ListObjects` with a
//! page of keys), and the bucket lifecycle band whose selectors pin every subresource key absent
//! so a configuration request can never create or delete a bucket.
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
    RouteTable::build(entries, &rustfs_gateway_core::route::PROVISIONAL_SHADOWING)
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
    let table = RouteTable::build(entries, &rustfs_gateway_core::route::PROVISIONAL_SHADOWING)
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

/// The `?tagging` band claims its own three requests, and each one is a different method.
///
/// Positive half of the block below. The band is checked as a whole rather than one row per test,
/// because the property is that *all three* methods leave the plain object band — a table that
/// gained the read and forgot the write would still be the destructive half of issue #16.
#[test]
fn the_tagging_subresource_routes_to_the_tagging_operations() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?tagging", "GetObjectTagging"),
        ("PUT /bucket/key?tagging", "PutObjectTagging"),
        ("DELETE /bucket/key?tagging", "DeleteObjectTagging"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(hit.precedence < 790, "{line} must sit ahead of the object band, got {}", hit.precedence);
    }
}

/// Negative — none of the three is claimed by the plain object band.
///
/// Each substitution is a distinct fault and all three are named here rather than folded into one
/// assertion: the read hands back the object's bytes, the write stores the tagging document *as*
/// the object, and the delete removes the object the caller only wanted to untag.
#[test]
fn n_the_tagging_requests_are_never_claimed_by_the_plain_object_band() {
    let table = generated_table();
    for (line, forbidden, harm) in [
        (
            "GET /bucket/key?tagging",
            "GetObject",
            "the object's bytes answer a question about its labels",
        ),
        ("PUT /bucket/key?tagging", "PutObject", "the tagging document is stored as the object"),
        ("DELETE /bucket/key?tagging", "DeleteObject", "the object is deleted instead of untagged"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}: {harm}");
    }
}

/// Negative — a tagging write carrying a copy source is a tagging write, not a copy.
///
/// `CopyObject` sits at 790 and its whole discriminator is the header, so the two meet on this
/// request. The other order would overwrite the destination from the source and discard the
/// document the request carried.
#[test]
fn n_a_copy_source_header_does_not_pull_a_tagging_write_into_the_copy_row() {
    let table = generated_table();
    let request = Req::new("PUT /bucket/key?tagging").header("x-amz-copy-source", "/other/key");
    assert_eq!(routed(&table, &request), Some("PutObjectTagging"));
}

/// Negative — the multipart band is still tried first, in all three methods.
///
/// The same order the attributes row settled at 470. A request naming both an upload and the
/// tagging subresource is undocumented, and answering it from the tagging row would apply a label
/// operation to an in-progress upload.
#[test]
fn n_a_request_naming_an_upload_and_tagging_stays_with_the_multipart_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?uploadId=u&tagging", "ListParts"),
        ("PUT /bucket/key?uploadId=u&partNumber=1&tagging", "UploadPart"),
        ("DELETE /bucket/key?uploadId=u&tagging", "AbortMultipartUpload"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — `?tagging` on a bucket is the bucket's tag set, which has rows of its own, so it
/// must not reach any of the three object rows: the two scopes follow different unconfigured
/// rules, and crossing them would answer a bucket question with an object rule.
#[test]
fn n_the_tagging_key_on_a_bucket_does_not_reach_an_object_tagging_row() {
    let table = generated_table();
    for line in ["GET /bucket?tagging", "PUT /bucket?tagging", "DELETE /bucket?tagging"] {
        let hit = routed(&table, &Req::new(line));
        assert!(
            !matches!(hit, Some("GetObjectTagging" | "PutObjectTagging" | "DeleteObjectTagging")),
            "{line} routed to {hit:?}, which is an object-scoped operation"
        );
    }
}

/// The bucket `?tagging` band claims its own three requests, one per method.
///
/// The positive half of the bucket-scope block, checked as a whole for the same reason the object
/// band is: the property is that *all three* methods reach their own rows rather than the bucket
/// band's fallbacks.
#[test]
fn the_bucket_tagging_subresource_routes_to_the_bucket_tagging_operations() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?tagging", "GetBucketTagging"),
        ("PUT /bucket?tagging", "PutBucketTagging"),
        ("DELETE /bucket?tagging", "DeleteBucketTagging"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(hit.precedence < 600, "{line} must sit ahead of the listing band, got {}", hit.precedence);
    }
}

/// Negative — the bucket tagging read is never claimed by a listing. Before the row at 310
/// existed, `GET /bucket?tagging` was answered by `ListObjects` with a page of keys — a wrong
/// answer wearing a `200`, the bucket-scope twin of the object band's disclosure.
#[test]
fn n_a_bucket_tagging_read_is_not_claimed_by_a_listing() {
    let table = generated_table();
    for forbidden in ["ListObjects", "ListObjectsV2", "ListObjectVersions", "ListMultipartUploads"] {
        assert_ne!(routed(&table, &Req::new("GET /bucket?tagging")), Some(forbidden));
    }
}

/// Negative — a request sending `?tagging` beside another bucket query still has one fixed
/// answer: `?location` wins above the band, and the listings lose below it.
#[test]
fn n_a_bucket_tagging_request_with_a_second_query_key_keeps_the_band_order() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?location&tagging", "GetBucketLocation"),
        ("GET /bucket?tagging&list-type=2", "GetBucketTagging"),
        ("GET /bucket?tagging&versions", "GetBucketTagging"),
        ("GET /bucket?tagging&uploads", "GetBucketTagging"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the bucket rows are bound to their methods and their target. `HEAD /bucket?tagging`
/// reaches no *tagging* operation, and the object-scope requests stay with the object rows.
///
/// The HEAD half changed meaning when the lifecycle band landed: with no HEAD bucket row the
/// request matched nothing, and now `HeadBucket` — which pins no query key, because no bucket
/// subresource defines a HEAD — answers it as a plain existence probe with an inert key, the same
/// reading `GET /bucket?unknown` has always had from `ListObjects`. What must still never happen
/// is a tagging row answering a method it does not define.
#[test]
fn n_a_bucket_tagging_row_is_not_reachable_under_another_method_or_target() {
    let table = generated_table();
    assert_eq!(
        routed(&table, &Req::new("HEAD /bucket?tagging")),
        Some("HeadBucket"),
        "HEAD names no tagging operation, so the existence probe with an inert key answers"
    );
    for (line, expected) in [
        ("GET /bucket/key?tagging", "GetObjectTagging"),
        ("PUT /bucket/key?tagging", "PutObjectTagging"),
        ("DELETE /bucket/key?tagging", "DeleteObjectTagging"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line} is object-scoped");
    }
}

/// Negative — the bucket band's neighbours are untouched by the three rows put beside them.
#[test]
fn n_the_bucket_band_is_unchanged_beside_the_bucket_tagging_rows() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?location", "GetBucketLocation"),
        ("GET /bucket", "ListObjects"),
        ("GET /bucket?list-type=2", "ListObjectsV2"),
        ("POST /bucket?delete", "DeleteObjects"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — each tagging row is bound to one method, so the key alone does not reach it.
#[test]
fn n_a_tagging_row_is_not_reachable_under_another_method() {
    let table = generated_table();
    for (line, forbidden) in [
        ("PUT /bucket/key?tagging", "GetObjectTagging"),
        ("DELETE /bucket/key?tagging", "PutObjectTagging"),
        ("GET /bucket/key?tagging", "DeleteObjectTagging"),
        ("HEAD /bucket/key?tagging", "GetObjectTagging"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — the plain object band is untouched by the three rows put ahead of it.
#[test]
fn n_the_plain_object_band_is_unchanged_by_the_tagging_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key", "GetObject"),
        ("PUT /bucket/key", "PutObject"),
        ("DELETE /bucket/key", "DeleteObject"),
        ("GET /bucket/key?versionId=v", "GetObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The `?cors` band claims its own three requests, one per method, on the bucket target.
///
/// Positive half of the block below. Checked as a whole for the same reason the tagging band is:
/// the property is that all three methods leave the fallback rows at once — a table that gained
/// the read and forgot the write would still store a CORS document as a listing answer's
/// neighbour, and a table that forgot the delete would leave `DELETE /b?cors` unroutable.
#[test]
fn the_cors_subresource_routes_to_the_cors_operations() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?cors", "GetBucketCors"),
        ("PUT /bucket?cors", "PutBucketCors"),
        ("DELETE /bucket?cors", "DeleteBucketCors"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence < 460,
            "{line} must sit in the bucket subresource band ahead of the listings, got {}",
            hit.precedence
        );
    }
}

/// Negative — the CORS read is never claimed by the bucket listing fallback.
///
/// `ListObjects` pins no query key, so before the row existed `GET /b?cors` was answered with a
/// key listing — the debt-register line this band retires. The PUT and DELETE halves have no
/// fallback to be claimed by, so for them the fault mode was "no route at all", asserted above.
#[test]
fn n_the_cors_read_is_never_claimed_by_the_listing_fallback() {
    let table = generated_table();
    for (line, forbidden) in [
        ("GET /bucket?cors", "ListObjects"),
        ("GET /bucket?cors", "ListObjectsV2"),
        ("GET /bucket?cors", "ListObjectVersions"),
    ] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some(forbidden),
            "{line}: a CORS document request answered with a key listing"
        );
    }
}

/// Negative — a request sending `?location` and `?cors` together stays with the earlier band.
///
/// AWS documents no such combination, so the order is fixed by precedence (300 before 310) rather
/// than left to source order — the same rule every other both-keys pair in the table follows.
#[test]
fn n_a_request_naming_location_and_cors_stays_with_the_location_row() {
    let table = generated_table();
    assert_eq!(routed(&table, &Req::new("GET /bucket?location&cors")), Some("GetBucketLocation"));
}

/// Negative — `?cors` beats the listings it overlaps, in both directions of the band.
#[test]
fn n_a_request_naming_cors_and_a_listing_stays_with_the_cors_row() {
    let table = generated_table();
    for line in [
        "GET /bucket?cors&uploads",
        "GET /bucket?cors&list-type=2",
        "GET /bucket?cors&versions",
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some("GetBucketCors"), "{line}");
    }
}

/// Negative — each CORS row is bound to one method, so the key alone does not reach it.
#[test]
fn n_a_cors_row_is_not_reachable_under_another_method() {
    let table = generated_table();
    for (line, forbidden) in [
        ("PUT /bucket?cors", "GetBucketCors"),
        ("DELETE /bucket?cors", "PutBucketCors"),
        ("GET /bucket?cors", "DeleteBucketCors"),
        ("HEAD /bucket?cors", "GetBucketCors"),
        ("POST /bucket?cors", "PutBucketCors"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — `?cors` on an object key is not a bucket subresource and must not reach the band.
///
/// The three CORS rows pin `Target(Bucket)`, so `GET /bucket/key?cors` is a plain object read
/// carrying an inert query key, exactly as it is on AWS.
#[test]
fn n_the_cors_key_on_an_object_does_not_reach_a_bucket_cors_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?cors", "GetObject"),
        ("PUT /bucket/key?cors", "PutObject"),
        ("DELETE /bucket/key?cors", "DeleteObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the listing fallbacks still answer their own requests beside the new band.
#[test]
fn n_the_bucket_bands_are_unchanged_by_the_cors_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket", "ListObjects"),
        ("GET /bucket?list-type=2", "ListObjectsV2"),
        ("GET /bucket?location", "GetBucketLocation"),
        ("GET /bucket?uploads", "ListMultipartUploads"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The bucket lifecycle band claims its own three requests, one method each.
///
/// Positive half of the block below. `PUT /{bucket}`, `DELETE /{bucket}` and `HEAD /{bucket}` are
/// the bucket-level twins of the object band's fallbacks: no positive query key, distinguished
/// only by method and target. All three sit after the listing band and before the object band.
#[test]
fn the_bucket_lifecycle_rows_route_their_three_methods() {
    let table = generated_table();
    for (line, expected) in [
        ("PUT /bucket", "CreateBucket"),
        ("DELETE /bucket", "DeleteBucket"),
        ("HEAD /bucket", "HeadBucket"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            (700..790).contains(&hit.precedence),
            "{line} must sit in the bucket band after the listings, got {}",
            hit.precedence
        );
    }
}

/// Negative — a bucket subresource request is never claimed by the lifecycle band.
///
/// This is the defect the `query_absent` lists exist for, and it is the destructive direction:
/// with a bare `PUT /{bucket}` selector, `PUT /b?acl` would *create a bucket* and answer 200 for a
/// request that wanted permissions written, and `DELETE /b?policy` would *delete the bucket* for a
/// request that wanted a policy removed. The lists name every bucket subresource key under the
/// method — served and deferred alike — so a deferred key falls through to no route at all, and a
/// served one (`cors`, `tagging`) reaches its own row by first-match with the lifecycle row
/// provably disjoint rather than merely later. Implementing a subresource must not change what a
/// bare `PUT /{bucket}` means, and neither may deferring one.
#[test]
fn n_a_bucket_subresource_request_is_never_claimed_by_the_lifecycle_band() {
    let table = generated_table();
    let deferred_put = [
        "abac",
        "accelerate",
        "acl",
        "analytics",
        "intelligent-tiering",
        "inventory",
        "logging",
        "metadataAnnotationTable",
        "metadataInventoryTable",
        "metadataJournalTable",
        "metrics",
        "notification",
        "ownershipControls",
        "policy",
        "publicAccessBlock",
        "requestPayment",
        "versioning",
        "website",
    ];
    for key in deferred_put {
        let line = format!("PUT /bucket?{key}");
        assert_eq!(routed(&table, &Req::new(&line)), None, "{line} must not be a bucket creation");
    }
    let deferred_delete = [
        "analytics",
        "intelligent-tiering",
        "inventory",
        "metadataConfiguration",
        "metadataTable",
        "metrics",
        "ownershipControls",
        "policy",
        "publicAccessBlock",
        "website",
    ];
    for key in deferred_delete {
        let line = format!("DELETE /bucket?{key}");
        assert_eq!(routed(&table, &Req::new(&line)), None, "{line} must not be a bucket deletion");
    }
    // The served subresources are the same rule with a different observable: the request reaches
    // the subresource's own row, never the lifecycle one. `?object-lock` moved from the deferred
    // list above to this one when its pair landed at 397/398.
    for (line, expected) in [
        ("PUT /bucket?cors", "PutBucketCors"),
        ("PUT /bucket?tagging", "PutBucketTagging"),
        ("PUT /bucket?object-lock", "PutObjectLockConfiguration"),
        ("DELETE /bucket?cors", "DeleteBucketCors"),
        ("DELETE /bucket?tagging", "DeleteBucketTagging"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the lifecycle rows are bucket-scoped, so the object band keeps its three methods.
#[test]
fn n_the_object_band_is_unchanged_by_the_bucket_lifecycle_band() {
    let table = generated_table();
    for (line, expected) in [
        ("PUT /bucket/key", "PutObject"),
        ("DELETE /bucket/key", "DeleteObject"),
        ("HEAD /bucket/key", "HeadObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the lifecycle rows are method-bound: a bucket-level GET is still the listing, and a
/// POST is still the batch delete, whatever rows sit beside them now.
#[test]
fn n_a_bucket_get_and_post_are_untouched_by_the_lifecycle_band() {
    let table = generated_table();
    assert_eq!(routed(&table, &Req::new("GET /bucket")), Some("ListObjects"));
    assert_eq!(routed(&table, &Req::new("POST /bucket?delete")), Some("DeleteObjects"));
}

/// The SDK disambiguator stays inert on the new rows: `x-id` pins nothing anywhere else and must
/// pin nothing here.
#[test]
fn an_x_id_parameter_does_not_disturb_the_lifecycle_band() {
    let table = generated_table();
    assert_eq!(routed(&table, &Req::new("PUT /bucket?x-id=CreateBucket")), Some("CreateBucket"));
    assert_eq!(routed(&table, &Req::new("DELETE /bucket?x-id=DeleteBucket")), Some("DeleteBucket"));
}

/// Negative — a query key that is not a subresource does not eject a request from the lifecycle
/// band: only the subresource keys are pinned absent.
#[test]
fn a_non_subresource_query_key_stays_in_the_lifecycle_band() {
    let table = generated_table();
    assert_eq!(routed(&table, &Req::new("HEAD /bucket?unrelated=1")), Some("HeadBucket"));
}

/// The `?lifecycle` band claims its own three requests, one per method, on the bucket target.
///
/// Positive half of the block below, checked as a whole for the same reason the CORS band is:
/// a table that gained the read and forgot the write would leave a lifecycle document to be
/// stored by a neighbour, and a table that forgot the delete would leave `DELETE /b?lifecycle`
/// unroutable.
#[test]
fn the_lifecycle_subresource_routes_to_the_lifecycle_operations() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?lifecycle", "GetBucketLifecycleConfiguration"),
        ("PUT /bucket?lifecycle", "PutBucketLifecycleConfiguration"),
        ("DELETE /bucket?lifecycle", "DeleteBucketLifecycle"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence < 460,
            "{line} must sit in the bucket subresource band ahead of the listings, got {}",
            hit.precedence
        );
    }
}

/// Negative — the lifecycle read is never claimed by the bucket listing fallback.
///
/// `ListObjects` pins no query key, so before the row existed `GET /b?lifecycle` was answered
/// with a key listing — the `GetBucketLifecycleConfiguration -> ListObjects` debt-register line
/// this band retires. The PUT and DELETE halves had no fallback to be claimed by, so for them
/// the fault mode was "no route at all", asserted above.
#[test]
fn n_the_lifecycle_read_is_never_claimed_by_the_listing_fallback() {
    let table = generated_table();
    for (line, forbidden) in [
        ("GET /bucket?lifecycle", "ListObjects"),
        ("GET /bucket?lifecycle", "ListObjectsV2"),
        ("GET /bucket?lifecycle", "ListObjectVersions"),
    ] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some(forbidden),
            "{line}: a lifecycle document request answered with a key listing"
        );
    }
}

/// Negative — a request naming an earlier subresource beside `?lifecycle` stays with the earlier
/// band.
///
/// AWS documents no such combination, so the order is fixed by precedence (300 and 310 before
/// 370) rather than left to source order — the same rule every other both-keys pair in the table
/// follows. The `?cors` pair matters most: it is the first time two configuration subresource
/// bands sit side by side, in every method.
#[test]
fn n_a_request_naming_an_earlier_subresource_and_lifecycle_stays_with_the_earlier_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?location&lifecycle", "GetBucketLocation"),
        ("GET /bucket?cors&lifecycle", "GetBucketCors"),
        ("PUT /bucket?cors&lifecycle", "PutBucketCors"),
        ("DELETE /bucket?cors&lifecycle", "DeleteBucketCors"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — `?lifecycle` beats the listings it overlaps, in both directions of the band.
#[test]
fn n_a_request_naming_lifecycle_and_a_listing_stays_with_the_lifecycle_row() {
    let table = generated_table();
    for line in [
        "GET /bucket?lifecycle&uploads",
        "GET /bucket?lifecycle&list-type=2",
        "GET /bucket?lifecycle&versions",
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some("GetBucketLifecycleConfiguration"), "{line}");
    }
}

/// Negative — each lifecycle row is bound to one method, so the key alone does not reach it.
#[test]
fn n_a_lifecycle_row_is_not_reachable_under_another_method() {
    let table = generated_table();
    for (line, forbidden) in [
        ("PUT /bucket?lifecycle", "GetBucketLifecycleConfiguration"),
        ("DELETE /bucket?lifecycle", "PutBucketLifecycleConfiguration"),
        ("GET /bucket?lifecycle", "DeleteBucketLifecycle"),
        ("HEAD /bucket?lifecycle", "GetBucketLifecycleConfiguration"),
        ("POST /bucket?lifecycle", "PutBucketLifecycleConfiguration"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — `?lifecycle` on an object key is not a bucket subresource and must not reach the
/// band.
///
/// The three lifecycle rows pin `Target(Bucket)`, so `GET /bucket/key?lifecycle` is a plain
/// object read carrying an inert query key, exactly as it is on AWS.
#[test]
fn n_the_lifecycle_key_on_an_object_does_not_reach_a_bucket_lifecycle_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?lifecycle", "GetObject"),
        ("PUT /bucket/key?lifecycle", "PutObject"),
        ("DELETE /bucket/key?lifecycle", "DeleteObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the neighbouring bands still answer their own requests beside the new band.
#[test]
fn n_the_bucket_bands_are_unchanged_by_the_lifecycle_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket", "ListObjects"),
        ("GET /bucket?list-type=2", "ListObjectsV2"),
        ("GET /bucket?location", "GetBucketLocation"),
        ("GET /bucket?cors", "GetBucketCors"),
        ("PUT /bucket?cors", "PutBucketCors"),
        ("DELETE /bucket?cors", "DeleteBucketCors"),
        ("GET /bucket?uploads", "ListMultipartUploads"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The `?encryption` band claims its own three requests, one per method, on the bucket target.
///
/// Positive half of the block below, checked as a whole for the same reason the lifecycle band
/// is: a table that gained the read and forgot the write would leave an encryption document to
/// be stored by a neighbour, and a table that forgot the delete would leave
/// `DELETE /b?encryption` unroutable.
#[test]
fn the_encryption_subresource_routes_to_the_encryption_operations() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?encryption", "GetBucketEncryption"),
        ("PUT /bucket?encryption", "PutBucketEncryption"),
        ("DELETE /bucket?encryption", "DeleteBucketEncryption"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence < 460,
            "{line} must sit in the bucket subresource band ahead of the listings, got {}",
            hit.precedence
        );
    }
}

/// Negative — the encryption read is never claimed by the bucket listing fallback.
///
/// `ListObjects` pins no query key, so before the row existed `GET /b?encryption` was answered
/// with a key listing — the `GetBucketEncryption -> ListObjects` debt-register line this band
/// retires. The PUT and DELETE halves had no fallback to be claimed by, so for them the fault
/// mode was "no route at all", asserted above.
#[test]
fn n_the_encryption_read_is_never_claimed_by_the_listing_fallback() {
    let table = generated_table();
    for (line, forbidden) in [
        ("GET /bucket?encryption", "ListObjects"),
        ("GET /bucket?encryption", "ListObjectsV2"),
        ("GET /bucket?encryption", "ListObjectVersions"),
    ] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some(forbidden),
            "{line}: an encryption document request answered with a key listing"
        );
    }
}

/// Negative — a request naming an earlier subresource beside `?encryption` stays with the
/// earlier band.
///
/// AWS documents no such combination, so the order is fixed by precedence (300, 310, 340 and 370
/// before 391) rather than left to source order — the same rule every other both-keys pair in
/// the table follows. Three configuration bands now sit ahead of this one, so every method has
/// neighbours to lose to.
#[test]
fn n_a_request_naming_an_earlier_subresource_and_encryption_stays_with_the_earlier_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?location&encryption", "GetBucketLocation"),
        ("GET /bucket?cors&encryption", "GetBucketCors"),
        ("GET /bucket?tagging&encryption", "GetBucketTagging"),
        ("GET /bucket?lifecycle&encryption", "GetBucketLifecycleConfiguration"),
        ("PUT /bucket?cors&encryption", "PutBucketCors"),
        ("PUT /bucket?tagging&encryption", "PutBucketTagging"),
        ("PUT /bucket?lifecycle&encryption", "PutBucketLifecycleConfiguration"),
        ("DELETE /bucket?cors&encryption", "DeleteBucketCors"),
        ("DELETE /bucket?tagging&encryption", "DeleteBucketTagging"),
        ("DELETE /bucket?lifecycle&encryption", "DeleteBucketLifecycle"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — `?encryption` beats the listings it overlaps, in both directions of the band.
#[test]
fn n_a_request_naming_encryption_and_a_listing_stays_with_the_encryption_row() {
    let table = generated_table();
    for line in [
        "GET /bucket?encryption&uploads",
        "GET /bucket?encryption&list-type=2",
        "GET /bucket?encryption&versions",
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some("GetBucketEncryption"), "{line}");
    }
}

/// Negative — each encryption row is bound to one method, so the key alone does not reach it.
#[test]
fn n_an_encryption_row_is_not_reachable_under_another_method() {
    let table = generated_table();
    for (line, forbidden) in [
        ("PUT /bucket?encryption", "GetBucketEncryption"),
        ("DELETE /bucket?encryption", "PutBucketEncryption"),
        ("GET /bucket?encryption", "DeleteBucketEncryption"),
        ("HEAD /bucket?encryption", "GetBucketEncryption"),
        ("POST /bucket?encryption", "PutBucketEncryption"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — `?encryption` on an object key is not a bucket subresource and must not reach the
/// band.
///
/// The three encryption rows pin `Target(Bucket)`, so `GET /bucket/key?encryption` is a plain
/// object read carrying an inert query key, exactly as it is on AWS.
#[test]
fn n_the_encryption_key_on_an_object_does_not_reach_a_bucket_encryption_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?encryption", "GetObject"),
        ("PUT /bucket/key?encryption", "PutObject"),
        ("DELETE /bucket/key?encryption", "DeleteObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the neighbouring bands still answer their own requests beside the new band.
#[test]
fn n_the_bucket_bands_are_unchanged_by_the_encryption_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket", "ListObjects"),
        ("GET /bucket?list-type=2", "ListObjectsV2"),
        ("GET /bucket?location", "GetBucketLocation"),
        ("GET /bucket?lifecycle", "GetBucketLifecycleConfiguration"),
        ("PUT /bucket?lifecycle", "PutBucketLifecycleConfiguration"),
        ("DELETE /bucket?lifecycle", "DeleteBucketLifecycle"),
        ("GET /bucket?uploads", "ListMultipartUploads"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The `?object-lock` pair claims its two requests on the bucket target — and only two.
///
/// Positive half of the block below. Two methods, not three, is the family's shape: the pinned
/// model defines no delete for a lock configuration, because object lock once enabled has no
/// wire spelling for "off". The absent DELETE is asserted here rather than assumed, since a
/// table that invented one would hand `DELETE /b?object-lock` to whatever claimed it.
#[test]
fn the_object_lock_subresource_routes_to_the_lock_pair() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?object-lock", "GetObjectLockConfiguration"),
        ("PUT /bucket?object-lock", "PutObjectLockConfiguration"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence < 460,
            "{line} must sit in the bucket subresource band ahead of the listings, got {}",
            hit.precedence
        );
    }
    // No delete row — and no `DeleteBucket` exclusion either: the model defines no delete for a
    // lock configuration, so under DELETE the key is inert exactly like any key without an
    // operation behind it, and the request keeps the meaning a bare `DELETE /{bucket}` has.
    // (`DeleteBucket`'s `QueryAbsent` list names exactly the subresources with DELETE
    // operations, deferred or served; `object-lock` is not one.)
    assert_eq!(routed(&table, &Req::new("DELETE /bucket?object-lock")), Some("DeleteBucket"));
}

/// Negative — the lock-configuration read is never claimed by the bucket listing fallback.
///
/// `ListObjects` pins no query key, so before the row existed `GET /b?object-lock` was answered
/// with a key listing — the `GetObjectLockConfiguration -> ListObjects` debt-register line this
/// pair retires. The PUT half had no fallback to be claimed by, so for it the fault mode was
/// "no route at all".
#[test]
fn n_the_lock_configuration_read_is_never_claimed_by_the_listing_fallback() {
    let table = generated_table();
    for (line, forbidden) in [
        ("GET /bucket?object-lock", "ListObjects"),
        ("GET /bucket?object-lock", "ListObjectsV2"),
        ("GET /bucket?object-lock", "ListObjectVersions"),
    ] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some(forbidden),
            "{line}: a WORM configuration request answered with a key listing"
        );
    }
}

/// Negative — a request naming an earlier subresource beside `?object-lock` stays with the
/// earlier band.
///
/// Four configuration bands now sit ahead of this pair (300, 310-330, 340-360, 370-390 and
/// 391-393 before 397/398), so both methods have neighbours to lose to — including
/// `?encryption`, the nearest one in the packed corner of the band.
#[test]
fn n_a_request_naming_an_earlier_subresource_and_object_lock_stays_with_the_earlier_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?location&object-lock", "GetBucketLocation"),
        ("GET /bucket?cors&object-lock", "GetBucketCors"),
        ("GET /bucket?tagging&object-lock", "GetBucketTagging"),
        ("GET /bucket?lifecycle&object-lock", "GetBucketLifecycleConfiguration"),
        ("GET /bucket?encryption&object-lock", "GetBucketEncryption"),
        ("PUT /bucket?cors&object-lock", "PutBucketCors"),
        ("PUT /bucket?tagging&object-lock", "PutBucketTagging"),
        ("PUT /bucket?lifecycle&object-lock", "PutBucketLifecycleConfiguration"),
        ("PUT /bucket?encryption&object-lock", "PutBucketEncryption"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — `?object-lock` beats the listings it overlaps.
#[test]
fn n_a_request_naming_object_lock_and_a_listing_stays_with_the_lock_row() {
    let table = generated_table();
    for line in [
        "GET /bucket?object-lock&uploads",
        "GET /bucket?object-lock&list-type=2",
        "GET /bucket?object-lock&versions",
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some("GetObjectLockConfiguration"), "{line}");
    }
}

/// Negative — each lock row is bound to one method, so the key alone does not reach it.
#[test]
fn n_an_object_lock_row_is_not_reachable_under_another_method() {
    let table = generated_table();
    for (line, forbidden) in [
        ("PUT /bucket?object-lock", "GetObjectLockConfiguration"),
        ("GET /bucket?object-lock", "PutObjectLockConfiguration"),
        ("HEAD /bucket?object-lock", "GetObjectLockConfiguration"),
        ("POST /bucket?object-lock", "PutObjectLockConfiguration"),
        ("DELETE /bucket?object-lock", "GetObjectLockConfiguration"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — `?object-lock` on an object key is not a bucket subresource and must not reach
/// the pair.
///
/// Both lock rows pin `Target(Bucket)`, so `GET /bucket/key?object-lock` is a plain object read
/// carrying an inert query key, exactly as it is on AWS.
#[test]
fn n_the_object_lock_key_on_an_object_does_not_reach_the_bucket_pair() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?object-lock", "GetObject"),
        ("PUT /bucket/key?object-lock", "PutObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The `?retention` and `?legal-hold` rows claim their four requests on the object target.
///
/// Positive half of the block below, checked as a whole for the same reason the tagging band
/// is: a table that gained the reads and forgot the writes would leave the retention and hold
/// documents to be stored by `PutObject` — as the object's body.
#[test]
fn the_retention_and_legal_hold_subresources_route_to_their_rows() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?retention", "GetObjectRetention"),
        ("PUT /bucket/key?retention", "PutObjectRetention"),
        ("GET /bucket/key?legal-hold", "GetObjectLegalHold"),
        ("PUT /bucket/key?legal-hold", "PutObjectLegalHold"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence > 460 && hit.precedence < 790,
            "{line} must sit in the object subresource band, after multipart and before the copy row, got {}",
            hit.precedence
        );
    }
}

/// Negative — the four lock-state requests are never claimed by the plain object band.
///
/// The reads were `GetObject`'s — a compliance document request answered with the object's
/// bytes — and the writes were `PutObject`'s, which stored the document *as the object*: a
/// caller protecting an object destroyed it, with a 200. These are the
/// `GetObjectRetention -> GetObject`, `GetObjectLegalHold -> GetObject`,
/// `PutObjectRetention -> PutObject` and `PutObjectLegalHold -> PutObject` debt-register lines
/// this band retires.
#[test]
fn n_the_retention_and_legal_hold_requests_are_never_claimed_by_the_plain_object_band() {
    let table = generated_table();
    for (line, forbidden) in [
        ("GET /bucket/key?retention", "GetObject"),
        ("GET /bucket/key?legal-hold", "GetObject"),
        ("PUT /bucket/key?retention", "PutObject"),
        ("PUT /bucket/key?legal-hold", "PutObject"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — a copy-source header does not pull a retention or hold write into the copy row.
///
/// `CopyObject` is selected by the header alone, so without the band order a retention write
/// carrying `x-amz-copy-source` would be served as a copy: destination overwritten from the
/// source, the retention document discarded.
#[test]
fn n_a_copy_source_header_does_not_pull_a_lock_state_write_into_the_copy_row() {
    let table = generated_table();
    for (line, expected) in [
        ("PUT /bucket/key?retention", "PutObjectRetention"),
        ("PUT /bucket/key?legal-hold", "PutObjectLegalHold"),
    ] {
        let request = Req::new(line).header("x-amz-copy-source", "/src/key");
        assert_eq!(routed(&table, &request), Some(expected), "{line} + x-amz-copy-source");
    }
}

/// Negative — a request naming an upload beside a lock subresource stays with the multipart
/// band, the same order the attributes and tagging rows settled.
#[test]
fn n_a_request_naming_an_upload_and_a_lock_subresource_stays_with_the_multipart_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?uploadId=u1&retention", "ListParts"),
        ("GET /bucket/key?uploadId=u1&legal-hold", "ListParts"),
        ("PUT /bucket/key?partNumber=1&uploadId=u1&retention", "UploadPart"),
        ("PUT /bucket/key?partNumber=1&uploadId=u1&legal-hold", "UploadPart"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — inside the family and against its earlier neighbours, the band order decides.
///
/// `?retention` and `?legal-hold` together name both halves of the object-lock state; the
/// retention row arrived first (510/520 before 530/540) in both methods. The attributes and
/// tagging rows are earlier still.
#[test]
fn n_the_earlier_object_subresource_wins_beside_a_lock_subresource() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?retention&legal-hold", "GetObjectRetention"),
        ("PUT /bucket/key?retention&legal-hold", "PutObjectRetention"),
        ("GET /bucket/key?attributes&retention", "GetObjectAttributes"),
        ("GET /bucket/key?tagging&retention", "GetObjectTagging"),
        ("GET /bucket/key?tagging&legal-hold", "GetObjectTagging"),
        ("PUT /bucket/key?tagging&retention", "PutObjectTagging"),
        ("PUT /bucket/key?tagging&legal-hold", "PutObjectTagging"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the lock-state keys on a bucket do not reach the object rows.
///
/// All four rows pin `Target(Object)`, so on a bucket the keys are inert: the GET falls to the
/// listing fallback, exactly as an unknown query key does on AWS.
#[test]
fn n_the_lock_state_keys_on_a_bucket_do_not_reach_the_object_rows() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?retention", "ListObjects"),
        ("GET /bucket?legal-hold", "ListObjects"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the neighbouring bands still answer their own requests beside the new rows.
#[test]
fn n_the_object_band_is_unchanged_by_the_lock_state_rows() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key", "GetObject"),
        ("PUT /bucket/key", "PutObject"),
        ("DELETE /bucket/key", "DeleteObject"),
        ("GET /bucket/key?tagging", "GetObjectTagging"),
        ("GET /bucket/key?attributes", "GetObjectAttributes"),
        ("GET /bucket/key?uploadId=u1", "ListParts"),
        ("GET /bucket?encryption", "GetBucketEncryption"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The `?replication` band claims its own three requests, one per method, on the bucket target.
///
/// Positive half of the block below, checked as a whole for the same reason the encryption band
/// is: a table that gained the read and forgot the write would leave a replication document to
/// be stored by a neighbour, and a table that forgot the delete would leave
/// `DELETE /b?replication` unroutable.
#[test]
fn the_replication_subresource_routes_to_the_replication_operations() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?replication", "GetBucketReplication"),
        ("PUT /bucket?replication", "PutBucketReplication"),
        ("DELETE /bucket?replication", "DeleteBucketReplication"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence < 460,
            "{line} must sit in the bucket subresource band ahead of the listings, got {}",
            hit.precedence
        );
    }
}

/// Negative — the replication read is never claimed by the bucket listing fallback.
///
/// `ListObjects` pins no query key, so before the row existed `GET /b?replication` was answered
/// with a key listing — the `GetBucketReplication -> ListObjects` debt-register line this band
/// retires. The PUT and DELETE halves had no fallback to be claimed by, so for them the fault
/// mode was "no route at all", asserted above.
#[test]
fn n_the_replication_read_is_never_claimed_by_the_listing_fallback() {
    let table = generated_table();
    for (line, forbidden) in [
        ("GET /bucket?replication", "ListObjects"),
        ("GET /bucket?replication", "ListObjectsV2"),
        ("GET /bucket?replication", "ListObjectVersions"),
    ] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some(forbidden),
            "{line}: a replication document request answered with a key listing"
        );
    }
}

/// Negative — a request naming an earlier subresource beside `?replication` stays with the
/// earlier band.
///
/// AWS documents no such combination, so the order is fixed by precedence (300, 310, 340, 370
/// and 391 before 394) rather than left to source order — the same rule every other both-keys
/// pair in the table follows. Four configuration bands now sit ahead of this one, so every
/// method has neighbours to lose to.
#[test]
fn n_a_request_naming_an_earlier_subresource_and_replication_stays_with_the_earlier_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket?location&replication", "GetBucketLocation"),
        ("GET /bucket?cors&replication", "GetBucketCors"),
        ("GET /bucket?tagging&replication", "GetBucketTagging"),
        ("GET /bucket?lifecycle&replication", "GetBucketLifecycleConfiguration"),
        ("GET /bucket?encryption&replication", "GetBucketEncryption"),
        ("PUT /bucket?cors&replication", "PutBucketCors"),
        ("PUT /bucket?tagging&replication", "PutBucketTagging"),
        ("PUT /bucket?lifecycle&replication", "PutBucketLifecycleConfiguration"),
        ("PUT /bucket?encryption&replication", "PutBucketEncryption"),
        ("DELETE /bucket?cors&replication", "DeleteBucketCors"),
        ("DELETE /bucket?tagging&replication", "DeleteBucketTagging"),
        ("DELETE /bucket?lifecycle&replication", "DeleteBucketLifecycle"),
        ("DELETE /bucket?encryption&replication", "DeleteBucketEncryption"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — `?replication` beats the listings it overlaps, in both directions of the band.
#[test]
fn n_a_request_naming_replication_and_a_listing_stays_with_the_replication_row() {
    let table = generated_table();
    for line in [
        "GET /bucket?replication&uploads",
        "GET /bucket?replication&list-type=2",
        "GET /bucket?replication&versions",
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some("GetBucketReplication"), "{line}");
    }
}

/// Negative — each replication row is bound to one method, so the key alone does not reach it.
#[test]
fn n_a_replication_row_is_not_reachable_under_another_method() {
    let table = generated_table();
    for (line, forbidden) in [
        ("PUT /bucket?replication", "GetBucketReplication"),
        ("DELETE /bucket?replication", "PutBucketReplication"),
        ("GET /bucket?replication", "DeleteBucketReplication"),
        ("HEAD /bucket?replication", "GetBucketReplication"),
        ("POST /bucket?replication", "PutBucketReplication"),
    ] {
        assert_ne!(routed(&table, &Req::new(line)), Some(forbidden), "{line}");
    }
}

/// Negative — `?replication` on an object key is not a bucket subresource and must not reach
/// the band.
///
/// The three replication rows pin `Target(Bucket)`, so `GET /bucket/key?replication` is a plain
/// object read carrying an inert query key, exactly as it is on AWS.
#[test]
fn n_the_replication_key_on_an_object_does_not_reach_a_bucket_replication_row() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key?replication", "GetObject"),
        ("PUT /bucket/key?replication", "PutObject"),
        ("DELETE /bucket/key?replication", "DeleteObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the neighbouring bands still answer their own requests beside the new band.
#[test]
fn n_the_bucket_bands_are_unchanged_by_the_replication_band() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket", "ListObjects"),
        ("GET /bucket?list-type=2", "ListObjectsV2"),
        ("GET /bucket?location", "GetBucketLocation"),
        ("GET /bucket?encryption", "GetBucketEncryption"),
        ("PUT /bucket?encryption", "PutBucketEncryption"),
        ("DELETE /bucket?encryption", "DeleteBucketEncryption"),
        ("GET /bucket?uploads", "ListMultipartUploads"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// The `?restore` and `?select` rows claim the two POSTs the object target had no row for.
///
/// Positive half of the block below. Both are `POST /{Bucket}/{Key+}`, a shape the table only
/// knew as the multipart band, so before these rows the two requests reached **no route at all**
/// and were answered `501` with the "the vhost domain is probably unconfigured" message — the
/// answer an SDK reads as "this endpoint does not implement S3", not as "this operation is not
/// available here".
#[test]
fn the_restore_and_select_subresources_route_to_their_rows() {
    let table = generated_table();
    for (line, expected) in [
        ("POST /bucket/key?restore", "RestoreObject"),
        ("POST /bucket/key?select&select-type=2", "SelectObjectContent"),
    ] {
        let hit = table
            .resolve(&Req::new(line).parts())
            .unwrap_or_else(|| panic!("{line} has a route"));
        assert_eq!(hit.op_name, expected, "{line}");
        assert!(
            hit.precedence > 540 && hit.precedence < 650,
            "{line} must sit after the lock band and ahead of the plain object rows, got {}",
            hit.precedence
        );
    }
}

/// Negative — `select-type` is part of the predicate, not decoration.
///
/// AWS spells the operation `?select&select-type=2`, and the `2` is the version of the request
/// grammar. A table that pinned only `?select` would hand `?select&select-type=1` — a document
/// this decoder has never validated — to `SelectObjectContent`. There is no row for it, so the
/// request must reach nothing at all rather than the version-2 operation.
#[test]
fn n_a_select_request_without_select_type_two_does_not_reach_the_select_row() {
    let table = generated_table();
    for line in [
        "POST /bucket/key?select",
        "POST /bucket/key?select&select-type=1",
        "POST /bucket/key?select&select-type=3",
        "POST /bucket/key?select&select-type=",
        "POST /bucket/key?select&select-type=02",
        "POST /bucket/key?select-type=2",
    ] {
        assert_ne!(
            routed(&table, &Req::new(line)),
            Some("SelectObjectContent"),
            "{line} must not be read as a version-2 select"
        );
    }
}

/// Negative — neither row is answered by a plain object operation in any method.
///
/// The control runs in both directions: the same two subresource keys are checked on `GET` and
/// `PUT`, where the rows pin `Method(POST)` and the keys are inert, so the assertion below
/// cannot be satisfied by a table that simply refuses everything.
#[test]
fn n_the_restore_and_select_keys_are_not_answered_by_the_object_band_on_post() {
    let table = generated_table();
    for line in ["POST /bucket/key?restore", "POST /bucket/key?select&select-type=2"] {
        let hit = routed(&table, &Req::new(line));
        assert_ne!(hit, Some("PutObject"), "{line}");
        assert_ne!(hit, Some("GetObject"), "{line}");
        assert_ne!(hit, Some("CopyObject"), "{line}");
    }
    for (line, expected) in [
        ("GET /bucket/key?restore", "GetObject"),
        ("PUT /bucket/key?restore", "PutObject"),
        ("GET /bucket/key?select&select-type=2", "GetObject"),
        ("PUT /bucket/key?select&select-type=2", "PutObject"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — a POST naming an upload beside `?restore` or `?select` stays with the multipart
/// band.
///
/// This is the pair with teeth. `CompleteMultipartUpload` is `POST /{Bucket}/{Key+}?uploadId`,
/// so a completion that also carried `?restore` reaches both rows; the multipart band is tried
/// first (420/450 before 570/580), which keeps a completion a completion.
#[test]
fn n_a_post_naming_an_upload_and_a_restore_or_select_stays_with_the_multipart_band() {
    let table = generated_table();
    for (line, expected) in [
        ("POST /bucket/key?uploadId=u1&restore", "CompleteMultipartUpload"),
        ("POST /bucket/key?uploads&restore", "CreateMultipartUpload"),
        ("POST /bucket/key?uploadId=u1&select&select-type=2", "CompleteMultipartUpload"),
        ("POST /bucket/key?uploads&select&select-type=2", "CreateMultipartUpload"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — inside the family the band order decides, and it is recorded rather than inherited
/// from source order.
///
/// Neither selector refines the other — `?restore` and `?select&select-type=2` are different
/// keys — so a request carrying both is settled by precedence alone: the restore row is at 570.
#[test]
fn n_the_restore_row_wins_over_the_select_row_when_a_request_carries_both() {
    let table = generated_table();
    let line = "POST /bucket/key?restore&select&select-type=2";
    assert_eq!(routed(&table, &Req::new(line)), Some("RestoreObject"), "{line}");
}

/// Negative — both keys on a bucket target are inert.
///
/// Both rows pin `Target(Object)`. On a bucket, `POST /bucket?restore` reaches no row (the only
/// bucket POST is `?delete`), and the GET falls to the listing fallback exactly as an unknown
/// query key does on AWS.
#[test]
fn n_the_restore_and_select_keys_on_a_bucket_do_not_reach_the_object_rows() {
    let table = generated_table();
    for line in ["POST /bucket?restore", "POST /bucket?select&select-type=2"] {
        assert_eq!(routed(&table, &Req::new(line)), None, "{line}");
    }
    for (line, expected) in [
        ("GET /bucket?restore", "ListObjects"),
        ("GET /bucket?select&select-type=2", "ListObjects"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
    }
}

/// Negative — the neighbouring bands still answer their own requests beside the two new rows.
#[test]
fn n_the_object_band_is_unchanged_by_the_restore_and_select_rows() {
    let table = generated_table();
    for (line, expected) in [
        ("GET /bucket/key", "GetObject"),
        ("PUT /bucket/key", "PutObject"),
        ("DELETE /bucket/key", "DeleteObject"),
        ("POST /bucket/key?uploads", "CreateMultipartUpload"),
        ("POST /bucket/key?uploadId=u1", "CompleteMultipartUpload"),
        ("POST /bucket?delete", "DeleteObjects"),
        ("GET /bucket/key?retention", "GetObjectRetention"),
    ] {
        assert_eq!(routed(&table, &Req::new(line)), Some(expected), "{line}");
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

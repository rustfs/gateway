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

//! RustFS's metadata listing extension as two of the dialect's S3-table rows
//! (rustfs/gateway#1588): `GET /{bucket}?list-type=2&metadata=true` and
//! `GET /{bucket}?versions&metadata=true`, which RustFS's metadata route claims before its admin
//! router and its S3 service.
//!
//! Responsible for: which requests reach the two operations under both operation selections,
//! path-style and virtual-hosted — both shapes, their order against every other key, `x-id` and
//! the admin router's discriminators — and that every near miss (the `metadata` value, a missing
//! or other listing selector, another target, method, sub-resource or key spelling, a repeat)
//! reaches exactly what it reaches without the dialect; and each operation's floor against the
//! standard listing operations' floors, its action, codec, row and record.
//! NOT responsible for: the service-level authentication and authorisation order (the goldens
//! crate's `rustfs_admin_dialect::metadata_listing_tests`), the admin router's eight rows
//! (`extensions`), or the generator.
//! Upstream: this crate's public surface and `rustfs-gateway-core`'s router. Downstream: nothing.
//!
//! Evidence: RustFS's selector reads the first `metadata` value and requires it to be exactly
//! `true`, then picks the versions listing when `versions` is named and the V2 listing when the
//! first `list-type` value is `2`, and otherwise leaves the request to its S3 service:
//! https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/app/metadata_route.rs

use http::Request;
use rustfs_gateway_core::codec::RequestBodyMode;
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::route::{HostClass, Predicate, RouteRequestParts, Selection, TargetKind};
use rustfs_gateway_dialect_rustfs_admin::ops::{list_object_versions_with_metadata, list_objects_v2_with_metadata};
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, ExtensionOperation, OVERLAY};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{OperationFloor, SecurityFloor};
use rustfs_gateway_types::dto::{ListObjectVersions, ListObjectsV2};

use super::{dialect, path_style_target};

use list_object_versions_with_metadata::ListObjectVersionsWithMetadata;
use list_objects_v2_with_metadata::ListObjectsV2WithMetadata;

const V2: &str = "rustfs:ListObjectsV2WithMetadata";
const VERSIONS: &str = "rustfs:ListObjectVersionsWithMetadata";
const BOTH: [Selection; 2] = [Selection::Table, Selection::RustfsLegacy];

/// The operation `method target` reaches, path-style or as a virtual host naming a bucket, under
/// `selection`, with the dialect installed or not.
fn reach_on(installed: bool, selection: Selection, virtual_hosted: bool, method: &str, target: &str) -> Option<&'static str> {
    let mut builder = RouterBuilder::new().selecting(selection);
    let dialect = dialect();
    if installed {
        builder = builder.dialect(&dialect);
    }
    let router = builder.build().expect("the router builds");
    let request = Request::builder()
        .method(method)
        .uri(format!("http://s3.example.com{target}"))
        .header("host", "s3.example.com")
        .body(())
        .expect("a fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let path = wire.raw_path().as_str();
    let parts = RouteRequestParts {
        method: wire.method(),
        path,
        target: if virtual_hosted {
            if path == "/" { TargetKind::Bucket } else { TargetKind::Object }
        } else {
            path_style_target(path)
        },
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
        host_named_bucket: virtual_hosted,
    };
    router.resolve(&parts).map(|entry| entry.op_name)
}

fn reach(installed: bool, selection: Selection, method: &str, target: &str) -> Option<&'static str> {
    reach_on(installed, selection, false, method, target)
}

/// The operation `method target` reaches with the dialect under both selections, which must agree.
fn reached(method: &str, target: &str) -> Option<&'static str> {
    let table = reach(true, Selection::Table, method, target);
    let legacy = reach(true, Selection::RustfsLegacy, method, target);
    assert_eq!(table, legacy, "{method} {target}: the two selections disagree");
    table
}

/// Asserts that `method target` is not a metadata listing, and reaches under each selection with
/// the dialect exactly what it reaches with the dialect today: the table's answer without the
/// dialect, unless that is an admin-router extension row's request, which the dialect claims.
fn unchanged(method: &str, target: &str, expected: &str) {
    for selection in BOTH {
        let with = reach(true, selection, method, target);
        assert_eq!(with, Some(expected), "{selection:?} {method} {target}");
        assert_ne!(with, Some(V2), "{selection:?} {method} {target}");
        assert_ne!(with, Some(VERSIONS), "{selection:?} {method} {target}");
    }
    if !expected.starts_with("rustfs:") {
        assert_eq!(reach(false, Selection::Table, method, target), Some(expected), "{method} {target}");
    }
}

// ── routing: both shapes ──────────────────────────────────────────────────────────────────────

/// Positive — `?list-type=2&metadata=true` is the V2 metadata listing, in either order and with
/// every listing parameter beside it.
#[test]
fn a_v2_listing_with_metadata_true_is_the_v2_metadata_listing() {
    for target in [
        "/bkt?list-type=2&metadata=true",
        "/bkt?metadata=true&list-type=2",
        "/bkt?list-type=2&metadata=true&prefix=a%2F&delimiter=%2F&max-keys=10&encoding-type=url",
        "/bkt?continuation-token=t&fetch-owner=true&start-after=s&list-type=2&metadata=true",
    ] {
        assert_eq!(reached("GET", target), Some(V2), "{target}");
    }
}

/// Positive — `?versions&metadata=true` is the versions metadata listing, with any `versions`
/// value and every listing parameter beside it.
#[test]
fn a_versions_listing_with_metadata_true_is_the_versions_metadata_listing() {
    for target in [
        "/bkt?versions&metadata=true",
        "/bkt?metadata=true&versions",
        "/bkt?versions=&metadata=true",
        "/bkt?versions&metadata=true&key-marker=k&version-id-marker=v&max-keys=5",
    ] {
        assert_eq!(reached("GET", target), Some(VERSIONS), "{target}");
    }
}

/// Positive — `versions` and `list-type=2` together are the versions listing, as RustFS's
/// selector tries `versions` first.
#[test]
fn versions_wins_over_list_type_two_as_rustfs_tries_it_first() {
    assert_eq!(reached("GET", "/bkt?list-type=2&versions&metadata=true"), Some(VERSIONS));
    assert_eq!(reached("GET", "/bkt?versions&list-type=2&metadata=true"), Some(VERSIONS));
}

/// Positive — a virtual-hosted listing names the bucket by its host and reaches the same
/// operation, under both selections.
#[test]
fn a_virtual_hosted_listing_is_the_same_metadata_listing() {
    for selection in BOTH {
        assert_eq!(
            reach_on(true, selection, true, "GET", "/?list-type=2&metadata=true"),
            Some(V2),
            "{selection:?}"
        );
        assert_eq!(
            reach_on(true, selection, true, "GET", "/?versions&metadata=true"),
            Some(VERSIONS),
            "{selection:?}"
        );
    }
}

/// Positive — the metadata listing is ahead of every operation key, `x-id`, and the admin
/// router's discriminators, as RustFS asks its metadata route before either reads the query.
#[test]
fn a_metadata_listing_is_ahead_of_every_operation_key_x_id_and_the_admin_router() {
    assert_eq!(reached("GET", "/bkt?acl&list-type=2&metadata=true"), Some(V2));
    assert_eq!(reached("GET", "/bkt?uploads&versions&metadata=true"), Some(VERSIONS));
    assert_eq!(reached("GET", "/bkt?x-id=ListObjects&list-type=2&metadata=true"), Some(V2));
    assert_eq!(reached("GET", "/bkt?x-id=GetBucketAcl&versions&metadata=true"), Some(VERSIONS));
    assert_eq!(reached("GET", "/bkt?replication-check&list-type=2&metadata=true"), Some(V2));
    assert_eq!(reached("GET", "/bkt?events&versions&metadata=true"), Some(VERSIONS));
    assert_eq!(reached("GET", "/bkt?replication-metrics=2&list-type=2&metadata=true"), Some(V2));
}

// ── routing: near misses ──────────────────────────────────────────────────────────────────────

/// Negative — without the dialect each shape is the standard listing under the table's selection
/// and nothing under legacy RustFS's, which names an operation the table lacks.
#[test]
fn n_without_the_dialect_a_metadata_listing_is_the_standard_listing_or_nothing() {
    for (target, standard) in [
        ("/bkt?list-type=2&metadata=true", "ListObjectsV2"),
        ("/bkt?versions&metadata=true", "ListObjectVersions"),
    ] {
        assert_eq!(reach(false, Selection::Table, "GET", target), Some(standard), "{target}");
        assert_eq!(reach(false, Selection::RustfsLegacy, "GET", target), None, "{target}");
    }
}

/// Negative — a `metadata` value that is not exactly `true` selects no metadata listing: the
/// request is the standard listing it is today. The match is byte for byte and case-sensitive,
/// as RustFS's is; a percent-encoded `true` is matched as it arrived, like every routing value.
#[test]
fn n_a_metadata_value_other_than_true_is_the_standard_listing() {
    for value in [
        "metadata=false",
        "metadata=",
        "metadata",
        "metadata=TRUE",
        "metadata=True",
        "metadata=1",
        "metadata=yes",
        "metadata=truee",
        "metadata=true%20",
        "metadata=%74rue",
        "metadata=false&metadata=true",
    ] {
        unchanged("GET", &format!("/bkt?list-type=2&{value}"), "ListObjectsV2");
        unchanged("GET", &format!("/bkt?versions&{value}"), "ListObjectVersions");
    }
    // The first value decides, as RustFS reads it: a later `false` does not spoil a first `true`.
    assert_eq!(reached("GET", "/bkt?list-type=2&metadata=true&metadata=false"), Some(V2));
}

/// Negative — `metadata=true` without a listing selector RustFS reads is the standard operation
/// it is today: no selector, a V1 listing, another `list-type`, or a repeat whose first value is
/// not `2`.
#[test]
fn n_metadata_true_without_a_v2_or_versions_selector_is_unchanged() {
    for target in [
        "/bkt?metadata=true",
        "/bkt?list-type=1&metadata=true",
        "/bkt?list-type=3&metadata=true",
        "/bkt?list-type=&metadata=true",
        "/bkt?list-type&metadata=true",
        "/bkt?prefix=a&metadata=true",
    ] {
        unchanged("GET", target, "ListObjects");
    }
    // A repeated `list-type` never routes: the wire layer refuses the duplicate first.
    let request = Request::builder()
        .method("GET")
        .uri("http://s3.example.com/bkt?list-type=1&list-type=2&metadata=true")
        .header("host", "s3.example.com")
        .body(())
        .expect("a fixture request");
    assert!(WireRequest::accept(request, &Limits::default()).is_err());
}

/// Negative — a percent-encoded `list-type=%32` is matched as it arrived, as every routing value
/// is, so it is no metadata listing under either selection; each selection answers exactly what it
/// answers without `metadata=true`, which is where the two already part (the table's
/// `ListObjects`, legacy RustFS's decoded `ListObjectsV2`). RustFS's own selector decodes it; no
/// SigV4 client sends it, since the canonical encoding leaves `2` alone.
#[test]
fn n_an_encoded_list_type_is_no_metadata_listing_under_either_selection() {
    for selection in BOTH {
        let with = reach(true, selection, "GET", "/bkt?list-type=%32&metadata=true");
        assert_eq!(with, reach(true, selection, "GET", "/bkt?list-type=%32"), "{selection:?}");
        assert_ne!(with, Some(V2), "{selection:?}");
    }
    assert_eq!(
        reach(true, Selection::Table, "GET", "/bkt?list-type=%32&metadata=true"),
        Some("ListObjects")
    );
    assert_eq!(
        reach(true, Selection::RustfsLegacy, "GET", "/bkt?list-type=%32&metadata=true"),
        Some("ListObjectsV2")
    );
}

/// Negative — on an object path or the service root, either shape is that target's own
/// operation, path-style and virtual-hosted.
#[test]
fn n_a_metadata_listing_on_another_target_is_unchanged() {
    for target in [
        "/bkt/obj?list-type=2&metadata=true",
        "/bkt/obj?versions&metadata=true",
        "/bkt/a/b?list-type=2&metadata=true",
    ] {
        unchanged("GET", target, "GetObject");
    }
    unchanged("GET", "/?list-type=2&metadata=true", "ListBuckets");
    unchanged("GET", "/?versions&metadata=true", "ListBuckets");
    for selection in BOTH {
        assert_eq!(
            reach_on(true, selection, true, "GET", "/obj?list-type=2&metadata=true"),
            Some("GetObject"),
            "{selection:?}"
        );
    }
}

/// Negative — `metadata=true` beside another sub-resource and no listing selector is that
/// sub-resource's operation, the admin router's discriminators included.
#[test]
fn n_metadata_true_on_another_sub_resource_is_unchanged() {
    for (target, expected) in [
        ("/bkt?acl&metadata=true", "GetBucketAcl"),
        ("/bkt?uploads&metadata=true", "ListMultipartUploads"),
        ("/bkt?location&metadata=true", "GetBucketLocation"),
        ("/bkt?metadataConfiguration&metadata=true", "GetBucketMetadataConfiguration"),
        ("/bkt?replication-check&metadata=true", "rustfs:CheckReplication"),
        ("/bkt?events&metadata=true", "rustfs:ListenBucketNotification"),
    ] {
        unchanged("GET", target, expected);
    }
}

/// Negative — either shape on another method is that method's own operation.
#[test]
fn n_a_metadata_listing_on_another_method_is_unchanged() {
    for (method, expected) in [("PUT", "CreateBucket"), ("HEAD", "HeadBucket"), ("DELETE", "DeleteBucket")] {
        unchanged(method, "/bkt?list-type=2&metadata=true", expected);
    }
    for selection in BOTH {
        for target in ["/bkt?list-type=2&metadata=true", "/bkt?versions&metadata=true"] {
            let with = reach(true, selection, "POST", target);
            assert_eq!(with, reach(false, selection, "POST", target), "{selection:?} {target}");
            assert!(with != Some(V2) && with != Some(VERSIONS), "{selection:?} {target}");
        }
    }
}

/// Negative — a key spelled another way names nothing: the match is byte for byte.
#[test]
fn n_a_misspelled_key_is_unchanged() {
    for target in [
        "/bkt?list-type=2&Metadata=true",
        "/bkt?list-type=2&METADATA=true",
        "/bkt?list-type=2&metadata_=true",
        "/bkt?list-type=2&meta-data=true",
    ] {
        unchanged("GET", target, "ListObjectsV2");
    }
    unchanged("GET", "/bkt?List-Type=2&metadata=true", "ListObjects");
    unchanged("GET", "/bkt?Versions&metadata=true", "ListObjects");
}

/// Negative — a bucket or key named like a key is the ordinary request.
#[test]
fn n_a_path_named_like_a_key_is_unchanged() {
    unchanged("GET", "/metadata", "ListObjects");
    unchanged("GET", "/metadata?list-type=2", "ListObjectsV2");
    unchanged("GET", "/bkt/metadata=true", "GetObject");
    assert_eq!(reached("GET", "/metadata?list-type=2&metadata=true"), Some(V2));
}

/// Negative — the two selections agree on every metadata request and near miss, with the dialect.
#[test]
fn n_the_two_selections_never_disagree_on_a_metadata_request() {
    let queries = [
        "list-type=2&metadata=true",
        "versions&metadata=true",
        "list-type=2&versions&metadata=true",
        "list-type=1&metadata=true",
        "metadata=true",
        "list-type=2&metadata=false",
        "versions&metadata=",
        "acl&list-type=2&metadata=true",
        "events&versions&metadata=true",
    ];
    for method in ["GET", "PUT", "HEAD", "DELETE"] {
        for path in ["/", "/bkt", "/bkt/obj"] {
            for query in queries {
                let target = format!("{path}?{query}");
                assert_eq!(
                    reach(true, Selection::Table, method, &target),
                    reach(true, Selection::RustfsLegacy, method, &target),
                    "{method} {target}"
                );
            }
        }
    }
}

// ── declarations ──────────────────────────────────────────────────────────────────────────────

/// Every admission question a deployment's floor can ask of an operation floor, under every
/// combination of the anonymous and presigned policies a deployment can choose.
fn admissions(floor: &OperationFloor) -> Vec<(bool, bool)> {
    let base = SecurityFloor::new();
    let delegating = base
        .clone()
        .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    [
        base.clone(),
        delegating.clone(),
        base.admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report(),
        delegating.admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report(),
    ]
    .iter()
    .map(|policy| (policy.admits_anonymous(floor), policy.admits_presigned(floor)))
    .collect()
}

/// Everything a floor decides, its name aside.
fn shape(floor: &OperationFloor) -> String {
    format!(
        "privileged={} schemes={:?} sigv4={} service={:?} bearer={:?} admissions={:?}",
        floor.privileged(),
        floor.allowed_schemes(),
        floor.requires_sigv4_under_every_policy(),
        floor.service(),
        floor.query_bearer_claim().is_some(),
        admissions(floor)
    )
}

/// Positive and negative — each operation's floor is exactly the floor of the standard listing it
/// stands in front of: anonymous and presigned requests are refused under the default floor and
/// admitted to the authorizer where a deployment delegates them, as for `ListObjectsV2` and
/// `ListObjectVersions`; never privileged, so never the admin router's header-only floor.
#[test]
fn each_metadata_listing_floor_is_exactly_its_standard_listings_floor() {
    let v2 = <ListObjectsV2WithMetadata as Operation>::floor();
    let versions = <ListObjectVersionsWithMetadata as Operation>::floor();
    assert_eq!(shape(v2), shape(<ListObjectsV2 as Operation>::floor()));
    assert_eq!(shape(versions), shape(<ListObjectVersions as Operation>::floor()));
    for floor in [v2, versions] {
        // Both directions: refused where nothing is delegated, admitted where both are.
        assert_eq!(admissions(floor), [(false, false), (true, false), (false, true), (true, true)]);
        assert!(!floor.privileged() && !floor.allows_anonymous());
        assert_ne!(shape(floor), shape(&rustfs_gateway_dialect_rustfs_admin::admin::floor("x")));
        assert_ne!(shape(floor), shape(&rustfs_gateway_dialect_rustfs_admin::admin::presigned_floor("x")));
    }
    assert_eq!(v2.name(), V2);
    assert_eq!(versions.name(), VERSIONS);
}

/// Positive — each is authorised by its listing action on the bucket, reads no body, holds no
/// secret, and its row names the method, the bucket target, its selector and `metadata=true`.
#[test]
fn each_metadata_listing_declares_its_listing_action_codec_and_row() {
    fn check<O: ExtensionOperation>(name: &str, action: &str, selector: Predicate) {
        let auth = O::spec().auth.expect("an action");
        assert_eq!((auth.action, auth.resource), (action, ResourceShape::Bucket), "{name}");
        assert!(auth.version_requirement().is_none(), "{name}");
        assert!(!O::spec().receives_caller_secret(), "{name}");
        assert_eq!(O::spec().success_status, 200, "{name}");
        assert_eq!(O::REQUEST_BODY, RequestBodyMode::None, "{name}");
        assert_eq!(
            O::ROUTE.selector,
            [
                Predicate::Method(http::Method::GET),
                Predicate::Target(TargetKind::Bucket),
                selector,
                Predicate::QueryEquals("metadata", "true"),
            ],
            "{name}"
        );
        assert_eq!(O::NAME, name);
    }
    check::<ListObjectsV2WithMetadata>(V2, "s3:ListBucket", Predicate::QueryEquals("list-type", "2"));
    check::<ListObjectVersionsWithMetadata>(VERSIONS, "s3:ListBucketVersions", Predicate::QueryPresent("versions"));
}

/// Positive — the two rows are the first two extension records and overlay rows, at 78 and 79,
/// ahead of the admin router's rows, citing RustFS's metadata route and this issue, and never
/// anonymous in the overlay: anonymous admission is the deployment floor's delegation, not an
/// operation opt-in.
#[test]
fn the_two_rows_are_recorded_first_with_their_gate_and_evidence() {
    let names: Vec<&str> = EXTENSION_ROUTES.iter().take(2).map(|record| record.operation).collect();
    assert_eq!(names, [VERSIONS, V2]);
    for (record, key, rule, precedence) in [
        (&EXTENSION_ROUTES[0], "versions", "present", 78),
        (&EXTENSION_ROUTES[1], "list-type", "equals:2", 79),
    ] {
        assert_eq!((record.method, record.target, record.query), ("GET", "bucket", (key, rule)));
        assert_eq!(record.requires, [("metadata", "equals:true")]);
        let row = OVERLAY
            .operations
            .iter()
            .find(|row| row.name == record.operation)
            .expect("an overlay row");
        assert_eq!(row.precedence, precedence, "{}", record.operation);
        assert!(!row.anonymous, "{}", record.operation);
        assert!(
            row.evidence
                .iter()
                .any(|url| url.ends_with("rustfs/src/app/metadata_route.rs"))
        );
        assert!(row.evidence.contains(&"https://github.com/rustfs/gateway/issues/1588"));
        assert!(!row.evidence.iter().any(|url| url.contains("rustfs/src/admin/router.rs")));
    }
    assert!(EXTENSION_ROUTES.iter().skip(2).all(|record| record.requires.is_empty()));
    let dialect = dialect();
    let lowest = dialect
        .operations()
        .iter()
        .map(|operation| operation.entry().precedence)
        .min();
    assert_eq!(lowest, Some(78));
}

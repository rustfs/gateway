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

//! RustFS's eight S3-shaped extension routes as the dialect's S3-table rows, and the
//! object-zip-download pair as claimed rows (rustfs/backlog#2753): which requests reach them,
//! which do not, and what each operation declares.
//!
//! Responsible for: routing every extension request through core's router under both operation
//! selections, with and without the dialect — each discriminator, its value forms, its order
//! against every operation key, `x-id` and the other discriminators, and every near miss by
//! value, method, target, spelling and repetition — and each operation's row, floor, action,
//! codec and record against an independent model of the route table; and the zip pair's rows,
//! floors, labels and near misses.
//! NOT responsible for: authentication, the authorizer and the answer through an assembled
//! service (`rustfs-gateway-goldens`'s `rustfs_admin_dialect::extension_tests`), legacy RustFS's
//! selection itself (`rustfs-gateway-core`), or the binding to the recorded inventory (goldens).
//! Upstream: this crate's public surface and `rustfs-gateway-core`'s router. Downstream: nothing.

use std::collections::BTreeSet;

use http::Request;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseBody};
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::route::{HostClass, Predicate, RouteRequestParts, Selection, TargetKind, render_selector};
use rustfs_gateway_dialect_rustfs_admin::admin::AdminResponse;
use rustfs_gateway_dialect_rustfs_admin::ops::{
    check_replication, get_replication_metrics, get_replication_metrics_v2, get_replication_reset_status,
    get_v3_object_zip_downloads_by_id_zip, invoke_object_lambda, listen_bucket_notification, listen_notification,
    post_v3_object_zip_downloads, reset_bucket_replication,
};
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, ExtensionOperation, OVERLAY, ROUTES, STAYING};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::SigService;

use super::{dialect, path_style_target};

const RESET: &str = "rustfs:ResetBucketReplication";
const RESET_STATUS: &str = "rustfs:GetReplicationResetStatus";
const METRICS_V2: &str = "rustfs:GetReplicationMetricsV2";
const METRICS: &str = "rustfs:GetReplicationMetrics";
const CHECK: &str = "rustfs:CheckReplication";
const LAMBDA: &str = "rustfs:InvokeObjectLambda";
const LISTEN: &str = "rustfs:ListenNotification";
const LISTEN_BUCKET: &str = "rustfs:ListenBucketNotification";
const ZIP_GET: &str = "rustfs:GetV3ObjectZipDownloadsByIdZip";
const ZIP_POST: &str = "rustfs:PostV3ObjectZipDownloads";
const BOTH: [Selection; 2] = [Selection::Table, Selection::RustfsLegacy];

/// The operation `method target` reaches, read path-style or as a virtual host naming a bucket,
/// under `selection`, with the dialect installed or not.
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

/// [`reach_on`], path-style.
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

// ── routing: every discriminator, under both selections ───────────────────────────────────────

/// Positive — `PUT /{bucket}?replication-reset` with an empty value is the reset operation.
#[test]
fn a_bucket_put_with_replication_reset_is_the_reset_operation() {
    assert_eq!(reached("PUT", "/bkt?replication-reset"), Some(RESET));
    assert_eq!(reached("PUT", "/bkt?replication-reset="), Some(RESET));
    assert_eq!(reached("PUT", "/bkt?replication-reset&arn=x"), Some(RESET));
}

/// Positive — `GET /{bucket}?replication-reset-status` is the reset-status operation.
#[test]
fn a_bucket_get_with_replication_reset_status_is_the_status_operation() {
    assert_eq!(reached("GET", "/bkt?replication-reset-status"), Some(RESET_STATUS));
    assert_eq!(reached("GET", "/bkt?replication-reset-status=&arn=x"), Some(RESET_STATUS));
}

/// Positive — `?replication-metrics` with the value `2` and with no value are two operations,
/// as RustFS's router splits them.
#[test]
fn replication_metrics_with_and_without_a_value_are_two_operations() {
    assert_eq!(reached("GET", "/bkt?replication-metrics=2"), Some(METRICS_V2));
    assert_eq!(reached("GET", "/bkt?replication-metrics"), Some(METRICS));
    assert_eq!(reached("GET", "/bkt?replication-metrics="), Some(METRICS));
    assert_ne!(METRICS, METRICS_V2);
}

/// Positive — `GET /{bucket}?replication-check` is the check operation, not `GetBucketReplication`.
#[test]
fn a_bucket_get_with_replication_check_is_the_check_operation() {
    assert_eq!(reached("GET", "/bkt?replication-check"), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?replication-check="), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?replication"), Some("GetBucketReplication"));
}

/// Positive — `GET /{bucket}/{key}?lambdaArn=…` is the object lambda operation, with any value,
/// not `GetObject`.
#[test]
fn an_object_get_with_lambda_arn_is_the_object_lambda_operation() {
    assert_eq!(
        reached("GET", "/bkt/obj?lambdaArn=arn:aws:s3-object-lambda::1:accesspoint/ap"),
        Some(LAMBDA)
    );
    assert_eq!(reached("GET", "/bkt/obj?lambdaArn"), Some(LAMBDA));
    assert_eq!(reached("GET", "/bkt/a/b/c?lambdaArn=x&versionId=v"), Some(LAMBDA));
    assert_eq!(reached("GET", "/bkt/obj"), Some("GetObject"));
}

/// Positive — `GET /?events=…` is the service listener and `GET /{bucket}?events=…` the bucket
/// listener, with any value.
#[test]
fn events_on_the_service_and_on_a_bucket_are_the_two_listeners() {
    assert_eq!(reached("GET", "/?events=s3:ObjectCreated:*"), Some(LISTEN));
    assert_eq!(reached("GET", "/?events"), Some(LISTEN));
    assert_eq!(reached("GET", "/bkt?events=s3:ObjectCreated:*"), Some(LISTEN_BUCKET));
    assert_eq!(reached("GET", "/bkt?events&prefix=a&suffix=b"), Some(LISTEN_BUCKET));
    assert_eq!(reached("GET", "/"), Some("ListBuckets"));
}

/// Positive — the object-zip-download pair routes inside the admin claim under both prefixes:
/// the download by its one opaque `{+id}` segment, the minting `POST` by its exact path.
#[test]
fn the_zip_download_pair_routes_inside_the_admin_claim() {
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        assert_eq!(
            reached("GET", &format!("{prefix}/v3/object-zip-downloads/abc.zip?token=t")),
            Some(ZIP_GET)
        );
        assert_eq!(reached("GET", &format!("{prefix}/v3/object-zip-downloads/a%2Fb.zip")), Some(ZIP_GET));
        assert_eq!(reached("POST", &format!("{prefix}/v3/object-zip-downloads")), Some(ZIP_POST));
    }
}

/// Positive — an extension row is ahead of every operation key of its method and target, and
/// of `x-id`, as RustFS's router is asked before its S3 service reads either.
#[test]
fn an_extension_discriminator_is_ahead_of_every_operation_key_and_of_x_id() {
    assert_eq!(reached("GET", "/bkt?acl&replication-check"), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?replication-check&acl"), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?list-type=2&replication-metrics=2"), Some(METRICS_V2));
    assert_eq!(reached("GET", "/bkt?versions&events"), Some(LISTEN_BUCKET));
    assert_eq!(reached("PUT", "/bkt?versioning&replication-reset"), Some(RESET));
    assert_eq!(reached("GET", "/bkt/obj?tagging&lambdaArn=x"), Some(LAMBDA));
    assert_eq!(reached("GET", "/bkt/obj?uploadId=u&lambdaArn=x"), Some(LAMBDA));
    assert_eq!(reached("GET", "/bkt?x-id=ListObjects&replication-check"), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?x-id=GetBucketAcl&events"), Some(LISTEN_BUCKET));
    assert_eq!(reached("GET", "/?x-id=ListBuckets&events"), Some(LISTEN));
    assert_eq!(reached("PUT", "/bkt?x-id=CreateBucket&replication-reset"), Some(RESET));
}

/// Positive — two discriminators in one request resolve in the order RustFS's router tries them:
/// the replication ones first, reset-status before metrics before check, then the listeners.
#[test]
fn two_discriminators_resolve_in_the_order_rustfs_tries_them() {
    assert_eq!(reached("GET", "/bkt?replication-check&replication-reset-status"), Some(RESET_STATUS));
    assert_eq!(reached("GET", "/bkt?replication-metrics=2&replication-reset-status"), Some(RESET_STATUS));
    assert_eq!(reached("GET", "/bkt?replication-check&replication-metrics=2"), Some(METRICS_V2));
    assert_eq!(reached("GET", "/bkt?replication-check&replication-metrics"), Some(METRICS));
    assert_eq!(reached("GET", "/bkt?events&replication-check"), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?events&replication-reset-status"), Some(RESET_STATUS));
    // A metrics value that is neither `2` nor empty names no metrics operation, and the next
    // discriminator decides.
    assert_eq!(reached("GET", "/bkt?replication-metrics=3&replication-check"), Some(CHECK));
}

/// Positive — a virtual-hosted request names the bucket by its host, so the discriminator reads
/// the same bucket operation. Legacy RustFS reads the path alone there (`/` is no bucket to it),
/// which makes a virtual-hosted `?replication-check` an object listing and a virtual-hosted
/// `?events` the service listener; the gateway addresses the bucket the host names.
#[test]
fn a_virtual_hosted_extension_request_is_the_bucket_operation() {
    for selection in BOTH {
        assert_eq!(
            reach_on(true, selection, true, "GET", "/?replication-check"),
            Some(CHECK),
            "{selection:?}"
        );
        assert_eq!(reach_on(true, selection, true, "GET", "/?events"), Some(LISTEN_BUCKET), "{selection:?}");
        assert_eq!(
            reach_on(true, selection, true, "PUT", "/?replication-reset"),
            Some(RESET),
            "{selection:?}"
        );
        assert_eq!(reach_on(true, selection, true, "GET", "/obj?lambdaArn=x"), Some(LAMBDA), "{selection:?}");
    }
}

// ── routing: near misses ──────────────────────────────────────────────────────────────────────

/// Negative — without the dialect, every extension request is the standard operation under the
/// table's selection and nothing under legacy RustFS's, which names an operation the table lacks.
#[test]
fn n_without_the_dialect_an_extension_request_is_the_standard_operation_or_nothing() {
    let cases: [(&str, &str, &str); 8] = [
        ("PUT", "/bkt?replication-reset", "CreateBucket"),
        ("GET", "/bkt?replication-reset-status", "ListObjects"),
        ("GET", "/bkt?replication-metrics=2", "ListObjects"),
        ("GET", "/bkt?replication-metrics", "ListObjects"),
        ("GET", "/bkt?replication-check", "ListObjects"),
        ("GET", "/bkt/obj?lambdaArn=x", "GetObject"),
        ("GET", "/?events", "ListBuckets"),
        ("GET", "/bkt?events", "ListObjects"),
    ];
    for (method, target, standard) in cases {
        assert_eq!(reach(false, Selection::Table, method, target), Some(standard), "{method} {target}");
        assert_eq!(reach(false, Selection::RustfsLegacy, method, target), None, "{method} {target}");
        assert_ne!(reach(true, Selection::Table, method, target), Some(standard), "{method} {target}");
    }
}

/// Negative — a discriminator whose first value is not what RustFS's router reads selects no
/// extension: the request is the standard operation, exactly as without the dialect.
#[test]
fn n_a_discriminator_with_the_wrong_value_is_not_the_extension() {
    for (method, target) in [
        ("PUT", "/bkt?replication-reset=1"),
        ("PUT", "/bkt?replication-reset=%20"),
        ("GET", "/bkt?replication-reset-status=x"),
        ("GET", "/bkt?replication-metrics=3"),
        ("GET", "/bkt?replication-metrics=%32"),
        ("GET", "/bkt?replication-metrics=22"),
        ("GET", "/bkt?replication-check=1"),
        ("GET", "/bkt?replication-check=%00"),
    ] {
        for selection in BOTH {
            assert_eq!(
                reach(true, selection, method, target),
                reach(false, Selection::Table, method, target),
                "{selection:?} {method} {target}"
            );
        }
        assert!(
            matches!(reached(method, target), Some("CreateBucket" | "ListObjects")),
            "{method} {target}"
        );
    }
}

/// Negative — the right key on the wrong method is the method's own operation.
#[test]
fn n_a_discriminator_on_the_wrong_method_is_not_the_extension() {
    for (method, target, standard) in [
        ("GET", "/bkt?replication-reset", "ListObjects"),
        ("PUT", "/bkt?replication-reset-status", "CreateBucket"),
        ("PUT", "/bkt?replication-metrics=2", "CreateBucket"),
        ("PUT", "/bkt?replication-check", "CreateBucket"),
        ("PUT", "/bkt?events", "CreateBucket"),
        ("HEAD", "/bkt?events", "HeadBucket"),
        ("DELETE", "/bkt?replication-check", "DeleteBucket"),
        ("PUT", "/bkt/obj?lambdaArn=x", "PutObject"),
        ("HEAD", "/bkt/obj?lambdaArn=x", "HeadObject"),
        ("DELETE", "/bkt/obj?lambdaArn=x", "DeleteObject"),
    ] {
        assert_eq!(reached(method, target), Some(standard), "{method} {target}");
        assert_eq!(reach(false, Selection::Table, method, target), Some(standard), "{method} {target}");
    }
    for selection in BOTH {
        assert_eq!(
            reach(true, selection, "POST", "/bkt?events"),
            reach(false, selection, "POST", "/bkt?events")
        );
    }
}

/// Negative — the right key on the wrong target is the target's own operation.
#[test]
fn n_a_discriminator_on_the_wrong_target_is_not_the_extension() {
    for (method, target, standard) in [
        ("GET", "/bkt/obj?replication-check", "GetObject"),
        ("GET", "/bkt/obj?replication-metrics=2", "GetObject"),
        ("GET", "/bkt/obj?replication-reset-status", "GetObject"),
        ("GET", "/bkt/obj?events", "GetObject"),
        ("PUT", "/bkt/obj?replication-reset", "PutObject"),
        ("GET", "/bkt?lambdaArn=x", "ListObjects"),
        ("GET", "/?lambdaArn=x", "ListBuckets"),
        ("GET", "/?replication-check", "ListBuckets"),
        ("GET", "/?replication-metrics=2", "ListBuckets"),
    ] {
        assert_eq!(reached(method, target), Some(standard), "{method} {target}");
    }
}

/// Negative — a key is matched byte for byte: another case, a longer or shorter spelling names
/// nothing. (A percent-encoded key, `replication%2Dcheck`, is refused `400` by the wire layer as
/// an ambiguous parameter name before anything routes.)
#[test]
fn n_a_misspelled_discriminator_is_not_the_extension() {
    for target in [
        "/bkt?Replication-Check",
        "/bkt?REPLICATION-CHECK",
        "/bkt?replication-check-",
        "/bkt?replication-chec",
        "/bkt?Events",
        "/bkt?events-",
        "/bkt?replication-metrics2",
        "/bkt?replication_metrics=2",
    ] {
        assert_eq!(reached("GET", target), Some("ListObjects"), "{target}");
    }
    assert_eq!(reached("GET", "/bkt/obj?lambdaarn=x"), Some("GetObject"));
    assert_eq!(reached("GET", "/bkt/obj?LambdaArn=x"), Some("GetObject"));
    assert_eq!(reached("GET", "/?EVENTS"), Some("ListBuckets"));
}

/// Negative — a repeated discriminator is read by its first value, as RustFS reads it; a later
/// value neither rescues nor spoils the first.
#[test]
fn n_a_repeated_discriminator_reads_its_first_value() {
    assert_eq!(reached("GET", "/bkt?replication-check=1&replication-check"), Some("ListObjects"));
    assert_eq!(reached("GET", "/bkt?replication-check&replication-check=1"), Some(CHECK));
    assert_eq!(reached("GET", "/bkt?replication-metrics=3&replication-metrics=2"), Some("ListObjects"));
    assert_eq!(reached("GET", "/bkt?replication-metrics=2&replication-metrics=3"), Some(METRICS_V2));
    assert_eq!(reached("GET", "/bkt?replication-metrics&replication-metrics=2"), Some(METRICS));
    assert_eq!(reached("GET", "/bkt?events&events=x"), Some(LISTEN_BUCKET));
}

/// Negative — a near miss of the zip pair reaches the admin fallback, never the pair: a missing
/// id, a second segment, another method, or a trailing slash.
#[test]
fn n_a_zip_near_miss_reaches_the_fallback() {
    for (method, target) in [
        ("GET", "/rustfs/admin/v3/object-zip-downloads"),
        ("GET", "/rustfs/admin/v3/object-zip-downloads/"),
        ("GET", "/rustfs/admin/v3/object-zip-downloads/a/b.zip"),
        ("PUT", "/rustfs/admin/v3/object-zip-downloads/abc.zip"),
        ("DELETE", "/rustfs/admin/v3/object-zip-downloads/abc.zip"),
        ("POST", "/rustfs/admin/v3/object-zip-downloads/abc.zip"),
        ("PUT", "/rustfs/admin/v3/object-zip-downloads"),
        ("GET", "/rustfs/admin/v3/object-zip-download/abc.zip"),
    ] {
        assert_eq!(reached(method, target), Some("rustfs:AdminFallback"), "{method} {target}");
    }
    // The opaque capture takes any one segment: a wrong suffix reaches the operation, whose
    // handler refuses an id the token was not minted for.
    assert_eq!(reached("GET", "/rustfs/admin/v3/object-zip-downloads/abc.tar"), Some(ZIP_GET));
}

/// Negative — the two selections agree on every extension request and near miss, with and
/// without the dialect, so a RustFS deployment sees one answer whichever selection it builds.
#[test]
fn n_the_two_selections_never_disagree_on_an_extension_request() {
    let keys = [
        "replication-reset",
        "replication-reset=",
        "replication-reset=1",
        "replication-reset-status",
        "replication-metrics",
        "replication-metrics=2",
        "replication-metrics=3",
        "replication-check",
        "replication-check=1",
        "lambdaArn=x",
        "events",
        "events=x",
        "acl&events",
        "replication-check&events",
    ];
    for method in ["GET", "PUT", "HEAD", "DELETE"] {
        for path in ["/", "/bkt", "/bkt/obj"] {
            for key in keys {
                let target = format!("{path}?{key}");
                for installed in [true, false] {
                    let table = reach(installed, Selection::Table, method, &target);
                    let legacy = reach(installed, Selection::RustfsLegacy, method, &target);
                    if installed || table.is_none() || legacy.is_some() {
                        assert_eq!(table, legacy, "{installed} {method} {target}");
                    } else {
                        // Without the dialect, legacy RustFS names the missing extension operation
                        // and the table serves the standard one: the one disagreement, by design.
                        assert!(table.is_some_and(|op| !op.starts_with("rustfs:")), "{method} {target}");
                    }
                }
            }
        }
    }
}

// ── declarations ──────────────────────────────────────────────────────────────────────────────

/// Positive — exactly the eight extension operations are declared as S3-table rows, each under
/// its record's name, at its row's precedence, with its selector recorded in the overlay.
#[test]
fn the_eight_extension_operations_are_declared_as_their_records_say() {
    let dialect = dialect();
    let declared: Vec<(&str, u16, String)> = dialect
        .operations()
        .iter()
        .map(|operation| {
            (
                operation.name(),
                operation.entry().precedence,
                render_selector(&operation.entry().selector),
            )
        })
        .collect();
    assert_eq!(declared.len(), 8);
    assert_eq!(EXTENSION_ROUTES.len(), 8);
    let names: Vec<&str> = EXTENSION_ROUTES.iter().map(|record| record.operation).collect();
    assert_eq!(names, [RESET, RESET_STATUS, METRICS_V2, METRICS, CHECK, LAMBDA, LISTEN, LISTEN_BUCKET]);
    for ((name, precedence, selector), record) in declared.iter().zip(EXTENSION_ROUTES) {
        assert_eq!(*name, record.operation);
        let row = OVERLAY
            .operations
            .iter()
            .find(|row| row.name == *name)
            .expect("the overlay records every extension operation");
        assert_eq!((row.precedence, row.selector), (*precedence, selector.as_str()), "{name}");
        assert_eq!(row.action, record.action, "{name}");
        assert!(!row.anonymous, "{name}");
        assert!(row.evidence.iter().any(|url| url.contains("rustfs/src/admin/router.rs")), "{name}");
        assert!(row.evidence.contains(&"https://github.com/rustfs/backlog/issues/2753"), "{name}");
        assert!(selector.contains(&format!("Method({})", record.method)), "{name}: {selector}");
        let target = match record.target {
            "service" => "Target(Service)",
            "bucket" => "Target(Bucket)",
            "object" => "Target(Object)",
            other => panic!("{name}: an unknown target {other:?}"),
        };
        assert!(selector.contains(target), "{name}: {selector}");
        let (key, rule) = record.query;
        let predicate = match rule.strip_prefix("equals:") {
            Some(value) => format!("QueryEquals({key:?}, {value:?})"),
            None => {
                assert_eq!(rule, "present", "{name}");
                format!("QueryPresent({key:?})")
            }
        };
        assert!(selector.ends_with(&predicate), "{name}: {selector}");
    }
    // Precedences are distinct and in the inventory's order, ahead of every standard row (90 up).
    let precedences: Vec<u16> = declared.iter().map(|(_, precedence, _)| *precedence).collect();
    assert!(precedences.windows(2).all(|pair| pair[0] < pair[1]), "{precedences:?}");
    assert!(precedences.iter().all(|precedence| *precedence < 90), "{precedences:?}");
}

/// Positive and negative — every extension operation's floor is privileged and header-signed
/// only, its action is the inventory's IAM action on the resource its target names, it reads no
/// body, and it holds no secret.
#[test]
fn every_extension_operation_declares_a_privileged_floor_and_its_inventory_action() {
    fn check<O: ExtensionOperation>(record_name: &str, action: &str, resource: ResourceShape) {
        let floor = O::floor();
        assert!(floor.privileged(), "{record_name}");
        assert!(!floor.allows_anonymous(), "{record_name}");
        assert!(!floor.allowed_schemes().allows_presigned(), "{record_name}");
        assert_eq!(floor.service(), SigService::S3, "{record_name}");
        let auth = O::spec().auth.expect("an action");
        assert_eq!((auth.render(), auth.resource), (action.to_owned(), resource), "{record_name}");
        assert!(!O::spec().receives_caller_secret(), "{record_name}");
        assert_eq!(O::spec().success_status, 200, "{record_name}");
        assert_eq!(O::REQUEST_BODY, RequestBodyMode::None, "{record_name}");
        assert_eq!(O::ROUTE.selector.len(), 3, "{record_name}: method, target and one discriminator");
        assert!(matches!(O::ROUTE.selector[0], Predicate::Method(_)), "{record_name}");
        assert!(matches!(O::ROUTE.selector[1], Predicate::Target(_)), "{record_name}");
        assert!(!O::ROUTE.shadows.is_empty(), "{record_name}: an S3-shaped row shadows its cell");
        assert_eq!(O::NAME, record_name);
    }
    check::<reset_bucket_replication::ResetBucketReplication>(RESET, "s3:ResetBucketReplicationState", ResourceShape::Bucket);
    check::<get_replication_reset_status::GetReplicationResetStatus>(
        RESET_STATUS,
        "s3:ResetBucketReplicationState",
        ResourceShape::Bucket,
    );
    check::<get_replication_metrics_v2::GetReplicationMetricsV2>(
        METRICS_V2,
        "s3:GetReplicationConfiguration",
        ResourceShape::Bucket,
    );
    check::<get_replication_metrics::GetReplicationMetrics>(METRICS, "s3:GetReplicationConfiguration", ResourceShape::Bucket);
    check::<check_replication::CheckReplication>(CHECK, "s3:PutReplicationConfiguration", ResourceShape::Bucket);
    check::<invoke_object_lambda::InvokeObjectLambda>(LAMBDA, "s3:GetObject", ResourceShape::Object);
    check::<listen_notification::ListenNotification>(LISTEN, "s3:ListenNotification", ResourceShape::Service);
    check::<listen_bucket_notification::ListenBucketNotification>(
        LISTEN_BUCKET,
        "s3:ListenBucketNotification",
        ResourceShape::Bucket,
    );
}

/// Positive and negative — each extension row's declared shadows are exactly the standard rows of
/// its method and target a request can satisfy together with it, plus every later extension row
/// of that cell it can be named with: read from the built table, not from the declarations.
#[test]
fn an_extension_row_shadows_exactly_the_rows_of_its_cell_it_can_be_named_with() {
    let dialect = dialect();
    let router = RouterBuilder::new().dialect(&dialect).build().expect("the router builds");
    let entries = router.table().entries();
    for operation in dialect.operations() {
        let mine = operation.entry();
        let (method, target, key, equals) = {
            let predicates = mine.selector.predicates();
            let method = predicates.iter().find_map(|predicate| match predicate {
                Predicate::Method(method) => Some(method.clone()),
                _ => None,
            });
            let target = predicates.iter().find_map(|predicate| match predicate {
                Predicate::Target(target) => Some(*target),
                _ => None,
            });
            let (key, equals) = predicates
                .iter()
                .find_map(|predicate| match predicate {
                    Predicate::QueryPresent(key) => Some((*key, None)),
                    Predicate::QueryEquals(key, value) => Some((*key, Some(*value))),
                    _ => None,
                })
                .expect("one discriminator");
            (method.expect("a method"), target.expect("a target"), key, equals)
        };
        let expected: BTreeSet<&str> = entries
            .iter()
            .filter(|entry| entry.op_name != mine.op_name)
            .filter(|entry| {
                let predicates = entry.selector.predicates();
                let same_cell =
                    predicates.contains(&Predicate::Method(method.clone())) && predicates.contains(&Predicate::Target(target));
                let can_coexist = predicates.iter().all(|predicate| match predicate {
                    Predicate::QueryAbsent(other) => *other != key,
                    Predicate::QueryEquals(other, value) => *other != key || equals.is_none_or(|mine| mine == *value),
                    _ => true,
                });
                same_cell && can_coexist && entry.precedence > mine.precedence
            })
            .map(|entry| entry.op_name)
            .collect();
        let declared: BTreeSet<&str> = operation.shadows().iter().map(|decl| decl.shadowed).collect();
        assert_eq!(declared, expected, "{}", mine.op_name);
        assert_eq!(declared.len(), operation.shadows().len(), "{}: each row declared once", mine.op_name);
        assert!(
            operation
                .shadows()
                .iter()
                .all(|decl| decl.winner == mine.op_name && !decl.evidence.is_empty()),
            "{}",
            mine.op_name
        );
        // Every standard row of the cell is behind the extension row.
        assert!(
            entries
                .iter()
                .filter(|entry| !entry.op_name.starts_with("rustfs:"))
                .filter(|entry| {
                    let predicates = entry.selector.predicates();
                    predicates.contains(&Predicate::Method(method.clone())) && predicates.contains(&Predicate::Target(target))
                })
                .all(|entry| entry.precedence > mine.precedence),
            "{}",
            mine.op_name
        );
    }
}

/// Negative — no extension operation is a claimed row, a form claim, an inventory route or a
/// staying route, and no claimed operation is an extension row: the three kinds are disjoint.
#[test]
fn n_an_extension_operation_is_declared_only_once_and_only_as_a_table_row() {
    let dialect = dialect();
    let extension_names: BTreeSet<&str> = dialect.operations().iter().map(|operation| operation.name()).collect();
    assert!(
        dialect
            .claimed_operations()
            .iter()
            .all(|operation| !extension_names.contains(operation.name()))
    );
    assert!(
        dialect
            .form_operations()
            .iter()
            .all(|operation| !extension_names.contains(operation.name()))
    );
    assert!(ROUTES.iter().all(|record| !extension_names.contains(record.operation)));
    assert!(
        EXTENSION_ROUTES
            .iter()
            .all(|record| !ROUTES.iter().any(|route| route.operation == record.operation))
    );
    let overlay: Vec<&str> = OVERLAY.operations.iter().map(|row| row.name).collect();
    for name in &extension_names {
        assert_eq!(overlay.iter().filter(|recorded| *recorded == name).count(), 1, "{name}");
    }
    assert_eq!(extension_names.len(), dialect.operations().len());
}

/// Positive — the staying list is the four `/health` rows and nothing else: the zip pair left it.
#[test]
fn only_the_four_health_rows_stay_with_rustfs() {
    let staying: Vec<(&str, &str)> = STAYING.iter().map(|route| (route.method, route.path)).collect();
    assert_eq!(
        staying,
        [
            ("GET", "/health"),
            ("GET", "/health/ready"),
            ("HEAD", "/health"),
            ("HEAD", "/health/ready")
        ]
    );
    assert!(STAYING.iter().all(|route| route.group == "health"));
    assert!(!STAYING.iter().any(|route| route.path.contains("zip")));
}

/// Positive and negative — the zip pair: the download is a claimed row on one opaque `{+id}`
/// segment under both prefixes, the minting `POST` an exact row; both floors are privileged,
/// never anonymous and never presigned; each is authorised by its own vendor label about the
/// caller; the download reads no body, the `POST` hands its body over; and the records keep the
/// inventory's `{id}.zip` spelling.
#[test]
fn the_zip_pair_declares_privileged_floors_own_labels_and_its_inventory_rows() {
    use get_v3_object_zip_downloads_by_id_zip::GetV3ObjectZipDownloadsByIdZip as Download;
    use post_v3_object_zip_downloads::PostV3ObjectZipDownloads as Mint;
    for (floor, name) in [(Download::floor(), ZIP_GET), (Mint::floor(), ZIP_POST)] {
        assert!(floor.privileged(), "{name}");
        assert!(!floor.allows_anonymous(), "{name}");
        assert!(!floor.allowed_schemes().allows_presigned(), "{name}");
    }
    let download = Download::spec().auth.expect("an action");
    assert_eq!(
        (download.render(), download.resource),
        ("rustfs:DownloadObjectZip about caller".to_owned(), ResourceShape::Service)
    );
    let mint = Mint::spec().auth.expect("an action");
    assert_eq!(
        (mint.render(), mint.resource),
        ("rustfs:CreateObjectZipDownload about caller".to_owned(), ResourceShape::Service)
    );
    assert_eq!(Download::REQUEST_BODY, RequestBodyMode::None);
    assert_eq!(Mint::REQUEST_BODY, RequestBodyMode::Full);
    let templates: Vec<&str> = get_v3_object_zip_downloads_by_id_zip::ROWS
        .iter()
        .map(|row| row.template)
        .collect();
    assert_eq!(
        templates,
        [
            "/rustfs/admin/v3/object-zip-downloads/{+id}",
            "/minio/admin/v3/object-zip-downloads/{+id}"
        ]
    );
    let download_record = get_v3_object_zip_downloads_by_id_zip::RECORD;
    assert_eq!(
        (download_record.path, download_record.alias, download_record.group, download_record.ruled),
        (
            "/rustfs/admin/v3/object-zip-downloads/{id}.zip",
            Some("/minio/admin/v3/object-zip-downloads/{id}.zip"),
            "object_zip_download",
            Some("CredentialOnly")
        )
    );
    assert!(!download_record.anonymous);
    let mint_record = post_v3_object_zip_downloads::RECORD;
    assert_eq!(
        (mint_record.path, mint_record.ruled, mint_record.rustfs_handler),
        (
            "/rustfs/admin/v3/object-zip-downloads",
            Some("S3Action"),
            "CreateObjectZipDownloadHandler"
        )
    );
    assert!(ROUTES.contains(&download_record) && ROUTES.contains(&mint_record));
}

/// Positive — an extension codec reads no body and answers what the handler answers, complete
/// or streamed.
#[test]
fn an_extension_codec_reads_no_body_and_answers_what_the_handler_answers() {
    let request = Request::builder()
        .method("GET")
        .uri("http://s3.example.com/bkt?replication-check")
        .header("host", "s3.example.com")
        .body(())
        .expect("a fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let meta = MetaView::of(&wire, TargetKind::Bucket).expect("a view");
    check_replication::CheckReplication::decode(&meta, RequestBody::None).expect("nothing to decode");
    let encoded = check_replication::CheckReplication::encode(AdminResponse::json(b"{\"ok\":true}".to_vec()), &meta, 200)
        .expect("the answer encodes");
    assert_eq!(encoded.status, 200);
    assert!(matches!(&encoded.body, ResponseBody::Complete(bytes) if bytes.as_slice() == b"{\"ok\":true}"));
    let empty = listen_notification::ListenNotification::encode(AdminResponse::empty(), &meta, 200).expect("encodes");
    assert!(matches!(empty.body, ResponseBody::Empty));
}

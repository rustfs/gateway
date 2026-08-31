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

//! Routing decides which operation; validation decides whether its parameters are there.
//!
//! Responsible for: the parameter cases, the two textually different `501`s, and the properties of
//! an error raised before anybody has been authenticated — never a `5xx`, never a word from the
//! request.
//! NOT responsible for: the code-to-status table itself, which belongs to `rustfs-gateway-types`
//! and is tested there.
//! Upstream: `support`. Downstream: nothing.
//!
//! # The headline
//!
//! `PUT /bucket?analytics` without `id` must be a `400` naming the parameter. Modelling `id` as a
//! routing predicate makes it a `501`, and a `501` tells the client this service does not support
//! the operation — so the client disables the feature instead of fixing its request, and the
//! operator goes looking for a handler that is not missing.

use crate::support;

use http::{Method, StatusCode};
use rustfs_gateway_core::dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE, Router};
use rustfs_gateway_core::error::{PRE_AUTH_STATUSES, PreAuthError};
use rustfs_gateway_core::op::{AuthRequirement, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec, ParamKind, Registry, RegistryError, RequiredParam};
use rustfs_gateway_core::route::{Predicate, RouteTable, ShadowingDecls, ShadowingPolicy, TargetKind};
use rustfs_gateway_types::ErrorCode;
use support::{Req, entry};

static PUT_ANALYTICS: OperationSpec = OperationSpec::builder("PutBucketAnalyticsConfiguration", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[RequiredParam {
        kind: ParamKind::Query,
        name: "id",
        missing_error: ErrorCode::INVALID_ARGUMENT,
        message: "The required parameter 'id' is missing",
    }])
    .auth(AuthRequirement::new("s3:PutAnalyticsConfiguration", ResourceShape::Bucket))
    .build();

static GET_OBJECT: OperationSpec = OperationSpec::builder("GetObject", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object))
    .build();

static DELETE_OBJECT: OperationSpec = OperationSpec::builder("DeleteObject", 204, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:DeleteObject", ResourceShape::Object))
    .build();

static LIST_OBJECTS: OperationSpec = OperationSpec::builder("ListObjects", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket))
    .build();

static GET_LIFECYCLE: OperationSpec =
    OperationSpec::builder("GetBucketLifecycleConfiguration", 200, Some(ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION))
        .required_params(&[])
        .auth(AuthRequirement::new("s3:GetLifecycleConfiguration", ResourceShape::Bucket))
        .build();

static COPY_OBJECT: OperationSpec = OperationSpec::builder("CopyObject", 200, None)
    .required_params(&[RequiredParam {
        kind: ParamKind::Header,
        name: "x-amz-copy-source",
        missing_error: ErrorCode::INVALID_ARGUMENT,
        message: "The required header 'x-amz-copy-source' is missing",
    }])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// The plain object write, registered by the ACL block below so that a request reaching it
/// instead of its subresource row is a wrong answer rather than a second `501`.
static PUT_OBJECT: OperationSpec = OperationSpec::builder("PutObject", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// Deliberately unregistrable, and kept for the test that says so.
///
/// `MissingContentLength` is a good S3 code and a bad pre-authentication one: it maps to `411`,
/// which is outside the closed set. That is not a gap in the set — a missing `Content-Length` is a
/// framing fact the acceptance layer already refuses, long before an operation is known — but the
/// only way to be sure the closed set is enforced rather than described is to try to break it.
static UPLOAD_PART: OperationSpec = OperationSpec::builder("UploadPart", 200, None)
    .required_params(&[RequiredParam {
        kind: ParamKind::Header,
        name: "content-length",
        missing_error: ErrorCode::MISSING_CONTENT_LENGTH,
        message: "The request is missing a Content-Length header",
    }])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// A table with the four operations these cases route to.
fn table() -> RouteTable {
    let entries = vec![
        entry(
            "PutBucketAnalyticsConfiguration",
            300,
            vec![
                Predicate::Method(Method::PUT),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
            ],
        ),
        entry(
            "GetBucketLifecycleConfiguration",
            310,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("lifecycle"),
            ],
        ),
        entry(
            "CopyObject",
            320,
            vec![
                Predicate::Method(Method::PUT),
                Predicate::Target(TargetKind::Object),
                Predicate::QueryAbsent("uploadId"),
            ],
        ),
        entry(
            "GetObject",
            820,
            vec![Predicate::Method(Method::GET), Predicate::Target(TargetKind::Object)],
        ),
        entry(
            "DeleteObject",
            830,
            vec![Predicate::Method(Method::DELETE), Predicate::Target(TargetKind::Object)],
        ),
    ];
    RouteTable::build(entries, &ShadowingDecls::NONE.with_policy(ShadowingPolicy::TotalOnly)).expect("a well-formed table")
}

fn router(specs: &[&'static OperationSpec]) -> Router {
    let mut registry = Registry::new();
    for spec in specs {
        registry.register(spec).expect("a registrable spec");
    }
    Router::new(table(), registry).expect("a compilable table")
}

fn full_router() -> Router {
    router(&[&PUT_ANALYTICS, &GET_OBJECT, &DELETE_OBJECT, &GET_LIFECYCLE, &COPY_OBJECT])
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// c-param-0001
#[test]
fn analytics_with_an_id_routes_and_validates() {
    let router = full_router();
    let request = Req::new("PUT /bucket?analytics&id=x");
    let dispatch = router.dispatch(&request.parts()).expect("routed and valid");
    assert_eq!(dispatch.entry.op_name, "PutBucketAnalyticsConfiguration");
    assert_eq!(dispatch.spec.name, "PutBucketAnalyticsConfiguration");
}

/// c-param-0002
#[test]
fn an_object_get_has_nothing_to_validate() {
    let router = full_router();
    let request = Req::new("GET /bucket/key");
    let dispatch = router.dispatch(&request.parts()).expect("routed");
    assert_eq!(dispatch.entry.op_name, "GetObject");
    assert!(dispatch.spec.required_params.is_empty());
}

/// c-err-0009 — the delete family's success status is carried per operation, not assumed.
#[test]
fn the_delete_family_succeeds_with_204() {
    let router = full_router();
    let dispatch = router.dispatch(&Req::new("DELETE /bucket/key").parts()).expect("routed");
    assert_eq!(dispatch.spec.success_status, 204);
    let get = router.dispatch(&Req::new("GET /bucket/key").parts()).expect("routed");
    assert_eq!(get.spec.success_status, 200);
}

/// c-err-0006 — an unconfigured subresource has its own code, not a generic not-found.
#[test]
fn an_unconfigured_subresource_has_its_own_code() {
    let router = full_router();
    let dispatch = router.dispatch(&Req::new("GET /bucket?lifecycle").parts()).expect("routed");
    let code = dispatch
        .spec
        .not_configured_error
        .clone()
        .expect("a bucket subresource declares one");
    assert_eq!(code, ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION);
    assert_eq!(code.default_status(), StatusCode::NOT_FOUND);
    assert_ne!(code, ErrorCode::NO_SUCH_KEY, "a generic not-found sends the operator elsewhere");
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// c-param-1001 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
/// The headline: a missing required parameter is a `400`, not a `501`.
#[test]
fn a_missing_required_query_parameter_is_a_400_not_a_501() {
    let router = full_router();
    let request = Req::new("PUT /bucket?analytics");
    let error = router.dispatch(&request.parts()).expect_err("id is required");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(*error.code(), ErrorCode::INVALID_ARGUMENT);
    assert_eq!(error.message(), "The required parameter 'id' is missing");
    assert_eq!(error.operation(), Some("PutBucketAnalyticsConfiguration"));
    assert_ne!(
        error.status(),
        StatusCode::NOT_IMPLEMENTED,
        "501 would tell the client this service does not support the operation"
    );
}

/// c-param-1001 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
/// Routing still happened: the operation is known, which is why the error can be specific.
#[test]
fn the_route_still_resolves_when_a_required_parameter_is_missing() {
    let router = full_router();
    let request = Req::new("PUT /bucket?analytics");
    let hit = router.resolve(&request.parts()).expect("routing does not depend on `id`");
    assert_eq!(hit.op_name, "PutBucketAnalyticsConfiguration");
}

/// A missing required header behaves the same way, with the operation's own code.
#[test]
fn a_missing_required_header_is_the_operations_own_code() {
    let router = full_router();
    let request = Req::new("PUT /bucket/key");
    let error = router.dispatch(&request.parts()).expect_err("x-amz-copy-source is required");
    assert_eq!(*error.code(), ErrorCode::INVALID_ARGUMENT);
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.operation(), Some("CopyObject"));

    let with_header = Req::new("PUT /bucket/key").header("x-amz-copy-source", "/other/key");
    assert!(router.dispatch(&with_header.parts()).is_ok(), "the header satisfies it");
}

/// `411` is not a pre-authentication status, so registration must refuse a spec that wants one.
///
/// This is the check that keeps the closed status set from being a comment.
#[test]
fn a_required_parameter_declaring_an_out_of_band_status_cannot_be_registered() {
    let mut registry = Registry::new();
    let error = registry
        .register(&UPLOAD_PART)
        .expect_err("411 is not reachable before authentication");
    let RegistryError::UnusableMissingError { name, param, .. } = &error else {
        panic!("expected an unusable code, got {error}");
    };
    assert_eq!(*name, "UploadPart");
    assert_eq!(*param, "content-length");
}

/// c-route-1005 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
/// The two `501`s call for opposite actions, so they must not read the same.
#[test]
fn the_two_not_implemented_messages_are_different() {
    let router = router(&[&GET_OBJECT]);

    let unrouted = router
        .dispatch(&Req::new("BREW /bucket/key").parts())
        .expect_err("no route for this");
    let unregistered = router
        .dispatch(&Req::new("DELETE /bucket/key").parts())
        .expect_err("routed, but not handled here");

    assert_eq!(unrouted.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(unregistered.status(), StatusCode::NOT_IMPLEMENTED);
    assert_ne!(
        unrouted.message(),
        unregistered.message(),
        "one means fix the configuration, the other means write a handler"
    );
    assert_eq!(unrouted.message(), NO_ROUTE_MESSAGE);
    assert_eq!(unregistered.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(unrouted.operation(), None);
    assert_eq!(unregistered.operation(), Some("DeleteObject"));
}

/// c-route-1004 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
/// The unrouted message must be actionable: the usual cause is an unconfigured vhost domain.
#[test]
fn the_unrouted_message_says_what_to_check() {
    assert!(
        NO_ROUTE_MESSAGE.contains("virtual host"),
        "a bare 'not implemented' sends the operator looking for a missing feature"
    );
}

/// c-param-1002 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
/// Nothing in a pre-authentication error may come from the request.
#[test]
fn a_missing_parameter_error_echoes_nothing_from_the_request() {
    let router = full_router();
    let request = Req::new("PUT /secret-bucket?analytics&marker=CANARY");
    let error = router.dispatch(&request.parts()).expect_err("id is required");
    let rendered = error.to_string();
    for probe in ["secret-bucket", "CANARY", "marker"] {
        assert!(
            !rendered.contains(probe),
            "the error must not reflect {probe:?} back to an unauthenticated caller:\n{rendered}"
        );
    }
}

/// Every constructor lands inside the closed set.
#[test]
fn every_pre_auth_error_carries_an_allowed_status() {
    let errors = [
        PreAuthError::invalid_argument("a"),
        PreAuthError::invalid_request("b"),
        PreAuthError::access_denied("c"),
        PreAuthError::not_implemented("d"),
    ];
    for error in errors {
        assert!(
            PRE_AUTH_STATUSES.contains(&error.status()),
            "{} maps to {}, outside the pre-authentication set",
            error.code(),
            error.status()
        );
        // 501 is in the set on purpose; 500 and 503 are what must be unreachable, because a
        // client that receives one retries a request that cannot succeed.
        assert_ne!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

/// A `5xx` code cannot be smuggled in through the general constructor.
#[test]
fn a_server_error_code_cannot_become_a_pre_auth_error() {
    for code in [
        ErrorCode::INTERNAL_ERROR,
        ErrorCode::SERVICE_UNAVAILABLE,
        ErrorCode::SLOW_DOWN,
    ] {
        let error = PreAuthError::with_code(code.clone(), "static").expect_err("a 5xx is not reachable here");
        assert!(error.status.is_server_error());
        assert_eq!(error.code, code);
    }
}

/// A code with no table row carries the status its author named, and the pre-authentication
/// surface stays closed against the 5xx band in both directions.
#[test]
fn an_unknown_code_carries_the_status_its_author_named() {
    let code = ErrorCode::custom("SomethingNobodyModelled", StatusCode::BAD_REQUEST);
    assert!(!code.is_known());
    assert_eq!(code.default_status(), StatusCode::BAD_REQUEST);
    let error = PreAuthError::with_code(code, "static").expect("400 is reachable before authentication");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);

    // The other direction: an undeclared code cannot smuggle a 5xx past the pre-authentication
    // surface just because nobody wrote a row for it.
    PreAuthError::with_code(ErrorCode::custom("SomethingNobodyModelled", StatusCode::INTERNAL_SERVER_ERROR), "static")
        .expect_err("a 5xx is not reachable before authentication, declared or not");
}

/// `NotImplemented` for a routed-but-unhandled operation is not the same as `MethodNotAllowed`.
#[test]
fn an_unhandled_operation_is_not_reported_as_a_method_problem() {
    let router = router(&[&GET_OBJECT]);
    let error = router
        .dispatch(&Req::new("DELETE /bucket/key").parts())
        .expect_err("not handled here");
    assert_ne!(*error.code(), ErrorCode::METHOD_NOT_ALLOWED);
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
}

/// One registration per operation.
#[test]
fn registering_an_operation_twice_is_refused() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("first registration");
    let error = registry.register(&GET_OBJECT).expect_err("second registration");
    assert!(matches!(error, RegistryError::Duplicate { .. }), "got {error}");
}

/// c-route-1005 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
/// An empty registry routes everything and handles nothing — every answer is the second `501`.
#[test]
fn an_empty_registry_answers_the_second_not_implemented() {
    let router = router(&[]);
    let error = router
        .dispatch(&Req::new("GET /bucket/key").parts())
        .expect_err("nothing handled");
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("GetObject"));
}

/// An operation the protocol defines and this build does not handle is refused, not substituted.
///
/// The generated table, not the fixture: the point of the case is that routing is settled by the
/// protocol before registration is consulted, so a backend that handles `GetObject` and nothing
/// else must answer an attributes read with the second `501` naming `GetObjectAttributes` — never
/// with `GetObject`'s answer. Registering a handler may change whether a request can be *served*;
/// it must not change what the request *means*.
#[test]
fn an_unhandled_attributes_read_is_refused_rather_than_answered_by_the_object_read() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let error = router
        .dispatch(&Req::new("GET /bucket/key?attributes").parts())
        .expect_err("no backend in this workspace handles the attributes read");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(
        error.operation(),
        Some("GetObjectAttributes"),
        "the refusal must name the operation the request asked for"
    );
}

/// The registered neighbour is still served, so the refusal above is not a blanket one.
#[test]
fn the_generated_router_still_serves_the_plain_object_read() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let dispatch = router.dispatch(&Req::new("GET /bucket/key").parts()).expect("routed");
    assert_eq!(dispatch.entry.op_name, "GetObject");
}

/// Negative — an unhandled tagging request is refused by name, in all three methods.
///
/// The registry below handles the plain object band and nothing else, which is the shape of every
/// deployment that has not implemented tagging. Each of the three must come back as the second
/// `501` naming the tagging operation the request asked for — not as a `GetObject` body, not as a
/// `PutObject` write, and not as a `DeleteObject` that answers `204` for a request that meant to
/// remove a label. Registration decides whether a request can be *served*; it must never decide
/// what the request *means*.
#[test]
fn n_an_unhandled_tagging_request_is_refused_rather_than_answered_by_the_object_band() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    registry.register(&DELETE_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket/key?tagging", "GetObjectTagging"),
        ("PUT /bucket/key?tagging", "PutObjectTagging"),
        ("DELETE /bucket/key?tagging", "DeleteObjectTagging"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no tagging operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// The two registered neighbours are still served, so the refusal above is not a blanket one.
#[test]
fn the_generated_router_still_serves_the_plain_object_band_beside_the_tagging_rows() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    registry.register(&DELETE_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [("GET /bucket/key", "GetObject"), ("DELETE /bucket/key", "DeleteObject")] {
        let dispatch = router.dispatch(&Req::new(line).parts()).expect("routed");
        assert_eq!(dispatch.entry.op_name, expected, "{line}");
    }
}

/// Negative — an unhandled CORS-configuration request is refused by name, in all three methods.
///
/// The registry below handles the listing fallback and nothing else, which is the shape of every
/// deployment that has not implemented CORS configuration. Each of the three must come back as
/// the second `501` naming the CORS operation the request asked for — the GET in particular must
/// not fall through to `ListObjects`, which is exactly what it did while the operation was
/// deferred (the `GetBucketCors -> ListObjects` debt-register line). Registration decides whether
/// a request can be *served*; it must never decide what the request *means*.
#[test]
fn n_an_unhandled_cors_request_is_refused_rather_than_answered_by_the_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?cors", "GetBucketCors"),
        ("PUT /bucket?cors", "PutBucketCors"),
        ("DELETE /bucket?cors", "DeleteBucketCors"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no CORS operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// Negative — an unhandled lifecycle-configuration request is refused by name, in all three
/// methods.
///
/// Same shape as the CORS block above: the registry handles the listing fallback and nothing
/// else, which is the shape of every deployment that has not implemented lifecycle
/// configuration. Each of the three must come back as the second `501` naming the lifecycle
/// operation the request asked for — the GET in particular must not fall through to
/// `ListObjects`, which is exactly what it did while the operation was deferred (the
/// `GetBucketLifecycleConfiguration -> ListObjects` debt-register line).
#[test]
fn n_an_unhandled_lifecycle_request_is_refused_rather_than_answered_by_the_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?lifecycle", "GetBucketLifecycleConfiguration"),
        ("PUT /bucket?lifecycle", "PutBucketLifecycleConfiguration"),
        ("DELETE /bucket?lifecycle", "DeleteBucketLifecycle"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no lifecycle operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// Negative — an unhandled encryption-configuration request is refused by name, in all three
/// methods.
///
/// Same shape as the lifecycle block above: the registry handles the listing fallback and
/// nothing else, which is the shape of every deployment that has not implemented default
/// encryption. Each of the three must come back as the second `501` naming the encryption
/// operation the request asked for — the GET in particular must not fall through to
/// `ListObjects`, which is exactly what it did while the operation was deferred (the
/// `GetBucketEncryption -> ListObjects` debt-register line).
#[test]
fn n_an_unhandled_encryption_request_is_refused_rather_than_answered_by_the_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?encryption", "GetBucketEncryption"),
        ("PUT /bucket?encryption", "PutBucketEncryption"),
        ("DELETE /bucket?encryption", "DeleteBucketEncryption"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no encryption operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// Negative — an unhandled replication-configuration request is refused by name, in all three
/// methods.
///
/// Same shape as the encryption block above: the registry handles the listing fallback and
/// nothing else, which is the shape of every deployment that has not implemented replication.
/// Each of the three must come back as the second `501` naming the replication operation the
/// request asked for — the GET in particular must not fall through to `ListObjects`, which is
/// exactly what it did while the operation was deferred (the
/// `GetBucketReplication -> ListObjects` debt-register line).
#[test]
fn n_an_unhandled_replication_request_is_refused_rather_than_answered_by_the_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?replication", "GetBucketReplication"),
        ("PUT /bucket?replication", "PutBucketReplication"),
        ("DELETE /bucket?replication", "DeleteBucketReplication"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no replication operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// The registered fallback is still served, so the refusal above is not a blanket one.
#[test]
fn the_generated_router_still_serves_the_listing_beside_the_cors_rows() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let dispatch = router.dispatch(&Req::new("GET /bucket").parts()).expect("routed");
    assert_eq!(dispatch.entry.op_name, "ListObjects");
}

/// Negative — an unhandled *bucket* tagging request is refused by name, in all three methods.
///
/// The bucket-scope twin of the object-band block above and the CORS block beside it, with a
/// different wrong answer to exclude: before the rows existed the GET was claimed by
/// `ListObjects` and answered with a page of keys, and the PUT and DELETE were unroutable. All
/// three must now come back as the second `501`, naming the bucket operation the request asked
/// for.
#[test]
fn n_an_unhandled_bucket_tagging_request_is_refused_rather_than_answered_by_a_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?tagging", "GetBucketTagging"),
        ("PUT /bucket?tagging", "PutBucketTagging"),
        ("DELETE /bucket?tagging", "DeleteBucketTagging"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no bucket tagging operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// The bucket-scope unconfigured answer is declared, not improvised: `GetBucketTagging`'s spec
/// carries `NoSuchTagSet` as its `not_configured_error`, and the code's own status is the 404 a
/// client branches on. The object read deliberately declares none — its empty answer is a `200`.
#[test]
fn the_bucket_tagging_read_declares_its_own_not_configured_code() {
    use rustfs_gateway_core::op::Operation;
    let code = rustfs_gateway_types::dto::GetBucketTagging::spec()
        .not_configured_error
        .clone()
        .expect("the bucket subresource declares one");
    assert_eq!(code, ErrorCode::NO_SUCH_TAG_SET);
    assert_eq!(code.default_status(), StatusCode::NOT_FOUND);
    assert!(
        rustfs_gateway_types::dto::GetObjectTagging::spec()
            .not_configured_error
            .is_none(),
        "the object read answers 200 with an empty set, never NoSuchTagSet"
    );
}

/// Negative — an unhandled object-lock configuration request is refused by name, in both
/// methods the family defines.
///
/// Same shape as the encryption block above: the registry handles the listing fallback and
/// nothing else. Both requests must come back as the second `501` naming the lock operation
/// the request asked for — the GET in particular must not fall through to `ListObjects`, which
/// is exactly what it did while the operation was deferred (the
/// `GetObjectLockConfiguration -> ListObjects` debt-register line).
#[test]
fn n_an_unhandled_object_lock_request_is_refused_rather_than_answered_by_the_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?object-lock", "GetObjectLockConfiguration"),
        ("PUT /bucket?object-lock", "PutObjectLockConfiguration"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no object-lock operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// Negative — an unhandled retention or legal-hold request is refused by name, in both methods
/// of both subresources.
///
/// The registry below handles the plain object band and nothing else, which is the shape of
/// every deployment that has not implemented object lock. Each of the four must come back as
/// the second `501` naming the lock operation the request asked for — not as a `GetObject` body
/// and not as a `PutObject` write that stores the compliance document as the object.
#[test]
fn n_an_unhandled_lock_state_request_is_refused_rather_than_answered_by_the_object_band() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket/key?retention", "GetObjectRetention"),
        ("PUT /bucket/key?retention", "PutObjectRetention"),
        ("GET /bucket/key?legal-hold", "GetObjectLegalHold"),
        ("PUT /bucket/key?legal-hold", "PutObjectLegalHold"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no lock-state operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// The family's two unconfigured answers are declared, not improvised, and they are different
/// codes: the bucket read carries `ObjectLockConfigurationNotFoundError`, the two object reads
/// carry `NoSuchObjectLockConfiguration`, and clients branch on the difference. The writes
/// declare none — a write has no unconfigured answer.
#[test]
fn the_lock_reads_declare_their_two_distinct_not_configured_codes() {
    use rustfs_gateway_core::op::Operation;
    let bucket = rustfs_gateway_types::dto::GetObjectLockConfiguration::spec()
        .not_configured_error
        .clone()
        .expect("the bucket read declares one");
    assert_eq!(bucket, ErrorCode::OBJECT_LOCK_CONFIGURATION_NOT_FOUND);
    assert_eq!(bucket.default_status(), StatusCode::NOT_FOUND);
    for (name, code) in [
        (
            "GetObjectRetention",
            rustfs_gateway_types::dto::GetObjectRetention::spec()
                .not_configured_error
                .clone(),
        ),
        (
            "GetObjectLegalHold",
            rustfs_gateway_types::dto::GetObjectLegalHold::spec()
                .not_configured_error
                .clone(),
        ),
    ] {
        let code = code.expect("the object read declares one");
        assert_eq!(code, ErrorCode::NO_SUCH_OBJECT_LOCK_CONFIGURATION, "{name}");
        assert_eq!(code.default_status(), StatusCode::NOT_FOUND, "{name}");
        assert_ne!(code, bucket, "{name}: the object-level code must stay distinct from the bucket-level one");
    }
    assert!(
        rustfs_gateway_types::dto::PutObjectRetention::spec()
            .not_configured_error
            .is_none()
            && rustfs_gateway_types::dto::PutObjectLegalHold::spec()
                .not_configured_error
                .is_none()
            && rustfs_gateway_types::dto::PutObjectLockConfiguration::spec()
                .not_configured_error
                .is_none(),
        "a write has no unconfigured answer"
    );
}

/// The replication read declares its own unconfigured code, and its two siblings declare none.
///
/// The declaration is what a backend outside this workspace reads to learn which 404 an
/// unconfigured bucket owes, and since gateway#242 the conformance fixture answers from that
/// declaration rather than from a constant of its own. This test holds the near end of that chain;
/// a replication case observes the far end.
///
/// Both directions are asserted deliberately. A spec field stuck on `Some(..)` would satisfy the
/// first assertion alone, and the write and the delete are exactly the operations that must
/// carry `None`: neither reads a configuration, and a 404 from either would mean "no such
/// bucket" to a client that branches on the code.
#[test]
fn the_replication_read_declares_its_own_not_configured_code() {
    use rustfs_gateway_core::op::Operation;
    let code = rustfs_gateway_types::dto::GetBucketReplication::spec()
        .not_configured_error
        .clone()
        .expect("the bucket subresource read declares one");
    assert_eq!(code, ErrorCode::REPLICATION_CONFIGURATION_NOT_FOUND);
    assert_eq!(code.default_status(), StatusCode::NOT_FOUND);
    assert_eq!(
        code.as_str(),
        "ReplicationConfigurationNotFoundError",
        "the literal ends in Error, which is the spelling clients branch on"
    );
    for (name, declared) in [
        (
            "PutBucketReplication",
            rustfs_gateway_types::dto::PutBucketReplication::spec()
                .not_configured_error
                .is_none(),
        ),
        (
            "DeleteBucketReplication",
            rustfs_gateway_types::dto::DeleteBucketReplication::spec()
                .not_configured_error
                .is_none(),
        ),
    ] {
        assert!(declared, "{name} reads no configuration and must declare no unconfigured code");
    }
}

/// Negative — an unhandled bucket lifecycle request is refused by name, in all three methods.
///
/// The registry below handles the object band and nothing else. Each bucket-level request must
/// come back as the second `501` naming the lifecycle operation it asked for — routing is settled
/// by the protocol before registration is consulted, and a backend that has not implemented the
/// family must not change what `PUT /bucket` means.
#[test]
fn n_an_unhandled_bucket_lifecycle_request_is_refused_by_name() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    registry.register(&DELETE_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("PUT /bucket", "CreateBucket"),
        ("DELETE /bucket", "DeleteBucket"),
        ("HEAD /bucket", "HeadBucket"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no bucket lifecycle operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// Negative — a deferred bucket subresource write has no route, so it is the first `501`, never a
/// lifecycle operation's answer. This is the dispatch-level half of the `query_absent` guarantee:
/// `DELETE /b?policy` must not delete a bucket and `PUT /b?versioning` must not create one,
/// whether or not the lifecycle family is registered. The served subresources (`cors`, `tagging`,
/// `acl`, and the nine configuration-band keys) are the same rule with a different observable —
/// a `501` naming their own operation — and are asserted below and in `route_table.rs`.
#[test]
fn n_a_bucket_subresource_write_is_a_route_miss_not_a_lifecycle_operation() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");
    for line in [
        "PUT /bucket?abac",
        "DELETE /bucket?ownershipControls",
        "PUT /bucket?inventory",
        "DELETE /bucket?analytics",
    ] {
        let error = router.dispatch(&Req::new(line).parts()).expect_err("no route");
        assert_eq!(error.message(), NO_ROUTE_MESSAGE, "{line}");
        assert_eq!(error.operation(), None, "{line} names no operation because none claimed it");
    }
    // The other direction, for the four keys that moved out of the list above when the
    // bucket-configuration band landed: a served subresource write is a 501 that *names its own
    // operation*, never a lifecycle answer and never a route miss. Without this half, deleting the
    // rows would turn these back into the first branch and the test would still pass.
    for (line, expected) in [
        ("PUT /bucket?versioning", "PutBucketVersioning"),
        ("DELETE /bucket?policy", "DeleteBucketPolicy"),
        ("DELETE /bucket?website", "DeleteBucketWebsite"),
        ("PUT /bucket?publicAccessBlock", "PutPublicAccessBlock"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("no handler is registered");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// Negative — an unhandled restore or select request is refused by name, not by no-route.
///
/// The observable this family changes. Before the two rows existed both requests matched
/// nothing, so the answer was the *first* `501` — [`NO_ROUTE_MESSAGE`], the one that says the
/// virtual-host domain is probably unconfigured — and an SDK reads that as "this is not an S3
/// endpoint". Now each comes back as the second `501`, naming the operation it asked for, which
/// is the answer that means "not available here".
///
/// Both directions are checked in one test: the two rows answer by name, and a `?select` without
/// `select-type=2` still answers no-route, because there is no row for it and inventing one
/// would decode a request grammar this decoder has never validated.
#[test]
fn n_an_unhandled_restore_or_select_request_is_refused_by_name() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("POST /bucket/key?restore", "RestoreObject"),
        ("POST /bucket/key?select&select-type=2", "SelectObjectContent"),
        ("POST /bucket/key?restore&versionId=v1", "RestoreObject"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles neither operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }

    for line in ["POST /bucket/key?select", "POST /bucket/key?select&select-type=1"] {
        let error = router.dispatch(&Req::new(line).parts()).expect_err("no route");
        assert_eq!(error.message(), NO_ROUTE_MESSAGE, "{line}");
        assert_eq!(error.operation(), None, "{line} names no operation because none claimed it");
    }
}

/// The restore operation declares 202, and declares the 200 as its one alternative.
///
/// The declaration and the mapping are two things that can disagree, so both directions are
/// asserted here rather than either one alone:
///
/// * every status `RestoreState` can answer on success is either the declared success status or
///   a declared alternative — a mapping that grew a third success would be red;
/// * every declared alternative is a status some state actually answers — a list that grew a
///   number nothing produces would be red too.
///
/// Without the second half the list could be `&[200, 418]` and pass; without the first it could
/// be empty. The pair is the assertion.
#[test]
fn the_restore_status_declaration_and_the_state_mapping_agree() {
    use rustfs_gateway_core::op::Operation;
    use rustfs_gateway_core::ops::restore_object::ALT_SUCCESS_STATUSES;
    use rustfs_gateway_core::ops::shared::restore::RestoreState;

    let declared = rustfs_gateway_types::dto::RestoreObject::spec().success_status;
    assert_eq!(declared, 202, "a first retrieval is Accepted, not OK");
    assert_eq!(ALT_SUCCESS_STATUSES, &[200], "the repeat against a restored copy");

    let states = [
        RestoreState::Initiated,
        RestoreState::AlreadyRestored,
        RestoreState::InProgress,
        RestoreState::NotArchived,
    ];
    let produced: Vec<u16> = states.iter().filter_map(|state| state.status()).collect();
    for status in &produced {
        assert!(
            *status == declared || ALT_SUCCESS_STATUSES.contains(status),
            "the mapping answers {status}, which the operation does not declare"
        );
    }
    for alternative in ALT_SUCCESS_STATUSES {
        assert!(
            produced.contains(alternative),
            "the operation declares {alternative}, which no state answers"
        );
    }
    assert_eq!(produced.len(), 2, "exactly two of the four outcomes are successes");
    assert!(produced.contains(&declared), "the declared status is one a state answers");
}

/// The two new operations declare no unconfigured code, and that is not an oversight.
///
/// `not_configured_error` is the 404 a *subresource read* owes when the document was never
/// written. Neither of these reads a stored document — a restore acts on the object's storage
/// class and a select acts on its bytes — so both must declare `None`, and a value here would
/// tell a backend to answer 404 for a state that is not "unconfigured" at all. Asserted with a
/// control, because the field defaults to `None` and an assertion that everything is `None`
/// would hold over an empty table too.
#[test]
fn neither_restore_nor_select_declares_an_unconfigured_code() {
    use rustfs_gateway_core::op::Operation;
    assert!(
        rustfs_gateway_types::dto::RestoreObject::spec()
            .not_configured_error
            .is_none(),
        "a restore reads no stored configuration"
    );
    assert!(
        rustfs_gateway_types::dto::SelectObjectContent::spec()
            .not_configured_error
            .is_none(),
        "a select reads no stored configuration"
    );
    assert!(
        rustfs_gateway_types::dto::GetObjectRetention::spec()
            .not_configured_error
            .is_some(),
        "the retention read declares one, so the two assertions above are not vacuous"
    );
}

/// Negative — every read in the 200-249 configuration band is refused by name rather than
/// answered by the key listing.
///
/// The registry below handles `ListObjects` and nothing else, which is the shape of a deployment
/// that has not implemented any of this family. Each of the nine must come back as the second
/// `501` naming the operation the request asked for. While these were deferred, every one of them
/// fell through to `ListObjects` and was answered with a page of keys — nine lines of the
/// route-coverage debt register — and a page of keys is a *success*, so nothing the client could
/// see said the question had not been answered.
#[test]
fn n_an_unhandled_bucket_configuration_read_is_refused_rather_than_answered_by_the_listing() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?accelerate", "GetBucketAccelerateConfiguration"),
        ("GET /bucket?logging", "GetBucketLogging"),
        ("GET /bucket?notification", "GetBucketNotificationConfiguration"),
        ("GET /bucket?policy", "GetBucketPolicy"),
        ("GET /bucket?policyStatus", "GetBucketPolicyStatus"),
        ("GET /bucket?publicAccessBlock", "GetPublicAccessBlock"),
        ("GET /bucket?requestPayment", "GetBucketRequestPayment"),
        ("GET /bucket?versioning", "GetBucketVersioning"),
        ("GET /bucket?website", "GetBucketWebsite"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no bucket configuration operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }
}

/// The band's nine unconfigured answers are declared, not improvised — and the declaration is
/// what an external backend reads.
///
/// This test was written because the equivalent claim in the replication family could once be
/// **deleted outright** and the whole workspace stayed green: the conformance 404 came from the
/// fixture's own constant, so `not_configured_error` was decoration. gateway#242 removed that
/// second constant — the fixture now answers from this field — and the shape below is still what
/// makes the claim two-directional, because a field stuck on `Some(..)` satisfies only the first
/// half and a field stuck on `None` satisfies only the second:
///
/// * three reads declare a code, and no two of them declare the same one;
/// * six reads declare **none**, because their unconfigured answer is a `200` — five an empty
///   document and one a default value — and a `404` there is a bug a client sees as a missing
///   bucket;
/// * every write and delete declares none, because neither has an unconfigured answer at all.
#[test]
fn the_configuration_band_declares_three_distinct_not_configured_codes_and_six_absences() {
    use rustfs_gateway_core::op::Operation;
    use rustfs_gateway_types::dto;

    for (name, code, expected) in [
        (
            "GetBucketWebsite",
            dto::GetBucketWebsite::spec().not_configured_error.clone(),
            ErrorCode::NO_SUCH_WEBSITE_CONFIGURATION,
        ),
        (
            "GetBucketPolicy",
            dto::GetBucketPolicy::spec().not_configured_error.clone(),
            ErrorCode::NO_SUCH_BUCKET_POLICY,
        ),
        (
            "GetBucketPolicyStatus",
            dto::GetBucketPolicyStatus::spec().not_configured_error.clone(),
            ErrorCode::NO_SUCH_BUCKET_POLICY,
        ),
        (
            "GetPublicAccessBlock",
            dto::GetPublicAccessBlock::spec().not_configured_error.clone(),
            ErrorCode::NO_SUCH_PUBLIC_ACCESS_BLOCK_CONFIGURATION,
        ),
    ] {
        let declared = code.unwrap_or_else(|| panic!("{name} answers a 404 when unconfigured and must declare which"));
        assert_eq!(declared, expected, "{name}");
        assert_eq!(declared.default_status(), StatusCode::NOT_FOUND, "{name}");
    }

    // The website and public-access literals are distinct from each other and from the policy
    // one. `GetBucketPolicyStatus` shares the policy read's code on purpose — it is the same
    // missing document — and that sharing is asserted above rather than left to coincidence.
    assert_ne!(ErrorCode::NO_SUCH_WEBSITE_CONFIGURATION, ErrorCode::NO_SUCH_BUCKET_POLICY);
    assert_ne!(ErrorCode::NO_SUCH_PUBLIC_ACCESS_BLOCK_CONFIGURATION, ErrorCode::NO_SUCH_BUCKET_POLICY);
    assert_ne!(
        ErrorCode::NO_SUCH_WEBSITE_CONFIGURATION,
        ErrorCode::NO_SUCH_PUBLIC_ACCESS_BLOCK_CONFIGURATION
    );

    // The six reads whose unconfigured answer is a 200. A code here would turn "acceleration is
    // off" into "this bucket is missing something", which is what a client's error branch reads.
    for (name, code) in [
        (
            "GetBucketAccelerateConfiguration",
            dto::GetBucketAccelerateConfiguration::spec().not_configured_error.clone(),
        ),
        ("GetBucketLogging", dto::GetBucketLogging::spec().not_configured_error.clone()),
        (
            "GetBucketNotificationConfiguration",
            dto::GetBucketNotificationConfiguration::spec().not_configured_error.clone(),
        ),
        (
            "GetBucketRequestPayment",
            dto::GetBucketRequestPayment::spec().not_configured_error.clone(),
        ),
        ("GetBucketVersioning", dto::GetBucketVersioning::spec().not_configured_error.clone()),
        // The writes and deletes, which have no unconfigured answer of any kind.
        ("PutBucketVersioning", dto::PutBucketVersioning::spec().not_configured_error.clone()),
        ("PutBucketWebsite", dto::PutBucketWebsite::spec().not_configured_error.clone()),
        ("DeleteBucketWebsite", dto::DeleteBucketWebsite::spec().not_configured_error.clone()),
        ("PutBucketPolicy", dto::PutBucketPolicy::spec().not_configured_error.clone()),
        ("DeleteBucketPolicy", dto::DeleteBucketPolicy::spec().not_configured_error.clone()),
        ("PutPublicAccessBlock", dto::PutPublicAccessBlock::spec().not_configured_error.clone()),
        (
            "DeletePublicAccessBlock",
            dto::DeletePublicAccessBlock::spec().not_configured_error.clone(),
        ),
        (
            "PutBucketAccelerateConfiguration",
            dto::PutBucketAccelerateConfiguration::spec().not_configured_error.clone(),
        ),
        ("PutBucketLogging", dto::PutBucketLogging::spec().not_configured_error.clone()),
        (
            "PutBucketNotificationConfiguration",
            dto::PutBucketNotificationConfiguration::spec().not_configured_error.clone(),
        ),
        (
            "PutBucketRequestPayment",
            dto::PutBucketRequestPayment::spec().not_configured_error.clone(),
        ),
    ] {
        assert!(code.is_none(), "{name} must declare no unconfigured code, it declared {code:?}");
    }
}

/// The band's success statuses are declared, and the three deletes are the only 204s in it.
///
/// Worth its own assertion because the family mixes them: eight writes answer 200 while the three
/// deletes answer 204, and a delete that answered 200 with no body is a response some clients
/// treat as a truncated document.
#[test]
fn the_configuration_band_answers_204_for_its_three_deletes_and_200_for_everything_else() {
    use rustfs_gateway_core::op::Operation;
    use rustfs_gateway_types::dto;

    for (name, status) in [
        ("DeleteBucketWebsite", dto::DeleteBucketWebsite::spec().success_status),
        ("DeleteBucketPolicy", dto::DeleteBucketPolicy::spec().success_status),
        ("DeletePublicAccessBlock", dto::DeletePublicAccessBlock::spec().success_status),
    ] {
        assert_eq!(status, 204, "{name}");
    }
    for (name, status) in [
        ("PutBucketVersioning", dto::PutBucketVersioning::spec().success_status),
        ("PutBucketWebsite", dto::PutBucketWebsite::spec().success_status),
        ("PutBucketPolicy", dto::PutBucketPolicy::spec().success_status),
        ("PutPublicAccessBlock", dto::PutPublicAccessBlock::spec().success_status),
        ("GetBucketPolicy", dto::GetBucketPolicy::spec().success_status),
        ("GetBucketVersioning", dto::GetBucketVersioning::spec().success_status),
    ] {
        assert_eq!(status, 200, "{name}");
    }
}

/// A parameter check without a route never runs: the order of the three questions is fixed.
#[test]
fn a_request_that_does_not_route_never_reaches_parameter_validation() {
    let router = full_router();
    // `POST` is not in the table at all, so no operation — and therefore no parameter — applies.
    let error = router
        .dispatch(&Req::new("POST /bucket?analytics").parts())
        .expect_err("no route");
    assert_eq!(error.message(), NO_ROUTE_MESSAGE);
    assert_ne!(*error.code(), ErrorCode::INVALID_ARGUMENT);
}

/// Negative — an unhandled ACL request is refused by name, on both targets and both methods.
///
/// Three of the four had a *wrong answer* rather than no answer while they were deferred, and
/// the registry here is the shape that produced it: a deployment that handles the listing, the
/// object read and the object write and nothing else. `GET /b?acl` fell through to `ListObjects`,
/// `GET /b/k?acl` to `GetObject` and `PUT /b/k?acl` to `PutObject` — the three debt-register
/// lines this family retires — so each must now come back as the second `501` naming the ACL
/// operation the request asked for.
#[test]
fn n_an_unhandled_acl_request_is_refused_rather_than_answered_by_its_neighbour() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    registry.register(&GET_OBJECT).expect("a registrable spec");
    registry.register(&PUT_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, expected) in [
        ("GET /bucket?acl", "GetBucketAcl"),
        ("PUT /bucket?acl", "PutBucketAcl"),
        ("GET /bucket/key?acl", "GetObjectAcl"),
        ("PUT /bucket/key?acl", "PutObjectAcl"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry handles no ACL operation");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected), "{line} must name the operation it asked for");
    }

    // And the neighbours are still served, so the refusals above are not a blanket one — a
    // router that had stopped dispatching anything would satisfy the loop alone.
    for (line, expected) in [
        ("GET /bucket", "ListObjects"),
        ("GET /bucket/key", "GetObject"),
        ("PUT /bucket/key", "PutObject"),
    ] {
        let dispatch = router
            .dispatch(&Req::new(line).parts())
            .unwrap_or_else(|_| panic!("{line} routed"));
        assert_eq!(dispatch.entry.op_name, expected, "{line}");
    }
}

/// All four ACL operations declare **no** unconfigured error, which is what makes this family
/// different from every other subresource in the table.
///
/// The declaration is what a backend outside this workspace reads to learn which 404 an
/// unconfigured resource owes, and here the answer is "none, because there is no such state".
/// Asserted against the neighbours rather than alone: a spec field stuck on `None` would satisfy
/// the ACL half by itself, so the two reads that *do* declare one are checked in the same test.
#[test]
fn the_acl_reads_declare_no_unconfigured_code_where_their_neighbours_do() {
    use rustfs_gateway_core::op::Operation;
    for (name, code) in [
        (
            "GetBucketAcl",
            rustfs_gateway_types::dto::GetBucketAcl::spec().not_configured_error.clone(),
        ),
        (
            "PutBucketAcl",
            rustfs_gateway_types::dto::PutBucketAcl::spec().not_configured_error.clone(),
        ),
        (
            "GetObjectAcl",
            rustfs_gateway_types::dto::GetObjectAcl::spec().not_configured_error.clone(),
        ),
        (
            "PutObjectAcl",
            rustfs_gateway_types::dto::PutObjectAcl::spec().not_configured_error.clone(),
        ),
    ] {
        assert!(
            code.is_none(),
            "{name}: an ACL always exists, so there is no unconfigured answer to declare"
        );
    }
    // The control: the two subresource reads either side of the object ACL row in the table do
    // declare one, so "every read declares None" is not what this is measuring.
    assert_eq!(
        rustfs_gateway_types::dto::GetObjectRetention::spec()
            .not_configured_error
            .clone()
            .expect("the retention read declares one"),
        ErrorCode::NO_SUCH_OBJECT_LOCK_CONFIGURATION
    );
    assert_eq!(
        rustfs_gateway_types::dto::GetBucketTagging::spec()
            .not_configured_error
            .clone()
            .expect("the bucket tagging read declares one"),
        ErrorCode::NO_SUCH_TAG_SET
    );
}

/// The four ACL operations declare the authorisation actions and resource shapes AWS documents.
///
/// A backend reads these to build its policy check, and a bucket action asked about an object
/// resource — or an object action about a bucket — is a policy evaluated against the wrong ARN,
/// which is a check that passes for the wrong reason.
#[test]
fn the_acl_operations_declare_their_own_actions_and_resource_shapes() {
    use rustfs_gateway_core::op::Operation;
    for (name, spec, action, shape) in [
        (
            "GetBucketAcl",
            rustfs_gateway_types::dto::GetBucketAcl::spec(),
            "s3:GetBucketAcl",
            ResourceShape::Bucket,
        ),
        (
            "PutBucketAcl",
            rustfs_gateway_types::dto::PutBucketAcl::spec(),
            "s3:PutBucketAcl",
            ResourceShape::Bucket,
        ),
        (
            "GetObjectAcl",
            rustfs_gateway_types::dto::GetObjectAcl::spec(),
            "s3:GetObjectAcl",
            ResourceShape::Object,
        ),
        (
            "PutObjectAcl",
            rustfs_gateway_types::dto::PutObjectAcl::spec(),
            "s3:PutObjectAcl",
            ResourceShape::Object,
        ),
    ] {
        let auth = spec.auth.as_ref().unwrap_or_else(|| panic!("{name} declares an action"));
        assert_eq!(auth.action, action, "{name}");
        assert_eq!(auth.resource, shape, "{name}");
        assert_eq!(spec.success_status, 200, "{name}");
        assert!(spec.required_params.is_empty(), "{name}: ?acl is a discriminator, not a parameter");
    }
}

/// An unhandled rename is refused by name instead of being dispatched as PutObject.
#[test]
fn n_unhandled_rename_object_is_refused_instead_of_dispatched_as_put_object() {
    let mut registry = Registry::new();
    registry.register(&PUT_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let error = router
        .dispatch(&Req::new("PUT /bucket/key?renameObject").parts())
        .expect_err("this registry has no RenameObject handler");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("RenameObject"));

    let plain = router
        .dispatch(&Req::new("PUT /bucket/key").parts())
        .expect("the registered PutObject neighbour remains served");
    assert_eq!(plain.entry.op_name, "PutObject");
}

/// An unhandled annotation deletion is refused by name instead of deleting the parent object.
#[test]
fn n_unhandled_delete_object_annotation_is_refused_instead_of_deleting_the_object() {
    let mut registry = Registry::new();
    registry.register(&DELETE_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let error = router
        .dispatch(&Req::new("DELETE /bucket/key?annotation&annotationName=name").parts())
        .expect_err("this registry has no DeleteObjectAnnotation handler");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("DeleteObjectAnnotation"));

    let plain = router
        .dispatch(&Req::new("DELETE /bucket/key").parts())
        .expect("the registered DeleteObject neighbour remains served");
    assert_eq!(plain.entry.op_name, "DeleteObject");
}

/// Unhandled annotation reads are refused by name instead of returning the parent object body.
#[test]
fn n_unhandled_object_annotation_reads_are_refused_instead_of_dispatching_get_object() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, operation) in [
        ("GET /bucket/key?annotation&annotationName=name", "GetObjectAnnotation"),
        ("GET /bucket/key?annotation", "ListObjectAnnotations"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("this registry has no object-annotation read handler");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(operation), "{line}");
    }

    let plain = router
        .dispatch(&Req::new("GET /bucket/key").parts())
        .expect("the registered GetObject neighbour remains served");
    assert_eq!(plain.entry.op_name, "GetObject");
}

/// An unhandled torrent read is refused by name instead of returning the parent object body.
#[test]
fn n_unhandled_get_object_torrent_is_refused_instead_of_dispatching_get_object() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let error = router
        .dispatch(&Req::new("GET /bucket/key?torrent").parts())
        .expect_err("this registry has no GetObjectTorrent handler");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("GetObjectTorrent"));

    let plain = router
        .dispatch(&Req::new("GET /bucket/key").parts())
        .expect("the registered GetObject neighbour remains served");
    assert_eq!(plain.entry.op_name, "GetObject");
}

/// An unhandled ownership-controls read is refused by name instead of returning listed keys.
#[test]
fn n_unhandled_get_bucket_ownership_controls_is_refused_instead_of_dispatching_list_objects() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let error = router
        .dispatch(&Req::new("GET /bucket?ownershipControls").parts())
        .expect_err("this registry has no GetBucketOwnershipControls handler");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("GetBucketOwnershipControls"));

    let plain = router
        .dispatch(&Req::new("GET /bucket").parts())
        .expect("the registered ListObjects neighbour remains served");
    assert_eq!(plain.entry.op_name, "ListObjects");
}

/// Unhandled intelligent-tiering reads are refused by name instead of returning listed keys.
#[test]
fn n_unhandled_intelligent_tiering_reads_are_refused_instead_of_dispatching_list_objects() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    for (line, operation) in [
        ("GET /bucket?intelligent-tiering&id=archive", "GetBucketIntelligentTieringConfiguration"),
        ("GET /bucket?intelligent-tiering", "ListBucketIntelligentTieringConfigurations"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("the intelligent-tiering handler is absent");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(operation), "{line}");
    }

    let plain = router
        .dispatch(&Req::new("GET /bucket").parts())
        .expect("the registered ListObjects neighbour remains served");
    assert_eq!(plain.entry.op_name, "ListObjects");
}

/// An unhandled ABAC status read is refused by name instead of returning listed keys.
#[test]
fn n_unhandled_get_bucket_abac_is_refused_instead_of_dispatching_list_objects() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");

    let error = router
        .dispatch(&Req::new("GET /bucket?abac").parts())
        .expect_err("this registry has no GetBucketAbac handler");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("GetBucketAbac"));

    let plain = router
        .dispatch(&Req::new("GET /bucket").parts())
        .expect("the registered ListObjects neighbour remains served");
    assert_eq!(plain.entry.op_name, "ListObjects");
}

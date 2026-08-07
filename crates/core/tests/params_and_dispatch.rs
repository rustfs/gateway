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

mod support;

use http::{Method, StatusCode};
use rustfs_gateway_core::dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE, Router};
use rustfs_gateway_core::error::{PRE_AUTH_STATUSES, PreAuthError};
use rustfs_gateway_core::op::{AuthRequirement, ResourceShape};
use rustfs_gateway_core::registry::{OperationSpec, ParamKind, Registry, RegistryError, RequiredParam};
use rustfs_gateway_core::route::{Predicate, RouteTable, ShadowingDecls, ShadowingPolicy, TargetKind};
use rustfs_gateway_types::ErrorCode;
use support::{Req, entry};

static PUT_ANALYTICS: OperationSpec = OperationSpec {
    name: "PutBucketAnalyticsConfiguration",
    success_status: 200,
    required_params: &[RequiredParam {
        kind: ParamKind::Query,
        name: "id",
        missing_error: ErrorCode::INVALID_ARGUMENT,
        message: "The required parameter 'id' is missing",
    }],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutAnalyticsConfiguration", ResourceShape::Bucket)),
};

static GET_OBJECT: OperationSpec = OperationSpec {
    name: "GetObject",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetObject", ResourceShape::Object)),
};

static DELETE_OBJECT: OperationSpec = OperationSpec {
    name: "DeleteObject",
    success_status: 204,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:DeleteObject", ResourceShape::Object)),
};

static LIST_OBJECTS: OperationSpec = OperationSpec {
    name: "ListObjects",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket)),
};

static GET_LIFECYCLE: OperationSpec = OperationSpec {
    name: "GetBucketLifecycleConfiguration",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION),
    auth: Some(AuthRequirement::new("s3:GetLifecycleConfiguration", ResourceShape::Bucket)),
};

static COPY_OBJECT: OperationSpec = OperationSpec {
    name: "CopyObject",
    success_status: 200,
    required_params: &[RequiredParam {
        kind: ParamKind::Header,
        name: "x-amz-copy-source",
        missing_error: ErrorCode::INVALID_ARGUMENT,
        message: "The required header 'x-amz-copy-source' is missing",
    }],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutObject", ResourceShape::Object)),
};

/// Deliberately unregistrable, and kept for the test that says so.
///
/// `MissingContentLength` is a good S3 code and a bad pre-authentication one: it maps to `411`,
/// which is outside the closed set. That is not a gap in the set — a missing `Content-Length` is a
/// framing fact the acceptance layer already refuses, long before an operation is known — but the
/// only way to be sure the closed set is enforced rather than described is to try to break it.
static UPLOAD_PART: OperationSpec = OperationSpec {
    name: "UploadPart",
    success_status: 200,
    required_params: &[RequiredParam {
        kind: ParamKind::Header,
        name: "content-length",
        missing_error: ErrorCode::MISSING_CONTENT_LENGTH,
        message: "The request is missing a Content-Length header",
    }],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutObject", ResourceShape::Object)),
};

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

/// The unrouted message must be actionable: the usual cause is an unconfigured vhost domain.
#[test]
fn the_unrouted_message_says_what_to_check() {
    assert!(
        NO_ROUTE_MESSAGE.contains("virtual host"),
        "a bare 'not implemented' sends the operator looking for a missing feature"
    );
}

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

/// A code with no table row falls back to `400`, never to a server error.
#[test]
fn an_unknown_code_falls_back_to_400_not_500() {
    let code = ErrorCode::custom("SomethingNobodyModelled");
    assert!(!code.is_known());
    assert_eq!(code.default_status(), StatusCode::BAD_REQUEST);
    let error = PreAuthError::with_code(code, "static").expect("400 is reachable before authentication");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
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
/// `PUT /b?acl` must not create a bucket and `DELETE /b?policy` must not delete one, whether or
/// not the lifecycle family is registered. The served subresources (`cors`, `tagging`) are the
/// same rule with a different observable and are asserted with their own rows in
/// `route_table.rs`.
#[test]
fn n_a_bucket_subresource_write_is_a_route_miss_not_a_lifecycle_operation() {
    let mut registry = Registry::new();
    registry.register(&GET_OBJECT).expect("a registrable spec");
    let router = Router::from_generated(registry).expect("the generated table builds");
    for line in [
        "PUT /bucket?acl",
        "DELETE /bucket?policy",
        "PUT /bucket?versioning",
        "DELETE /bucket?website",
    ] {
        let error = router.dispatch(&Req::new(line).parts()).expect_err("no route");
        assert_eq!(error.message(), NO_ROUTE_MESSAGE, "{line}");
        assert_eq!(error.operation(), None, "{line} names no operation because none claimed it");
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

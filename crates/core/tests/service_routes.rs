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

//! Explicit service routing and its separation from the default S3 table.
//!
//! Responsible for: shallow claims, exact action routes, and service-bound assembly refusals.
//! NOT responsible for: signature verification or response serialization.
//! Upstream: dialect and router builders. Downstream: facade service routing tests.

use crate::support;

use std::sync::Arc;

use http::Method;
use rustfs_gateway_core::{
    AuthRequirement, BuildError, ClaimedRoute, ClaimedRow, Dialect, DialectError, DialectOverlay, DialectRoute, Handler,
    HandlerDeadlineClass, HandlerResult, NoDerived, Operation, OperationSpec, OverlayRow, PathClaim, Predicate, Req,
    ResourceShape, Resp, RouterBuilder,
};
use rustfs_gateway_sig::{OperationFloor, SigService};

const SERVICE: SigService = SigService::Sts;
const NAMES: [&str; 3] = ["example:PutVectors", "example:ListTags", "example:Anonymous"];
const EVIDENCE: &[&str] = &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_ListTagsForResource.html"];
const TAGS: PathClaim = PathClaim {
    prefix: "/tags",
    reason: "This separately assembled signing service owns its tag resource path.",
    evidence: EVIDENCE,
};
const ACTION: &[Predicate] = &[Predicate::Method(Method::POST), Predicate::PathLiteral("/PutVectors")];
const TAG_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/tags/{+resource_arn}",
    selector: &[Predicate::Method(Method::GET)],
}];

struct TestOperation<const N: usize>;

const fn spec(name: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .auth(AuthRequirement::new("example:Read", ResourceShape::Service))
        .build()
}

static SPECS: [OperationSpec; 3] = [spec(NAMES[0]), spec(NAMES[1]), spec(NAMES[2])];
static FLOORS: [OperationFloor; 3] = [
    OperationFloor::custom(NAMES[0], SERVICE).require_sigv4_under_every_policy(),
    OperationFloor::custom(NAMES[1], SERVICE).require_sigv4_under_every_policy(),
    OperationFloor::custom(NAMES[2], SERVICE).allow_anonymous_after_listing_in_the_posture_report(),
];

impl<const N: usize> Operation for TestOperation<N> {
    const NAME: &'static str = NAMES[N];
    type Input = ();
    type Output = ();
    type DerivedResources = NoDerived;

    fn derive_resources(_: &Self::Input) -> Result<NoDerived, rustfs_gateway_core::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPECS[N]
    }

    fn floor() -> &'static OperationFloor {
        &FLOORS[N]
    }
}

struct Backend;

impl<const N: usize> Handler<TestOperation<N>> for Backend {
    async fn call(&self, _: Req<TestOperation<N>>) -> HandlerResult<TestOperation<N>> {
        Ok(Resp::new(()))
    }
}

fn overlay<const N: usize>(claimed: bool) -> &'static DialectOverlay {
    let selector = if claimed {
        rustfs_gateway_core::dialect::render_claimed_rows(TAG_ROWS)
    } else {
        "Method(POST) ∧ PathLiteral(\"/PutVectors\")".to_owned()
    };
    Box::leak(Box::new(DialectOverlay {
        name: "service-routing-test",
        vendor: "example",
        claims: if claimed { &[TAGS] } else { &[] },
        operations: Box::leak(
            vec![OverlayRow {
                name: NAMES[N],
                precedence: 50,
                selector: Box::leak(selector.into_boxed_str()),
                action: "example:Read",
                resource: ResourceShape::Service,
                success_status: 200,
                anonymous: N == 2,
                evidence: EVIDENCE,
            }]
            .into_boxed_slice(),
        ),
    }))
}

fn action<const N: usize>(service: Option<SigService>) -> Result<Dialect, Vec<DialectError>> {
    let record = overlay::<N>(false);
    let builder = match service {
        Some(service) => Dialect::assemble_for_service(record, service),
        None => Dialect::assemble(record),
    };
    builder
        .declare::<TestOperation<N>>(DialectRoute {
            precedence: 50,
            selector: ACTION,
            path_shape: "/PutVectors",
            shadows: &[],
        })
        .build()
}

fn tags(service: Option<SigService>) -> Result<Dialect, Vec<DialectError>> {
    let record = overlay::<1>(true);
    let builder = match service {
        Some(service) => Dialect::assemble_for_service(record, service),
        None => Dialect::assemble(record),
    };
    builder
        .declare_claimed::<TestOperation<1>>(ClaimedRoute {
            precedence: 50,
            rows: TAG_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .build()
}

#[test]
fn service_routes_preserve_action_case_and_opaque_tag_parameters() {
    let router = RouterBuilder::for_service(SERVICE)
        .dialect(&action::<0>(Some(SERVICE)).expect("matching action"))
        .dialect(&tags(Some(SERVICE)).expect("matching tags"))
        .handle_without_codec::<TestOperation<0>, _>(Arc::new(Backend))
        .handle_without_codec::<TestOperation<1>, _>(Arc::new(Backend))
        .build()
        .expect("service routes assemble");
    let action = support::Req::new("POST /PutVectors");
    assert_eq!(router.dispatch(&action.parts()).expect("action routes").spec.name, NAMES[0]);
    let request = support::Req::new("GET /tags/arn%3Aaws%3As3vectors%3Aus-east-1%3A%3Abucket%2Fvectors?tagKeys=a&tagKeys=b");
    let dispatched = router.dispatch(&request.parts()).expect("tags route");
    let claimed = dispatched.claimed.expect("the tag route retains its claim");
    let values = claimed.template().extract(request.parts().path).expect("opaque ARN");
    assert_eq!(values.get("resource_arn"), Some("arn:aws:s3vectors:us-east-1::bucket/vectors"));
}

#[test]
fn service_routes_never_fall_back_to_s3() {
    let router = RouterBuilder::for_service(SERVICE)
        .dialect(&action::<0>(Some(SERVICE)).expect("matching action"))
        .dialect(&tags(Some(SERVICE)).expect("matching tags"))
        .build()
        .expect("route-only service");
    for request in [
        "GET /",
        "GET /bucket/object",
        "POST /putvectors",
        "GET /PutVectors",
        "DELETE /tags/object",
        "GET /tags",
        "GET /tagstone/object",
    ] {
        let request = support::Req::new(request);
        assert!(
            router.resolve(&request.parts()).is_none(),
            "unexpected fallback for {}",
            request.parts().path
        );
    }
}

#[test]
fn default_s3_keeps_the_tags_bucket_and_rejects_its_shallow_claim() {
    let router = RouterBuilder::new().build().expect("default S3");
    let request = support::Req::new("GET /tags/object");
    assert_eq!(router.resolve(&request.parts()).expect("S3 object").op_name, "GetObject");
    assert!(tags(None).is_err());
}

#[test]
fn a_service_dialect_cannot_be_installed_in_the_default_router() {
    let dialect = tags(Some(SERVICE)).expect("service tags");
    assert!(matches!(
        RouterBuilder::new().dialect(&dialect).build(),
        Err(BuildError::DialectServiceMismatch {
            expected: None,
            actual: Some(SERVICE),
            ..
        })
    ));
}

#[test]
fn a_service_router_refuses_unscoped_and_other_service_dialects() {
    let unscoped = action::<0>(None).expect("ordinary action declaration");
    assert!(matches!(
        RouterBuilder::for_service(SERVICE).dialect(&unscoped).build(),
        Err(BuildError::DialectServiceMismatch {
            expected: Some(SERVICE),
            actual: None,
            ..
        })
    ));
    let scoped = action::<0>(Some(SERVICE)).expect("scoped action declaration");
    assert!(matches!(
        RouterBuilder::for_service(SigService::S3).dialect(&scoped).build(),
        Err(BuildError::DialectServiceMismatch {
            expected: Some(SigService::S3),
            actual: Some(SERVICE),
            ..
        })
    ));
}

#[test]
fn service_operation_floors_must_match_and_require_signatures() {
    assert!(matches!(action::<0>(Some(SigService::S3)), Err(errors)
        if errors.iter().any(|error| matches!(error, DialectError::SigningServiceMismatch { .. }))));
    assert!(matches!(action::<2>(Some(SERVICE)), Err(errors)
        if errors.iter().any(|error| matches!(error, DialectError::ServiceRequiresSigV4 { .. }))));
    assert!(matches!(
        RouterBuilder::for_service(SigService::S3)
            .handle_without_codec::<TestOperation<0>, _>(Arc::new(Backend))
            .build(),
        Err(BuildError::OperationServiceMismatch { .. })
    ));
    assert!(matches!(
        RouterBuilder::for_service(SERVICE)
            .handle_without_codec::<TestOperation<2>, _>(Arc::new(Backend))
            .build(),
        Err(BuildError::ServiceRequiresSigV4 { .. })
    ));
}

#[test]
fn a_service_handler_requires_an_explicit_dialect_route() {
    assert!(matches!(
        RouterBuilder::for_service(SERVICE)
            .handle_without_codec::<TestOperation<0>, _>(Arc::new(Backend))
            .build(),
        Err(BuildError::UnverifiedCodecRoute { .. })
    ));
}

#[test]
fn n_service_router_under_rustfs_legacy_selection_never_falls_into_s3_selection() {
    let router = RouterBuilder::for_service(SERVICE)
        .selecting(rustfs_gateway_core::route::Selection::RustfsLegacy)
        .dialect(&action::<0>(Some(SERVICE)).expect("matching action"))
        .dialect(&tags(Some(SERVICE)).expect("matching tags"))
        .handle_without_codec::<TestOperation<0>, _>(Arc::new(Backend))
        .handle_without_codec::<TestOperation<1>, _>(Arc::new(Backend))
        .build()
        .expect("service routes assemble");
    let post = support::Req::new("POST /PutVectors");
    assert_eq!(router.dispatch(&post.parts()).expect("declared action routes").spec.name, NAMES[0]);
    let with_x_id = support::Req::new("POST /PutVectors?x-id=PutObject");
    assert_eq!(
        router
            .dispatch(&with_x_id.parts())
            .expect("x-id does not hijack service route")
            .spec
            .name,
        NAMES[0]
    );
    let unknown_x_id = support::Req::new("GET /bucket/object?x-id=GetObject");
    let err = router.dispatch(&unknown_x_id.parts()).expect_err("no S3 fallback");
    assert_eq!(err.code(), &rustfs_gateway_types::ErrorCode::NOT_IMPLEMENTED);
}

#[test]
fn service_claimed_route_matches_even_when_host_named_bucket_is_set() {
    let router = RouterBuilder::for_service(SERVICE)
        .dialect(&tags(Some(SERVICE)).expect("matching tags"))
        .handle_without_codec::<TestOperation<1>, _>(Arc::new(Backend))
        .build()
        .expect("service routes assemble");
    let request = support::Req::new("GET /tags/arn%3Aaws%3As3vectors%3Aus-east-1%3A%3Abucket%2Fvectors");
    let mut parts = request.parts();
    parts.host_named_bucket = true;
    assert_eq!(router.dispatch(&parts).expect("claimed route matches on vhost").spec.name, NAMES[1]);
}

#[test]
fn n_s3_claimed_route_still_returns_outside_when_host_named_bucket_is_set() {
    use rustfs_gateway_core::route::{ClaimLookup, ClaimedTable, InstalledClaim, ShadowingDecls};
    let table = ClaimedTable::build(
        vec![InstalledClaim {
            dialect: "fixture",
            claim: PathClaim {
                prefix: "/_admin/v1",
                reason: "fixture claim for S3 host-named-bucket control",
                evidence: EVIDENCE,
            },
        }],
        Vec::new(),
        &ShadowingDecls::NONE,
    )
    .expect("valid S3 claim");
    let request = support::Req::new("GET /_admin/v1/info");
    let mut parts = request.parts();
    parts.host_named_bucket = true;
    assert!(matches!(table.lookup(&parts), ClaimLookup::Outside));
}

#[test]
fn n_non_s3_service_unknown_and_unregistered_routes_omit_s3_prose() {
    let router = RouterBuilder::for_service(SERVICE)
        .dialect(&action::<0>(Some(SERVICE)).expect("matching action"))
        .build()
        .expect("route-only service");

    let unknown = support::Req::new("POST /UnknownAction");
    let err = router.dispatch(&unknown.parts()).expect_err("unknown route");
    assert!(!err.message().contains("S3"), "unexpected S3 prose: {}", err.message());
    assert!(!err.message().contains("virtual host"), "unexpected vhost prose: {}", err.message());
    assert!(!err.message().contains("bucket"), "unexpected bucket prose: {}", err.message());

    let unhandled = support::Req::new("POST /PutVectors");
    let err = router.dispatch(&unhandled.parts()).expect_err("unhandled route");
    assert!(!err.message().contains("S3"), "unexpected S3 prose: {}", err.message());
}

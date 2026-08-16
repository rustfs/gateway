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

//! What a dialect may add to this gateway, and every shape of addition it refuses.
//!
//! Responsible for: the worked example end to end — a vendor operation that routes to its own
//! handler while its standard sibling keeps routing to the standard one — and one test per refusal
//! the assembly makes, each pinned to the specific error rather than to "assembly failed".
//! NOT responsible for: the registration rules themselves (`registration.rs` owns the name,
//! action, spec and floor rules on their own), route overlap as a property of the table
//! (`route_table.rs`), or the wire (a dialect operation has no generated codec, so it registers
//! through `handle_without_codec`).
//! Upstream: `support`. Downstream: nothing.
//!
//! # Why every mismatch is its own test
//!
//! The overlay is a second statement of what the code already says. Its whole value is that a
//! disagreement is a refusal, so a test that only proved "some error came back" would pass with
//! every field cross-check deleted but one. Each test below names the variant, so deleting one
//! check turns exactly one test red.

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::Method;
use rustfs_gateway_core::dialect::{Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::dispatch::RouterBuildError;
use rustfs_gateway_core::handler::{Handler, HandlerResult, Req, Resp};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{BuildError, HandlerDeadlineClass, OperationSpec, RegistryError, RouterBuilder};
use rustfs_gateway_core::route::{HostClass, Predicate, RouteBuildError, ShadowingDecl, TargetKind};
use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::HeadObject;
use support::{Req as RouteReq, block_on};

// ── the worked example ───────────────────────────────────────────────────────────────────────
//
// `HEAD /{bucket}/{key}?acme-report` is a vendor operation AWS does not define. It is the smallest
// shape that is not vacuous: `HEAD` on an object target has exactly one standard row (`HeadObject`,
// precedence 950), so the dialect row overlaps exactly one operation and therefore needs exactly
// one shadowing declaration. Every other method-and-target cell in the table holds between two and
// a dozen rows, and a dialect row there needs a declaration per pair.

/// The vendor operation the example registers.
struct HeadObjectReport;

static REPORT_SPEC: OperationSpec = OperationSpec::builder("acme:HeadObjectReport", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Object))
    .build();

static REPORT_FLOOR: OperationFloor = OperationFloor::custom("acme:HeadObjectReport", SigService::S3);

impl Operation for HeadObjectReport {
    const NAME: &'static str = "acme:HeadObjectReport";
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &REPORT_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &REPORT_FLOOR
    }
}

/// The precedence the example places the row at: inside the object subresource band, ahead of the
/// `HeadObject` row it shadows for requests carrying the vendor key.
const REPORT_PRECEDENCE: u16 = 505;

/// The routing conjunction, as the code states it.
static REPORT_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::HEAD),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent("acme-report"),
];

/// The one overlap the row has, declared with a reason and a source.
static REPORT_SHADOWS: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "acme:HeadObjectReport",
    shadowed: "HeadObject",
    reason: "A HEAD carrying the vendor report key asks for the report, not for the object's \
             metadata; without this order the vendor key is ignored and the answer is the object's.",
    evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html"],
}];

/// The reviewed record of the row: the same five facts, written where a reviewer reads them.
static OVERLAY: DialectOverlay = DialectOverlay {
    name: "acme",
    vendor: "acme",
    operations: &[OverlayRow {
        name: "acme:HeadObjectReport",
        precedence: REPORT_PRECEDENCE,
        selector: "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"acme-report\")",
        action: "acme:HeadObjectReport",
        resource: ResourceShape::Object,
        success_status: 200,
        anonymous: false,
        evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html"],
    }],
};

fn report_route() -> DialectRoute {
    DialectRoute {
        precedence: REPORT_PRECEDENCE,
        selector: REPORT_SELECTOR,
        path_shape: "/{Bucket}/{Key+}",
        shadows: REPORT_SHADOWS,
    }
}

// ── a backend ────────────────────────────────────────────────────────────────────────────────

/// A backend that answers the vendor operation and the standard sibling, and counts each.
#[derive(Debug, Default)]
struct Fs {
    reports: AtomicUsize,
    heads: AtomicUsize,
}

impl Fs {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl Handler<HeadObjectReport> for Fs {
    async fn call(&self, request: Req<HeadObjectReport>) -> HandlerResult<HeadObjectReport> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    async fn call_with_context(
        &self,
        _request: Req<HeadObjectReport>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> HandlerResult<HeadObjectReport> {
        self.reports.fetch_add(1, Ordering::Relaxed);
        Ok(Resp::new(()))
    }
}

impl Handler<HeadObject> for Fs {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    async fn call_with_context(
        &self,
        _request: Req<HeadObject>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> HandlerResult<HeadObject> {
        self.heads.fetch_add(1, Ordering::Relaxed);
        Ok(Resp::new(rustfs_gateway_types::dto::HeadObjectOutput::default()))
    }
}

/// The dialect the example assembles, or the reason it could not be.
fn example_dialect() -> Dialect {
    Dialect::assemble(&OVERLAY)
        .declare::<HeadObjectReport>(report_route())
        .build()
        .expect("the overlay and the declaration agree")
}

/// The first refusal of an assembly.
///
/// The first rather than the only one: refusals accumulate, and a declaration refused for one
/// reason can leave its overlay row with nothing declaring it, which is a second true statement
/// about the same mistake. The order the checks run in is what these tests pin.
fn first_dialect_error(result: Result<Dialect, Vec<DialectError>>) -> DialectError {
    let errors = result.expect_err("this assembly must be refused");
    errors.into_iter().next().expect("a refusal list is never empty")
}

// ── positive: the mechanism works end to end ─────────────────────────────────────────────────

/// Positive -- the vendor request reaches the vendor handler, through the ordinary router.
#[test]
fn a_declared_dialect_operation_reaches_its_own_handler() {
    let fs = Fs::new();
    let router = RouterBuilder::new()
        .handle::<HeadObject, _>(Arc::clone(&fs))
        .handle_without_codec::<HeadObjectReport, _>(Arc::clone(&fs))
        .dialect(&example_dialect())
        .build()
        .expect("a declared dialect operation is registrable");

    let request = RouteReq::new("HEAD /bucket/key?acme-report");
    let dispatch = router.dispatch(&request.parts()).expect("the vendor row wins");
    assert_eq!(dispatch.spec.name, "acme:HeadObjectReport");
    assert_eq!(dispatch.entry.precedence, REPORT_PRECEDENCE);

    let answer = block_on(
        router
            .registry()
            .authorize_and_invoke_no_derived::<HeadObjectReport>(())
            .expect("input authorization succeeds")
            .expect("registered"),
    );
    assert!(answer.is_ok());
    assert_eq!(fs.reports.load(Ordering::Relaxed), 1);
    assert_eq!(fs.heads.load(Ordering::Relaxed), 0, "the sibling's handler was not the one called");
}

/// Positive -- the sibling shape still reaches the standard operation, unchanged.
///
/// The other half of the previous test: a dialect row that swallowed `HEAD /bucket/key` would pass
/// every assertion above and break every S3 client.
#[test]
fn the_standard_sibling_shape_still_reaches_the_standard_operation() {
    let fs = Fs::new();
    let router = RouterBuilder::new()
        .handle::<HeadObject, _>(Arc::clone(&fs))
        .handle_without_codec::<HeadObjectReport, _>(Arc::clone(&fs))
        .dialect(&example_dialect())
        .build()
        .expect("a declared dialect operation is registrable");

    let request = RouteReq::new("HEAD /bucket/key");
    let dispatch = router.dispatch(&request.parts()).expect("the standard row wins");
    assert_eq!(dispatch.spec.name, "HeadObject");
}

/// Positive -- a dialect names what it added, so a start-up report can print it.
#[test]
fn a_dialect_names_the_operations_it_contributes() {
    let dialect = example_dialect();
    assert_eq!(dialect.name(), "acme");
    assert_eq!(dialect.operation_names().collect::<Vec<_>>(), vec!["acme:HeadObjectReport"]);
}

// ── negative: the registration rules, reached through a dialect ───────────────────────────────

/// Declares one badly named or badly specified vendor operation after another.
///
/// A macro rather than a dozen near-identical blocks: each case differs in one constant, and a
/// dozen hand-copied blocks is where a test starts asserting the wrong thing about the wrong one.
macro_rules! vendor_operation {
    (
        $ident:ident,
        name = $name:expr,
        spec_name = $spec_name:expr,
        action = $action:expr,
        resource = $resource:expr,
        status = $status:expr,
        anonymous = $anonymous:expr
    ) => {
        struct $ident;

        const _: () = {
            static SPEC: OperationSpec = match $action {
                Some(auth) => OperationSpec::builder($spec_name, $status, None)
                    .handler_deadline_class(HandlerDeadlineClass::Standard)
                    .auth(auth)
                    .build(),
                None => OperationSpec::builder($spec_name, $status, None)
                    .handler_deadline_class(HandlerDeadlineClass::Standard)
                    .build(),
            };
            static FLOOR: OperationFloor = if $anonymous {
                OperationFloor::custom($name, SigService::S3).allow_anonymous_after_listing_in_the_posture_report()
            } else {
                OperationFloor::custom($name, SigService::S3)
            };

            impl Operation for $ident {
                const NAME: &'static str = $name;
                type Input = ();
                type Output = ();
                type DerivedResources = rustfs_gateway_core::NoDerived;

                fn derive_resources(
                    _input: &Self::Input,
                ) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
                    Ok(rustfs_gateway_core::NoDerived)
                }

                fn seal_derived_input(_input: &mut Self::Input) {}

                fn spec() -> &'static OperationSpec {
                    &SPEC
                }

                fn floor() -> &'static OperationFloor {
                    &FLOOR
                }
            }

            let _ = $resource;
        };
    };
}

vendor_operation!(
    NoNamespace,
    name = "HeadObjectReportish",
    spec_name = "HeadObjectReportish",
    action = Some(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Object)),
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    ExactAwsName,
    name = "HeadObject",
    spec_name = "HeadObject",
    action = Some(AuthRequirement::new("s3:HeadObject", ResourceShape::Object)),
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    LowercasedAwsName,
    name = "headobject",
    spec_name = "headobject",
    action = Some(AuthRequirement::new("s3:HeadObject", ResourceShape::Object)),
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    NoAction,
    name = "acme:HeadObjectReport",
    spec_name = "acme:HeadObjectReport",
    action = None,
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    OtherVendor,
    name = "other:HeadObjectReport",
    spec_name = "other:HeadObjectReport",
    action = Some(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Object)),
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    WrongStatus,
    name = "acme:HeadObjectReport",
    spec_name = "acme:HeadObjectReport",
    action = Some(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Object)),
    resource = (),
    status = 204,
    anonymous = false
);

vendor_operation!(
    WrongAction,
    name = "acme:HeadObjectReport",
    spec_name = "acme:HeadObjectReport",
    action = Some(AuthRequirement::new("acme:SomethingElse", ResourceShape::Object)),
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    WrongResource,
    name = "acme:HeadObjectReport",
    spec_name = "acme:HeadObjectReport",
    action = Some(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Bucket)),
    resource = (),
    status = 200,
    anonymous = false
);

vendor_operation!(
    AnonymouslyReachable,
    name = "acme:HeadObjectReport",
    spec_name = "acme:HeadObjectReport",
    action = Some(AuthRequirement::new("acme:HeadObjectReport", ResourceShape::Object)),
    resource = (),
    status = 200,
    anonymous = true
);

/// Negative -- a vendor operation whose name carries no namespace is refused.
///
/// R1. Without the namespace, "is this operation AWS's?" is no longer answerable from the name,
/// which is what the route table, the posture report and the audit log all do.
#[test]
fn a_dialect_operation_without_a_vendor_namespace_is_refused() {
    let result = Dialect::assemble(&OVERLAY).declare::<NoNamespace>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::Registration(RegistryError::NameNotNamespaced {
            name: "HeadObjectReportish"
        })
    );
}

/// Negative -- a vendor operation may not take an AWS operation name.
///
/// R2 / F-5: a dialect that registered `HeadObject` would stand in front of the operation every
/// client already calls, and every later reader of the registry sees the AWS name.
#[test]
fn a_dialect_operation_may_not_take_an_aws_name() {
    let result = Dialect::assemble(&OVERLAY).declare::<ExactAwsName>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::Registration(RegistryError::NameCollidesWithStandard {
            name: "HeadObject",
            standard: "HeadObject",
        })
    );
}

/// Negative -- nor a differently cased spelling of one.
///
/// `headobject` is not the AWS name, and a registry that held both would show a human two entries
/// they read as one.
#[test]
fn a_dialect_operation_may_not_take_an_aws_name_in_another_case() {
    let result = Dialect::assemble(&OVERLAY)
        .declare::<LowercasedAwsName>(report_route())
        .build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::Registration(RegistryError::NameCollidesWithStandard {
            name: "headobject",
            standard: "HeadObject",
        })
    );
}

/// Negative -- a vendor operation nobody can authorise cannot be assembled into a dialect.
///
/// R4, and the one that matters: this is rustfs/rustfs#4845 made unrepresentable at the dialect
/// boundary as well as at the registry's, so a dialect cannot be the path on which the
/// authorisation question is never asked.
#[test]
fn a_dialect_operation_with_no_action_is_refused() {
    let result = Dialect::assemble(&OVERLAY).declare::<NoAction>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::Registration(RegistryError::MissingAuthRequirement {
            name: "acme:HeadObjectReport"
        })
    );
}

// ── negative: the overlay and the code must agree ─────────────────────────────────────────────

/// Negative -- an operation whose namespace is not this dialect's vendor is refused.
///
/// Otherwise one dialect vouches for another's operations, and the overlay stops being a record of
/// what this dialect adds.
#[test]
fn an_operation_from_another_vendor_is_refused() {
    let result = Dialect::assemble(&OVERLAY).declare::<OtherVendor>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::WrongVendor {
            name: "other:HeadObjectReport",
            vendor: "acme",
        }
    );
}

/// Negative -- a declaration with no overlay row is refused.
///
/// The row is where the evidence and the reviewed precedence live. A declaration without one is an
/// operation nobody reviewed.
#[test]
fn a_declaration_with_no_overlay_row_is_refused() {
    static EMPTY: DialectOverlay = DialectOverlay {
        name: "acme",
        vendor: "acme",
        operations: &[],
    };
    let result = Dialect::assemble(&EMPTY).declare::<HeadObjectReport>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::NotInOverlay {
            name: "acme:HeadObjectReport"
        }
    );
}

/// Negative -- an overlay row nobody declared is refused.
///
/// The other direction, and the one that rots: a row left behind by a deleted operation reads as a
/// reviewed decision about behaviour that no longer exists.
#[test]
fn an_overlay_row_nobody_declared_is_refused() {
    let result = Dialect::assemble(&OVERLAY).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::DeclaredNowhere {
            name: "acme:HeadObjectReport"
        }
    );
}

/// Negative -- the same operation declared twice in one dialect is refused.
#[test]
fn an_operation_declared_twice_in_one_dialect_is_refused() {
    let result = Dialect::assemble(&OVERLAY)
        .declare::<HeadObjectReport>(report_route())
        .declare::<HeadObjectReport>(report_route())
        .build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::DeclaredTwice {
            name: "acme:HeadObjectReport"
        }
    );
}

/// Negative -- a precedence the overlay does not record is refused.
///
/// Precedence is the whole of what a dialect row can and cannot shadow, so it is the one number a
/// reviewer must see in the overlay.
#[test]
fn a_precedence_the_overlay_does_not_record_is_refused() {
    let route = DialectRoute {
        precedence: 506,
        ..report_route()
    };
    let result = Dialect::assemble(&OVERLAY).declare::<HeadObjectReport>(route).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::PrecedenceMismatch {
            name: "acme:HeadObjectReport",
            declared: 506,
            overlay: REPORT_PRECEDENCE,
        }
    );
}

/// Negative -- a selector the overlay does not record is refused.
#[test]
fn a_selector_the_overlay_does_not_record_is_refused() {
    static WIDER: &[Predicate] = &[Predicate::Method(Method::HEAD), Predicate::Target(TargetKind::Object)];
    let route = DialectRoute {
        selector: WIDER,
        ..report_route()
    };
    let error = first_dialect_error(Dialect::assemble(&OVERLAY).declare::<HeadObjectReport>(route).build());
    let DialectError::SelectorMismatch { name, declared, overlay } = error else {
        panic!("expected a selector mismatch, got {error:?}");
    };
    assert_eq!(name, "acme:HeadObjectReport");
    assert_eq!(declared, "Method(HEAD) ∧ Target(Object)");
    assert_eq!(overlay, "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"acme-report\")");
}

/// Negative -- an action the overlay does not record is refused.
#[test]
fn an_action_the_overlay_does_not_record_is_refused() {
    let result = Dialect::assemble(&OVERLAY).declare::<WrongAction>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::ActionMismatch {
            name: "acme:HeadObjectReport",
            declared: "acme:SomethingElse",
            overlay: "acme:HeadObjectReport",
        }
    );
}

/// Negative -- a resource shape the overlay does not record is refused.
///
/// The shape decides which ARN an authorizer is asked about. A bucket-shaped answer to an
/// object-shaped operation authorises the wrong thing.
#[test]
fn a_resource_shape_the_overlay_does_not_record_is_refused() {
    let result = Dialect::assemble(&OVERLAY).declare::<WrongResource>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::ResourceMismatch {
            name: "acme:HeadObjectReport",
            declared: ResourceShape::Bucket,
            overlay: ResourceShape::Object,
        }
    );
}

/// Negative -- a success status the overlay does not record is refused.
#[test]
fn a_success_status_the_overlay_does_not_record_is_refused() {
    let result = Dialect::assemble(&OVERLAY).declare::<WrongStatus>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::StatusMismatch {
            name: "acme:HeadObjectReport",
            declared: 204,
            overlay: 200,
        }
    );
}

/// Negative -- an overlay row with no evidence is refused.
///
/// An unsourced dialect row is the same defect as an unsourced shadowing declaration: a claim about
/// another implementation's wire behaviour that nobody can check.
#[test]
fn an_overlay_row_with_no_evidence_is_refused() {
    static UNSOURCED: DialectOverlay = DialectOverlay {
        name: "acme",
        vendor: "acme",
        operations: &[OverlayRow {
            name: "acme:HeadObjectReport",
            precedence: REPORT_PRECEDENCE,
            selector: "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"acme-report\")",
            action: "acme:HeadObjectReport",
            resource: ResourceShape::Object,
            success_status: 200,
            anonymous: false,
            evidence: &[],
        }],
    };
    let result = Dialect::assemble(&UNSOURCED)
        .declare::<HeadObjectReport>(report_route())
        .build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::UnsourcedOperation {
            name: "acme:HeadObjectReport"
        }
    );
}

/// Negative -- an anonymously reachable vendor operation the overlay does not acknowledge.
///
/// R5 / F-3 attack scenario A: a dialect that can quietly mount an anonymous operation lets an
/// attacker pick the authentication strength by picking the operation, which is the shape of
/// `GHSA-5qfg-mf7r-jp3w` and `GHSA-3473-5353-xhwh`. The acknowledgement is in the overlay because
/// the overlay is what a reviewer reads.
#[test]
fn an_anonymous_vendor_operation_the_overlay_does_not_acknowledge_is_refused() {
    let result = Dialect::assemble(&OVERLAY)
        .declare::<AnonymouslyReachable>(report_route())
        .build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::AnonymousNotAcknowledged {
            name: "acme:HeadObjectReport"
        }
    );
}

/// Negative -- and the acknowledgement may not outlive the floor that needed it.
///
/// The other direction. A row that still says `anonymous = true` after the floor was tightened
/// tells a reviewer the deployment has an anonymous surface it no longer has, and the next reviewer
/// stops believing the field.
#[test]
fn an_acknowledgement_for_an_operation_that_is_not_anonymous_is_refused() {
    static STALE: DialectOverlay = DialectOverlay {
        name: "acme",
        vendor: "acme",
        operations: &[OverlayRow {
            name: "acme:HeadObjectReport",
            precedence: REPORT_PRECEDENCE,
            selector: "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"acme-report\")",
            action: "acme:HeadObjectReport",
            resource: ResourceShape::Object,
            success_status: 200,
            anonymous: true,
            evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html"],
        }],
    };
    let result = Dialect::assemble(&STALE).declare::<HeadObjectReport>(report_route()).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::StaleAnonymousAcknowledgement {
            name: "acme:HeadObjectReport"
        }
    );
}

/// Negative -- a vendor operation may not claim a reserved endpoint family.
///
/// R6. S3 Express signs with a different service, Object Lambda serves a literal path that is not a
/// bucket, and the website endpoint is a second protocol on the same shapes. A dialect row on one
/// of those faces would inherit constraints nobody wrote for it.
#[test]
fn a_vendor_operation_on_a_reserved_host_class_is_refused() {
    static EXPRESS: &[Predicate] = &[
        Predicate::Method(Method::HEAD),
        Predicate::Target(TargetKind::Object),
        Predicate::QueryPresent("acme-report"),
        Predicate::HostClass(HostClass::S3Express),
    ];
    let route = DialectRoute {
        selector: EXPRESS,
        ..report_route()
    };
    let result = Dialect::assemble(&OVERLAY).declare::<HeadObjectReport>(route).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::ReservedHostClass {
            name: "acme:HeadObjectReport",
            class: HostClass::S3Express,
        }
    );
}

/// Negative -- a dialect may not declare a shadowing between two operations it did not add.
///
/// A dialect accounts for the overlaps its own row creates. A declaration naming two standard
/// operations is a dialect signing off on a routing decision in the generated table — harmless
/// today, because every standard pair is already declared, and a silent approval of a routing
/// change the moment a model upgrade introduces a pair that is not.
#[test]
fn a_dialect_may_not_declare_a_shadowing_between_two_standard_operations() {
    static FOREIGN: &[ShadowingDecl] = &[ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "ListObjects",
        reason: "Not this dialect's business.",
        evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html"],
    }];
    let result = Dialect::assemble(&OVERLAY)
        .declare::<HeadObjectReport>(DialectRoute {
            shadows: FOREIGN,
            ..report_route()
        })
        .build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::ForeignShadowing {
            dialect: "acme",
            winner: "GetBucketAcl",
            shadowed: "ListObjects",
        }
    );
}

/// Negative -- a vendor operation with an empty selector is refused.
///
/// An empty conjunction accepts every request that reaches its precedence. The route table only
/// refuses one outside the fallback band, because the fallback is where an all-matching row
/// legitimately lives; a vendor operation is never that row.
#[test]
fn a_vendor_operation_with_an_empty_selector_is_refused() {
    static NOTHING: &[Predicate] = &[];
    let route = DialectRoute {
        selector: NOTHING,
        ..report_route()
    };
    let result = Dialect::assemble(&OVERLAY).declare::<HeadObjectReport>(route).build();
    assert_eq!(
        first_dialect_error(result),
        DialectError::EmptySelector {
            name: "acme:HeadObjectReport"
        }
    );
}

// ── negative: the table's own decision, reached through a dialect ─────────────────────────────

/// Negative -- a dialect row overlapping a standard one with no declaration refuses the build.
///
/// R3 / F-5. The refusal is the route table's, not the dialect's: the same predicate-lattice
/// decision that governs the generated rows governs an added one, and it names both selectors.
#[test]
fn a_dialect_row_overlapping_a_standard_row_with_no_declaration_is_refused() {
    static UNDECLARED: &[ShadowingDecl] = &[];
    let dialect = Dialect::assemble(&OVERLAY)
        .declare::<HeadObjectReport>(DialectRoute {
            shadows: UNDECLARED,
            ..report_route()
        })
        .build()
        .expect("the overlay says nothing about shadowing, so assembly succeeds");

    let fs = Fs::new();
    let result = RouterBuilder::new()
        .handle_without_codec::<HeadObjectReport, _>(Arc::clone(&fs))
        .dialect(&dialect)
        .build();

    let Err(BuildError::Route(RouterBuildError::Route(RouteBuildError::UndeclaredShadowing { winner, shadowed, .. }))) = result
    else {
        panic!("expected undeclared shadowing, got {result:?}");
    };
    assert_eq!(winner.op_name, "acme:HeadObjectReport");
    assert_eq!(shadowed.op_name, "HeadObject");
    assert_eq!(shadowed.selector, "Method(HEAD) ∧ Target(Object)");
}

/// Negative -- moving the row behind the operation it declared it shadows refuses the build.
///
/// The precedence is not decoration. At 960 the standard row is tried first, the vendor key is
/// ignored, and the declaration now describes an order the table does not have — which the table
/// reports as a stale declaration rather than serving the wrong operation.
#[test]
fn moving_the_dialect_row_behind_the_row_it_shadows_is_refused() {
    static MOVED_OVERLAY: DialectOverlay = DialectOverlay {
        name: "acme",
        vendor: "acme",
        operations: &[OverlayRow {
            name: "acme:HeadObjectReport",
            precedence: 960,
            selector: "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"acme-report\")",
            action: "acme:HeadObjectReport",
            resource: ResourceShape::Object,
            success_status: 200,
            anonymous: false,
            evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html"],
        }],
    };
    let dialect = Dialect::assemble(&MOVED_OVERLAY)
        .declare::<HeadObjectReport>(DialectRoute {
            precedence: 960,
            ..report_route()
        })
        .build()
        .expect("the overlay was moved with the row, so assembly still succeeds");

    let fs = Fs::new();
    let result = RouterBuilder::new()
        .handle_without_codec::<HeadObjectReport, _>(Arc::clone(&fs))
        .dialect(&dialect)
        .build();
    let Err(BuildError::Route(RouterBuildError::Route(RouteBuildError::StaleShadowing { winner, shadowed, .. }))) = result else {
        panic!("expected a stale declaration, got {result:?}");
    };
    assert_eq!(winner, "acme:HeadObjectReport");
    assert_eq!(shadowed, "HeadObject");
}

/// Negative -- a dialect whose operation was never handed a handler still answers 501, not 500.
///
/// Assembly installs a route, not an implementation. The two are separate calls on purpose, and the
/// gap is the ordinary "this backend does not handle that operation".
#[test]
fn a_dialect_route_with_no_handler_is_not_implemented() {
    let router = RouterBuilder::new()
        .dialect(&example_dialect())
        .build()
        .expect("a route with no handler is a legitimate table");
    let request = RouteReq::new("HEAD /bucket/key?acme-report");
    let error = router.dispatch(&request.parts()).expect_err("nothing handles it");
    assert_eq!(error.status(), 501);
}

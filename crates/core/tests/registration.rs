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

//! What registration refuses, what erasure preserves, and what an unregistered operation answers.
//!
//! Responsible for: the registration rules (namespace, collision, authorisation, duplicates), the
//! erased call path, `require` and the one-line completeness message, and the 501 an operation with
//! no handler receives.
//! NOT responsible for: routing itself (`route_table.rs`), required parameters
//! (`params_and_dispatch.rs`), or the macro (`rustfs-gateway-macros`).
//! Upstream: `support`. Downstream: nothing.
//!
//! # The headline
//!
//! A third party can add an operation, and it travels the same authentication and authorisation
//! path as `GetObject` — or it does not get registered. There is no third state, which is the
//! structural difference from a side-mounted custom route (rustfs/rustfs#4845).
//!
//! Written against the public API only, so everything here is also a worked example of what a P5
//! operation family has to do.

use crate::support;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Method, Request};
use rustfs_gateway_core::dispatch::NOT_REGISTERED_MESSAGE;
use rustfs_gateway_core::handler::{Handler, HandlerError, HandlerResult, Req, Resp};
use rustfs_gateway_core::op::{AuthRequirement, HasOperation, Operation, ResourceShape};
use rustfs_gateway_core::registry::{
    BuildError, MissingHandlers, OperationSet, OperationSpec, Registry, RegistryError, RouterBuilder,
};
use rustfs_gateway_core::route::{Predicate, TargetKind};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{
    GetBucketLocation, GetBucketLocationInput, GetBucketLocationOutput, PutObject, PutObjectInput, PutObjectOutput,
};
use support::{Req as RouteReq, block_on, entry};

fn erased_get_bucket_location() -> rustfs_gateway_core::ErasedRequest {
    let request = Request::builder()
        .method("GET")
        .uri("http://host.invalid/bucket?location")
        .header("host", "host.invalid")
        .body(())
        .expect("valid request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted request");
    let meta = rustfs_gateway_core::MetaView::of(&wire, TargetKind::Bucket).expect("bucket target");
    let codec = rustfs_gateway_core::ErasedCodec::for_operation::<GetBucketLocation>();
    let decoded = codec
        .decode(&meta, rustfs_gateway_core::RequestBody::Buffered(Bytes::new()))
        .expect("decoded");
    codec.authorize(decoded, &[]).expect("no derived resources")
}

// ── a backend ────────────────────────────────────────────────────────────────────────────────

/// A backend that answers two operations and counts what it was asked.
#[derive(Debug, Default)]
struct Fs {
    calls: AtomicUsize,
    region: &'static str,
}

impl Fs {
    fn new(region: &'static str) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            region,
        })
    }
}

impl Handler<GetBucketLocation> for Fs {
    fn call(&self, request: Req<GetBucketLocation>) -> impl Future<Output = HandlerResult<GetBucketLocation>> + Send {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let region = self.region;
        let _ = request.input();
        async move {
            Ok(Resp::new(GetBucketLocationOutput {
                location_constraint: Some(rustfs_gateway_types::dto::LocationConstraint::custom(region)),
            }))
        }
    }
}

impl Handler<PutObject> for Fs {
    fn call(&self, _request: Req<PutObject>) -> impl Future<Output = HandlerResult<PutObject>> + Send {
        self.calls.fetch_add(1, Ordering::Relaxed);
        async move { Err(HandlerError::internal_error("this backend is read only")) }
    }
}

// ── third-party operations, declared the way a plugin would ──────────────────────────────────
//
// None of these implements `OperationCodec`, so they register through `handle_without_codec`.
// That is the escape hatch's whole purpose: the registration rules below are about names, actions,
// specs and floors, and they hold identically whether or not an operation can be read off the
// wire. The codec half of registration is `tests/codec_binding.rs`.

/// A well-formed third-party operation.
struct AdminSetConfig;

static ADMIN_SPEC: OperationSpec = OperationSpec::builder("rustfs:AdminSetConfig", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("admin:SetConfig", ResourceShape::Service))
    .build();

static ADMIN_FLOOR: OperationFloor = OperationFloor::custom("rustfs:AdminSetConfig", SigService::S3);

impl Operation for AdminSetConfig {
    const NAME: &'static str = "rustfs:AdminSetConfig";
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &ADMIN_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &ADMIN_FLOOR
    }
}

/// Spelled `async fn` rather than `-> impl Future`, because RPITIT allows an implementor either
/// one. The macro generates the second form, since its body is a delegation rather than an `async`
/// block; a hand-written handler is free to take the shorter one.
impl Handler<AdminSetConfig> for Fs {
    async fn call(&self, _request: Req<AdminSetConfig>) -> HandlerResult<AdminSetConfig> {
        Ok(Resp::new(()))
    }
}

/// Declares one badly named, badly specified operation after another.
///
/// A macro rather than eight near-identical types: each case differs in one field, and eight
/// hand-copied blocks is where a test starts asserting the wrong thing about the wrong constant.
macro_rules! bad_operation {
    ($ident:ident, name = $name:expr, spec_name = $spec:expr, floor_name = $floor:expr, auth = $auth:expr) => {
        struct $ident;

        const _: () = {
            static SPEC: OperationSpec = match $auth {
                Some(auth) => OperationSpec::builder($spec, 200, None).auth(auth).build(),
                None => OperationSpec::builder($spec, 200, None).build(),
            };
            static FLOOR: OperationFloor = OperationFloor::custom($floor, SigService::S3);

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
        };

        impl Handler<$ident> for Fs {
            fn call(&self, _request: Req<$ident>) -> impl Future<Output = HandlerResult<$ident>> + Send {
                async move { Ok(Resp::new(())) }
            }
        }
    };
}

const SERVICE_AUTH: Option<AuthRequirement> = Some(AuthRequirement::new("admin:Thing", ResourceShape::Service));

bad_operation!(
    NotNamespaced,
    name = "AdminThing",
    spec_name = "AdminThing",
    floor_name = "AdminThing",
    auth = SERVICE_AUTH
);
bad_operation!(
    TakesAwsName,
    name = "PutObject",
    spec_name = "PutObject",
    floor_name = "PutObject",
    auth = SERVICE_AUTH
);
bad_operation!(
    TakesAwsNameCased,
    name = "putobject",
    spec_name = "putobject",
    floor_name = "putobject",
    auth = SERVICE_AUTH
);
bad_operation!(
    NoAuth,
    name = "acme:NoAuth",
    spec_name = "acme:NoAuth",
    floor_name = "acme:NoAuth",
    auth = None
);
bad_operation!(
    BadAction,
    name = "acme:BadAction",
    spec_name = "acme:BadAction",
    floor_name = "acme:BadAction",
    auth = Some(AuthRequirement::new("SetConfig", ResourceShape::Service))
);
bad_operation!(
    SpecRenamed,
    name = "acme:SpecRenamed",
    spec_name = "acme:SomethingElse",
    floor_name = "acme:SpecRenamed",
    auth = SERVICE_AUTH
);
bad_operation!(
    FloorRenamed,
    name = "acme:FloorRenamed",
    spec_name = "acme:FloorRenamed",
    floor_name = "acme:SomethingElse",
    auth = SERVICE_AUTH
);

/// The reverse mapping a compatibility layer needs, used the way that layer would use it.
type S3Request<I> = Req<<I as HasOperation>::Op>;

fn only_error(result: Result<rustfs_gateway_core::Router, BuildError>) -> RegistryError {
    match result {
        Err(BuildError::Registration(errors)) => match errors.as_slice() {
            [error] => error.clone(),
            other => panic!("expected exactly one refusal, got {other:?}"),
        },
        Err(other) => panic!("expected a registration refusal, got {other}"),
        Ok(_) => panic!("expected the build to be refused"),
    }
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — a registered operation is called through the erased entry, with its types intact.
#[test]
fn an_erased_registration_still_calls_the_typed_handler() {
    let fs = Fs::new("eu-central-1");
    let router = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fs))
        .build()
        .expect("the builder accepts a well-formed registration");

    let invocation = router
        .registry()
        .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default())
        .expect("input authorization succeeds")
        .expect("GetBucketLocation is registered");
    let response = block_on(invocation).expect("the handler answers");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .output()
            .expect("a settled answer")
            .location_constraint
            .as_ref()
            .map(|region| region.as_str()),
        Some("eu-central-1")
    );
    assert_eq!(fs.calls.load(Ordering::Relaxed), 1);
}

/// Positive — the same process holds two routers over two backends, and they answer differently.
///
/// This is the arrangement a process-global registry cannot express, and the reason `inventory` is
/// banned (ADR-0003): RustFS runs a fake target beside the production backend in one process.
#[test]
fn two_backends_coexist_in_one_process() {
    let production = Fs::new("us-east-1");
    let fake = Fs::new("test-region");
    let one = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&production))
        .build()
        .expect("one");
    let two = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fake))
        .build()
        .expect("two");

    let region_of = |router: &rustfs_gateway_core::Router| {
        let invocation = router
            .registry()
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default())
            .expect("input authorization succeeds")
            .expect("registered");
        block_on(invocation)
            .expect("answered")
            .output()
            .expect("a settled answer")
            .location_constraint
            .as_ref()
            .map(|region| region.as_str().to_owned())
    };

    assert_eq!(region_of(&one).as_deref(), Some("us-east-1"));
    assert_eq!(region_of(&two).as_deref(), Some("test-region"));
}

/// Positive — a third-party operation registers beside the AWS ones and is invoked the same way.
#[test]
fn a_namespaced_third_party_operation_registers() {
    let fs = Fs::new("us-east-1");
    let router = RouterBuilder::new()
        .handle::<PutObject, _>(Arc::clone(&fs))
        .handle_without_codec::<AdminSetConfig, _>(Arc::clone(&fs))
        .route(entry(
            "rustfs:AdminSetConfig",
            60,
            vec![Predicate::Method(Method::POST), Predicate::Target(TargetKind::Service)],
        ))
        .build()
        .expect("a namespaced operation with an action and a floor is registrable");

    assert_eq!(
        router.registry().handler_names().collect::<Vec<_>>(),
        vec!["PutObject", "rustfs:AdminSetConfig"]
    );
    let answer = block_on(
        router
            .registry()
            .authorize_and_invoke_no_derived::<AdminSetConfig>(())
            .expect("input authorization succeeds")
            .expect("registered"),
    );
    assert!(answer.is_ok());
}

/// Positive — `require` passes when every operation in the set has a handler.
#[test]
fn require_passes_on_a_covered_set() {
    let fs = Fs::new("us-east-1");
    let builder = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fs))
        .handle::<PutObject, _>(Arc::clone(&fs))
        .require(&OperationSet::of(["GetBucketLocation", "PutObject"]))
        .expect("both are registered");
    assert!(builder.build().is_ok());
}

/// Positive — the input-to-operation mapping lets a migration keep its existing signatures.
#[test]
fn the_reverse_mapping_names_the_operation_its_input_belongs_to() {
    let request: S3Request<PutObjectInput> = Req::new(PutObjectInput::default());
    assert_eq!(request.operation_name(), "PutObject");

    let other: S3Request<GetBucketLocationInput> = Req::new(GetBucketLocationInput::default());
    assert_eq!(other.operation_name(), "GetBucketLocation");
}

/// Positive — a spec-only registration is enough for routing and validation to work.
#[test]
fn a_spec_registration_without_a_handler_still_routes() {
    let mut registry = Registry::new();
    registry
        .register(PutObject::spec())
        .expect("the generated spec is registrable");
    assert_eq!(registry.names().collect::<Vec<_>>(), vec!["PutObject"]);
    assert_eq!(registry.handler_names().count(), 0);
    assert!(
        registry
            .authorize_and_invoke_no_derived::<PutObject>(PutObjectInput::default())
            .expect("input authorization succeeds")
            .is_none()
    );
}

/// Positive — the answer's status comes from the operation's spec, and can be overridden per call.
#[test]
fn the_answer_carries_the_operations_declared_status() {
    assert_eq!(Resp::<PutObject>::new(PutObjectOutput::default()).status(), 200);
    assert_eq!(Resp::<PutObject>::with_status(PutObjectOutput::default(), 206).status(), 206);
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// Negative — an operation with no handler is a 501, and nothing had to declare a default method.
#[test]
fn an_unregistered_operation_is_not_implemented() {
    let fs = Fs::new("us-east-1");
    let router = RouterBuilder::new()
        .handle::<PutObject, _>(Arc::clone(&fs))
        .build()
        .expect("built");

    assert!(
        router
            .registry()
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default())
            .expect("input authorization succeeds")
            .is_none()
    );

    let request = RouteReq::new("GET /bucket?location");
    let error = router
        .dispatch(&request.parts())
        .expect_err("no handler for GetBucketLocation");
    assert_eq!(error.code(), &ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("GetBucketLocation"));
}

/// Negative — a third-party operation must be namespaced.
#[test]
fn a_third_party_name_without_a_namespace_is_refused() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<NotNamespaced, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(error, RegistryError::NameNotNamespaced { name: "AdminThing" });
}

/// Negative — a third party may not take an AWS operation name.
#[test]
fn a_third_party_may_not_take_an_aws_name() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<TakesAwsName, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(
        error,
        RegistryError::NameCollidesWithStandard {
            name: "PutObject",
            standard: "PutObject",
        }
    );
}

/// Negative — nor a differently cased spelling of one.
#[test]
fn a_third_party_may_not_take_an_aws_name_in_another_case() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<TakesAwsNameCased, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(
        error,
        RegistryError::NameCollidesWithStandard {
            name: "putobject",
            standard: "PutObject",
        }
    );
}

/// a-asm-0012 / c-azc-0024. Negative — an operation nobody can authorise cannot be registered.
///
/// The one that matters: this is the shape of rustfs/rustfs#4845 made unrepresentable.
#[test]
fn an_operation_with_no_action_cannot_be_registered() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<NoAuth, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(error, RegistryError::MissingAuthRequirement { name: "acme:NoAuth" });
}

/// Negative — an action that is not `service:Action` is not an action.
#[test]
fn a_malformed_action_is_refused() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<BadAction, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(
        error,
        RegistryError::MalformedAuthAction {
            name: "acme:BadAction",
            action: "SetConfig",
        }
    );
}

/// Negative — a spec registered under a different name than its operation.
#[test]
fn a_spec_naming_another_operation_is_refused() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<SpecRenamed, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(
        error,
        RegistryError::SpecNameMismatch {
            name: "acme:SpecRenamed",
            spec: "acme:SomethingElse",
        }
    );
}

/// Negative — a security floor registered under a different name than its operation.
///
/// The floor decides whether a presigned URL may reach the operation. One belonging to another
/// operation is the MinIO #5411 shape: a fence that describes something else.
#[test]
fn a_floor_naming_another_operation_is_refused() {
    let fs = Fs::new("us-east-1");
    let error = only_error(
        RouterBuilder::new()
            .handle_without_codec::<FloorRenamed, _>(Arc::clone(&fs))
            .build(),
    );
    assert_eq!(
        error,
        RegistryError::FloorNameMismatch {
            name: "acme:FloorRenamed",
            floor: "acme:SomethingElse",
        }
    );
}

/// Negative — the second registration of a name is refused, and the first one survives untouched.
#[test]
fn a_second_registration_does_not_win() {
    let first = Fs::new("first-region");
    let second = Fs::new("second-region");
    let mut registry = Registry::new();
    registry
        .register_handler::<GetBucketLocation, _>(Arc::clone(&first))
        .expect("the first registration");
    let error = registry
        .register_handler::<GetBucketLocation, _>(Arc::clone(&second))
        .expect_err("the second must be refused");
    assert_eq!(
        error,
        RegistryError::Duplicate {
            name: "GetBucketLocation"
        }
    );

    let answer = block_on(
        registry
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    assert_eq!(
        answer
            .output()
            .expect("a settled answer")
            .location_constraint
            .as_ref()
            .map(|region| region.as_str()),
        Some("first-region"),
        "a refused registration must not have replaced the handler that was already there"
    );
}

/// Negative — every refusal is reported, not only the first.
#[test]
fn the_build_reports_every_refusal_at_once() {
    let fs = Fs::new("us-east-1");
    let result = RouterBuilder::new()
        .handle_without_codec::<NotNamespaced, _>(Arc::clone(&fs))
        .handle_without_codec::<NoAuth, _>(Arc::clone(&fs))
        .handle_without_codec::<BadAction, _>(Arc::clone(&fs))
        .build();
    match result {
        Err(BuildError::Registration(errors)) => assert_eq!(errors.len(), 3, "{errors:?}"),
        other => panic!("expected three refusals, got {other:?}"),
    }
}

/// Negative — an added route entry may not wear an AWS operation name.
#[test]
fn an_added_route_may_not_claim_an_aws_operation() {
    let result = RouterBuilder::new()
        .route(entry(
            "PutObject",
            10,
            vec![Predicate::Method(Method::PUT), Predicate::Target(TargetKind::Object)],
        ))
        .build();
    assert!(
        matches!(result, Err(BuildError::RouteClaimsStandardName { op_name: "PutObject" })),
        "{result:?}"
    );
}

/// Negative — an added route that collides with a generated one at the same precedence is refused.
///
/// Delegated to the route table's own conflict decision, so a third-party selector cannot win by
/// sort order — the property P4-01 established, reached through registration.
#[test]
fn an_added_route_colliding_with_a_standard_one_is_refused() {
    let result = RouterBuilder::new()
        .route(entry(
            "acme:Shadow",
            800,
            vec![Predicate::Method(Method::PUT), Predicate::Target(TargetKind::Object)],
        ))
        .build();
    assert!(matches!(result, Err(BuildError::Route(_))), "{result:?}");
}

/// Negative — a failed build produces no router at all, so a reload keeps the one it has.
#[test]
fn a_failed_rebuild_leaves_the_running_router_alone() {
    let fs = Fs::new("us-east-1");
    let running = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fs))
        .build()
        .expect("the first build");

    let reloaded = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fs))
        .handle_without_codec::<NoAuth, _>(Arc::clone(&fs))
        .build();
    assert!(reloaded.is_err(), "the reload must be refused as a whole");

    // The old router is untouched and still answers.
    let answer = block_on(
        running
            .registry()
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default())
            .expect("input authorization succeeds")
            .expect("still registered"),
    );
    assert!(answer.is_ok());
}

/// Negative — `require` names what is missing, on one line, with a total.
#[test]
fn require_reports_the_missing_operations_on_one_line() {
    let fs = Fs::new("us-east-1");
    let missing = RouterBuilder::new()
        .handle::<PutObject, _>(Arc::clone(&fs))
        .require(&OperationSet::aws_full())
        .expect_err("every generated operation but one has no handler");

    // The set is `OperationSet::aws_full()`, which reads the generated route table — so this
    // assertion moves with the whitelist, and that is the point: a family that lands and forgets
    // its registration shows up here.
    let text = missing.to_string();
    assert_eq!(text.lines().count(), 1, "the completeness message must be one line: {text}");
    assert_eq!(
        text,
        "backend is missing handlers for: AbortMultipartUpload, CompleteMultipartUpload, CopyObject, \
         CreateBucket, CreateMultipartUpload, DeleteBucket, DeleteBucketCors, DeleteBucketEncryption, DeleteBucketLifecycle, \
         DeleteBucketPolicy, ... and 61 more (71 of 72)"
    );
    assert_eq!(
        missing.missing(),
        [
            "AbortMultipartUpload",
            "CompleteMultipartUpload",
            "CopyObject",
            "CreateBucket",
            "CreateMultipartUpload",
            "DeleteBucket",
            "DeleteBucketCors",
            "DeleteBucketEncryption",
            "DeleteBucketLifecycle",
            "DeleteBucketPolicy",
            "DeleteBucketReplication",
            "DeleteBucketTagging",
            "DeleteBucketWebsite",
            "DeleteObject",
            "DeleteObjectTagging",
            "DeleteObjects",
            "DeletePublicAccessBlock",
            "GetBucketAccelerateConfiguration",
            "GetBucketAcl",
            "GetBucketCors",
            "GetBucketEncryption",
            "GetBucketLifecycleConfiguration",
            "GetBucketLocation",
            "GetBucketLogging",
            "GetBucketNotificationConfiguration",
            "GetBucketPolicy",
            "GetBucketPolicyStatus",
            "GetBucketReplication",
            "GetBucketRequestPayment",
            "GetBucketTagging",
            "GetBucketVersioning",
            "GetBucketWebsite",
            "GetObject",
            "GetObjectAcl",
            "GetObjectAttributes",
            "GetObjectLegalHold",
            "GetObjectLockConfiguration",
            "GetObjectRetention",
            "GetObjectTagging",
            "GetPublicAccessBlock",
            "HeadBucket",
            "HeadObject",
            "ListBuckets",
            "ListMultipartUploads",
            "ListObjectVersions",
            "ListObjects",
            "ListObjectsV2",
            "ListParts",
            "PutBucketAccelerateConfiguration",
            "PutBucketAcl",
            "PutBucketCors",
            "PutBucketEncryption",
            "PutBucketLifecycleConfiguration",
            "PutBucketLogging",
            "PutBucketNotificationConfiguration",
            "PutBucketPolicy",
            "PutBucketReplication",
            "PutBucketRequestPayment",
            "PutBucketTagging",
            "PutBucketVersioning",
            "PutBucketWebsite",
            "PutObjectAcl",
            "PutObjectLegalHold",
            "PutObjectLockConfiguration",
            "PutObjectRetention",
            "PutObjectTagging",
            "PutPublicAccessBlock",
            "RestoreObject",
            "SelectObjectContent",
            "UploadPart",
            "UploadPartCopy"
        ]
    );
    assert_eq!(missing.required(), 72);
}

/// Negative — a long list is truncated and still says how much is missing in total.
#[test]
fn a_long_missing_list_is_truncated_but_still_counted() {
    const NAMES: [&str; 12] = [
        "acme:A", "acme:B", "acme:C", "acme:D", "acme:E", "acme:F", "acme:G", "acme:H", "acme:I", "acme:J", "acme:K", "acme:L",
    ];
    let missing: MissingHandlers = RouterBuilder::new()
        .require(&OperationSet::of(NAMES))
        .expect_err("nothing is registered");
    let text = missing.to_string();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.ends_with(", ... and 2 more (12 of 12)"), "{text}");
    assert!(text.contains("acme:J"), "{text}");
    assert!(!text.contains("acme:K"), "{text}");
}

/// Negative — an erased call with the wrong payload answers, rather than panicking.
///
/// Unreachable through the typed entry point, which looks the handler up by the operation's own
/// name. It is reachable from a pipeline that boxed the wrong thing, and a framework bug must not
/// be able to take the process down.
#[test]
fn an_erased_call_with_the_wrong_payload_is_an_error_not_a_panic() {
    let fs = Fs::new("us-east-1");
    let router = RouterBuilder::new()
        .handle::<PutObject, _>(Arc::clone(&fs))
        .build()
        .expect("built");

    let wrong = erased_get_bucket_location();
    let call = router
        .registry()
        .handlers()
        .invoke_erased("PutObject", wrong)
        .expect("PutObject is registered");
    let error = block_on(call).expect_err("the payload is another operation's");
    assert_eq!(error.code(), &ErrorCode::INTERNAL_ERROR);
    assert!(error.message().contains("PutObject"), "{error}");
}

/// Negative — an erased call for an operation nobody registered finds nothing.
#[test]
fn an_erased_call_for_an_unregistered_operation_finds_nothing() {
    let router = RouterBuilder::new().build().expect("an empty backend still builds");
    let payload = erased_get_bucket_location();
    assert!(router.registry().handlers().invoke_erased("PutObject", payload).is_none());
    assert!(router.registry().handlers().is_empty());
}

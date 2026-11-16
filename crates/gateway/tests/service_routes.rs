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

//! Service-scoped registration through the complete authentication and authorization pipeline.
//!
//! Responsible for: service addressing, refused credentials, and immutable routing scope on updates.
//! NOT responsible for: external service codecs or SDK serialization.
//! Upstream: public service assembly. Downstream: embedding hosts with several signing services.

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    AssemblyUpdate, AuthRequirement, ClockSkewAck, CodecError, Credentials, EncodedResponse, Handler, HandlerDeadlineClass,
    HandlerResult, MetaView, NoDerived, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, RegionSet, Req,
    RequestBody, RequestBodyMode, ResourceShape, Resp, S3Service, SecurityFloor, ServiceBuilder, SigService, SigV4Authenticator,
    StaticCredentials, allow_when,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, OverlayRow};

const SERVICE: SigService = SigService::S3Vectors;
const NAME: &str = "example:PutVectors";
const PREDICATES: &[Predicate] = &[Predicate::Method(Method::POST), Predicate::PathLiteral("/PutVectors")];

struct Action;

static SPEC: OperationSpec = OperationSpec::builder(NAME, 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .auth(AuthRequirement::new("example:PutVectors", ResourceShape::Service))
    .build();
// A non-privileged floor lets anonymous delegation test the SigV4 requirement independently.
static FLOOR: OperationFloor = OperationFloor::builtin(NAME, SERVICE).require_sigv4_under_every_policy();
static OVERLAY: DialectOverlay = DialectOverlay {
    name: "service-runtime-test",
    vendor: "example",
    claims: &[],
    operations: &[OverlayRow {
        name: NAME,
        precedence: 50,
        selector: "Method(POST) ∧ PathLiteral(\"/PutVectors\")",
        action: "example:PutVectors",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_PutVectors.html"],
    }],
};

impl Operation for Action {
    const NAME: &'static str = NAME;
    type Input = ();
    type Output = ();
    type DerivedResources = NoDerived;

    fn derive_resources(_: &Self::Input) -> Result<NoDerived, rustfs_gateway::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl OperationCodec for Action {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

    fn decode(request: &MetaView<'_>, _: RequestBody) -> Result<(), CodecError> {
        if request.bucket().is_some() || request.key().is_some() {
            return Err(CodecError::invalid_argument("a service action cannot have an S3 target"));
        }
        Ok(())
    }

    fn encode(_: (), _: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

#[derive(Default)]
struct Backend {
    handler_calls: AtomicUsize,
    authorizer_calls: AtomicUsize,
}

impl Handler<Action> for Backend {
    async fn call(&self, _: Req<Action>) -> HandlerResult<Action> {
        self.handler_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(()))
    }
}

fn dialect() -> Dialect {
    Dialect::assemble_for_service(&OVERLAY, SERVICE)
        .declare::<Action>(DialectRoute {
            precedence: 50,
            selector: PREDICATES,
            path_shape: "/PutVectors",
            shadows: &[],
        })
        .build()
        .expect("matching service declaration")
}

fn registered(backend: Arc<Backend>) -> ServiceBuilder {
    ServiceBuilder::for_service(SERVICE)
        .dialect(&dialect())
        .register::<Action, _>(backend)
}

fn service(backend: Arc<Backend>, allowed: bool) -> S3Service {
    service_with_floor(backend, allowed, SecurityFloor::new())
}

fn service_with_floor(backend: Arc<Backend>, allowed: bool, floor: SecurityFloor) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("test credentials")));
    let observed = Arc::clone(&backend);
    registered(backend)
        .security_floor(floor)
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region")))
        .authorizer(allow_when(move |_| {
            observed.authorizer_calls.fetch_add(1, Ordering::SeqCst);
            allowed
        }))
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("service assembly")
}

fn signed(service: SigService, target: &str) -> Request<Bytes> {
    let probe = Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("host probe");
    let wire = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted host");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("timestamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", service).expect("signing scope");
    let mut signer = SigV4Signer::new(SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("credentials"), scope);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let request = SigningRequest::new(
        &Method::POST,
        path,
        query,
        &headers,
        wire.host().raw_for_signing(),
        PayloadMode::Empty,
        stamp,
    )
    .with_wire_content_length(0);
    let signed = signer.sign_headers(&request).expect("signed request");
    let mut builder = Request::builder().method(Method::POST).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("wire request")
}

#[tokio::test]
async fn uppercase_action_reaches_the_handler_as_a_service_request() {
    let backend = Arc::new(Backend::default());
    let service = service(Arc::clone(&backend), true);
    let response = service.call_bytes(signed(SERVICE, "/PutVectors?first=b&second=a")).await;
    assert_eq!(response.status(), StatusCode::OK, "uppercase-action-status");
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 1, "uppercase-action-handler-count");
}

#[tokio::test]
async fn another_service_signature_never_reaches_the_handler() {
    let backend = Arc::new(Backend::default());
    let service = service(Arc::clone(&backend), true);
    let response = service.call_bytes(signed(SigService::S3, "/PutVectors")).await;
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 0, "wrong-service-handler-count");
    assert!(response.status().is_client_error(), "wrong-service-status");
}

#[tokio::test]
async fn a_tampered_query_never_reaches_the_handler() {
    let backend = Arc::new(Backend::default());
    let service = service(Arc::clone(&backend), true);
    let mut tampered = signed(SERVICE, "/PutVectors?first=a&second=b");
    *tampered.uri_mut() = "/PutVectors?first=a&second=c".parse().expect("URI");
    let response = service.call_bytes(tampered).await;
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 0, "query-tamper-handler-count");
    assert!(response.status().is_client_error(), "query-tamper-status");
}

#[tokio::test]
async fn an_anonymous_request_is_refused_before_the_allowing_authorizer() {
    anonymous_requires_signature(SecurityFloor::new()).await;
}

#[tokio::test]
async fn anonymous_delegation_preserves_the_signature_requirement() {
    anonymous_requires_signature(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .await;
}

async fn anonymous_requires_signature(floor: SecurityFloor) {
    let backend = Arc::new(Backend::default());
    let service = service_with_floor(Arc::clone(&backend), true, floor);
    let control = service.call_bytes(signed(SERVICE, "/PutVectors")).await;
    assert_eq!(control.status(), StatusCode::OK, "anonymous-control-status");
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 1, "anonymous-control-handler-count");
    let authorized_before = backend.authorizer_calls.load(Ordering::SeqCst);
    assert!(authorized_before > 0, "anonymous-control-authorizer-count");

    let mut anonymous = signed(SERVICE, "/PutVectors");
    anonymous.headers_mut().remove(http::header::AUTHORIZATION);
    let response = service.call_bytes(anonymous).await;
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 1, "anonymous-handler-count");
    assert_eq!(
        backend.authorizer_calls.load(Ordering::SeqCst),
        authorized_before,
        "anonymous-authorizer-count"
    );
    assert!(response.status().is_client_error(), "anonymous-status");
}

#[tokio::test]
async fn a_signed_request_reaches_the_denying_authorizer_without_calling_the_handler() {
    let backend = Arc::new(Backend::default());
    let service = service(Arc::clone(&backend), false);
    let response = service.call_bytes(signed(SERVICE, "/PutVectors")).await;
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 0, "signed-denial-handler-count");
    assert_eq!(backend.authorizer_calls.load(Ordering::SeqCst), 1, "signed-denial-authorizer-count");
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "signed-denial-status");
}

#[tokio::test]
async fn registry_and_assembly_updates_keep_the_initial_service_scope() {
    let backend = Arc::new(Backend::default());
    let service = service(Arc::clone(&backend), true);
    let ordinary = || {
        support::wired()
            .dialect(&support::ping_dialect())
            .register::<support::Ping, _>(Arc::new(support::Backend))
    };
    assert!(service.replace_registry(ordinary()).is_err());
    assert!(
        service
            .replace_assembly(
                AssemblyUpdate::new()
                    .dialect(&support::ping_dialect())
                    .register::<support::Ping, _>(Arc::new(support::Backend))
                    .authorizer(allow_when(|_| true))
            )
            .is_err()
    );
    assert_eq!(
        service.call_bytes(signed(SERVICE, "/PutVectors")).await.status(),
        StatusCode::OK,
        "update-before-status"
    );
    service
        .replace_registry(registered(Arc::clone(&backend)))
        .expect("same-scope registry update");
    service
        .replace_assembly(
            AssemblyUpdate::for_service(SERVICE)
                .dialect(&dialect())
                .register::<Action, _>(Arc::clone(&backend))
                .authorizer(allow_when(|_| true)),
        )
        .expect("same-scope assembly update");
    assert_eq!(
        service.call_bytes(signed(SERVICE, "/PutVectors")).await.status(),
        StatusCode::OK,
        "update-after-status"
    );
    assert_eq!(backend.handler_calls.load(Ordering::SeqCst), 2, "update-handler-count");
}

#[test]
fn a_default_s3_instance_refuses_a_service_scoped_registry_update() {
    let service = support::service();
    assert!(service.replace_registry(registered(Arc::new(Backend::default()))).is_err());
    assert!(
        service
            .replace_assembly(
                AssemblyUpdate::for_service(SERVICE)
                    .dialect(&dialect())
                    .register::<Action, _>(Arc::new(Backend::default()))
                    .authorizer(allow_when(|_| true))
            )
            .is_err()
    );
}

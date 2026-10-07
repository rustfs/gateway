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

//! A claimed route's declared body bounded as legacy RustFS bounds its admin surface's, through
//! the whole service (rustfs/gateway#1173).
//!
//! Responsible for: proving that `ServiceBuilder::bound_claimed_route_bodies_as_legacy_rustfs`
//! refuses a claimed route declaring more than 1 MiB — one that buffers its body and one that
//! reads none — with legacy RustFS's `400 EntityTooLarge`, after the signature and before
//! authorization, with no body byte read and no handler reached; that a request presenting no
//! credential is refused by it ahead of the floor; and that 1 MiB exactly, an unclaimed operation,
//! a bad or malformed signature and the default assembly are answered as before.
//! NOT responsible for: the ceiling's value (`src/builder/claimed_bodies.rs`) or which routes a
//! dialect claims (`crates/core/tests/dialect_claims*.rs`).
//! Upstream: `S3Service` with a claimed example dialect. Downstream: none.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::sig::{
    AmzDate, AuthError, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, PayloadMode, SigService, SigV4Signer,
    SignatureVerifier, SigningCredentials, SigningRequest, SigningScope, Verdict,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerResult, InputAuthzRequest, InputDecisions,
    RegionSet, Req, RequestContext, Resp, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, dto,
};
use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode};
use rustfs_gateway_core::{
    AuthRequirement, ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, HandlerDeadlineClass, Operation, OperationSpec,
    OverlayRow, PathClaim, Predicate, ResourceShape,
};
use rustfs_gateway_sig::{OperationFloor, SecurityFloor};

use crate::support::{self, CountingBody};

const EVIDENCE: &[&str] = &["https://github.com/rustfs/gateway/issues/1173"];
const INFO: &str = "example:Info";
const IMPORT: &str = "example:Import";

/// The two claimed operations: `Info` reads no body, `Import` buffers one and reports its length.
struct Info;
struct Import;

const fn spec(name: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("admin:Thing", ResourceShape::Service))
}

static SPECS: [OperationSpec; 2] = [spec(INFO).build(), spec(IMPORT).build()];
static FLOORS: [OperationFloor; 2] = [
    OperationFloor::custom(INFO, SigService::S3),
    OperationFloor::custom(IMPORT, SigService::S3),
];

macro_rules! claimed_operation {
    ($type:ty, $name:expr, $index:expr, $mode:expr, $input:ty) => {
        impl Operation for $type {
            const NAME: &'static str = $name;
            type Input = $input;
            type Output = ();
            type DerivedResources = rustfs_gateway_core::NoDerived;

            fn derive_resources(
                _input: &Self::Input,
            ) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
                Ok(rustfs_gateway_core::NoDerived)
            }

            fn seal_derived_input(_input: &mut Self::Input) {}

            fn spec() -> &'static OperationSpec {
                &SPECS[$index]
            }

            fn floor() -> &'static OperationFloor {
                &FLOORS[$index]
            }
        }

        impl OperationCodec for $type {
            const REQUEST_BODY: RequestBodyMode = $mode;

            fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<$input, CodecError> {
                Ok(<$input>::from(body.into_buffered()?.len()))
            }

            fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
                Ok(EncodedResponse::of(status))
            }
        }
    };
}

claimed_operation!(Info, INFO, 0, RequestBodyMode::None, usize);
claimed_operation!(Import, IMPORT, 1, RequestBodyMode::Full, usize);

static GET: &[Predicate] = &[Predicate::Method(http::Method::GET)];
static PUT: &[Predicate] = &[Predicate::Method(http::Method::PUT)];
static INFO_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/example/admin/v1/info",
    selector: GET,
}];
static IMPORT_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/example/admin/v1/import",
    selector: PUT,
}];

const fn row(name: &'static str, precedence: u16, selector: &'static str) -> OverlayRow {
    OverlayRow {
        name,
        precedence,
        selector,
        action: "admin:Thing",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }
}

static OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-bodies",
    vendor: "example",
    operations: &[
        row(INFO, 10, "PathTemplate(\"/example/admin/v1/info\") ∧ Method(GET)"),
        row(IMPORT, 11, "PathTemplate(\"/example/admin/v1/import\") ∧ Method(PUT)"),
    ],
    claims: &[PathClaim {
        prefix: "/example/admin",
        reason: "The vendor serves its admin surface here, ahead of S3.",
        evidence: EVIDENCE,
    }],
};

fn dialect() -> Dialect {
    let claimed = |precedence, rows| ClaimedRoute {
        precedence,
        rows,
        shadows: &[],
        bucket_param: None,
    };
    Dialect::assemble(&OVERLAY)
        .declare_claimed::<Info>(claimed(10, INFO_ROWS))
        .declare_claimed::<Import>(claimed(11, IMPORT_ROWS))
        .build()
        .expect("the record and the declarations agree")
}

/// What reached the handlers and the authorizer.
#[derive(Default)]
struct Seen {
    handled: AtomicUsize,
    imported: AtomicUsize,
    asked: AtomicUsize,
}

struct Backend(Arc<Seen>);

impl Handler<Info> for Backend {
    async fn call(&self, _request: Req<Info>) -> HandlerResult<Info> {
        self.0.handled.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(()))
    }
}

impl Handler<Import> for Backend {
    async fn call(&self, request: Req<Import>) -> HandlerResult<Import> {
        self.0.handled.fetch_add(1, Ordering::SeqCst);
        self.0.imported.store(request.into_input(), Ordering::SeqCst);
        Ok(Resp::new(()))
    }
}

impl Handler<dto::GetObject> for Backend {
    async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        self.0.handled.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

/// Counts every question and answers `allow` or `deny`.
struct Counting(Arc<Seen>, Decision);

impl Authorizer for Counting {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        self.0.asked.fetch_add(1, Ordering::SeqCst);
        let decision = self.1;
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.0.asked.fetch_add(1, Ordering::SeqCst);
        let decisions = request.decide_all(self.1, |_| self.1);
        Box::pin(async move { decisions })
    }
}

fn service(bounded: bool, decision: Decision) -> (S3Service, Arc<Seen>) {
    service_with_floor(bounded, decision, SecurityFloor::new())
}

fn service_with_floor(bounded: bool, decision: Decision, floor: SecurityFloor) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid key");
    let mut builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(credentials)),
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .security_floor(floor)
        .authorizer(Counting(Arc::clone(&seen), decision))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .dialect(&dialect())
        .register::<Info, _>(Arc::new(Backend(Arc::clone(&seen))))
        .register::<Import, _>(Arc::new(Backend(Arc::clone(&seen))))
        .register::<dto::GetObject, _>(Arc::new(Backend(Arc::clone(&seen))));
    if bounded {
        builder = builder.bound_claimed_route_bodies_as_legacy_rustfs();
    }
    (builder.build().expect("a complete assembly"), seen)
}

/// `method target`, header-signed over `UNSIGNED-PAYLOAD` with `secret`, declaring `length`.
fn signed(method: http::Method, target: &str, length: u64, secret: &[u8]) -> http::request::Builder {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", secret).expect("credentials");
    let signing =
        SigningRequest::new(&method, target, "", &headers, &host, PayloadMode::Unsigned, stamp).with_wire_content_length(length);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.header(http::header::CONTENT_LENGTH, length)
}

const MIB: usize = 1024 * 1024;
const REFUSAL: &str = "Custom route request body exceeds the configured maximum size.";

async fn send(service: &S3Service, request: http::request::Builder, length: usize) -> (http::StatusCode, String, u64) {
    let (body, polled) = CountingBody::new(Bytes::from(vec![b'x'; length]));
    let response = service.call(request.body(body).expect("a valid request")).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let text = String::from_utf8_lossy(collected.body()).into_owned();
    (collected.status(), text, polled.load(Ordering::SeqCst))
}

/// Positive — under the switch a buffering claimed route declaring 1 MiB and a byte is refused
/// `400 EntityTooLarge` with legacy RustFS's sentence, before any body byte is read or handler run.
#[tokio::test]
async fn a_claimed_body_past_one_mebibyte_is_refused_before_it_is_read() {
    let (service, seen) = service(true, Decision::Allow);
    let length = MIB + 1;
    let (status, body, polled) = send(
        &service,
        signed(http::Method::PUT, "/example/admin/v1/import", length as u64, b"secret"),
        length,
    )
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(support::element_text(&body, "Code"), Some("EntityTooLarge"), "{body}");
    assert_eq!(support::element_text(&body, "Message"), Some(REFUSAL), "{body}");
    assert_eq!(polled, 0, "the body was read before the refusal");
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// Positive — so is a claimed route that reads no body, as legacy RustFS refuses one.
#[tokio::test]
async fn a_bodyless_claimed_route_declaring_two_mebibytes_is_refused() {
    let (service, seen) = service(true, Decision::Allow);
    let length = 2 * MIB;
    let (status, body, polled) = send(
        &service,
        signed(http::Method::GET, "/example/admin/v1/info", length as u64, b"secret"),
        length,
    )
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(support::element_text(&body, "Message"), Some(REFUSAL), "{body}");
    assert_eq!(polled, 0);
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// Positive — the refusal comes before authorization, as legacy RustFS's comes before its access
/// check: a caller the authorizer would deny is answered `400`, not `403`, and nothing is asked.
#[tokio::test]
async fn the_ceiling_is_applied_before_authorization() {
    let (service, seen) = service(true, Decision::Deny);
    let length = MIB + 1;
    let (status, body, _polled) = send(
        &service,
        signed(http::Method::PUT, "/example/admin/v1/import", length as u64, b"secret"),
        length,
    )
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(seen.asked.load(Ordering::SeqCst), 0, "the authorizer was asked first");
}

/// Negative — under the switch a claimed route's body of exactly 1 MiB is read whole and handled.
#[tokio::test]
async fn n_a_claimed_body_of_exactly_one_mebibyte_is_handled() {
    let (service, seen) = service(true, Decision::Allow);
    let (status, body, polled) = send(
        &service,
        signed(http::Method::PUT, "/example/admin/v1/import", MIB as u64, b"secret"),
        MIB,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(polled, MIB as u64);
    assert_eq!(seen.imported.load(Ordering::SeqCst), MIB);
}

/// Negative — without the switch the same 1 MiB and a byte is read and handled.
#[tokio::test]
async fn n_the_default_handles_a_claimed_body_past_one_mebibyte() {
    let (service, seen) = service(false, Decision::Allow);
    let length = MIB + 1;
    let (status, body, _polled) = send(
        &service,
        signed(http::Method::PUT, "/example/admin/v1/import", length as u64, b"secret"),
        length,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(seen.imported.load(Ordering::SeqCst), length);
}

/// Negative — under the switch an unclaimed operation declaring 2 MiB is answered as before.
#[tokio::test]
async fn n_an_unclaimed_operation_is_not_bounded_by_it() {
    let (service, seen) = service(true, Decision::Allow);
    let length = 2 * MIB;
    let (status, body, _polled) =
        send(&service, signed(http::Method::GET, "/bucket/object", length as u64, b"secret"), length).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(seen.handled.load(Ordering::SeqCst), 1);
}

/// Negative — under the switch a bad signature is still `403`, ahead of the ceiling.
#[tokio::test]
async fn n_a_bad_signature_is_refused_before_the_ceiling() {
    let (service, seen) = service(true, Decision::Allow);
    let length = 2 * MIB;
    let (status, body, polled) = send(
        &service,
        signed(http::Method::PUT, "/example/admin/v1/import", length as u64, b"wrong"),
        length,
    )
    .await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(polled, 0);
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// `method target` presenting no credential, declaring `length`.
fn anonymous(method: http::Method, target: &str, length: u64) -> http::request::Builder {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_LENGTH, length)
}

/// Positive — a request presenting no credential has no signature to verify first, and legacy
/// RustFS bounds its admin surface's declared body before its access check: an anonymous request
/// declaring 1 MiB and a byte is `400 EntityTooLarge`, not the floor's `403` for an anonymous
/// admin call. Measured against frozen RustFS 5e1bd498 (rustfs/gateway#1173, 2026-10-05): above
/// 1 MiB valid and anonymous requests answer `400 EntityTooLarge`, forged ones `403`.
#[tokio::test]
async fn an_anonymous_claimed_body_past_one_mebibyte_is_refused_as_too_large() {
    let (service, seen) = service(true, Decision::Allow);
    for (method, target) in [
        (http::Method::PUT, "/example/admin/v1/import"),
        (http::Method::GET, "/example/admin/v1/info"),
    ] {
        let length = MIB + 1;
        let (status, body, polled) = send(&service, anonymous(method, target, length as u64), length).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target}: {body}");
        assert_eq!(support::element_text(&body, "Code"), Some("EntityTooLarge"), "{target}: {body}");
        assert_eq!(support::element_text(&body, "Message"), Some(REFUSAL), "{target}: {body}");
        assert_eq!(polled, 0, "{target}: the body was read before the refusal");
    }
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
    assert_eq!(seen.asked.load(Ordering::SeqCst), 0);
}

/// Negative — an anonymous request within the ceiling is still the floor's `403`, as legacy
/// RustFS's access check answers it: the ceiling moved ahead of the floor, the floor stayed.
#[tokio::test]
async fn n_an_anonymous_claimed_body_within_the_ceiling_is_still_refused_by_the_floor() {
    let (service, seen) = service(true, Decision::Allow);
    let (status, body, polled) = send(&service, anonymous(http::Method::PUT, "/example/admin/v1/import", MIB as u64), MIB).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(polled, 0);
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// Negative — without the switch an anonymous oversized claimed request is the floor's `403`.
#[tokio::test]
async fn n_the_default_refuses_an_anonymous_oversized_claimed_request_at_the_floor() {
    let (service, seen) = service(false, Decision::Allow);
    let length = 2 * MIB;
    let (status, body, polled) =
        send(&service, anonymous(http::Method::PUT, "/example/admin/v1/import", length as u64), length).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(polled, 0);
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// Negative — under the switch an anonymous unclaimed request declaring 2 MiB is not answered
/// with the claimed route's ceiling.
#[tokio::test]
async fn n_an_anonymous_unclaimed_request_is_not_bounded_by_it() {
    let (service, _seen) = service(true, Decision::Allow);
    let length = 2 * MIB;
    let (status, body, _polled) = send(&service, anonymous(http::Method::GET, "/bucket/object", length as u64), length).await;
    assert_ne!(support::element_text(&body, "Code"), Some("EntityTooLarge"), "{status}: {body}");
    assert_ne!(support::element_text(&body, "Message"), Some(REFUSAL), "{status}: {body}");
}

/// Negative — a request presenting a credential the floor cannot read is still refused by the
/// floor ahead of the ceiling: only a request presenting nothing skips the signature.
#[tokio::test]
async fn n_a_malformed_credential_is_refused_before_the_ceiling() {
    let (service, seen) = service(true, Decision::Allow);
    let length = 2 * MIB;
    let request = anonymous(http::Method::PUT, "/example/admin/v1/import", length as u64)
        .header(http::header::AUTHORIZATION, "AWS4-HMAC-SHA256 Credential=broken");
    let (status, body, polled) = send(&service, request, length).await;
    assert_ne!(support::element_text(&body, "Code"), Some("EntityTooLarge"), "{status}: {body}");
    assert!(status.is_client_error(), "{status}: {body}");
    assert_eq!(polled, 0);
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// Refuses every request presented under the custom scheme, counting each one.
struct RefusingVerifier(Arc<AtomicUsize>);

impl SignatureVerifier for RefusingVerifier {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        Verdict::reject(AuthError::AccessDenied)
    }
}

/// Negative — a credential presented under a registered custom scheme is a credential: its
/// verifier answers first, and an oversized claimed body is not refused as too large ahead of it.
#[tokio::test]
async fn n_a_custom_scheme_credential_is_verified_before_the_ceiling() {
    let seen = Arc::new(Seen::default());
    let verified = Arc::new(AtomicUsize::new(0));
    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("a legal custom prefix"))
        .expect("the first scheme is unique");
    let service = support::wired()
        .security_floor(rustfs_gateway::SecurityFloor::new().with_custom_schemes(registry))
        .custom_signature_verifier(RefusingVerifier(Arc::clone(&verified)))
        .authorizer(Counting(Arc::clone(&seen), Decision::Allow))
        .dialect(&dialect())
        .register::<Info, _>(Arc::new(Backend(Arc::clone(&seen))))
        .register::<Import, _>(Arc::new(Backend(Arc::clone(&seen))))
        .bound_claimed_route_bodies_as_legacy_rustfs()
        .build()
        .expect("a complete assembly");
    let length = 2 * MIB;
    let request = anonymous(http::Method::PUT, "/example/admin/v1/import", length as u64).header("x-vendor-auth-token", "opaque");
    let (status, body, polled) = send(&service, request, length).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_ne!(support::element_text(&body, "Code"), Some("EntityTooLarge"), "{body}");
    assert_eq!(verified.load(Ordering::SeqCst), 1, "the custom verifier was not asked");
    assert_eq!(polled, 0);
    assert_eq!(seen.handled.load(Ordering::SeqCst), 0);
}

/// Observe both claimed routes under the floor's chosen recognition policy.
async fn assert_query_credential_response(
    query: &str,
    legacy: bool,
    bounded: bool,
    length: usize,
    expected: (http::StatusCode, &str),
) {
    for (method, path) in [
        (http::Method::PUT, "/example/admin/v1/import"),
        (http::Method::GET, "/example/admin/v1/info"),
    ] {
        let target = format!("{path}?{query}");
        let floor = if legacy {
            SecurityFloor::new().recognize_signatures_as_legacy_rustfs()
        } else {
            SecurityFloor::new()
        };
        let (service, _seen) = service_with_floor(bounded, Decision::Allow, floor);
        let (status, body, polled) = send(&service, anonymous(method, &target, length as u64), length).await;
        assert_eq!(status, expected.0, "{target}, legacy={legacy}, bounded={bounded}: {body}");
        assert_eq!(
            support::element_text(&body, "Code"),
            Some(expected.1),
            "{target}, legacy={legacy}, bounded={bounded}: {body}"
        );
        assert_eq!(
            polled, 0,
            "{target}, legacy={legacy}, bounded={bounded}: the body was read before the refusal"
        );
    }
}

/// An incomplete query credential keeps the unbounded assembly's floor refusal on both routes.
async fn assert_query_credential_is_refused_before_the_ceiling(query: &str) {
    for bounded in [false, true] {
        assert_query_credential_response(query, false, bounded, MIB + 1, (http::StatusCode::FORBIDDEN, "AccessDenied")).await;
    }
}

/// Negative — a query carrying only a SigV4 credential is still an AWS credential attempt.
#[tokio::test]
async fn n_a_query_credential_is_refused_before_the_ceiling() {
    assert_query_credential_is_refused_before_the_ceiling("X-Amz-Credential=broken").await;
}

/// Negative — a query carrying only a SigV4 algorithm is not a request presenting nothing.
#[tokio::test]
async fn n_a_query_algorithm_is_refused_before_the_ceiling() {
    assert_query_credential_is_refused_before_the_ceiling("X-Amz-Algorithm=AWS4-HMAC-SHA256").await;
}

/// Negative — a query carrying only a SigV2 access key is still an AWS credential attempt.
#[tokio::test]
async fn n_a_query_access_key_is_refused_before_the_ceiling() {
    assert_query_credential_is_refused_before_the_ceiling("AWSAccessKeyId=broken").await;
}

/// Positive — under legacy recognition these unsigned query cues remain anonymous, so the
/// anonymous ceiling still precedes the floor.
#[tokio::test]
async fn an_unsigned_query_under_legacy_recognition_is_bounded_as_anonymous() {
    for query in [
        "X-Amz-Credential=broken",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "AWSAccessKeyId=broken",
    ] {
        assert_query_credential_response(query, true, true, MIB + 1, (http::StatusCode::BAD_REQUEST, "EntityTooLarge")).await;
    }
}

/// Negative — legacy recognition still refuses anonymous access at the floor when the ceiling
/// is not exceeded or the ceiling switch is off.
#[tokio::test]
async fn n_an_unsigned_query_under_legacy_recognition_keeps_the_floor_without_a_ceiling_refusal() {
    for query in [
        "X-Amz-Credential=broken",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "AWSAccessKeyId=broken",
    ] {
        for (bounded, length) in [(true, MIB), (false, MIB + 1)] {
            assert_query_credential_response(query, true, bounded, length, (http::StatusCode::FORBIDDEN, "AccessDenied")).await;
        }
    }
}

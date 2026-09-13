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

//! Path-prefix claims, templates, aliases, service-level operations and the per-operation secret
//! through the assembled service (ADR-0024).
//!
//! Responsible for: what the facade pipeline does with a claimed row — no bucket and no key at
//! either authorizer stage or in the handler context, typed path parameters in the context, the
//! claim's own `501` before any authorisation, a refused parameter value before any
//! authorisation — the same for a service-level S3-table row, the secret reaching only an
//! operation that opted in, and a virtual-hosted, presigned or anonymous request never reaching a
//! claimed handler.
//! NOT responsible for: the claim and template rules (`crates/core/tests/dialect_claims*.rs`) or
//! the context's other facts (`request_context_runtime.rs`).
//! Upstream: `rustfs-gateway`, `rustfs-gateway-core`'s dialect types, `support`. Downstream: nothing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{GetObject, GetObjectOutput, HeadObject, HeadObjectOutput};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerContext, HandlerResult, InputAuthzRequest,
    InputDecisions, RegionSet, Req, RequestContext, RequestContextView, Resp, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials, VirtualHostStyle,
};
use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode};
use rustfs_gateway_core::dispatch::NO_CLAIMED_ROUTE_MESSAGE;
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_core::{
    AuthRequirement, ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, DialectRoute, HandlerDeadlineClass, Operation,
    OperationSpec, OverlayRow, PathClaim, Predicate, ResourceShape, ShadowingDecl,
};
use rustfs_gateway_sig::OperationFloor;

use crate::support::{self, SIGNED_AT_STAMP, exchange};

const ACCESS_KEY: &str = "AKIDCLAIMS";
const SECRET: &[u8] = b"claims-runtime-secret-key";
const HOST: &str = "s3.example.com";
const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];

const STATUS: &str = "example:Status";
const JOB: &str = "example:Job";
const SEALED: &str = "example:Sealed";
const HEAD_STATUS: &str = "example:HeadStatus";

// ── the operations ───────────────────────────────────────────────────────────────────────────

/// One vendor operation per index, all bodiless and answered by the recorder.
struct Vendor<const N: usize>;

const NAMES: [&str; 4] = [STATUS, JOB, SEALED, HEAD_STATUS];

const fn spec(name: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("admin:Thing", ResourceShape::Service))
}

static SPECS: [OperationSpec; 4] = [
    spec(STATUS).build(),
    spec(JOB).build(),
    spec(SEALED).hand_caller_secret_to_handler().build(),
    spec(HEAD_STATUS).build(),
];

static FLOORS: [OperationFloor; 4] = [
    OperationFloor::custom(STATUS, SigService::S3),
    OperationFloor::custom(JOB, SigService::S3),
    OperationFloor::custom(SEALED, SigService::S3),
    OperationFloor::custom(HEAD_STATUS, SigService::S3),
];

impl<const N: usize> Operation for Vendor<N> {
    const NAME: &'static str = NAMES[N];
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPECS[N]
    }

    fn floor() -> &'static OperationFloor {
        &FLOORS[N]
    }
}

impl<const N: usize> OperationCodec for Vendor<N> {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<(), CodecError> {
        Ok(())
    }

    fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

// ── the dialect ──────────────────────────────────────────────────────────────────────────────

static GET: &[Predicate] = &[Predicate::Method(http::Method::GET)];
static STATUS_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/example/admin/v1/status",
    selector: GET,
}];
static JOB_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/example/admin/v1/job/{job}/part/{part}",
    selector: GET,
}];
static SEALED_ROWS: &[ClaimedRow] = &[
    ClaimedRow {
        template: "/example/admin/v1/sealed",
        selector: GET,
    },
    ClaimedRow {
        template: "/compat/admin/v1/sealed",
        selector: GET,
    },
];
static HEAD_STATUS_SELECTOR: &[Predicate] = &[
    Predicate::Method(http::Method::HEAD),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent("example-status"),
];
static HEAD_STATUS_SHADOWS: &[ShadowingDecl] = &[ShadowingDecl {
    winner: HEAD_STATUS,
    shadowed: "HeadObject",
    reason: "A HEAD carrying the vendor status key asks for the service status, not the object.",
    evidence: EVIDENCE,
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
    name: "example-claims",
    vendor: "example",
    operations: &[
        row(STATUS, 10, "PathTemplate(\"/example/admin/v1/status\") ∧ Method(GET)"),
        row(JOB, 11, "PathTemplate(\"/example/admin/v1/job/{job}/part/{part}\") ∧ Method(GET)"),
        row(
            SEALED,
            12,
            "PathTemplate(\"/example/admin/v1/sealed\") ∧ Method(GET) ∨ PathTemplate(\"/compat/admin/v1/sealed\") ∧ Method(GET)",
        ),
        row(HEAD_STATUS, 505, "Method(HEAD) ∧ Target(Object) ∧ QueryPresent(\"example-status\")"),
    ],
    claims: &[
        PathClaim {
            prefix: "/example/admin",
            reason: "The vendor serves its admin surface here, ahead of S3.",
            evidence: EVIDENCE,
        },
        PathClaim {
            prefix: "/compat/admin",
            reason: "The vendor's compatibility alias of the same admin surface.",
            evidence: EVIDENCE,
        },
    ],
};

fn dialect() -> Dialect {
    let claimed = |precedence, rows| ClaimedRoute {
        precedence,
        rows,
        shadows: &[],
    };
    Dialect::assemble(&OVERLAY)
        .declare_claimed::<Vendor<0>>(claimed(10, STATUS_ROWS))
        .declare_claimed::<Vendor<1>>(claimed(11, JOB_ROWS))
        .declare_claimed::<Vendor<2>>(claimed(12, SEALED_ROWS))
        .declare::<Vendor<3>>(DialectRoute {
            precedence: 505,
            selector: HEAD_STATUS_SELECTOR,
            path_shape: "/{Bucket}/{Key+}",
            shadows: HEAD_STATUS_SHADOWS,
        })
        .build()
        .expect("the record and the declarations agree")
}

// ── what the pipeline handed over ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct Asked {
    stage: &'static str,
    operation: String,
    bucket: Option<String>,
    key: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct Seen {
    operation: String,
    bucket: Option<String>,
    key: Option<String>,
    raw_path: String,
    params: Vec<(String, String)>,
    part: Option<u32>,
    holds_secret: bool,
}

#[derive(Default)]
struct Recorder {
    asked: Mutex<Vec<Asked>>,
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn ask(&self, stage: &'static str, request: &AuthzRequest<'_>) -> Decision {
        self.asked.lock().expect("uncontended").push(Asked {
            stage,
            operation: request.operation.to_owned(),
            bucket: request.bucket.map(|bucket| bucket.as_str().to_owned()),
            key: request.key.map(|key| key.as_str().to_owned()),
        });
        Decision::Allow
    }

    fn see(&self, context: &RequestContextView) {
        self.seen.lock().expect("uncontended").push(Seen {
            operation: context.operation().to_owned(),
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            key: context.key().map(|key| key.as_str().to_owned()),
            raw_path: context.raw_path().to_owned(),
            params: context
                .path_params()
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            part: context.path_params().parse::<u32>("part").ok(),
            holds_secret: context
                .principal()
                .and_then(|principal| principal.secret_key_from_authenticator_lookup())
                .is_some(),
        });
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().expect("uncontended").clone()
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("uncontended").clone()
    }
}

/// Allows everything and records every question; the recorder is shared with the handlers.
struct RecordingAuthorizer(Arc<Recorder>);

impl Authorizer for RecordingAuthorizer {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.0.ask("route", request);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.0.ask("input", request.route());
        let decisions = request.decide_all(stage, |resource| self.0.ask("resource", resource));
        Box::pin(async move { decisions })
    }
}

impl<const N: usize> Handler<Vendor<N>> for Recorder {
    async fn call(&self, request: Req<Vendor<N>>) -> HandlerResult<Vendor<N>> {
        self.see(request.context());
        Ok(Resp::new(()))
    }

    async fn call_with_context(&self, request: Req<Vendor<N>>, _context: HandlerContext) -> HandlerResult<Vendor<N>> {
        self.see(request.context());
        Ok(Resp::new(()))
    }
}

impl Handler<GetObject> for Recorder {
    async fn call(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        self.see(request.context());
        Ok(Resp::new(GetObjectOutput::default()))
    }

    async fn call_with_context(&self, request: Req<GetObject>, _context: HandlerContext) -> HandlerResult<GetObject> {
        self.see(request.context());
        Ok(Resp::new(GetObjectOutput::default()))
    }
}

impl Handler<HeadObject> for Recorder {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        self.see(request.context());
        Ok(Resp::new(HeadObjectOutput::default()))
    }

    async fn call_with_context(&self, request: Req<HeadObject>, _context: HandlerContext) -> HandlerResult<HeadObject> {
        self.see(request.context());
        Ok(Resp::new(HeadObjectOutput::default()))
    }
}

// ── the service and its requests ─────────────────────────────────────────────────────────────

/// Which operations the assembly lets a handed-over secret reach.
#[derive(Clone, Copy)]
enum Scope {
    /// ADR-0024's default: only operations that opted in.
    OptedIn,
    /// The widened, every-operation scope.
    Every,
}

#[derive(Clone, Copy)]
struct Setup {
    hand_off: Option<Scope>,
    delegate_anonymous: bool,
}

const HAND_OFF: Setup = Setup {
    hand_off: Some(Scope::OptedIn),
    delegate_anonymous: false,
};

fn service(recorder: &Arc<Recorder>, setup: Setup) -> S3Service {
    let credentials = Credentials::new(ACCESS_KEY, SECRET).expect("a valid key");
    let mut authenticator = SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(credentials)),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    );
    if setup.hand_off.is_some() {
        authenticator = authenticator.hand_caller_secret_to_handlers();
    }
    let mut builder = ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(RecordingAuthorizer(Arc::clone(recorder)))
        .host_resolver(VirtualHostStyle::new([HOST]).expect("a well-formed base domain"))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .dialect(&dialect())
        .register::<Vendor<0>, _>(Arc::clone(recorder))
        .register::<Vendor<1>, _>(Arc::clone(recorder))
        .register::<Vendor<2>, _>(Arc::clone(recorder))
        .register::<Vendor<3>, _>(Arc::clone(recorder))
        .register::<GetObject, _>(Arc::clone(recorder))
        .register::<HeadObject, _>(Arc::clone(recorder));
    if matches!(setup.hand_off, Some(Scope::Every)) {
        builder = builder.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report();
    }
    if setup.delegate_anonymous {
        builder =
            builder.security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report());
    }
    builder.build().expect("a complete assembly")
}

fn signing_parts(method: &http::Method, target: &str, host: &str) -> (String, String, http::HeaderMap) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_str(host).expect("a host"));
    let _ = method;
    (path.to_owned(), query.to_owned(), headers)
}

fn signer() -> (SigV4Signer, AmzDate) {
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    (
        SigV4Signer::new(SigningCredentials::new(ACCESS_KEY, SECRET).expect("credentials"), scope),
        stamp,
    )
}

/// `method target` on `host`, header-signed at the fixture clock.
fn signed_on(method: http::Method, target: &str, host: &str) -> http::Request<Bytes> {
    let (path, query, headers) = signing_parts(&method, target, host);
    let raw_host = rustfs_gateway_http::RawHost::from_host_header(host.as_bytes()).expect("an acceptable host");
    let (mut signer, stamp) = signer();
    let signing = SigningRequest::new(&method, &path, &query, &headers, &raw_host, PayloadMode::Empty, stamp);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a request")
}

fn signed(method: http::Method, target: &str) -> http::Request<Bytes> {
    signed_on(method, target, HOST)
}

/// `GET path`, presigned in the query at the fixture clock.
fn presigned(path: &str) -> http::Request<Bytes> {
    let method = http::Method::GET;
    let (path, query, headers) = signing_parts(&method, path, HOST);
    let raw_host = rustfs_gateway_http::RawHost::from_host_header(HOST.as_bytes()).expect("an acceptable host");
    let (mut signer, stamp) = signer();
    let signing = SigningRequest::new(&method, &path, &query, &headers, &raw_host, PayloadMode::Unsigned, stamp);
    let signed = signer.presign(&signing, 900).expect("a signable request");
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a request")
}

fn anonymous(path: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header("host", HOST)
        .body(Bytes::new())
        .expect("a request")
}

async fn run(setup: Setup, request: http::Request<Bytes>) -> (http::StatusCode, String, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let (status, body) = exchange(&service(&recorder, setup), request).await;
    (status, body, recorder)
}

fn assert_nothing_asked_or_handled(recorder: &Recorder) {
    assert!(recorder.asked().is_empty(), "the authorizer was asked: {:?}", recorder.asked());
    assert!(recorder.seen().is_empty(), "a handler ran: {:?}", recorder.seen());
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — a claimed operation is service-level: both authorizer stages and the handler see no
/// bucket and no key, although the path-style resolver would have read `example` as one.
#[tokio::test]
async fn a_claimed_operation_is_authorised_and_handled_with_no_bucket() {
    let (status, body, recorder) = run(HAND_OFF, signed(http::Method::GET, "/example/admin/v1/status")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let asked = recorder.asked();
    let stages: Vec<_> = asked.iter().map(|asked| asked.stage).collect();
    assert_eq!(stages, ["route", "input"]);
    for question in &asked {
        assert_eq!(question.operation, STATUS);
        assert_eq!((question.bucket.as_deref(), question.key.as_deref()), (None, None), "{question:?}");
    }
    let seen = recorder.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].operation, STATUS);
    assert_eq!((seen[0].bucket.as_deref(), seen[0].key.as_deref()), (None, None));
    assert_eq!(seen[0].raw_path, "/example/admin/v1/status");
    assert!(seen[0].params.is_empty());
}

/// Positive — a template's values reach the handler decoded, and parse as typed values.
#[tokio::test]
async fn a_templated_operation_reads_its_typed_values_from_the_context() {
    let (status, body, recorder) = run(HAND_OFF, signed(http::Method::GET, "/example/admin/v1/job/nightly%20run/part/7")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let seen = recorder.seen();
    assert_eq!(seen[0].operation, JOB);
    assert_eq!(
        seen[0].params,
        [
            ("job".to_owned(), "nightly run".to_owned()),
            ("part".to_owned(), "7".to_owned())
        ]
    );
    assert_eq!(seen[0].part, Some(7));
}

/// Positive — the alias row reaches the same operation, and the operation that opted in holds the
/// caller's secret at both rows.
#[tokio::test]
async fn both_rows_of_an_opted_in_operation_receive_the_secret() {
    for path in ["/example/admin/v1/sealed", "/compat/admin/v1/sealed"] {
        let (status, body, recorder) = run(HAND_OFF, signed(http::Method::GET, path)).await;
        assert_eq!(status, http::StatusCode::OK, "{path}: {body}");
        let seen = recorder.seen();
        assert_eq!(seen[0].operation, SEALED, "{path}");
        assert!(seen[0].holds_secret, "{path}");
    }
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// Negative — a service-level operation on an S3-table row never passes the bucket the path names
/// to the authorizer or the handler.
#[tokio::test]
async fn n_a_service_level_s3_table_operation_never_passes_a_bucket() {
    let (status, body, recorder) = run(HAND_OFF, signed(http::Method::HEAD, "/photos/a.png?example-status")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    for question in recorder.asked() {
        assert_eq!(question.operation, HEAD_STATUS);
        assert_eq!((question.bucket, question.key), (None, None));
    }
    let seen = recorder.seen();
    assert_eq!(seen[0].operation, HEAD_STATUS);
    assert_eq!((seen[0].bucket.as_deref(), seen[0].key.as_deref()), (None, None));
    // The standard neighbour on the same path still names its bucket and key.
    let (_, _, recorder) = run(HAND_OFF, signed(http::Method::HEAD, "/photos/a.png")).await;
    let asked = recorder.asked();
    assert_eq!(asked[0].operation, "HeadObject");
    assert_eq!((asked[0].bucket.as_deref(), asked[0].key.as_deref()), (Some("photos"), Some("a.png")));
}

/// Negative — inside the claim, a request no row accepts is the claim's own `501`, answered before
/// the authorizer is asked anything or any handler runs.
#[tokio::test]
async fn n_an_unmatched_claimed_request_is_refused_before_authorisation() {
    for request in [
        signed(http::Method::GET, "/example/admin/v1/nope"),
        signed(http::Method::HEAD, "/example/admin/v1/status"),
        signed(http::Method::GET, "/example/admin/v1/job/a%2Fb/part/1"),
        signed(http::Method::GET, "/example/admin/v1/job/../part/1"),
    ] {
        let target = request.uri().to_string();
        let (status, body, recorder) = run(HAND_OFF, request).await;
        assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED, "{target}: {body}");
        if !body.is_empty() {
            assert!(body.contains(NO_CLAIMED_ROUTE_MESSAGE), "{target}: {body}");
        }
        assert_nothing_asked_or_handled(&recorder);
    }
}

/// Negative — a parameter value no handler may be handed is a `400` naming the parameter, before
/// any authorisation, and the value is not echoed.
#[tokio::test]
async fn n_a_refused_parameter_value_is_a_400_before_authorisation() {
    for (target, echoed) in [
        ("/example/admin/v1/job/a%00b/part/1", "a%00b"),
        ("/example/admin/v1/job/%ff/part/1", "%ff"),
    ] {
        let (status, body, recorder) = run(HAND_OFF, signed(http::Method::GET, target)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target}: {body}");
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
        assert!(!body.contains(echoed), "{body}");
        assert_nothing_asked_or_handled(&recorder);
    }
}

/// Negative — on a virtual host the path is a key in the host's bucket: the claim never reads it,
/// and the request is an ordinary object read authorised on that bucket and key.
#[tokio::test]
async fn n_a_virtual_hosted_request_is_never_captured_by_a_claim() {
    let request = signed_on(http::Method::GET, "/example/admin/v1/status", "photos.s3.example.com");
    let (status, body, recorder) = run(HAND_OFF, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let asked = recorder.asked();
    assert_eq!(asked[0].operation, "GetObject");
    assert_eq!(
        (asked[0].bucket.as_deref(), asked[0].key.as_deref()),
        (Some("photos"), Some("example/admin/v1/status"))
    );
    assert_eq!(recorder.seen()[0].operation, "GetObject");
}

/// Negative — outside the claim, a path-style request in a bucket named like the claim is S3.
#[tokio::test]
async fn n_a_key_outside_the_claim_in_a_bucket_named_like_it_is_s3() {
    let (status, body, recorder) = run(HAND_OFF, signed(http::Method::GET, "/example/administrator.txt")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let asked = recorder.asked();
    assert_eq!(asked[0].operation, "GetObject");
    assert_eq!(
        (asked[0].bucket.as_deref(), asked[0].key.as_deref()),
        (Some("example"), Some("administrator.txt"))
    );
}

/// Negative — with the authenticator's hand-off on, a claimed operation that did not opt in holds
/// no secret; and an operation that opted in holds none when the deployment did not hand it over.
#[tokio::test]
async fn n_the_secret_needs_both_the_operation_and_the_deployment() {
    let (_, _, recorder) = run(HAND_OFF, signed(http::Method::GET, "/example/admin/v1/status")).await;
    assert!(!recorder.seen()[0].holds_secret);
    let no_hand_off = Setup {
        hand_off: None,
        delegate_anonymous: false,
    };
    for path in ["/example/admin/v1/sealed", "/compat/admin/v1/sealed"] {
        let (status, body, recorder) = run(no_hand_off, signed(http::Method::GET, path)).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert_eq!(recorder.seen()[0].operation, SEALED);
        assert!(!recorder.seen()[0].holds_secret, "{path}");
    }
}

/// Positive — under ADR-0022's every-operation scope an operation that never opted in holds the
/// secret too: that scope is the deployment's explicit choice, not the operation's.
#[tokio::test]
async fn the_every_operation_scope_reaches_an_operation_that_did_not_opt_in() {
    let every = Setup {
        hand_off: Some(Scope::Every),
        delegate_anonymous: false,
    };
    let (status, body, recorder) = run(every, signed(http::Method::GET, "/example/admin/v1/status")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorder.seen()[0].operation, STATUS);
    assert!(recorder.seen()[0].holds_secret);
}

/// Negative — a presigned request to a claimed operation is refused before the authorizer: a
/// claimed operation's floor admits header signatures only, and nothing opts it in (ADR-0024).
#[tokio::test]
async fn n_a_presigned_claimed_request_is_refused_before_authorisation() {
    for path in ["/example/admin/v1/status", "/compat/admin/v1/sealed"] {
        let (status, body, recorder) = run(HAND_OFF, presigned(path)).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "{path}: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
        assert_nothing_asked_or_handled(&recorder);
    }
}

/// Negative — an anonymous claimed request is refused before the authorizer, even when anonymous
/// admission is delegated to it (ADR-0021): a vendor operation's floor is privileged.
#[tokio::test]
async fn n_an_anonymous_claimed_request_is_refused_before_authorisation() {
    let delegating = Setup {
        hand_off: Some(Scope::OptedIn),
        delegate_anonymous: true,
    };
    let (status, body, recorder) = run(delegating, anonymous("/example/admin/v1/status")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_nothing_asked_or_handled(&recorder);
}

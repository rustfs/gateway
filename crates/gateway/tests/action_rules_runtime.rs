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

//! ADR-0025's action and subject rules through the assembled service, where the RustFS proof
//! cannot reach.
//!
//! Responsible for: an all-of rule asking every action and refusing when any one is refused,
//! with the input stage re-asking the route's deciding action; and an own-account operation whose
//! floor admits anonymous requests never asking the authorizer about an anonymous caller, even
//! with anonymous admission delegated to it.
//! NOT responsible for: the rule functions (`rustfs-gateway-core`'s unit tests), or the RustFS
//! classes and the bound bucket (`crates/goldens/src/rustfs_admin_proof/class_tests.rs`).
//! Upstream: `rustfs-gateway`, `rustfs-gateway-core`'s dialect types, `support`. Downstream:
//! nothing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerContext, HandlerResult, InputAuthzRequest,
    InputDecisions, RegionSet, Req, RequestContext, Resp, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
    Subject, SubjectRule,
};
use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode};
use rustfs_gateway_core::{
    AuthRequirement, ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, HandlerDeadlineClass, Operation, OperationSpec,
    OverlayRow, PathClaim, Predicate, ResourceShape,
};
use rustfs_gateway_sig::OperationFloor;

use crate::support::{self, SIGNED_AT_STAMP, exchange};

const ACCESS_KEY: &str = "AKIDRULES";
const SECRET: &[u8] = b"action-rules-runtime-secret";
const HOST: &str = "s3.example.com";
const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];

const BOTH: &str = "example:Both";
const MINE: &str = "example:Mine";
const BOTH_ACTIONS: &[&str] = &["admin:A", "admin:B"];
const BOTH_PATH: &str = "/example/admin/v1/both";
const MINE_PATH: &str = "/example/admin/v1/mine";

// ── the operations ───────────────────────────────────────────────────────────────────────────

struct Ruled<const N: usize>;

const NAMES: [&str; 2] = [BOTH, MINE];

const fn spec(index: usize, auth: AuthRequirement) -> OperationSpec {
    OperationSpec::builder(NAMES[index], 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(auth)
        .build()
}

static SPECS: [OperationSpec; 2] = [
    spec(0, AuthRequirement::all_of(BOTH_ACTIONS, ResourceShape::Service)),
    spec(1, AuthRequirement::new(MINE, ResourceShape::Service).about_subject(SubjectRule::Caller)),
];

/// `example:Mine` admits anonymous requests at its floor, so only the facade's own guard stands
/// between an anonymous caller and a question about "its" account.
static FLOORS: [OperationFloor; 2] = [
    OperationFloor::custom(BOTH, SigService::S3),
    OperationFloor::custom(MINE, SigService::S3).allow_anonymous_after_listing_in_the_posture_report(),
];

impl<const N: usize> Operation for Ruled<N> {
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

impl<const N: usize> OperationCodec for Ruled<N> {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<(), CodecError> {
        Ok(())
    }

    fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

static GET: &[Predicate] = &[Predicate::Method(http::Method::GET)];
static BOTH_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: BOTH_PATH,
    selector: GET,
}];
static MINE_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: MINE_PATH,
    selector: GET,
}];

static OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-rules",
    vendor: "example",
    operations: &[
        OverlayRow {
            name: BOTH,
            precedence: 10,
            selector: "PathTemplate(\"/example/admin/v1/both\") ∧ Method(GET)",
            action: "allOf(admin:A, admin:B)",
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: EVIDENCE,
        },
        OverlayRow {
            name: MINE,
            precedence: 11,
            selector: "PathTemplate(\"/example/admin/v1/mine\") ∧ Method(GET)",
            action: "example:Mine about caller",
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: true,
            evidence: EVIDENCE,
        },
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
        .declare_claimed::<Ruled<0>>(claimed(10, BOTH_ROWS))
        .declare_claimed::<Ruled<1>>(claimed(11, MINE_ROWS))
        .build()
        .expect("the record and the declarations agree")
}

// ── the authorizer and the handler ───────────────────────────────────────────────────────────

/// One question: the stage, the action, and whether it was about the caller's own account.
type Asked = (&'static str, String, bool);

/// Allows exactly `allowed`, records every question, and records every handler call.
struct Recorder {
    allowed: &'static [&'static str],
    asked: Mutex<Vec<Asked>>,
    handled: Mutex<Vec<String>>,
}

impl Recorder {
    fn ask(&self, stage: &'static str, request: &AuthzRequest<'_>) -> Decision {
        let about_caller = request.subject == Some(&Subject::Caller);
        self.asked
            .lock()
            .expect("uncontended")
            .push((stage, request.action.to_owned(), about_caller));
        if self.allowed.contains(&request.action) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().expect("uncontended").clone()
    }

    fn handled(&self) -> Vec<String> {
        self.handled.lock().expect("uncontended").clone()
    }
}

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

impl<const N: usize> Handler<Ruled<N>> for Recorder {
    async fn call(&self, request: Req<Ruled<N>>) -> HandlerResult<Ruled<N>> {
        self.handled
            .lock()
            .expect("uncontended")
            .push(request.context().operation().to_owned());
        Ok(Resp::new(()))
    }

    async fn call_with_context(&self, request: Req<Ruled<N>>, _context: HandlerContext) -> HandlerResult<Ruled<N>> {
        self.call(request).await
    }
}

// ── the service and its requests ─────────────────────────────────────────────────────────────

fn service(recorder: &Arc<Recorder>) -> S3Service {
    let credentials = Credentials::new(ACCESS_KEY, SECRET).expect("a valid key");
    let authenticator = SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(credentials)),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    );
    ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(RecordingAuthorizer(Arc::clone(recorder)))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .dialect(&dialect())
        .register::<Ruled<0>, _>(Arc::clone(recorder))
        .register::<Ruled<1>, _>(Arc::clone(recorder))
        .build()
        .expect("a complete assembly")
}

fn signed(path: &str) -> http::Request<Bytes> {
    let method = http::Method::GET;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static(HOST));
    let raw_host = rustfs_gateway_http::RawHost::from_host_header(HOST.as_bytes()).expect("an acceptable host");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let mut signer = SigV4Signer::new(SigningCredentials::new(ACCESS_KEY, SECRET).expect("credentials"), scope);
    let signing = SigningRequest::new(&method, path, "", &headers, &raw_host, PayloadMode::Empty, stamp);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut builder = http::Request::builder().method(method).uri(path);
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

async fn run(allowed: &'static [&'static str], request: http::Request<Bytes>) -> (http::StatusCode, Arc<Recorder>) {
    let recorder = Arc::new(Recorder {
        allowed,
        asked: Mutex::new(Vec::new()),
        handled: Mutex::new(Vec::new()),
    });
    let (status, _body) = exchange(&service(&recorder), request).await;
    (status, recorder)
}

fn route_actions(recorder: &Recorder) -> Vec<String> {
    recorder
        .asked()
        .into_iter()
        .filter(|(stage, ..)| *stage == "route")
        .map(|(_, action, _)| action)
        .collect()
}

// ── all-of ───────────────────────────────────────────────────────────────────────────────────

/// Positive — both actions allowed: both asked in order at the route stage, the first re-asked at
/// the input stage, and the handler runs.
#[tokio::test]
async fn an_all_of_rule_allowed_on_every_action_reaches_the_handler() {
    let (status, recorder) = run(BOTH_ACTIONS, signed(BOTH_PATH)).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(route_actions(&recorder), BOTH_ACTIONS);
    assert!(recorder.asked().contains(&("input", "admin:A".to_owned(), false)));
    assert_eq!(recorder.handled(), [BOTH]);
}

/// Negative — missing either one of the two actions is a refusal before the handler, after both
/// were asked.
#[tokio::test]
async fn n_an_all_of_rule_missing_one_action_is_refused() {
    for held in [&["admin:A"][..], &["admin:B"][..], &[][..]] {
        let (status, recorder) = run(held, signed(BOTH_PATH)).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "holding {held:?}");
        assert_eq!(route_actions(&recorder), BOTH_ACTIONS, "holding {held:?}");
        assert!(recorder.handled().is_empty(), "holding {held:?}");
    }
}

// ── the anonymous-subject guard ──────────────────────────────────────────────────────────────

/// Positive — a signed caller's own-account request is asked about the caller.
#[tokio::test]
async fn a_signed_own_account_request_is_asked_about_the_caller() {
    let (status, recorder) = run(&[MINE], signed(MINE_PATH)).await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(
        recorder
            .asked()
            .iter()
            .all(|(_, action, about_caller)| action == MINE && *about_caller)
    );
    assert_eq!(recorder.handled(), [MINE]);
}

/// Negative — an anonymous caller has no account: with its floor admitting anonymous requests and
/// anonymous admission delegated to an authorizer that would allow it, the request is still
/// refused, and the authorizer is never asked.
#[tokio::test]
async fn n_an_anonymous_own_account_request_is_refused_without_asking() {
    let (status, recorder) = run(&[MINE], anonymous(MINE_PATH)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(recorder.asked().is_empty(), "{:?}", recorder.asked());
    assert!(recorder.handled().is_empty());
}

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

//! The `Authorizer` extension point's contract, from outside the crate that defines it.
//!
//! Responsible for: the three properties no conformance case can express — that the third verdict
//! state reaches the wire as a refusal rather than as an answer or a `500`, that the policy
//! snapshot a request is judged against is taken exactly once, and that the audit sink observes a
//! decision it cannot change.
//! NOT responsible for: the shape of the refusal document (`tests/pipeline.rs`), what routing chose
//! (`tests/vhost_resolution.rs`), or evaluating any policy — this gateway does not have a policy
//! language and never will.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why the fail-closed direction is asserted three ways
//!
//! `Decision::Indeterminate` exists because a provider that cannot answer must not be able to say
//! "allow" by accident, and the accident has a documented shape: rustfs/rustfs's
//! `GHSA-j548-9grx-fh4f` treated an unreadable bucket record as "no Object Lock configured" and
//! deleted a retained object. So the state is asserted at the wire (`403`, not `200` and not
//! `500`), at the handler (never reached), and at the type (`Decision::settle` is total and only
//! `Allow` returns `Ok`).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustfs_gateway::{
    Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, AuthzStage, BoxFuture, Credentials, Decision, DenyAllAuthorizer,
    Identity, InputAuthzRequest, InputDecisions, PolicyError, PolicySnapshot, PolicySource, PolicyTimeout, RegionSet,
    RequestContext, S3Service, ServiceBuilder, SigV4Authenticator, SnapshotId, StaticCredentials, TargetOrigin, allow_when,
    decide_with,
};

use support::vhost_stub::AlwaysVirtualHosted;
use support::{Backend, CountingBackend, CountingBody, Ping, exchange, exchange_wire, ping_route};

// ── the instruments ────────────────────────────────────────────────────────────────────────────

/// A policy source that counts how often the framework asked it for a snapshot.
///
/// The count is the whole point: "one snapshot per request" is not observable from a response, and
/// a source that is asked twice hands the two authorisation readers two different views of policy.
#[derive(Default)]
struct CountingPolicySource {
    calls: AtomicUsize,
    fail: bool,
}

impl CountingPolicySource {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PolicySource for CountingPolicySource {
    fn snapshot<'a>(&'a self, _identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(PolicyError::unavailable())
            } else {
                Ok(PolicySnapshot::of(Arc::new(String::from("a policy document"))))
            }
        })
    }
}

/// An authorizer that answers one fixed verdict and records the snapshot identifier it saw.
struct Fixed {
    verdict: Decision,
    calls: AtomicUsize,
    seen: Mutex<Vec<SnapshotId>>,
    anonymous: Mutex<Vec<bool>>,
}

impl Fixed {
    fn new(verdict: Decision) -> Self {
        Self {
            verdict,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            anonymous: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn snapshots(&self) -> Vec<SnapshotId> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

impl Authorizer for Fixed {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("not poisoned").push(context.policy().id());
        self.anonymous.lock().expect("not poisoned").push(request.is_anonymous());
        let verdict = self.verdict;
        Box::pin(async move { verdict })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("not poisoned").push(context.policy().id());
        self.anonymous
            .lock()
            .expect("not poisoned")
            .push(request.route().is_anonymous());
        let verdict = self.verdict;
        let decisions = request.decide_all(verdict, |_| verdict);
        Box::pin(async move { decisions })
    }
}

struct InputDeny;

impl Authorizer for InputDeny {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Deny, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

struct PanicRoute;

impl Authorizer for PanicRoute {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { panic!("route authorizer panic") })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

struct PendingPolicy;

impl PolicySource for PendingPolicy {
    fn snapshot<'a>(&'a self, _identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        Box::pin(std::future::pending())
    }
}

struct PanickingAudit;

impl AuthzAuditSink for PanickingAudit {
    fn on_decision(&self, _event: &AuthzAuditEvent<'_>) {
        panic!("audit sink panic");
    }
}

/// An audit sink that keeps every event it was handed, flattened into assertable values.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Recorded>>,
    /// Set by the sink and read by nothing in the framework. If a future change ever lets a sink
    /// speak, this is the flag that would carry the word.
    interfered: AtomicBool,
}

#[derive(Clone, Debug)]
struct Recorded {
    stage: AuthzStage,
    operation: String,
    action: String,
    decision: Decision,
    bucket: Option<String>,
    key: Option<String>,
    target_origin: TargetOrigin,
    snapshot: Option<SnapshotId>,
    identity: Option<String>,
    auth_scheme: String,
    rendered: String,
    resources: usize,
    resource_actions: Vec<String>,
}

impl Recorder {
    fn events(&self) -> Vec<Recorded> {
        self.events.lock().expect("not poisoned").clone()
    }
}

impl AuthzAuditSink for Recorder {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        self.interfered.store(true, Ordering::SeqCst);
        self.events.lock().expect("not poisoned").push(Recorded {
            stage: event.stage,
            operation: event.operation.to_owned(),
            action: event.action.to_owned(),
            decision: event.decision,
            bucket: event.bucket.map(|bucket| bucket.as_str().to_owned()),
            key: event.key.map(|key| key.as_str().to_owned()),
            target_origin: event.target_origin,
            snapshot: event.policy_snapshot,
            identity: event.identity.map(|identity| identity.access_key_id().to_owned()),
            auth_scheme: format!("{:?}", event.auth_scheme),
            rendered: format!("{event:?}"),
            resources: event.resources.len(),
            resource_actions: event.resources.iter().map(|resource| resource.action.to_owned()).collect(),
        });
    }
}

// ── assembly ───────────────────────────────────────────────────────────────────────────────────

fn authenticator() -> SigV4Authenticator {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"))
}

fn base() -> ServiceBuilder {
    ServiceBuilder::new()
        .authenticator(authenticator())
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
}

/// A backend for the one AWS operation this suite drives, so that a refusal is about a **bucket**
/// rather than about the service. The handler is never reached: every request that gets this far is
/// refused above it, and that is itself one of the assertions.
struct Listing;

impl rustfs_gateway::Handler<rustfs_gateway::dto::ListObjectsV2> for Listing {
    async fn call(
        &self,
        _request: rustfs_gateway::Req<rustfs_gateway::dto::ListObjectsV2>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::ListObjectsV2> {
        Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::ListObjectsV2Output::default()))
    }
}

struct Copying;

impl rustfs_gateway::Handler<rustfs_gateway::dto::CopyObject> for Copying {
    async fn call(
        &self,
        _request: rustfs_gateway::Req<rustfs_gateway::dto::CopyObject>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::CopyObject> {
        Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::CopyObjectOutput::default()))
    }
}

fn ping() -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

// ── the third verdict state ────────────────────────────────────────────────────────────────────

/// c-azc-0011. Negative — `Indeterminate` is answered `403 AccessDenied`. Not `500`, which some front ends
/// retry and some fail open on, and not `200`. GHSA-j548-9grx-fh4f regression.
#[tokio::test]
async fn n_indeterminate_is_answered_403_access_denied() {
    let service = base()
        .authorizer(decide_with(|_| Decision::Indeterminate))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
}

/// Negative — `Indeterminate` never reaches the handler. A verdict of "I could not decide" that
/// still ran the backend would have decided.
#[tokio::test]
async fn n_indeterminate_never_reaches_the_handler() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = ServiceBuilder::new()
        .authenticator(authenticator())
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .authorizer(decide_with(|_| Decision::Indeterminate))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert_eq!(reached.load(Ordering::SeqCst), 0);

    // The other direction, so that a backend nothing ever reaches cannot satisfy the assertion
    // above by never having been wired.
    let allowed = ServiceBuilder::new()
        .authenticator(authenticator())
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .authorizer(allow_when(|_| true))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&allowed, ping()).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// c-azc-0009. Negative — route refusal happens before the body is polled.
#[tokio::test]
async fn n_route_denial_does_not_read_the_body() {
    let service = base()
        .authorizer(decide_with(|_| Decision::Deny))
        .build()
        .expect("a complete assembly");
    let (body, read) = CountingBody::new(Bytes::from(vec![0_u8; 4096]));
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", "4096")
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

/// c-azc-0010. Negative — the second stage can refuse after decoding and before dispatch.
#[tokio::test]
async fn n_input_denial_never_reaches_the_handler() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = ServiceBuilder::new()
        .authenticator(authenticator())
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .authorizer(InputDeny)
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — `Deny` is answered `403 AccessDenied`, exactly as `Indeterminate` is. The two states
/// differ to the authorizer and are indistinguishable to the caller.
#[tokio::test]
async fn n_deny_and_indeterminate_are_the_same_answer_on_the_wire() {
    let denied = base()
        .authorizer(decide_with(|_| Decision::Deny))
        .build()
        .expect("a complete assembly");
    let unknown = base()
        .authorizer(decide_with(|_| Decision::Indeterminate))
        .build()
        .expect("a complete assembly");
    let (deny_status, deny_body) = exchange(&denied, ping()).await;
    let (unknown_status, unknown_body) = exchange(&unknown, ping()).await;
    assert_eq!(deny_status, unknown_status);
    assert_eq!(redact(&deny_body), redact(&unknown_body));
    assert_eq!(deny_status, http::StatusCode::FORBIDDEN);
}

/// c-azc-0018. Negative — both refusal states pay the same non-zero framework failure floor.
#[tokio::test]
async fn n_deny_and_indeterminate_both_pay_the_failure_floor() {
    for decision in [Decision::Deny, Decision::Indeterminate] {
        let service = base()
            .authorizer(decide_with(move |_| decision))
            .build()
            .expect("a complete assembly");
        let started = Instant::now();
        let (status, _) = exchange(&service, ping()).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN);
        assert!(started.elapsed() >= Duration::from_millis(25));
    }
}

/// c-azc-0030. Negative — an authorizer panic is contained as a `500`, never mistaken for permission.
#[tokio::test]
async fn n_an_authorizer_panic_is_not_allow() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = ServiceBuilder::new()
        .authenticator(authenticator())
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .authorizer(PanicRoute)
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — the settlement of a verdict is total, and only `Allow` continues. Asserted in all
/// three directions so that a fourth state cannot be swept into the allow branch by a wildcard.
#[test]
fn n_only_allow_settles_to_a_continuation() {
    assert!(Decision::Allow.settle().is_ok());
    let deny = Decision::Deny.settle().expect_err("deny does not continue");
    let unknown = Decision::Indeterminate.settle().expect_err("indeterminate does not continue");
    assert_eq!(deny.code(), &rustfs_gateway::ErrorCode::ACCESS_DENIED);
    assert_eq!(unknown.code(), &rustfs_gateway::ErrorCode::ACCESS_DENIED);
    assert_eq!(deny.code(), unknown.code(), "the caller-visible code must be identical");
    assert_ne!(
        deny.decision(),
        unknown.decision(),
        "the operator-side audit decision must remain distinct"
    );
}

// ── the policy snapshot ────────────────────────────────────────────────────────────────────────

/// Negative — the snapshot is taken **once** per request. A second reading is a TOCTOU window
/// between two readers of policy, and nothing in a response would show it.
#[tokio::test]
async fn n_the_policy_snapshot_is_taken_once_per_request() {
    let source = Arc::new(CountingPolicySource::default());
    let service = base()
        .authorizer(allow_when(|_| true))
        .policy_source(Arc::clone(&source))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(source.calls(), 1, "the framework asked the policy source more than once");
}

/// c-azc-0012. Negative — a policy source that cannot answer produces `Indeterminate`, which is `403`. It is
/// not a `500`, and the authorizer is not consulted with a snapshot nobody could take.
#[tokio::test]
async fn n_a_policy_source_failure_denies_and_never_reaches_the_authorizer() {
    let source = Arc::new(CountingPolicySource {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let authorizer = Arc::new(Fixed::new(Decision::Allow));
    let service = base()
        .authorizer(Arc::clone(&authorizer) as Arc<dyn Authorizer>)
        .policy_source(Arc::clone(&source))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(authorizer.calls(), 0, "an unavailable policy must not be judged against");
    assert_eq!(source.calls(), 1);
}

/// c-azc-0013. Negative — a policy source cannot hang the request beyond the configured hard limit.
#[tokio::test]
async fn n_a_policy_source_timeout_is_forced_and_denied() {
    let authorizer = Arc::new(Fixed::new(Decision::Allow));
    let service = base()
        .authorizer(Arc::clone(&authorizer) as Arc<dyn Authorizer>)
        .policy_source(PendingPolicy)
        .policy_timeout(PolicyTimeout::new(Duration::from_millis(5)).expect("a bounded timeout"))
        .build()
        .expect("a complete assembly");
    let started = Instant::now();
    let (status, body) = exchange(&service, ping()).await;
    let elapsed = started.elapsed();

    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(
        elapsed >= Duration::from_millis(5),
        "timeout returned before its configured limit: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(1), "timeout did not bound the request: {elapsed:?}");
    assert_eq!(authorizer.calls(), 0);
}

/// Negative — zero and over-limit timeouts are unrepresentable in a built service.
#[test]
fn n_policy_timeout_is_non_zero_and_bounded() {
    assert!(PolicyTimeout::new(Duration::ZERO).is_err());
    assert!(PolicyTimeout::new(Duration::from_secs(5)).is_ok());
    assert!(PolicyTimeout::new(Duration::from_secs(5) + Duration::from_nanos(1)).is_err());
}

/// Negative — the identifier the authorizer saw is the identifier the audit event carries. Two
/// readings of policy in one request would show up here as two identifiers.
#[tokio::test]
async fn n_the_authorizer_and_the_audit_event_name_one_snapshot() {
    let source = Arc::new(CountingPolicySource::default());
    let authorizer = Arc::new(Fixed::new(Decision::Allow));
    let recorder = Arc::new(Recorder::default());
    let service = base()
        .authorizer(Arc::clone(&authorizer) as Arc<dyn Authorizer>)
        .policy_source(Arc::clone(&source))
        .authz_audit(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::OK);
    let seen = authorizer.snapshots();
    let events = recorder.events();
    assert_eq!(seen.len(), 2);
    assert_eq!(events.len(), 2);
    assert!(seen.iter().all(|snapshot| *snapshot == seen[0]));
    assert!(events.iter().all(|event| event.snapshot == Some(seen[0])));
}

/// Negative — two requests are two snapshots. Without this the identifier comparison above would
/// pass against a constant, which is the shape of defect this repository keeps producing.
#[tokio::test]
async fn n_two_requests_do_not_share_one_snapshot_identifier() {
    let source = Arc::new(CountingPolicySource::default());
    let authorizer = Arc::new(Fixed::new(Decision::Allow));
    let service = base()
        .authorizer(Arc::clone(&authorizer) as Arc<dyn Authorizer>)
        .policy_source(Arc::clone(&source))
        .build()
        .expect("a complete assembly");
    let _ = exchange(&service, ping()).await;
    let _ = exchange(&service, ping()).await;
    let seen = authorizer.snapshots();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[2], seen[3]);
    assert_ne!(seen[0], seen[2], "each request is judged against its own reading of policy");
    assert_eq!(source.calls(), 2);
}

// ── the audit hook ─────────────────────────────────────────────────────────────────────────────

/// c-azc-0003. Positive — an allowed request produces both stage events, and each says what was decided about
/// what.
#[tokio::test]
async fn p_an_allowed_request_produces_two_complete_events() {
    let recorder = Arc::new(Recorder::default());
    let service = base()
        .authorizer(allow_when(|_| true))
        .authz_audit(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::OK);
    let events = recorder.events();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events.iter().map(|event| event.stage).collect::<Vec<_>>(),
        [AuthzStage::Route, AuthzStage::Input]
    );
    for event in &events {
        assert_eq!(event.operation, "example:Ping");
        assert_eq!(event.action, "example:Ping");
        assert_eq!(event.decision, Decision::Allow);
        assert_eq!(event.target_origin, TargetOrigin::Path);
        assert_eq!(event.resources, 1);
        assert_eq!(event.auth_scheme, "Anonymous");
    }
}

/// c-azc-0004. Positive — the input-stage CopyObject event contains the destination and normalized source.
#[tokio::test]
async fn p_copy_object_input_audit_contains_source_and_destination() {
    let recorder = Arc::new(Recorder::default());
    let service = base()
        .register::<rustfs_gateway::dto::CopyObject, _>(Arc::new(Copying))
        .authorizer(allow_when(|_| true))
        .authz_audit(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let request = support::signed_with(http::Method::PUT, "/destination/object", &[("x-amz-copy-source", "/source/original")]);
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let events = recorder.events();
    assert_eq!(events.len(), 2);
    let input = events
        .iter()
        .find(|event| event.stage == AuthzStage::Input)
        .expect("input event");
    assert_eq!(input.resources, 2);
    assert_eq!(input.resource_actions, ["s3:PutObject", "s3:GetObject"]);
    assert_eq!(input.auth_scheme, "Authenticated");
}

/// Negative — a refused request produces an event too, carrying the state that refused it. An
/// audit trail that records only what was allowed is the one nobody can investigate with.
#[tokio::test]
async fn n_a_refusal_is_audited_with_the_state_that_refused_it() {
    for verdict in [Decision::Deny, Decision::Indeterminate] {
        let recorder = Arc::new(Recorder::default());
        let service = base()
            .authorizer(decide_with(move |_| verdict))
            .authz_audit(Arc::clone(&recorder))
            .build()
            .expect("a complete assembly");
        let (status, _) = exchange(&service, ping()).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN);
        let events = recorder.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, verdict, "the wire cannot tell the two apart; the audit trail must");
    }
}

/// Negative — a sink that does everything it can changes nothing. The response of a service with
/// the sink installed is the response of one without it, byte for byte once the per-request
/// identifiers are redacted, and for an allow and a refusal alike.
#[tokio::test]
async fn n_an_audit_sink_cannot_change_the_decision() {
    for (verdict, expected) in [
        (Decision::Allow, http::StatusCode::OK),
        (Decision::Deny, http::StatusCode::FORBIDDEN),
        (Decision::Indeterminate, http::StatusCode::FORBIDDEN),
    ] {
        let recorder = Arc::new(Recorder::default());
        let audited = base()
            .authorizer(decide_with(move |_| verdict))
            .authz_audit(Arc::clone(&recorder))
            .build()
            .expect("a complete assembly");
        let silent = base()
            .authorizer(decide_with(move |_| verdict))
            .build()
            .expect("a complete assembly");
        let (audited_status, audited_body) = exchange(&audited, ping()).await;
        let (silent_status, silent_body) = exchange(&silent, ping()).await;
        assert!(recorder.interfered.load(Ordering::SeqCst), "the sink must have run");
        assert_eq!(audited_status, expected);
        assert_eq!(audited_status, silent_status);
        assert_eq!(redact(&audited_body), redact(&silent_body));
    }
}

/// c-azc-0022. Negative — a sink panic is isolated after the decision and cannot change either direction.
#[tokio::test]
async fn n_an_audit_sink_panic_does_not_change_the_response() {
    for (decision, expected) in [
        (Decision::Allow, http::StatusCode::OK),
        (Decision::Deny, http::StatusCode::FORBIDDEN),
    ] {
        let service = base()
            .authorizer(decide_with(move |_| decision))
            .authz_audit(PanickingAudit)
            .build()
            .expect("a complete assembly");
        let (status, _) = exchange(&service, ping()).await;
        assert_eq!(status, expected);
    }
}

/// c-azc-0023. Negative — the event carries no secret. It is the value most likely to be handed straight to a
/// log aggregator, and the policy document it was judged against is reachable from it only as an
/// opaque identifier.
#[tokio::test]
async fn n_an_audit_event_carries_no_secret_and_no_policy_text() {
    let recorder = Arc::new(Recorder::default());
    let service = base()
        .authorizer(allow_when(|_| true))
        .policy_source(Arc::new(CountingPolicySource::default()))
        .authz_audit(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, support::signed(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    let events = recorder.events();
    assert_eq!(events.len(), 2);
    // The positive control: the caller's public identifier *is* in the event, so the absences
    // below are absences of secrets rather than of a record.
    assert_eq!(events[0].identity.as_deref(), Some("AKIDEXAMPLE"));
    for event in &events {
        let rendered = event.rendered.to_ascii_lowercase();
        for forbidden in ["secret", "signature", "aws4-hmac", "a policy document", "sessiontoken"] {
            assert!(!rendered.contains(forbidden), "the event rendered `{forbidden}`: {rendered}");
        }
    }
}

/// c-azc-0005. Positive — where the bucket name came from is recorded, and it is recorded from the resolution
/// rather than assumed. Both directions, because a field stuck on `Path` satisfies every
/// path-style assertion in this file.
#[tokio::test]
async fn n_the_audited_target_origin_follows_the_resolution_in_both_directions() {
    let by_path = Arc::new(Recorder::default());
    let path_style = base()
        .authorizer(allow_when(|_| true))
        .authz_audit(Arc::clone(&by_path))
        .build()
        .expect("a complete assembly");
    let _ = exchange(&path_style, ping()).await;

    let by_host = Arc::new(Recorder::default());
    let vhost = base()
        .authorizer(allow_when(|_| true))
        .host_resolver(AlwaysVirtualHosted)
        .authz_audit(Arc::clone(&by_host))
        .build()
        .expect("a complete assembly");
    let _ = exchange(&vhost, ping()).await;

    assert_eq!(by_path.events()[0].target_origin, TargetOrigin::Path);
    assert_eq!(by_host.events()[0].target_origin, TargetOrigin::Host);
}

#[path = "authz_contract/oracle.rs"]
mod oracle;
// ── the shipped implementations ────────────────────────────────────────────────────────────────

/// Positive — the shipped refusal is installable behind `Arc<dyn Authorizer>`, which is the
/// property ADR-0002 exists to protect, and a service assembled with it answers `403`.
#[tokio::test]
async fn p_deny_all_is_installable_and_refuses_a_real_request() {
    let service: S3Service = base().authorizer(DenyAllAuthorizer).build().expect("a complete assembly");
    let (status, body) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
}

/// c-azc-0027. Negative — an anonymous request is authorised, not skipped. Anonymity is a result of
/// authentication and never a way around the next stage; rustfs's `GHSA-5qfg-mf7r-jp3w` is what
/// skipping looks like.
#[tokio::test]
async fn n_an_anonymous_request_is_still_authorised() {
    let authorizer = Arc::new(Fixed::new(Decision::Deny));
    let service = base()
        .authorizer(Arc::clone(&authorizer) as Arc<dyn Authorizer>)
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert_eq!(authorizer.calls(), 1);
    assert_eq!(authorizer.anonymous.lock().expect("not poisoned").as_slice(), [true]);
}

/// c-azc-0006. Positive — an anonymous allowed request still traverses both mandatory stages.
#[tokio::test]
async fn p_anonymous_allow_runs_both_authorization_stages() {
    let authorizer = Arc::new(Fixed::new(Decision::Allow));
    let service = base()
        .authorizer(Arc::clone(&authorizer) as Arc<dyn Authorizer>)
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, ping()).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(authorizer.calls(), 2);
    assert_eq!(authorizer.anonymous.lock().expect("not poisoned").as_slice(), [true, true]);
}

// ── helpers ────────────────────────────────────────────────────────────────────────────────────

/// Removes the two per-request identifiers, which differ between any two responses by design.
fn redact(body: &str) -> String {
    let mut text = body.to_owned();
    for element in ["RequestId", "HostId"] {
        let open = format!("<{element}>");
        let close = format!("</{element}>");
        let mut out = String::with_capacity(text.len());
        let mut cursor = text.as_str();
        while let Some(start) = cursor.find(&open) {
            let after = start + open.len();
            let Some(end) = cursor[after..].find(&close) else { break };
            out.push_str(&cursor[..after]);
            out.push_str("REDACTED");
            cursor = &cursor[after + end..];
        }
        out.push_str(cursor);
        text = out;
    }
    text
}

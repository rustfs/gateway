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

//! What the CORS runtime costs, and what it never writes — counted, not inferred.
//!
//! Responsible for: the four properties `conformance/cases/cors/` cannot express, because a case
//! reads a response and these are about what happened *behind* one — how many times the
//! deployment's `CorsSource` was called, whether the governor was consulted before it, and
//! whether a credentials allowance can be reached from a wildcard match through a real assembly.
//! NOT responsible for: matching (`rustfs-gateway-core`'s `cors` inline tests), the wire shape of
//! any answer (`conformance/cases/cors/c-cors-0027` onwards), or the cache's own mechanics
//! (`crate::ext::cors` inline tests).
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why counting is the assertion here
//!
//! The amplifier this task exists to close is not visible in any response. An unauthenticated
//! `GET` carrying an `Origin` is refused with a `403` whether or not it read a bucket's CORS
//! document on the way, and a preflight answers the same `403` whether it read the document once
//! or once per request. A suite that only looked at responses would stay green through the exact
//! regression the design is about — which is the shape of defect this repository has produced
//! seven times. So the source below counts its calls, and the counts are the assertions.
//!
//! Every count is asserted in both directions: a number that is zero because nothing ever calls
//! the source proves nothing, so each zero has a sibling assertion that the same source does get
//! called on the path where it should.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::dto::{CorsConfiguration, CorsRule};
use rustfs_gateway::{
    AuthRequirement, BoxFuture, BucketName, CodecError, CorsOrigins, CorsPolicy, CorsSource, CorsSourceError, Credentials,
    EncodedResponse, FixedClock, Governor, GovernorRequest, Handler, HandlerResult, Lease, MetaView, Operation, OperationCodec,
    OperationFloor, OperationSpec, Predicate, RegionSet, Req, RequestBody, ResourceShape, Resp, ResponseBody, RouteEntry,
    RouteSelector, S3Service, ServiceBuilder, SigService, SigV4Authenticator, StaticCredentials, TargetKind, WireResponse,
    allow_when, collect,
};

/// The origin every rule below names literally.
const NAMED: &str = "https://app.example.com";
/// An origin no rule names literally; only a wildcard can admit it.
const STRANGER: &str = "https://stranger.invalid";
/// The bucket every request addresses.
const BUCKET: &str = "cors-runtime";

// ── a vendor operation on a bucket path, reachable without a signature ──────────────────────────
//
// `rustfs_gateway::sig` cannot produce a signature, so every AWS operation is out of reach here
// and the conformance suite is where the signed paths are exercised. What this file needs is an
// operation on a *bucket* target — the CORS runtime has nothing to say about a service-target
// request — that an anonymous caller can reach, so that the post-authorisation injection runs at
// all. `?corsping` is a query key no AWS operation claims.

struct BucketPing;

struct BucketPingInput;

struct BucketPingOutput;

static BUCKET_PING_SPEC: OperationSpec = OperationSpec::builder("example:BucketPing", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("example:BucketPing", ResourceShape::Bucket))
    .build();

static BUCKET_PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:BucketPing", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

static BUCKET_PING_PREDICATES: &[Predicate] = &[
    Predicate::Method(http::Method::POST),
    Predicate::Target(TargetKind::Bucket),
    Predicate::QueryPresent("corsping"),
    // Disjoint from `DeleteObjects`, the only other `POST` on a bucket, so this entry stands in
    // front of nothing standard and the table builds.
    Predicate::QueryAbsent("delete"),
];

impl Operation for BucketPing {
    const NAME: &'static str = "example:BucketPing";

    type Input = BucketPingInput;
    type Output = BucketPingOutput;
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &BUCKET_PING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &BUCKET_PING_FLOOR
    }
}

impl OperationCodec for BucketPing {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<BucketPingInput, CodecError> {
        Ok(BucketPingInput)
    }

    fn encode(_output: BucketPingOutput, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.set_header("content-type", "application/xml");
        encoded.body = ResponseBody::Complete(b"<Ping/>".to_vec());
        Ok(encoded)
    }
}

struct PingBackend;

impl Handler<BucketPing> for PingBackend {
    async fn call(&self, _request: Req<BucketPing>) -> HandlerResult<BucketPing> {
        Ok(Resp::new(BucketPingOutput))
    }
}

/// A registered AWS read, so that an unsigned request to it is refused by the **security floor**
/// rather than by the absence of a handler. The difference matters: a `501` for an unregistered
/// operation is refused before routing finishes, and asserting no CORS read happened there would
/// prove much less than asserting it about a request that got as far as the floor.
impl Handler<rustfs_gateway::dto::GetObject> for PingBackend {
    async fn call(&self, _request: Req<rustfs_gateway::dto::GetObject>) -> HandlerResult<rustfs_gateway::dto::GetObject> {
        Ok(Resp::new(rustfs_gateway::dto::GetObjectOutput::default()))
    }
}

fn bucket_ping_route() -> RouteEntry {
    RouteEntry {
        precedence: 52,
        selector: RouteSelector::new(BUCKET_PING_PREDICATES),
        op_name: "example:BucketPing",
        path_shape: "/{Bucket}",
    }
}

// ── the source, counting ────────────────────────────────────────────────────────────────────────

/// A `CorsSource` that answers one document for [`BUCKET`] and counts every call.
struct CountingSource {
    reads: Arc<AtomicUsize>,
    document: CorsConfiguration,
}

/// A source failure whose retries are visible at the assembled gateway boundary.
struct FailingSource {
    reads: Arc<AtomicUsize>,
}

impl CorsSource for FailingSource {
    fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(CorsSourceError) })
    }
}

impl CountingSource {
    fn new(reads: &Arc<AtomicUsize>, origins: &[&str], methods: &[&str]) -> Self {
        Self {
            reads: Arc::clone(reads),
            document: CorsConfiguration {
                cors_rules: vec![CorsRule {
                    allowed_methods: methods.iter().map(|m| (*m).to_owned()).collect(),
                    allowed_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
                    ..CorsRule::default()
                }],
            },
        }
    }
}

impl CorsSource for CountingSource {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let found = (bucket.as_str() == BUCKET).then(|| self.document.clone());
        Box::pin(async move { Ok(found) })
    }
}

/// A governor that refuses everything and records what it was asked about.
struct RefusingGovernor {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Governor for RefusingGovernor {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(request.operation().to_owned());
        }
        Box::pin(async { Err(()) })
    }
}

// ── assembly ────────────────────────────────────────────────────────────────────────────────────

struct Built {
    service: S3Service,
    reads: Arc<AtomicUsize>,
}

fn build(origins: &[&str], methods: &[&str], policy: CorsPolicy, governor: Option<RefusingGovernor>) -> Built {
    let reads = Arc::new(AtomicUsize::new(0));
    build_with_source(CountingSource::new(&reads, origins, methods), Arc::clone(&reads), policy, governor)
}

fn build_with_source(
    source: impl CorsSource,
    reads: Arc<AtomicUsize>,
    policy: CorsPolicy,
    governor: Option<RefusingGovernor>,
) -> Built {
    let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id");
    let mut builder = ServiceBuilder::new()
        .register::<BucketPing, _>(Arc::new(PingBackend))
        .register::<rustfs_gateway::dto::GetObject, _>(Arc::new(PingBackend))
        .route(bucket_ping_route())
        .authenticator(SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(credentials)),
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(1_767_225_600),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .cors_source(source)
        .cors_policy(policy);
    if let Some(governor) = governor {
        builder = builder.governor(governor);
    }
    Built {
        service: builder.build().expect("a complete assembly"),
        reads,
    }
}

async fn send(service: &S3Service, method: &str, uri: &str, headers: &[(&str, &str)]) -> WireResponse {
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "host.invalid")
        .body(bytes::Bytes::new())
        .expect("a well-formed fixture request");
    for (name, value) in headers {
        request.headers_mut().append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    collect(service.call_bytes(request).await)
        .await
        .expect("the fixture response body is readable")
}

fn header(response: &WireResponse, name: &str) -> Option<String> {
    response.header(name).map(str::to_owned)
}

const PREFLIGHT: &str = "/cors-runtime/key.txt";
const PING: &str = "/cors-runtime?corsping";

// ── the counts ──────────────────────────────────────────────────────────────────────────────────

/// Negative — an unauthenticated request that never reaches authorisation costs **zero**
/// configuration reads, and the same source does get read on the path that did reach it. Without
/// the second half this assertion is satisfied by a source nothing ever calls.
///
/// This is the amplifier, measured. The pre-authentication `Origin` path is the one an attacker
/// controls for free; if it reached the store, every anonymous request with one header would be a
/// storage read.
#[tokio::test]
async fn an_unauthorised_request_with_an_origin_reads_no_configuration() {
    let built = build(&["*"], &["POST"], CorsPolicy::default(), None);
    // `GetObject` is registered and would answer `200`; the request carries no signature, so the
    // security floor refuses it. That is a refusal from as deep in the pipeline as an
    // unauthenticated caller can reach, which is what makes the count below meaningful.
    let refused = send(&built.service, "GET", PREFLIGHT, &[("origin", STRANGER)]).await;
    assert_eq!(refused.status().as_u16(), 403, "expected the floor's refusal");
    assert_eq!(header(&refused, "access-control-allow-origin"), None);
    assert_eq!(built.reads.load(Ordering::SeqCst), 0, "a refused request read the CORS store");

    // The same source, the same origin, on a request that is authorised.
    let served = send(&built.service, "POST", PING, &[("origin", STRANGER)]).await;
    assert_eq!(served.status().as_u16(), 200);
    assert_eq!(header(&served, "access-control-allow-origin").as_deref(), Some("*"));
    assert_eq!(
        built.reads.load(Ordering::SeqCst),
        1,
        "the authorised request did not read the CORS store"
    );
}

/// Negative — a repeated preflight is one read, not one read per request. The cache is in the
/// only path there is, so this cannot be satisfied by a deployment that forgot to enable it.
#[tokio::test]
async fn a_repeated_preflight_reads_the_configuration_once() {
    let built = build(&[NAMED], &["PUT"], CorsPolicy::default(), None);
    for _ in 0..50 {
        let response = send(
            &built.service,
            "OPTIONS",
            PREFLIGHT,
            &[("origin", NAMED), ("access-control-request-method", "PUT")],
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
    }
    assert_eq!(built.reads.load(Ordering::SeqCst), 1);
}

/// Negative — a preflight for a bucket nobody configured is cached as hard as one for a bucket
/// that is, so the enumeration probe an attacker repeats costs one read however often they repeat
/// it.
#[tokio::test]
async fn a_repeated_preflight_for_an_unknown_bucket_reads_the_configuration_once() {
    let built = build(&[NAMED], &["PUT"], CorsPolicy::default(), None);
    for _ in 0..50 {
        let response = send(
            &built.service,
            "OPTIONS",
            "/never-existed/key.txt",
            &[("origin", NAMED), ("access-control-request-method", "PUT")],
        )
        .await;
        assert_eq!(response.status().as_u16(), 403);
    }
    assert_eq!(built.reads.load(Ordering::SeqCst), 1);
}

/// Negative — a source failure is collapsed into the same cached absence as a missing document.
/// The repeated wire request is important: a response-only assertion cannot distinguish a real
/// collapse from a source that is retried and happens to fail the same way every time.
#[tokio::test]
async fn a_repeated_preflight_for_a_failing_source_reads_once() {
    let reads = Arc::new(AtomicUsize::new(0));
    let built = build_with_source(
        FailingSource {
            reads: Arc::clone(&reads),
        },
        Arc::clone(&reads),
        CorsPolicy::default(),
        None,
    );
    for _ in 0..2 {
        let response = send(
            &built.service,
            "OPTIONS",
            PREFLIGHT,
            &[("origin", NAMED), ("access-control-request-method", "PUT")],
        )
        .await;
        assert_eq!(response.status().as_u16(), 403);
    }
    assert_eq!(built.reads.load(Ordering::SeqCst), 1, "a failed source read was not collapsed");
}

/// Negative — the governor is consulted for a preflight, under its own name, and a refusal stops
/// the request **before** the configuration read. A limit applied after the read is a limit on
/// nothing.
#[tokio::test]
async fn the_governor_runs_before_the_configuration_read() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let built = build(
        &[NAMED],
        &["PUT"],
        CorsPolicy::default(),
        Some(RefusingGovernor { seen: Arc::clone(&seen) }),
    );
    let response = send(
        &built.service,
        "OPTIONS",
        PREFLIGHT,
        &[("origin", NAMED), ("access-control-request-method", "PUT")],
    )
    .await;
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(built.reads.load(Ordering::SeqCst), 0, "the read happened despite the refusal");
    assert_eq!(
        seen.lock().expect("the recorder is not poisoned").as_slice(),
        &["CorsPreflight".to_owned()],
        "the preflight was not limited under its own name"
    );
}

// ── the credential exclusion, through a real assembly ───────────────────────────────────────────

/// Positive — an operator who enumerates an origin and asks for credentials gets them. Without
/// this the exclusion below would be satisfied by an assembly that never writes the header at all,
/// which is the one-directional control AGENTS.md names.
#[tokio::test]
async fn an_enumerated_origin_receives_the_credentials_allowance() {
    let policy = CorsPolicy::new(CorsOrigins::Exact(Box::from([NAMED.to_owned()])), true).expect("an enumerated policy");
    let built = build(&[NAMED], &["POST"], policy, None);
    let response = send(&built.service, "POST", PING, &[("origin", NAMED)]).await;
    assert_eq!(header(&response, "access-control-allow-origin").as_deref(), Some(NAMED));
    assert_eq!(header(&response, "access-control-allow-credentials").as_deref(), Some("true"));
    assert_eq!(header(&response, "vary").as_deref(), Some("origin"));
}

/// Negative — the same policy, and a rule that matches through a wildcard rather than by name:
/// the origin is reflected and the credentials allowance is gone. This is
/// `GHSA-x5xv-223c-8vm7` measured through the assembly a deployment actually builds, rather than
/// through the function that decides it.
#[tokio::test]
async fn a_wildcard_match_never_receives_the_credentials_allowance() {
    let policy = CorsPolicy::new(CorsOrigins::Exact(Box::from([NAMED.to_owned()])), true).expect("an enumerated policy");
    // The rule admits the very origin the policy enumerates, but admits it through a wildcard.
    let built = build(&["https://*.example.com"], &["POST"], policy, None);
    let response = send(&built.service, "POST", PING, &[("origin", NAMED)]).await;
    assert_eq!(
        header(&response, "access-control-allow-origin").as_deref(),
        Some(NAMED),
        "the wildcard must reflect the concrete origin, not answer a star"
    );
    assert_eq!(
        header(&response, "access-control-allow-credentials"),
        None,
        "a reflected origin was paired with a credentials allowance"
    );
}

/// Negative — the bare star, with the same credential-bearing policy in force. The star is the
/// other wildcard form and it has to be excluded too; a browser refuses it beside credentials, but
/// this service must not be the one relying on that.
#[tokio::test]
async fn the_star_never_receives_the_credentials_allowance() {
    let policy = CorsPolicy::new(CorsOrigins::Exact(Box::from([NAMED.to_owned()])), true).expect("an enumerated policy");
    let built = build(&["*"], &["POST"], policy, None);
    let response = send(&built.service, "POST", PING, &[("origin", NAMED)]).await;
    assert_eq!(header(&response, "access-control-allow-origin").as_deref(), Some("*"));
    assert_eq!(header(&response, "access-control-allow-credentials"), None);
}

/// Negative — a preflight is answered without reaching the handler. The handler here answers
/// `<Ping/>`, and the preflight's body is empty: if the branch ever fell through, the assertion
/// that the body is empty is what catches it before the status does.
#[tokio::test]
async fn a_preflight_reaches_no_handler() {
    let built = build(&[NAMED], &["POST"], CorsPolicy::default(), None);
    let response = send(
        &built.service,
        "OPTIONS",
        PING,
        &[("origin", NAMED), ("access-control-request-method", "POST")],
    )
    .await;
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.body().is_empty(), "a preflight answered with a handler's body");
    assert_eq!(header(&response, "content-length").as_deref(), Some("0"));
    // And the same route, reached by the method the preflight described, does answer the handler.
    let served = send(&built.service, "POST", PING, &[("origin", NAMED)]).await;
    assert_eq!(served.body().as_ref(), b"<Ping/>");
}

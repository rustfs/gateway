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

//! The fixtures both integration suites assemble against.
//!
//! Responsible for: a vendor operation that is anonymously reachable, the backends the suites
//! register, a body that counts how much of itself was read, and the two builder shortcuts.
//! NOT responsible for: asserting anything. Every assertion lives in the suite that makes it.
//! Upstream: `rustfs-gateway`. Downstream: `tests/assembly.rs`, `tests/pipeline.rs`.
//!
//! # Why the reachable operation is a vendor one
//!
//! Every AWS operation ships with `AllowedSchemes::HEADER_ONLY`, and `rustfs-gateway-sig` cannot
//! produce a signature yet — `rustfs_gateway::sig::Signer` is the missing piece. So a suite that
//! wants to reach a handler has to drive an operation that declares itself anonymously reachable.
//! The AWS operations are still registered, and what they assert is the refusal.

// Each suite uses a subset of this module, and `unreachable_pub` sees a test binary that never
// re-exports it. Both are properties of a shared test fixture rather than of the code under test.
#![allow(dead_code, unreachable_pub, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::dto::{Bucket, ListBuckets, ListBucketsOutput};
use rustfs_gateway::{
    AuthRequirement, BoxFuture, BucketName, CodecError, Credentials, EncodedResponse, Governor, GovernorRequest, Handler,
    HandlerError, HandlerResult, Lease, MetaView, Observer, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate,
    RegionSet, Req, RequestBody, RequestEvent, ResourceShape, Resp, ResponseBody, RouteEntry, RouteSelector, S3Service,
    ServiceBuilder, SigService, SigV4Authenticator, StaticCredentials, TargetKind, allow_when,
};

// ── a vendor operation, anonymously reachable ──────────────────────────────────────────────────

/// What [`Ping`]'s encoder writes into the identifier headers, so a test can prove it lost.
pub const HANDLER_CHOSEN_ID: &str = "HANDLERCHOSEN000";

/// A vendor operation with a namespaced name and no input.
pub struct Ping;

/// What `example:Ping` decodes to.
pub struct PingInput;

/// What `example:Ping` answers with.
pub struct PingOutput {
    pub message: String,
}

pub static PING_SPEC: OperationSpec = OperationSpec {
    name: "example:Ping",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:Ping", ResourceShape::Service)),
};

pub static PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:Ping", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

/// `POST /`, which no AWS operation claims.
pub static PING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::POST), Predicate::Target(TargetKind::Service)];

impl Operation for Ping {
    const NAME: &'static str = "example:Ping";

    type Input = PingInput;
    type Output = PingOutput;

    fn spec() -> &'static OperationSpec {
        &PING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &PING_FLOOR
    }
}

impl OperationCodec for Ping {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<PingInput, CodecError> {
        Ok(PingInput)
    }

    fn encode(output: PingOutput, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.set_header("content-type", "application/xml");
        // Deliberate: an encoder that claims the identifier headers for itself. The service must
        // overwrite both, so that the value in a log line is always the one the service minted.
        encoded.set_header("x-amz-request-id", HANDLER_CHOSEN_ID);
        encoded.set_header("x-amz-id-2", HANDLER_CHOSEN_ID);
        encoded.body = ResponseBody::Complete(format!("<Ping>{}</Ping>", output.message).into_bytes());
        Ok(encoded)
    }
}

/// The route entry that reaches [`Ping`].
#[must_use]
pub fn ping_route() -> RouteEntry {
    RouteEntry {
        precedence: 50,
        selector: RouteSelector::new(PING_PREDICATES),
        op_name: "example:Ping",
        path_shape: "/",
    }
}

// ── a vendor operation answering HEAD, so the RFC 9110 body rules are reachable ─────────────────

/// The length [`HeadPing`]'s encoder writes into `Content-Length`, and the length of the content it
/// would have sent to a `GET`.
pub const HEAD_PING_LENGTH: usize = 5;

/// A vendor operation reached by `HEAD /`.
///
/// The suite needs one because every AWS `HEAD` operation is header-signatures-only and this crate
/// cannot sign; the point is the method, not the operation.
pub struct HeadPing;

/// Which answer a request asked for. Read from the query, so one operation covers every shape a
/// response can take without a route entry each.
pub enum HeadPingInput {
    /// Answer `200` with content.
    Content,
    /// Refuse with `412`, which renders an `<Error>` document.
    Refuse,
    /// Refuse with `304`, which is bodyless whatever the method.
    NotModified,
    /// Commit the head, then answer.
    CommitThenAnswer,
    /// Commit the head, then fail — the shape `CompleteMultipartUpload` and `CopyObject` need.
    CommitThenFail,
}

pub static HEAD_PING_SPEC: OperationSpec = OperationSpec {
    name: "example:HeadPing",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:HeadPing", ResourceShape::Service)),
};

pub static HEAD_PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:HeadPing", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

/// `HEAD /`, which no AWS operation claims.
pub static HEAD_PING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::HEAD), Predicate::Target(TargetKind::Service)];

/// `PUT /`, which no AWS operation claims either.
///
/// The same operation, the same handler and the same encoder reached by a method that *may* carry
/// content. Without it a `HEAD` assertion could only compare against a number written down by hand,
/// and the number is the half of RFC 9110 §9.3.2 that is easiest to get wrong.
pub static CONTENT_PING_PREDICATES: &[Predicate] =
    &[Predicate::Method(http::Method::PUT), Predicate::Target(TargetKind::Service)];

impl Operation for HeadPing {
    const NAME: &'static str = "example:HeadPing";

    type Input = HeadPingInput;
    type Output = PingOutput;

    fn spec() -> &'static OperationSpec {
        &HEAD_PING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &HEAD_PING_FLOOR
    }
}

impl OperationCodec for HeadPing {
    fn decode(request: &MetaView<'_>, _body: RequestBody) -> Result<HeadPingInput, CodecError> {
        if request.query("refuse").is_some() {
            return Ok(HeadPingInput::Refuse);
        }
        if request.query("not-modified").is_some() {
            return Ok(HeadPingInput::NotModified);
        }
        if request.query("commit-then-answer").is_some() {
            return Ok(HeadPingInput::CommitThenAnswer);
        }
        if request.query("commit-then-fail").is_some() {
            return Ok(HeadPingInput::CommitThenFail);
        }
        Ok(HeadPingInput::Content)
    }

    fn encode(output: PingOutput, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.set_header("content-type", "application/xml");
        // Written by hand because nothing else writes it on the answered path, and it is the number
        // the `HEAD` rule is about: the bytes go, this stays.
        encoded.set_header("content-length", &output.message.len().to_string());
        encoded.body = ResponseBody::Complete(output.message.into_bytes());
        // The same line every generated encoder ends with. It is deliberately *not* the only
        // enforcement: the facade applies the same decision to the refusal path, which never
        // reaches an encoder at all.
        encoded.enforce_http_invariants(request.method());
        Ok(encoded)
    }
}

/// The route entry that reaches [`HeadPing`] under `HEAD`.
#[must_use]
pub fn head_ping_route() -> RouteEntry {
    RouteEntry {
        precedence: 51,
        selector: RouteSelector::new(HEAD_PING_PREDICATES),
        op_name: "example:HeadPing",
        path_shape: "/",
    }
}

/// The twin of [`HeadPing`] reached by a method that may carry content.
///
/// A separate operation rather than a second route entry, because a route table refuses two entries
/// naming one operation. Everything below it is shared: the same input, the same output, the same
/// decoder, the same encoder and the same handler body — so a difference between the two responses
/// is a difference the method made and nothing else.
pub struct ContentPing;

pub static CONTENT_PING_SPEC: OperationSpec = OperationSpec {
    name: "example:ContentPing",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:ContentPing", ResourceShape::Service)),
};

pub static CONTENT_PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:ContentPing", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

impl Operation for ContentPing {
    const NAME: &'static str = "example:ContentPing";

    type Input = HeadPingInput;
    type Output = PingOutput;

    fn spec() -> &'static OperationSpec {
        &CONTENT_PING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &CONTENT_PING_FLOOR
    }
}

/// The header `ContentPing`'s encoder echoes the request's `Content-Length` into.
///
/// It exists so that "a stage filter's rewrite reached the decoder" is an observation and not a
/// claim: the value comes from the `MetaView` the pipeline built, so a filter that did not run
/// leaves the header off entirely.
pub const LENGTH_ECHO: &str = "x-length-seen";

impl OperationCodec for ContentPing {
    fn decode(request: &MetaView<'_>, body: RequestBody) -> Result<HeadPingInput, CodecError> {
        HeadPing::decode(request, body)
    }

    fn encode(output: PingOutput, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = HeadPing::encode(output, request, status)?;
        if let Some(declared) = request.header("content-length") {
            encoded.set_header(LENGTH_ECHO, declared.as_ref());
        }
        Ok(encoded)
    }
}

impl Handler<ContentPing> for Backend {
    async fn call(&self, request: Req<ContentPing>) -> HandlerResult<ContentPing> {
        answer_ping(request.input())
    }
}

/// The route entry that reaches [`ContentPing`].
#[must_use]
pub fn content_ping_route() -> RouteEntry {
    RouteEntry {
        precedence: 52,
        selector: RouteSelector::new(CONTENT_PING_PREDICATES),
        op_name: "example:ContentPing",
        path_shape: "/",
    }
}

/// What a committed answer's encoder is handed: a whole document, declaration included, because that
/// is what a generated encoder produces and the framework has to remove exactly one of them.
#[must_use]
pub fn committed_answer_document() -> String {
    format!("{}<Ping>committed</Ping>", rustfs_gateway::declaration())
}

/// The one answer both twins give, so neither can drift from the other.
///
/// `Resp` rather than `PingOutput`, because two of the five shapes are a *response* decision rather
/// than an output: committing the head is choosing a status before the content exists.
fn answer_ping<O>(input: &HeadPingInput) -> HandlerResult<O>
where
    O: Operation<Output = PingOutput>,
{
    match input {
        HeadPingInput::Content => Ok(Resp::new(PingOutput {
            message: "hello".to_owned(),
        })),
        HeadPingInput::Refuse => Err(HandlerError::precondition_failed("If-Match")),
        HeadPingInput::NotModified => Err(HandlerError::new(
            rustfs_gateway::ErrorCode::NOT_MODIFIED,
            "the representation has not changed",
        )),
        // The head goes out here. What follows can no longer choose a status: the continuation's
        // output type is `Result<O::Output, HandlerError>` and neither arm carries one.
        HeadPingInput::CommitThenAnswer => Ok(Resp::commit(Box::pin(async {
            Ok(PingOutput {
                message: committed_answer_document(),
            })
        }))),
        HeadPingInput::CommitThenFail => Ok(Resp::commit(Box::pin(async {
            Err(HandlerError::new(rustfs_gateway::ErrorCode::NO_SUCH_KEY, "the source is gone"))
        }))),
    }
}

impl Handler<HeadPing> for Backend {
    async fn call(&self, request: Req<HeadPing>) -> HandlerResult<HeadPing> {
        answer_ping(request.input())
    }
}

// ── a vendor operation whose name is not namespaced ─────────────────────────────────────────────

/// A vendor operation that forgot its namespace. Registration must refuse it.
pub struct Unnamespaced;

pub static UNNAMESPACED_SPEC: OperationSpec = OperationSpec {
    name: "Ping",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:Ping", ResourceShape::Service)),
};

pub static UNNAMESPACED_FLOOR: OperationFloor = OperationFloor::custom("Ping", SigService::S3);

impl Operation for Unnamespaced {
    const NAME: &'static str = "Ping";

    type Input = PingInput;
    type Output = PingOutput;

    fn spec() -> &'static OperationSpec {
        &UNNAMESPACED_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &UNNAMESPACED_FLOOR
    }
}

impl OperationCodec for Unnamespaced {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<PingInput, CodecError> {
        Ok(PingInput)
    }

    fn encode(output: PingOutput, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ping::encode(output, request, status)
    }
}

/// A vendor operation wearing an AWS name. Registration must refuse it.
pub struct Impostor;

pub static IMPOSTOR_SPEC: OperationSpec = OperationSpec {
    name: "GetObject",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetObject", ResourceShape::Object)),
};

pub static IMPOSTOR_FLOOR: OperationFloor = OperationFloor::custom("GetObject", SigService::S3);

impl Operation for Impostor {
    const NAME: &'static str = "GetObject";

    type Input = PingInput;
    type Output = PingOutput;

    fn spec() -> &'static OperationSpec {
        &IMPOSTOR_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &IMPOSTOR_FLOOR
    }
}

impl OperationCodec for Impostor {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<PingInput, CodecError> {
        Ok(PingInput)
    }

    fn encode(output: PingOutput, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ping::encode(output, request, status)
    }
}

// ── backends ────────────────────────────────────────────────────────────────────────────────────

/// Answers `example:Ping` and lists two buckets.
pub struct Backend;

impl Handler<Ping> for Backend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

impl Handler<ListBuckets> for Backend {
    async fn call(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        Ok(Resp::new(ListBucketsOutput {
            buckets: vec![Bucket {
                name: BucketName::new("alpha").expect("a valid bucket name"),
                // A real instant, not the default: `CreationDate` is bound to an ISO-8601
                // rendering, and the zero value has none — so a fixture that left it default
                // answered `500 InternalError` the first time anything managed to sign a request
                // and reach the encoder.
                creation_date: rustfs_gateway::Timestamp::from_secs(SIGNED_AT_UNIX_SECONDS),
                ..Bucket::default()
            }],
            ..ListBucketsOutput::default()
        }))
    }
}

impl Handler<Unnamespaced> for Backend {
    async fn call(&self, _request: Req<Unnamespaced>) -> HandlerResult<Unnamespaced> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

impl Handler<Impostor> for Backend {
    async fn call(&self, _request: Req<Impostor>) -> HandlerResult<Impostor> {
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

/// A backend that counts the requests that reached it, so "the handler never ran" is a
/// measurement.
pub struct CountingBackend {
    reached: Arc<AtomicUsize>,
}

impl CountingBackend {
    #[must_use]
    pub fn new(reached: &Arc<AtomicUsize>) -> Self {
        Self {
            reached: Arc::clone(reached),
        }
    }
}

impl Handler<Ping> for CountingBackend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        self.reached.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

/// A backend whose handler always fails, so the failure path can be observed.
pub struct Failing;

impl Handler<Ping> for Failing {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Err(HandlerError::internal_error("the backend is not available"))
    }
}

// ── extension-point fixtures ───────────────────────────────────────────────────────────────────

/// A governor that refuses everything.
pub struct RefuseEverything;

impl Governor for RefuseEverything {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        Box::pin(async { Err(()) })
    }
}

/// An observer that records the status of every request it is told about.
#[derive(Default)]
pub struct Recorder {
    pub seen: std::sync::Mutex<Vec<(Option<String>, u16)>>,
    /// The error code each response carried, if any. Separate from `seen` because a committed
    /// failure is a `200` *and* an error, and a recorder that kept only the status could not say so.
    pub errors: std::sync::Mutex<Vec<Option<String>>>,
}

impl Observer for Recorder {
    fn on_response(&self, event: &RequestEvent<'_>) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((event.operation.map(str::to_owned), event.status));
        }
        if let Ok(mut errors) = self.errors.lock() {
            errors.push(event.error.map(ToString::to_string));
        }
    }
}

/// Drives one request through the tower adapter rather than the inherent entry point.
///
/// Spelled with the fully-qualified call because `S3Service` has an inherent `call` too, and the
/// point of the assertion is which of the two ran.
pub async fn tower_exchange(service: &mut S3Service, request: http::Request<Bytes>) -> (http::StatusCode, String) {
    let (parts, body) = request.into_parts();
    let request = http::Request::from_parts(parts, http_body_util::Full::new(body));
    let response = <S3Service as tower::Service<http::Request<http_body_util::Full<Bytes>>>>::call(service, request)
        .await
        .expect("the adapter's error type is Infallible");
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    (collected.status(), body)
}

/// A body that reports how many of its bytes were ever polled for.
///
/// What makes "the governor refused before the body was read" a measurement rather than a claim.
pub struct CountingBody {
    bytes: Option<Bytes>,
    read: Arc<AtomicU64>,
}

impl CountingBody {
    #[must_use]
    pub fn new(bytes: Bytes) -> (Self, Arc<AtomicU64>) {
        let read = Arc::new(AtomicU64::new(0));
        (
            Self {
                bytes: Some(bytes),
                read: Arc::clone(&read),
            },
            read,
        )
    }
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.bytes.take() {
            Some(bytes) => {
                this.read.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                core::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            None => core::task::Poll::Ready(None),
        }
    }
}

// ── assembly shortcuts ─────────────────────────────────────────────────────────────────────────

/// A builder with the two required extension points installed and nothing registered.
#[must_use]
pub fn wired() -> ServiceBuilder {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .authorizer(allow_when(|_| true))
}

/// The service both suites drive: `example:Ping`, `example:HeadPing` and `ListBuckets`.
#[must_use]
pub fn service() -> S3Service {
    let backend = Arc::new(Backend);
    wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .register::<HeadPing, _>(Arc::clone(&backend))
        .register::<ContentPing, _>(Arc::clone(&backend))
        .register::<ListBuckets, _>(backend)
        .route(ping_route())
        .route(head_ping_route())
        .route(content_ping_route())
        .build()
        .expect("a complete assembly")
}

/// Sends one request and reads the whole answer back.
pub async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> (http::StatusCode, String) {
    let response = service.call_bytes(request).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    (collected.status(), body)
}

/// Sends one request and keeps the whole response, head included.
///
/// `exchange` throws the head away, which is the right shape for an assertion that only reads a
/// body. A case about a header cannot use it.
pub async fn exchange_wire(service: &S3Service, request: http::Request<Bytes>) -> rustfs_gateway::WireResponse {
    let response = service.call_bytes(request).await;
    rustfs_gateway::collect(response).await.expect("an in-memory body")
}

/// The text of the first `<name>` element of a document.
///
/// Enough for an assertion about one element, and deliberately not a parser: a test that needed
/// one would be asserting on `rustfs-gateway-xml` rather than on the pipeline.
#[must_use]
pub fn element_text<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = body.find(&open)? + open.len();
    let end = body.get(start..)?.find(&close)? + start;
    body.get(start..end)
}

/// A `GET`/`POST` with a host and no body.
#[must_use]
pub fn plain(method: http::Method, uri: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

// ── signing, so that "the signature survived" is a measurement ──────────────────────────────────

/// The instant every signed fixture is built at, in the two spellings that must agree: the seconds
/// the service's clock is fixed to, and the `x-amz-date` stamp the signature is scoped by.
///
/// One constant pair rather than two derivations, because a signer and a verifier disagreeing about
/// the day is a `403` that looks exactly like the refusal a negative case is asserting.
pub const SIGNED_AT_UNIX_SECONDS: i64 = 1_767_323_045;
/// The `x-amz-date` spelling of [`SIGNED_AT_UNIX_SECONDS`].
pub const SIGNED_AT_STAMP: &str = "20260102T030405Z";

/// The clock a service must be built with to answer a request from [`signed`].
#[must_use]
pub fn fixed_clock() -> rustfs_gateway::FixedClock {
    rustfs_gateway::FixedClock::at_unix_seconds(SIGNED_AT_UNIX_SECONDS)
}

/// One correctly signed, body-less request against the fixture's credentials.
///
/// `extra` headers are signed along with the rest, which is what lets a case assert that a filter
/// rewriting a **signed** header still leaves the verdict alone.
#[must_use]
pub fn signed_with(method: http::Method, target: &str, extra: &[(&str, &str)]) -> http::Request<Bytes> {
    use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};

    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));

    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        let name: http::HeaderName = name.parse().expect("a header name");
        map.insert(name, http::HeaderValue::from_str(value).expect("a header value"));
    }

    // The canonical request needs the host in the byte-exact form acceptance settles on, and
    // `WireRequest` is the only way to obtain one. A bare probe is used rather than the real head:
    // the real one may be deliberately malformed by the case, and acceptance would refuse it here
    // instead of where the case is looking.
    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");

    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let signing = SigningRequest::new(&method, path, query, &map, accepted.host().raw_for_signing(), PayloadMode::Empty, stamp)
        .with_wire_content_length(0);
    let signed = signer.sign_headers(&signing).expect("a signable request");

    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a valid request")
}

/// [`signed_with`] with no extra headers.
#[must_use]
pub fn signed(method: http::Method, target: &str) -> http::Request<Bytes> {
    signed_with(method, target, &[])
}

/// A builder whose authorizer denies everything, for the assertions about what runs after it.
#[must_use]
pub fn wired_denying() -> ServiceBuilder {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .authorizer(allow_when(|_| false))
}

// ── the GetObjectAttributes fixture, for the OpLayer demonstration ─────────────────────────────

/// What the backend answers, so a rewrite by a layer is visible as a difference from it.
pub const BACKEND_ETAG: &str = "backend-etag";
/// What the demonstration layer writes instead.
pub const LAYER_ETAG: &str = "rewritten-by-a-layer";

/// A backend that answers `GetObjectAttributes` with one entity tag and nothing else.
pub struct Attributes;

impl Handler<rustfs_gateway::dto::GetObjectAttributes> for Attributes {
    async fn call(
        &self,
        _request: Req<rustfs_gateway::dto::GetObjectAttributes>,
    ) -> HandlerResult<rustfs_gateway::dto::GetObjectAttributes> {
        Ok(Resp::new(rustfs_gateway::dto::GetObjectAttributesOutput {
            e_tag: Some(rustfs_gateway::ETag::new(BACKEND_ETAG).expect("a valid entity tag")),
            ..rustfs_gateway::dto::GetObjectAttributesOutput::default()
        }))
    }
}

/// A service over `GetObjectAttributes`, optionally with the demonstration layer installed.
///
/// The layer's body is the three statements the landing table promises, against the one today's
/// tower layer needs a whole XML round trip for.
#[must_use]
pub fn attributes_service(with_layer: bool) -> S3Service {
    use rustfs_gateway::dto::GetObjectAttributes;
    use rustfs_gateway::{BoxFuture, Next, op_layer};

    let builder = wired()
        .clock(fixed_clock())
        .register::<GetObjectAttributes, _>(Arc::new(Attributes));
    let builder = if with_layer {
        builder.op_layer::<GetObjectAttributes, _>(op_layer(
            |request: Req<GetObjectAttributes>, next: Next<'_, GetObjectAttributes>| {
                Box::pin(async move {
                    let mut response = next.run(request).await?;
                    if let Some(output) = response.output_mut() {
                        output.e_tag = Some(rustfs_gateway::ETag::new(LAYER_ETAG).expect("a valid entity tag"));
                    }
                    Ok(response)
                }) as BoxFuture<'_, HandlerResult<GetObjectAttributes>>
            },
        ))
    } else {
        builder
    };
    builder.build().expect("a complete assembly")
}

/// The signed `GetObjectAttributes` request both halves of the demonstration send.
#[must_use]
pub fn attributes_request() -> http::Request<Bytes> {
    signed_with(http::Method::GET, "/bucket/key?attributes", &[("x-amz-object-attributes", "ETag")])
}

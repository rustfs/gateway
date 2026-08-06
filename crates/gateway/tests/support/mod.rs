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
use std::sync::atomic::{AtomicU64, Ordering};

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
}

impl Observer for Recorder {
    fn on_response(&self, event: &RequestEvent<'_>) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((event.operation.map(str::to_owned), event.status));
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

/// The service both suites drive: `example:Ping` plus `ListBuckets`.
#[must_use]
pub fn service() -> S3Service {
    let backend = Arc::new(Backend);
    wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .register::<ListBuckets, _>(backend)
        .route(ping_route())
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

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

//! The caller's secret over a signed body through the assembled service (rustfs/gateway#1587,
//! ADR-0053), for a claimed fixture operation whose body is read whole.
//!
//! Responsible for: which requests hand that operation's handler the caller's secret — a declared
//! digest, signed aws-chunked chunks and the STS body digest do; `UNSIGNED-PAYLOAD`, unsigned
//! streaming with a trailer, a presigned URL and the empty-payload token do not, under the opted-in
//! and the every-operation scope alike — that a declared digest over another body is refused before
//! the handler. An operation that does not opt in beside it is the every-operation control.
//! NOT responsible for: the claim and template rules (`dialect_claims_runtime.rs`), the STS
//! endpoint's own parity (`rustfs-gateway-goldens`), a fallback after a rejected STS-digest
//! comparison (`src/ext/authenticator_sts_body_tests.rs`: the built-in authenticator cannot accept
//! an `sts` scope without the STS body reading, so the fallback cannot be staged here), or the
//! registration refusal of a body not read whole (`rustfs-gateway-core`'s registry tests).
//! Upstream: `rustfs-gateway`, `support`, `bodyless_bodies::streaming_head`, and
//! `sts_body_signature::signed`. Downstream: nothing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{
    Authenticator, Credentials, Handler, HandlerResult, HeaderTokenClaim, HeaderTokenRefused, HeaderTokenVerifier, Identity,
    RegionSet, Req, RequestContextView, RequestNow, Resp, S3Service, ServiceBuilder, SessionBinding, SigV4Authenticator,
    StaticCredentials, VirtualHostStyle, allow_when,
};
use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode};
use rustfs_gateway_core::{
    AuthRequirement, ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, HandlerDeadlineClass, Operation, OperationSpec,
    OverlayRow, PathClaim, Predicate, ResourceShape,
};
use rustfs_gateway_sig::{DeclaredTrailers, OperationFloor, TrailerName};
use sha2::{Digest as _, Sha256};

use crate::bodyless_bodies::streaming_head;
use crate::sts_body_signature::signed as sts_signed;
use crate::support::{self, SIGNED_AT_STAMP};

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET: &str = "secret";
const HOST: &str = "s3.example.com";
const EVIDENCE: &[&str] = &["https://github.com/rustfs/gateway/issues/1587"];
const FORM: &str = "example:Form";
const PLAIN: &str = "example:Plain";
const STS_FORM: &str = "example:StsForm";
const FORM_PATH: &str = "/example/admin/v1/form";
const PLAIN_PATH: &str = "/example/admin/v1/plain";
const STS_FORM_PATH: &str = "/example/admin/v1/sts-form";
const TOKEN_HEADER: &str = "x-auth-token";
const BODY: &[u8] = b"Action=AssumeRole&DurationSeconds=900";
/// The fixture body of the unsigned trailer form, and its base64 CRC32.
const OBJECT: &[u8] = b"hello world";
const OBJECT_CRC32: &str = "DUoRhQ==";
const SESSION_TOKEN: &str = "FwoGZXIvYXdzEXAMPLE-signed-body-session-token";

// ── the operations ───────────────────────────────────────────────────────────────────────────

/// `0`: the signed-body opt-in; `1`: an operation that does not opt in at all; `2`: the signed-body
/// opt-in on an STS-service floor, as `rustfs:StsFormPost` declares.
struct Fixture<const N: usize>;

const NAMES: [&str; 3] = [FORM, PLAIN, STS_FORM];

const fn spec(name: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("example:Write", ResourceShape::Service))
}

static SPECS: [OperationSpec; 3] = [
    spec(FORM).hand_caller_secret_to_handler_over_a_signed_body().build(),
    spec(PLAIN).build(),
    spec(STS_FORM).hand_caller_secret_to_handler_over_a_signed_body().build(),
];
static FLOORS: [OperationFloor; 3] = [
    OperationFloor::builtin_presigned(FORM, SigService::S3),
    OperationFloor::builtin_presigned(PLAIN, SigService::S3),
    OperationFloor::builtin(STS_FORM, SigService::Sts),
];

impl<const N: usize> Operation for Fixture<N> {
    const NAME: &'static str = NAMES[N];
    type Input = Bytes;
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

impl<const N: usize> OperationCodec for Fixture<N> {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::Full;

    fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<Bytes, CodecError> {
        body.into_buffered()
    }

    fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

static PUT: &[Predicate] = &[Predicate::Method(http::Method::PUT)];
static FORM_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: FORM_PATH,
    selector: PUT,
}];
static PLAIN_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: PLAIN_PATH,
    selector: PUT,
}];
static STS_FORM_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: STS_FORM_PATH,
    selector: PUT,
}];

const fn row(name: &'static str, precedence: u16, selector: &'static str) -> OverlayRow {
    OverlayRow {
        name,
        precedence,
        selector,
        action: "example:Write",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }
}

static OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-signed-body",
    vendor: "example",
    operations: &[
        row(FORM, 10, "PathTemplate(\"/example/admin/v1/form\") ∧ Method(PUT)"),
        row(PLAIN, 11, "PathTemplate(\"/example/admin/v1/plain\") ∧ Method(PUT)"),
        row(STS_FORM, 12, "PathTemplate(\"/example/admin/v1/sts-form\") ∧ Method(PUT)"),
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
        .declare_claimed::<Fixture<0>>(claimed(10, FORM_ROWS))
        .declare_claimed::<Fixture<1>>(claimed(11, PLAIN_ROWS))
        .declare_claimed::<Fixture<2>>(claimed(12, STS_FORM_ROWS))
        .build()
        .expect("the record and the declarations agree")
}

// ── what the handler held ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    operation: String,
    principal: bool,
    secret: bool,
    body: Vec<u8>,
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Held>>);

impl Recorder {
    fn see(&self, context: &RequestContextView, body: &Bytes) {
        let principal = context.principal();
        self.0.lock().expect("uncontended").push(Held {
            operation: context.operation().to_owned(),
            principal: principal.is_some(),
            secret: principal
                .and_then(|principal| principal.secret_key_from_authenticator_lookup())
                .is_some(),
            body: body.to_vec(),
        });
    }

    fn held(&self) -> Vec<Held> {
        self.0.lock().expect("uncontended").clone()
    }
}

impl<const N: usize> Handler<Fixture<N>> for Recorder {
    async fn call(&self, request: Req<Fixture<N>>) -> HandlerResult<Fixture<N>> {
        self.see(request.context(), request.input());
        Ok(Resp::new(()))
    }
}

// ── the service ──────────────────────────────────────────────────────────────────────────────

fn sigv4(secret: &str, legacy_sts: bool) -> SigV4Authenticator {
    let credentials = Credentials::new(ACCESS_KEY, secret.as_bytes()).expect("a valid key");
    let authenticator = SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(credentials)),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
    .hand_caller_secret_to_handlers();
    if legacy_sts {
        authenticator.accept_legacy_rustfs_signing_services()
    } else {
        authenticator
    }
}

/// The same authenticator over a temporary credential bound to [`SESSION_TOKEN`].
fn sigv4_session() -> SigV4Authenticator {
    let binding = SessionBinding::new("sts.example", support::SIGNED_AT_UNIX_SECONDS + 3_600).expect("a binding");
    let credentials = Credentials::new(ACCESS_KEY, SECRET.as_bytes())
        .expect("a valid key")
        .with_session(SESSION_TOKEN, binding)
        .expect("a session");
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(credentials)),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
    .hand_caller_secret_to_handlers()
}

fn service(recorder: &Arc<Recorder>, authenticator: impl Authenticator, every_operation: bool) -> S3Service {
    let builder = ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(allow_when(|_| true))
        .host_resolver(VirtualHostStyle::new([HOST]).expect("a well-formed base domain"))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .dialect(&dialect())
        .register::<Fixture<0>, _>(Arc::clone(recorder))
        .register::<Fixture<1>, _>(Arc::clone(recorder))
        .register::<Fixture<2>, _>(Arc::clone(recorder));
    let builder = if every_operation {
        builder.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()
    } else {
        builder
    };
    builder.build().expect("a complete assembly")
}

async fn run_with(
    authenticator: impl Authenticator,
    every_operation: bool,
    request: http::Request<Bytes>,
) -> (http::StatusCode, String, Vec<Held>) {
    let recorder = Arc::new(Recorder::default());
    let (status, body) = support::exchange(&service(&recorder, authenticator, every_operation), request).await;
    (status, body, recorder.held())
}

async fn run(request: http::Request<Bytes>) -> (http::StatusCode, String, Vec<Held>) {
    run_with(sigv4(SECRET, true), false, request).await
}

// ── the requests ─────────────────────────────────────────────────────────────────────────────

/// A header-signed `PUT path` declaring `payload`, carrying `body`.
fn header_signed(path: &str, payload: PayloadMode, body: &[u8]) -> http::Request<Bytes> {
    streaming_head(http::Method::PUT, path, &[], payload, Some(body.len() as u64), None)
        .body(Bytes::copy_from_slice(body))
        .expect("a request")
}

fn digest(body: &[u8]) -> PayloadMode {
    PayloadMode::ExactSha256(Sha256::digest(body).into())
}

/// The STS-scoped header signature over `signed_body` with no payload header, carrying `body`.
fn sts_scoped(path: &str, signed_body: &[u8], body: &[u8]) -> http::Request<Bytes> {
    let mut request = sts_signed(path, "sts", ACCESS_KEY, SECRET, signed_body, Bytes::copy_from_slice(body));
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
    request
}

fn signer() -> (SigV4Signer, AmzDate) {
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new(ACCESS_KEY, SECRET.as_bytes()).expect("credentials");
    (SigV4Signer::new(credentials, scope), stamp)
}

/// `PUT path` presigned in the query over `UNSIGNED-PAYLOAD`, carrying `body`.
fn presigned(path: &str, body: &[u8]) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static(HOST));
    let host = rustfs_gateway_http::RawHost::from_host_header(HOST.as_bytes()).expect("an acceptable host");
    let (mut signer, stamp) = signer();
    let method = http::Method::PUT;
    let signing = SigningRequest::new(&method, path, "", &headers, &host, PayloadMode::Unsigned, stamp);
    let signed = signer.presign(&signing, 900).expect("a signable request");
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("{path}?{}", signed.query()))
        .header(http::header::CONTENT_LENGTH, body.len());
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::copy_from_slice(body)).expect("a request")
}

/// `PUT path` carrying `decoded` as aws-chunked chunks, each signed in the chain the head seeds.
fn chunk_signed(path: &str, decoded: &[u8]) -> http::Request<Bytes> {
    const CHUNK: usize = 16;
    let wire_len = decoded
        .chunks(CHUNK)
        .map(|chunk| chunk.len() + format!("{:x}", chunk.len()).len() + 17 + 64 + 4)
        .sum::<usize>()
        + 1
        + 17
        + 64
        + 4;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static(HOST));
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_len));
    headers.insert("content-encoding", http::HeaderValue::from_static("aws-chunked"));
    let host = rustfs_gateway_http::RawHost::from_host_header(HOST.as_bytes()).expect("an acceptable host");
    let (mut signer, stamp) = signer();
    let method = http::Method::PUT;
    let payload = PayloadMode::StreamingSigned {
        trailer: TrailerSet::None,
    };
    let signing = SigningRequest::new(&method, path, "", &headers, &host, payload, stamp)
        .with_wire_content_length(wire_len as u64)
        .with_decoded_content_length(decoded.len() as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut wire = Vec::with_capacity(wire_len);
    for chunk in decoded.chunks(CHUNK) {
        wire.extend_from_slice(&chain.encode_chunk(chunk));
    }
    wire.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(wire.len(), wire_len, "the signed wire length is the one that was signed");
    let mut builder = http::Request::builder().method(method).uri(path);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::from(wire)).expect("a request")
}

/// `PUT path` declaring `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: header-signed, chunks unsigned.
fn unsigned_streaming(path: &str) -> http::Request<Bytes> {
    let mut wire = format!("{:x}\r\n", OBJECT.len()).into_bytes();
    wire.extend_from_slice(OBJECT);
    wire.extend_from_slice(b"\r\n0\r\n");
    wire.extend_from_slice(format!("x-amz-checksum-crc32:{OBJECT_CRC32}\r\n\r\n").as_bytes());
    let trailer = TrailerSet::Declared(
        DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("a trailer name")], false)
            .expect("a trailer declaration"),
    );
    let payload = PayloadMode::parse("STREAMING-UNSIGNED-PAYLOAD-TRAILER", trailer).expect("an unsigned trailer mode");
    streaming_head(
        http::Method::PUT,
        path,
        &[("content-encoding", "aws-chunked"), ("x-amz-trailer", "x-amz-checksum-crc32")],
        payload,
        Some(wire.len() as u64),
        Some(OBJECT.len() as u64),
    )
    .body(Bytes::from(wire))
    .expect("a request")
}

fn held(operation: &str, secret: bool, body: &[u8]) -> Vec<Held> {
    vec![Held {
        operation: operation.to_owned(),
        principal: true,
        secret,
        body: body.to_vec(),
    }]
}

// ── the cases ────────────────────────────────────────────────────────────────────────────────

/// Positive — every form of a signature over the body hands the handler the caller's secret: a
/// declared digest the facade compares, signed aws-chunked chunks, and the STS body digest the
/// authenticator computes when no payload header is sent.
#[tokio::test]
async fn a_signature_over_the_body_hands_the_handler_the_secret() {
    let (status, answer, seen) = run(header_signed(FORM_PATH, digest(BODY), BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "declared digest: {answer}");
    assert_eq!(seen, held(FORM, true, BODY), "declared digest");

    let (status, answer, seen) = run(chunk_signed(FORM_PATH, BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "signed chunks: {answer}");
    assert_eq!(seen, held(FORM, true, BODY), "signed chunks");

    let (status, answer, seen) = run(sts_scoped(FORM_PATH, BODY, BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "STS body digest: {answer}");
    assert_eq!(seen, held(FORM, true, BODY), "STS body digest");
}

/// Negative — a request whose signature does not cover the body reaches the handler
/// authenticated but without the secret: `UNSIGNED-PAYLOAD`, unsigned streaming with a trailer,
/// and a presigned URL.
#[tokio::test]
async fn n_a_signature_that_does_not_cover_the_body_hands_over_no_secret() {
    let (status, answer, seen) = run(header_signed(FORM_PATH, PayloadMode::Unsigned, BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "UNSIGNED-PAYLOAD: {answer}");
    assert_eq!(seen, held(FORM, false, BODY), "UNSIGNED-PAYLOAD");

    let (status, answer, seen) = run(unsigned_streaming(FORM_PATH)).await;
    assert_eq!(status, http::StatusCode::OK, "unsigned streaming: {answer}");
    assert_eq!(seen, held(FORM, false, OBJECT), "unsigned streaming");

    let (status, answer, seen) = run(presigned(FORM_PATH, BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "presigned: {answer}");
    assert_eq!(seen, held(FORM, false, BODY), "presigned");
}

/// Negative — a declared digest over another body is refused before the handler, so no handler
/// ever held the secret for the swapped body.
#[tokio::test]
async fn n_a_declared_digest_over_another_body_is_refused_before_the_handler() {
    let swapped = b"Action=AssumeRole&DurationSeconds=999";
    assert_eq!(swapped.len(), BODY.len(), "the same length, so only the digest can tell");
    let request = streaming_head(http::Method::PUT, FORM_PATH, &[], digest(BODY), Some(BODY.len() as u64), None)
        .body(Bytes::from_static(swapped))
        .expect("a request");
    let (status, answer, seen) = run(request).await;
    assert!(status.is_client_error(), "{status}: {answer}");
    assert!(seen.is_empty(), "the handler never ran: {seen:?}");
}

/// Negative — the every-operation scope does not lift the signed-body condition: an
/// `UNSIGNED-PAYLOAD` request still reaches the signed-body operation without the secret, while an
/// operation that did not opt in at all receives it there, as that scope says.
#[tokio::test]
async fn n_the_every_operation_scope_keeps_the_signed_body_condition() {
    let (status, answer, seen) = run_with(sigv4(SECRET, true), true, header_signed(FORM_PATH, PayloadMode::Unsigned, BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "{answer}");
    assert_eq!(seen, held(FORM, false, BODY), "the signed-body operation");

    let (status, answer, seen) =
        run_with(sigv4(SECRET, true), true, header_signed(PLAIN_PATH, PayloadMode::Unsigned, BODY)).await;
    assert_eq!(status, http::StatusCode::OK, "{answer}");
    assert_eq!(seen, held(PLAIN, true, BODY), "the every-operation control");
}

/// A header-signed `PUT` of the form path declaring `payload` and carrying the session token.
fn session_signed(payload: PayloadMode) -> http::Request<Bytes> {
    streaming_head(
        http::Method::PUT,
        FORM_PATH,
        &[("x-amz-security-token", SESSION_TOKEN)],
        payload,
        Some(BODY.len() as u64),
        None,
    )
    .body(Bytes::from_static(BODY))
    .expect("a request")
}

/// Positive and negative — a temporary credential is held to the same condition: its own secret
/// reaches the handler over a declared digest and not over `UNSIGNED-PAYLOAD`.
#[tokio::test]
async fn a_session_credential_holds_its_secret_only_over_a_signed_body() {
    let (status, answer, seen) = run_with(sigv4_session(), false, session_signed(digest(BODY))).await;
    assert_eq!(status, http::StatusCode::OK, "{answer}");
    assert_eq!(seen, held(FORM, true, BODY), "a session over a declared digest");

    let (status, answer, seen) = run_with(sigv4_session(), false, session_signed(PayloadMode::Unsigned)).await;
    assert_eq!(status, http::StatusCode::OK, "{answer}");
    assert_eq!(seen, held(FORM, false, BODY), "a session over UNSIGNED-PAYLOAD");
}

/// Negative — a temporary credential presented without its token is refused before the handler,
/// over a signed body too, so no handler holds its secret.
#[tokio::test]
async fn n_a_session_credential_without_its_token_is_refused_before_the_handler() {
    let request = header_signed(FORM_PATH, digest(BODY), BODY);
    let (status, answer, seen) = run_with(sigv4_session(), false, request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{answer}");
    assert!(seen.is_empty(), "the handler never ran: {seen:?}");
}

/// What the fixture host's outer token layer leaves in a request once it validated the token.
#[derive(Clone)]
struct Established(&'static str);

/// The fixture host: it names the principal its outer layer established.
struct TokenHost;

impl HeaderTokenVerifier for TokenHost {
    type Established = Established;

    fn identity(&self, established: &Established, _now: RequestNow) -> Result<Identity, HeaderTokenRefused> {
        Identity::new(established.0).map_err(|_| HeaderTokenRefused)
    }
}

/// `PUT path` whose only credential is the claimed header token, with its principal established.
async fn by_header_token(path: &str) -> (http::StatusCode, String, Vec<Held>) {
    let claim = HeaderTokenClaim::new(TOKEN_HEADER).expect("a legal claim");
    let recorder = Arc::new(Recorder::default());
    let service = ServiceBuilder::new()
        .authenticator(sigv4(SECRET, true))
        .authorizer(allow_when(|_| true))
        .security_floor(SecurityFloor::new().with_header_token_claim(claim))
        .host_verified_header_token(claim, TokenHost)
        .host_resolver(VirtualHostStyle::new([HOST]).expect("a well-formed base domain"))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .dialect(&dialect())
        .register::<Fixture<0>, _>(Arc::clone(&recorder))
        .register::<Fixture<1>, _>(Arc::clone(&recorder))
        .register::<Fixture<2>, _>(Arc::clone(&recorder))
        .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()
        .build()
        .expect("a complete assembly");
    let mut request = http::Request::builder()
        .method(http::Method::PUT)
        .uri(path)
        .header(http::header::HOST, HOST)
        .header(http::header::CONTENT_LENGTH, BODY.len())
        .header(TOKEN_HEADER, "header-token-fixture")
        .body(Bytes::from_static(BODY))
        .expect("a request");
    request.extensions_mut().insert(Established("TOKENUSER"));
    let (status, body) = support::exchange(&service, request).await;
    (status, body, recorder.held())
}

/// Negative — a header-token verdict looked up no secret and is no `RequestPrincipal`, so a
/// header-token request reaches a signed-body operation without one, even in the every-operation
/// scope; an
/// STS-service floor, as `rustfs:StsFormPost`'s is, refuses the scheme before any handler
/// (ADR-0054).
#[tokio::test]
async fn n_a_header_token_request_holds_no_secret_and_the_sts_floor_refuses_it() {
    let (status, answer, seen) = by_header_token(FORM_PATH).await;
    assert_eq!(status, http::StatusCode::OK, "{answer}");
    // A header-token verdict is no `RequestPrincipal`, so no principal could carry a secret either.
    assert_eq!(
        seen,
        [Held {
            operation: FORM.to_owned(),
            principal: false,
            secret: false,
            body: BODY.to_vec(),
        }],
        "a header token over the signed-body operation"
    );

    let (status, answer, seen) = by_header_token(STS_FORM_PATH).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{answer}");
    assert!(seen.is_empty(), "an STS floor refuses the header token before any handler: {seen:?}");
}

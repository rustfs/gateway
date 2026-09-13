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

//! The server-side-encryption properties no conformance case can express.
//!
//! Responsible for: the transport gate driven through a real assembly **in both directions** —
//! the corpus can only ever run in cleartext, so the served half of the gate exists nowhere else;
//! the proof that a handler which writes a customer key onto a response does not get it out; that
//! the handler is not reached at all when the gate refuses; the multipart binding, which needs two
//! requests and a backend that remembers the first; and **which of the two request heads the gate
//! reads**, now that `StageFilter::on_wire` can rewrite one of them.
//! NOT responsible for: the value rules — the strict decoders, the digest agreement, the channel
//! exclusivity and the constant sentences all live beside their code in
//! `rustfs_gateway_core::sse`. Nor for the refused half of the gate as a *wire* answer, which
//! `conformance/cases/ssec/` pins because the runner is always in cleartext.
//! Upstream: `rustfs-gateway`. Downstream: nothing; this is a leaf test.
//!
//! # Why this file exists rather than more cases
//!
//! `crates/conformance`'s runner has no socket. `RUN_OVER_TLS` is a constant `false`, and both
//! transports refuse a `[connection.tls]` block outright, so a case can *declare*
//! `applies_to.tls = "required"` and will then be skipped on every run — which is a case that
//! cannot fail, and this repository has produced seven of those already. The cleartext half of
//! the gate is a corpus case (`c-ssec-0001`, `c-ssec-0002`); the encrypted half is here, where a
//! test can put a `TransportSecurity` into a request's extensions the way a TLS-terminating
//! transport will.
//!
//! A wire filter is the same story for a different reason: a conformance case configures no
//! deployment code, so the head a filter produced is not a head the corpus can ask for.
//!
//! # Why every assertion has its opposite
//!
//! A gate that refuses everything satisfies every refusal case, and a strip that removes every
//! header satisfies every "the key is gone" case. So the served request sits beside the refused
//! one, the stripped header sits beside the two headers that must survive, and the handler's
//! call counter is asserted to be non-zero somewhere before it is asserted to be zero.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{
    AuthRequirement, CodecError, EncodedResponse, FixedClock, Handler, HandlerError, HandlerResult, KeyFingerprint, MetaView,
    Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, Req, RequestBody, ResourceShape, Resp, ResponseBody,
    S3Service, ServiceBuilder, SigService, SseConfig, StageFilter, TargetKind, TransportSecurity, WireHead, WireResponse,
    allow_when, check_part, collect, wire_filter,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, HandlerDeadlineClass, OverlayRow};
use rustfs_gateway_types::ErrorCode;

/// A 32-byte key and its true MD5.
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const MD5_A: &str = "tP/LI3N87DFaSk0aoqYgzg==";
/// A different key and its true MD5.
const KEY_B: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
const MD5_B: &str = "v2HomVYPq94vbXb0BabrcA==";

const SSEC_ALGORITHM: &str = "x-amz-server-side-encryption-customer-algorithm";
const SSEC_KEY: &str = "x-amz-server-side-encryption-customer-key";
const SSEC_KEY_MD5: &str = "x-amz-server-side-encryption-customer-key-md5";

const OBJECT: &str = "/sse-runtime/object.bin?sseput";
const PART: &str = "/sse-runtime/object.bin?ssepart";

// ── two vendor operations on an object path, reachable without a signature ──────────────────────
//
// `rustfs_gateway::sig` produces no signature inside this crate's tests, so every AWS operation
// is out of reach and the corpus is where the signed paths run. What is needed here is any
// operation on an *object* target that an anonymous caller can reach: the enforcement runs for
// every operation, so which one it is carries no information.

/// The state a backend would keep for one multipart upload: the digest the upload was created
/// with, and how many times a handler ran.
#[derive(Default)]
struct Backend {
    bound: std::sync::Mutex<Option<KeyFingerprint>>,
    calls: AtomicUsize,
}

struct SsePut;
struct SsePart;

/// Deliberately empty decoder output.
///
/// The backend must use `Req::sse`, not reconstruct the proof from a codec-specific field. Keeping
/// an always-empty slot makes a mutation back to `request.input().0` compile and fail at run time.
struct PresentedKey(Option<KeyFingerprint>);

struct Answered;

static PUT_SPEC: OperationSpec = OperationSpec::builder("example:SsePut", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:SsePut", ResourceShape::Object))
    .build();

static PART_SPEC: OperationSpec = OperationSpec::builder("example:SsePart", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:SsePart", ResourceShape::Object))
    .build();

static PUT_FLOOR: OperationFloor =
    OperationFloor::custom("example:SsePut", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();
static PART_FLOOR: OperationFloor =
    OperationFloor::custom("example:SsePart", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

// `POST` on an object, and disjoint from every standard entry by construction.
//
// Two constraints decide this shape. The route table's default `ShadowingPolicy` asks for a
// declaration for **every** cross-precedence overlap, and `ServiceBuilder` publishes no way to
// write one — so a vendor entry has to be disjoint from every standard entry, not merely earlier
// than them. And `PUT` on an object is out for that reason: `PutObject` is `Method(PUT) ∧
// Target(Object)` with no further constraint, so every `PUT` on an object overlaps it and no
// number of `QueryAbsent` predicates helps. `POST` on an object has no such catch-all — the four
// standard entries each require their own query key — so naming those four, plus each other, makes
// these two disjoint from the whole table. The enforcement under test is operation-agnostic
// (`rustfs_gateway_core::sse::tests::n_the_gate_is_the_same_for_a_bucket_target_as_for_an_object`),
// so which method carries it says nothing about the property.
static PUT_PREDICATES: &[Predicate] = &[
    Predicate::Method(http::Method::POST),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent("sseput"),
    Predicate::QueryAbsent("ssepart"),
    Predicate::QueryAbsent("uploadId"),
    Predicate::QueryAbsent("uploads"),
    Predicate::QueryAbsent("restore"),
    Predicate::QueryAbsent("select"),
];

static PART_PREDICATES: &[Predicate] = &[
    Predicate::Method(http::Method::POST),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent("ssepart"),
    Predicate::QueryAbsent("sseput"),
    Predicate::QueryAbsent("uploadId"),
    Predicate::QueryAbsent("uploads"),
    Predicate::QueryAbsent("restore"),
    Predicate::QueryAbsent("select"),
];

static SSE_TEST_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-sse-test",
    vendor: "example",
    operations: &[
        OverlayRow {
            name: "example:SsePut",
            precedence: 52,
            selector: "Method(POST) ∧ Target(Object) ∧ QueryPresent(\"sseput\") ∧ QueryAbsent(\"ssepart\") ∧ QueryAbsent(\"uploadId\") ∧ QueryAbsent(\"uploads\") ∧ QueryAbsent(\"restore\") ∧ QueryAbsent(\"select\")",
            action: "example:SsePut",
            resource: ResourceShape::Object,
            success_status: 200,
            anonymous: true,
            evidence: &["https://github.com/rustfs/gateway/issues/37"],
        },
        OverlayRow {
            name: "example:SsePart",
            precedence: 52,
            selector: "Method(POST) ∧ Target(Object) ∧ QueryPresent(\"ssepart\") ∧ QueryAbsent(\"sseput\") ∧ QueryAbsent(\"uploadId\") ∧ QueryAbsent(\"uploads\") ∧ QueryAbsent(\"restore\") ∧ QueryAbsent(\"select\")",
            action: "example:SsePart",
            resource: ResourceShape::Object,
            success_status: 200,
            anonymous: true,
            evidence: &["https://github.com/rustfs/gateway/issues/37"],
        },
    ],
};

fn sse_test_dialect() -> Dialect {
    Dialect::assemble(&SSE_TEST_OVERLAY)
        .declare::<SsePut>(DialectRoute {
            precedence: 52,
            selector: PUT_PREDICATES,
            path_shape: "/{Bucket}/{Key+}",
            shadows: &[],
        })
        .declare::<SsePart>(DialectRoute {
            precedence: 52,
            selector: PART_PREDICATES,
            path_shape: "/{Bucket}/{Key+}",
            shadows: &[],
        })
        .build()
        .expect("the SSE test overlay and codec declarations must agree")
}

impl Operation for SsePut {
    const NAME: &'static str = "example:SsePut";
    type Input = PresentedKey;
    type Output = Answered;
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}
    fn spec() -> &'static OperationSpec {
        &PUT_SPEC
    }
    fn floor() -> &'static OperationFloor {
        &PUT_FLOOR
    }
}

impl Operation for SsePart {
    const NAME: &'static str = "example:SsePart";
    type Input = PresentedKey;
    type Output = Answered;
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}
    fn spec() -> &'static OperationSpec {
        &PART_SPEC
    }
    fn floor() -> &'static OperationFloor {
        &PART_FLOOR
    }
}

/// Reads the presented fingerprint, and writes the whole SSE-C header group back — **including
/// the key**.
///
/// The echo is deliberate and is the mutation target: this encoder is a backend behaving badly,
/// and the assertion is that the framework's response invariant removes the key anyway while
/// leaving the algorithm and the digest, which AWS does return.
fn decode_presented(request: &MetaView<'_>) -> Result<PresentedKey, CodecError> {
    let _ = request;
    Ok(PresentedKey(None))
}

fn encode_echoing_everything(status: u16) -> Result<EncodedResponse, CodecError> {
    let mut encoded = EncodedResponse::of(status);
    encoded.set_header(SSEC_ALGORITHM, "AES256");
    encoded.set_header(SSEC_KEY_MD5, MD5_A);
    // A backend behaving badly, on purpose. See `decode_presented`.
    encoded.set_header(SSEC_KEY, KEY_A);
    encoded.body = ResponseBody::Complete(b"<Ok/>".to_vec());
    Ok(encoded)
}

impl OperationCodec for SsePut {
    fn decode(request: &MetaView<'_>, _body: RequestBody) -> Result<PresentedKey, CodecError> {
        decode_presented(request)
    }
    fn encode(_output: Answered, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        encode_echoing_everything(status)
    }
}

impl OperationCodec for SsePart {
    fn decode(request: &MetaView<'_>, _body: RequestBody) -> Result<PresentedKey, CodecError> {
        decode_presented(request)
    }
    fn encode(_output: Answered, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        encode_echoing_everything(status)
    }
}

impl Handler<SsePut> for Backend {
    async fn call(&self, request: Req<SsePut>) -> HandlerResult<SsePut> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.input().0.is_some() {
            return Err(HandlerError::internal_error("the fixture decoder unexpectedly carried an SSE proof"));
        }
        if let Ok(mut bound) = self.bound.lock() {
            *bound = request.sse().customer_key_fingerprint().copied();
        }
        Ok(Resp::new(Answered))
    }

    async fn call_with_context(&self, request: Req<SsePut>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<SsePut> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.input().0.is_some() {
            return Err(HandlerError::internal_error("the fixture decoder unexpectedly carried an SSE proof"));
        }
        if let Ok(mut bound) = self.bound.lock() {
            *bound = request.sse().customer_key_fingerprint().copied();
        }
        Ok(Resp::new(Answered))
    }
}

impl Handler<SsePart> for Backend {
    async fn call(&self, request: Req<SsePart>) -> HandlerResult<SsePart> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bound = match self.bound.lock() {
            Ok(bound) => *bound,
            Err(_) => return Err(HandlerError::internal_error("the fixture's upload state is poisoned")),
        };
        // The cross-request rule the framework cannot apply for a backend, applied by the backend
        // through the framework's one function.
        check_part(bound.as_ref(), request.sse().customer_key_fingerprint()).map_err(|_| {
            HandlerError::new(ErrorCode::INVALID_ARGUMENT, "the part's encryption headers do not match the upload's")
        })?;
        Ok(Resp::new(Answered))
    }

    async fn call_with_context(&self, request: Req<SsePart>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<SsePart> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bound = match self.bound.lock() {
            Ok(bound) => *bound,
            Err(_) => return Err(HandlerError::internal_error("the fixture's upload state is poisoned")),
        };
        // The cross-request rule the framework cannot apply for a backend, applied by the backend
        // through the framework's one function.
        check_part(bound.as_ref(), request.sse().customer_key_fingerprint()).map_err(|_| {
            HandlerError::new(ErrorCode::INVALID_ARGUMENT, "the part's encryption headers do not match the upload's")
        })?;
        Ok(Resp::new(Answered))
    }
}

fn build(sse: SseConfig) -> (S3Service, Arc<Backend>) {
    build_with(sse, None)
}

fn build_with(sse: SseConfig, filter: Option<Arc<dyn StageFilter>>) -> (S3Service, Arc<Backend>) {
    let backend = Arc::new(Backend::default());
    let mut builder = ServiceBuilder::new()
        .register::<SsePut, _>(Arc::clone(&backend))
        .register::<SsePart, _>(Arc::clone(&backend))
        .dialect(&sse_test_dialect())
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            Arc::new(rustfs_gateway::StaticCredentials::new()),
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(1_767_225_600),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .sse_config(sse);
    if let Some(filter) = filter {
        builder = builder.stage_filter(filter);
    }
    (builder.build().expect("a complete assembly"), backend)
}

/// A wire filter that writes the whole customer-key trio onto every request.
fn filter_that_adds_the_trio() -> Arc<dyn StageFilter> {
    Arc::new(wire_filter(|head: &mut WireHead<'_>| {
        head.set_header(http::HeaderName::from_static(SSEC_ALGORITHM), http::HeaderValue::from_static("AES256"))?;
        head.set_header(http::HeaderName::from_static(SSEC_KEY), http::HeaderValue::from_static(KEY_A))?;
        head.set_header(http::HeaderName::from_static(SSEC_KEY_MD5), http::HeaderValue::from_static(MD5_A))?;
        Ok(())
    }))
}

/// A wire filter that deletes the whole customer-key trio from every request.
fn filter_that_removes_the_trio() -> Arc<dyn StageFilter> {
    Arc::new(wire_filter(|head: &mut WireHead<'_>| {
        for name in [SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5] {
            head.remove_header(&http::HeaderName::from_static(name))?;
        }
        Ok(())
    }))
}

/// Sends one request, with or without a transport that declares TLS.
async fn send(service: &S3Service, target: &str, headers: &[(&str, &str)], transport: Option<TransportSecurity>) -> WireResponse {
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(bytes::Bytes::new())
        .expect("a well-formed fixture request");
    for (name, value) in headers {
        request.headers_mut().append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    if let Some(transport) = transport {
        // Exactly what a TLS-terminating transport does, and the only channel that is believed.
        request.extensions_mut().insert(transport);
    }
    collect(service.call_bytes(request).await)
        .await
        .expect("the fixture response body is readable")
}

fn trio(key: &'static str, digest: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![(SSEC_ALGORITHM, "AES256"), (SSEC_KEY, key), (SSEC_KEY_MD5, digest)]
}

/// Every byte a caller can see: the status line's headers and the body, rendered together.
fn everything_the_caller_sees(response: &WireResponse) -> Vec<u8> {
    let mut seen = Vec::new();
    for (name, value) in response.headers() {
        seen.extend_from_slice(name.as_str().as_bytes());
        seen.push(b':');
        seen.extend_from_slice(value.as_bytes());
        seen.push(b'\n');
    }
    seen.extend_from_slice(response.body());
    seen
}

// ── the gate, both directions ────────────────────────────────────────────────────────────────

/// Positive — over a connection the transport declared encrypted, the request is served.
///
/// The half of the gate the conformance corpus cannot reach: its runner has no socket and
/// `RUN_OVER_TLS` is a constant `false`.
#[tokio::test]
async fn a_customer_key_over_a_declared_tls_connection_is_served() {
    let (service, backend) = build(SseConfig::strict());
    let response = send(&service, OBJECT, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(response.status().as_u16(), 200, "body: {:?}", response.body());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "the handler must have run");
    assert!(
        backend.bound.lock().expect("the fixture's upload state").is_some(),
        "the handler received an empty decoder field instead of the pipeline-produced SSE proof"
    );
}

/// Negative — the same request with no transport declaration is refused, and the handler is never
/// reached.
///
/// "Never reached" is the assertion that matters: a refusal rendered *after* a handler saw the key
/// is a refusal that already handed the key to whatever the handler does with one.
#[tokio::test]
async fn n_a_customer_key_over_cleartext_is_refused_before_the_handler() {
    let (service, backend) = build(SseConfig::strict());
    let response = send(&service, OBJECT, &trio(KEY_A, MD5_A), None).await;
    assert_eq!(response.status().as_u16(), 400);
    let body = String::from_utf8_lossy(response.body()).into_owned();
    assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");
    assert!(body.contains("must be made over a secure connection"), "{body}");
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0, "the handler saw a key it should never have seen");
}

/// Negative — the gate is not simply refusing everything.
///
/// Three requests through the same cleartext assembly: one with a key, refused; two without,
/// served. A gate stuck closed passes the case above and fails this one.
#[tokio::test]
async fn n_the_gate_refuses_the_key_and_not_the_request() {
    let (service, backend) = build(SseConfig::strict());
    assert_eq!(send(&service, OBJECT, &trio(KEY_A, MD5_A), None).await.status().as_u16(), 400);
    assert_eq!(send(&service, OBJECT, &[], None).await.status().as_u16(), 200);
    assert_eq!(
        send(&service, OBJECT, &[("x-amz-server-side-encryption", "AES256")], None)
            .await
            .status()
            .as_u16(),
        200,
        "the managed channel puts no key on the wire and must not be gated"
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}

/// Negative — a caller cannot open the gate by claiming its own connection was encrypted.
#[tokio::test]
async fn n_a_forwarded_protocol_header_does_not_open_the_gate() {
    let (service, _) = build(SseConfig::strict());
    for claim in [
        ("x-forwarded-proto", "https"),
        ("x-forwarded-protocol", "https"),
        ("x-forwarded-ssl", "on"),
        ("front-end-https", "on"),
    ] {
        let mut headers = trio(KEY_A, MD5_A);
        headers.push(claim);
        let response = send(&service, OBJECT, &headers, None).await;
        assert_eq!(response.status().as_u16(), 400, "{} opened the gate", claim.0);
    }
}

/// Negative — the acknowledged allowance serves, and the strict default does not.
///
/// Two assemblies, one request. Without both halves the switch could be hard-wired either way.
#[tokio::test]
async fn n_the_plaintext_allowance_takes_effect_only_when_acknowledged() {
    let (strict, _) = build(SseConfig::strict());
    assert_eq!(send(&strict, OBJECT, &trio(KEY_A, MD5_A), None).await.status().as_u16(), 400);

    let (relaxed, backend) = build(SseConfig::allowing_customer_keys_over_plaintext(
        rustfs_gateway::PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear(),
    ));
    assert_eq!(send(&relaxed, OBJECT, &trio(KEY_A, MD5_A), None).await.status().as_u16(), 200);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

// ── the key never comes back ─────────────────────────────────────────────────────────────────

/// Negative — a backend that writes the key onto its response does not get it out, and the two
/// headers AWS does return survive.
#[tokio::test]
async fn n_a_backend_that_echoes_the_customer_key_does_not_get_it_onto_the_wire() {
    let (service, _) = build(SseConfig::strict());
    let response = send(&service, OBJECT, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.header(SSEC_KEY).is_none(), "the key header reached the wire");
    assert_eq!(response.header(SSEC_ALGORITHM), Some("AES256"), "the algorithm must survive");
    assert_eq!(response.header(SSEC_KEY_MD5), Some(MD5_A), "the key digest must survive");
}

/// Negative — nothing a caller can read contains the key, in either its base64 spelling or its
/// decoded bytes, on the served path or on the refused one.
///
/// This is the assertion the mutation table's hardest row targets: put the key into a refusal
/// message or into a response header and this goes red.
#[tokio::test]
async fn n_no_response_byte_carries_the_key_in_either_spelling() {
    let raw_key: [u8; 32] = core::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
    let (service, _) = build(SseConfig::strict());
    let responses = [
        // Served, over TLS, by a backend that tried to echo the key.
        send(&service, OBJECT, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await,
        // Refused by the transport gate.
        send(&service, OBJECT, &trio(KEY_A, MD5_A), None).await,
        // Refused because the key and the digest disagree.
        send(&service, OBJECT, &trio(KEY_A, MD5_B), Some(TransportSecurity::Encrypted)).await,
        // Refused because the key is not thirty-two bytes.
        send(&service, OBJECT, &trio("QUJD", MD5_A), Some(TransportSecurity::Encrypted)).await,
    ];
    for response in &responses {
        let seen = everything_the_caller_sees(response);
        let text = String::from_utf8_lossy(&seen);
        assert!(!text.contains(KEY_A), "the key's base64 text reached the caller:\n{text}");
        assert!(
            !seen.windows(raw_key.len()).any(|window| window == raw_key),
            "the key's decoded bytes reached the caller"
        );
    }
}

/// Negative — the two ways to get the pair wrong produce byte-identical answers.
///
/// A response that differed would tell a caller which half it had guessed right, one request at a
/// time. The request identifier is minted per request, so it is excluded from the comparison and
/// nothing else is.
#[tokio::test]
async fn n_a_wrong_key_and_a_wrong_digest_are_answered_identically() {
    let (service, _) = build(SseConfig::strict());
    let wrong_digest = send(&service, OBJECT, &trio(KEY_A, MD5_B), Some(TransportSecurity::Encrypted)).await;
    let wrong_key = send(&service, OBJECT, &trio(KEY_B, MD5_A), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(wrong_digest.status(), wrong_key.status());
    assert_eq!(redacted(&wrong_digest), redacted(&wrong_key));
}

/// The response body with the per-request identifiers blanked, so two refusals can be compared.
fn redacted(response: &WireResponse) -> String {
    let body = String::from_utf8_lossy(response.body()).into_owned();
    let mut out = String::new();
    let mut rest = body.as_str();
    for tag in ["RequestId", "HostId"] {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        while let (Some(start), Some(end)) = (rest.find(&open), rest.find(&close)) {
            if start > end {
                break;
            }
            out.push_str(&rest[..start.saturating_add(open.len())]);
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out
}

// ── the multipart binding ────────────────────────────────────────────────────────────────────

/// Positive — a part repeating the upload's key is served.
#[tokio::test]
async fn a_part_repeating_the_upload_s_key_is_served() {
    let (service, backend) = build(SseConfig::strict());
    let begin = send(&service, OBJECT, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(begin.status().as_u16(), 200);
    let part = send(&service, PART, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(part.status().as_u16(), 200, "body: {:?}", part.body());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}

/// Negative — a part under a different key is refused.
#[tokio::test]
async fn n_a_part_under_a_different_key_is_refused() {
    let (service, _) = build(SseConfig::strict());
    send(&service, OBJECT, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    let part = send(&service, PART, &trio(KEY_B, MD5_B), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(part.status().as_u16(), 400);
    assert!(String::from_utf8_lossy(part.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — a part that drops the headers on an encrypted upload is refused.
#[tokio::test]
async fn n_an_unencrypted_part_of_an_encrypted_upload_is_refused() {
    let (service, _) = build(SseConfig::strict());
    send(&service, OBJECT, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    let part = send(&service, PART, &[], Some(TransportSecurity::Encrypted)).await;
    assert_eq!(part.status().as_u16(), 400);
}

/// Negative — and the other way round: a key on a part of an upload that has none.
#[tokio::test]
async fn n_an_encrypted_part_of_an_unencrypted_upload_is_refused() {
    let (service, _) = build(SseConfig::strict());
    let begin = send(&service, OBJECT, &[], Some(TransportSecurity::Encrypted)).await;
    assert_eq!(begin.status().as_u16(), 200);
    let part = send(&service, PART, &trio(KEY_A, MD5_A), Some(TransportSecurity::Encrypted)).await;
    assert_eq!(part.status().as_u16(), 400);
}

/// Negative — a part of an unencrypted upload that also carries no key is served, so the rule
/// above is a comparison and not a blanket refusal of the second request.
#[tokio::test]
async fn n_an_unencrypted_part_of_an_unencrypted_upload_is_served() {
    let (service, backend) = build(SseConfig::strict());
    send(&service, OBJECT, &[], Some(TransportSecurity::Encrypted)).await;
    let part = send(&service, PART, &[], Some(TransportSecurity::Encrypted)).await;
    assert_eq!(part.status().as_u16(), 200, "body: {:?}", part.body());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
}

// ── which head the gate reads ────────────────────────────────────────────────────────────────
//
// P6-01 put a `StageFilter::on_wire` seam **before** `WireRequest::accept`, and a filter there may
// add or remove any header but `host`. That creates two heads: the snapshot taken before the seam,
// which every signature-adjacent stage reads so that a filter cannot forge or break a signature,
// and the post-seam head that acceptance, routing, decoding and the handler all read.
//
// **This gate reads the post-seam head** — `MetaView`, the same value the decoder builds the
// operation's input from. That is the only choice that closes both holes, and the four cases below
// are the two directions of each:
//
// * reading the *snapshot* would let a filter that ADDS the trio hand a key to a handler over a
//   cleartext connection that the gate never looked at — the smuggle;
// * reading the snapshot would also make a filter that REMOVES the trio refuse a request that no
//   longer carries a key at all, which is not a security property, just a wrong answer.
//
// The invariant underneath is simpler than either: **the gate and every consumer of the key read
// one head.** There is no window between them for anything to change. A filter is deployment code
// inside the trust boundary, so "a filter added a key" is the deployment's decision — and it is
// still subject to the gate, which is what the first pair asserts.

/// Negative — a filter that adds the trio over cleartext does not smuggle the key past the gate.
///
/// The request arrives carrying nothing. If the gate read the pre-seam snapshot it would see no
/// customer-key header, serve the request, and hand the filter's key to the handler in cleartext.
#[tokio::test]
async fn n_a_wire_filter_cannot_smuggle_a_customer_key_past_the_gate() {
    let (service, backend) = build_with(SseConfig::strict(), Some(filter_that_adds_the_trio()));
    let response = send(&service, OBJECT, &[], None).await;
    assert_eq!(response.status().as_u16(), 400, "a filter-added key was served over cleartext");
    let body = String::from_utf8_lossy(response.body()).into_owned();
    assert!(body.contains("must be made over a secure connection"), "{body}");
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        0,
        "the handler was reached with a key the gate never checked"
    );
}

/// Positive — the same filter over a declared-TLS connection is served, so the case above is the
/// gate firing and not the filter itself being refused.
#[tokio::test]
async fn a_wire_filter_that_adds_the_trio_is_served_over_tls() {
    let (service, backend) = build_with(SseConfig::strict(), Some(filter_that_adds_the_trio()));
    let response = send(&service, OBJECT, &[], Some(TransportSecurity::Encrypted)).await;
    assert_eq!(response.status().as_u16(), 200, "body: {:?}", response.body());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert!(response.header(SSEC_KEY).is_none(), "the filter's key was echoed back");
}

/// Negative — a filter that removes the trio leaves nothing for the gate to refuse, **and nothing
/// for the handler to receive**.
///
/// This is the direction that would be a defect if the two heads disagreed: the request is served,
/// so the assertion that matters is not the status but that the key is gone from the head the
/// decoder reads. A gate on the snapshot would refuse here; a gate on the post-seam head serves,
/// and the handler sees no key because there is none.
#[tokio::test]
async fn n_a_wire_filter_that_removes_the_trio_leaves_no_key_for_the_handler() {
    let (service, backend) = build_with(SseConfig::strict(), Some(filter_that_removes_the_trio()));
    let response = send(&service, OBJECT, &trio(KEY_A, MD5_A), None).await;
    assert_eq!(response.status().as_u16(), 200, "body: {:?}", response.body());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert!(
        backend.bound.lock().expect("the fixture's upload state").is_none(),
        "the decoder saw a key the filter had removed: the gate and the decoder are reading different heads"
    );
}

/// Negative — without the filter the identical request is refused, so the case above measures the
/// filter and not a gate that had stopped working.
#[tokio::test]
async fn n_the_same_request_without_the_removing_filter_is_still_refused() {
    let (service, backend) = build(SseConfig::strict());
    let response = send(&service, OBJECT, &trio(KEY_A, MD5_A), None).await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[path = "sse_runtime/context.rs"]
mod context;

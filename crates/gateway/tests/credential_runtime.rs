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

//! The credential-provider properties that need a whole assembly to be visible.
//!
//! Responsible for: **when** the provider is consulted (never on a path the request has not
//! already earned, never for an anonymous request), and **what the caller can tell apart** once it
//! has been — an unknown access key, an expired session, a session credential used without its
//! token, a long-term credential used with one, and a disabled credential must all produce the
//! same bytes; and the *ordering* proof that none of those rules answered before the signature was
//! compared.
//! NOT responsible for: the value rules on [`rustfs_gateway::Credentials`] and
//! [`rustfs_gateway::SessionBinding`], which live beside their code; nor the wire form of the
//! rejection, which `conformance/cases/cred/` pins byte for byte against a running server.
//! Upstream: `rustfs-gateway`. Downstream: nothing; this is a leaf test.
//!
//! # Why the ordering is asserted with a wrong signature rather than with a clock
//!
//! "The expiry check does not short-circuit" is a statement about latency, and this repository has
//! already shipped one timing assertion that passed 440 runs and proved nothing. It is asserted
//! here as a *behavioural* consequence instead: a credential that is expired **and** carries a
//! wrong signature answers the exact same bytes as an unknown access key, not an expiry answer.
//! That can only be true if the expiry verdict was computed and then held until after the
//! comparison — a check that returned on the spot would answer the expiry condition and the
//! assertion would go red. No clock is read, so there is nothing for a loaded runner to perturb.
//!
//! # Why every assertion has its opposite
//!
//! A provider that is never called satisfies every "the provider was not called" case, and a
//! service that refuses everything satisfies every rejection case. So the call counter is asserted
//! non-zero before it is asserted zero, and each refusal sits beside the accepted request that
//! differs from it in exactly one way.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SessionToken, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};
use rustfs_gateway::{
    AuthRequirement, BoxFuture, ClockSkewAck, CodecError, CredentialGuardConfig, CredentialLookup, CredentialProvider,
    Credentials, DEFAULT_MAX_BUFFERED_BODY_BYTES, EncodedResponse, FixedClock, GovernorRates, Handler, HandlerResult, Limits,
    MetaView, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, ProviderError, Rate, RegionSet, Req,
    RequestBody, ResourceShape, Resp, ResponseBody, S3Service, ServiceBuilder, ServiceConfig, SessionBinding, SigV4Authenticator,
    StaticCredentials, TargetKind, WireRequest, WireResponse, allow_when, collect,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, HandlerDeadlineClass, OverlayRow};

/// The instant every request in this file is signed at and judged against.
const NOW: i64 = 1_767_225_600;
/// One hour after [`NOW`]: a session that is still live.
const LATER: i64 = NOW + 3_600;
/// One hour before [`NOW`]: a session that is not.
const EARLIER: i64 = NOW - 3_600;
/// The `YYYYMMDDTHHMMSSZ` spelling of [`NOW`]. Fixed rather than computed, so a defect in the
/// formatter cannot make the request and the assertion agree with each other and with nothing else.
const STAMP: &str = "20260101T000000Z";

const HOST: &str = "creds.example.com";
const REGION: &str = "us-east-1";
const TARGET: &str = "/creds-runtime/object.bin?credprobe";

const LONG_TERM_KEY: &str = "AKIDLONGTERMEXAMPLE";
const SESSION_KEY: &str = "AKIDSESSIONEXAMPLE";
const EXPIRED_KEY: &str = "AKIDEXPIREDEXAMPLE";
const DISABLED_KEY: &str = "AKIDDISABLEDEXAMPLE";
const UNKNOWN_KEY: &str = "AKIDUNKNOWNEXAMPLE";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const WRONG_SECRET: &[u8] = b"this-is-not-the-secret-the-target-knows-";
const TOKEN: &str = "FQoGZXIvYXdzEExampleSessionTokenValue";
const OTHER_TOKEN: &str = "FQoGZXIvYXdzEAnotherSessionTokenValue";
const LOG_CAPTURE_CHILD: &str = "GATEWAY_C_SIG_0128_LOG_CAPTURE_CHILD";
const LOG_CAPTURE_POISON: &str = "GATEWAY_C_SIG_0128_LOG_CAPTURE_POISON";
const LOG_CAPTURE_MARKER: &str = "c-sig-0128 request path completed";

// ── one vendor operation on an object path, reachable only with a signature ─────────────────────

struct CredProbe;
struct Nothing;
struct Answered;

static SPEC: OperationSpec = OperationSpec::builder("example:CredProbe", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:CredProbe", ResourceShape::Object))
    .build();

/// No `allow_anonymous_after_listing_in_the_posture_report`: this operation demands a signature,
/// which is what makes the provider reachable at all.
static FLOOR: OperationFloor = OperationFloor::custom("example:CredProbe", SigService::S3);

static PREDICATES: &[Predicate] = &[
    Predicate::Method(http::Method::POST),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent("credprobe"),
    Predicate::QueryAbsent("uploadId"),
    Predicate::QueryAbsent("uploads"),
    Predicate::QueryAbsent("restore"),
    Predicate::QueryAbsent("select"),
];

static CRED_PROBE_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-credential-test",
    vendor: "example",
    operations: &[OverlayRow {
        name: "example:CredProbe",
        precedence: 52,
        selector: "Method(POST) ∧ Target(Object) ∧ QueryPresent(\"credprobe\") ∧ QueryAbsent(\"uploadId\") ∧ QueryAbsent(\"uploads\") ∧ QueryAbsent(\"restore\") ∧ QueryAbsent(\"select\")",
        action: "example:CredProbe",
        resource: ResourceShape::Object,
        success_status: 200,
        anonymous: false,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

fn cred_probe_dialect() -> Dialect {
    Dialect::assemble(&CRED_PROBE_OVERLAY)
        .declare::<CredProbe>(DialectRoute {
            precedence: 52,
            selector: PREDICATES,
            path_shape: "/{Bucket}/{Key+}",
            shadows: &[],
        })
        .build()
        .expect("the credential probe overlay and codec declaration must agree")
}

impl Operation for CredProbe {
    const NAME: &'static str = "example:CredProbe";
    type Input = Nothing;
    type Output = Answered;
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }
    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl OperationCodec for CredProbe {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<Nothing, CodecError> {
        Ok(Nothing)
    }
    fn encode(_output: Answered, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.body = ResponseBody::Complete(b"<Ok/>".to_vec());
        Ok(encoded)
    }
}

struct Backend;

impl Handler<CredProbe> for Backend {
    async fn call(&self, _request: Req<CredProbe>) -> HandlerResult<CredProbe> {
        Ok(Resp::new(Answered))
    }

    async fn call_with_context(
        &self,
        _request: Req<CredProbe>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<CredProbe> {
        Ok(Resp::new(Answered))
    }
}

// ── a provider that counts, wrapping the fixture set ────────────────────────────────────────────

/// The fixture credential set, plus how many times anything asked it a question.
///
/// The counter is the instrument for "the provider is not on the unauthenticated path": a
/// framework that consulted it before the floor had admitted the request would turn every forged
/// header into a backend round trip.
struct Counting {
    inner: StaticCredentials,
    calls: AtomicUsize,
}

impl Counting {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialProvider for Counting {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.lookup(access_key_id)
    }
}

fn fixtures() -> Arc<Counting> {
    let live = SessionBinding::new("sts.example.com", LATER).expect("a well-formed binding");
    let dead = SessionBinding::new("sts.example.com", EARLIER).expect("a well-formed binding");
    let entries = StaticCredentials::new()
        .with(Credentials::new(LONG_TERM_KEY, SECRET).expect("valid"))
        .with(
            Credentials::new(SESSION_KEY, SECRET)
                .expect("valid")
                .with_session(TOKEN, live)
                .expect("valid"),
        )
        .with(
            Credentials::new(EXPIRED_KEY, SECRET)
                .expect("valid")
                .with_session(TOKEN, dead)
                .expect("valid"),
        )
        .with(Credentials::new(DISABLED_KEY, SECRET).expect("valid").disable());
    Arc::new(Counting {
        inner: entries,
        calls: AtomicUsize::new(0),
    })
}

fn build<P: CredentialProvider>(provider: Arc<P>) -> S3Service {
    let authenticator = SigV4Authenticator::new(provider, RegionSet::new([REGION]).expect("non-empty"));
    build_with_authenticator(authenticator, None)
}

fn build_verbose<P: CredentialProvider>(provider: Arc<P>) -> S3Service {
    let authenticator = SigV4Authenticator::new(provider, RegionSet::new([REGION]).expect("non-empty"));
    build_with_authenticator(authenticator, Some(true))
}

fn build_with_authenticator(authenticator: SigV4Authenticator, verbose_signature_errors: Option<bool>) -> S3Service {
    let builder = match verbose_signature_errors {
        Some(enabled) => {
            ServiceBuilder::new()
                .config(ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES).with_verbose_signature_errors(enabled))
                .0
        }
        None => ServiceBuilder::new(),
    };
    builder
        .register::<CredProbe, _>(Arc::new(Backend))
        .dialect(&cred_probe_dialect())
        .authenticator(authenticator)
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(NOW),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly")
}

/// Negative — deliberately closing both credential protections remains visible to whoever emits
/// the start-up posture report. A silent weak configuration is harder to find than a loud one.
#[test]
fn a_closed_negative_cache_and_per_ip_bucket_are_named_in_the_posture() {
    let authenticator = SigV4Authenticator::with_guard_config(
        fixtures(),
        RegionSet::new([REGION]).expect("non-empty"),
        CredentialGuardConfig {
            budget: rustfs_gateway::sig::LookupBudget::DEFAULT,
            negative_entries: 0,
        },
    );
    let service = ServiceBuilder::new()
        .register::<CredProbe, _>(Arc::new(Backend))
        .dialect(&cred_probe_dialect())
        .authenticator(authenticator)
        .authorizer(allow_when(|_| true))
        .framework_governor_rates(GovernorRates {
            per_ip: Rate::none(),
            ..GovernorRates::default()
        })
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(NOW),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");

    let report = service.security_posture().to_string();
    assert!(report.contains("credential negative cache: disabled"), "{report}");
    assert!(report.contains("per-IP bucket: closed"), "{report}");
}

/// The host in the byte-exact form the acceptance layer settles on, which is the only spelling a
/// signature may be built from.
fn accepted_host() -> WireRequest<bytes::Bytes> {
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("http://{HOST}/"))
        .header(http::header::HOST, HOST)
        .body(bytes::Bytes::new())
        .expect("a well-formed probe");
    WireRequest::accept(request, &Limits::default()).expect("the fixture host is acceptable")
}

/// Signs one `POST` at [`STAMP`] and submits it.
async fn send(service: &S3Service, access_key: &str, secret: &[u8], token: Option<&str>) -> WireResponse {
    let mut credentials = SigningCredentials::new(access_key, secret).expect("well-formed signing credentials");
    if let Some(token) = token {
        credentials = credentials.with_session_token(SessionToken::new(token).expect("a non-empty token"));
    }
    let stamp = AmzDate::parse(STAMP).expect("a well-formed stamp");
    let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let (path, query) = TARGET.split_once('?').expect("the fixture target carries a query");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static(HOST));
    let method = http::Method::POST;
    let accepted = accepted_host();
    let signing = SigningRequest::new(
        &method,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Empty,
        stamp,
    )
    .with_wire_content_length(0);
    let signed = signer.sign_headers(&signing).expect("the fixture request is signable");

    submit(service, signed.headers().clone()).await
}

/// Submits a head with whatever headers it was handed, signed or not.
async fn submit(service: &S3Service, headers: http::HeaderMap) -> WireResponse {
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("http://{HOST}{TARGET}"))
        .body(bytes::Bytes::new())
        .expect("a well-formed fixture request");
    for (name, value) in &headers {
        request.headers_mut().append(name.clone(), value.clone());
    }
    // Only when the caller did not already carry one: a second `host` line is a conflict the wire
    // layer refuses, and it would refuse every signed request in this file.
    if !request.headers().contains_key(http::header::HOST) {
        request
            .headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_static(HOST));
    }
    collect(service.call_bytes(request).await)
        .await
        .expect("the fixture response body is readable")
}

/// Everything the caller can tell apart: the status, every header, and the body.
fn everything_the_caller_sees(response: &WireResponse) -> Vec<u8> {
    let mut seen = format!("{}\n", response.status().as_u16()).into_bytes();
    for (name, value) in response.headers() {
        // The request id is minted per request and is the one value that legitimately differs.
        if name.as_str().eq_ignore_ascii_case("x-amz-request-id") || name.as_str().eq_ignore_ascii_case("x-amz-id-2") {
            continue;
        }
        seen.extend_from_slice(name.as_str().as_bytes());
        seen.push(b':');
        seen.extend_from_slice(value.as_bytes());
        seen.push(b'\n');
    }
    seen.extend_from_slice(response.body());
    seen
}

/// Redacts the two per-request identifiers so two rejections can be compared byte for byte.
///
/// `RequestId` and `HostId` are minted per request and are the only values in an error body that
/// legitimately differ between two otherwise identical refusals. Nothing else is redacted — in
/// particular the error code is not, because the code is the whole question.
fn without_request_id(response: &WireResponse) -> String {
    let text = String::from_utf8_lossy(&everything_the_caller_sees(response)).into_owned();
    let mut out = text;
    for element in ["RequestId", "HostId"] {
        out = redact_element(&out, element);
    }
    out
}

fn redact_element(text: &str, element: &str) -> String {
    let open_tag = format!("<{element}>");
    let close_tag = format!("</{element}>");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find(&open_tag) {
        out.push_str(&rest[..open]);
        out.push_str(&format!("{open_tag}__REDACTED__{close_tag}"));
        let after = &rest[open..];
        match after.find(&close_tag) {
            Some(close) => rest = &after[close + close_tag.len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

// ── positives: the provider answers, and a session credential works ─────────────────────────────

/// Positive — a long-term credential with a correct signature is authenticated, and the provider
/// was consulted exactly once. Without this the zero-call assertions below are satisfied by a
/// provider nothing ever reaches.
#[tokio::test]
async fn a_long_term_credential_is_authenticated_and_the_provider_was_asked() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = send(&service, LONG_TERM_KEY, SECRET, None).await;
    assert_eq!(response.status().as_u16(), 200, "{}", without_request_id(&response));
    assert_eq!(provider.calls(), 1);
}

/// Positive — an unexpired session credential presenting its token is authenticated.
#[tokio::test]
async fn a_live_session_credential_with_its_token_is_authenticated() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = send(&service, SESSION_KEY, SECRET, Some(TOKEN)).await;
    assert_eq!(response.status().as_u16(), 200, "{}", without_request_id(&response));
}

/// Negative — a token signed with the right access key and secret is still refused when it is not
/// the token issued with that access key. Signature coverage prevents in-flight tampering; this
/// binding check prevents a caller that knows the key pair from substituting a different session.
#[tokio::test]
async fn a_session_credential_refuses_a_different_signed_token() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = send(&service, SESSION_KEY, SECRET, Some(OTHER_TOKEN)).await;
    assert_eq!(response.status().as_u16(), 403, "{}", without_request_id(&response));
}

// ── the provider is not on the unauthenticated path ─────────────────────────────────────────────

/// Negative — a request that presents nothing never reaches the provider. A lookup here would be
/// one backend round trip per anonymous request, bought by anybody who can reach the port.
#[tokio::test]
async fn an_unsigned_request_never_reaches_the_provider() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = submit(&service, http::HeaderMap::new()).await;
    assert_eq!(provider.calls(), 0);
    assert_ne!(response.status().as_u16(), 200);
}

/// Negative — a request whose `Authorization` header cannot be parsed never reaches the provider
/// either: there is no access key to look up, and inventing one would make garbage as expensive
/// as a real forgery.
#[tokio::test]
async fn a_malformed_authorization_header_never_reaches_the_provider() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_static("AWS4-HMAC-SHA256 nonsense"));
    let response = submit(&service, headers).await;
    assert_eq!(provider.calls(), 0);
    assert_eq!(response.status().as_u16(), 403, "{}", without_request_id(&response));
}

/// Negative — a signature the security floor refuses on a rule of its own (here: a region this
/// deployment does not serve) is refused before the credential store is asked.
#[tokio::test]
async fn a_scope_the_floor_refuses_never_reaches_the_provider() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let credentials = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("well-formed");
    let stamp = AmzDate::parse(STAMP).expect("a well-formed stamp");
    let scope = SigningScope::new(stamp.day(), "eu-central-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let (path, query) = TARGET.split_once('?').expect("a query");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static(HOST));
    let method = http::Method::POST;
    let accepted = accepted_host();
    let signing = SigningRequest::new(
        &method,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Empty,
        stamp,
    )
    .with_wire_content_length(0);
    let signed = signer.sign_headers(&signing).expect("signable");
    let response = submit(&service, signed.headers().clone()).await;
    assert_ne!(response.status().as_u16(), 200);
    assert_eq!(provider.calls(), 0, "{}", without_request_id(&response));
}

// ── indistinguishability ────────────────────────────────────────────────────────────────────────

/// Negative — an unknown access key, an expired session, a disabled credential, a session
/// credential used without its token and a long-term credential used with one all produce the
/// same bytes, request id excluded.
#[tokio::test]
async fn five_unusable_credentials_produce_one_answer() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));

    let unknown = send(&service, UNKNOWN_KEY, SECRET, None).await;
    let expired = send(&service, EXPIRED_KEY, SECRET, Some(TOKEN)).await;
    let disabled = send(&service, DISABLED_KEY, SECRET, None).await;
    let session_without_token = send(&service, SESSION_KEY, SECRET, None).await;
    let long_term_with_token = send(&service, LONG_TERM_KEY, SECRET, Some(TOKEN)).await;

    let baseline = without_request_id(&unknown);
    assert_eq!(unknown.status().as_u16(), 403, "{baseline}");
    for (label, response) in [
        ("expired session", &expired),
        ("disabled credential", &disabled),
        ("session credential without its token", &session_without_token),
        ("long-term credential with a token", &long_term_with_token),
    ] {
        assert_eq!(
            without_request_id(response),
            baseline,
            "{label} is distinguishable from an unknown access key"
        );
    }
}

/// Negative — an unknown key and a known key carrying a wrong signature have one wire answer.
#[tokio::test]
async fn a_wrong_secret_is_indistinguishable_from_an_unknown_key() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let unknown = without_request_id(&send(&service, UNKNOWN_KEY, SECRET, None).await);
    let wrong = without_request_id(&send(&service, LONG_TERM_KEY, WRONG_SECRET, None).await);
    assert_eq!(unknown, wrong, "a wrong signature disclosed that the access key exists");
}

/// Positive — c-sig-0257: an operator who explicitly enables verbose signature errors receives
/// the two comparison intermediates for a known key whose signature did not match.
#[tokio::test]
async fn c_sig_0257_verbose_signature_errors_render_comparison_intermediates() {
    let provider = fixtures();
    let service = build_verbose(Arc::clone(&provider));
    let body = without_request_id(&send(&service, LONG_TERM_KEY, WRONG_SECRET, None).await);
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(body.contains("<CanonicalRequest>"), "{body}");
    assert!(body.contains("<StringToSign>"), "{body}");
    assert!(!body.contains("Signature="), "the presented signature reached the response: {body}");
    assert!(!body.contains("wJalrXUtnFEMI"), "the secret reached the response: {body}");
}

/// Negative — c-sig-0257: the shipped default never reflects comparison intermediates.
#[tokio::test]
async fn c_sig_0257_default_signature_errors_are_not_verbose() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let body = without_request_id(&send(&service, LONG_TERM_KEY, WRONG_SECRET, None).await);
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
    assert!(!body.contains("<CanonicalRequest>"), "{body}");
    assert!(!body.contains("<StringToSign>"), "{body}");
}

/// Negative — verbose mode does not invent comparison detail for an unknown access key.
#[tokio::test]
async fn c_sig_0257_verbose_signature_errors_do_not_disclose_unknown_keys() {
    let provider = fixtures();
    let service = build_verbose(Arc::clone(&provider));
    let body = without_request_id(&send(&service, UNKNOWN_KEY, SECRET, None).await);
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
    assert!(!body.contains("<CanonicalRequest>"), "{body}");
    assert!(!body.contains("<StringToSign>"), "{body}");
}

/// Negative — a known but unusable credential remains indistinguishable from an unknown key even
/// when verbose diagnostics are enabled.
#[tokio::test]
async fn c_sig_0257_verbose_signature_errors_do_not_disclose_unusable_keys() {
    let provider = fixtures();
    let service = build_verbose(Arc::clone(&provider));
    let body = without_request_id(&send(&service, EXPIRED_KEY, WRONG_SECRET, Some(TOKEN)).await);
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
    assert!(!body.contains("<CanonicalRequest>"), "{body}");
    assert!(!body.contains("<StringToSign>"), "{body}");
}

/// Negative — a valid session token can participate in comparison without ever being reflected
/// into the verbose response.
#[tokio::test]
async fn c_sig_0257_verbose_signature_errors_redact_session_tokens() {
    let provider = fixtures();
    let service = build_verbose(Arc::clone(&provider));
    let body = without_request_id(&send(&service, SESSION_KEY, WRONG_SECRET, Some(TOKEN)).await);
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(body.contains("<CanonicalRequest>"), "{body}");
    assert!(body.contains("x-amz-security-token:__REDACTED__"), "{body}");
    assert!(!body.contains(TOKEN), "the session token reached the response: {body}");
}

// ── ordering: no session rule answers before the signature has been compared ────────────────────

/// Negative — an expired session with a wrong signature remains on the uniform credential-failure
/// response. Neither fact confirms that the access key exists.
#[tokio::test]
async fn an_expired_session_with_a_wrong_signature_is_uniform() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = send(&service, EXPIRED_KEY, WRONG_SECRET, Some(TOKEN)).await;
    let body = without_request_id(&response);
    assert!(body.contains("InvalidAccessKeyId"), "{body}");
    assert!(!body.contains("SignatureDoesNotMatch"), "{body}");
}

/// Negative — the same uniform answer applies to a disabled credential.
#[tokio::test]
async fn a_disabled_credential_with_a_wrong_signature_is_uniform() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = send(&service, DISABLED_KEY, WRONG_SECRET, None).await;
    let body = without_request_id(&response);
    assert!(body.contains("InvalidAccessKeyId"), "{body}");
    assert!(!body.contains("SignatureDoesNotMatch"), "{body}");
}

/// Negative — and the same for a token-binding violation.
#[tokio::test]
async fn a_token_binding_violation_with_a_wrong_signature_is_uniform() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    let response = send(&service, LONG_TERM_KEY, WRONG_SECRET, Some(TOKEN)).await;
    let body = without_request_id(&response);
    assert!(body.contains("InvalidAccessKeyId"), "{body}");
    assert!(!body.contains("SignatureDoesNotMatch"), "{body}");
}

// ── nothing that is a credential reaches the caller ─────────────────────────────────────────────

/// Negative — no rejection and no success carries the secret, the token, or the access key's
/// signature material.
#[tokio::test]
async fn no_response_carries_key_material() {
    let provider = fixtures();
    let service = build(Arc::clone(&provider));
    for response in [
        send(&service, LONG_TERM_KEY, SECRET, None).await,
        send(&service, UNKNOWN_KEY, SECRET, None).await,
        send(&service, EXPIRED_KEY, SECRET, Some(TOKEN)).await,
        send(&service, LONG_TERM_KEY, WRONG_SECRET, None).await,
    ] {
        let seen = String::from_utf8_lossy(&everything_the_caller_sees(&response)).into_owned();
        assert!(!seen.contains("wJalrXUtnFEMI"), "the secret reached the caller: {seen}");
        assert!(!seen.contains(TOKEN), "the session token reached the caller: {seen}");
        assert!(!seen.contains("StringToSign"), "the string to sign reached the caller: {seen}");
    }
}

/// Negative — c-sig-0128: the real request path writes no credential material to captured process
/// output. A second child emits a safe `Authorization`-shaped poison line so the parent also proves
/// the capture and detector can observe the forbidden direction.
#[test]
fn c_sig_0128_request_logs_exclude_credential_material() {
    if std::env::var_os(LOG_CAPTURE_CHILD).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the test runtime is constructible");
        runtime.block_on(async {
            let provider = fixtures();
            let service = build(Arc::clone(&provider));
            let accepted = send(&service, LONG_TERM_KEY, SECRET, None).await;
            let rejected = send(&service, LONG_TERM_KEY, WRONG_SECRET, None).await;
            assert_eq!(accepted.status().as_u16(), 200);
            assert_eq!(rejected.status().as_u16(), 403);
            assert_eq!(provider.calls(), 2);
        });
        eprintln!("{LOG_CAPTURE_MARKER}");
        if std::env::var_os(LOG_CAPTURE_POISON).is_some() {
            eprintln!("Authorization: capture-control-without-credential-material");
        }
        return;
    }

    let clean = run_log_capture_child(false);
    assert!(clean.status.success(), "{}", String::from_utf8_lossy(&clean.stderr));
    let clean_log = captured_output(&clean);
    assert!(clean_log.contains(LOG_CAPTURE_MARKER), "the child output was not captured: {clean_log}");
    assert_no_credential_material(&clean_log);

    let poison = run_log_capture_child(true);
    assert!(poison.status.success(), "{}", String::from_utf8_lossy(&poison.stderr));
    let poison_log = captured_output(&poison);
    assert!(
        credential_material_marker(&poison_log).is_some(),
        "the poison control did not reach the detector: {poison_log}"
    );
}

fn run_log_capture_child(poison: bool) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().expect("the test executable has a path"));
    command
        .env(LOG_CAPTURE_CHILD, "1")
        .arg("--exact")
        .arg("credential_runtime::c_sig_0128_request_logs_exclude_credential_material")
        .arg("--nocapture");
    if poison {
        command.env(LOG_CAPTURE_POISON, "1");
    }
    command.output().expect("the log-capture child starts")
}

fn captured_output(output: &std::process::Output) -> String {
    let mut captured = String::from_utf8_lossy(&output.stdout).into_owned();
    captured.push_str(&String::from_utf8_lossy(&output.stderr));
    captured
}

fn assert_no_credential_material(captured: &str) {
    assert!(
        credential_material_marker(captured).is_none(),
        "credential material reached captured output: {captured}"
    );
}

fn credential_material_marker(captured: &str) -> Option<&'static str> {
    [
        ("wJalrXUtnFEMI", "secret access key"),
        (TOKEN, "session token"),
        (OTHER_TOKEN, "alternate session token"),
        ("Authorization:", "Authorization header"),
        ("X-Amz-Signature", "query signature"),
        ("Signature=", "expected signature"),
        ("StringToSign", "string to sign"),
    ]
    .into_iter()
    .find_map(|(needle, label)| captured.contains(needle).then_some(label))
}

struct Fails;

impl CredentialProvider for Fails {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        Box::pin(async { Err(ProviderError::Backend) })
    }
}

struct Panics;

impl CredentialProvider for Panics {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        Box::pin(async { panic!("provider panic fixture") })
    }
}

struct Never;

impl CredentialProvider for Never {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        Box::pin(std::future::pending())
    }
}

/// Negative — backend failure, provider panic and timeout all fail closed with the same 403 an
/// unknown credential receives.
#[tokio::test]
async fn provider_faults_are_isolated_and_indistinguishable() {
    let baseline_service = build(fixtures());
    let baseline = without_request_id(&send(&baseline_service, UNKNOWN_KEY, SECRET, None).await);

    let failed = build(Arc::new(Fails));
    let panicked = build(Arc::new(Panics));
    let timed_out = build_with_authenticator(
        SigV4Authenticator::with_guard_config(
            Arc::new(Never),
            RegionSet::new([REGION]).expect("non-empty"),
            CredentialGuardConfig {
                budget: rustfs_gateway::sig::LookupBudget::new(
                    std::time::Duration::from_millis(5),
                    std::time::Duration::from_secs(30),
                    std::time::Duration::from_secs(30),
                ),
                ..CredentialGuardConfig::default()
            },
        ),
        None,
    );

    for response in [
        send(&failed, LONG_TERM_KEY, SECRET, None).await,
        send(&panicked, LONG_TERM_KEY, SECRET, None).await,
        send(&timed_out, LONG_TERM_KEY, SECRET, None).await,
    ] {
        assert_eq!(response.status().as_u16(), 403);
        assert_eq!(without_request_id(&response), baseline);
    }
}

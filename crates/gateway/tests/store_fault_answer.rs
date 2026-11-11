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

//! What a credential-store fault is answered, in every authentication form, in both positions of
//! `SigV4Authenticator::answer_credential_store_faults_as_unavailable` (rustfs/gateway#1585).
//!
//! Responsible for: proving that, off (the default), a provider fault is the closed
//! `403 InvalidAccessKeyId` an unknown key gets — status, headers, connection verdict and body; that,
//! on, it is `500 InternalError` carrying no request or provider text, with the connection verdict
//! of an unknown key; that only a fault changes its answer — an unknown key, a session or disabled
//! credential and a wrong signature answer the same in both positions; and that the fault answer is
//! held until the point an unknown key is answered. The forms are SigV4 header, presigned,
//! streaming, POST policy (routed, and the RustFS-profile object-path form refusal), SigV2 header,
//! presigned and POST policy (routed and object-path), and the RustFS STS header signature over a
//! bounded body. `edges` holds the cases outside that matrix.
//! NOT responsible for: the closed answer's other properties (`credential_runtime.rs`), the empty
//! secret (`empty_secret_runtime.rs`), or the guard's timeout and panic isolation themselves
//! (`credential_guard.rs`).
//! Upstream: `rustfs-gateway`, `rustfs-gateway-sig`. Downstream: nothing.
//!
//! # Why the order is asserted with a refusal, not a clock
//!
//! "The fault does not answer early" is a latency statement, and no wall-clock assertion may gate
//! this repository. It is asserted as a behavioural consequence instead: a request that the
//! signature work itself refuses after the lookup (a header sent outside `SignedHeaders`) gets that
//! refusal under a fault exactly as it does under an unknown key. An authenticator that answered
//! the fault the moment the lookup returned would answer `500` there.
//!
//! # What the connection assertion observes
//!
//! The `ConnectionIntent` a rendered refusal hands the transport, read in process. It is the input
//! the transport acts on, not an observed socket close; `connection_teardown.rs` owns the socket.
//!
//! Negative cases outnumber positive ones.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::BodyExt as _;
use rustfs_gateway::dto::{PostObject, PostObjectOutput, PutObject, PutObjectOutput};
use rustfs_gateway::{
    BoxFuture, ClockSkewAck, ConnectionIntent, CredentialGuardConfig, CredentialLookup, CredentialProvider, Credentials,
    GuardedCredentialProvider, Handler, HandlerError, HandlerResult, ProviderError, RegionSet, Req, Resp, S3Service,
    ServiceBuilder, SessionBinding, SigV4Authenticator, allow_when,
};
use rustfs_gateway_sig::SecurityFloor;
use rustfs_gateway_sig::sig_v2::SigV2Signer;

use crate::support;

#[path = "store_fault_answer/edges.rs"]
mod edges;
#[path = "store_fault_answer/requests.rs"]
mod requests;
use requests::{form_request, request};

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const WRONG_SECRET: &str = "this-is-not-the-secret-the-store-holds--";
const TOKEN: &str = "FQoGZXIvYXdzEExampleSessionTokenValue";
/// [`support::SIGNED_AT_UNIX_SECONDS`] as SigV2's `Date` header spells it.
const SIGNED_AT_RFC1123: &str = "Fri, 02 Jan 2026 03:04:05 GMT";
const BOUNDARY: &str = "store-fault-form";

/// Every surface a signature can arrive on and the built-in authenticator serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    V4Header,
    V4Presigned,
    V4Streaming,
    V4Policy,
    /// A SigV4 form on an object path, which the RustFS profile authenticates and then refuses.
    V4ObjectPath,
    V2Header,
    V2Presigned,
    V2Policy,
    /// A SigV2 form on an object path, which the RustFS profile authenticates and then refuses.
    V2ObjectPath,
    /// An STS-scoped header signature with no `x-amz-content-sha256`, over its bounded body.
    StsBody,
}

const FORMS: [Form; 10] = [
    Form::V4Header,
    Form::V4Presigned,
    Form::V4Streaming,
    Form::V4Policy,
    Form::V4ObjectPath,
    Form::V2Header,
    Form::V2Presigned,
    Form::V2Policy,
    Form::V2ObjectPath,
    Form::StsBody,
];

impl Form {
    /// Whether the form is the RustFS profile's object-path form, which is refused by method once
    /// it has authenticated and so reaches no handler whatever its credential.
    fn is_object_form(self) -> bool {
        matches!(self, Self::V4ObjectPath | Self::V2ObjectPath)
    }

    /// Whether the request carries a body this server has not read when authentication answers.
    fn has_body(self) -> bool {
        !matches!(self, Self::V4Header | Self::V4Presigned | Self::V2Header | Self::V2Presigned)
    }

    /// Whether `status` is what a correctly signed request with a found key is answered: success,
    /// or `405` for an object-path form.
    fn authenticated(self, status: StatusCode) -> bool {
        if self.is_object_form() {
            status == StatusCode::METHOD_NOT_ALLOWED
        } else {
            status.is_success()
        }
    }
}

// ── the credential store ───────────────────────────────────────────────────────────────────────

/// What the store holds for [`ACCESS_KEY`], or how it fails to answer.
#[derive(Clone, Copy, Debug)]
enum Record {
    Found,
    NotFound,
    Fault(ProviderError),
    /// The provider panics; the guard turns that into `ProviderError::Panicked`.
    Panics,
    /// The provider never answers; the guard's deadline turns that into `ProviderError::Timeout`.
    Hangs,
    /// A live session credential, presented without its token by every request here.
    Session,
    Disabled,
}

struct Store {
    record: Mutex<Record>,
    calls: AtomicUsize,
}

impl Store {
    fn holding(record: Record) -> Arc<Self> {
        Arc::new(Self {
            record: Mutex::new(record),
            calls: AtomicUsize::new(0),
        })
    }

    fn set(&self, record: Record) {
        *self.record.lock().expect("fixture lock") = record;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialProvider for Store {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let record = *self.record.lock().expect("fixture lock");
        let credentials = || Credentials::new(access_key_id, SECRET.as_bytes()).expect("a valid credential");
        let answer = match record {
            _ if access_key_id != ACCESS_KEY => Ok(CredentialLookup::NotFound),
            Record::Found => Ok(CredentialLookup::Found(credentials())),
            Record::NotFound => Ok(CredentialLookup::NotFound),
            Record::Fault(error) => Err(error),
            Record::Panics => return Box::pin(async { panic!("credential provider panic fixture") }),
            Record::Hangs => return Box::pin(std::future::pending()),
            Record::Session => {
                let binding =
                    SessionBinding::new("sts.example.test", support::SIGNED_AT_UNIX_SECONDS + 3_600).expect("a valid binding");
                Ok(CredentialLookup::Found(
                    credentials().with_session(TOKEN, binding).expect("a valid token"),
                ))
            }
            Record::Disabled => Ok(CredentialLookup::Found(credentials().disable())),
        };
        Box::pin(async move { answer })
    }
}

/// The provider faults a store can report, the panic the guard isolates and the deadline it keeps.
const FAULTS: [Record; 4] = [
    Record::Fault(ProviderError::Backend),
    Record::Fault(ProviderError::Unavailable),
    Record::Panics,
    Record::Hangs,
];

// ── the service ────────────────────────────────────────────────────────────────────────────────

/// Counts every handler call, whichever operation the form reached.
#[derive(Default)]
struct Reached(AtomicUsize);

impl Handler<PostObject> for Reached {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let mut body = request.into_input().body.into_body();
        while let Some(frame) = body.frame().await {
            frame.map_err(|_| HandlerError::internal_error("the POST file stream failed"))?;
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

impl Handler<PutObject> for Reached {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        if let Some(body) = request.into_input().body {
            let mut body = body.into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| HandlerError::internal_error("the upload stream failed"))?;
            }
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(PutObjectOutput::default()))
    }
}

/// A response as the assertions compare it: the status, every header but the per-request
/// identifiers and `Date`, the connection verdict handed to the transport, and the body with its
/// identifiers redacted.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: StatusCode,
    connection: Option<ConnectionIntent>,
    headers: Vec<(String, String)>,
    body: String,
}

/// Headers that differ between two otherwise identical answers.
const PER_REQUEST_HEADERS: [&str; 4] = ["x-amz-request-id", "x-amz-id-2", "x-request-id", "date"];

/// Sends `request` to `service` and reads the whole answer back.
async fn answer(service: &S3Service, request: http::Request<Bytes>) -> Answer {
    let response = service.call(request.map(Unsized)).await;
    let connection = rustfs_gateway::connection_intent_of(&response);
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let mut headers: Vec<(String, String)> = collected
        .headers()
        .iter()
        .filter(|(name, _)| !PER_REQUEST_HEADERS.contains(&name.as_str()))
        .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
        .collect();
    headers.sort();
    let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    Answer {
        status: collected.status(),
        connection,
        headers,
        body: redact(&redact(&body, "RequestId"), "HostId"),
    }
}

/// The authenticator every harness is built over: a 50 ms lookup deadline, so a hanging provider
/// is a `ProviderError::Timeout` quickly. A store that answers does so on its first poll.
fn authenticator(provider: Arc<dyn CredentialProvider>) -> SigV4Authenticator {
    let budget =
        rustfs_gateway::sig::LookupBudget::new(Duration::from_millis(50), Duration::from_secs(30), Duration::from_secs(30));
    SigV4Authenticator::with_guard_config(
        provider,
        RegionSet::new(["us-east-1"]).expect("non-empty"),
        CredentialGuardConfig {
            budget,
            ..CredentialGuardConfig::default()
        },
    )
}

/// The builder every form needs around `authenticator`: its operation, floor and readings.
fn builder_for(
    form: Form,
    authenticator: SigV4Authenticator,
    reached: &Arc<Reached>,
    pings: &Arc<AtomicUsize>,
) -> ServiceBuilder {
    let builder = support::wired()
        .authenticator(authenticator)
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .authorizer(allow_when(|request| request.identity.is_some()));
    match form {
        Form::V4Policy | Form::V2Policy | Form::V4ObjectPath | Form::V2ObjectPath => {
            let builder = builder
                .security_floor(
                    SecurityFloor::new()
                        .enable_sigv2_presigned_compatibility()
                        .recognize_signatures_as_legacy_rustfs(),
                )
                .register::<PostObject, _>(Arc::clone(reached))
                .legacy_rustfs_post_forms();
            if form.is_object_form() {
                builder.select_operations_as_legacy_rustfs()
            } else {
                builder
            }
        }
        Form::V4Streaming => builder.register::<PutObject, _>(Arc::clone(reached)),
        Form::StsBody => builder
            .answer_header_signatures_as_legacy_rustfs()
            .accept_all_checksum_omissions()
            .register::<PutObject, _>(Arc::clone(reached)),
        Form::V4Header | Form::V4Presigned | Form::V2Header | Form::V2Presigned => builder
            .security_floor(SecurityFloor::new().enable_sigv2_presigned_compatibility())
            .register::<support::Ping, _>(Arc::new(support::CountingBackend::new(pings)))
            .dialect(&support::ping_dialect()),
    }
}

/// One service over one store, with the observation points every assertion reads.
struct Harness {
    service: S3Service,
    guard: Arc<GuardedCredentialProvider>,
    store: Arc<Store>,
    pings: Arc<AtomicUsize>,
    reached: Arc<Reached>,
}

impl Harness {
    fn new(form: Form, record: Record, switch: bool) -> Self {
        Self::with(form, record, |authenticator| {
            if switch {
                authenticator.answer_credential_store_faults_as_unavailable()
            } else {
                authenticator
            }
        })
    }

    /// [`Harness::new`] with the switches `configure` chooses on the authenticator.
    fn with(form: Form, record: Record, configure: impl FnOnce(SigV4Authenticator) -> SigV4Authenticator) -> Self {
        let store = Store::holding(record);
        // The authenticator's own guard is private, so the metric is read off a second one wrapped
        // around the store: the same type, seeing the same provider answers.
        let guard = Arc::new(GuardedCredentialProvider::new(Arc::clone(&store) as Arc<dyn CredentialProvider>));
        let authenticator = authenticator(Arc::clone(&guard) as Arc<dyn CredentialProvider>);
        let authenticator = if form == Form::StsBody {
            authenticator.accept_legacy_rustfs_signing_services()
        } else {
            authenticator
        };
        let pings = Arc::new(AtomicUsize::new(0));
        let reached = Arc::new(Reached::default());
        let builder = builder_for(form, configure(authenticator), &reached, &pings);
        Self {
            service: builder.build().expect("a complete assembly"),
            guard,
            store,
            pings,
            reached,
        }
    }

    /// Sends `form` signed with `secret`.
    async fn send(&self, form: Form, secret: &str) -> Answer {
        self.send_request(request(form, secret)).await
    }

    async fn send_request(&self, request: http::Request<Bytes>) -> Answer {
        answer(&self.service, request).await
    }

    /// Whether no handler ran. Asserted only off the object path: an object-path form reaches no
    /// handler even when it authenticates, so the count could not tell a refusal from success.
    fn unreached(&self, form: Form) -> bool {
        form.is_object_form() || self.pings.load(Ordering::SeqCst) + self.reached.0.load(Ordering::SeqCst) == 0
    }

    fn reached(&self) -> usize {
        self.pings.load(Ordering::SeqCst) + self.reached.0.load(Ordering::SeqCst)
    }
}

/// One frame and no exact size hint, the way a socket delivers a body.
struct Unsized(Bytes);

impl http_body::Body for Unsized {
    type Data = Bytes;
    type Error = core::convert::Infallible;

    fn poll_frame(
        mut self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let data = core::mem::take(&mut self.0);
        core::task::Poll::Ready((!data.is_empty()).then(|| Ok(http_body::Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}

fn redact(text: &str, element: &str) -> String {
    let (open, close) = (format!("<{element}>"), format!("</{element}>"));
    match (text.find(&open), text.find(&close)) {
        (Some(start), Some(end)) if start < end => format!("{}{open}{close}{}", &text[..start], &text[end + close.len()..]),
        _ => text.to_owned(),
    }
}

/// What an unknown key is answered in `form`, in the given switch position.
async fn unknown_key_answer(form: Form, switch: bool) -> Answer {
    Harness::new(form, Record::NotFound, switch).send(form, SECRET).await
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — a found key with a correct signature authenticates in every form, in both switch
/// positions. The control that every fixture signer is right: without it, each refusal below
/// could be a broken request.
#[tokio::test]
async fn a_found_key_authenticates_in_every_form_in_both_positions() {
    for switch in [false, true] {
        for form in FORMS {
            let harness = Harness::new(form, Record::Found, switch);
            let answer = harness.send(form, SECRET).await;
            assert!(form.authenticated(answer.status), "{form:?} switch={switch}: {answer:?}");
            assert_eq!(harness.reached(), usize::from(!form.is_object_form()), "{form:?} switch={switch}");
        }
    }
}

/// Positive — **the case the switch exists for.** Under it, a provider fault is `500
/// InternalError` in every form, and no handler is reached.
#[tokio::test]
async fn under_the_switch_a_fault_is_an_internal_error_in_every_form() {
    let mut wrong = Vec::new();
    for fault in FAULTS {
        for form in FORMS {
            let harness = Harness::new(form, fault, true);
            let answer = harness.send(form, SECRET).await;
            if answer.status != StatusCode::INTERNAL_SERVER_ERROR
                || !answer.body.contains("<Code>InternalError</Code>")
                || !harness.unreached(form)
            {
                wrong.push((fault, form, answer));
            }
        }
    }
    assert!(wrong.is_empty(), "a fault under the switch was not a 500: {wrong:#?}");
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — off, the default: a provider fault is the closed `403 InvalidAccessKeyId`, the answer
/// an unknown key gets — status, headers, connection verdict and body — in every form.
#[tokio::test]
async fn n_without_the_switch_a_fault_is_the_closed_403_in_every_form() {
    for form in FORMS {
        let unknown = unknown_key_answer(form, false).await;
        assert_eq!(unknown.status, StatusCode::FORBIDDEN, "{form:?}: {unknown:?}");
        assert!(unknown.body.contains("<Code>InvalidAccessKeyId</Code>"), "{form:?}: {unknown:?}");
        for fault in FAULTS {
            let harness = Harness::new(form, fault, false);
            assert_eq!(harness.send(form, SECRET).await, unknown, "{form:?} {fault:?}");
            assert!(harness.unreached(form), "{form:?} {fault:?}");
        }
    }
}

/// Negative — an unknown key is `403 InvalidAccessKeyId` under the switch too, the same answer it
/// gets without it: the switch changes the answer to a fault and nothing else.
#[tokio::test]
async fn n_an_unknown_key_is_403_in_both_positions() {
    for form in FORMS {
        let off = unknown_key_answer(form, false).await;
        let on = unknown_key_answer(form, true).await;
        assert_eq!(on.status, StatusCode::FORBIDDEN, "{form:?}: {on:?}");
        assert!(on.body.contains("<Code>InvalidAccessKeyId</Code>"), "{form:?}: {on:?}");
        assert_eq!(on, off, "{form:?}");
    }
}

/// Negative — finding 1 of the #1594 review. Under the switch, the fault's `500` hands the
/// transport the connection verdict an unknown key's `403` does: `Close` whenever a body is still
/// owed, so an unidentified peer's body is not drained. Off, the two answers are one answer.
#[tokio::test]
async fn n_a_fault_closes_the_connection_exactly_as_an_unknown_key_does() {
    let mut wrong = Vec::new();
    for switch in [false, true] {
        for form in FORMS {
            let unknown = unknown_key_answer(form, switch).await.connection;
            let expected = Some(if form.has_body() {
                ConnectionIntent::Close
            } else {
                ConnectionIntent::MayKeepAlive
            });
            assert_eq!(unknown, expected, "{form:?} switch={switch}: the unknown-key control moved");
            for fault in FAULTS {
                let fault_answer = Harness::new(form, fault, switch).send(form, SECRET).await.connection;
                if fault_answer != unknown {
                    wrong.push((switch, form, fault, fault_answer));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "a fault kept a connection an unknown key closes: {wrong:?}");
}

/// Negative — a session credential presented without its token, and a disabled credential, keep
/// their answer in both positions: neither is a store fault. Off the object path that answer is the
/// uniform refusal, except for the SigV4 object-path form, which checks only the key and the HMAC
/// before its method refusal (`authenticator_presented.rs`, legacy-compat) and so is the `405` in
/// both positions.
#[tokio::test]
async fn n_session_and_disabled_refusals_are_unchanged_by_the_switch() {
    for record in [Record::Session, Record::Disabled] {
        for form in FORMS {
            let off = Harness::new(form, record, false).send(form, SECRET).await;
            if form == Form::V4ObjectPath {
                assert_eq!(off.status, StatusCode::METHOD_NOT_ALLOWED, "{record:?} {form:?}: {off:?}");
            } else {
                assert_eq!(off, unknown_key_answer(form, false).await, "{record:?} {form:?}");
            }
            let harness = Harness::new(form, record, true);
            assert_eq!(harness.send(form, SECRET).await, off, "{record:?} {form:?}");
            assert!(harness.unreached(form), "{record:?} {form:?}");
        }
    }
}

/// Negative — a wrong signature over a found key is `403 SignatureDoesNotMatch` in both positions,
/// with the same answer.
#[tokio::test]
async fn n_a_wrong_signature_over_a_found_key_is_unchanged_by_the_switch() {
    for form in FORMS {
        let off = Harness::new(form, Record::Found, false).send(form, WRONG_SECRET).await;
        assert_eq!(off.status, StatusCode::FORBIDDEN, "{form:?}: {off:?}");
        assert!(off.body.contains("<Code>SignatureDoesNotMatch</Code>"), "{form:?}: {off:?}");
        let harness = Harness::new(form, Record::Found, true);
        assert_eq!(harness.send(form, WRONG_SECRET).await, off, "{form:?}");
        assert!(harness.unreached(form), "{form:?}");
    }
}

/// Negative — under the switch, a fault answers a wrong signature exactly as it answers a correct
/// one: the signature a caller tried is not observable through a fault.
#[tokio::test]
async fn n_a_wrong_signature_under_a_fault_gets_the_same_internal_error() {
    for form in FORMS {
        let harness = Harness::new(form, Record::Fault(ProviderError::Backend), true);
        let correct = harness.send(form, SECRET).await;
        let wrong = harness.send(form, WRONG_SECRET).await;
        assert_eq!(wrong.status, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}: {wrong:?}");
        assert_eq!(wrong, correct, "{form:?}");
        assert!(harness.unreached(form), "{form:?}");
    }
}

/// Negative — the `500` names no access key, secret, token, signature or provider error in its body
/// or any header, and is the same answer whichever fault the store reported.
#[tokio::test]
async fn n_the_internal_error_carries_no_request_or_provider_text() {
    for form in FORMS {
        let first = Harness::new(form, FAULTS[0], true).send(form, SECRET).await;
        let headers: String = first
            .headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\n"))
            .collect();
        for needle in [
            ACCESS_KEY,
            SECRET,
            TOKEN,
            "Signature",
            "signature",
            "backend",
            "unavailable",
            "deadline",
            "stopped",
            "panic",
        ] {
            assert!(!first.body.contains(needle), "{form:?}: {needle} reached the body: {first:?}");
            assert!(!headers.contains(needle), "{form:?}: {needle} reached a header: {first:?}");
        }
        for fault in &FAULTS[1..] {
            assert_eq!(Harness::new(form, *fault, true).send(form, SECRET).await, first, "{form:?} {fault:?}");
        }
    }
}

/// A correctly signed request in `form` refused after the lookup and before any comparison could
/// match: an `x-amz-*` header outside a SigV4 `SignedHeaders`, or a SigV2 policy that is not base64.
/// SigV2 header and presigned have no such step — every refusal their string-to-sign can raise (a
/// repeated `Content-Type`, an unreadable header value, a repeated sub-resource) is answered before
/// the lookup — so they are not probed; their return shares the policy form's line in `sigv2.rs`.
fn refused_after_the_lookup(form: Form) -> Option<http::Request<Bytes>> {
    match form {
        Form::V2Policy => {
            let signature = SigV2Signer::new(ACCESS_KEY, SECRET.as_bytes())
                .expect("a valid access key id")
                .post_policy_signature("not-base64!");
            Some(form_request(
                "/example-bucket",
                &[
                    ("key", "upload"),
                    ("AWSAccessKeyId", ACCESS_KEY),
                    ("policy", "not-base64!"),
                    ("signature", &signature),
                ],
            ))
        }
        Form::V4Header | Form::V4Presigned | Form::V4Streaming => {
            let mut request = request(form, SECRET);
            request
                .headers_mut()
                .insert("x-amz-meta-unsigned", http::HeaderValue::from_static("added-after-signing"));
            Some(request)
        }
        _ => None,
    }
}

/// Negative — the order. Under the switch, a request the signature work refuses after the lookup
/// gets that refusal under a fault, exactly as under an unknown key: the fault is held to the point
/// an unknown key is answered, after the signature work, not returned when the lookup does.
#[tokio::test]
async fn n_a_fault_is_answered_only_where_an_unknown_key_is() {
    // Every form is tried before anything is asserted, so a failure names all the forms it hit.
    let mut early = Vec::new();
    for form in FORMS.into_iter().filter(|form| refused_after_the_lookup(*form).is_some()) {
        let send = |harness: Harness| async move {
            let request = refused_after_the_lookup(form).expect("a probe");
            (harness.send_request(request).await, harness.unreached(form))
        };
        let (unknown, _) = send(Harness::new(form, Record::NotFound, true)).await;
        assert_ne!(unknown.status, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}: {unknown:?}");
        assert!(!unknown.status.is_success(), "{form:?}: {unknown:?}");
        for fault in FAULTS {
            let (answer, unreached) = send(Harness::new(form, fault, true)).await;
            if answer != unknown || !unreached {
                early.push((form, fault, answer.status));
            }
        }
    }
    assert!(early.is_empty(), "a fault was answered before an unknown key would be: {early:?}");
}

/// Negative — a fault under the switch is still counted for operators and never cached: every
/// request asks the store again, and once the store recovers the next request authenticates. The
/// store's own call count is what shows it: had the authenticator's guard cached the fault, the
/// second request would not have reached the store.
#[tokio::test]
async fn n_a_fault_under_the_switch_is_counted_never_cached_and_leaves_nothing_behind() {
    for form in FORMS {
        let harness = Harness::new(form, Record::Fault(ProviderError::Unavailable), true);
        for _ in 0..2 {
            assert_eq!(harness.send(form, SECRET).await.status, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}");
        }
        assert_eq!(harness.store.calls(), 2, "{form:?}: a fault was served from a cache");
        let metrics = harness.guard.metrics();
        assert_eq!(metrics.backend_errors, 2, "{form:?}: {metrics:?}");
        harness.store.set(Record::Found);
        let answer = harness.send(form, SECRET).await;
        assert!(form.authenticated(answer.status), "{form:?}: {answer:?}");
        assert_eq!(harness.store.calls(), 3, "{form:?}");
    }
}

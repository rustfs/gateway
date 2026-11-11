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
//! `403 InvalidAccessKeyId` an unknown key gets, byte for byte; that, on, it is `500 InternalError`
//! carrying no request or provider text; that only a fault changes its answer — an unknown key, a
//! session or disabled credential and a wrong signature answer the same in both positions; and that
//! the fault answer is held until the point an unknown key is answered, after the signature work.
//! The forms are SigV4 header, presigned, streaming, POST policy (routed, and the RustFS-profile
//! object-path form refusal), SigV2 header, presigned and POST policy (routed and object-path), and
//! the RustFS STS header signature over a bounded body.
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
//! Negative cases outnumber positive ones.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::StatusCode;
use http_body_util::BodyExt as _;
use rustfs_gateway::dto::{PostObject, PostObjectOutput, PutObject, PutObjectOutput};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{
    BoxFuture, ClockSkewAck, CredentialLookup, CredentialProvider, Credentials, GuardedCredentialProvider, Handler, HandlerError,
    HandlerResult, ProviderError, RegionSet, Req, Resp, S3Service, SessionBinding, SigV4Authenticator, allow_when,
};
use rustfs_gateway_sig::sig_v2::{SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway_sig::{RawQuery, SecurityFloor, percent_encode};
use sha2::{Digest as _, Sha256};

use crate::support;

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
    /// it has authenticated and reaches no handler.
    fn is_object_form(self) -> bool {
        matches!(self, Self::V4ObjectPath | Self::V2ObjectPath)
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
        let store = Store::holding(record);
        // The authenticator's own guard is private, so the metric is read off a second one wrapped
        // around the store: the same type, seeing the same provider answers.
        let guard = Arc::new(GuardedCredentialProvider::new(Arc::clone(&store) as Arc<dyn CredentialProvider>));
        let authenticator = SigV4Authenticator::new(
            Arc::clone(&guard) as Arc<dyn CredentialProvider>,
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        );
        let authenticator = if form == Form::StsBody {
            authenticator.accept_legacy_rustfs_signing_services()
        } else {
            authenticator
        };
        let authenticator = if switch {
            authenticator.answer_credential_store_faults_as_unavailable()
        } else {
            authenticator
        };
        let pings = Arc::new(AtomicUsize::new(0));
        let reached = Arc::new(Reached::default());
        let builder = support::wired()
            .authenticator(authenticator)
            .clock_with_skew_ack(
                support::fixed_clock(),
                ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .authorizer(allow_when(|request| request.identity.is_some()));
        let builder = match form {
            Form::V4Policy | Form::V2Policy | Form::V4ObjectPath | Form::V2ObjectPath => {
                let builder = builder
                    .security_floor(
                        SecurityFloor::new()
                            .enable_sigv2_presigned_compatibility()
                            .recognize_signatures_as_legacy_rustfs(),
                    )
                    .register::<PostObject, _>(Arc::clone(&reached))
                    .legacy_rustfs_post_forms();
                if matches!(form, Form::V4ObjectPath | Form::V2ObjectPath) {
                    builder.select_operations_as_legacy_rustfs()
                } else {
                    builder
                }
            }
            Form::V4Streaming => builder.register::<PutObject, _>(Arc::clone(&reached)),
            Form::StsBody => builder
                .answer_header_signatures_as_legacy_rustfs()
                .accept_all_checksum_omissions()
                .register::<PutObject, _>(Arc::clone(&reached)),
            Form::V4Header | Form::V4Presigned | Form::V2Header | Form::V2Presigned => builder
                .security_floor(SecurityFloor::new().enable_sigv2_presigned_compatibility())
                .register::<support::Ping, _>(Arc::new(support::CountingBackend::new(&pings)))
                .dialect(&support::ping_dialect()),
        };
        Self {
            service: builder.build().expect("a complete assembly"),
            guard,
            store,
            pings,
            reached,
        }
    }

    /// Sends `form` signed with `secret`.
    async fn send(&self, form: Form, secret: &str) -> (StatusCode, String) {
        self.send_request(request(form, secret)).await
    }

    /// Sends one request; per-request identifiers are redacted so two answers compare byte for byte.
    async fn send_request(&self, request: http::Request<Bytes>) -> (StatusCode, String) {
        let response = self.service.call(request.map(Unsized)).await;
        let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        (collected.status(), redact(&redact(&body, "RequestId"), "HostId"))
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

// ── requests, one per form ─────────────────────────────────────────────────────────────────────

fn request(form: Form, secret: &str) -> http::Request<Bytes> {
    match form {
        Form::V4Header => v4(secret, false),
        Form::V4Presigned => v4(secret, true),
        Form::V4Streaming => v4_streaming(secret),
        Form::V4Policy => v4_policy(secret, "/example-bucket"),
        Form::V4ObjectPath => v4_policy(secret, "/example-bucket/upload"),
        Form::V2Header => v2_header(secret),
        Form::V2Presigned => v2_presigned(secret),
        Form::V2Policy => v2_policy(secret, "/example-bucket"),
        Form::V2ObjectPath => v2_policy(secret, "/example-bucket/upload"),
        Form::StsBody => {
            let body = Bytes::from_static(b"sts-body");
            let mut request =
                crate::sts_body_signature::signed("/example-bucket/object", "sts", ACCESS_KEY, secret, &body, body.clone());
            request
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
            request
        }
    }
}

fn v4_signer(secret: &str) -> (SigV4Signer, AmzDate) {
    let credentials = SigningCredentials::new(ACCESS_KEY, secret.as_bytes()).expect("signing credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    (SigV4Signer::new(credentials, scope), stamp)
}

fn v4(secret: &str, presigned: bool) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let (mut signer, stamp) = v4_signer(secret);
    let method = http::Method::POST;
    // A presigned URL carries no body digest, so its canonical payload is `UNSIGNED-PAYLOAD`.
    let payload = if presigned {
        PayloadMode::Unsigned
    } else {
        PayloadMode::Empty
    };
    let signing = SigningRequest::new(&method, "/", "", &headers, &host, payload, stamp);
    let (uri, signed) = if presigned {
        let signed = signer.presign(&signing, 900).expect("a signable request");
        (format!("/?{}", signed.query()), signed)
    } else {
        let signed = signer
            .sign_headers(&signing.with_wire_content_length(0))
            .expect("a signable request");
        ("/".to_owned(), signed)
    };
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a valid request")
}

/// A `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` upload of one chunk and the terminal chunk.
fn v4_streaming(secret: &str) -> http::Request<Bytes> {
    const OBJECT: &[u8] = b"streamed-object";
    let target = "/example-bucket/object";
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let (mut signer, stamp) = v4_signer(secret);
    // Per chunk: the hex size, `;chunk-signature=`, 64 hex digits and two CRLFs.
    let wire_length = format!("{:x}", OBJECT.len()).len() + 17 + 64 + 4 + OBJECT.len() + 1 + 17 + 64 + 4;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_length));
    let method = http::Method::PUT;
    let signing = SigningRequest::new(
        &method,
        target,
        "",
        &headers,
        &host,
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_decoded_content_length(OBJECT.len() as u64)
    .with_wire_content_length(wire_length as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut body = chain.encode_chunk(OBJECT);
    body.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(body.len(), wire_length, "the framing arithmetic above is the one the signer used");
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::from(body)).expect("a valid request")
}

fn v2_header(secret: &str) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::DATE, http::HeaderValue::from_static(SIGNED_AT_RFC1123));
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &query, &headers, None);
    let authorization = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .authorization(&spec)
        .expect("a signable request");
    let mut builder = http::Request::builder().method(http::Method::POST).uri("/");
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    builder
        .header(http::header::AUTHORIZATION, authorization)
        .body(Bytes::new())
        .expect("a valid request")
}

fn v2_presigned(secret: &str) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let expires = support::SIGNED_AT_UNIX_SECONDS + 900;
    let raw = format!("AWSAccessKeyId={ACCESS_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::POST, "/", &query, &headers, None);
    let signature = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .presigned_signature(&spec)
        .expect("a signable request");
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/?{raw}&Signature={}", percent_encode(signature.as_bytes())))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

fn v4_policy(secret: &str, target: &str) -> http::Request<Bytes> {
    let credential = format!("{ACCESS_KEY}/20260102/us-east-1/s3/aws4_request");
    let policy = base64(&format!(
        r#"{{"expiration":"2026-01-02T04:04:05Z","conditions":[{{"bucket":"example-bucket"}},{{"key":"upload"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{credential}"}},{{"x-amz-date":"{}"}}]}}"#,
        support::SIGNED_AT_STAMP
    ));
    let signature = v4_policy_signature(secret.as_bytes(), &policy);
    form_request(
        target,
        &[
            ("key", "upload"),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", &credential),
            ("x-amz-date", support::SIGNED_AT_STAMP),
            ("policy", &policy),
            ("x-amz-signature", &signature),
        ],
    )
}

fn v2_policy(secret: &str, target: &str) -> http::Request<Bytes> {
    let policy = base64(r#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"}]}"#);
    let signature = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .post_policy_signature(&policy);
    form_request(
        target,
        &[
            ("key", "upload"),
            ("AWSAccessKeyId", ACCESS_KEY),
            ("policy", &policy),
            ("signature", &signature),
        ],
    )
}

fn form_request(target: &str, fields: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\n\
         Content-Type: application/octet-stream\r\n\r\nhello\r\n--{BOUNDARY}--\r\n"
    ));
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://host.invalid{target}"))
        .header(http::header::HOST, "host.invalid")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid request")
}

/// HMAC-SHA256 from RFC 2104, so the policy signature does not come from the crate under test.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

fn v4_policy_signature(secret: &[u8], policy: &str) -> String {
    let mut key = [b"AWS4".as_slice(), secret].concat();
    for step in ["20260102", "us-east-1", "s3", "aws4_request"] {
        key = hmac(&key, step.as_bytes()).to_vec();
    }
    hmac(&key, policy.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let bits = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                char::from(ALPHABET[((bits >> (18 - 6 * i)) & 0x3f) as usize])
            } else {
                '='
            });
        }
    }
    out
}

/// The provider faults a store can report, and the panic the guard isolates.
const FAULTS: [Record; 3] = [
    Record::Fault(ProviderError::Backend),
    Record::Fault(ProviderError::Unavailable),
    Record::Panics,
];

/// What an unknown key is answered in `form`, in the given switch position.
async fn unknown_key_answer(form: Form, switch: bool) -> (StatusCode, String) {
    Harness::new(form, Record::NotFound, switch).send(form, SECRET).await
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — a found key with a correct signature authenticates in every form, in both switch
/// positions. The control that every fixture signer above is right: without it, each refusal
/// below could be a broken request.
#[tokio::test]
async fn a_found_key_authenticates_in_every_form_in_both_positions() {
    for switch in [false, true] {
        for form in FORMS {
            let harness = Harness::new(form, Record::Found, switch);
            let (status, body) = harness.send(form, SECRET).await;
            assert!(form.authenticated(status), "{form:?} switch={switch}: {status} {body}");
            assert_eq!(harness.reached(), usize::from(!form.is_object_form()), "{form:?} switch={switch}");
        }
    }
}

/// Positive — **the case the switch exists for.** Under it, a provider fault is `500
/// InternalError` in every form, and the handler is never reached.
#[tokio::test]
async fn under_the_switch_a_fault_is_an_internal_error_in_every_form() {
    let mut wrong = Vec::new();
    for fault in FAULTS {
        for form in FORMS {
            let harness = Harness::new(form, fault, true);
            let (status, body) = harness.send(form, SECRET).await;
            if status != StatusCode::INTERNAL_SERVER_ERROR
                || !body.contains("<Code>InternalError</Code>")
                || harness.reached() != 0
            {
                wrong.push((fault, form, status, body));
            }
        }
    }
    assert!(wrong.is_empty(), "a fault under the switch was not a 500: {wrong:#?}");
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — off, the default: a provider fault is the closed `403 InvalidAccessKeyId`, byte for
/// byte the answer an unknown key gets, in every form.
#[tokio::test]
async fn n_without_the_switch_a_fault_is_the_closed_403_in_every_form() {
    for form in FORMS {
        let unknown = unknown_key_answer(form, false).await;
        assert_eq!(unknown.0, StatusCode::FORBIDDEN, "{form:?}: {}", unknown.1);
        assert!(unknown.1.contains("<Code>InvalidAccessKeyId</Code>"), "{form:?}: {}", unknown.1);
        for fault in FAULTS {
            let harness = Harness::new(form, fault, false);
            assert_eq!(harness.send(form, SECRET).await, unknown, "{form:?} {fault:?}");
            assert_eq!(harness.reached(), 0, "{form:?} {fault:?}");
        }
    }
}

/// Negative — an unknown key is `403 InvalidAccessKeyId` under the switch too, byte for byte the
/// answer it gets without it: the switch changes the answer to a fault and nothing else.
#[tokio::test]
async fn n_an_unknown_key_is_403_in_both_positions() {
    for form in FORMS {
        let off = unknown_key_answer(form, false).await;
        let on = unknown_key_answer(form, true).await;
        assert_eq!(on.0, StatusCode::FORBIDDEN, "{form:?}: {}", on.1);
        assert!(on.1.contains("<Code>InvalidAccessKeyId</Code>"), "{form:?}: {}", on.1);
        assert_eq!(on, off, "{form:?}");
    }
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
                assert_eq!(off.0, StatusCode::METHOD_NOT_ALLOWED, "{record:?} {form:?}: {}", off.1);
            } else {
                assert_eq!(off, unknown_key_answer(form, false).await, "{record:?} {form:?}");
            }
            let harness = Harness::new(form, record, true);
            assert_eq!(harness.send(form, SECRET).await, off, "{record:?} {form:?}");
            assert_eq!(harness.reached(), 0, "{record:?} {form:?}");
        }
    }
}

/// Negative — a wrong signature over a found key is `403 SignatureDoesNotMatch` in both positions,
/// with the same bytes.
#[tokio::test]
async fn n_a_wrong_signature_over_a_found_key_is_unchanged_by_the_switch() {
    for form in FORMS {
        let off = Harness::new(form, Record::Found, false).send(form, WRONG_SECRET).await;
        assert_eq!(off.0, StatusCode::FORBIDDEN, "{form:?}: {}", off.1);
        assert!(off.1.contains("<Code>SignatureDoesNotMatch</Code>"), "{form:?}: {}", off.1);
        let harness = Harness::new(form, Record::Found, true);
        assert_eq!(harness.send(form, WRONG_SECRET).await, off, "{form:?}");
        assert_eq!(harness.reached(), 0, "{form:?}");
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
        assert_eq!(wrong.0, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}: {}", wrong.1);
        assert_eq!(wrong, correct, "{form:?}");
        assert_eq!(harness.reached(), 0, "{form:?}");
    }
}

/// Negative — the `500` names no access key, secret, token, signature or provider error: the body
/// is the same constant text whichever fault the store reported.
#[tokio::test]
async fn n_the_internal_error_carries_no_request_or_provider_text() {
    for form in FORMS {
        let first = Harness::new(form, FAULTS[0], true).send(form, SECRET).await;
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
            assert!(!first.1.contains(needle), "{form:?}: {needle} reached the answer: {}", first.1);
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
        Form::V4Header | Form::V4Presigned => {
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
    let probed: Vec<Form> = FORMS
        .into_iter()
        .filter(|form| refused_after_the_lookup(*form).is_some())
        .collect();
    assert_eq!(probed.len(), 3, "{probed:?}");
    // Every form is tried before anything is asserted, so a failure names all the forms it hit.
    let mut early = Vec::new();
    for form in probed {
        let send = |harness: Harness| async move {
            let request = refused_after_the_lookup(form).expect("a probe");
            (harness.send_request(request).await, harness.reached())
        };
        let (unknown, _) = send(Harness::new(form, Record::NotFound, true)).await;
        assert_ne!(unknown.0, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}: {}", unknown.1);
        assert!(!unknown.0.is_success(), "{form:?}: {}", unknown.1);
        for fault in FAULTS {
            let (answer, reached) = send(Harness::new(form, fault, true)).await;
            if answer != unknown || reached != 0 {
                early.push((form, fault, answer.0, reached));
            }
        }
    }
    assert!(early.is_empty(), "a fault was answered before an unknown key would be: {early:?}");
}

/// Negative — a fault under the switch is still counted for operators and never cached: every
/// request asks the store again, and once the store recovers the next request authenticates.
#[tokio::test]
async fn n_a_fault_under_the_switch_is_counted_never_cached_and_leaves_nothing_behind() {
    for form in FORMS {
        let harness = Harness::new(form, Record::Fault(ProviderError::Unavailable), true);
        for _ in 0..2 {
            assert_eq!(harness.send(form, SECRET).await.0, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}");
        }
        let metrics = harness.guard.metrics();
        assert_eq!(metrics.backend_errors, 2, "{form:?}: {metrics:?}");
        assert_eq!(metrics.negative_cache_hits, 0, "{form:?}: {metrics:?}");
        harness.store.set(Record::Found);
        let (status, body) = harness.send(form, SECRET).await;
        assert!(form.authenticated(status), "{form:?}: {status} {body}");
        assert_eq!(harness.store.calls.load(Ordering::SeqCst), 3, "{form:?}");
    }
}

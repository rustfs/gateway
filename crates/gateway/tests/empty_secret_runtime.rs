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

//! A stored secret of zero bytes, end to end, in every authentication form (rustfs/gateway#1573).
//!
//! Responsible for: proving that a credential store holding an empty secret for a known access key
//! cannot be authenticated against with the empty HMAC key — SigV4 header, SigV4 presigned, SigV4
//! POST policy, SigV2 header, SigV2 presigned and SigV2 POST policy — that the refusal is answered
//! exactly as an unknown key is, and that it is a counted, uncached provider fault.
//! NOT responsible for: the derivation or the comparison themselves (`rustfs-gateway-sig`), nor
//! for the provider-fault answer in general (`credential_runtime.rs`).
//! Upstream: `rustfs-gateway`, `rustfs-gateway-sig`. Downstream: nothing.
//!
//! # Why the provider here builds its credential the way a host does
//!
//! An HMAC key of length zero is known to everybody, so "the derivation runs and the comparison
//! fails" is false for a caller who signs with it. The fixture store therefore holds raw secret
//! bytes and builds a `Credentials` on every lookup, converting a refused construction with the
//! framework's own `ProviderError::from` — the path a real IAM-backed provider takes — rather than
//! being handed a value the test already knows is valid.
//!
//! Negative cases outnumber positive ones.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::StatusCode;
use http_body_util::BodyExt as _;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    BoxFuture, ClockSkewAck, CredentialLookup, CredentialProvider, Credentials, GuardedCredentialProvider, Handler, HandlerError,
    HandlerResult, ProviderError, RegionSet, Req, Resp, S3Service, SigV4Authenticator, allow_when,
};
use rustfs_gateway_sig::sig_v2::{SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway_sig::{RawQuery, SecurityFloor, percent_encode};
use sha2::{Digest as _, Sha256};

use crate::support;

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const REAL_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const GARBAGE_SECRET: &[u8] = b"not-the-secret-anybody-stored";
/// [`support::SIGNED_AT_UNIX_SECONDS`] as SigV2's `Date` header spells it.
const SIGNED_AT_RFC1123: &str = "Fri, 02 Jan 2026 03:04:05 GMT";
const BOUNDARY: &str = "empty-secret-form";

/// Every surface a signature can arrive on.
#[derive(Clone, Copy, Debug)]
enum Form {
    V4Header,
    V4Presigned,
    V4Policy,
    V2Header,
    V2Presigned,
    V2Policy,
}

const FORMS: [Form; 6] = [
    Form::V4Header,
    Form::V4Presigned,
    Form::V4Policy,
    Form::V2Header,
    Form::V2Presigned,
    Form::V2Policy,
];

// ── the credential store ───────────────────────────────────────────────────────────────────────

/// One access key whose stored secret the test controls; `None` means the key is not registered.
struct Stored {
    secret: Mutex<Option<Vec<u8>>>,
    calls: AtomicUsize,
}

impl Stored {
    fn holding(secret: Option<&[u8]>) -> Arc<Self> {
        Arc::new(Self {
            secret: Mutex::new(secret.map(<[u8]>::to_vec)),
            calls: AtomicUsize::new(0),
        })
    }

    fn store(&self, secret: &[u8]) {
        *self.secret.lock().expect("fixture lock") = Some(secret.to_vec());
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialProvider for Stored {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stored = self.secret.lock().expect("fixture lock").clone();
        let answer = match stored {
            Some(secret) if access_key_id == ACCESS_KEY => Credentials::new(access_key_id, &secret)
                .map(CredentialLookup::Found)
                .map_err(ProviderError::from),
            _ => Ok(CredentialLookup::NotFound),
        };
        Box::pin(async move { answer })
    }
}

// ── the service ────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct FormBackend(AtomicUsize);

impl Handler<PostObject> for FormBackend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        // Drained as a store would: a file part dropped unread is answered as a short body.
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

/// One service over one store, with the observation points every assertion reads.
struct Harness {
    service: S3Service,
    guard: Arc<GuardedCredentialProvider>,
    stored: Arc<Stored>,
    pings: Arc<AtomicUsize>,
    forms: Arc<FormBackend>,
}

impl Harness {
    fn new(form: Form, secret: Option<&[u8]>) -> Self {
        let stored = Stored::holding(secret);
        // The guard the authenticator installs is private, so the metric is read off a second one
        // wrapped around the store: the same type, seeing the same provider answers.
        let guard = Arc::new(GuardedCredentialProvider::new(Arc::clone(&stored) as Arc<dyn CredentialProvider>));
        let authenticator = SigV4Authenticator::new(
            Arc::clone(&guard) as Arc<dyn CredentialProvider>,
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        );
        let pings = Arc::new(AtomicUsize::new(0));
        let forms = Arc::new(FormBackend::default());
        let builder = support::wired()
            .authenticator(authenticator)
            .clock_with_skew_ack(
                support::fixed_clock(),
                ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .authorizer(allow_when(|request| request.identity.is_some()));
        let builder = if matches!(form, Form::V4Policy | Form::V2Policy) {
            builder
                .security_floor(
                    SecurityFloor::new()
                        .enable_sigv2_presigned_compatibility()
                        .recognize_signatures_as_legacy_rustfs(),
                )
                .register::<PostObject, _>(Arc::clone(&forms))
                .legacy_rustfs_post_forms()
        } else {
            builder
                .security_floor(SecurityFloor::new().enable_sigv2_presigned_compatibility())
                .register::<support::Ping, _>(Arc::new(support::CountingBackend::new(&pings)))
                .dialect(&support::ping_dialect())
        };
        Self {
            service: builder.build().expect("a complete assembly"),
            guard,
            stored,
            pings,
            forms,
        }
    }

    /// Sends `form` signed with `secret` and returns the status and the body, per-request
    /// identifiers redacted so that two refusals compare byte for byte.
    async fn send(&self, form: Form, secret: &[u8]) -> (StatusCode, String) {
        let response = self.service.call(request(form, secret).map(Unsized)).await;
        let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        (collected.status(), redact(&redact(&body, "RequestId"), "HostId"))
    }

    fn reached(&self) -> usize {
        self.pings.load(Ordering::SeqCst) + self.forms.0.load(Ordering::SeqCst)
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

fn request(form: Form, secret: &[u8]) -> http::Request<Bytes> {
    match form {
        Form::V4Header => v4(secret, false),
        Form::V4Presigned => v4(secret, true),
        Form::V2Header => v2_header(secret),
        Form::V2Presigned => v2_presigned(secret),
        Form::V4Policy => v4_policy(secret),
        Form::V2Policy => v2_policy(secret),
    }
}

fn v4(secret: &[u8], presigned: bool) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let credentials = SigningCredentials::new(ACCESS_KEY, secret).expect("signing credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
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

fn v2_header(secret: &[u8]) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::DATE, http::HeaderValue::from_static(SIGNED_AT_RFC1123));
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &query, &headers, None);
    let authorization = SigV2Signer::new(ACCESS_KEY, secret)
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

fn v2_presigned(secret: &[u8]) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let expires = support::SIGNED_AT_UNIX_SECONDS + 900;
    let raw = format!("AWSAccessKeyId={ACCESS_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::POST, "/", &query, &headers, None);
    let signature = SigV2Signer::new(ACCESS_KEY, secret)
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

fn v4_policy(secret: &[u8]) -> http::Request<Bytes> {
    let credential = format!("{ACCESS_KEY}/20260102/us-east-1/s3/aws4_request");
    let policy = base64(&format!(
        r#"{{"expiration":"2026-01-02T04:04:05Z","conditions":[{{"bucket":"example-bucket"}},{{"key":"upload"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{credential}"}},{{"x-amz-date":"{}"}}]}}"#,
        support::SIGNED_AT_STAMP
    ));
    let signature = v4_policy_signature(secret, &policy);
    form_request(&[
        ("key", "upload"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", &credential),
        ("x-amz-date", support::SIGNED_AT_STAMP),
        ("policy", &policy),
        ("x-amz-signature", &signature),
    ])
}

fn v2_policy(secret: &[u8]) -> http::Request<Bytes> {
    let policy = base64(r#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"}]}"#);
    let signature = SigV2Signer::new(ACCESS_KEY, secret)
        .expect("a valid access key id")
        .post_policy_signature(&policy);
    form_request(&[
        ("key", "upload"),
        ("AWSAccessKeyId", ACCESS_KEY),
        ("policy", &policy),
        ("signature", &signature),
    ])
}

fn form_request(fields: &[(&str, &str)]) -> http::Request<Bytes> {
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
        .uri("http://host.invalid/example-bucket")
        .header(http::header::HOST, "host.invalid")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid request")
}

// ── an independent SigV4 policy signer ─────────────────────────────────────────────────────────

/// HMAC-SHA256 written out from RFC 2104, so the policy signature does not come from the crate
/// under test. A zero-length key is the case this file is about, and RFC 2104 defines it.
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

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — a stored, non-empty secret still authenticates in every form. The control that
/// every fixture signer above is right: without it, each refusal below could be a broken request.
#[tokio::test]
async fn a_real_secret_still_authenticates_in_every_form() {
    for form in FORMS {
        let harness = Harness::new(form, Some(REAL_SECRET));
        let (status, body) = harness.send(form, REAL_SECRET).await;
        assert!(status.is_success(), "{form:?}: {status} {body}");
        assert_eq!(harness.reached(), 1, "{form:?}");
        assert_eq!(harness.guard.metrics().backend_errors, 0, "{form:?}");
    }
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — **the case this file exists for.** A store holding an empty secret, and a request
/// correctly signed with the empty HMAC key, is refused in every form, and the handler is never
/// reached — on operations that would answer an anonymous request, so a downgrade would show.
#[tokio::test]
async fn n_a_request_signed_with_the_empty_key_is_refused_in_every_form() {
    // Every form is tried before anything is asserted, so a failure names all the forms it hit.
    let mut admitted = Vec::new();
    for form in FORMS {
        let harness = Harness::new(form, Some(b""));
        let (status, _) = harness.send(form, b"").await;
        if status != StatusCode::FORBIDDEN || harness.reached() != 0 {
            admitted.push((form, status, harness.reached()));
        }
    }
    assert!(admitted.is_empty(), "the empty key was not refused: {admitted:?}");
}

/// Negative — a secret of NUL bytes is the empty key in disguise: HMAC zero-pads a short key to
/// its block, so `"AWS4" || "\0\0\0\0"` and `"AWS4"` derive the same signing key, and SigV2's raw
/// key pads the same way. A blank fixed-width record is exactly this value; it is refused too.
#[tokio::test]
async fn n_a_secret_of_nul_bytes_is_refused_like_the_empty_secret() {
    let mut admitted = Vec::new();
    for form in FORMS {
        let harness = Harness::new(form, Some(&[0_u8; 16]));
        let (status, _) = harness.send(form, b"").await;
        if status != StatusCode::FORBIDDEN || harness.reached() != 0 {
            admitted.push((form, status, harness.reached()));
        }
    }
    assert!(admitted.is_empty(), "the empty key verified against NUL bytes: {admitted:?}");
}

/// Negative — the refusal is the unknown-key answer, byte for byte, request identifiers aside:
/// nothing tells a prober that this key exists and its secret is blank.
#[tokio::test]
async fn n_an_empty_secret_answers_exactly_as_an_unknown_key() {
    for form in FORMS {
        let unknown = Harness::new(form, None).send(form, b"").await;
        assert_eq!(unknown.0, StatusCode::FORBIDDEN, "{form:?}: {}", unknown.1);
        assert!(unknown.1.contains("<Code>InvalidAccessKeyId</Code>"), "{form:?}: {}", unknown.1);
        let blank = Harness::new(form, Some(b"")).send(form, b"").await;
        assert_eq!(blank, unknown, "{form:?}: an empty secret is distinguishable from an unknown key");
    }
}

/// Negative — a garbage signature against the same empty secret gets the same answer as the
/// empty-key signature: which key the caller tried is not observable either.
#[tokio::test]
async fn n_a_garbage_signature_against_an_empty_secret_gets_the_same_answer() {
    for form in FORMS {
        let harness = Harness::new(form, Some(b""));
        let empty_key = harness.send(form, b"").await;
        let garbage = harness.send(form, GARBAGE_SECRET).await;
        assert_eq!(garbage.0, StatusCode::FORBIDDEN, "{form:?}: {}", garbage.1);
        assert_eq!(garbage, empty_key, "{form:?}");
        assert_eq!(harness.reached(), 0, "{form:?}");
    }
}

/// Negative — the refusal is counted as a provider fault, not as an unknown key: it lands in
/// `backend_errors` and never in the negative cache, so every request asks the store again.
#[tokio::test]
async fn n_an_empty_secret_is_a_counted_provider_fault_and_is_never_cached() {
    for form in FORMS {
        let harness = Harness::new(form, Some(b""));
        for _ in 0..2 {
            assert_eq!(harness.send(form, b"").await.0, StatusCode::FORBIDDEN, "{form:?}");
        }
        let metrics = harness.guard.metrics();
        assert_eq!(metrics.backend_errors, 2, "{form:?}: {metrics:?}");
        assert_eq!(metrics.negative_cache_hits, 0, "{form:?}: {metrics:?}");
        assert_eq!(harness.stored.calls(), 2, "{form:?}");
    }
}

/// Negative — once the store is repaired, the next request authenticates: the earlier refusal left
/// nothing behind that answers for the key. Paired with the empty-key refusal on the same service,
/// so a fixture that could not authenticate at all fails here too.
#[tokio::test]
async fn n_a_refusal_leaves_nothing_behind_once_the_store_is_repaired() {
    for form in FORMS {
        let harness = Harness::new(form, Some(b""));
        assert_eq!(harness.send(form, b"").await.0, StatusCode::FORBIDDEN, "{form:?}");
        harness.stored.store(REAL_SECRET);
        let (status, body) = harness.send(form, REAL_SECRET).await;
        assert!(status.is_success(), "{form:?}: {status} {body}");
        assert_eq!(harness.reached(), 1, "{form:?}");
        assert_eq!(harness.stored.calls(), 2, "{form:?}");
    }
}

/// Positive — non-empty is the only length rule: a one-byte secret is the host's business.
#[test]
fn a_one_byte_secret_is_held() {
    let credentials = Credentials::new("AKIDEXAMPLE", b"x").expect("non-empty");
    assert_eq!(credentials.secret().expose(), b"x");
    // One non-zero byte anywhere is enough: the NUL rule is not a character policy.
    assert!(Credentials::new("AKIDEXAMPLE", b"\0\0x\0").is_ok());
}

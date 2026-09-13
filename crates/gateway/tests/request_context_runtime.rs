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

//! The handler request context, as an assembled service hands it to a backend (ADR-0022).
//!
//! Responsible for: proving, through a real signed request and the real pipeline, that
//! `Req::context()` carries the verified principal, the verified scope, the routed bucket and key,
//! the raw target and every accepted header line; that an anonymous request carries neither a
//! principal nor a scope; that the caller's secret reaches a handler only when the authenticator
//! was told to hand it over; and that no `Debug` rendering of the request shows a secret.
//! NOT responsible for: how the verdict or the scope is produced (`src/ext/authenticator_tests.rs`,
//! `verified_scope_runtime`), or the compile-time read-only guarantees (the `compile_fail`
//! doctests on `rustfs_gateway_core::RequestContextView`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{HeadObject, HeadObjectOutput};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SecurityFloor, SigFamily, SigLocation, SigService, SigV4Signer, SigningCredentials, SigningRequest,
    SigningScope,
};
use rustfs_gateway::{
    AddressingStyle, Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerContext, HandlerResult,
    InputAuthzRequest, InputDecisions, RegionSet, Req, RequestContext, Resp, S3Service, ServiceBuilder, SessionBinding,
    SigV4Authenticator, StaticCredentials,
};

use crate::support::{self, SIGNED_AT_STAMP, exchange};

const ACCESS_KEY: &str = "AKIDCONTEXT";
/// Distinctive, so a leak into a rendering is found by substring.
const SECRET: &[u8] = b"wJalrXUtnFEMI-handler-context-secret";
const SESSION_TOKEN: &str = "FwoGZXIvYXdzEXAMPLE-handler-context-session-token";

/// Everything a handler read from its request, copied out so the test can look after it returns.
#[derive(Clone, Debug, Default)]
struct Seen {
    operation: String,
    method: String,
    raw_path: String,
    raw_query: String,
    host: String,
    path_style: bool,
    bucket: Option<String>,
    key: Option<String>,
    anonymous: bool,
    access_key: Option<String>,
    scheme: Option<(SigFamily, SigLocation, SigService, bool)>,
    scope: Option<(String, String, String)>,
    principal_scope_agrees: bool,
    secret: Option<Vec<u8>>,
    headers: Vec<(String, Vec<u8>)>,
    debug_context: String,
    debug_request: String,
    debug_secret: String,
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn record(&self, request: &Req<HeadObject>) {
        let context = request.context();
        let principal = context.principal();
        let seen = Seen {
            operation: context.operation().to_owned(),
            method: context.method().as_str().to_owned(),
            raw_path: context.raw_path().to_owned(),
            raw_query: context.raw_query().to_owned(),
            host: context.host().to_owned(),
            path_style: matches!(context.addressing(), AddressingStyle::Path),
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            key: context.key().map(|key| key.as_str().to_owned()),
            anonymous: context.is_anonymous(),
            access_key: principal.map(|principal| principal.access_key_id().to_owned()),
            scheme: principal.map(|principal| {
                let scheme = principal.scheme();
                (scheme.family(), scheme.location(), scheme.service(), scheme.is_temporary())
            }),
            scope: context
                .verified_scope()
                .map(|scope| (scope.date().as_str().to_owned(), scope.region().to_owned(), scope.service().to_owned())),
            principal_scope_agrees: principal
                .map(|principal| principal.verified_scope())
                .unwrap_or(None)
                .is_some()
                == context.verified_scope().is_some(),
            secret: principal
                .and_then(|principal| principal.secret_key_from_authenticator_lookup())
                .map(|secret| secret.expose_secret().to_vec()),
            headers: context
                .headers()
                .iter_raw()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            debug_context: format!("{context:?}"),
            debug_request: format!("{request:?}"),
            debug_secret: format!("{:?}", principal.and_then(|principal| principal.secret_key_from_authenticator_lookup())),
        };
        self.seen.lock().expect("not poisoned").push(seen);
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

impl Handler<HeadObject> for Recorder {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        self.record(&request);
        Ok(Resp::new(HeadObjectOutput::default()))
    }

    async fn call_with_context(&self, request: Req<HeadObject>, _context: HandlerContext) -> HandlerResult<HeadObject> {
        self.record(&request);
        Ok(Resp::new(HeadObjectOutput::default()))
    }
}

/// Allows every stage, so every refusal in this file is the pipeline's and not a policy's.
struct AllowEveryStage;

impl Authorizer for AllowEveryStage {
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
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// How the service's authenticator treats the caller's secret, and what the store holds.
#[derive(Clone, Copy)]
enum Setup {
    /// The built-in default: the secret stays inside the authenticator.
    Default,
    /// The authenticator hands the secret it looked up to the handler.
    HandOff,
    /// As `HandOff`, with a temporary credential bound to [`SESSION_TOKEN`].
    HandOffSession,
}

/// Serves `HeadObject` in two regions whose sorted first is `eu-west-1`, while every fixture signs
/// for `us-east-1`: a context reporting the first configured region would be caught.
fn service(recorder: &Arc<Recorder>, setup: Setup) -> S3Service {
    let mut credentials = Credentials::new(ACCESS_KEY, SECRET).expect("a valid key");
    if matches!(setup, Setup::HandOffSession) {
        let binding = SessionBinding::new("sts.example", support::SIGNED_AT_UNIX_SECONDS + 3_600).expect("a binding");
        credentials = credentials.with_session(SESSION_TOKEN, binding).expect("a session");
    }
    let mut authenticator = SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(credentials)),
        RegionSet::new(["us-east-1", "eu-west-1"]).expect("non-empty"),
    );
    if !matches!(setup, Setup::Default) {
        authenticator = authenticator.hand_caller_secret_to_handlers();
    }
    ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(AllowEveryStage)
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<HeadObject, _>(Arc::clone(recorder))
        .build()
        .expect("a complete assembly")
}

/// A `HEAD` of `target`, header-signed at the fixture clock with `secret`, carrying `extra`.
fn signed(target: &str, extra: &[(&str, &[u8])], secret: &[u8]) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        let name: http::HeaderName = name.parse().expect("a header name");
        map.append(name, http::HeaderValue::from_bytes(value).expect("a header value"));
    }
    let probe = http::Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a probe");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let mut signer = SigV4Signer::new(SigningCredentials::new(ACCESS_KEY, secret).expect("credentials"), scope);
    let method = http::Method::HEAD;
    let signing = SigningRequest::new(&method, path, query, &map, accepted.host().raw_for_signing(), PayloadMode::Empty, stamp);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a request")
}

fn anonymous(target: &str, extra: &[(&str, &[u8])]) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(http::Method::HEAD)
        .uri(target)
        .header("host", "s3.example.com");
    for (name, value) in extra {
        builder = builder.header(*name, http::HeaderValue::from_bytes(value).expect("a header value"));
    }
    builder.body(Bytes::new()).expect("a request")
}

async fn one_seen(setup: Setup, request: http::Request<Bytes>) -> Seen {
    let recorder = Arc::new(Recorder::default());
    let (status, body) = exchange(&service(&recorder, setup), request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let mut seen = recorder.seen();
    assert_eq!(seen.len(), 1, "the handler ran once");
    seen.remove(0)
}

fn header<'s>(seen: &'s Seen, name: &str) -> Vec<&'s [u8]> {
    seen.headers
        .iter()
        .filter(|(line, _)| line == name)
        .map(|(_, value)| value.as_slice())
        .collect()
}

/// No early exit on the first differing byte: even a test does not model a short-circuiting
/// comparison of key material.
fn same_secret(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0_u8, |acc, (l, r)| acc | (l ^ r)) == 0
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — every fact the handler reads is the one the pipeline verified or routed.
#[tokio::test]
async fn a_signed_request_reaches_the_handler_with_its_verified_context() {
    let request = signed("/photos/2026/a.jpg?versionId=v1", &[("x-proxy-note", b"first")], SECRET);
    let seen = one_seen(Setup::Default, request).await;

    assert_eq!(seen.operation, "HeadObject");
    assert_eq!(seen.method, "HEAD");
    assert_eq!((seen.raw_path.as_str(), seen.raw_query.as_str()), ("/photos/2026/a.jpg", "versionId=v1"));
    assert_eq!(seen.host, "s3.example.com");
    assert!(seen.path_style);
    assert_eq!((seen.bucket.as_deref(), seen.key.as_deref()), (Some("photos"), Some("2026/a.jpg")));
    assert!(!seen.anonymous);
    assert_eq!(seen.access_key.as_deref(), Some(ACCESS_KEY));
    assert_eq!(seen.scheme, Some((SigFamily::V4, SigLocation::Header, SigService::S3, false)));
    let expected_scope = ("20260102".to_owned(), "us-east-1".to_owned(), "s3".to_owned());
    assert_eq!(seen.scope, Some(expected_scope));
    assert!(seen.principal_scope_agrees);
    assert_eq!(header(&seen, "x-proxy-note"), [b"first".as_slice()]);
    assert_eq!(header(&seen, "authorization").len(), 1, "the signed lines are headers the handler sees");
}

/// Positive — with the hand-off, the secret is exactly the one the credential store answered with.
#[tokio::test]
async fn a_handed_off_secret_is_the_one_the_credential_store_holds() {
    let seen = one_seen(Setup::HandOff, signed("/photos/a.jpg", &[], SECRET)).await;
    let secret = seen.secret.expect("the authenticator handed the secret over");
    assert!(same_secret(&secret, SECRET));
}

/// Positive — an unrelated header whose value is not UTF-8 reaches the handler byte for byte,
/// because the context publishes every accepted line (`iter_raw`), not only the readable ones.
#[tokio::test]
async fn a_non_utf8_unrelated_header_reaches_the_handler_byte_for_byte() {
    let seen = one_seen(Setup::Default, anonymous("/photos/a.jpg", &[("x-proxy-note", b"caf\xe9")])).await;
    assert_eq!(header(&seen, "x-proxy-note"), [b"caf\xe9".as_slice()]);
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — an anonymous request carries no principal and no scope, and no secret even when the
/// authenticator would hand one over: there is no lookup to take it from.
#[tokio::test]
async fn an_anonymous_request_has_no_principal_no_scope_and_no_secret() {
    let seen = one_seen(Setup::HandOff, anonymous("/photos/a.jpg", &[])).await;
    assert!(seen.anonymous);
    assert_eq!(seen.access_key, None);
    assert_eq!(seen.scheme, None);
    assert_eq!(seen.scope, None);
    assert_eq!(seen.secret, None);
    assert_eq!((seen.bucket.as_deref(), seen.key.as_deref()), (Some("photos"), Some("a.jpg")));
}

/// Negative — by default the secret stays inside the authenticator.
#[tokio::test]
async fn by_default_no_secret_reaches_the_handler() {
    let seen = one_seen(Setup::Default, signed("/photos/a.jpg", &[], SECRET)).await;
    assert_eq!(seen.access_key.as_deref(), Some(ACCESS_KEY));
    assert_eq!(seen.secret, None);
}

/// Negative — neither the context's nor the whole request's `Debug` shows the secret, the session
/// token, the signature or the `Authorization` value, even with a session credential and the
/// hand-off on. The access key id, which is public, is shown.
#[tokio::test]
async fn debug_of_the_request_and_its_context_shows_no_secret() {
    let request = signed(
        "/photos/a.jpg?versionId=v1",
        &[("x-amz-security-token", SESSION_TOKEN.as_bytes())],
        SECRET,
    );
    let authorization = request.headers()[http::header::AUTHORIZATION]
        .to_str()
        .expect("text")
        .to_owned();
    let signature = authorization
        .rsplit_once("Signature=")
        .map(|(_, signature)| signature.to_owned())
        .expect("a signature");
    let seen = one_seen(Setup::HandOffSession, request).await;
    assert!(seen.secret.is_some(), "the hand-off is on, so there is a secret that could leak");
    assert_eq!(seen.scheme.map(|scheme| scheme.3), Some(true), "a temporary credential");

    let secret = std::str::from_utf8(SECRET).expect("text");
    for rendering in [&seen.debug_context, &seen.debug_request] {
        for forbidden in [secret, SESSION_TOKEN, signature.as_str(), authorization.as_str()] {
            assert!(!rendering.contains(forbidden), "{rendering}");
        }
        assert!(rendering.contains(ACCESS_KEY), "{rendering}");
        assert!(rendering.contains("<redacted>"), "{rendering}");
    }
    // The key's own `Debug`, formatted directly rather than through the principal.
    assert!(!seen.debug_secret.contains(secret), "{}", seen.debug_secret);
    assert!(seen.debug_secret.contains("<redacted>"), "{}", seen.debug_secret);
}

/// Negative — a request whose signature does not match never reaches the handler, so no context
/// is ever built from a rejected verdict.
#[tokio::test]
async fn a_rejected_signature_never_reaches_the_handler() {
    let recorder = Arc::new(Recorder::default());
    let request = signed("/photos/a.jpg", &[], b"another-secret");
    let (status, _) = exchange(&service(&recorder, Setup::HandOff), request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(recorder.seen().is_empty());
}

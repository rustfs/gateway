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

//! RustFS's SigV4 header guard as the RustFS-profile launcher answers it (rustfs/gateway#1120).
//!
//! Responsible for: a swapped or unsupported algorithm token, an unreadable `AWS4-HMAC-SHA256`
//! value, and an `x-amz-*` header a header-signed or presigned request leaves unsigned, each
//! answered `403 AccessDenied` with legacy RustFS's sentence and a closing connection before the
//! request is routed; what each refused write leaves in storage; and the requests the guard leaves
//! to the rest of the pipeline.
//! NOT responsible for: the guard's grammar and rules one by one (`rustfs-gateway`'s
//! `builder::sigv4_header_guard` unit suite).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`) over raw
//! sockets: `403 AccessDenied`, `Connection: close`, and "Unsupported SigV4 authorization
//! algorithm" for `OTHER` and `AWS4-HMAC-SHA512`, "Invalid SigV4 authorization header" for
//! `AWS4-HMAC-SHA256 garbage`, "There were headers present in the request which were not signed"
//! for an unsigned `x-amz-copy-source` or `x-amz-meta-*`; the source is
//! `rustfs/src/server/layer.rs:1610-1701` and `rustfs/src/auth.rs:1037-1228`.

use super::*;

use rustfs_gateway::ConnectionIntent;

const UNSUPPORTED: &str = "Unsupported SigV4 authorization algorithm";
const INVALID: &str = "Invalid SigV4 authorization header";
const UNSIGNED: &str = "There were headers present in the request which were not signed";
const CONTENT: &[u8] = b"guarded source content";

fn message_of(response: &WireResponse) -> String {
    let body = body_of(response);
    body.split_once("<Message>")
        .and_then(|(_, rest)| rest.split_once("</Message>"))
        .map(|(message, _)| message.to_owned())
        .unwrap_or_default()
}

fn code_of(response: &WireResponse) -> String {
    let body = body_of(response);
    body.split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_owned())
        .unwrap_or_default()
}

/// The answer, with the connection verdict the transport reads off it.
async fn answered(service: &S3Service, request: http::Request<Bytes>) -> (WireResponse, Option<ConnectionIntent>) {
    let response = service.call_bytes(request).await;
    let intent = response.extensions().get::<ConnectionIntent>().copied();
    (collect(response).await.expect("a finite response"), intent)
}

/// A correctly signed request whose `Authorization` then has its algorithm token replaced.
fn with_algorithm(request: http::Request<Bytes>, algorithm: &str) -> http::Request<Bytes> {
    let (mut parts, body) = request.into_parts();
    let value = parts.headers[http::header::AUTHORIZATION]
        .to_str()
        .expect("a signed header")
        .replacen("AWS4-HMAC-SHA256", algorithm, 1);
    parts
        .headers
        .insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(&value).expect("a header value"));
    http::Request::from_parts(parts, body)
}

/// A correctly signed request with `name: value` added after signing.
fn with_unsigned(request: http::Request<Bytes>, name: &'static str, value: &'static str) -> http::Request<Bytes> {
    let (mut parts, body) = request.into_parts();
    parts
        .headers
        .insert(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    http::Request::from_parts(parts, body)
}

/// A presigned SigV4 request of `method` on `target`, signed over no `x-amz-*` header.
fn presigned(method: http::Method, target: &str, body: &'static [u8]) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new(MAIN_KEY, MAIN_SECRET.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(
        &method,
        target,
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    let signed = SigV4Signer::new(credentials, scope)
        .presign(&signing, 900)
        .expect("a signable request");
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("{target}?{}", signed.query()))
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::from_static(body)).expect("a valid presigned request")
}

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/guarded", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let put = exchange(&service, as_main(http::Method::PUT, "/guarded/source", Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    service
}

async fn stored(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

fn assert_guarded(response: &WireResponse, intent: Option<ConnectionIntent>, sentence: &str, what: &str) {
    assert_eq!(response.status(), 403, "{what}: {}", body_of(response));
    assert_eq!(code_of(response), "AccessDenied", "{what}");
    assert_eq!(message_of(response), sentence, "{what}");
    assert_eq!(
        intent,
        Some(ConnectionIntent::Close),
        "{what}: the guard answers without reading the body"
    );
}

/// Negative — an algorithm token other than `AWS4-HMAC-SHA256` over an otherwise valid signature is
/// `403 AccessDenied` "Unsupported SigV4 authorization algorithm", read or write, and the write
/// stores nothing.
#[tokio::test]
async fn n_another_algorithm_token_is_refused_as_unsupported() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for algorithm in ["OTHER", "AWS4-HMAC-SHA512"] {
        let read = with_algorithm(as_main(http::Method::GET, "/guarded/source", Bytes::new()), algorithm);
        let (response, intent) = answered(&service, read).await;
        assert_guarded(&response, intent, UNSUPPORTED, algorithm);
        assert!(!body_of(&response).contains("guarded source content"), "{algorithm}: the object leaked");

        let write = with_algorithm(as_main(http::Method::PUT, "/guarded/fresh", Bytes::from_static(b"forged")), algorithm);
        let (response, intent) = answered(&service, write).await;
        assert_guarded(&response, intent, UNSUPPORTED, algorithm);
    }
    assert_eq!(stored(&service, "/guarded/fresh").await.status(), 404);
}

/// Negative — an `Authorization` value that claims `AWS4-HMAC-SHA256` and does not read is `403
/// AccessDenied` "Invalid SigV4 authorization header".
#[tokio::test]
async fn n_an_unreadable_sigv4_value_is_refused_as_invalid() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let (mut parts, body) = as_main(http::Method::GET, "/guarded/source", Bytes::new()).into_parts();
    parts
        .headers
        .insert(http::header::AUTHORIZATION, http::HeaderValue::from_static("AWS4-HMAC-SHA256 garbage"));
    let (response, intent) = answered(&service, http::Request::from_parts(parts, body)).await;
    assert_guarded(&response, intent, INVALID, "AWS4-HMAC-SHA256 garbage");
}

/// Negative, and the data-layer half — GHSA-xm99: an unsigned `x-amz-copy-source` added to a
/// correctly signed `PutObject` is refused before anything is routed, so the upload never becomes
/// a copy: the target stays absent and the source keeps its bytes. An unsigned `x-amz-meta-*` is
/// refused the same way and stores nothing.
#[tokio::test]
async fn n_an_unsigned_amz_header_on_a_header_signed_write_is_refused_and_stores_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let copy = with_unsigned(
        as_main(http::Method::PUT, "/guarded/copied", Bytes::new()),
        "x-amz-copy-source",
        "/guarded/source",
    );
    let (response, intent) = answered(&service, copy).await;
    assert_guarded(&response, intent, UNSIGNED, "x-amz-copy-source");

    let metadata = with_unsigned(
        as_main(http::Method::PUT, "/guarded/tagged", Bytes::from_static(b"body")),
        "x-amz-meta-owner",
        "attacker",
    );
    let (response, intent) = answered(&service, metadata).await;
    assert_guarded(&response, intent, UNSIGNED, "x-amz-meta-owner");

    assert_eq!(stored(&service, "/guarded/copied").await.status(), 404);
    assert_eq!(stored(&service, "/guarded/tagged").await.status(), 404);
    assert_eq!(stored(&service, "/guarded/source").await.body().as_ref(), CONTENT);
}

/// Negative, and the data-layer half — GHSA-g8w9: a presigned upload carrying an `x-amz-*` header
/// its URL did not sign is refused and stores nothing; a presigned read with one is refused too.
/// Positive control: the same presigned upload without the extra header is stored.
#[tokio::test]
async fn n_an_unsigned_amz_header_on_a_presigned_request_is_refused_and_stores_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let upload = with_unsigned(
        presigned(http::Method::PUT, "/guarded/presigned", b"presigned body"),
        "x-amz-tagging",
        "owner=attacker",
    );
    let (response, intent) = answered(&service, upload).await;
    assert_guarded(&response, intent, UNSIGNED, "x-amz-tagging");
    assert_eq!(stored(&service, "/guarded/presigned").await.status(), 404);

    let read = with_unsigned(
        presigned(http::Method::GET, "/guarded/source", b""),
        "x-amz-server-side-encryption",
        "AES256",
    );
    let (response, intent) = answered(&service, read).await;
    assert_guarded(&response, intent, UNSIGNED, "x-amz-server-side-encryption");

    let control = exchange(&service, presigned(http::Method::PUT, "/guarded/presigned", b"presigned body")).await;
    assert_eq!(control.status(), 200, "{}", body_of(&control));
    assert_eq!(stored(&service, "/guarded/presigned").await.body().as_ref(), b"presigned body");
}

/// Positive — the guard leaves a request it has no rule for to the rest of the pipeline: a signed
/// `x-amz-*` header is served, and an anonymous request is judged by policy, not by the guard.
#[tokio::test]
async fn a_request_the_guard_has_no_rule_for_is_served_as_before() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let signed_metadata = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/guarded/with-metadata",
        Bytes::from_static(b"body"),
        &[("x-amz-meta-owner", "app")],
    );
    let stored_ok = exchange(&service, signed_metadata).await;
    assert_eq!(stored_ok.status(), 200, "{}", body_of(&stored_ok));
    assert_eq!(stored(&service, "/guarded/with-metadata").await.body().as_ref(), b"body");

    let anonymous = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/guarded/anonymous")
        .header(http::header::HOST, "s3.example.com")
        .header("x-amz-copy-source", "/guarded/source")
        .header(http::header::CONTENT_LENGTH, "0")
        .body(Bytes::new())
        .expect("a valid request");
    let refused = exchange(&service, anonymous).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_ne!(message_of(&refused), UNSIGNED, "an anonymous request carries no signed list");
    assert_eq!(stored(&service, "/guarded/anonymous").await.status(), 404);
}

/// Negative — a `HEAD` with a swapped token is refused the same way, with no document.
#[tokio::test]
async fn n_a_guarded_head_carries_no_document() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let head = with_algorithm(as_main(http::Method::HEAD, "/guarded/source", Bytes::new()), "OTHER");
    let (response, intent) = answered(&service, head).await;
    assert_eq!(response.status(), 403);
    assert!(response.body().is_empty(), "{}", body_of(&response));
    assert_eq!(intent, Some(ConnectionIntent::Close));
}

/// Negative — a virtual-hosted-looking write of the service root keeps the virtual-host hint, which
/// RustFS answers ahead of its guard; the guard does not turn it into a `403`.
#[tokio::test]
async fn n_a_hinted_service_root_write_keeps_the_hint() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let (mut parts, body) = with_algorithm(as_main(http::Method::PUT, "/", Bytes::new()), "OTHER").into_parts();
    parts
        .headers
        .insert(http::header::HOST, http::HeaderValue::from_static("guarded.s3.example.com"));
    let (response, _) = answered(&service, http::Request::from_parts(parts, body)).await;
    assert_eq!(response.status(), 501, "{}", body_of(&response));
    assert_ne!(message_of(&response), UNSUPPORTED);
}

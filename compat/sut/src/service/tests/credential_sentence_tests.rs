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

//! The two credential refusals as the RustFS-profile launcher words them (rustfs/gateway#1120).
//!
//! Responsible for: a signature that does not match — header-signed and presigned SigV4, header
//! and presigned SigV2 — answering `403 SignatureDoesNotMatch` with the sentence legacy RustFS
//! writes, an unknown access key answering `403 InvalidAccessKeyId` with RustFS's sentence, what a
//! refused write leaves in storage, and the refusals the switch must not reach.
//! NOT responsible for: the codes or the connection verdicts, which the authenticator decides the
//! same way with the switch off, or the sentence rules themselves (`rustfs-gateway`'s
//! `builder::credential_sentences`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`) over raw
//! sockets: all four forged-signature shapes answer the same `SignatureDoesNotMatch` sentence, and
//! an unknown key the `InvalidAccessKeyId` one from `rustfs/src/auth.rs:271-274`.

use super::*;

use rustfs_gateway::sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

const SIGNATURE_SENTENCE: &str = "The request signature we calculated does not match the signature you provided. Check \
     your AWS secret access key and signing method. For more information, see REST Authentication and SOAP Authentication \
     for details.";
const UNKNOWN_KEY_SENTENCE: &str = "The Access Key Id you provided does not exist in our records.";
const GATEWAY_SENTENCE: &str = "the request was not authenticated";
const CONTENT: &[u8] = b"credential sentence content";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

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

/// A presigned SigV4 `GET` of `target`, signed with `secret`.
fn presigned_get(target: &str, secret: &str) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let rendered = Timestamp::from_secs(i64::try_from(now()).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new(MAIN_KEY, secret.as_bytes()).expect("valid signing credentials");
    let method = http::Method::GET;
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
        .method(http::Method::GET)
        .uri(format!("{target}?{}", signed.query()));
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::new()).expect("a valid presigned request")
}

/// A header-signed SigV2 `method` of `path`, signed with `secret`.
fn sigv2_header(method: http::Method, path: &str, secret: &str, body: Bytes) -> http::Request<Bytes> {
    let date = Timestamp::from_secs(i64::try_from(now()).expect("a representable clock"))
        .render(TimestampFormat::HttpDate)
        .expect("a representable date");
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    map.insert(http::header::DATE, http::HeaderValue::from_str(&date).expect("a date value"));
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &method, path, &query, &map, None);
    let authorization = SigV2Signer::new(MAIN_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .authorization(&spec)
        .expect("a signable request");
    let mut builder = http::Request::builder().method(method).uri(path);
    for (name, value) in &map {
        builder = builder.header(name, value);
    }
    builder
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .header(http::header::AUTHORIZATION, authorization)
        .body(body)
        .expect("a valid request")
}

/// A presigned SigV2 `GET` of `path`, signed with `secret`.
fn sigv2_presigned_get(path: &str, secret: &str) -> http::Request<Bytes> {
    let expires = now() + 300;
    let raw = format!("AWSAccessKeyId={MAIN_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let headers = http::HeaderMap::new();
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::GET, path, &query, &headers, None);
    let signature = SigV2Signer::new(MAIN_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .presigned_signature(&spec)
        .expect("a signable request");
    let escaped = signature.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
    http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{path}?AWSAccessKeyId={MAIN_KEY}&Expires={expires}&Signature={escaped}"))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/sentences", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let put = exchange(&service, as_main(http::Method::PUT, "/sentences/k", Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    service
}

async fn stored(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

/// Negative — every forged-signature shape RustFS serves is `403 SignatureDoesNotMatch` with the
/// legacy sentence, and the gateway's own sentence appears in none of them. Positive control
/// first: the same four shapes signed with the right secret read the object, so the refusal is
/// about the secret and nothing else.
#[tokio::test]
async fn n_a_forged_signature_is_answered_with_the_legacy_sentence_in_every_shape() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let shapes = |secret: &str| {
        [
            (
                "header SigV4",
                signed(MAIN_KEY, secret, http::Method::GET, "/sentences/k", Bytes::new(), &[]),
            ),
            ("presigned SigV4", presigned_get("/sentences/k", secret)),
            ("header SigV2", sigv2_header(http::Method::GET, "/sentences/k", secret, Bytes::new())),
            ("presigned SigV2", sigv2_presigned_get("/sentences/k", secret)),
        ]
    };
    for (shape, request) in shapes(MAIN_SECRET) {
        let read = exchange(&service, request).await;
        assert_eq!(read.status(), 200, "{shape}: {}", body_of(&read));
        assert_eq!(read.body().as_ref(), CONTENT, "{shape}");
    }
    for (shape, request) in shapes("a-secret-nobody-issued-for-this-key") {
        let refused = exchange(&service, request).await;
        assert_eq!(refused.status(), 403, "{shape}: {}", body_of(&refused));
        assert_eq!(code_of(&refused), "SignatureDoesNotMatch", "{shape}");
        assert_eq!(message_of(&refused), SIGNATURE_SENTENCE, "{shape}");
        assert!(!body_of(&refused).contains(GATEWAY_SENTENCE), "{shape}: {}", body_of(&refused));
        assert!(!body_of(&refused).contains(CONTENT_TEXT), "{shape}: the object leaked");
    }
}

const CONTENT_TEXT: &str = "credential sentence content";

/// Negative — an access key nobody issued is `403 InvalidAccessKeyId` with RustFS's sentence,
/// header-signed and presigned alike.
#[tokio::test]
async fn n_an_unknown_access_key_is_answered_with_the_legacy_sentence() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let unknown = signed("AKIANOBODYISSUEDTHIS", MAIN_SECRET, http::Method::GET, "/sentences/k", Bytes::new(), &[]);
    let refused = exchange(&service, unknown).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_eq!(code_of(&refused), "InvalidAccessKeyId");
    assert_eq!(message_of(&refused), UNKNOWN_KEY_SENTENCE);
    assert!(!body_of(&refused).contains(GATEWAY_SENTENCE), "{}", body_of(&refused));
}

/// Negative, and the data-layer half — a forged-signature write stores nothing: the new key stays
/// absent and an existing object keeps its bytes, for both SigV4 and SigV2 uploads.
#[tokio::test]
async fn n_a_forged_upload_is_refused_with_the_legacy_sentence_and_stores_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let forged = "a-secret-nobody-issued-for-this-key";

    for (target, request) in [
        (
            "/sentences/fresh-v4",
            signed(
                MAIN_KEY,
                forged,
                http::Method::PUT,
                "/sentences/fresh-v4",
                Bytes::from_static(b"forged"),
                &[],
            ),
        ),
        (
            "/sentences/k",
            signed(MAIN_KEY, forged, http::Method::PUT, "/sentences/k", Bytes::from_static(b"forged"), &[]),
        ),
        (
            "/sentences/fresh-v2",
            sigv2_header(http::Method::PUT, "/sentences/fresh-v2", forged, Bytes::from_static(b"forged")),
        ),
    ] {
        let refused = exchange(&service, request).await;
        assert_eq!(refused.status(), 403, "{target}: {}", body_of(&refused));
        assert_eq!(message_of(&refused), SIGNATURE_SENTENCE, "{target}");
    }
    assert_eq!(stored(&service, "/sentences/fresh-v4").await.status(), 404);
    assert_eq!(stored(&service, "/sentences/fresh-v2").await.status(), 404);
    assert_eq!(stored(&service, "/sentences/k").await.body().as_ref(), CONTENT);
}

/// Negative — the switch reaches the two credential codes only: an authenticated identity that
/// is denied, and an anonymous request, keep the gateway's own answers.
#[tokio::test]
async fn n_a_denial_and_an_anonymous_refusal_keep_their_own_sentences() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let denied = exchange(&service, as_alt(http::Method::GET, "/sentences/k", Bytes::new())).await;
    assert_eq!(denied.status(), 403, "{}", body_of(&denied));
    assert_eq!(code_of(&denied), "AccessDenied");
    assert_ne!(message_of(&denied), SIGNATURE_SENTENCE);
    assert_ne!(message_of(&denied), UNKNOWN_KEY_SENTENCE);

    let anonymous = http::Request::builder()
        .method(http::Method::GET)
        .uri("/sentences/k")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let refused = exchange(&service, anonymous).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_eq!(code_of(&refused), "AccessDenied");
    assert_ne!(message_of(&refused), SIGNATURE_SENTENCE);
}

/// Negative — a forged `HEAD` keeps its shape: `403` and no document to carry a sentence in.
#[tokio::test]
async fn n_a_forged_head_carries_no_document() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let forged = signed(
        MAIN_KEY,
        "a-secret-nobody-issued-for-this-key",
        http::Method::HEAD,
        "/sentences/k",
        Bytes::new(),
        &[],
    );
    let refused = exchange(&service, forged).await;
    assert_eq!(refused.status(), 403);
    assert!(refused.body().is_empty(), "{}", body_of(&refused));
}

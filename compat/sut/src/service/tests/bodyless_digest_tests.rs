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

//! The signed `x-amz-content-sha256` of a request without a body, as the RustFS-profile launcher
//! reads it (rustfs/gateway#1099).
//!
//! Responsible for: legacy RustFS's answers to a header-signed request that declares the digest of
//! some other payload — `GetObject`, `HeadObject`, `ListObjectsV2` and `DeleteObject` are served
//! (the delete deletes, as legacy's does), and every operation that takes a body still refuses it
//! and stores nothing.
//! NOT responsible for: the switch's mechanics (`rustfs-gateway`'s
//! `tests/bodyless_payload_digest.rs`) or the sentence of a body refusal (`body_refusal_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

/// The digest these requests declare: that of a payload none of them carries.
fn other_digest() -> [u8; 32] {
    Sha256::digest(b"some other payload").into()
}

/// A header-signed request as the main identity carrying `body` but declaring, and signing, the
/// digest of another payload.
fn signed_with_other_digest(method: http::Method, target: &str, body: &'static [u8]) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if !body.is_empty() {
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
    }
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
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::ExactSha256(other_digest()),
        stamp,
    )
    .with_wire_content_length(body.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::from_static(body)).expect("a valid request")
}

async fn with_object(root: &TestRoot, key: &str) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/digests", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(
        &service,
        as_main(http::Method::PUT, &format!("/digests/{key}"), Bytes::from_static(b"stored")),
    )
    .await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// Positive — a read, a listing and a delete declaring another payload's digest are served as
/// legacy RustFS serves them: the object comes back, the listing names it, and the delete removes
/// it.
#[tokio::test]
async fn a_bodyless_request_declaring_another_digest_is_served() {
    let root = TestRoot::new();
    let service = with_object(&root, "k").await;
    let read = exchange(&service, signed_with_other_digest(http::Method::GET, "/digests/k", b"")).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(body_of(&read), "stored");
    let head = exchange(&service, signed_with_other_digest(http::Method::HEAD, "/digests/k", b"")).await;
    assert_eq!(head.status(), 200);
    let listing = exchange(&service, signed_with_other_digest(http::Method::GET, "/digests?list-type=2", b"")).await;
    assert_eq!(listing.status(), 200, "{}", body_of(&listing));
    assert!(body_of(&listing).contains("<Key>k</Key>"), "{}", body_of(&listing));
    let deleted = exchange(&service, signed_with_other_digest(http::Method::DELETE, "/digests/k", b"")).await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    let gone = exchange(&service, as_main(http::Method::GET, "/digests/k", Bytes::new())).await;
    assert_eq!(gone.status(), 404, "the delete removed the object, as legacy's does");
}

/// Negative — an upload declaring another payload's digest is still `400 BadDigest` and stores
/// nothing, as on legacy RustFS.
#[tokio::test]
async fn n_an_upload_declaring_another_digest_is_still_refused() {
    let root = TestRoot::new();
    let service = with_object(&root, "k").await;
    let refused = exchange(&service, signed_with_other_digest(http::Method::PUT, "/digests/fresh", b"hello")).await;
    let body = body_of(&refused);
    assert_eq!(refused.status(), 400, "{body}");
    assert!(body.contains("<Code>BadDigest</Code>"), "{body}");
    let read = exchange(&service, as_main(http::Method::GET, "/digests/fresh", Bytes::new())).await;
    assert_eq!(read.status(), 404, "the refused upload was stored");
}

/// Negative — a buffered body declaring another payload's digest is still refused and changes
/// nothing: the object's tag set stays empty.
#[tokio::test]
async fn n_a_buffered_body_declaring_another_digest_is_still_refused() {
    let root = TestRoot::new();
    let service = with_object(&root, "k").await;
    let tagging: &'static [u8] = b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
    let refused = exchange(&service, signed_with_other_digest(http::Method::PUT, "/digests/k?tagging", tagging)).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    let tags = exchange(&service, as_main(http::Method::GET, "/digests/k?tagging", Bytes::new())).await;
    assert_eq!(tags.status(), 200, "{}", body_of(&tags));
    assert!(
        !body_of(&tags).contains("<Key>a</Key>"),
        "the refused tag set was stored: {}",
        body_of(&tags)
    );
}

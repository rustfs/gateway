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

//! An empty upload without `Content-Length` as the RustFS-profile launcher serves it
//! (rustfs/rustfs#6849).
//!
//! Responsible for: what legacy RustFS stores for a signed `PutObject` or `UploadPart` that
//! carries neither `Content-Length` nor `Transfer-Encoding` — a zero-length object or part with
//! the empty-body `ETag` — and that everything around it is refused and stores nothing: a chunked
//! transfer of nothing, and an empty body signed for other bytes, which also leaves an existing
//! object untouched.
//! NOT responsible for: the switch itself (`crates/gateway/tests/empty_upload_without_length.rs`)
//! or the core's `411` default.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use rustfs_gateway::sig::PayloadMode;

/// The `ETag` of a zero-length object: the MD5 of no bytes.
const EMPTY_ETAG: &str = "\"d41d8cd98f00b204e9800998ecf8427e\"";

/// A request signed by the main identity whose head carries exactly `extra` besides the signing
/// headers: no `Content-Length` unless `extra` names one.
fn lengthless(method: http::Method, target: &str, payload: PayloadMode, extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a payload token"),
    );
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
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
    let signing = SigningRequest::new(&method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    let request = request.body(Bytes::new()).expect("a valid signed request");
    assert!(
        extra.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            || request.headers().get(http::header::CONTENT_LENGTH).is_none(),
        "the fixture carries no length of its own"
    );
    request
}

fn empty_digest() -> PayloadMode {
    PayloadMode::ExactSha256(Sha256::digest(b"").into())
}

async fn bucket(service: &S3Service) {
    let created = exchange(service, as_main(http::Method::PUT, "/lengthless", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response.header(name)
}

/// Positive — a signed empty `PutObject` with no `Content-Length` is stored as a zero-length
/// object with the empty-body `ETag`, whether its empty body is signed by digest or unsigned, and
/// reads back as legacy RustFS reads it back: `HEAD` reports length zero, `GET` returns no bytes.
#[tokio::test]
async fn an_empty_put_without_content_length_is_stored_as_an_empty_object() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    bucket(&service).await;

    for (key, payload) in [("digest", empty_digest()), ("unsigned", PayloadMode::Unsigned)] {
        let target = format!("/lengthless/{key}");
        let put = exchange(&service, lengthless(http::Method::PUT, &target, payload, &[])).await;
        assert_eq!(put.status(), 200, "{key}: {}", body_of(&put));
        assert_eq!(header(&put, "etag"), Some(EMPTY_ETAG), "{key}");

        let head = exchange(&service, as_main(http::Method::HEAD, &target, Bytes::new())).await;
        assert_eq!(head.status(), 200, "{key}");
        assert_eq!(header(&head, "content-length"), Some("0"), "{key}");
        assert_eq!(header(&head, "etag"), Some(EMPTY_ETAG), "{key}");

        let get = exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await;
        assert_eq!(get.status(), 200, "{key}: {}", body_of(&get));
        assert!(get.body().is_empty(), "{key}");
    }
}

/// Positive — a signed empty `UploadPart` with no `Content-Length` is stored as a zero-length
/// part with the empty-body `ETag`, as legacy RustFS stores it.
#[tokio::test]
async fn an_empty_part_without_content_length_is_stored_as_an_empty_part() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    bucket(&service).await;
    let created = exchange(&service, as_main(http::Method::POST, "/lengthless/parts?uploads", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let body = body_of(&created);
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .and_then(|rest| rest.split("</UploadId>").next())
        .expect("an upload id");

    let target = format!("/lengthless/parts?partNumber=1&uploadId={upload_id}");
    let part = exchange(&service, lengthless(http::Method::PUT, &target, empty_digest(), &[])).await;
    assert_eq!(part.status(), 200, "{}", body_of(&part));
    assert_eq!(header(&part, "etag"), Some(EMPTY_ETAG));

    let listed = exchange(
        &service,
        as_main(http::Method::GET, &format!("/lengthless/parts?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    let listing = body_of(&listed);
    assert_eq!(listed.status(), 200, "{listing}");
    assert!(listing.contains("<PartNumber>1</PartNumber>"), "{listing}");
    assert!(listing.contains("<Size>0</Size>"), "{listing}");
}

/// Negative — a chunked transfer has no length until it ends, so even an empty one is refused
/// with `411 MissingContentLength`, as legacy RustFS refuses it, and nothing is stored.
#[tokio::test]
async fn n_a_chunked_transfer_of_nothing_is_still_411_and_stores_nothing() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    bucket(&service).await;

    let mut request = lengthless(http::Method::PUT, "/lengthless/chunked", empty_digest(), &[]);
    request
        .headers_mut()
        .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    let refused = exchange(&service, request).await;
    assert_eq!(refused.status(), 411, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>MissingContentLength</Code>"), "{}", body_of(&refused));

    let absent = exchange(&service, as_main(http::Method::HEAD, "/lengthless/chunked", Bytes::new())).await;
    assert_eq!(absent.status(), 404);
}

/// Negative — an empty body signed for other bytes is refused and stores nothing; over an existing
/// object it leaves the stored bytes exactly as they were.
#[tokio::test]
async fn n_an_empty_body_signed_for_other_bytes_is_refused_and_changes_nothing() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    bucket(&service).await;
    let stored = exchange(
        &service,
        as_main(http::Method::PUT, "/lengthless/kept", Bytes::from_static(b"kept bytes")),
    )
    .await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));

    let other = PayloadMode::ExactSha256(Sha256::digest(b"abc").into());
    for key in ["kept", "fresh"] {
        let target = format!("/lengthless/{key}");
        let refused = exchange(&service, lengthless(http::Method::PUT, &target, other.clone(), &[])).await;
        assert_eq!(refused.status(), 400, "{key}: {}", body_of(&refused));
    }

    let kept = exchange(&service, as_main(http::Method::GET, "/lengthless/kept", Bytes::new())).await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));
    assert_eq!(kept.body().as_ref(), b"kept bytes");
    let fresh = exchange(&service, as_main(http::Method::HEAD, "/lengthless/fresh", Bytes::new())).await;
    assert_eq!(fresh.status(), 404);
}

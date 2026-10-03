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

//! Reads and deletes sent without `Content-Length`, as the RustFS-profile launcher serves them
//! (rustfs/gateway#1120).
//!
//! Responsible for: the S3 scenarios of legacy RustFS's `EmptyBodyContentLengthCompatLayer` tests
//! (`rustfs/src/server/layer.rs` `s3_empty_body_*`, `s3_delete_object_version_*`,
//! `s3_delete_bucket_*`, `empty_body_layer_preserves_explicit_content_length_header`) and of its
//! e2e `delete_object_no_content_length_test` — a signed `GET`, `HEAD`, listing, `DeleteObject`,
//! `DeleteObject?versionId` and `DeleteBucket` with no `Content-Length`, by digest and unsigned,
//! with an explicit `Content-Length: 0`, and with a chunked transfer of nothing — and what each
//! delete removes from storage.
//! NOT responsible for: an upload without `Content-Length` (`empty_upload_tests.rs`, #1099) or the
//! admin routes the layer also normalizes, which this launcher does not serve.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`) over raw
//! sockets: every request below is served — `200` with the object or listing, `204` for a delete —
//! and the deleted object, version or bucket is gone. The layer exists because the legacy stack
//! once refused such a delete `MissingContentLength`; the gateway never did, so the RustFS profile
//! needs no switch here and these cases pin that.

use super::*;

use rustfs_gateway::sig::PayloadMode;

const CONTENT: &[u8] = b"lengthless";

/// A request signed by the main identity whose head carries exactly `extra` besides the signing
/// headers — no `Content-Length` unless `extra` names one — and no body.
fn lengthless(method: &http::Method, target: &str, payload: PayloadMode, extra: &[(&str, &str)]) -> http::Request<Bytes> {
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
    // No body on the wire, whatever the head says about it.
    let signing = SigningRequest::new(method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp)
        .with_wire_content_length(0);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method.clone()).uri(target);
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

/// The two payload declarations a client without `Content-Length` sends: the empty body's digest,
/// and `UNSIGNED-PAYLOAD` (the e2e regression's).
fn declarations() -> [(&'static str, PayloadMode); 2] {
    [
        ("digest", PayloadMode::ExactSha256(Sha256::digest(b"").into())),
        ("unsigned", PayloadMode::Unsigned),
    ]
}

async fn stored(service: &S3Service, target: &str) {
    let put = exchange(service, as_main(http::Method::PUT, target, Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{target}: {}", body_of(&put));
}

async fn served() -> (TestRoot, S3Service) {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/lengthless", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    stored(&service, "/lengthless/object").await;
    (root, service)
}

/// Positive — a `GET`, a `HEAD` and a listing without `Content-Length` are served, by digest and
/// unsigned, and so is one with a chunked transfer of nothing.
#[tokio::test]
async fn a_read_without_content_length_is_served() {
    let (_root, service) = served().await;
    for (what, payload) in declarations() {
        let get = exchange(&service, lengthless(&http::Method::GET, "/lengthless/object", payload.clone(), &[])).await;
        assert_eq!(get.status(), 200, "{what}: {}", body_of(&get));
        assert_eq!(get.body().as_ref(), CONTENT, "{what}");
        let head = exchange(&service, lengthless(&http::Method::HEAD, "/lengthless/object", payload.clone(), &[])).await;
        assert_eq!(head.status(), 200, "{what}");
        assert_eq!(head.header("content-length"), Some("10"), "{what}");
        let listing = exchange(&service, lengthless(&http::Method::GET, "/lengthless?list-type=2", payload, &[])).await;
        assert_eq!(listing.status(), 200, "{what}: {}", body_of(&listing));
        assert!(body_of(&listing).contains("<Key>object</Key>"), "{what}: {}", body_of(&listing));
    }
    for method in [http::Method::GET, http::Method::HEAD] {
        let chunked = exchange(
            &service,
            lengthless(&method, "/lengthless/object", PayloadMode::Unsigned, &[("transfer-encoding", "chunked")]),
        )
        .await;
        assert_eq!(chunked.status(), 200, "{method}: {}", body_of(&chunked));
    }
}

/// Positive, and the data-layer half — a `DeleteObject` without `Content-Length` answers `204` with
/// no content and removes the object, by digest, unsigned, with an explicit `Content-Length: 0`,
/// and with a chunked transfer of nothing.
#[tokio::test]
async fn a_delete_without_content_length_removes_the_object() {
    let (_root, service) = served().await;
    let [(_, digest), (_, unsigned)] = declarations();
    for (what, payload, extra) in [
        ("digest", digest, vec![]),
        ("unsigned", unsigned.clone(), vec![]),
        ("explicit zero", unsigned.clone(), vec![("content-length", "0")]),
        ("chunked nothing", unsigned, vec![("transfer-encoding", "chunked")]),
    ] {
        stored(&service, "/lengthless/doomed").await;
        let deleted = exchange(&service, lengthless(&http::Method::DELETE, "/lengthless/doomed", payload, &extra)).await;
        assert_eq!(deleted.status(), 204, "{what}: {}", body_of(&deleted));
        assert!(deleted.body().is_empty(), "{what}: {}", body_of(&deleted));
        assert!(!body_of(&deleted).contains("MissingContentLength"), "{what}");
        let gone = exchange(&service, as_main(http::Method::GET, "/lengthless/doomed", Bytes::new())).await;
        assert_eq!(gone.status(), 404, "{what}: {}", body_of(&gone));
    }
    let kept = exchange(&service, as_main(http::Method::GET, "/lengthless/object", Bytes::new())).await;
    assert_eq!(kept.body().as_ref(), CONTENT, "a delete removed only its own object");
}

/// Positive, and the data-layer half — the e2e regression: a signed `DeleteObject?versionId` with
/// `UNSIGNED-PAYLOAD` and no `Content-Length` answers `204` with no content and removes that
/// version — the `null` version written before versioning was enabled, and a version written
/// after — while the other version stays readable.
#[tokio::test]
async fn a_version_delete_without_content_length_removes_that_version() {
    let (_root, service) = served().await;
    let enabled = exchange(
        &service,
        as_main(
            http::Method::PUT,
            "/lengthless?versioning",
            Bytes::from_static(
                b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>",
            ),
        ),
    )
    .await;
    assert_eq!(enabled.status(), 200, "{}", body_of(&enabled));
    let later = exchange(&service, as_main(http::Method::PUT, "/lengthless/object", Bytes::from_static(b"later"))).await;
    assert_eq!(later.status(), 200, "{}", body_of(&later));
    let later_version = later.header("x-amz-version-id").expect("a version id").to_owned();

    let null = exchange(
        &service,
        lengthless(&http::Method::DELETE, "/lengthless/object?versionId=null", PayloadMode::Unsigned, &[]),
    )
    .await;
    assert_eq!(null.status(), 204, "{}", body_of(&null));
    assert!(null.body().is_empty());
    let null_gone = exchange(&service, as_main(http::Method::GET, "/lengthless/object?versionId=null", Bytes::new())).await;
    assert_eq!(null_gone.status(), 404, "{}", body_of(&null_gone));
    let current = exchange(&service, as_main(http::Method::GET, "/lengthless/object", Bytes::new())).await;
    assert_eq!(current.body().as_ref(), b"later", "the other version stays");

    let target = format!("/lengthless/object?versionId={later_version}");
    let deleted = exchange(&service, lengthless(&http::Method::DELETE, &target, PayloadMode::Unsigned, &[])).await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    let gone = exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await;
    assert_eq!(gone.status(), 404, "{}", body_of(&gone));
}

/// Positive, and the data-layer half — a `DeleteBucket` without `Content-Length` answers `204` and
/// removes the bucket.
#[tokio::test]
async fn a_bucket_delete_without_content_length_removes_the_bucket() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/lengthless-empty", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let deleted = exchange(
        &service,
        lengthless(&http::Method::DELETE, "/lengthless-empty", PayloadMode::Unsigned, &[]),
    )
    .await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    assert!(deleted.body().is_empty());
    let gone = exchange(&service, as_main(http::Method::HEAD, "/lengthless-empty", Bytes::new())).await;
    assert_eq!(gone.status(), 404);
}

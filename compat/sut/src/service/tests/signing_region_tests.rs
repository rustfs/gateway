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

//! The signing regions the RustFS-profile launcher verifies (rustfs/backlog#1677, R2).
//!
//! Responsible for: a request signed for an empty region — RustFS's replication client — or for a
//! region the launcher does not serve being verified and answered, while the signature is still
//! checked over the presented bytes and a region legacy RustFS refuses is still refused.
//! NOT responsible for: the default refusal of either, which the conformance corpus pins
//! (`c-location-0005`), or the scope rules themselves (`rustfs_gateway_sig::enforce_scope`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/regions", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn signed_for(region: Option<&str>, secret: &str, method: http::Method, target: &str) -> http::Request<Bytes> {
    signed_in(region, MAIN_KEY, secret, method, target, Bytes::new(), &[])
}

/// Positive — the HeadBucket, ListObjectsV2 and PutObject of a client signing with an empty region
/// (RustFS's replication client) are verified and answered, as legacy RustFS answers them.
#[tokio::test]
async fn an_empty_signing_region_is_verified_and_answered() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    let head = exchange(&service, signed_for(None, MAIN_SECRET, http::Method::HEAD, "/regions")).await;
    assert_eq!(head.status(), 200, "{}", body_of(&head));
    let listed = exchange(&service, signed_for(None, MAIN_SECRET, http::Method::GET, "/regions?list-type=2")).await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    let put = signed_in(
        None,
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/regions/replica",
        Bytes::from_static(b"r"),
        &[],
    );
    let stored = exchange(&service, put).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let read = exchange(&service, as_main(http::Method::GET, "/regions/replica", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(read.body().as_ref(), b"r");
}

/// A presigned `GET` of `path`, scoped to `region` (`None`: the empty region), signed now.
fn presigned_get(region: Option<&str>, path: &str) -> http::Request<Bytes> {
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
    let scope = match region {
        Some(region) => SigningScope::new(stamp.day(), region, SigService::S3).expect("a valid signing scope"),
        None => SigningScope::with_empty_region(stamp.day(), SigService::S3),
    };
    let credentials = SigningCredentials::new(MAIN_KEY, MAIN_SECRET.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(
        &http::Method::GET,
        path,
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    let signed = SigV4Signer::new(credentials, scope)
        .presign(&signing, 900)
        .expect("a presignable request");
    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::new()).expect("a valid presigned request")
}

/// Positive — a presigned URL scoped to the empty region is verified too, where the default
/// refuses it as an unreadable credential (`c-sig-0597`).
#[tokio::test]
async fn a_presigned_url_with_an_empty_region_is_verified() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/regions/shared", Bytes::from_static(b"s"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));

    let read = exchange(&service, presigned_get(None, "/regions/shared")).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(read.body().as_ref(), b"s");
}

/// Positive — a region in the configured-name grammar the launcher does not serve is verified.
#[tokio::test]
async fn an_unserved_region_in_the_grammar_is_verified() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    for region in ["rustfs-local", "eu-west-1"] {
        let head = exchange(&service, signed_for(Some(region), MAIN_SECRET, http::Method::HEAD, "/regions")).await;
        assert_eq!(head.status(), 200, "{region}: {}", body_of(&head));
    }
}

/// Negative — the region is admitted, the signature is not: an empty-region request signed with
/// the wrong secret is `403 SignatureDoesNotMatch`, and nothing is stored.
#[tokio::test]
async fn n_an_empty_region_does_not_waive_the_signature() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    let forged = exchange(&service, signed_for(None, ALT_SECRET, http::Method::HEAD, "/regions")).await;
    assert_eq!(forged.status(), 403);
    let put = signed_in(
        None,
        MAIN_KEY,
        ALT_SECRET,
        http::Method::PUT,
        "/regions/forged",
        Bytes::from_static(b"f"),
        &[],
    );
    let refused = exchange(&service, put).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&refused));
    let missing = exchange(&service, as_main(http::Method::GET, "/regions/forged", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
}

/// Negative — a region legacy RustFS refuses (outside its region grammar) is still refused, before
/// any key is derived, naming the region to use.
#[tokio::test]
async fn n_a_region_outside_the_grammar_is_still_refused() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    for region in ["US-EAST-1", "rustfs_local", "eu.west.1"] {
        let refused = exchange(&service, signed_for(Some(region), MAIN_SECRET, http::Method::GET, "/regions?location")).await;
        assert_eq!(refused.status(), 400, "{region}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains("<Code>AuthorizationHeaderMalformed</Code>"),
            "{region}: {}",
            body_of(&refused)
        );
    }
}

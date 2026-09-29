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

//! Presigned URLs on every standard operation, as the RustFS-profile launcher serves them
//! (rustfs/gateway#1052, rustfs/backlog#1677 ruling R7).
//!
//! Responsible for: a SigV4 presigned URL being served on the operations legacy RustFS was observed
//! serving one on — reads, listings, writes, deletes, multipart and bucket configuration — with the
//! write really performed; a SigV2 presigned URL served beyond GetObject; and every tampered form
//! refused with legacy RustFS's status, and its code where the gateway shares it, with nothing
//! written or deleted.
//! NOT responsible for: the floor's own rules (`rustfs-gateway-sig`'s
//! `tests/security_floor_presigned.rs`), the presigned payload reading
//! (`presigned_payload_tests.rs`), or SigV2 verification details (`sigv2_presigned_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed on a legacy RustFS build with botocore-generated URLs: GetObject,
//! HeadObject, ListObjectsV2, ListObjects, ListBuckets, HeadBucket, GetBucketLocation,
//! GetBucketVersioning, GetObjectTagging, PutObject, UploadPart, ListParts, CreateMultipartUpload,
//! DeleteObject, PutBucketTagging and DeleteBucketTagging are all served (`200`/`204`); an altered
//! signature, an added query parameter or another method is `403 SignatureDoesNotMatch`; a missing
//! `X-Amz-Expires` or `X-Amz-Date`, or an expiry above seven days, is
//! `400 AuthorizationQueryParametersError`; an unsigned `x-amz-*` header, or a missing
//! `X-Amz-Signature`, is `403 AccessDenied`.

use super::*;

use rustfs_gateway::sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

/// A SigV4 presigned target for `method target`, valid for `expires` seconds, signed now by the
/// first identity.
fn presign(method: &http::Method, target: &str, expires: u64) -> String {
    presign_as((MAIN_KEY, MAIN_SECRET), method, target, expires)
}

/// A SigV4 presigned target for `method target`, valid for `expires` seconds, signed now with
/// `identity`'s key pair.
fn presign_as((key, secret): (&str, &str), method: &http::Method, target: &str, expires: u64) -> String {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
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
    let credentials = SigningCredentials::new(key, secret.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(
        method,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    SigV4Signer::new(credentials, scope)
        .presign(&signing, expires)
        .expect("a presignable request")
        .target()
}

/// Sends `target` the way curl redeems a link: no `Authorization`, only the query.
async fn redeem(service: &S3Service, method: http::Method, target: &str, body: &[u8], extra: &[(&str, &str)]) -> WireResponse {
    let mut request = http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    exchange(service, request.body(Bytes::copy_from_slice(body)).expect("a valid request")).await
}

fn code(response: &WireResponse) -> Option<String> {
    let body = body_of(response);
    let start = body.find("<Code>")? + "<Code>".len();
    let end = body[start..].find("</Code>")? + start;
    Some(body[start..end].to_owned())
}

async fn served(root: &TestRoot) -> (S3Service, String) {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/links", ""), ("/links/k", "hello"), ("/links/del", "x")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    let created = exchange(&service, as_main(http::Method::POST, "/links/mpu?uploads", Bytes::new())).await;
    let body = body_of(&created);
    let start = body.find("<UploadId>").expect("an upload id") + "<UploadId>".len();
    let end = body[start..].find("</UploadId>").expect("a closed upload id") + start;
    (service, body[start..end].to_owned())
}

async fn status_of(service: &S3Service, method: http::Method, target: &str) -> u16 {
    exchange(service, as_main(method, target, Bytes::new()))
        .await
        .status()
        .as_u16()
}

/// Positive — every operation legacy RustFS serves a presigned URL on is served here too, and the
/// writes and deletes take effect.
#[tokio::test]
async fn a_presigned_url_is_served_on_every_standard_operation_legacy_rustfs_serves() {
    let root = TestRoot::new();
    let (service, upload) = served(&root).await;
    let tagging = "<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
    let part = format!("/links/mpu?partNumber=1&uploadId={upload}");
    let parts = format!("/links/mpu?uploadId={upload}");
    let rows: Vec<(http::Method, &str, &[u8], u16)> = vec![
        (http::Method::GET, "/links/k", b"", 200),
        (http::Method::HEAD, "/links/k", b"", 200),
        (http::Method::GET, "/links?list-type=2", b"", 200),
        (http::Method::GET, "/links", b"", 200),
        (http::Method::GET, "/", b"", 200),
        (http::Method::HEAD, "/links", b"", 200),
        (http::Method::GET, "/links?location", b"", 200),
        (http::Method::GET, "/links?versioning", b"", 200),
        (http::Method::GET, "/links/k?tagging", b"", 200),
        (http::Method::PUT, "/links/p", b"presigned", 200),
        (http::Method::PUT, &part, b"part", 200),
        (http::Method::GET, &parts, b"", 200),
        (http::Method::POST, "/links/mpu2?uploads", b"", 200),
        (http::Method::DELETE, "/links/del", b"", 204),
        (http::Method::PUT, "/links?tagging", tagging.as_bytes(), 200),
        (http::Method::DELETE, "/links?tagging", b"", 204),
    ];
    for (method, target, body, expected) in rows {
        let link = presign(&method, target, 300);
        let answer = redeem(&service, method.clone(), &link, body, &[]).await;
        assert_eq!(answer.status(), expected, "{method} {target}: {}", body_of(&answer));
    }
    // The writes and the delete took effect.
    assert_eq!(status_of(&service, http::Method::HEAD, "/links/p").await, 200);
    assert_eq!(status_of(&service, http::Method::HEAD, "/links/del").await, 404);
    let listed = exchange(&service, as_main(http::Method::GET, &parts, Bytes::new())).await;
    assert!(body_of(&listed).contains("<PartNumber>1</PartNumber>"), "{}", body_of(&listed));
}

/// A tampered form of a link: method, target, extra headers, and legacy RustFS's status and code.
type Tampered = (http::Method, String, Vec<(&'static str, &'static str)>, u16, &'static str);

/// Negative — a tampered link is refused as legacy RustFS refuses it, and deletes nothing.
#[tokio::test]
async fn n_a_tampered_presigned_url_is_refused_as_legacy_rustfs_refuses_it() {
    let root = TestRoot::new();
    let (service, _upload) = served(&root).await;
    let link = presign(&http::Method::DELETE, "/links/del", 300);
    let (path, query) = link.split_once('?').expect("a presigned query");
    let without = |name: &str| {
        let kept: Vec<&str> = query
            .split('&')
            .filter(|pair| !pair.starts_with(&format!("{name}=")))
            .collect();
        format!("{path}?{}", kept.join("&"))
    };
    let altered = {
        let pairs: Vec<String> = query
            .split('&')
            .map(|pair| match pair.strip_prefix("X-Amz-Signature=") {
                Some(signature) => {
                    let flipped = if signature.ends_with('0') { '1' } else { '0' };
                    format!("X-Amz-Signature={}{flipped}", &signature[..signature.len() - 1])
                }
                None => pair.to_owned(),
            })
            .collect();
        format!("{path}?{}", pairs.join("&"))
    };
    let rows: Vec<Tampered> = vec![
        (http::Method::DELETE, altered, vec![], 403, "SignatureDoesNotMatch"),
        (
            http::Method::DELETE,
            format!("{link}&versionId=null"),
            vec![],
            403,
            "SignatureDoesNotMatch",
        ),
        (http::Method::GET, link.clone(), vec![], 403, "SignatureDoesNotMatch"),
        (
            http::Method::DELETE,
            without("X-Amz-Expires"),
            vec![],
            400,
            "AuthorizationQueryParametersError",
        ),
        (
            http::Method::DELETE,
            without("X-Amz-Date"),
            vec![],
            400,
            "AuthorizationQueryParametersError",
        ),
        (
            http::Method::DELETE,
            link.replace("X-Amz-Expires=300", "X-Amz-Expires=604801"),
            vec![],
            400,
            "AuthorizationQueryParametersError",
        ),
    ];
    for (method, target, extra, status, expected) in rows {
        let refused = redeem(&service, method.clone(), &target, b"", &extra).await;
        assert_eq!(
            (refused.status().as_u16(), code(&refused).as_deref()),
            (status, Some(expected)),
            "{method} {target}: {}",
            body_of(&refused)
        );
    }
    // Two more forms are refused with legacy RustFS's `403`, in another code, whatever the
    // operation and before this change as after it: an unsigned `x-amz-*` header beside the link
    // (legacy `AccessDenied`, "There were headers present in the request which were not signed";
    // the gateway's signature verifier answers `SignatureDoesNotMatch`, as for a header signature),
    // and the link without its `X-Amz-Signature` (legacy `AccessDenied`; the gateway
    // `InvalidAccessKeyId` — without the parameter the URL presents no signature to admit).
    let injected = redeem(&service, http::Method::DELETE, &link, b"", &[("x-amz-meta-extra", "1")]).await;
    assert_eq!(injected.status(), 403, "{}", body_of(&injected));
    let unsigned = redeem(&service, http::Method::DELETE, &without("X-Amz-Signature"), b"", &[]).await;
    assert_eq!(unsigned.status(), 403, "{}", body_of(&unsigned));
    assert_eq!(status_of(&service, http::Method::HEAD, "/links/del").await, 200, "nothing was deleted");
}

/// Negative — a presigned URL is authorized like a header signature: the second identity, refused
/// on the first identity's bucket with a header signature, is refused with a presigned URL too, and
/// deletes nothing. Admitting the scheme widens nothing about who may do what.
#[tokio::test]
async fn n_a_presigned_url_is_authorized_like_a_header_signature() {
    let root = TestRoot::new();
    let (service, _upload) = served(&root).await;
    let header = exchange(&service, as_alt(http::Method::GET, "/links?list-type=2", Bytes::new())).await;
    assert_eq!(
        (header.status().as_u16(), code(&header).as_deref()),
        (403, Some("AccessDenied")),
        "{}",
        body_of(&header)
    );
    for (method, target) in [
        (http::Method::GET, "/links?list-type=2"),
        (http::Method::DELETE, "/links/del"),
    ] {
        let link = presign_as((ALT_KEY, ALT_SECRET), &method, target, 300);
        let refused = redeem(&service, method.clone(), &link, b"", &[]).await;
        assert_eq!(
            (refused.status().as_u16(), code(&refused).as_deref()),
            (403, Some("AccessDenied")),
            "{method} {target}: {}",
            body_of(&refused)
        );
    }
    assert_eq!(status_of(&service, http::Method::HEAD, "/links/del").await, 200, "nothing was deleted");
}

/// The `Signature` a SigV2 client computes for `method path` expiring at `expires`.
fn sigv2_signature(method: &http::Method, path: &str, expires: u64) -> String {
    let raw = format!("AWSAccessKeyId={MAIN_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let headers = http::HeaderMap::new();
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, method, path, &query, &headers, None);
    SigV2Signer::new(MAIN_KEY, MAIN_SECRET.as_bytes())
        .expect("a valid access key id")
        .presigned_signature(&spec)
        .expect("a signable request")
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Positive and negative — a SigV2 presigned URL is served beyond GetObject too, and a tampered one
/// deletes nothing.
#[tokio::test]
async fn a_sigv2_presigned_url_is_served_beyond_get_object() {
    let root = TestRoot::new();
    let (service, _upload) = served(&root).await;
    let expires = now() + 300;

    let listed = redeem(
        &service,
        http::Method::GET,
        &format!(
            "/links?AWSAccessKeyId={MAIN_KEY}&Expires={expires}&Signature={}",
            sigv2_signature(&http::Method::GET, "/links", expires)
        ),
        b"",
        &[],
    )
    .await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));

    let forged = redeem(
        &service,
        http::Method::DELETE,
        &format!(
            "/links/del?AWSAccessKeyId={MAIN_KEY}&Expires={expires}&Signature={}",
            sigv2_signature(&http::Method::DELETE, "/links/k", expires)
        ),
        b"",
        &[],
    )
    .await;
    assert_eq!(forged.status(), 403, "{}", body_of(&forged));
    assert_eq!(status_of(&service, http::Method::HEAD, "/links/del").await, 200);

    let deleted = redeem(
        &service,
        http::Method::DELETE,
        &format!(
            "/links/del?AWSAccessKeyId={MAIN_KEY}&Expires={expires}&Signature={}",
            sigv2_signature(&http::Method::DELETE, "/links/del", expires)
        ),
        b"",
        &[],
    )
    .await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    assert_eq!(status_of(&service, http::Method::HEAD, "/links/del").await, 404);
}

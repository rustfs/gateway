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

//! Request-checksum refusals as the RustFS-profile launcher answers them (rustfs/gateway#1057).
//!
//! Responsible for: an unreadable or mismatched `x-amz-checksum-*` claim, and a streamed body that
//! does not match its signed payload hash, being answered `400 BadDigest` as legacy RustFS answers
//! them — and every one of them leaving storage exactly as legacy leaves it: no new object, no
//! overwritten object, no stored part, no completed upload. And the refusals legacy answers with
//! other codes keeping theirs.
//! NOT responsible for: the default codes, which the conformance corpus pins, or the digest
//! comparison itself (`rustfs_gateway_http::BodyIntegrity`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

/// The CRC-32 of `hello`, base64.
const HELLO_CRC32: &str = "NhCmhg==";
/// A well-formed CRC-32 that is not the digest of `hello`.
const OTHER_CRC32: &str = "AAAAAA==";
/// The base64 MD5 of `wrong`, which is not the MD5 of `hello`.
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/digests", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

async fn put(service: &S3Service, target: &str, body: &'static [u8], extra: &[(&str, &str)]) -> WireResponse {
    let request = signed(MAIN_KEY, MAIN_SECRET, http::Method::PUT, target, Bytes::from_static(body), extra);
    exchange(service, request).await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

/// A request's extra headers and the code its refusal must carry.
type Refusal<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);

fn assert_code(response: &WireResponse, status: u16, code: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), status, "{body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "expected {code}: {body}");
}

fn element<'a>(body: &'a str, name: &str) -> &'a str {
    let open = format!("<{name}>");
    let start = body.find(&open).map(|at| at + open.len()).expect("the element is present");
    let end = body[start..].find('<').map(|at| start + at).expect("the element closes");
    &body[start..end]
}

/// Positive control — a claim that matches is stored, so the refusals below are about the claim.
#[tokio::test]
async fn a_matching_checksum_is_stored() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let stored = put(&service, "/digests/ok", b"hello", &[("x-amz-checksum-crc32", HELLO_CRC32)]).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let read = get(&service, "/digests/ok").await;
    assert_eq!(read.body().as_ref(), b"hello");
}

/// Negative — a value that is not valid for its algorithm and a digest that does not match are
/// both `400 BadDigest`, and neither creates the object.
#[tokio::test]
async fn n_an_unreadable_or_mismatched_checksum_is_bad_digest_and_stores_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (key, value) in [("unreadable", "bad"), ("short", "AAAA"), ("mismatched", OTHER_CRC32)] {
        let target = format!("/digests/{key}");
        let refused = put(&service, &target, b"hello", &[("x-amz-checksum-crc32", value)]).await;
        assert_code(&refused, 400, "BadDigest");
        assert_code(&get(&service, &target).await, 404, "NoSuchKey");
    }
}

/// Negative — a refused overwrite leaves the object it would have replaced byte for byte.
#[tokio::test]
async fn n_a_refused_overwrite_keeps_the_stored_object() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let original = put(&service, "/digests/kept", b"first", &[]).await;
    assert_eq!(original.status(), 200, "{}", body_of(&original));
    let refused = put(&service, "/digests/kept", b"hello", &[("x-amz-checksum-crc32", OTHER_CRC32)]).await;
    assert_code(&refused, 400, "BadDigest");
    assert_eq!(get(&service, "/digests/kept").await.body().as_ref(), b"first");
}

/// Negative — a streamed body that does not match its signed `x-amz-content-sha256` is
/// `BadDigest`, as legacy RustFS answers it, and is not stored.
#[tokio::test]
async fn n_a_streamed_body_that_does_not_match_its_payload_hash_is_bad_digest() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let signed_for_hello = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/digests/swapped",
        Bytes::from_static(b"hello"),
        &[],
    );
    let swapped = signed_for_hello.map(|_| Bytes::from_static(b"HELLO"));
    assert_code(&exchange(&service, swapped).await, 400, "BadDigest");
    assert_code(&get(&service, "/digests/swapped").await, 404, "NoSuchKey");
}

/// Negative — a part whose checksum does not match is `BadDigest` and is not stored, and a
/// completion carrying an unreadable object checksum (s3-tests `test_multipart_checksum_sha256`)
/// is `BadDigest` and completes nothing: the upload is still in progress and no object exists.
#[tokio::test]
async fn n_multipart_checksum_failures_are_bad_digest_and_complete_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let created = exchange(&service, as_main(http::Method::POST, "/digests/multi?uploads", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let created = body_of(&created);
    let upload_id = element(&created, "UploadId").to_owned();

    let part_target = format!("/digests/multi?partNumber=1&uploadId={upload_id}");
    let refused = put(&service, &part_target, b"hello", &[("x-amz-checksum-crc32", OTHER_CRC32)]).await;
    assert_code(&refused, 400, "BadDigest");
    let parts = exchange(
        &service,
        as_main(http::Method::GET, &format!("/digests/multi?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(parts.status(), 200, "{}", body_of(&parts));
    assert!(!body_of(&parts).contains("<Part>"), "{}", body_of(&parts));

    let stored = put(&service, &part_target, b"hello", &[]).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let etag = stored
        .headers()
        .iter()
        .find(|(name, _)| *name == http::header::ETAG)
        .and_then(|(_, value)| value.to_str().ok())
        .expect("the part answers an entity tag")
        .to_owned();
    let completion =
        format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
    let complete = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::POST,
        &format!("/digests/multi?uploadId={upload_id}"),
        Bytes::from(completion),
        &[("x-amz-checksum-sha256", "bad")],
    );
    assert_code(&exchange(&service, complete).await, 400, "BadDigest");
    let uploads = exchange(&service, as_main(http::Method::GET, "/digests?uploads", Bytes::new())).await;
    assert!(body_of(&uploads).contains(&upload_id), "{}", body_of(&uploads));
    assert_code(&get(&service, "/digests/multi").await, 404, "NoSuchKey");
}

/// Negative — a buffered body is held to its checksum claim too, and under the RustFS codes a
/// mismatch is `BadDigest`: a `DeleteObjects` whose key list does not match its checksum deletes
/// nothing. (Legacy RustFS does not compare a buffered body's `x-amz-checksum-*` at all and would
/// delete the listed keys; the gateway keeps the comparison, which is registered as a divergence.)
#[tokio::test]
async fn n_a_buffered_body_that_does_not_match_its_checksum_is_bad_digest_and_deletes_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    assert_eq!(put(&service, "/digests/survivor", b"hello", &[]).await.status(), 200);
    let delete = "<Delete><Object><Key>survivor</Key></Object></Delete>";
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::POST,
        "/digests?delete",
        Bytes::from_static(delete.as_bytes()),
        &[("x-amz-checksum-crc32", OTHER_CRC32)],
    );
    assert_code(&exchange(&service, request).await, 400, "BadDigest");
    assert_eq!(get(&service, "/digests/survivor").await.body().as_ref(), b"hello");
}

/// Negative — the refusals legacy RustFS answers with other codes keep them: an unreadable and a
/// mismatched `Content-MD5` (`InvalidDigest`, `BadDigest`) and two different checksum claims
/// (`InvalidRequest`); and none of them stores anything.
#[tokio::test]
async fn n_other_integrity_refusals_keep_their_codes() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let cases: [Refusal<'_>; 3] = [
        ("md5-unreadable", &[("content-md5", "not-base64!")], "InvalidDigest"),
        ("md5-mismatched", &[("content-md5", WRONG_MD5)], "BadDigest"),
        (
            "two-claims",
            &[("x-amz-checksum-crc32", HELLO_CRC32), ("x-amz-checksum-crc32c", "AAAAAA==")],
            "InvalidRequest",
        ),
    ];
    for (key, extra, code) in cases {
        let target = format!("/digests/{key}");
        assert_code(&put(&service, &target, b"hello", extra).await, 400, code);
        assert_code(&get(&service, &target).await, 404, "NoSuchKey");
    }
}

/// Negative — a buffered body that does not match its payload hash keeps the core's
/// `XAmzContentSHA256Mismatch`: legacy RustFS answers it `500 InternalError`, which is not copied.
/// The bucket it would have created does not exist.
#[tokio::test]
async fn n_a_buffered_payload_hash_mismatch_keeps_its_code() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let signed_body = "<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>";
    let sent_body = "<CreateBucketConfiguration><LocationConstraint>us-east-2</LocationConstraint></CreateBucketConfiguration>";
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/digests-created",
        Bytes::from_static(signed_body.as_bytes()),
        &[],
    )
    .map(|_| Bytes::from_static(sent_body.as_bytes()));
    assert_code(&exchange(&service, request).await, 400, "XAmzContentSHA256Mismatch");
    let head = exchange(&service, as_main(http::Method::HEAD, "/digests-created", Bytes::new())).await;
    assert_eq!(head.status(), 404);
}

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

//! The three integrity refusals legacy RustFS answers `500 InternalError`, as the RustFS-profile
//! launcher answers them: with the client error the request is (rustfs/backlog#1677; `rd-err-0012`,
//! `rd-err-0013`, `rd-body-0011`), and nothing stored.
//!
//! Responsible for: an UploadPart whose `Content-MD5` is not base64 (`400 InvalidDigest`, no part);
//! a trailer checksum whose value is not base64 (`400 BadDigest`, no object); and a PutObjectTagging
//! body that does not hash to its signed `x-amz-content-sha256` (`400 XAmzContentSHA256Mismatch`, no
//! tags).
//! NOT responsible for: the PutObject and CreateBucket forms of the first and third, which
//! `bad_digest_tests.rs` pins.
//! Upstream: the parent module's two-identity assembly, and the hand-signed streaming upload of
//! `body_refusal_tests.rs`. Downstream: nothing.
//!
//! Legacy behaviour, observed on a legacy RustFS build (rustfs/rustfs `e870a6d25b`,
//! `RUSTFS_S3_STACK=legacy`): each of the three is `500 InternalError` and stores nothing — a legacy
//! bug, not a decision, so it is not reproduced.

use super::body_refusal_tests::{framed, streaming_put};
use super::*;

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/servererrors", ""), ("/servererrors/tagged", "hello")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    service
}

fn assert_code(response: &WireResponse, status: u16, code: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), status, "{body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "expected {code}: {body}");
}

/// Negative — an UploadPart whose `Content-MD5` is not base64 is `400 InvalidDigest`, and the part
/// is not stored.
#[tokio::test]
async fn n_an_unreadable_content_md5_on_a_part_is_invalid_digest() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let created = body_of(&exchange(&service, as_main(http::Method::POST, "/servererrors/mpu?uploads", Bytes::new())).await);
    let start = created.find("<UploadId>").expect("an upload id") + "<UploadId>".len();
    let end = created[start..].find("</UploadId>").expect("an upload id") + start;
    let upload = &created[start..end];
    let part = format!("/servererrors/mpu?partNumber=1&uploadId={upload}");
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        &part,
        Bytes::from_static(b"hello"),
        &[("content-md5", "not-base64!")],
    );
    assert_code(&exchange(&service, request).await, 400, "InvalidDigest");
    let listed = body_of(
        &exchange(
            &service,
            as_main(http::Method::GET, &format!("/servererrors/mpu?uploadId={upload}"), Bytes::new()),
        )
        .await,
    );
    assert!(!listed.contains("<PartNumber>"), "{listed}");
}

/// Negative — a trailer checksum whose value is not base64 is `400 BadDigest`, the code legacy
/// RustFS gives every other unreadable checksum, and the object is not stored.
#[tokio::test]
async fn n_an_unreadable_trailer_checksum_is_bad_digest() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let body = framed(b"hello", "x-amz-checksum-crc32:not base64!\r\n");
    let request = streaming_put("/servererrors/trailed", 5, "x-amz-checksum-crc32", body);
    assert_code(&exchange(&service, request).await, 400, "BadDigest");
    let head = exchange(&service, as_main(http::Method::HEAD, "/servererrors/trailed", Bytes::new())).await;
    assert_eq!(head.status(), 404);
}

/// Negative — a PutObjectTagging body that does not hash to its signed `x-amz-content-sha256` is
/// `400 XAmzContentSHA256Mismatch`, and the object's tags are unchanged.
#[tokio::test]
async fn n_a_tagging_body_that_does_not_hash_to_its_signed_digest_changes_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let signed_body = "<Tagging><TagSet><Tag><Key>signed</Key><Value>1</Value></Tag></TagSet></Tagging>";
    let sent_body = "<Tagging><TagSet><Tag><Key>posted</Key><Value>1</Value></Tag></TagSet></Tagging>";
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/servererrors/tagged?tagging",
        Bytes::from_static(signed_body.as_bytes()),
        &[],
    )
    .map(|_| Bytes::from_static(sent_body.as_bytes()));
    assert_code(&exchange(&service, request).await, 400, "XAmzContentSHA256Mismatch");
    let tags = body_of(&exchange(&service, as_main(http::Method::GET, "/servererrors/tagged?tagging", Bytes::new())).await);
    assert!(!tags.contains("<Key>"), "{tags}");
}

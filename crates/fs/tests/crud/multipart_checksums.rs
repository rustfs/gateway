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

//! Multipart checksum negotiation evidence for the filesystem reference backend.
//!
//! Responsible for: initiation persistence, per-part algorithm/value enforcement, retryability,
//! and completion checksum reporting through signed production requests.
//! NOT responsible for: minimum-part sizing, version publication, lifecycle, or object tags.
//! Upstream: the filesystem multipart authority. Downstream: the crate verification gate.

use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec};

use super::*;

pub(super) fn checksum(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> ChecksumSpec {
    let mut checksummer = algorithm.checksummer();
    checksummer.update(bytes);
    ChecksumSpec::from_digest(algorithm, &checksummer.finalize()).expect("a computed checksum has the algorithm width")
}

pub(super) async fn initiate_checksum(
    service: &S3Service,
    bucket: &str,
    key: &str,
    algorithm: &str,
    checksum_type: &str,
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-algorithm"),
        http::HeaderValue::from_str(algorithm).expect("a fixture algorithm"),
    );
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-type"),
        http::HeaderValue::from_str(checksum_type).expect("a fixture checksum type"),
    );
    exchange(
        service,
        signed_with_headers(http::Method::POST, &format!("/{bucket}/{key}?uploads"), Bytes::new(), headers),
    )
    .await
}

pub(super) async fn put_checksum_part(
    service: &S3Service,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: i32,
    checksum: ChecksumSpec,
    body: &'static [u8],
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static(checksum.algorithm().header_name()),
        http::HeaderValue::from_str(checksum.render_base64()).expect("a fixture checksum"),
    );
    exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("/{bucket}/{key}?partNumber={part_number}&uploadId={upload_id}"),
            Bytes::from_static(body),
            headers,
        ),
    )
    .await
}

pub(super) fn completion_with_checksum(part_number: i32, etag: &str, algorithm: ChecksumAlgorithm, value: &str) -> Bytes {
    let element = match algorithm {
        ChecksumAlgorithm::Crc32 => "ChecksumCRC32",
        ChecksumAlgorithm::Crc32c => "ChecksumCRC32C",
        ChecksumAlgorithm::Crc64Nvme => "ChecksumCRC64NVME",
        ChecksumAlgorithm::Sha1 => "ChecksumSHA1",
        ChecksumAlgorithm::Sha256 => "ChecksumSHA256",
        _ => unreachable!("the public checksum algorithm set is exhausted by this fixture"),
    };
    Bytes::from(format!(
        "<CompleteMultipartUpload><Part><PartNumber>{part_number}</PartNumber><ETag>{etag}</ETag><{element}>{value}</{element}></Part></CompleteMultipartUpload>"
    ))
}

pub(super) async fn complete_checksum(
    service: &S3Service,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: Bytes,
) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed(http::Method::POST, &format!("/{bucket}/{key}?uploadId={upload_id}"), body),
    )
    .await
}

async fn complete_checksum_with_headers(
    service: &S3Service,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: Bytes,
    headers: http::HeaderMap,
) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(http::Method::POST, &format!("/{bucket}/{key}?uploadId={upload_id}"), body, headers),
    )
    .await
}

pub(super) fn error_code(response: &rustfs_gateway::WireResponse) -> Option<String> {
    element(response.body(), "Code")
}

pub(super) fn upload_record(root: &TestRoot, bucket: &str, upload_id: &str) -> PathBuf {
    let digest = Sha256::digest(upload_id.as_bytes());
    root.0
        .join(format!("b-{}", hex::encode(bucket.as_bytes())))
        .join("uploads")
        .join(format!("u-{}", hex::encode(digest)))
        .join("record")
}

/// Positive — the negotiated algorithm survives restart and drives both part and completion output.
#[tokio::test]
async fn negotiated_composite_checksum_survives_restart_and_is_reported() {
    let root = TestRoot::new();
    let (_, initial_service) = service(&root);
    create_bucket(&initial_service, "checksum-persist").await;
    let initiated = initiate_checksum(&initial_service, "checksum-persist", "object", "CRC32C", "COMPOSITE").await;
    assert_eq!(initiated.status(), 200, "{}", String::from_utf8_lossy(initiated.body()));
    assert_eq!(
        header(&initiated, "x-amz-checksum-algorithm"),
        Some(&http::HeaderValue::from_static("CRC32C"))
    );
    assert_eq!(
        header(&initiated, "x-amz-checksum-type"),
        Some(&http::HeaderValue::from_static("COMPOSITE"))
    );
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    drop(initial_service);

    let (_, restarted) = service(&root);
    let part_checksum = checksum(ChecksumAlgorithm::Crc32c, b"persistent-part");
    let uploaded =
        put_checksum_part(&restarted, "checksum-persist", "object", &upload_id, 1, part_checksum, b"persistent-part").await;
    assert_eq!(uploaded.status(), 200, "{}", String::from_utf8_lossy(uploaded.body()));
    assert_eq!(
        header(&uploaded, "x-amz-checksum-crc32c"),
        Some(&http::HeaderValue::from_str(part_checksum.render_base64()).expect("a checksum header"))
    );
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let completed = complete_checksum(
        &restarted,
        "checksum-persist",
        "object",
        &upload_id,
        completion_with_checksum(1, etag, ChecksumAlgorithm::Crc32c, part_checksum.render_base64()),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    let composite = ChecksumSpec::composite_of(&[part_checksum]).expect("one part has a composite checksum");
    assert_eq!(element(completed.body(), "ChecksumCRC32C").as_deref(), Some(composite.render_base64()));
    assert_eq!(element(completed.body(), "ChecksumType").as_deref(), Some("COMPOSITE"));
}

/// Positive — a full-object CRC may omit part checksum claims and reports the assembled checksum.
#[tokio::test]
async fn full_object_crc_computes_the_checksum_from_the_assembled_bytes() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-full").await;
    let initiated = initiate_checksum(&service, "checksum-full", "object", "CRC32", "FULL_OBJECT").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let uploaded = exchange(
        &service,
        signed(
            http::Method::PUT,
            &format!("/checksum-full/object?partNumber=1&uploadId={upload_id}"),
            Bytes::from_static(b"full-object"),
        ),
    )
    .await;
    assert_eq!(uploaded.status(), 200, "{}", String::from_utf8_lossy(uploaded.body()));
    let expected = checksum(ChecksumAlgorithm::Crc32, b"full-object");
    assert_eq!(
        header(&uploaded, "x-amz-checksum-crc32"),
        Some(&http::HeaderValue::from_str(expected.render_base64()).expect("a checksum header"))
    );
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let completed = complete(&service, "checksum-full", "object", &upload_id, &[(1, etag)]).await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    assert_eq!(element(completed.body(), "ChecksumCRC32").as_deref(), Some(expected.render_base64()));
    assert_eq!(element(completed.body(), "ChecksumType").as_deref(), Some("FULL_OBJECT"));
}

/// Negative — a negotiated upload refuses a part without the promised checksum and remains usable.
#[tokio::test]
async fn missing_part_checksum_is_rejected_without_consuming_the_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-missing").await;
    let initiated = initiate_checksum(&service, "checksum-missing", "object", "SHA256", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let missing = exchange(
        &service,
        signed(
            http::Method::PUT,
            &format!("/checksum-missing/object?partNumber=1&uploadId={upload_id}"),
            Bytes::from_static(b"retryable"),
        ),
    )
    .await;
    assert_eq!(missing.status(), 400, "{}", String::from_utf8_lossy(missing.body()));
    assert_eq!(error_code(&missing).as_deref(), Some("InvalidRequest"));
    let absent = complete_checksum(
        &service,
        "checksum-missing",
        "object",
        &upload_id,
        completion_with_checksum(
            1,
            "\"00000000000000000000000000000000\"",
            ChecksumAlgorithm::Sha256,
            checksum(ChecksumAlgorithm::Sha256, b"retryable").render_base64(),
        ),
    )
    .await;
    assert_eq!(absent.status(), 400);

    let digest = checksum(ChecksumAlgorithm::Sha256, b"retryable");
    let retry = put_checksum_part(&service, "checksum-missing", "object", &upload_id, 1, digest, b"retryable").await;
    assert_eq!(retry.status(), 200, "{}", String::from_utf8_lossy(retry.body()));
}

/// Negative — a valid digest under a different algorithm cannot satisfy the initiation contract.
#[tokio::test]
async fn part_checksum_algorithm_must_match_the_negotiated_algorithm() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-algorithm").await;
    let initiated = initiate_checksum(&service, "checksum-algorithm", "object", "CRC32C", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let crc32 = checksum(ChecksumAlgorithm::Crc32, b"same-bytes");
    let refused = put_checksum_part(&service, "checksum-algorithm", "object", &upload_id, 1, crc32, b"same-bytes").await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));

    let crc32c = checksum(ChecksumAlgorithm::Crc32c, b"same-bytes");
    let retry = put_checksum_part(&service, "checksum-algorithm", "object", &upload_id, 1, crc32c, b"same-bytes").await;
    assert_eq!(retry.status(), 200, "{}", String::from_utf8_lossy(retry.body()));
}

/// Negative — corrupt part bytes are rejected before the part becomes completion-visible.
#[tokio::test]
async fn corrupt_part_checksum_does_not_publish_a_part_or_object() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-corrupt").await;
    let initiated = initiate_checksum(&service, "checksum-corrupt", "object", "SHA1", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let wrong = checksum(ChecksumAlgorithm::Sha1, b"different");
    let refused = put_checksum_part(&service, "checksum-corrupt", "object", &upload_id, 1, wrong, b"received").await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("XAmzContentChecksumMismatch"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/checksum-corrupt/object", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — completion must quote the checksum returned for the selected part and remains retryable.
#[tokio::test]
async fn completion_checksum_disagreement_is_rejected_before_publication() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-complete").await;
    let initiated = initiate_checksum(&service, "checksum-complete", "object", "CRC32", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let actual = checksum(ChecksumAlgorithm::Crc32, b"part");
    let uploaded = put_checksum_part(&service, "checksum-complete", "object", &upload_id, 1, actual, b"part").await;
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let wrong = checksum(ChecksumAlgorithm::Crc32, b"wrong");
    let refused = complete_checksum(
        &service,
        "checksum-complete",
        "object",
        &upload_id,
        completion_with_checksum(1, etag, ChecksumAlgorithm::Crc32, wrong.render_base64()),
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("XAmzContentChecksumMismatch"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/checksum-complete/object", Bytes::new()))
            .await
            .status(),
        404
    );

    let retried = complete_checksum(
        &service,
        "checksum-complete",
        "object",
        &upload_id,
        completion_with_checksum(1, etag, ChecksumAlgorithm::Crc32, actual.render_base64()),
    )
    .await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — checksum uploads require a consecutive part sequence beginning at one.
#[tokio::test]
async fn nonconsecutive_checksum_parts_are_rejected_without_retiring_the_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-order").await;
    let initiated = initiate_checksum(&service, "checksum-order", "object", "SHA256", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let part_checksum = checksum(ChecksumAlgorithm::Sha256, b"part-two");
    let uploaded = put_checksum_part(&service, "checksum-order", "object", &upload_id, 2, part_checksum, b"part-two").await;
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let refused = complete_checksum(
        &service,
        "checksum-order",
        "object",
        &upload_id,
        completion_with_checksum(2, etag, ChecksumAlgorithm::Sha256, part_checksum.render_base64()),
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidPartOrder"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/checksum-order/object", Bytes::new()))
            .await
            .status(),
        404
    );

    let listed = exchange(
        &service,
        signed(http::Method::GET, &format!("/checksum-order/object?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert_eq!(element(listed.body(), "PartNumber").as_deref(), Some("2"));
}

/// A bare completion digest uses the negotiated composite type; supplied counts still bind.
#[tokio::test]
async fn bare_composite_completion_validates_digest_algorithm_and_optional_part_count() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-bare").await;
    let initiated = initiate_checksum(&service, "checksum-bare", "object", "CRC32C", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    // Independent CRC32C vectors for the twelve-byte body and its four-byte part digest (#1275).
    let part_checksum = ChecksumSpec::parse_header("x-amz-checksum-crc32c", "WMQBEQ==").expect("a fixed part checksum");
    let uploaded = put_checksum_part(&service, "checksum-bare", "object", &upload_id, 1, part_checksum, b"testcontent\n").await;
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let body = completion_with_checksum(1, etag, ChecksumAlgorithm::Crc32c, "WMQBEQ==");
    for (name, value) in [
        ("x-amz-checksum-crc32c", "k61Pow=="),
        ("x-amz-checksum-crc32c", "3+pJYA==-2"),
        ("x-amz-checksum-crc32", "3+pJYA=="),
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
        let refused =
            complete_checksum_with_headers(&service, "checksum-bare", "object", &upload_id, body.clone(), headers).await;
        assert_eq!(refused.status(), 400, "{name}: {value}");
        assert_eq!(error_code(&refused).as_deref(), Some("BadDigest"), "{name}: {value}");
        assert_eq!(
            exchange(&service, signed(http::Method::GET, "/checksum-bare/object", Bytes::new()))
                .await
                .status(),
            404,
            "a refused completion must not publish an object"
        );
    }
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-crc32c"),
        http::HeaderValue::from_static("3+pJYA=="),
    );
    let completed = complete_checksum_with_headers(&service, "checksum-bare", "object", &upload_id, body, headers).await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    let fetched = exchange(&service, signed(http::Method::GET, "/checksum-bare/object", Bytes::new())).await;
    assert_eq!(fetched.status(), 200);
    assert_eq!(fetched.body(), b"testcontent\n".as_slice());
}

/// Negative — completion cannot change the checksum type selected at initiation.
#[tokio::test]
async fn completion_checksum_type_disagreement_returns_bad_digest_and_is_retryable() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-type").await;
    let initiated = initiate_checksum(&service, "checksum-type", "object", "CRC32", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let part_checksum = checksum(ChecksumAlgorithm::Crc32, b"part");
    let uploaded = put_checksum_part(&service, "checksum-type", "object", &upload_id, 1, part_checksum, b"part").await;
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let body = completion_with_checksum(1, etag, ChecksumAlgorithm::Crc32, part_checksum.render_base64());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-type"),
        http::HeaderValue::from_static("FULL_OBJECT"),
    );
    let refused = complete_checksum_with_headers(&service, "checksum-type", "object", &upload_id, body.clone(), headers).await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("BadDigest"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/checksum-type/object", Bytes::new()))
            .await
            .status(),
        404
    );

    let retried = complete_checksum(&service, "checksum-type", "object", &upload_id, body).await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — a wrong full-object completion checksum is rejected before publication.
#[tokio::test]
async fn full_object_completion_checksum_mismatch_returns_bad_digest_and_is_retryable() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-object").await;
    let initiated = initiate_checksum(&service, "checksum-object", "object", "CRC32C", "FULL_OBJECT").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let uploaded = exchange(
        &service,
        signed(
            http::Method::PUT,
            &format!("/checksum-object/object?partNumber=1&uploadId={upload_id}"),
            Bytes::from_static(b"assembled"),
        ),
    )
    .await;
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let body = completion(&[(1, etag)]);
    let wrong = checksum(ChecksumAlgorithm::Crc32c, b"different");
    let mut wrong_headers = http::HeaderMap::new();
    wrong_headers.insert(
        http::HeaderName::from_static("x-amz-checksum-crc32c"),
        http::HeaderValue::from_str(wrong.render_base64()).expect("a checksum header"),
    );
    wrong_headers.insert(
        http::HeaderName::from_static("x-amz-checksum-type"),
        http::HeaderValue::from_static("FULL_OBJECT"),
    );
    let refused =
        complete_checksum_with_headers(&service, "checksum-object", "object", &upload_id, body.clone(), wrong_headers).await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("BadDigest"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/checksum-object/object", Bytes::new()))
            .await
            .status(),
        404
    );

    let expected = checksum(ChecksumAlgorithm::Crc32c, b"assembled");
    let mut correct_headers = http::HeaderMap::new();
    correct_headers.insert(
        http::HeaderName::from_static("x-amz-checksum-crc32c"),
        http::HeaderValue::from_str(expected.render_base64()).expect("a checksum header"),
    );
    correct_headers.insert(
        http::HeaderName::from_static("x-amz-checksum-type"),
        http::HeaderValue::from_static("FULL_OBJECT"),
    );
    let retried = complete_checksum_with_headers(&service, "checksum-object", "object", &upload_id, body, correct_headers).await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — a completion checksum cannot create negotiation state that initiation omitted.
#[tokio::test]
async fn completion_checksum_without_initiation_is_rejected_before_publication() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-late").await;
    let upload_id = initiate(&service, "checksum-late", "object").await;
    let etag = upload_part(&service, "checksum-late", "object", &upload_id, 1, b"late").await;
    let body = completion(&[(1, etag.as_str())]);
    let late = checksum(ChecksumAlgorithm::Crc32, b"late");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-crc32"),
        http::HeaderValue::from_str(late.render_base64()).expect("a checksum header"),
    );
    let refused = complete_checksum_with_headers(&service, "checksum-late", "object", &upload_id, body.clone(), headers).await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/checksum-late/object", Bytes::new()))
            .await
            .status(),
        404
    );

    let retried = complete_checksum(&service, "checksum-late", "object", &upload_id, body).await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — SHA algorithms cannot claim the CRC-only full-object combination mode.
#[tokio::test]
async fn unsupported_full_object_algorithm_is_rejected_before_upload_creation() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "checksum-unsupported").await;
    let refused = initiate_checksum(&service, "checksum-unsupported", "object", "SHA256", "FULL_OBJECT").await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));
    assert!(element(refused.body(), "UploadId").is_none());
}

/// Negative — an impossible persisted algorithm/type pair is never reinterpreted as a live upload.
#[tokio::test]
async fn corrupt_persisted_checksum_negotiation_fails_closed_after_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "checksum-state").await;
    let initiated = initiate_checksum(&running, "checksum-state", "object", "SHA256", "COMPOSITE").await;
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let record = upload_record(&root, "checksum-state", &upload_id);
    let encoded = std::fs::read_to_string(&record).expect("a persisted upload record");
    let prefix = encoded
        .strip_suffix("COMPOSITE\n")
        .expect("the negotiated checksum type suffix");
    std::fs::write(record, format!("{prefix}FULL_OBJECT\n")).expect("a corrupt checksum negotiation fixture");
    drop(running);

    let (_, restarted) = service(&root);
    let listed = exchange(&restarted, signed(http::Method::GET, "/checksum-state?uploads", Bytes::new())).await;
    assert_eq!(listed.status(), 500, "{}", String::from_utf8_lossy(listed.body()));
    let digest = checksum(ChecksumAlgorithm::Sha256, b"part");
    let refused = put_checksum_part(&restarted, "checksum-state", "object", &upload_id, 1, digest, b"part").await;
    assert_eq!(refused.status(), 404, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("NoSuchUpload"));
    assert_eq!(
        exchange(&restarted, signed(http::Method::GET, "/checksum-state/object", Bytes::new()))
            .await
            .status(),
        404
    );
}

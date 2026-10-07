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

//! Optional checksum claims in a multipart completion manifest.
//!
//! Responsible for: omitted claims, persisted computed values and rejection/retry boundaries.
//! NOT responsible for: UploadPart's checksum transport or negotiation grammar.
//! Upstream: signed completion requests. Downstream: the filesystem verification gate.

use super::*;

const BUCKET: &str = "checksum-manifest";
const BODY: &[u8] = b"verified-upload-part";

fn text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

fn manifest(number: i32, tag: &str, claim: &str) -> Bytes {
    Bytes::from(format!(
        "<CompleteMultipartUpload><Part><PartNumber>{number}</PartNumber><ETag>{tag}</ETag>{claim}</Part></CompleteMultipartUpload>"
    ))
}

async fn pending(service: &S3Service, algorithm: ChecksumAlgorithm, number: i32) -> (String, String, ChecksumSpec) {
    create_bucket(service, BUCKET).await;
    let begun = initiate_checksum(service, BUCKET, "object", algorithm.wire_name(), "COMPOSITE").await;
    assert_eq!(begun.status(), 200);
    let id = element(begun.body(), "UploadId").expect("upload");
    let value = checksum(algorithm, BODY);
    let uploaded = put_checksum_part(service, BUCKET, "object", &id, number, value, BODY).await;
    assert_eq!(uploaded.status(), 200);
    (id, text(&uploaded, "etag").expect("ETag").to_owned(), value)
}

async fn assert_absent(service: &S3Service) {
    let fetched = exchange(service, signed(http::Method::GET, &format!("/{BUCKET}/object"), Bytes::new())).await;
    assert_eq!(fetched.status(), 404);
}

#[tokio::test]
async fn omitted_claims_preserve_checksums_across_restart_and_replay() {
    for algorithm in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
    ] {
        let root = TestRoot::new();
        let (_, initial) = service(&root);
        let (id, tag, value) = pending(&initial, algorithm, 1).await;
        drop(initial);
        let (_, restarted) = service(&root);
        let body = manifest(1, &tag, "");
        let completed = complete_checksum(&restarted, BUCKET, "object", &id, body.clone()).await;
        assert_eq!(completed.status(), 200);
        let expected = ChecksumSpec::composite_of(&[value]).expect("composite");
        let field = match algorithm {
            ChecksumAlgorithm::Crc32 => "ChecksumCRC32",
            ChecksumAlgorithm::Crc32c => "ChecksumCRC32C",
            ChecksumAlgorithm::Sha1 => "ChecksumSHA1",
            ChecksumAlgorithm::Sha256 => "ChecksumSHA256",
            _ => unreachable!("fixture algorithms"),
        };
        assert_eq!(element(completed.body(), field).as_deref(), Some(expected.render_base64()));
        assert_eq!(element(completed.body(), "ChecksumType").as_deref(), Some("COMPOSITE"));
        drop(restarted);
        let (_, reopened) = service(&root);
        let replay = complete_checksum(&reopened, BUCKET, "object", &id, body).await;
        assert_eq!(replay.status(), 200);
        assert_eq!(element(replay.body(), field).as_deref(), Some(expected.render_base64()));
        assert_eq!(element(replay.body(), "ChecksumType").as_deref(), Some("COMPOSITE"));
        for method in [http::Method::GET, http::Method::HEAD] {
            for (query, expected) in [("", expected), ("?partNumber=1", value)] {
                let mut headers = http::HeaderMap::new();
                headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
                let fetched = exchange(
                    &reopened,
                    signed_with_headers(method.clone(), &format!("/{BUCKET}/object{query}"), Bytes::new(), headers),
                )
                .await;
                assert_eq!(
                    fetched.status(),
                    if method == http::Method::GET && !query.is_empty() {
                        206
                    } else {
                        200
                    }
                );
                assert_eq!(text(&fetched, algorithm.header_name()), Some(expected.render_base64()));
                assert_eq!(text(&fetched, "x-amz-checksum-type"), Some("COMPOSITE"));
                if method == http::Method::GET {
                    assert_eq!(fetched.body().as_ref(), BODY);
                }
            }
        }
    }
}

#[tokio::test]
async fn mixed_present_and_omitted_claims_use_each_parts_bytes() {
    use super::super::multipart_sizing::{FramedBody, MIN_PART_SIZE};
    for missing_first in [false, true] {
        let root = TestRoot::new();
        let (_, service) = service(&root);
        create_bucket(&service, BUCKET).await;
        let begun = initiate_checksum(&service, BUCKET, "object", "CRC32", "COMPOSITE").await;
        let id = element(begun.body(), "UploadId").expect("upload");
        let mut parts = String::new();
        let mut values = Vec::new();
        for (index, body) in [Bytes::from(vec![b'a'; MIN_PART_SIZE]), Bytes::from_static(BODY)]
            .into_iter()
            .enumerate()
        {
            let number = index + 1;
            let value = checksum(ChecksumAlgorithm::Crc32, &body);
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "x-amz-checksum-crc32",
                http::HeaderValue::from_str(value.render_base64()).expect("checksum"),
            );
            let request = signed_with_headers(
                http::Method::PUT,
                &format!("/{BUCKET}/object?partNumber={number}&uploadId={id}"),
                body.clone(),
                headers,
            );
            let (head, _) = request.into_parts();
            let uploaded = collect(service.call(http::Request::from_parts(head, FramedBody::new(body))).await)
                .await
                .expect("response");
            assert_eq!(uploaded.status(), 200);
            let tag = text(&uploaded, "etag").expect("ETag");
            let claim = if (index == 0) == missing_first {
                String::new()
            } else {
                format!("<ChecksumCRC32>{}</ChecksumCRC32>", value.render_base64())
            };
            parts.push_str(&format!("<Part><PartNumber>{number}</PartNumber><ETag>{tag}</ETag>{claim}</Part>"));
            values.push(value);
        }
        let completed = complete_checksum(
            &service,
            BUCKET,
            "object",
            &id,
            Bytes::from(format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")),
        )
        .await;
        assert_eq!(completed.status(), 200);
        assert_eq!(
            element(completed.body(), "ChecksumCRC32").as_deref(),
            Some(ChecksumSpec::composite_of(&values).expect("composite").render_base64())
        );
    }
}

async fn refused_claim(claim: &str, code: &str) {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let (id, tag, _) = pending(&service, ChecksumAlgorithm::Crc32, 1).await;
    let refused = complete_checksum(&service, BUCKET, "object", &id, manifest(1, &tag, claim)).await;
    assert_eq!(refused.status(), 400);
    assert_eq!(error_code(&refused).as_deref(), Some(code));
    assert_absent(&service).await;
    let retry = complete_checksum(&service, BUCKET, "object", &id, manifest(1, &tag, "")).await;
    assert_eq!(retry.status(), 200);
}

#[tokio::test]
async fn n_a_supplied_wrong_checksum_is_not_treated_as_omitted() {
    let wrong = checksum(ChecksumAlgorithm::Crc32, b"wrong");
    refused_claim(
        &format!("<ChecksumCRC32>{}</ChecksumCRC32>", wrong.render_base64()),
        "XAmzContentChecksumMismatch",
    )
    .await;
}

#[tokio::test]
async fn n_malformed_and_empty_claims_are_not_treated_as_omitted() {
    for value in ["", "!", "AAAA"] {
        refused_claim(&format!("<ChecksumCRC32>{value}</ChecksumCRC32>"), "InvalidPart").await;
    }
}

#[tokio::test]
async fn n_another_algorithm_does_not_replace_an_omitted_negotiated_claim() {
    let other = checksum(ChecksumAlgorithm::Sha256, BODY);
    refused_claim(&format!("<ChecksumSHA256>{}</ChecksumSHA256>", other.render_base64()), "InvalidPart").await;
}

#[tokio::test]
async fn n_multiple_claims_are_not_treated_as_one_optional_claim() {
    let value = checksum(ChecksumAlgorithm::Crc32, BODY);
    let other = checksum(ChecksumAlgorithm::Sha256, BODY);
    refused_claim(
        &format!(
            "<ChecksumCRC32>{}</ChecksumCRC32><ChecksumSHA256>{}</ChecksumSHA256>",
            value.render_base64(),
            other.render_base64()
        ),
        "InvalidPart",
    )
    .await;
}

#[tokio::test]
async fn n_an_omitted_checksum_does_not_bypass_the_entity_tag() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let (id, tag, _) = pending(&service, ChecksumAlgorithm::Crc32, 1).await;
    let refused =
        complete_checksum(&service, BUCKET, "object", &id, manifest(1, "\"00000000000000000000000000000000\"", "")).await;
    assert_eq!(refused.status(), 400);
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidPart"));
    assert_absent(&service).await;
    assert_eq!(
        complete_checksum(&service, BUCKET, "object", &id, manifest(1, &tag, ""))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn n_an_omitted_checksum_does_not_allow_a_nonconsecutive_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let (id, tag, value) = pending(&service, ChecksumAlgorithm::Crc32, 2).await;
    let refused = complete_checksum(&service, BUCKET, "object", &id, manifest(2, &tag, "")).await;
    assert_eq!(refused.status(), 400);
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidPartOrder"));
    assert_absent(&service).await;
    let uploaded = put_checksum_part(&service, BUCKET, "object", &id, 1, value, BODY).await;
    assert_eq!(uploaded.status(), 200);
    assert_eq!(
        complete_checksum(&service, BUCKET, "object", &id, manifest(1, text(&uploaded, "etag").expect("ETag"), ""))
            .await
            .status(),
        200
    );
}

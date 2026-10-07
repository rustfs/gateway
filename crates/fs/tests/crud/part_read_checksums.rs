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

//! Stored individual checksums on GET/HEAD part windows.
//!
//! Responsible for: checksum mode, exact part boundaries, upload type and version isolation.
//! NOT responsible for: multipart completion validation or window arithmetic.
//! Upstream: validated persisted part metadata. Downstream: the filesystem gate.

use super::super::multipart_checksums::{checksum, complete_checksum, initiate_checksum};
use super::super::multipart_sizing::FramedBody;
use super::*;
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec, WireResponse};

async fn checked_upload(
    service: &S3Service,
    algorithm: ChecksumAlgorithm,
    kind: &str,
    two: bool,
) -> (WireResponse, Vec<ChecksumSpec>) {
    let begun = initiate_checksum(service, BUCKET, "object", algorithm.wire_name(), kind).await;
    assert_eq!(begun.status(), 200);
    let id = element(begun.body(), "UploadId").expect("upload ID");
    let mut bodies = Vec::new();
    if two {
        bodies.push(Bytes::from(vec![b'a'; MIN_PART_SIZE]));
    }
    bodies.push(Bytes::from_static(TAIL));
    let mut values = Vec::new();
    let mut parts = String::new();
    for (index, body) in bodies.into_iter().enumerate() {
        let number = index + 1;
        let value = checksum(algorithm, &body);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static(algorithm.header_name()),
            http::HeaderValue::from_str(value.render_base64()).expect("checksum"),
        );
        let request = signed_with_headers(
            http::Method::PUT,
            &format!("/{BUCKET}/object?partNumber={number}&uploadId={id}"),
            body.clone(),
            headers,
        );
        let (head, _) = request.into_parts();
        let response = collect(service.call(http::Request::from_parts(head, FramedBody::new(body))).await)
            .await
            .expect("response");
        assert_eq!(response.status(), 200);
        let tag = text(&response, "etag").expect("part ETag");
        let field = match algorithm {
            ChecksumAlgorithm::Crc32 => "ChecksumCRC32",
            ChecksumAlgorithm::Sha256 => "ChecksumSHA256",
            _ => unreachable!("fixture algorithms"),
        };
        parts.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{tag}</ETag><{field}>{}</{field}></Part>",
            value.render_base64()
        ));
        values.push(value);
    }
    let response = complete_checksum(
        service,
        BUCKET,
        "object",
        &id,
        Bytes::from(format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")),
    )
    .await;
    assert_eq!(response.status(), 200);
    (response, values)
}

async fn read(service: &S3Service, method: http::Method, query: &str, range: Option<&str>, enabled: bool) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    if enabled {
        headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
    }
    if let Some(range) = range {
        headers.insert("range", http::HeaderValue::from_str(range).expect("range"));
    }
    exchange(
        service,
        signed_with_headers(method, &format!("/{BUCKET}/object?{query}"), Bytes::new(), headers),
    )
    .await
}

fn no_checksum(response: &WireResponse) {
    assert!(text(response, "x-amz-checksum-crc32").is_none());
    assert!(text(response, "x-amz-checksum-sha256").is_none());
    assert!(text(response, "x-amz-checksum-type").is_none());
}

#[tokio::test]
async fn part_checksums_survive_restart_without_changing_the_upload_type() {
    for (algorithm, kind) in [
        (ChecksumAlgorithm::Crc32, "COMPOSITE"),
        (ChecksumAlgorithm::Sha256, "COMPOSITE"),
        (ChecksumAlgorithm::Crc32, "FULL_OBJECT"),
    ] {
        let root = TestRoot::new();
        let (_, initial) = service(&root);
        create_bucket(&initial, BUCKET).await;
        let (_, values) = checked_upload(&initial, algorithm, kind, true).await;
        drop(initial);
        let (_, reopened) = service(&root);
        for (index, value) in values.iter().enumerate() {
            for method in [http::Method::GET, http::Method::HEAD] {
                let response = read(&reopened, method.clone(), &format!("partNumber={}", index + 1), None, true).await;
                assert_eq!(response.status(), if method == http::Method::GET { 206 } else { 200 });
                assert_eq!(text(&response, algorithm.header_name()), Some(value.render_base64()));
                assert_eq!(text(&response, "x-amz-checksum-type"), Some(kind));
                assert_eq!(text(&response, "x-amz-mp-parts-count"), Some("2"));
                if method == http::Method::GET {
                    assert_eq!(response.body().len(), if index == 0 { MIN_PART_SIZE } else { TAIL.len() });
                }
            }
        }
    }
}

#[tokio::test]
async fn aligned_ranges_report_the_matching_individual_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let (_, values) = checked_upload(&service, ChecksumAlgorithm::Crc32, "COMPOSITE", true).await;
    for (range, value) in [
        ("bytes=0-5242879", values[0]),
        ("bytes=5242880-", values[1]),
        ("bytes=-9", values[1]),
    ] {
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = read(&service, method, "", Some(range), true).await;
            assert_eq!(response.status(), 206);
            assert_eq!(text(&response, "x-amz-checksum-crc32"), Some(value.render_base64()));
            assert_eq!(text(&response, "x-amz-checksum-type"), Some("COMPOSITE"));
        }
    }
}

#[tokio::test]
async fn explicit_version_keeps_its_individual_checksum_after_replacement() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    assert_eq!(
        super::super::multipart_versioning::set_versioning(&initial, BUCKET, "Enabled")
            .await
            .status(),
        200
    );
    let (completed, values) = checked_upload(&initial, ChecksumAlgorithm::Crc32, "COMPOSITE", false).await;
    let version = text(&completed, "x-amz-version-id").expect("version").to_owned();
    assert_eq!(
        exchange(
            &initial,
            signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(b"new"))
        )
        .await
        .status(),
        200
    );
    drop(initial);
    let (_, reopened) = service(&root);
    for method in [http::Method::GET, http::Method::HEAD] {
        let old = read(&reopened, method.clone(), &format!("partNumber=1&versionId={version}"), None, true).await;
        assert_eq!(text(&old, "x-amz-checksum-crc32"), Some(values[0].render_base64()));
        assert_eq!(text(&old, "x-amz-version-id"), Some(version.as_str()));
        let current = read(&reopened, method, "partNumber=1", None, true).await;
        no_checksum(&current);
    }
}

#[tokio::test]
async fn n_checksum_mode_is_required_for_part_and_aligned_range_reads() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    checked_upload(&service, ChecksumAlgorithm::Crc32, "COMPOSITE", false).await;
    for method in [http::Method::GET, http::Method::HEAD] {
        for (query, range) in [("partNumber=1", None), ("", Some("bytes=0-8"))] {
            let response = read(&service, method.clone(), query, range, false).await;
            assert!(response.status() == 200 || response.status() == 206);
            no_checksum(&response);
        }
    }
}

#[tokio::test]
async fn n_partial_part_ranges_do_not_report_a_whole_part_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    checked_upload(&service, ChecksumAlgorithm::Crc32, "COMPOSITE", false).await;
    for range in ["bytes=0-3", "bytes=1-8", "bytes=-3"] {
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = read(&service, method, "", Some(range), true).await;
            assert_eq!(response.status(), 206);
            no_checksum(&response);
        }
    }
}

#[tokio::test]
async fn n_ranges_spanning_parts_do_not_report_one_parts_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    checked_upload(&service, ChecksumAlgorithm::Crc32, "COMPOSITE", true).await;
    for range in ["bytes=5242878-5242881", "bytes=0-", "bytes=0-5242881"] {
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = read(&service, method, "", Some(range), true).await;
            assert_eq!(response.status(), 206);
            no_checksum(&response);
        }
    }
}

#[tokio::test]
async fn n_legacy_lengths_do_not_invent_an_individual_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let (_, values) = checked_upload(&initial, ChecksumAlgorithm::Crc32, "COMPOSITE", false).await;
    drop(initial);
    let path = super::super::object_checksums::one_record(&root);
    let encoded = std::fs::read_to_string(&path).expect("record");
    std::fs::write(path, encoded.split("part-meta/1").next().expect("legacy record")).expect("old metadata");
    let (_, reopened) = service(&root);
    for method in [http::Method::GET, http::Method::HEAD] {
        let part = read(&reopened, method.clone(), "partNumber=1", None, true).await;
        assert!(part.status() == 200 || part.status() == 206);
        no_checksum(&part);
        let whole = read(&reopened, method, "", None, true).await;
        assert_eq!(whole.status(), 200);
        assert_eq!(
            text(&whole, "x-amz-checksum-crc32"),
            Some(ChecksumSpec::composite_of(&values).expect("composite").render_base64())
        );
    }
}

#[tokio::test]
async fn n_unnegotiated_parts_do_not_acquire_a_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = read(&service, method, "partNumber=1", None, true).await;
        assert!(response.status() == 200 || response.status() == 206);
        no_checksum(&response);
    }
}

#[tokio::test]
async fn n_plain_part_selectors_do_not_invent_multipart_metadata() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let value = checksum(ChecksumAlgorithm::Crc32, TAIL);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-checksum-crc32",
        http::HeaderValue::from_str(value.render_base64()).expect("checksum"),
    );
    assert_eq!(
        exchange(
            &service,
            signed_with_headers(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(TAIL), headers)
        )
        .await
        .status(),
        200
    );
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = read(&service, method.clone(), "partNumber=1", None, true).await;
        assert!(response.status() == 200 || response.status() == 206);
        if method == http::Method::HEAD {
            assert_eq!(text(&response, "x-amz-checksum-crc32"), Some(value.render_base64()));
            assert!(text(&response, "x-amz-checksum-type").is_none());
        } else {
            no_checksum(&response);
        }
        assert!(text(&response, "x-amz-mp-parts-count").is_none());
    }
}

#[tokio::test]
async fn n_an_ignored_if_range_does_not_report_the_individual_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let (_, values) = checked_upload(&service, ChecksumAlgorithm::Crc32, "COMPOSITE", false).await;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
    headers.insert("range", http::HeaderValue::from_static("bytes=0-8"));
    headers.insert("if-range", http::HeaderValue::from_static("\"stale\""));
    let response = exchange(
        &service,
        signed_with_headers(http::Method::GET, &format!("/{BUCKET}/object"), Bytes::new(), headers),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().as_ref(), TAIL);
    assert_eq!(
        text(&response, "x-amz-checksum-crc32"),
        Some(ChecksumSpec::composite_of(&values).expect("composite").render_base64())
    );
    assert_eq!(text(&response, "x-amz-checksum-type"), Some("COMPOSITE"));
}

#[tokio::test]
async fn an_empty_completed_part_reports_its_individual_checksum() {
    use super::super::multipart_checksums::{completion_with_checksum, put_checksum_part};
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let value = checksum(ChecksumAlgorithm::Crc32, b"");
    let begun = initiate_checksum(&service, BUCKET, "object", "CRC32", "COMPOSITE").await;
    let id = element(begun.body(), "UploadId").expect("upload");
    let part = put_checksum_part(&service, BUCKET, "object", &id, 1, value, b"").await;
    let body = completion_with_checksum(1, text(&part, "etag").expect("ETag"), ChecksumAlgorithm::Crc32, value.render_base64());
    assert_eq!(complete_checksum(&service, BUCKET, "object", &id, body).await.status(), 200);
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = read(&service, method.clone(), "partNumber=1", None, true).await;
        assert_eq!(response.status(), 200);
        assert!(response.body().is_empty());
        assert_eq!(text(&response, "content-length"), Some("0"));
        assert_eq!(text(&response, "x-amz-checksum-crc32"), Some(value.render_base64()));
        assert_eq!(text(&response, "x-amz-checksum-type"), Some("COMPOSITE"));
        assert_eq!(text(&response, "x-amz-mp-parts-count"), Some("1"));
        let missing = read(&service, method.clone(), "partNumber=2", None, true).await;
        assert_eq!(missing.status(), if method == http::Method::GET { 400 } else { 416 });
        no_checksum(&missing);
    }
}

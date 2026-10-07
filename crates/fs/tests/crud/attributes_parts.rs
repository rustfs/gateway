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

//! ObjectParts selection and pagination through signed attributes requests.
//!
//! Responsible for: original numbers, page boundaries, per-part checksums and version isolation.
//! NOT responsible for: record grammar or GET part byte ranges.
//! Upstream: completed version records. Downstream: the filesystem gate.

use super::*;
use rustfs_gateway::WireResponse;

async fn page(
    service: &S3Service,
    selection: &str,
    marker: Option<&str>,
    max: Option<&str>,
    version: Option<&str>,
) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-object-attributes", http::HeaderValue::from_str(selection).expect("selection"));
    for (name, value) in [("x-amz-part-number-marker", marker), ("x-amz-max-parts", max)] {
        if let Some(value) = value {
            headers.insert(name, http::HeaderValue::from_str(value).expect("fixture"));
        }
    }
    let mut target = format!("/{BUCKET}/object?attributes");
    if let Some(version) = version {
        target.push_str(&format!("&versionId={version}"));
    }
    exchange(service, signed_with_headers(http::Method::GET, &target, Bytes::new(), headers)).await
}

async fn complete(service: &S3Service, two: bool) -> WireResponse {
    let id = initiate(service, BUCKET, "object").await;
    let mut parts = String::new();
    if two {
        let tag = super::super::super::multipart_sizing::upload_owned(
            service,
            BUCKET,
            "object",
            &id,
            2,
            Bytes::from(vec![b'a'; 5 * 1024 * 1024]),
        )
        .await;
        parts.push_str(&format!("<Part><PartNumber>2</PartNumber><ETag>{tag}</ETag></Part>"));
    }
    let tag = upload_part(service, BUCKET, "object", &id, 5, BODY).await;
    parts.push_str(&format!("<Part><PartNumber>5</PartNumber><ETag>{tag}</ETag></Part>"));
    let response = exchange(
        service,
        signed(
            http::Method::POST,
            &format!("/{BUCKET}/object?uploadId={id}"),
            Bytes::from(format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")),
        ),
    )
    .await;
    assert_eq!(response.status(), 200);
    response
}

fn part_rows(response: &WireResponse) -> Vec<(String, String)> {
    let xml = element(response.body(), "ObjectParts").expect("parts group");
    xml.split("<Part>")
        .skip(1)
        .map(|row| {
            (
                element(row.as_bytes(), "PartNumber").expect("number"),
                element(row.as_bytes(), "Size").expect("size"),
            )
        })
        .collect()
}

#[tokio::test]
async fn sparse_pages_survive_restart_with_original_numbers_and_sizes() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    complete(&initial, true).await;
    drop(initial);
    let (_, reopened) = service(&root);
    let first = page(&reopened, "ObjectParts", None, Some("1"), None).await;
    assert_eq!(first.status(), 200);
    assert_eq!(part_rows(&first), vec![("2".into(), "5242880".into())]);
    for (field, value) in [
        ("PartsCount", "2"),
        ("MaxParts", "1"),
        ("IsTruncated", "true"),
        ("NextPartNumberMarker", "2"),
    ] {
        assert_eq!(element(first.body(), field).as_deref(), Some(value), "{field}");
    }
    assert!(element(first.body(), "PartNumberMarker").is_none());
    let last = page(&reopened, "ObjectParts", Some("2"), Some("1"), None).await;
    assert_eq!(last.status(), 200);
    assert_eq!(part_rows(&last), vec![("5".into(), BODY.len().to_string())]);
    assert_eq!(element(last.body(), "IsTruncated").as_deref(), Some("false"));
    assert_eq!(element(last.body(), "PartNumberMarker").as_deref(), Some("2"));
    assert_eq!(element(last.body(), "NextPartNumberMarker").as_deref(), Some("5"));
}

#[tokio::test]
async fn stored_individual_checksums_are_not_composite_values() {
    use super::super::super::multipart_checksums::{
        checksum, complete_checksum, completion_with_checksum, initiate_checksum, put_checksum_part,
    };
    use rustfs_gateway::ChecksumAlgorithm;
    for (algorithm, field) in [
        (ChecksumAlgorithm::Crc32, "ChecksumCRC32"),
        (ChecksumAlgorithm::Sha256, "ChecksumSHA256"),
    ] {
        let root = TestRoot::new();
        let (_, initial) = service(&root);
        create_bucket(&initial, BUCKET).await;
        let value = checksum(algorithm, BODY);
        let begun = initiate_checksum(&initial, BUCKET, "object", algorithm.wire_name(), "COMPOSITE").await;
        let id = element(begun.body(), "UploadId").expect("upload");
        let part = put_checksum_part(&initial, BUCKET, "object", &id, 1, value, BODY).await;
        let xml = completion_with_checksum(1, text(&part, "etag").expect("ETag"), algorithm, value.render_base64());
        assert_eq!(complete_checksum(&initial, BUCKET, "object", &id, xml).await.status(), 200);
        drop(initial);
        let (_, reopened) = service(&root);
        let response = page(&reopened, "ObjectParts,Checksum", None, None, None).await;
        assert_eq!(response.status(), 200);
        let parts = element(response.body(), "ObjectParts").expect("parts");
        assert_eq!(element(parts.as_bytes(), field).as_deref(), Some(value.render_base64()));
        let whole = element(response.body(), "Checksum").expect("whole checksum");
        assert_eq!(
            element(whole.as_bytes(), field).as_deref(),
            Some(
                rustfs_gateway::ChecksumSpec::composite_of(&[value])
                    .expect("composite")
                    .render_base64()
            )
        );
        assert_eq!(element(response.body(), "MaxParts").as_deref(), Some("1000"));
    }
}

#[tokio::test]
async fn explicit_version_parts_do_not_follow_an_overwrite() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    assert_eq!(
        super::super::super::multipart_versioning::set_versioning(&initial, BUCKET, "Enabled")
            .await
            .status(),
        200
    );
    let completed = complete(&initial, false).await;
    let version = text(&completed, "x-amz-version-id").expect("version").to_owned();
    put(&initial, "object", b"replacement").await;
    drop(initial);
    let (_, reopened) = service(&root);
    let old = page(&reopened, "ObjectParts", None, None, Some(&version)).await;
    assert_eq!(old.status(), 200);
    assert_eq!(part_rows(&old), vec![("5".into(), BODY.len().to_string())]);
    assert_eq!(text(&old, "x-amz-version-id"), Some(version.as_str()));
    let current = page(&reopened, "ObjectParts", None, None, None).await;
    assert_eq!(current.status(), 200);
    assert!(element(current.body(), "ObjectParts").is_none());
}

#[tokio::test]
async fn n_missing_markers_do_not_restart_the_page() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    complete(&service, true).await;
    for marker in ["4", "+4", "04"] {
        let response = page(&service, "ObjectParts", Some(marker), Some("1000"), None).await;
        assert_eq!(response.status(), 200);
        assert_eq!(part_rows(&response), vec![("5".into(), BODY.len().to_string())]);
        assert_eq!(element(response.body(), "PartNumberMarker").as_deref(), Some("4"));
        assert_eq!(element(response.body(), "IsTruncated").as_deref(), Some("false"));
    }
}

#[tokio::test]
async fn n_markers_at_or_after_the_last_part_do_not_return_it() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    complete(&service, false).await;
    for marker in ["5", "6", "10001"] {
        let response = page(&service, "ObjectParts", Some(marker), None, None).await;
        assert_eq!(response.status(), 200);
        assert!(part_rows(&response).is_empty());
        assert_eq!(element(response.body(), "IsTruncated").as_deref(), Some("false"));
        assert!(element(response.body(), "NextPartNumberMarker").is_none());
        assert_eq!(element(response.body(), "PartsCount").as_deref(), Some("1"));
    }
}

#[tokio::test]
async fn n_page_sizes_outside_one_to_one_thousand_are_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    complete(&service, false).await;
    for max in ["0", "-1", "1001"] {
        let response = page(&service, "ObjectParts", None, Some(max), None).await;
        assert_eq!(response.status(), 400);
        assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidArgument"));
    }
}

#[tokio::test]
async fn n_invalid_markers_are_refused_even_without_the_parts_group() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    complete(&service, false).await;
    for marker in ["bad", "-1", "2147483648"] {
        for selected in ["ObjectParts", "ETag"] {
            let response = page(&service, selected, Some(marker), None, None).await;
            assert_eq!(response.status(), 400);
            assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidArgument"));
        }
    }
}

#[tokio::test]
async fn n_unselected_parts_do_not_leak_or_validate_unused_page_size() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    complete(&service, false).await;
    let response = page(&service, "ETag", None, Some("-1"), None).await;
    assert_eq!(response.status(), 200);
    assert!(element(response.body(), "ObjectParts").is_none());
    assert!(element(response.body(), "ETag").is_some());
}

#[tokio::test]
async fn n_parts_without_negotiated_checksums_do_not_invent_them() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    complete(&service, false).await;
    let response = page(&service, "ObjectParts", Some("0"), None, None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(part_rows(&response), vec![("5".into(), BODY.len().to_string())]);
    assert!(!std::str::from_utf8(response.body()).expect("XML").contains("Checksum"));
    assert!(element(response.body(), "PartNumberMarker").is_none());
}

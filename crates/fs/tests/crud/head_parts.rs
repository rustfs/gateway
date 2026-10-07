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

//! HEAD partNumber metadata through signed production requests.
//!
//! Responsible for: selected lengths/counts, version isolation and selector refusal statuses.
//! NOT responsible for: GET byte slicing or the persisted table grammar.
//! Upstream: the object-parts fixture and production HEAD handler. Downstream: the FS gate.

use super::*;

async fn head(service: &S3Service, key: &str, query: &str, headers: http::HeaderMap) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(http::Method::HEAD, &format!("/{BUCKET}/{key}?{query}"), Bytes::new(), headers),
    )
    .await
}

#[tokio::test]
async fn restarted_head_reports_the_selected_length_and_part_count() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let completed = multipart(&initial, "object", true).await;
    let tag = element(completed.body(), "ETag").map(|tag| tag.replace("&quot;", "\""));
    drop(initial);
    let (_, restarted) = service(&root);
    for (number, length) in [(1, MIN_PART_SIZE), (2, TAIL.len())] {
        let response = head(&restarted, "object", &format!("partNumber={number}"), http::HeaderMap::new()).await;
        assert_eq!(response.status(), 200);
        assert_eq!(text(&response, "content-length"), Some(length.to_string().as_str()));
        assert_eq!(text(&response, "x-amz-mp-parts-count"), Some("2"));
        assert_eq!(text(&response, "content-range"), None);
        assert_eq!(text(&response, "etag"), tag.as_deref());
    }
}

#[tokio::test]
async fn plain_and_empty_head_parts_have_no_multipart_count() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    for body in [TAIL, b"".as_slice()] {
        assert_eq!(
            exchange(
                &service,
                signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::copy_from_slice(body))
            )
            .await
            .status(),
            200
        );
        let response = head(&service, "object", "partNumber=1", http::HeaderMap::new()).await;
        assert_eq!(response.status(), 200);
        assert_eq!(text(&response, "content-length"), Some(body.len().to_string().as_str()));
        assert_eq!(text(&response, "x-amz-mp-parts-count"), None);
        assert_eq!(text(&response, "content-range"), None);
    }
}

#[tokio::test]
async fn head_parts_report_the_stored_checksum_only_when_enabled() {
    use super::super::multipart_checksums::{
        checksum, complete_checksum, completion_with_checksum, initiate_checksum, put_checksum_part,
    };
    use rustfs_gateway::ChecksumAlgorithm;
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let value = checksum(ChecksumAlgorithm::Crc32, TAIL);
    let initiated = initiate_checksum(&service, BUCKET, "object", "CRC32", "COMPOSITE").await;
    let id = element(initiated.body(), "UploadId").expect("an upload id");
    let part = put_checksum_part(&service, BUCKET, "object", &id, 1, value, TAIL).await;
    let body = completion_with_checksum(
        1,
        text(&part, "etag").expect("an entity tag"),
        ChecksumAlgorithm::Crc32,
        value.render_base64(),
    );
    assert_eq!(complete_checksum(&service, BUCKET, "object", &id, body).await.status(), 200);
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
    let response = head(&service, "object", "partNumber=1", headers).await;
    // AWS documents the individual checksum for HEAD part reads, not the aggregate.
    // https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
    let expected = value;
    assert_eq!(response.status(), 200);
    assert_eq!(text(&response, "x-amz-checksum-crc32"), Some(expected.render_base64()));
    assert_eq!(text(&response, "x-amz-checksum-type"), Some("COMPOSITE"));
    let absent = head(&service, "object", "partNumber=1", http::HeaderMap::new()).await;
    assert_eq!(absent.status(), 200);
    assert_eq!(text(&absent, "x-amz-checksum-crc32"), None);
    assert_eq!(text(&absent, "x-amz-checksum-type"), None);
}

#[tokio::test]
async fn n_head_refuses_numbers_outside_the_wire_bounds() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    for number in ["-1", "0", "10001"] {
        assert_eq!(
            head(&service, "object", &format!("partNumber={number}"), http::HeaderMap::new())
                .await
                .status(),
            400
        );
    }
}

#[tokio::test]
async fn n_head_cannot_select_a_part_past_the_completed_table() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, &format!("/{BUCKET}/plain"), Bytes::from_static(TAIL)))
            .await
            .status(),
        200
    );
    for key in ["object", "plain"] {
        assert_eq!(head(&service, key, "partNumber=2", http::HeaderMap::new()).await.status(), 416);
    }
}

#[tokio::test]
async fn n_a_whole_head_does_not_invent_a_part_count() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    let whole = head(&service, "object", "", http::HeaderMap::new()).await;
    assert_eq!(whole.status(), 200);
    assert_eq!(text(&whole, "x-amz-mp-parts-count"), None);
    assert_eq!(text(&whole, "content-length"), Some(TAIL.len().to_string().as_str()));
}

#[tokio::test]
async fn n_head_does_not_guess_an_old_records_part_length() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    multipart(&initial, "object", false).await;
    drop(initial);
    let path = super::super::object_checksums::one_record(&root);
    let encoded = std::fs::read_to_string(&path).expect("a record");
    std::fs::write(&path, encoded.split("parts/1").next().expect("the old record")).expect("a legacy record");
    let (_, restarted) = service(&root);
    assert_eq!(
        head(&restarted, "object", "partNumber=1", http::HeaderMap::new())
            .await
            .status(),
        501
    );
    let whole = head(&restarted, "object", "", http::HeaderMap::new()).await;
    assert_eq!(whole.status(), 200);
    assert_eq!(text(&whole, "content-length"), Some(TAIL.len().to_string().as_str()));
}

#[tokio::test]
async fn n_head_cannot_combine_two_byte_selectors() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    let mut headers = http::HeaderMap::new();
    headers.insert("range", http::HeaderValue::from_static("bytes=0-2"));
    assert_eq!(head(&service, "object", "partNumber=1", headers).await.status(), 400);
}

#[tokio::test]
async fn n_a_new_version_does_not_replace_old_head_part_metadata() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    assert_eq!(
        super::super::multipart_versioning::set_versioning(&initial, BUCKET, "Enabled")
            .await
            .status(),
        200
    );
    let completed = multipart(&initial, "object", false).await;
    let version = text(&completed, "x-amz-version-id").expect("a version").to_owned();
    assert_eq!(
        exchange(
            &initial,
            signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(b"replacement"))
        )
        .await
        .status(),
        200
    );
    drop(initial);
    let (_, restarted) = service(&root);
    let old = head(&restarted, "object", &format!("partNumber=1&versionId={version}"), http::HeaderMap::new()).await;
    assert_eq!(old.status(), 200);
    assert_eq!(text(&old, "content-length"), Some(TAIL.len().to_string().as_str()));
    assert_eq!(text(&old, "x-amz-mp-parts-count"), Some("1"));
    let current = head(&restarted, "object", "partNumber=1", http::HeaderMap::new()).await;
    assert_eq!(current.status(), 200);
    assert_eq!(text(&current, "content-length"), Some("11"));
    assert_eq!(text(&current, "x-amz-mp-parts-count"), None);
}

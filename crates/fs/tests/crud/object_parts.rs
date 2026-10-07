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

//! Persisted multipart boundaries and signed GET partNumber reads.
//!
//! Responsible for: restarted byte windows, version isolation and refusal of unavailable parts.
//! NOT responsible for: HEAD part policy, attributes responses or range arithmetic.
//! Upstream: the production service and stored object records. Downstream: the FS verification gate.

use super::multipart_sizing::{MIN_PART_SIZE, upload_owned};
#[path = "head_parts.rs"]
mod head_parts;

#[path = "part_metadata.rs"]
mod part_metadata;

use super::*;

const BUCKET: &str = "stored-checksum";
const TAIL: &[u8] = b"last-part";

async fn multipart(service: &S3Service, key: &str, two: bool) -> rustfs_gateway::WireResponse {
    let id = initiate(service, BUCKET, key).await;
    let mut tags = Vec::new();
    if two {
        tags.push((
            2,
            upload_owned(service, BUCKET, key, &id, 2, Bytes::from(vec![b'a'; MIN_PART_SIZE])).await,
        ));
    }
    tags.push((5, upload_part(service, BUCKET, key, &id, 5, TAIL).await));
    let parts: Vec<_> = tags.iter().map(|(number, tag)| (*number, tag.as_str())).collect();
    let response = complete(service, BUCKET, key, &id, &parts).await;
    assert_eq!(response.status(), 200);
    response
}

async fn get(service: &S3Service, key: &str, query: &str) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
    exchange(
        service,
        signed_with_headers(http::Method::GET, &format!("/{BUCKET}/{key}?{query}"), Bytes::new(), headers),
    )
    .await
}

fn text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn multipart_windows_survive_restart_in_completed_order() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let completed = multipart(&initial, "object", true).await;
    let tag = element(completed.body(), "ETag").map(|tag| tag.replace("&quot;", "\""));
    drop(initial);
    let (_, restarted) = service(&root);
    for (number, start, expected) in [(1, 0, vec![b'a'; MIN_PART_SIZE]), (2, MIN_PART_SIZE, TAIL.to_vec())] {
        let response = get(&restarted, "object", &format!("partNumber={number}")).await;
        assert_eq!(response.status(), 206);
        assert_eq!(response.body().as_ref(), expected);
        let range = format!("bytes {start}-{}/{}", start + expected.len() - 1, MIN_PART_SIZE + TAIL.len());
        assert_eq!(text(&response, "content-range"), Some(range.as_str()));
        assert_eq!(text(&response, "content-length"), Some(expected.len().to_string().as_str()));
        assert_eq!(text(&response, "x-amz-mp-parts-count"), Some("2"));
        assert_eq!(text(&response, "etag"), tag.as_deref());
    }
}

#[tokio::test]
async fn plain_and_empty_objects_have_one_readable_part_without_a_multipart_count() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    for body in [b"ordinary".as_slice(), b"".as_slice()] {
        assert_eq!(
            exchange(
                &initial,
                signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::copy_from_slice(body))
            )
            .await
            .status(),
            200
        );
        let (_, restarted) = service(&root);
        let response = get(&restarted, "object", "partNumber=1").await;
        assert_eq!(response.status(), if body.is_empty() { 200 } else { 206 });
        assert_eq!(response.body().as_ref(), body);
        assert_eq!(text(&response, "content-range"), if body.is_empty() { None } else { Some("bytes 0-7/8") });
        assert_eq!(text(&response, "x-amz-mp-parts-count"), None);
    }
}

#[tokio::test]
async fn an_explicit_version_keeps_its_own_part_window() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&initial, BUCKET, "Enabled")
            .await
            .status(),
        200
    );
    let completed = multipart(&initial, "object", false).await;
    let version = text(&completed, "x-amz-version-id").expect("a version id").to_owned();
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
    let selected = get(&restarted, "object", &format!("partNumber=1&versionId={version}")).await;
    assert_eq!(selected.status(), 206);
    assert_eq!(selected.body().as_ref(), TAIL);
    assert_eq!(text(&selected, "x-amz-mp-parts-count"), Some("1"));
    assert_eq!(text(&selected, "x-amz-version-id"), Some(version.as_str()));
}

#[tokio::test]
async fn n_invalid_or_unavailable_part_numbers_are_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    for (number, code) in [
        ("0", "InvalidArgument"),
        ("-1", "InvalidArgument"),
        ("10001", "InvalidArgument"),
        ("2", "InvalidPart"),
        ("5", "InvalidPart"),
    ] {
        let response = get(&service, "object", &format!("partNumber={number}")).await;
        assert_eq!(response.status(), 400, "{number}");
        assert_eq!(element(response.body(), "Code").as_deref(), Some(code));
        assert_eq!(text(&response, "x-amz-mp-parts-count"), None);
    }
}

#[tokio::test]
async fn n_plain_overwrites_and_copies_do_not_inherit_a_multipart_layout() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    multipart(&service, "object", false).await;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-copy-source",
        http::HeaderValue::from_str(&format!("{BUCKET}/object")).expect("a source"),
    );
    assert_eq!(
        exchange(
            &service,
            signed_with_headers(http::Method::PUT, &format!("/{BUCKET}/copy"), Bytes::new(), headers)
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        exchange(
            &service,
            signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(TAIL))
        )
        .await
        .status(),
        200
    );
    for key in ["object", "copy"] {
        let response = get(&service, key, "partNumber=1").await;
        assert_eq!(response.status(), 206);
        assert_eq!(response.body().as_ref(), TAIL);
        assert_eq!(text(&response, "x-amz-mp-parts-count"), None);
        let missing = get(&service, key, "partNumber=2").await;
        assert_eq!(missing.status(), 400);
        assert_eq!(element(missing.body(), "Code").as_deref(), Some("InvalidPart"));
    }
}

#[tokio::test]
async fn n_a_part_read_does_not_report_the_whole_object_checksum() {
    use super::multipart_checksums::{
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
    let response = get(&service, "object", "partNumber=1").await;
    assert_eq!(response.status(), 206);
    assert_eq!(response.body().as_ref(), TAIL);
    assert_eq!(text(&response, "x-amz-checksum-crc32"), None);
    assert_eq!(text(&response, "x-amz-checksum-type"), None);
    let whole = get(&service, "object", "").await;
    assert_eq!(whole.status(), 200);
    assert!(text(&whole, "x-amz-checksum-crc32").is_some());
    assert_eq!(text(&whole, "x-amz-checksum-type"), Some("COMPOSITE"));
    assert_eq!(text(&whole, "x-amz-mp-parts-count"), None);
}

#[tokio::test]
async fn n_an_old_multipart_record_does_not_invent_part_boundaries() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    multipart(&initial, "object", false).await;
    drop(initial);
    let path = super::object_checksums::one_record(&root);
    let encoded = std::fs::read_to_string(&path).expect("a record");
    let old = encoded.split("parts/1").next().expect("the original record");
    std::fs::write(&path, old).expect("the legacy representation");
    let (_, restarted) = service(&root);
    let part = get(&restarted, "object", "partNumber=1").await;
    assert_eq!(part.status(), 501);
    assert_eq!(text(&part, "x-amz-mp-parts-count"), None);
    let whole = get(&restarted, "object", "").await;
    assert_eq!(whole.status(), 200);
    assert_eq!(whole.body().as_ref(), TAIL);
}

#[tokio::test]
async fn n_malformed_or_inconsistent_part_tables_are_refused() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    multipart(&initial, "object", false).await;
    drop(initial);
    let path = super::object_checksums::one_record(&root);
    let encoded = std::fs::read_to_string(&path).expect("a record");
    let old = encoded.split("parts/1").next().expect("the original record");
    for section in [
        "parts/1 0\n",
        "parts/1 10001\n",
        "parts/1 1\n",
        "parts/1 1\n-1\n",
        "parts/1 1\nnot-a-size\n",
        "parts/1 1\n8\n",
        "parts/1 2\n4\n5\n",
        "parts/1 1\n18446744073709551615\n",
        "parts/1 1\n9\n10\n",
        "parts/1 1\n9\nparts/1 1\n9\n",
    ] {
        std::fs::write(&path, format!("{old}{section}")).expect("the malformed table");
        let (_, restarted) = service(&root);
        for query in ["", "partNumber=1"] {
            let response = get(&restarted, "object", query).await;
            assert_eq!(response.status(), 500, "{section}: {query}");
        }
    }
}

#[tokio::test]
async fn n_an_upload_record_cannot_claim_completed_part_lengths() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let id = initiate(&initial, BUCKET, "object").await;
    drop(initial);
    let path = super::multipart_checksums::upload_record(&root, BUCKET, &id);
    let original = std::fs::read_to_string(&path).expect("an upload record");
    std::fs::write(&path, format!("{original}parts/1 1\n9\n")).expect("an invalid upload record");
    let (_, restarted) = service(&root);
    let response = exchange(&restarted, signed(http::Method::GET, &format!("/{BUCKET}?uploads"), Bytes::new())).await;
    assert_eq!(response.status(), 500);
}

#[tokio::test]
async fn n_an_overflowing_table_cannot_match_a_negative_record_size() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    multipart(&initial, "object", false).await;
    drop(initial);
    let path = super::object_checksums::one_record(&root);
    let encoded = std::fs::read_to_string(&path).expect("a record");
    let old = encoded.split("parts/1").next().expect("the original record");
    let mut fields: Vec<_> = old.lines().map(str::to_owned).collect();
    fields[5] = "00000000000000000000000000000000-2".to_owned();
    fields[6] = "-1".to_owned();
    std::fs::write(&path, format!("{}\nparts/1 2\n18446744073709551615\n1\n", fields.join("\n"))).expect("an overflowing table");
    let (_, restarted) = service(&root);
    assert_eq!(get(&restarted, "object", "").await.status(), 500);
}

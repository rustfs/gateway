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

//! Stored multipart checksums and completion retry responses.
//!
//! Responsible for: checksum/type persistence, read projection and replay isolation after restart.
//! NOT responsible for: part boundaries, partNumber reads or GetObjectAttributes.
//! Upstream: signed requests through the production service. Downstream: the FS verification gate.

use super::multipart_checksums::{checksum, complete_checksum, completion_with_checksum, initiate_checksum, put_checksum_part};
use super::*;
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec};

const BUCKET: &str = "stored-checksum";
const BODY: &[u8] = b"persisted-multipart-checksum";

async fn upload(service: &S3Service, key: &str, kind: &str) -> (String, Bytes, ChecksumSpec) {
    let algorithm = ChecksumAlgorithm::Crc32;
    let initiated = initiate_checksum(service, BUCKET, key, "CRC32", kind).await;
    assert_eq!(initiated.status(), 200);
    let id = element(initiated.body(), "UploadId").expect("an upload id");
    let part_checksum = checksum(algorithm, BODY);
    let part = put_checksum_part(service, BUCKET, key, &id, 1, part_checksum, BODY).await;
    assert_eq!(part.status(), 200);
    let etag = header(&part, "etag").expect("an entity tag").to_str().expect("a text tag");
    let body = completion_with_checksum(1, etag, algorithm, part_checksum.render_base64());
    let expected = if kind == "COMPOSITE" {
        ChecksumSpec::composite_of(&[part_checksum]).expect("one checksum of the same algorithm")
    } else {
        part_checksum
    };
    (id, body, expected)
}

fn enabled() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
    headers
}

#[tokio::test]
async fn completed_checksums_and_types_survive_restart() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let mut expected = Vec::new();
    for kind in ["COMPOSITE", "FULL_OBJECT"] {
        let (id, body, value) = upload(&initial, kind, kind).await;
        let completed = complete_checksum(&initial, BUCKET, kind, &id, body).await;
        assert_eq!(completed.status(), 200);
        expected.push((kind, value));
    }
    drop(initial);
    let (_, restarted) = service(&root);
    for (kind, value) in expected {
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = exchange(
                &restarted,
                signed_with_headers(method, &format!("/{BUCKET}/{kind}"), Bytes::new(), enabled()),
            )
            .await;
            assert_eq!(response.status(), 200);
            assert_eq!(
                header(&response, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
                Some(value.render_base64())
            );
            assert_eq!(header(&response, "x-amz-checksum-type").and_then(|v| v.to_str().ok()), Some(kind));
        }
    }
}

#[tokio::test]
async fn a_restarted_completion_replay_returns_the_committed_checksum_and_type() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let mut requests = Vec::new();
    for kind in ["COMPOSITE", "FULL_OBJECT"] {
        let (id, body, value) = upload(&initial, kind, kind).await;
        let first = complete_checksum(&initial, BUCKET, kind, &id, body.clone()).await;
        assert_eq!(first.status(), 200);
        assert_eq!(element(first.body(), "ChecksumCRC32").as_deref(), Some(value.render_base64()));
        requests.push((kind, id, body, value, element(first.body(), "ETag")));
    }
    drop(initial);
    let (_, restarted) = service(&root);
    for (kind, id, body, value, etag) in requests {
        let replay = complete_checksum(&restarted, BUCKET, kind, &id, body).await;
        assert_eq!(replay.status(), 200);
        assert_eq!(element(replay.body(), "ETag"), etag);
        assert_eq!(element(replay.body(), "ChecksumCRC32").as_deref(), Some(value.render_base64()));
        assert_eq!(element(replay.body(), "ChecksumType").as_deref(), Some(kind));
    }
}

#[tokio::test]
async fn n_disabled_mode_and_ranges_do_not_expose_a_multipart_checksum_or_type() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let (id, body, _) = upload(&service, "object", "COMPOSITE").await;
    assert_eq!(complete_checksum(&service, BUCKET, "object", &id, body).await.status(), 200);
    for method in [http::Method::GET, http::Method::HEAD] {
        for ranged in [false, true] {
            let mut headers = if ranged { enabled() } else { http::HeaderMap::new() };
            if ranged {
                headers.insert("range", http::HeaderValue::from_static("bytes=0-3"));
            }
            let response = exchange(
                &service,
                signed_with_headers(method.clone(), &format!("/{BUCKET}/object"), Bytes::new(), headers),
            )
            .await;
            assert_eq!(response.status(), if ranged { 206 } else { 200 });
            assert!(header(&response, "x-amz-checksum-crc32").is_none());
            assert!(header(&response, "x-amz-checksum-type").is_none());
        }
    }
}

#[tokio::test]
async fn n_an_overwrite_does_not_reuse_the_multipart_checksum_or_type() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let (id, body, _) = upload(&initial, "object", "COMPOSITE").await;
    assert_eq!(complete_checksum(&initial, BUCKET, "object", &id, body).await.status(), 200);
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
    let read = exchange(
        &restarted,
        signed_with_headers(http::Method::GET, &format!("/{BUCKET}/object"), Bytes::new(), enabled()),
    )
    .await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), b"replacement");
    assert!(header(&read, "x-amz-checksum-crc32").is_none());
    assert!(header(&read, "x-amz-checksum-type").is_none());
}

#[tokio::test]
async fn n_replay_with_other_parts_cannot_report_the_committed_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let (id, body, _) = upload(&initial, "object", "COMPOSITE").await;
    assert_eq!(
        complete_checksum(&initial, BUCKET, "object", &id, body.clone())
            .await
            .status(),
        200
    );
    let wrong = Bytes::from(
        String::from_utf8(body.to_vec())
            .expect("fixture XML")
            .replace("<PartNumber>1", "<PartNumber>2"),
    );
    drop(initial);
    let (_, restarted) = service(&root);
    let refused = complete_checksum(&restarted, BUCKET, "object", &id, wrong).await;
    assert_eq!(refused.status(), 400);
    assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidPart"));
    assert_eq!(element(refused.body(), "ChecksumCRC32"), None);
    assert_eq!(element(refused.body(), "ChecksumType"), None);
}

#[tokio::test]
async fn copy_keeps_composite_type_but_recalculation_and_full_object_copy_omit_it() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    for kind in ["COMPOSITE", "FULL_OBJECT"] {
        let (id, body, original) = upload(&initial, kind, kind).await;
        assert_eq!(complete_checksum(&initial, BUCKET, kind, &id, body).await.status(), 200);
        for recalculate in [false, true] {
            let target = format!("/{BUCKET}/{kind}-{recalculate}");
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "x-amz-copy-source",
                http::HeaderValue::from_str(&format!("{BUCKET}/{kind}")).expect("a source"),
            );
            if recalculate {
                headers.insert("x-amz-checksum-algorithm", http::HeaderValue::from_static("SHA256"));
            }
            let copied = exchange(&initial, signed_with_headers(http::Method::PUT, &target, Bytes::new(), headers)).await;
            assert_eq!(copied.status(), 200);
            let value = if recalculate {
                checksum(ChecksumAlgorithm::Sha256, BODY)
            } else {
                original
            };
            let name = if recalculate { "ChecksumSHA256" } else { "ChecksumCRC32" };
            let expected_type = (!recalculate && kind == "COMPOSITE").then_some("COMPOSITE");
            assert_eq!(element(copied.body(), name).as_deref(), Some(value.render_base64()));
            assert_eq!(element(copied.body(), "ChecksumType").as_deref(), expected_type);
            let (_, restarted) = service(&root);
            let read = exchange(&restarted, signed_with_headers(http::Method::GET, &target, Bytes::new(), enabled())).await;
            assert_eq!(read.status(), 200);
            assert_eq!(read.body(), BODY);
            assert_eq!(
                header(&read, value.algorithm().header_name()).and_then(|v| v.to_str().ok()),
                Some(value.render_base64())
            );
            assert_eq!(header(&read, "x-amz-checksum-type").and_then(|v| v.to_str().ok()), expected_type);
        }
    }
}

#[tokio::test]
async fn n_a_single_put_checksum_does_not_acquire_a_multipart_type() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let value = checksum(ChecksumAlgorithm::Crc32, BODY);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-checksum-crc32",
        http::HeaderValue::from_str(value.render_base64()).expect("a checksum"),
    );
    let written = exchange(
        &initial,
        signed_with_headers(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(BODY), headers),
    )
    .await;
    assert_eq!(written.status(), 200);
    drop(initial);
    let (_, restarted) = service(&root);
    for method in [http::Method::GET, http::Method::HEAD] {
        let read = exchange(
            &restarted,
            signed_with_headers(method, &format!("/{BUCKET}/object"), Bytes::new(), enabled()),
        )
        .await;
        assert_eq!(read.status(), 200);
        assert_eq!(
            header(&read, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
            Some(value.render_base64())
        );
        assert!(header(&read, "x-amz-checksum-type").is_none());
    }
}

#[tokio::test]
async fn n_malformed_or_contradictory_typed_checksum_records_are_refused() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    assert_eq!(
        exchange(
            &initial,
            signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(BODY))
        )
        .await
        .status(),
        200
    );
    drop(initial);
    let path = super::object_checksums::one_record(&root);
    let original = std::fs::read_to_string(&path).expect("the plain record");
    let full = checksum(ChecksumAlgorithm::Crc32, BODY);
    let composite = ChecksumSpec::composite_of(&[full]).expect("one part");
    for section in [
        "checksum/2 0\n".to_owned(),
        format!("checksum/2 0\nCRC32 FULL_OBJECT {}\n", full.render_base64()),
        format!("checksum/2 2\nCRC32 FULL_OBJECT {}\n", full.render_base64()),
        "checksum/2 1\n".to_owned(),
        format!("checksum/2 1\nCRC32 UNKNOWN {}\n", full.render_base64()),
        format!("checksum/2 1\nCRC32 COMPOSITE {}\n", full.render_base64()),
        format!("checksum/2 1\nCRC32 FULL_OBJECT {}\n", composite.render_base64()),
        format!("checksum/2 1\nCRC32 {}\n", full.render_base64()),
        "checksum/2 1\nCRC32 FULL_OBJECT not-base64\n".to_owned(),
        format!("checksum/2 1\nCRC32 FULL_OBJECT {}\nheaders/1 0\n", full.render_base64()),
        format!(
            "checksum/2 1\nCRC32 FULL_OBJECT {}\nchecksum/1 1\nCRC32 {}\n",
            full.render_base64(),
            full.render_base64()
        ),
    ] {
        std::fs::write(&path, format!("{original}{section}")).expect("a malformed typed checksum record");
        let (_, restarted) = service(&root);
        let response = exchange(
            &restarted,
            signed_with_headers(http::Method::GET, &format!("/{BUCKET}/object"), Bytes::new(), enabled()),
        )
        .await;
        assert_eq!(response.status(), 500, "{section}");
    }
}

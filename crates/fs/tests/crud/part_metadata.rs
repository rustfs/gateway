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

//! Completed multipart identity/checksum persistence through signed requests.
//!
//! Responsible for: original sparse numbers, verified part checksums and overwrite isolation.
//! NOT responsible for: attributes pagination or the private grammar's full rejection matrix.
//! Upstream: production completion and object records. Downstream: the filesystem gate.

use super::super::*;

const BUCKET: &str = "stored-checksum";
const BODY: &[u8] = b"part-metadata-body";

fn stored(root: &TestRoot) -> (PathBuf, String) {
    let path = super::super::object_checksums::one_record(root);
    let encoded = std::fs::read_to_string(&path).expect("stored record");
    (path, encoded)
}

async fn completed(service: &S3Service) {
    let id = initiate(service, BUCKET, "object").await;
    let tag = upload_part(service, BUCKET, "object", &id, 5, BODY).await;
    let body =
        format!("<CompleteMultipartUpload><Part><PartNumber>5</PartNumber><ETag>{tag}</ETag></Part></CompleteMultipartUpload>");
    assert_eq!(
        exchange(
            service,
            signed(http::Method::POST, &format!("/{BUCKET}/object?uploadId={id}"), Bytes::from(body))
        )
        .await
        .status(),
        200
    );
}

#[tokio::test]
async fn completed_sparse_identity_survives_restart() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    completed(&initial).await;
    assert!(stored(&root).1.ends_with("part-meta/1 1\n5 - -\n"));
    drop(initial);
    let (_, reopened) = service(&root);
    let response = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/{BUCKET}/object?partNumber=1"), Bytes::new()),
    )
    .await;
    assert_eq!(response.status(), 206);
    assert_eq!(response.body().as_ref(), BODY);
    assert!(stored(&root).1.ends_with("part-meta/1 1\n5 - -\n"));
}

#[tokio::test]
async fn completed_part_checksum_survives_restart_without_becoming_composite() {
    use super::super::multipart_checksums::{
        checksum, complete_checksum, completion_with_checksum, initiate_checksum, put_checksum_part,
    };
    use rustfs_gateway::ChecksumAlgorithm;
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let value = checksum(ChecksumAlgorithm::Crc32, BODY);
    let begun = initiate_checksum(&initial, BUCKET, "object", "CRC32", "COMPOSITE").await;
    let id = element(begun.body(), "UploadId").expect("upload ID");
    let part = put_checksum_part(&initial, BUCKET, "object", &id, 1, value, BODY).await;
    let tag = header(&part, "etag").expect("ETag").to_str().expect("ASCII");
    let body = completion_with_checksum(1, tag, ChecksumAlgorithm::Crc32, value.render_base64());
    assert_eq!(complete_checksum(&initial, BUCKET, "object", &id, body).await.status(), 200);
    let expected = format!("part-meta/1 1\n1 CRC32 {}\n", value.render_base64());
    assert!(stored(&root).1.ends_with(&expected));
    drop(initial);
    let (_, reopened) = service(&root);
    let response = exchange(&reopened, signed(http::Method::GET, &format!("/{BUCKET}/object"), Bytes::new())).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().as_ref(), BODY);
    assert!(stored(&root).1.ends_with(&expected));
}

#[tokio::test]
async fn n_plain_replacements_and_copies_do_not_keep_completed_identity() {
    for copying in [false, true] {
        let root = TestRoot::new();
        let (_, service) = service(&root);
        create_bucket(&service, BUCKET).await;
        completed(&service).await;
        if copying {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-amz-copy-source", http::HeaderValue::from_static("/stored-checksum/object"));
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
                exchange(&service, signed(http::Method::DELETE, &format!("/{BUCKET}/object"), Bytes::new()))
                    .await
                    .status(),
                204
            );
        } else {
            assert_eq!(
                exchange(
                    &service,
                    signed(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(BODY))
                )
                .await
                .status(),
                200
            );
        }
        assert!(!stored(&root).1.contains("part-meta/"));
    }
}

#[tokio::test]
async fn n_corrupt_identity_metadata_does_not_serve_object_bytes() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    completed(&initial).await;
    let (path, encoded) = stored(&root);
    assert!(encoded.contains("part-meta/1 1\n5 - -\n"));
    std::fs::write(path, encoded.replace("part-meta/1 1\n5 - -\n", "part-meta/1 1\n0 - -\n")).expect("corrupt number");
    drop(initial);
    let (_, reopened) = service(&root);
    let response = exchange(&reopened, signed(http::Method::GET, &format!("/{BUCKET}/object"), Bytes::new())).await;
    assert_eq!(response.status(), 500);
    assert!(!response.body().windows(BODY.len()).any(|window| window == BODY));
}

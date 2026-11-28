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

//! A repeated `CompleteMultipartUpload`, answered as RustFS answers it (rustfs/gateway#1002).
//!
//! Responsible for: a retry of a completed upload with the same parts replaying the committed
//! object — same entity tag and version — as RustFS's `complete_multipart_upload` does, a retry
//! naming different parts being `InvalidPart`, and a retry after the key was overwritten, or with
//! an id that was never completed, staying `NoSuchUpload`.
//! NOT responsible for: the first completion (`crud`, `multipart_*`).
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;

fn text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn code(response: &rustfs_gateway::WireResponse) -> Option<String> {
    element(response.body(), "Code")
}

/// Positive — the same completion again answers the committed object, twice, and survives a
/// restart; the object is unchanged.
#[tokio::test]
async fn a_repeated_completion_replays_the_committed_object() {
    let root = TestRoot::new();
    let (_, first) = service(&root);
    create_bucket(&first, "replay").await;
    let upload_id = initiate(&first, "replay", "key").await;
    let part = upload_part(&first, "replay", "key", &upload_id, 1, b"only part").await;
    let completed = complete(&first, "replay", "key", &upload_id, &[(1, part.as_str())]).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    let e_tag = element(completed.body(), "ETag").expect("an entity tag");
    drop(first);

    let (_, service) = service(&root);
    for attempt in 0..2 {
        let again = complete(&service, "replay", "key", &upload_id, &[(1, part.as_str())]).await;
        assert_eq!(again.status(), 200, "attempt {attempt}: {}", text(&again));
        assert_eq!(element(again.body(), "ETag").as_deref(), Some(e_tag.as_str()), "attempt {attempt}");
    }
    let read = exchange(&service, signed(http::Method::GET, "/replay/key", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), b"only part");
}

/// Negative — a retry naming a different part is `InvalidPart`, not a missing upload.
#[tokio::test]
async fn n_a_retry_with_other_parts_is_invalid_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "replay").await;
    let upload_id = initiate(&service, "replay", "key").await;
    let part = upload_part(&service, "replay", "key", &upload_id, 1, b"only part").await;
    assert_eq!(
        complete(&service, "replay", "key", &upload_id, &[(1, part.as_str())])
            .await
            .status(),
        200
    );
    let other = complete(&service, "replay", "key", &upload_id, &[(1, "\"0123456789abcdef0123456789abcdef\"")]).await;
    assert_eq!(other.status(), 400, "{}", text(&other));
    assert_eq!(code(&other).as_deref(), Some("InvalidPart"));
}

/// Negative — once the key holds something else, or for an id that was never completed, the
/// retry is `NoSuchUpload`.
#[tokio::test]
async fn n_an_overwritten_or_unknown_completion_is_no_such_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "replay").await;
    let upload_id = initiate(&service, "replay", "key").await;
    let part = upload_part(&service, "replay", "key", &upload_id, 1, b"only part").await;
    assert_eq!(
        complete(&service, "replay", "key", &upload_id, &[(1, part.as_str())])
            .await
            .status(),
        200
    );
    let overwrite = exchange(&service, signed(http::Method::PUT, "/replay/key", Bytes::from_static(b"replaced"))).await;
    assert_eq!(overwrite.status(), 200);

    let stale = complete(&service, "replay", "key", &upload_id, &[(1, part.as_str())]).await;
    assert_eq!(stale.status(), 404, "{}", text(&stale));
    assert_eq!(code(&stale).as_deref(), Some("NoSuchUpload"));
    let other_key = complete(&service, "replay", "elsewhere", &upload_id, &[(1, part.as_str())]).await;
    assert_eq!(code(&other_key).as_deref(), Some("NoSuchUpload"));
    let read = exchange(&service, signed(http::Method::GET, "/replay/key", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), b"replaced");

    // A later upload completed onto the same key: the earlier upload's retry names the parts that
    // later upload used and is still not that upload.
    let later = initiate(&service, "replay", "key").await;
    let later_part = upload_part(&service, "replay", "key", &later, 1, b"only part").await;
    assert_eq!(
        complete(&service, "replay", "key", &later, &[(1, later_part.as_str())])
            .await
            .status(),
        200
    );
    let earlier = complete(&service, "replay", "key", &upload_id, &[(1, later_part.as_str())]).await;
    assert_eq!(code(&earlier).as_deref(), Some("NoSuchUpload"), "{}", text(&earlier));
}

/// Negative — an unawaited `CompleteMultipartUpload` racing with rapid `PutObject` overwrites and
/// `GetObject` reads on the same key in a never-versioned bucket (the `aws-sdk-java-v2` Mint
/// `uploadMultiPartAsync_test` -> `uploadObjectVersions_test` pattern) must never answer `500` or
/// leave an orphaned `v-*/completion` directory behind (rustfs/gateway#1083).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_unawaited_multipart_completion_racing_put_and_get_never_returns_500() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let service = Arc::new(service);
    create_bucket(&service, "shared").await;
    let part_payload = Bytes::from(vec![b'M'; 64 * 1024]);
    let versions_dir = root.0.join(format!("b-{}", hex::encode("shared"))).join("versions");

    for iter in 0..6 {
        let upload_id = initiate(&service, "shared", "testobject").await;
        let part_response = exchange(
            &service,
            signed(
                http::Method::PUT,
                &format!("/shared/testobject?partNumber=1&uploadId={upload_id}"),
                part_payload.clone(),
            ),
        )
        .await;
        assert_eq!(part_response.status(), 200, "iter {iter}: {}", text(&part_response));
        let part_etag = header(&part_response, "etag")
            .expect("part etag")
            .to_str()
            .expect("ascii etag")
            .to_owned();

        let completion_service = Arc::clone(&service);
        let completion_body = completion(&[(1, part_etag.as_str())]);
        let completion_target = format!("/shared/testobject?uploadId={upload_id}");
        let completion_task = tokio::spawn(async move {
            exchange(&completion_service, signed(http::Method::POST, &completion_target, completion_body)).await
        });

        for attempt in 0..4 {
            let body = Bytes::from(format!("overwrite-{iter}-{attempt}"));
            let put = exchange(&service, signed(http::Method::PUT, "/shared/testobject", body)).await;
            assert_eq!(put.status(), 200, "iter {iter} put {attempt}: {}", text(&put));
        }
        let get = exchange(&service, signed(http::Method::GET, "/shared/testobject", Bytes::new())).await;
        assert_eq!(get.status(), 200, "iter {iter} get: {}", text(&get));

        let completed = completion_task.await.expect("completion task must not panic");
        assert_eq!(completed.status(), 200, "iter {iter} complete: {}", text(&completed));

        let entries: Vec<std::path::PathBuf> = std::fs::read_dir(&versions_dir)
            .expect("read versions dir")
            .map(|entry| entry.expect("entry").path())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "iter {iter}: expected a single healthy null version directory, found {entries:?}"
        );
        assert!(entries[0].join("record").is_file(), "iter {iter}: version directory missing record file");
    }

    let final_put = exchange(&service, signed(http::Method::PUT, "/shared/testobject", Bytes::from_static(b"final-ok"))).await;
    assert_eq!(final_put.status(), 200, "{}", text(&final_put));
    let final_get = exchange(&service, signed(http::Method::GET, "/shared/testobject", Bytes::new())).await;
    assert_eq!(final_get.status(), 200, "{}", text(&final_get));
    assert_eq!(final_get.body().as_ref(), b"final-ok");
}

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

//! Legacy RustFS's operation selection as the launcher serves it (rustfs/gateway#1127).
//!
//! Responsible for: what a request whose query carries `x-id`, or two operation keys, does to the
//! data on a real backend — each measured on a legacy build: a tagging document sent with
//! `x-id=PutObjectTagging` or beside a part's `partNumber&uploadId` stores tags and leaves the
//! object's bytes alone, `tagging&uploadId` deletes tags and aborts nothing, and `uploadId&uploads`
//! starts an upload; and an undeclared `x-id` refused before anything is written.
//! NOT responsible for: the order itself (`rustfs-gateway-core`'s `legacy_rustfs` tests).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const TAGS: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// `TAGS`' Content-MD5, which the tagging operation requires of its body.
const TAGS_MD5: &str = "EbdZDxVT2OADmYhaGBi6mA==";

const ORIGINAL: &[u8] = b"original-bytes";

/// A service with the bucket `sel` and the object `sel/obj` holding [`ORIGINAL`].
async fn selecting(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/sel", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let written = exchange(&service, as_main(http::Method::PUT, "/sel/obj", Bytes::from_static(ORIGINAL))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    service
}

fn put_tags(target: &str) -> http::Request<Bytes> {
    let length = TAGS.len().to_string();
    signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        target,
        Bytes::from_static(TAGS),
        &[("content-md5", TAGS_MD5), ("content-length", &length)],
    )
}

async fn object_bytes(service: &S3Service) -> Vec<u8> {
    let read = exchange(service, as_main(http::Method::GET, "/sel/obj", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    read.body().to_vec()
}

async fn tags(service: &S3Service) -> String {
    let read = exchange(service, as_main(http::Method::GET, "/sel/obj?tagging", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    body_of(&read)
}

/// Positive — a tagging document sent with `x-id=PutObjectTagging` stores tags; the object's bytes
/// are what they were.
#[tokio::test]
async fn an_x_id_stores_tags_and_leaves_the_object_alone() {
    let root = TestRoot::new();
    let service = selecting(&root).await;
    let tagged = exchange(&service, put_tags("/sel/obj?x-id=PutObjectTagging")).await;
    assert_eq!(tagged.status(), 200, "{}", body_of(&tagged));
    assert_eq!(object_bytes(&service).await, ORIGINAL);
    assert!(tags(&service).await.contains("<Key>k</Key>"));
}

/// Positive — tagging beside a part's keys is tagging: no part is written, the object is intact;
/// `tagging&uploadId` deletes the tags and aborts nothing; `uploadId&uploads` starts an upload.
#[tokio::test]
async fn two_operation_keys_act_as_legacy_rustfs_acts() {
    let root = TestRoot::new();
    let service = selecting(&root).await;
    let tagged = exchange(&service, put_tags("/sel/obj?tagging&partNumber=1&uploadId=nosuchupload")).await;
    assert_eq!(tagged.status(), 200, "{}", body_of(&tagged));
    assert_eq!(object_bytes(&service).await, ORIGINAL);
    assert!(tags(&service).await.contains("<Key>k</Key>"));
    let untagged = exchange(
        &service,
        as_main(http::Method::DELETE, "/sel/obj?tagging&uploadId=nosuchupload", Bytes::new()),
    )
    .await;
    assert_eq!(untagged.status(), 204, "{}", body_of(&untagged));
    assert!(!tags(&service).await.contains("<Key>k</Key>"));
    let started = exchange(
        &service,
        as_main(http::Method::POST, "/sel/obj?uploadId=nosuchupload&uploads", Bytes::new()),
    )
    .await;
    assert_eq!(started.status(), 200, "{}", body_of(&started));
    assert!(body_of(&started).contains("InitiateMultipartUploadResult"), "{}", body_of(&started));
}

/// Negative — an `x-id` legacy RustFS does not accept is `400 InvalidRequest`, and the tagging
/// document it carried is neither stored as tags nor as the object.
#[tokio::test]
async fn n_an_undeclared_x_id_writes_nothing() {
    let root = TestRoot::new();
    let service = selecting(&root).await;
    for target in ["/sel/obj?x-id=GetObjectTagging", "/sel/obj?x-id=NoSuchOp"] {
        let refused = exchange(&service, put_tags(target)).await;
        assert_eq!(refused.status(), 400, "{target}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains("<Code>InvalidRequest</Code>"),
            "{target}: {}",
            body_of(&refused)
        );
    }
    assert_eq!(object_bytes(&service).await, ORIGINAL);
    assert!(!tags(&service).await.contains("<Key>k</Key>"));
}

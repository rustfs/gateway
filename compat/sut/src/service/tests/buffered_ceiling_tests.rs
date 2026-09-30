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

//! Buffered writes past the core's bounds, as the RustFS-profile launcher stores them under
//! legacy RustFS's 20 MiB ceiling (rustfs/gateway#1173).
//!
//! Responsible for: a multipart completion, a tag set and a batch delete each past the core's
//! 1 MiB and 2 MiB bounds, applied as legacy RustFS applies them and read back; and the controls
//! that a body past 20 MiB applies nothing.
//! NOT responsible for: the ceiling's mechanics (`rustfs-gateway`'s `tests/buffered_ceiling.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `3268c42e00`): a
//! `PutBucketTagging` of 1.5 MiB is stored, a `DeleteObjects` padded to 3 MiB deletes the keys it
//! names, and a buffered body past 20 MiB applies nothing (`500 InternalError` there,
//! `400 MaxMessageLengthExceeded` here, rd-err-0014).

use super::*;

const MIB: usize = 1024 * 1024;
const XMLNS: &str = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/ceiling", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn code(response: &WireResponse) -> String {
    body_of(response)
        .split("<Code>")
        .nth(1)
        .and_then(|rest| rest.split("</Code>").next())
        .unwrap_or_default()
        .to_owned()
}

/// A tag set with one tag `key`, padded with white space to `length` bytes.
fn tag_set(key: &str, length: usize) -> Bytes {
    let head = "<Tagging><TagSet>";
    let tail = format!("<Tag><Key>{key}</Key><Value>v</Value></Tag></TagSet></Tagging>");
    Bytes::from(format!("{head}{}{tail}", " ".repeat(length - head.len() - tail.len())))
}

async fn tags(service: &S3Service) -> String {
    body_of(&exchange(service, as_main(http::Method::GET, "/ceiling?tagging", Bytes::new())).await)
}

/// Positive — a tag set of 1.5 MiB is stored and read back.
#[tokio::test]
async fn a_tag_set_past_one_mebibyte_is_stored() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/ceiling?tagging", tag_set("large", MIB + MIB / 2))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    assert!(tags(&service).await.contains("<Key>large</Key>"));
}

/// Positive — a multipart completion padded past 1 MiB completes, and the object holds its part.
#[tokio::test]
async fn a_completion_past_one_mebibyte_completes() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let created = body_of(&exchange(&service, as_main(http::Method::POST, "/ceiling/mpu?uploads", Bytes::new())).await);
    let upload = created
        .split("<UploadId>")
        .nth(1)
        .and_then(|rest| rest.split("</UploadId>").next())
        .expect("an upload id")
        .to_owned();
    let part = format!("/ceiling/mpu?partNumber=1&uploadId={upload}");
    let uploaded = exchange(&service, as_main(http::Method::PUT, &part, Bytes::from_static(b"hello"))).await;
    assert_eq!(uploaded.status(), 200, "{}", body_of(&uploaded));
    let list = format!(
        "<CompleteMultipartUpload {XMLNS}>{}<Part><PartNumber>1</PartNumber><ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag></Part></CompleteMultipartUpload>",
        " ".repeat(MIB + MIB / 2)
    );
    let completed = exchange(
        &service,
        as_main(http::Method::POST, &format!("/ceiling/mpu?uploadId={upload}"), Bytes::from(list)),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", body_of(&completed));
    let object = exchange(&service, as_main(http::Method::GET, "/ceiling/mpu", Bytes::new())).await;
    assert_eq!(object.status(), 200, "{}", body_of(&object));
    assert_eq!(object.body().as_ref(), b"hello");
}

/// Positive — a batch delete of a thousand keys padded to 3 MiB deletes the keys it names.
#[tokio::test]
async fn a_batch_delete_past_two_mebibytes_deletes() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let key = |index: usize| format!("k{index:04}");
    for index in [0, 999] {
        let target = format!("/ceiling/{}", key(index));
        let stored = exchange(&service, as_main(http::Method::PUT, &target, Bytes::from_static(b"x"))).await;
        assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    }
    let mut delete = String::from("<Delete>");
    for index in 0..1000 {
        delete.push_str(&format!("<Object><Key>{}</Key></Object>", key(index)));
    }
    delete.push_str(&" ".repeat(3 * MIB));
    delete.push_str("</Delete>");
    assert!(delete.len() > 3 * MIB);
    let deleted = exchange(&service, as_main(http::Method::POST, "/ceiling?delete", Bytes::from(delete))).await;
    assert_eq!(deleted.status(), 200, "{}", body_of(&deleted));
    for index in [0, 999] {
        let target = format!("/ceiling/{}", key(index));
        let read = exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await;
        assert_eq!(read.status(), 404, "key {index} was not deleted");
    }
}

/// Negative — a tag set one byte past 20 MiB is `400 MaxMessageLengthExceeded` and the stored tag
/// set is unchanged.
#[tokio::test]
async fn n_a_tag_set_past_twenty_mebibytes_stores_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let kept = exchange(&service, as_main(http::Method::PUT, "/ceiling?tagging", tag_set("kept", 128))).await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));
    let refused = exchange(&service, as_main(http::Method::PUT, "/ceiling?tagging", tag_set("large", 20 * MIB + 1))).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert_eq!(code(&refused), "MaxMessageLengthExceeded");
    let after = tags(&service).await;
    assert!(after.contains("<Key>kept</Key>") && !after.contains("<Key>large</Key>"), "{after}");
}

/// Negative — a tag set of exactly 20 MiB is stored: the ceiling is legacy RustFS's, not less.
#[tokio::test]
async fn n_a_tag_set_of_exactly_twenty_mebibytes_is_stored() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/ceiling?tagging", tag_set("edge", 20 * MIB))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    assert!(tags(&service).await.contains("<Key>edge</Key>"));
}

/// Negative — a completion past 20 MiB completes nothing: no object, and the part still listed.
#[tokio::test]
async fn n_a_completion_past_twenty_mebibytes_completes_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let created = body_of(&exchange(&service, as_main(http::Method::POST, "/ceiling/big?uploads", Bytes::new())).await);
    let upload = created
        .split("<UploadId>")
        .nth(1)
        .and_then(|rest| rest.split("</UploadId>").next())
        .expect("an upload id")
        .to_owned();
    let part = format!("/ceiling/big?partNumber=1&uploadId={upload}");
    let uploaded = exchange(&service, as_main(http::Method::PUT, &part, Bytes::from_static(b"hello"))).await;
    assert_eq!(uploaded.status(), 200, "{}", body_of(&uploaded));
    let list = format!(
        "<CompleteMultipartUpload {XMLNS}>{}<Part><PartNumber>1</PartNumber><ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag></Part></CompleteMultipartUpload>",
        " ".repeat(20 * MIB)
    );
    let complete = format!("/ceiling/big?uploadId={upload}");
    let refused = exchange(&service, as_main(http::Method::POST, &complete, Bytes::from(list))).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    let object = exchange(&service, as_main(http::Method::GET, "/ceiling/big", Bytes::new())).await;
    assert_eq!(object.status(), 404, "the refused completion stored an object");
    let parts = body_of(&exchange(&service, as_main(http::Method::GET, &complete, Bytes::new())).await);
    assert!(parts.contains("<PartNumber>1</PartNumber>"), "{parts}");
}

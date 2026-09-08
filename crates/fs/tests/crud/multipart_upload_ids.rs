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

//! Restart and storage-boundary evidence for multipart upload ID allocation.
//!
//! Responsible for: proving that one backend root mints distinct opaque upload capabilities after
//! reopen and that every minted capability remains active. NOT responsible for: upload listing,
//! part checksum semantics, or completion. Upstream: the persistent allocator in `uploads`.
//! Downstream: the filesystem CRUD verification target.

use bytes::Bytes;

use super::*;

const UPLOAD_ID_SEQUENCE: &str = ".multipart-upload-id-sequence";
const UPLOAD_ID_SEQUENCE_TEMP: &str = ".tmp-multipart-upload-id-sequence";

fn upload_id_authority(root: &TestRoot, bucket: &str, name: &str) -> PathBuf {
    root.0.join(format!("b-{}", hex::encode(bucket))).join("uploads").join(name)
}

fn upload_id_sequence(root: &TestRoot, bucket: &str) -> PathBuf {
    upload_id_authority(root, bucket, UPLOAD_ID_SEQUENCE)
}

async fn abort_upload(service: &S3Service, bucket: &str, upload_id: &str) {
    let response = exchange(
        service,
        signed(http::Method::DELETE, &format!("/{bucket}/same-key?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(response.status(), 204, "{}", String::from_utf8_lossy(response.body()));
}

async fn delete_bucket_response(service: &S3Service, bucket: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::DELETE, &format!("/{bucket}"), Bytes::new())).await
}

async fn initiate_response(service: &S3Service, bucket: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::POST, &format!("/{bucket}/same-key?uploads"), Bytes::new())).await
}

async fn assert_no_upload_was_created(service: &S3Service, bucket: &str) {
    let listed = exchange(service, signed(http::Method::GET, &format!("/{bucket}?uploads"), Bytes::new())).await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert!(!String::from_utf8_lossy(listed.body()).contains("<UploadId>"));
}

/// Positive — reopening the same root must advance the durable capability authority instead of
/// replaying the first process-local value. Writing a part through each ID proves both capabilities
/// remain active rather than merely proving that two response strings differ.
#[tokio::test]
async fn upload_id_allocation_survives_reopen_and_keeps_both_uploads_active() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    create_bucket(&running, "restart-upload-id").await;
    let first = initiate(&running, "restart-upload-id", "same-key").await;
    drop(running);
    drop(backend);

    let (_, reopened) = service(&root);
    let response = exchange(&reopened, signed(http::Method::POST, "/restart-upload-id/same-key?uploads", Bytes::new())).await;
    assert_eq!(
        response.status(),
        200,
        "first upload id {first}; second initiation returned {}",
        String::from_utf8_lossy(response.body())
    );
    let second = element(response.body(), "UploadId").expect("a second upload id");
    assert_ne!(second, first);

    let first_part = upload_part(&reopened, "restart-upload-id", "same-key", &first, 1, b"first").await;
    let second_part = upload_part(&reopened, "restart-upload-id", "same-key", &second, 1, b"second").await;
    assert_ne!(first_part, second_part);
}

/// Negative — the allocator reads its durable authority for every allocation; corrupting it after
/// open must refuse the request without deriving a replacement from upload directories.
#[tokio::test]
async fn n_corrupt_sequence_refuses_allocation_without_creating_an_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "corrupt-upload-id").await;
    std::fs::write(upload_id_sequence(&root, "corrupt-upload-id"), b"not-a-counter\n").expect("corrupt the exact test authority");

    let response = initiate_response(&service, "corrupt-upload-id").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_no_upload_was_created(&service, "corrupt-upload-id").await;
}

/// Negative — a valid but exhausted authority cannot wrap and reuse the first capability.
#[tokio::test]
async fn n_exhausted_sequence_refuses_allocation_without_creating_an_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "exhausted-upload-id").await;
    std::fs::write(upload_id_sequence(&root, "exhausted-upload-id"), format!("{}\n", u64::MAX))
        .expect("exhaust the exact test authority");

    let response = initiate_response(&service, "exhausted-upload-id").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_no_upload_was_created(&service, "exhausted-upload-id").await;
}

/// Negative — reopening does not let a corrupt durable authority silently restart at zero.
#[tokio::test]
async fn n_corrupt_sequence_refuses_allocation_after_backend_reopen() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    create_bucket(&running, "corrupt-reopen-id").await;
    drop(running);
    drop(backend);
    std::fs::write(upload_id_sequence(&root, "corrupt-reopen-id"), b"1\n2\n").expect("corrupt the exact test authority");

    let (_, reopened) = service(&root);
    let response = initiate_response(&reopened, "corrupt-reopen-id").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_no_upload_was_created(&reopened, "corrupt-reopen-id").await;
}

/// Negative — neither open nor allocation may follow a symlink replacing the durable authority.
#[cfg(unix)]
#[tokio::test]
async fn n_symlinked_sequence_is_refused_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (backend, running) = service(&root);
    create_bucket(&running, "symlink-upload-id").await;
    let target = outside.0.join("counter");
    std::fs::write(&target, b"0\n").expect("initialize the outside test file");
    let sequence = upload_id_sequence(&root, "symlink-upload-id");
    symlink(&target, &sequence).expect("replace the authority with a test symlink");

    let response = initiate_response(&running, "symlink-upload-id").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_no_upload_was_created(&running, "symlink-upload-id").await;
    assert_eq!(std::fs::read(&target).expect("read the outside test file"), b"0\n");
    drop(running);
    drop(backend);
    let (_, reopened) = service(&root);
    let response = initiate_response(&reopened, "symlink-upload-id").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
}

/// Negative — allocation must not follow or replace a pre-existing symlink at the atomic-write
/// temporary path, and the durable authority must remain unchanged.
#[cfg(unix)]
#[tokio::test]
async fn n_symlinked_sequence_temp_is_refused_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "symlink-upload-id-temp").await;
    let sequence = upload_id_sequence(&root, "symlink-upload-id-temp");
    std::fs::write(&sequence, b"0\n").expect("initialize the exact test authority");
    let target = outside.0.join("counter");
    std::fs::write(&target, b"outside\n").expect("initialize the outside test file");
    let temporary = upload_id_authority(&root, "symlink-upload-id-temp", UPLOAD_ID_SEQUENCE_TEMP);
    symlink(&target, &temporary).expect("replace the temporary authority path with a test symlink");

    let response = initiate_response(&service, "symlink-upload-id-temp").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_no_upload_was_created(&service, "symlink-upload-id-temp").await;
    assert_eq!(std::fs::read(&sequence).expect("read the durable test authority"), b"0\n");
    assert_eq!(std::fs::read(&target).expect("read the outside test file"), b"outside\n");
}

/// Positive — after the final upload retires, a reopened backend must treat its exact durable
/// sequence as internal authority, remove it, and delete the otherwise-empty bucket.
#[tokio::test]
async fn delete_bucket_after_abort_and_reopen_cleans_the_durable_sequence() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    create_bucket(&running, "delete-upload-sequence").await;
    let upload_id = initiate(&running, "delete-upload-sequence", "same-key").await;
    abort_upload(&running, "delete-upload-sequence", &upload_id).await;
    drop(running);
    drop(backend);

    let (_, reopened) = service(&root);
    let response = delete_bucket_response(&reopened, "delete-upload-sequence").await;
    assert_eq!(response.status(), 204, "{}", String::from_utf8_lossy(response.body()));
    assert!(!root.0.join(format!("b-{}", hex::encode("delete-upload-sequence"))).exists());
}

/// Positive — an interrupted atomic update may leave its exact regular temporary file behind;
/// bucket deletion may clean that reserved file, but no other upload-directory entry.
#[tokio::test]
async fn delete_bucket_cleans_the_exact_regular_sequence_temp() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "delete-upload-temp").await;
    let upload_id = initiate(&service, "delete-upload-temp", "same-key").await;
    abort_upload(&service, "delete-upload-temp", &upload_id).await;
    std::fs::write(
        upload_id_authority(&root, "delete-upload-temp", UPLOAD_ID_SEQUENCE_TEMP),
        b"interrupted\n",
    )
    .expect("create the exact reserved temporary file");

    let response = delete_bucket_response(&service, "delete-upload-temp").await;
    assert_eq!(response.status(), 204, "{}", String::from_utf8_lossy(response.body()));
}

/// Negative — a corrupt durable sequence is not an ignorable empty-bucket marker.
#[tokio::test]
async fn n_delete_bucket_refuses_a_malformed_sequence() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "delete-corrupt-sequence").await;
    let upload_id = initiate(&service, "delete-corrupt-sequence", "same-key").await;
    abort_upload(&service, "delete-corrupt-sequence", &upload_id).await;
    std::fs::write(upload_id_sequence(&root, "delete-corrupt-sequence"), b"not-a-counter\n")
        .expect("corrupt the exact test authority");

    let response = delete_bucket_response(&service, "delete-corrupt-sequence").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert!(upload_id_sequence(&root, "delete-corrupt-sequence").exists());
}

/// Negative — bucket deletion must not follow a symlink replacing the durable sequence.
#[cfg(unix)]
#[tokio::test]
async fn n_delete_bucket_refuses_a_symlinked_sequence_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "delete-symlink-sequence").await;
    let upload_id = initiate(&service, "delete-symlink-sequence", "same-key").await;
    abort_upload(&service, "delete-symlink-sequence", &upload_id).await;
    let sequence = upload_id_sequence(&root, "delete-symlink-sequence");
    std::fs::remove_file(&sequence).expect("remove the exact test authority");
    let target = outside.0.join("counter");
    std::fs::write(&target, b"outside\n").expect("initialize the outside test file");
    symlink(&target, &sequence).expect("replace the authority with a test symlink");

    let response = delete_bucket_response(&service, "delete-symlink-sequence").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(std::fs::read(&target).expect("read the outside test file"), b"outside\n");
}

/// Negative — bucket deletion must not treat a symlink at the atomic-write temporary path as a
/// removable internal file.
#[cfg(unix)]
#[tokio::test]
async fn n_delete_bucket_refuses_a_symlinked_sequence_temp_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "delete-symlink-sequence-temp").await;
    let upload_id = initiate(&service, "delete-symlink-sequence-temp", "same-key").await;
    abort_upload(&service, "delete-symlink-sequence-temp", &upload_id).await;
    let target = outside.0.join("counter");
    std::fs::write(&target, b"outside\n").expect("initialize the outside test file");
    let temporary = upload_id_authority(&root, "delete-symlink-sequence-temp", UPLOAD_ID_SEQUENCE_TEMP);
    symlink(&target, temporary).expect("replace the temporary authority path with a test symlink");

    let response = delete_bucket_response(&service, "delete-symlink-sequence-temp").await;
    assert_eq!(response.status(), 500, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(std::fs::read(&target).expect("read the outside test file"), b"outside\n");
}

/// Negative — only the two exact allocator authority names are internal; any other entry still
/// makes the bucket non-empty.
#[tokio::test]
async fn n_delete_bucket_refuses_any_other_upload_directory_entry() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "delete-extra-upload-entry").await;
    let upload_id = initiate(&service, "delete-extra-upload-entry", "same-key").await;
    abort_upload(&service, "delete-extra-upload-entry", &upload_id).await;
    std::fs::write(
        upload_id_authority(&root, "delete-extra-upload-entry", ".multipart-upload-id-sequence-extra"),
        b"0\n",
    )
    .expect("create a lookalike non-authority entry");

    let response = delete_bucket_response(&service, "delete-extra-upload-entry").await;
    assert_eq!(response.status(), 409, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>BucketNotEmpty</Code>"));
}

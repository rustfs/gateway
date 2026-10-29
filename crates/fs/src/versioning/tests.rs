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

//! The version lock, proven from the writer's side.
//!
//! Responsible for: version-lock coordination and durable version protection tests.
//! NOT responsible for: the versioning behaviour reachable through the wire, which
//! `tests/crud/versioning.rs` covers.
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used)]

use super::*;
use rustfs_gateway::{BucketName, Handler, Req, dto};

fn backend_with_bucket(tag: &str) -> (std::path::PathBuf, std::sync::Arc<FsBackend>) {
    let root = std::env::temp_dir().join(format!("rustfs-gateway-fs-versioning-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a test root");
    let backend = FsBackend::open(&root).expect("a usable test root");
    for directory in [
        super::super::OBJECTS_DIR,
        super::super::UPLOADS_DIR,
        super::super::VERSIONS_DIR,
    ] {
        std::fs::create_dir_all(backend.bucket_path("racing").join(directory)).expect("a bucket layout");
    }
    (root, std::sync::Arc::new(backend))
}

/// Negative — the current-record enumeration waits for the version lock instead of reading
/// past it. A `.tmp-*` directory exists only while `publish_version` holds the lock, and
/// `version_records` refuses one as corruption, so an enumeration that did not take the lock
/// answered `500` for a write in flight. Here the test is the writer: it holds the lock with the
/// temporary directory in place, proves the enumeration has not answered, then finishes the
/// write — and the enumeration answers the healthy listing.
#[tokio::test]
async fn n_the_current_record_enumeration_waits_for_a_write_in_flight() {
    let (root, backend) = backend_with_bucket("waits");
    let temporary = backend.versions_path("racing").join(".tmp-1-1");
    let guard = backend.version_lock.lock().await;
    std::fs::create_dir(&temporary).expect("the temporary directory of a write in flight");

    let listing = tokio::spawn({
        let backend = std::sync::Arc::clone(&backend);
        async move { backend.current_object_records("racing").await.map(|records| records.len()) }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!listing.is_finished(), "the enumeration answered while the write held the lock");

    std::fs::remove_dir(&temporary).expect("the write finishes");
    drop(guard);
    let records = listing.await.expect("the enumeration does not panic");
    assert_eq!(records.map_err(|error| error.code().clone()), Ok(0));
    let _ = std::fs::remove_dir_all(root);
}

fn sse_proof() -> rustfs_gateway::SseEnforced {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("a valid proof fixture");
    let wire = rustfs_gateway::WireRequest::accept(request, &rustfs_gateway::Limits::default()).expect("an accepted fixture");
    let meta = rustfs_gateway::MetaView::of(&wire, rustfs_gateway::TargetKind::Service).expect("a service fixture");
    rustfs_gateway::enforce_sse(&meta, rustfs_gateway::TransportSecurity::Encrypted, &rustfs_gateway::SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}

/// Negative — `DeleteBucket` waits for a write in flight instead of racing it. Without the lock a
/// version published between the emptiness check and the removal of `versions/` left `objects/`
/// gone and `versions/` not, and every later request on the bucket — a retry included — was
/// `500`. Here the test holds the lock as the writer would: the delete has not answered while it
/// is held, and answers `204` once the (empty) bucket is released to it.
#[tokio::test]
async fn n_delete_bucket_waits_for_a_write_in_flight() {
    let (root, backend) = backend_with_bucket("delete-waits");
    let guard = backend.version_lock.lock().await;
    let delete = tokio::spawn({
        let backend = std::sync::Arc::clone(&backend);
        async move {
            let input = dto::DeleteBucketInput {
                bucket: BucketName::new("racing").expect("a valid bucket"),
                ..dto::DeleteBucketInput::default()
            };
            Handler::<dto::DeleteBucket>::call(backend.as_ref(), Req::new(input, sse_proof()))
                .await
                .map(|response| response.status())
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!delete.is_finished(), "the delete answered while the write held the lock");
    drop(guard);
    let status = delete.await.expect("the delete does not panic");
    assert_eq!(status.map_err(|error| error.code().clone()), Ok(204));
    assert!(!backend.bucket_path("racing").exists(), "the bucket is gone once the delete ran");
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — a protected exact version stays present after restart and an explicit deletion.
#[tokio::test]
async fn n_a_restarted_protected_version_cannot_be_deleted() {
    let (root, backend) = backend_with_bucket("lock-restart");
    let bytes = b"protected";
    let tag = etag(bytes).expect("a valid entity tag");
    let record = backend
        .publish_version("racing", "object", Some("v1"), Some(bytes), Some(&tag), &ObjectAttributes::default())
        .await
        .expect("a persisted version");
    let path = record.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("the version record");
    encoded.push_str("lock/1 1\nCOMPLIANCE 4102444800 ON\n");
    std::fs::write(&path, encoded).expect("persist protection in the record");
    drop(backend);
    let reopened = FsBackend::open(&root).expect("reopen backend");
    let restored = reopened
        .read_version_record(record.path.clone())
        .await
        .expect("protected record survives restart");
    assert!(encode_version_record(&restored).ends_with("lock/1 1\nCOMPLIANCE 4102444800 ON\n"));
    let error = reopened
        .delete_object_version("racing", "object", Some("v1"))
        .await
        .expect_err("a protected version must not be removed");
    assert_eq!(error.code(), &ErrorCode::ACCESS_DENIED);
    assert!(record.path.join(BODY_FILE).exists(), "the protected bytes remain present");
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — malformed durable protection is refused rather than treated as unlocked.
#[test]
fn n_malformed_lock_records_are_rejected() {
    let prefix = "1\n6b\n7631\nobject\n0\nabc\n3\n5354414e44415244\n";
    for section in [
        "lock/1 0\nCOMPLIANCE 4102444800 ON\n",
        "lock/1 1\nUNKNOWN 4102444800 ON\n",
        "lock/1 1\nCOMPLIANCE invalid ON\n",
        "lock/1 1\nCOMPLIANCE 1.5 ON\n",
        "lock/1 1\nCOMPLIANCE 1.9999999999 ON\n",
        "lock/1 1\nCOMPLIANCE 1.12345678x ON\n",
        "lock/1 1\nCOMPLIANCE 4102444800 MAYBE\n",
        "lock/1 1\nCOMPLIANCE 4102444800 ON\nlock/1 1\nNONE - -\n",
    ] {
        let encoded = format!("{prefix}{section}");
        assert!(decode_version_record(PathBuf::new(), &encoded).is_err(), "{section:?}");
    }
}

/// Negative — replacing a protected null version must leave its old bytes intact.
#[tokio::test]
async fn n_protected_null_version_cannot_be_replaced() {
    let (root, backend) = backend_with_bucket("lock-null");
    let bytes = b"old";
    let tag = etag(bytes).expect("valid tag");
    let record = backend
        .publish_version("racing", "object", Some("null"), Some(bytes), Some(&tag), &ObjectAttributes::default())
        .await
        .expect("initial record");
    let path = record.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("record");
    encoded.push_str("lock/1 1\nGOVERNANCE 4102444800 OFF\n");
    std::fs::write(path, encoded).expect("protection");
    let result = backend
        .publish_object("racing", "object", b"new", &etag(b"new").expect("tag"), &ObjectAttributes::default())
        .await;
    assert_eq!(result.err().map(|error| error.code().clone()), Some(ErrorCode::ACCESS_DENIED));
    assert_eq!(std::fs::read(record.path.join(BODY_FILE)).expect("old bytes"), bytes);
    assert_eq!(backend.version_records("racing").await.expect("records").len(), 1);
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — lifecycle must retain a protected noncurrent version.
#[tokio::test]
async fn n_lifecycle_keeps_protected_noncurrent_version() {
    let (root, backend) = backend_with_bucket("lock-lifecycle");
    let tag = etag(b"old").expect("tag");
    let old = backend
        .publish_version("racing", "object", Some("v1"), Some(b"old"), Some(&tag), &ObjectAttributes::default())
        .await
        .expect("old version");
    let path = old.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("record");
    encoded.push_str("lock/1 1\nCOMPLIANCE 4102444800 OFF\n");
    std::fs::write(path, encoded).expect("protection");
    backend
        .publish_version(
            "racing",
            "object",
            Some("v2"),
            Some(b"new"),
            Some(&etag(b"new").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("successor");
    let rules = [dto::LifecycleRule {
        status: dto::Status::ENABLED,
        prefix: Some(String::new()),
        noncurrent_version_expiration: Some(dto::NoncurrentVersionExpiration {
            noncurrent_days: Some(1),
            ..Default::default()
        }),
        ..Default::default()
    }];
    let candidates = backend
        .expiring_version_candidates("racing", &rules, 4102444801)
        .await
        .expect("select candidates");
    assert!(candidates.contains(&("object".to_owned(), old.sequence)));
    backend
        .expire_selected_versions("racing", &rules, &candidates, 4102444801)
        .await
        .expect("run expiration");
    assert!(old.path.join(BODY_FILE).exists(), "protected bytes remain");
    let _ = std::fs::remove_dir_all(root);
}

/// Both retention and legal hold independently protect only while applicable.
#[tokio::test]
async fn lock_retention_and_hold_control_deletion_independently() {
    for (tag, section, blocked) in [
        ("future", "GOVERNANCE 4102444800 OFF", true),
        ("held", "COMPLIANCE 1 ON", true),
        ("expired", "COMPLIANCE 1 OFF", false),
        ("clear", "NONE - OFF", false),
    ] {
        let (root, backend) = backend_with_bucket(tag);
        let record = backend
            .publish_version(
                "racing",
                "object",
                Some("v1"),
                Some(b"x"),
                Some(&etag(b"x").expect("tag")),
                &ObjectAttributes::default(),
            )
            .await
            .expect("record");
        let path = record.path.join(RECORD_FILE);
        let mut encoded = std::fs::read_to_string(&path).expect("record");
        encoded.push_str(&format!("lock/1 1\n{section}\n"));
        std::fs::write(path, encoded).expect("protection");
        let result = backend.delete_object_version("racing", "object", Some("v1")).await;
        if blocked {
            assert_eq!(result.err().map(|error| error.code().clone()), Some(ErrorCode::ACCESS_DENIED), "{tag}");
            assert!(record.path.join(BODY_FILE).exists(), "{tag}");
        } else {
            assert!(result.is_ok(), "{tag}");
            assert!(!record.path.exists(), "{tag}");
        }
        let _ = std::fs::remove_dir_all(root);
    }
}

/// Negative — a malformed protected record blocks deletion and preserves bytes.
#[tokio::test]
async fn n_corrupt_protection_blocks_exact_deletion() {
    let (root, backend) = backend_with_bucket("lock-corrupt");
    let record = backend
        .publish_version(
            "racing",
            "object",
            Some("v1"),
            Some(b"x"),
            Some(&etag(b"x").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("record");
    let path = record.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("record");
    encoded.push_str("lock/1 1\nCOMPLIANCE invalid ON\n");
    std::fs::write(path, encoded).expect("protection");
    let error = backend
        .delete_object_version("racing", "object", Some("v1"))
        .await
        .expect_err("malformed record");
    assert_eq!(error.code(), &ErrorCode::INTERNAL_ERROR);
    assert!(record.path.join(BODY_FILE).exists());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — deleting the current null version cannot remove a held object.
#[tokio::test]
async fn n_protected_null_version_cannot_be_deleted_as_current() {
    let (root, backend) = backend_with_bucket("lock-null-delete");
    let record = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"x"),
            Some(&etag(b"x").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("record");
    let path = record.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("record");
    encoded.push_str("lock/1 1\nNONE - ON\n");
    std::fs::write(path, encoded).expect("protection");
    let error = backend
        .delete_object_version("racing", "object", None)
        .await
        .expect_err("held version");
    assert_eq!(error.code(), &ErrorCode::ACCESS_DENIED);
    assert!(record.path.join(BODY_FILE).exists());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — deletion must observe protection installed while it waits for the version lock.
#[tokio::test]
async fn n_delete_observes_protection_before_lock_release() {
    let (root, backend) = backend_with_bucket("lock-race");
    let record = backend
        .publish_version(
            "racing",
            "object",
            Some("v1"),
            Some(b"x"),
            Some(&etag(b"x").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("record");
    let guard = backend.version_lock.lock().await;
    let pending = tokio::spawn({
        let backend = std::sync::Arc::clone(&backend);
        async move { backend.delete_object_version("racing", "object", Some("v1")).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!pending.is_finished(), "deletion must wait for protection update");
    let path = record.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("record");
    encoded.push_str("lock/1 1\nNONE - ON\n");
    std::fs::write(path, encoded).expect("protection");
    drop(guard);
    let error = pending.await.expect("task completes").expect_err("protected version");
    assert_eq!(error.code(), &ErrorCode::ACCESS_DENIED);
    assert!(record.path.join(BODY_FILE).exists());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — delete markers cannot carry object retention or legal holds.
#[test]
fn n_delete_marker_cannot_carry_protection() {
    let encoded = "1\n6b\n7631\ndelete\n0\n\n0\n5354414e44415244\nlock/1 1\nNONE - ON\n";
    assert!(decode_version_record(PathBuf::new(), encoded).is_err());
}

/// Negative — unsupported upload protection must not be silently discarded.
#[test]
fn n_upload_record_with_lock_is_rejected() {
    let (root, backend) = backend_with_bucket("lock-upload");
    let upload = backend.upload_path("racing", "upload");
    std::fs::create_dir_all(upload.join(super::super::PARTS_DIR)).expect("parts directory");
    let path = upload.join(super::super::UPLOAD_RECORD);
    let plain = "726163696e67\n6f626a656374\n75706c6f6164\n0\n-\n-\n";
    std::fs::write(&path, plain).expect("ordinary upload");
    assert!(backend.read_upload_record("racing", "upload").is_some());
    std::fs::write(&path, format!("{plain}lock/1 1\nNONE - ON\n")).expect("protected upload");
    assert!(backend.read_upload_record("racing", "upload").is_none());
    let _ = std::fs::remove_dir_all(root);
}

/// A protection supplied to publication is encoded with the version and survives reopening.
#[tokio::test]
async fn protection_written_with_version_survives_restart() {
    let (root, backend) = backend_with_bucket("lock-publish");
    let lock =
        super::super::lock_record::decode(&mut "GOVERNANCE 4102444800.500000000 ON".lines(), "1").expect("valid protection");
    let attrs = ObjectAttributes {
        lock: Some(lock),
        ..ObjectAttributes::default()
    };
    let record = backend
        .publish_version("racing", "object", Some("v1"), Some(b"x"), Some(&etag(b"x").expect("tag")), &attrs)
        .await
        .expect("publish protected version");
    drop(backend);
    let reopened = FsBackend::open(&root).expect("reopen");
    let actual = reopened.read_version_record(record.path.clone()).await.expect("read version");
    assert!(encode_version_record(&actual).ends_with("lock/1 1\nGOVERNANCE 4102444800.500000000 ON\n"));
    let error = reopened
        .delete_object_version("racing", "object", Some("v1"))
        .await
        .expect_err("protection survives");
    assert_eq!(error.code(), &ErrorCode::ACCESS_DENIED);
    assert!(record.path.join(BODY_FILE).exists());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — fractional retention cannot be shortened to its whole-second prefix.
#[test]
fn n_fractional_retention_survives_roundtrip_and_same_second() {
    let mut lines = "COMPLIANCE 4102444800.500000000 OFF".lines();
    let lock = super::super::lock_record::decode(&mut lines, "1").expect("fractional protection");
    assert_eq!(
        super::super::lock_record::encode(Some(&lock)),
        "lock/1 1\nCOMPLIANCE 4102444800.500000000 OFF\n"
    );
    assert!(lock.prevents_deletion(4102444800));
    assert!(!lock.prevents_deletion(4102444801));
}

tokio::task_local! {
    static FAIL_VERSION_RECORD_WRITE: ();
}

pub(super) fn block_version_record_write(directory: &std::path::Path) {
    if FAIL_VERSION_RECORD_WRITE.try_with(|_| ()).is_ok() {
        std::fs::create_dir(directory.join(RECORD_FILE)).expect("install a real record-write obstruction");
    }
}

/// Negative — a failed record write cannot publish a partial protected version.
#[tokio::test]
async fn n_failed_protection_record_write_publishes_nothing() {
    let (root, backend) = backend_with_bucket("lock-write-failure");
    let old = backend
        .publish_version(
            "racing",
            "object",
            Some("v1"),
            Some(b"old"),
            Some(&etag(b"old").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old version");
    let lock = super::super::lock_record::decode(&mut "COMPLIANCE 4102444800 ON".lines(), "1").expect("protection");
    let attrs = ObjectAttributes {
        lock: Some(lock),
        ..ObjectAttributes::default()
    };
    let result = FAIL_VERSION_RECORD_WRITE
        .scope(
            (),
            backend.publish_version("racing", "object", Some("v2"), Some(b"new"), Some(&etag(b"new").expect("tag")), &attrs),
        )
        .await;
    assert_eq!(result.err().map(|error| error.code().clone()), Some(ErrorCode::INTERNAL_ERROR));
    assert_eq!(std::fs::read(old.path.join(BODY_FILE)).expect("old bytes"), b"old");
    assert!(
        !std::fs::read_dir(backend.versions_path("racing"))
            .expect("versions directory")
            .any(|entry| entry.expect("entry").file_name().to_string_lossy().starts_with(".tmp-"))
    );
    let records = backend.version_records("racing").await.expect("read versions after failure");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].version_id, "v1");
    let _ = std::fs::remove_dir_all(root);
}

#[path = "coordination_tests.rs"]
mod coordination_tests;

#[path = "cross_process_tests.rs"]
mod cross_process_tests;

#[path = "transaction_tests.rs"]
mod transaction_tests;

#[path = "lifecycle_transaction_tests.rs"]
mod lifecycle_transaction_tests;

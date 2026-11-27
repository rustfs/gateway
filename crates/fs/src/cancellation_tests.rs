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

//! Cancellation-drop and concurrent-access negative tests for `FsBackend`.
//!
//! Responsible for: proving that dropping async write/multipart futures mid-flight cleans staging
//! artifacts so buckets are never permanently bricked, that crash-left staging directories fail
//! safe while symlinks fail closed, and that shared-root upload allocation and bucket lifecycle
//! races never return `500 InternalError`.
//! NOT responsible for: ordinary S3 CRUD semantics (`tests/crud.rs`).
//! Upstream: `super` (`FsBackend`). Downstream: Cargo unit test harness.

#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};

use rustfs_gateway::dto::{
    CompleteMultipartUpload, CompleteMultipartUploadInput, CompletedMultipartUpload, CompletedPart, CreateBucket,
    CreateBucketInput, CreateMultipartUpload, CreateMultipartUploadInput, DeleteBucket, DeleteBucketInput, PutObject,
    PutObjectInput,
};
use rustfs_gateway::{BucketName, ByteStream, ErrorCode, Handler, ObjectKey, Req, UploadIdClaim};

use super::records::ObjectAttributes;
use super::staging::test_hooks::pause_at;
use super::{FsBackend, OBJECTS_DIR, UPLOADS_DIR, VERSIONS_DIR, etag};

fn scratch_root(tag: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("rustfs-gateway-fs-cancel-{}-{tag}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create test root");
    root
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

async fn create_bucket(backend: &FsBackend, name: &str) {
    let input = CreateBucketInput {
        bucket: BucketName::new(name).expect("valid bucket"),
        ..CreateBucketInput::default()
    };
    Handler::<CreateBucket>::call(backend, Req::new(input, sse_proof()))
        .await
        .expect("create bucket");
}

async fn delete_bucket(backend: &FsBackend, name: &str) -> Result<u16, ErrorCode> {
    let input = DeleteBucketInput {
        bucket: BucketName::new(name).expect("valid bucket"),
        ..DeleteBucketInput::default()
    };
    Handler::<DeleteBucket>::call(backend, Req::new(input, sse_proof()))
        .await
        .map(|resp| resp.status())
        .map_err(|err| err.code().clone())
}

fn entries_with_prefix(dir: &Path, prefix: &str) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read directory")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().to_string_lossy().into_owned();
            name.starts_with(prefix).then_some(name)
        })
        .collect()
}

/// Polls a future until `ready_to_drop()` holds, then drops the future in place without letting it
/// finish.
async fn poll_until_and_drop<F, P>(future: F, mut ready_to_drop: P)
where
    F: Future,
    P: FnMut() -> bool,
{
    let mut future = Box::pin(future);
    let mut observed = false;
    for _ in 0..4096 {
        let mut cx = Context::from_waker(Waker::noop());
        if Pin::as_mut(&mut future).poll(&mut cx).is_ready() {
            break;
        }
        if ready_to_drop() {
            observed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert!(observed, "staging artifact was never observed before the future finished");
    drop(future);
}

/// Negative — cancelling `CompleteMultipartUpload` after the upload is moved to `.complete-*`
/// while waiting on the version lock must clean up / restore `.complete-*` so `DeleteBucket` is
/// never permanently stuck returning `BucketNotEmpty`.
#[tokio::test]
async fn n_cancelled_complete_multipart_upload_does_not_leave_tombstone_or_brick_delete() {
    let root = scratch_root("complete-cancel");
    let backend = Arc::new(FsBackend::open(&root).expect("open backend"));
    create_bucket(&backend, "cancel-mpu").await;

    let bucket = BucketName::new("cancel-mpu").expect("bucket");
    let key = ObjectKey::new("obj").expect("key");
    let attrs = ObjectAttributes::default();
    let upload_id = backend
        .create_upload_locked(&bucket, &key, None, &attrs)
        .await
        .expect("create upload");
    let body = b"part-payload";
    backend
        .store_part("cancel-mpu", &upload_id, 1, body)
        .await
        .expect("store part");
    let part_etag = etag(body).expect("etag");

    // Hold version_lock so CompleteMultipartUpload parks right after renaming upload -> .complete-*.
    let guard = backend.version_lock.lock().await;
    let uploads_dir = backend.uploads_path("cancel-mpu");

    let complete_input = CompleteMultipartUploadInput {
        bucket: bucket.clone(),
        key: key.clone(),
        upload_id: UploadIdClaim::from_wire(upload_id.clone()),
        multipart_upload: CompletedMultipartUpload {
            parts: vec![CompletedPart {
                e_tag: Some(part_etag),
                part_number: 1,
                ..CompletedPart::default()
            }],
        },
        ..CompleteMultipartUploadInput::default()
    };

    let complete_fut = Handler::<CompleteMultipartUpload>::call(backend.as_ref(), Req::new(complete_input, sse_proof()));
    poll_until_and_drop(complete_fut, || !entries_with_prefix(&uploads_dir, ".complete-").is_empty()).await;
    drop(guard);

    assert!(
        entries_with_prefix(&uploads_dir, ".complete-").is_empty(),
        "cancelled CompleteMultipartUpload left .complete-* tombstone behind"
    );
    assert!(
        backend.read_upload_record("cancel-mpu", &upload_id).is_some(),
        "cancelled pre-publish completion should restore the pending upload"
    );
    assert_eq!(delete_bucket(&backend, "cancel-mpu").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — a crash-left `.tmp-*` directory in `versions/` must not permanently cause
/// `version_records()` to return `500 InternalError` or block `DeleteBucket`, while a symlinked
/// `.tmp-*` entry must still fail closed with `InvalidRequest`.
#[tokio::test]
async fn n_crash_left_version_temp_dir_recovers_while_symlink_fails_closed() {
    let root = scratch_root("crash-tmp-version");
    let backend = FsBackend::open(&root).expect("open backend");
    create_bucket(&backend, "crash-bkt").await;

    let stale = backend.versions_path("crash-bkt").join(".tmp-999999-42");
    std::fs::create_dir(&stale).expect("create stale staging dir");
    std::fs::write(stale.join("body"), b"partial").expect("write partial body");

    let records = backend
        .version_records("crash-bkt")
        .await
        .expect("crash-left .tmp-* dir must not brick version_records");
    assert!(records.is_empty());
    assert_eq!(delete_bucket(&backend, "crash-bkt").await, Ok(204));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = scratch_root("crash-tmp-outside");
        let victim = outside.join("victim");
        std::fs::create_dir_all(&victim).expect("victim dir");
        std::fs::write(victim.join("keep"), b"safe").expect("victim file");

        create_bucket(&backend, "symlink-bkt").await;
        symlink(&victim, backend.versions_path("symlink-bkt").join(".tmp-999999-99")).expect("symlink");
        let err = backend
            .version_records("symlink-bkt")
            .await
            .err()
            .expect("symlinked .tmp-* must fail closed");
        assert_eq!(err.code(), &ErrorCode::INVALID_REQUEST);
        assert_eq!(std::fs::read(victim.join("keep")).expect("victim intact"), b"safe");
        let _ = std::fs::remove_dir_all(outside);
    }

    let _ = std::fs::remove_dir_all(root);
}

/// Negative — multiple `FsBackend` instances sharing one data root allocating upload IDs
/// concurrently must serialize via bounded lock acquisition instead of failing fast with `500`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_concurrent_shared_root_upload_allocations_do_not_return_500() {
    let root = scratch_root("shared-root-mpu");
    let setup = FsBackend::open(&root).expect("open setup backend");
    create_bucket(&setup, "shared-mpu").await;

    // Hold the directory flock briefly from a background task to simulate another process/instance
    // reserving a window, and verify concurrent allocate_upload_id waits instead of failing fast.
    let uploads_dir = setup.uploads_path("shared-mpu");
    let lock_holder = std::fs::File::open(&uploads_dir).expect("open uploads dir");
    lock_holder.try_lock().expect("acquire initial flock");
    let release = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        drop(lock_holder);
    });

    let mut tasks = tokio::task::JoinSet::new();
    for worker in 0..4usize {
        let root = root.clone();
        tasks.spawn(async move {
            let backend = FsBackend::open(&root).expect("open shared backend");
            let mut ids = Vec::new();
            for round in 0..4usize {
                let input = CreateMultipartUploadInput {
                    bucket: BucketName::new("shared-mpu").expect("bucket"),
                    key: ObjectKey::new(format!("w{worker}-r{round}")).expect("key"),
                    ..CreateMultipartUploadInput::default()
                };
                let resp = Handler::<CreateMultipartUpload>::call(&backend, Req::new(input, sse_proof()))
                    .await
                    .unwrap_or_else(|err| panic!("worker {worker} round {round} failed: {}", err.code()));
                ids.push(resp.into_output().expect("upload output").upload_id);
            }
            ids
        });
    }

    release.await.expect("release task");
    let mut all_ids = HashSet::new();
    while let Some(joined) = tasks.join_next().await {
        for id in joined.expect("worker task") {
            assert!(all_ids.insert(id), "duplicate upload ID issued across shared-root backends");
        }
    }
    assert_eq!(all_ids.len(), 16);
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — racing `CreateBucket`, `DeleteBucket`, and `CreateMultipartUpload` on the same
/// backend must never return `500 InternalError` or leave a half-initialized bucket directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_concurrent_bucket_lifecycle_and_create_multipart_never_returns_500() {
    let root = scratch_root("bucket-mpu-race");
    let backend = Arc::new(FsBackend::open(&root).expect("open backend"));

    for round in 0..12usize {
        let name = format!("race-bkt-{round}");
        create_bucket(&backend, &name).await;

        let b_del = Arc::clone(&backend);
        let n_del = name.clone();
        let del_task = tokio::spawn(async move { delete_bucket(&b_del, &n_del).await });

        let b_mpu = Arc::clone(&backend);
        let n_mpu = name.clone();
        let mpu_task = tokio::spawn(async move {
            let input = CreateMultipartUploadInput {
                bucket: BucketName::new(&n_mpu).expect("bucket"),
                key: ObjectKey::new("k").expect("key"),
                ..CreateMultipartUploadInput::default()
            };
            Handler::<CreateMultipartUpload>::call(b_mpu.as_ref(), Req::new(input, sse_proof()))
                .await
                .map(|_| 200u16)
                .map_err(|err| err.code().clone())
        });

        let del_res = del_task.await.expect("delete task");
        let mpu_res = mpu_task.await.expect("mpu task");

        assert_ne!(del_res, Err(ErrorCode::INTERNAL_ERROR), "round {round}: DeleteBucket returned 500");
        assert_ne!(
            mpu_res,
            Err(ErrorCode::INTERNAL_ERROR),
            "round {round}: CreateMultipartUpload returned 500"
        );

        // The bucket directory must either be completely absent or completely intact (all 3 subdirs).
        let bucket_path = backend.bucket_path(&name);
        if bucket_path.exists() {
            assert!(bucket_path.join(OBJECTS_DIR).is_dir(), "round {round}: missing objects/");
            assert!(bucket_path.join(UPLOADS_DIR).is_dir(), "round {round}: missing uploads/");
            assert!(bucket_path.join(VERSIONS_DIR).is_dir(), "round {round}: missing versions/");
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — cancelling `publish_version` mid-flight after `.tmp-*` is created must clean the
/// staging directory immediately on drop so `version_records()` and `DeleteBucket` keep working.
#[tokio::test]
async fn n_cancelled_publish_version_cleans_staging_dir_on_drop() {
    let root = scratch_root("cancel-publish");
    let backend = FsBackend::open(&root).expect("open backend");
    create_bucket(&backend, "pub-bkt").await;

    let versions_dir = backend.versions_path("pub-bkt");
    let body = b"ephemeral";
    let tag = etag(body).expect("etag");
    let attrs = ObjectAttributes::default();
    let entered = Arc::new(AtomicBool::new(false));
    let fut = pause_at(
        "publish_version",
        Arc::clone(&entered),
        backend.publish_object("pub-bkt", "obj", body, &tag, &attrs),
    );
    poll_until_and_drop(fut, || {
        entered.load(Ordering::SeqCst) && !entries_with_prefix(&versions_dir, ".tmp-").is_empty()
    })
    .await;

    assert!(
        entries_with_prefix(&versions_dir, ".tmp-").is_empty(),
        "dropped publish_version left .tmp-* staging dir behind"
    );
    assert!(backend.version_records("pub-bkt").await.expect("version_records").is_empty());
    assert_eq!(delete_bucket(&backend, "pub-bkt").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — cancelling `create_upload` mid-flight after `.tmp-upload-*` is created must clean
/// the staging directory on drop so `DeleteBucket` does not return `BucketNotEmpty`.
#[tokio::test]
async fn n_cancelled_create_upload_cleans_staging_dir_on_drop() {
    let root = scratch_root("cancel-create-upload");
    let backend = FsBackend::open(&root).expect("open backend");
    create_bucket(&backend, "up-bkt").await;

    let uploads_dir = backend.uploads_path("up-bkt");
    let input = CreateMultipartUploadInput {
        bucket: BucketName::new("up-bkt").expect("bucket"),
        key: ObjectKey::new("obj").expect("key"),
        ..CreateMultipartUploadInput::default()
    };
    let entered = Arc::new(AtomicBool::new(false));
    let fut = pause_at(
        "create_upload",
        Arc::clone(&entered),
        Handler::<CreateMultipartUpload>::call(&backend, Req::new(input, sse_proof())),
    );
    poll_until_and_drop(fut, || {
        entered.load(Ordering::SeqCst) && !entries_with_prefix(&uploads_dir, ".tmp-upload-").is_empty()
    })
    .await;

    assert!(
        entries_with_prefix(&uploads_dir, ".tmp-upload-").is_empty(),
        "dropped create_upload left .tmp-upload-* staging dir behind"
    );
    assert_eq!(delete_bucket(&backend, "up-bkt").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — cancelling `CompleteMultipartUpload` after object publication while `.complete-*`
/// is being removed must still remove `.complete-*` on drop and keep the published object intact.
#[tokio::test]
async fn n_cancelled_post_publish_complete_removes_tombstone_on_drop() {
    let root = scratch_root("cancel-post-publish");
    let backend = FsBackend::open(&root).expect("open backend");
    create_bucket(&backend, "post-mpu").await;

    let bucket = BucketName::new("post-mpu").expect("bucket");
    let key = ObjectKey::new("obj").expect("key");
    let attrs = ObjectAttributes::default();
    let upload_id = backend
        .create_upload_locked(&bucket, &key, None, &attrs)
        .await
        .expect("create upload");
    let body = b"assembled";
    backend.store_part("post-mpu", &upload_id, 1, body).await.expect("store part");
    let part_etag = etag(body).expect("etag");
    let uploads_dir = backend.uploads_path("post-mpu");

    let complete_input = CompleteMultipartUploadInput {
        bucket,
        key,
        upload_id: UploadIdClaim::from_wire(upload_id),
        multipart_upload: CompletedMultipartUpload {
            parts: vec![CompletedPart {
                e_tag: Some(part_etag),
                part_number: 1,
                ..CompletedPart::default()
            }],
        },
        ..CompleteMultipartUploadInput::default()
    };
    let entered = Arc::new(AtomicBool::new(false));
    let fut = pause_at(
        "complete_remove",
        Arc::clone(&entered),
        Handler::<CompleteMultipartUpload>::call(&backend, Req::new(complete_input, sse_proof())),
    );
    poll_until_and_drop(fut, || {
        entered.load(Ordering::SeqCst) && !entries_with_prefix(&uploads_dir, ".complete-").is_empty()
    })
    .await;

    assert!(
        entries_with_prefix(&uploads_dir, ".complete-").is_empty(),
        "post-publish dropped CompleteMultipartUpload left .complete-* tombstone behind"
    );
    let records = backend.version_records("post-mpu").await.expect("version_records");
    assert_eq!(records.len(), 1);
    backend
        .delete_object_version("post-mpu", "obj", None)
        .await
        .expect("delete published object");
    assert_eq!(delete_bucket(&backend, "post-mpu").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — cancelling `AbortMultipartUpload` after moving the upload to `.abort-*` must still
/// remove `.abort-*` on drop so `DeleteBucket` succeeds.
#[tokio::test]
async fn n_cancelled_abort_multipart_upload_removes_tombstone_on_drop() {
    use rustfs_gateway::dto::{AbortMultipartUpload, AbortMultipartUploadInput};

    let root = scratch_root("cancel-abort");
    let backend = FsBackend::open(&root).expect("open backend");
    create_bucket(&backend, "abort-bkt").await;

    let bucket = BucketName::new("abort-bkt").expect("bucket");
    let key = ObjectKey::new("obj").expect("key");
    let attrs = ObjectAttributes::default();
    let upload_id = backend
        .create_upload_locked(&bucket, &key, None, &attrs)
        .await
        .expect("create upload");
    let uploads_dir = backend.uploads_path("abort-bkt");

    let abort_input = AbortMultipartUploadInput {
        bucket,
        key,
        upload_id: UploadIdClaim::from_wire(upload_id),
        ..AbortMultipartUploadInput::default()
    };
    let entered = Arc::new(AtomicBool::new(false));
    let fut = pause_at(
        "abort_upload",
        Arc::clone(&entered),
        Handler::<AbortMultipartUpload>::call(&backend, Req::new(abort_input, sse_proof())),
    );
    poll_until_and_drop(fut, || {
        entered.load(Ordering::SeqCst) && !entries_with_prefix(&uploads_dir, ".abort-").is_empty()
    })
    .await;

    assert!(
        entries_with_prefix(&uploads_dir, ".abort-").is_empty(),
        "dropped AbortMultipartUpload left .abort-* tombstone behind"
    );
    assert_eq!(delete_bucket(&backend, "abort-bkt").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — cancelling `write_atomic` mid-flight removes its `.tmp-*` file on drop.
#[tokio::test]
async fn n_cancelled_write_atomic_cleans_temp_file_on_drop() {
    let root = scratch_root("cancel-write-atomic");
    let backend = FsBackend::open(&root).expect("open backend");
    create_bucket(&backend, "atomic-bkt").await;

    let objects_dir = backend.objects_path("atomic-bkt");
    let dest = objects_dir.join("o-target");
    let entered = Arc::new(AtomicBool::new(false));
    let fut = pause_at(
        "write_atomic",
        Arc::clone(&entered),
        backend.write_atomic(&objects_dir, &dest, b"payload"),
    );
    poll_until_and_drop(fut, || {
        entered.load(Ordering::SeqCst) && !entries_with_prefix(&objects_dir, ".tmp-").is_empty()
    })
    .await;

    assert!(
        entries_with_prefix(&objects_dir, ".tmp-").is_empty(),
        "dropped write_atomic left .tmp-* file behind"
    );
    assert!(!dest.exists());
    assert_eq!(delete_bucket(&backend, "atomic-bkt").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — cancelling `CreateBucket` mid-flight cleans `.tmp-bucket-*` and leaves no half-built
/// bucket directory behind.
#[tokio::test]
async fn n_cancelled_create_bucket_cleans_staging_dir_on_drop() {
    let root = scratch_root("cancel-create-bucket");
    let backend = FsBackend::open(&root).expect("open backend");

    let input = CreateBucketInput {
        bucket: BucketName::new("staging-bkt").expect("bucket"),
        ..CreateBucketInput::default()
    };
    let entered = Arc::new(AtomicBool::new(false));
    let fut = pause_at(
        "create_bucket",
        Arc::clone(&entered),
        Handler::<CreateBucket>::call(&backend, Req::new(input, sse_proof())),
    );
    poll_until_and_drop(fut, || {
        entered.load(Ordering::SeqCst) && !entries_with_prefix(&root, ".tmp-bucket-").is_empty()
    })
    .await;

    assert!(
        entries_with_prefix(&root, ".tmp-bucket-").is_empty(),
        "dropped CreateBucket left .tmp-bucket-* staging dir behind"
    );
    assert!(!backend.bucket_path("staging-bkt").exists());
    create_bucket(&backend, "staging-bkt").await;
    assert_eq!(delete_bucket(&backend, "staging-bkt").await, Ok(204));
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — crash-left `.tmp-upload-*`, `.complete-*`, and `.abort-*` directories in `uploads/`
/// must not permanently brick `DeleteBucket` with `BucketNotEmpty`, while unknown entries still
/// return `BucketNotEmpty` and symlinked or non-directory staging entries fail closed with
/// `InvalidRequest` without touching external targets.
#[tokio::test]
async fn n_crash_left_upload_staging_dirs_recover_while_symlink_and_unknown_fail_closed() {
    let root = scratch_root("crash-upload-staging");
    let backend = FsBackend::open(&root).expect("open backend");

    create_bucket(&backend, "crash-uploads").await;
    let uploads = backend.uploads_path("crash-uploads");
    for name in [".tmp-upload-999999-1", ".complete-999999-2", ".abort-999999-3"] {
        let dir = uploads.join(name);
        std::fs::create_dir(&dir).expect("create crash-left staging dir");
        std::fs::write(dir.join("part"), b"partial").expect("write partial staging file");
    }
    assert_eq!(delete_bucket(&backend, "crash-uploads").await, Ok(204));

    // Unknown entries in uploads/ still block DeleteBucket with BucketNotEmpty.
    create_bucket(&backend, "unknown-uploads").await;
    std::fs::create_dir(backend.uploads_path("unknown-uploads").join(".stray-dir")).expect("create stray dir");
    assert_eq!(delete_bucket(&backend, "unknown-uploads").await, Err(ErrorCode::BUCKET_NOT_EMPTY));

    // A regular file disguised under an upload staging prefix fails closed with InvalidRequest.
    create_bucket(&backend, "file-staging-uploads").await;
    std::fs::write(backend.uploads_path("file-staging-uploads").join(".tmp-upload-999999-8"), b"file")
        .expect("create non-directory staging file");
    assert_eq!(delete_bucket(&backend, "file-staging-uploads").await, Err(ErrorCode::INVALID_REQUEST));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = scratch_root("crash-upload-outside");
        let victim = outside.join("victim");
        std::fs::create_dir_all(&victim).expect("victim dir");
        std::fs::write(victim.join("keep"), b"safe").expect("victim file");

        create_bucket(&backend, "symlink-uploads").await;
        symlink(&victim, backend.uploads_path("symlink-uploads").join(".complete-999999-9")).expect("symlink");
        assert_eq!(delete_bucket(&backend, "symlink-uploads").await, Err(ErrorCode::INVALID_REQUEST));
        assert_eq!(std::fs::read(victim.join("keep")).expect("victim intact"), b"safe");
        let _ = std::fs::remove_dir_all(outside);
    }

    let _ = std::fs::remove_dir_all(root);
}

/// Negative — Tokio's `tokio::fs::File::write_all` returns before its final background write
/// finishes unless flushed. On the very poll that `publish_version` or `create_upload_locked`
/// renames its staging directory into `v-*` or `u-*`, every staged file (`body`, `tags`, `record`)
/// must already be completely flushed on disk — never 0-byte or truncated.
#[test]
fn n_published_version_and_upload_tags_flush_before_rename() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("build single-blocking-thread runtime");

    runtime.block_on(async {
        let root = scratch_root("flush-before-rename");
        let backend = FsBackend::open(&root).expect("open backend");
        create_bucket(&backend, "flush-bkt").await;

        let versions_dir = backend.versions_path("flush-bkt");
        // Exceeds Tokio's 2 MiB File::poll_write chunk ceiling so BODY_FILE spans multiple
        // background writes before TAGS_FILE, RECORD_FILE, and rename.
        let multi_chunk: Vec<u8> = (0..(3 * 1024 * 1024))
            .map(|idx| u8::try_from(idx % 251).expect("below 251"))
            .collect();
        let big_input = PutObjectInput {
            bucket: BucketName::new("flush-bkt").expect("bucket"),
            key: ObjectKey::new("big-3mib").expect("key"),
            tagging: Some("size=3mib".to_owned()),
            body: Some(ByteStream::from_bytes(bytes::Bytes::from(multi_chunk.clone()))),
            ..PutObjectInput::default()
        };

        let mut put_fut = Box::pin(Handler::<PutObject>::call(&backend, Req::new(big_input, sse_proof())));
        let mut observed_commit = false;
        let put_result = std::future::poll_fn(|cx| {
            let poll = Pin::as_mut(&mut put_fut).poll(cx);
            if !observed_commit && let Some(name) = entries_with_prefix(&versions_dir, "v-").into_iter().next() {
                observed_commit = true;
                let dir = versions_dir.join(name);
                let body = std::fs::read(dir.join("body")).expect("committed body readable");
                assert_eq!(body.len(), multi_chunk.len(), "v-* renamed before multi-chunk body flushed");
                let tags = std::fs::read_to_string(dir.join("tags")).expect("committed tags readable");
                assert!(tags.contains("size"), "v-* renamed before version tags flushed: {tags:?}");
                let record = std::fs::read_to_string(dir.join("record")).expect("committed record readable");
                assert!(!record.is_empty(), "v-* renamed before version record flushed (0-byte record on disk)");
            }
            poll
        })
        .await;
        assert!(observed_commit, "PutObject must commit a v-* directory");
        put_result.expect("multi-chunk PutObject must succeed");

        // Same atomic-visibility check for tagged CreateMultipartUpload: the instant `u-*` is
        // renamed into place, its `tags` file must already be flushed on disk.
        let uploads_dir = backend.uploads_path("flush-bkt");
        let upload_input = CreateMultipartUploadInput {
            bucket: BucketName::new("flush-bkt").expect("bucket"),
            key: ObjectKey::new("flushed-mpu").expect("key"),
            tagging: Some("mpu=flushed".to_owned()),
            ..CreateMultipartUploadInput::default()
        };
        let mut mpu_fut = Box::pin(Handler::<CreateMultipartUpload>::call(&backend, Req::new(upload_input, sse_proof())));
        let mut observed_upload = false;
        let mpu_result = std::future::poll_fn(|cx| {
            let poll = Pin::as_mut(&mut mpu_fut).poll(cx);
            if !observed_upload && let Some(name) = entries_with_prefix(&uploads_dir, "u-").into_iter().next() {
                observed_upload = true;
                let tags = std::fs::read_to_string(uploads_dir.join(name).join("tags")).expect("committed upload tags readable");
                assert!(tags.contains("mpu"), "u-* renamed before upload tags flushed: {tags:?}");
            }
            poll
        })
        .await;
        assert!(observed_upload, "CreateMultipartUpload must commit a u-* directory");
        mpu_result.expect("CreateMultipartUpload with tags must succeed");

        let _ = std::fs::remove_dir_all(root);
    });
}

/// Negative — deterministic proof that `staging::create_and_write_file` stays `Poll::Pending`
/// until Tokio's background write actually completes on disk, preventing `rename` from exposing
/// a 0-byte or truncated file when the blocking pool is saturated.
#[test]
fn n_staging_create_and_write_file_waits_for_blocking_flush() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("build single-blocking-thread runtime");

    runtime.block_on(async {
        let root = scratch_root("staging-flush-pending");
        let path = root.join("record");
        let payload = b"committed-version-record-bytes";

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx.recv().expect("blocker entered sole blocking thread");

        let mut fut = Box::pin(super::staging::create_and_write_file(&path, payload));
        let mut cx = Context::from_waker(Waker::noop());
        let first_poll = Pin::as_mut(&mut fut).poll(&mut cx);
        assert!(
            first_poll.is_pending(),
            "create_and_write_file must stay Poll::Pending until Tokio flushes the blocking write (saw {first_poll:?}, disk len={})",
            std::fs::read(&path).map(|b| b.len()).unwrap_or(0)
        );
        assert_eq!(
            std::fs::read(&path).expect("synchronously created file exists").len(),
            0,
            "sole blocking thread is still blocked so write cannot have landed yet"
        );

        let _ = release_tx.send(());
        blocker.await.expect("blocker joins");
        fut.await.expect("create_and_write_file finishes once blocking thread is free");
        assert_eq!(std::fs::read(&path).expect("flushed bytes readable"), payload);

        let _ = std::fs::remove_dir_all(root);
    });
}

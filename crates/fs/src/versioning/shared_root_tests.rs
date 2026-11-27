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

//! Unit controls for shared-root locking, cancellation safety, duplicate-null recovery, and
//! multipart completion replay persistence (`#1537`).
//!
//! Responsible for: in-process multi-instance exclusion, canonical-root registry sharing and weak
//! pruning, queued and started cancellation controls, `.tmp-*` crash resilience beside committed
//! versions, directory-order-independent duplicate-null reconciliation and protection safety, and
//! staged completion receipt persistence under faults.
//! NOT responsible for: real cross-process spawning controls (`tests/crud/shared_root.rs`).
//! Upstream: `super` (`versioning`), `super::null_recovery`, and `super::super::root_lock`.
//! Downstream: Cargo unit test harness.

#![allow(clippy::expect_used)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Waker};
use std::time::Duration;

use rustfs_gateway::{BucketName, ErrorCode, Handler, ObjectKey, Req, UploadIdClaim, dto};

use super::null_recovery::{self, SUPERSEDES_NULL_FILE};
use super::tests::{backend_with_bucket, sse_proof};
use super::{BODY_FILE, ObjectAttributes, RECORD_FILE};
use crate::root_lock::RootVersionLock;
use crate::{FsBackend, etag};

tokio::task_local! {
    static OBSTRUCT_COMPLETION_RECEIPT: ();
}

pub(super) fn maybe_obstruct_completion_receipt(staging_dir: &Path) {
    if OBSTRUCT_COMPLETION_RECEIPT.try_with(|_| ()).is_ok() {
        std::fs::create_dir(staging_dir.join("completion")).expect("install receipt obstruction dir");
    }
}

/// Renames `old_dir` to valid `v-*` names until filesystem `read_dir` yields it before `new_dir`,
/// proving explicit-null selection cannot depend on directory iteration order.
fn force_old_before_new_in_read_dir(versions_dir: &Path, old_dir: &mut PathBuf, new_dir: &Path) {
    let new_name = new_dir.file_name().expect("new dir name").to_os_string();
    let is_first = |old: &Path| -> bool {
        let old_name = old.file_name().expect("old dir name");
        for entry in std::fs::read_dir(versions_dir).expect("read versions dir") {
            let name = entry.expect("dir entry").file_name();
            if name == old_name {
                return true;
            }
            if name == new_name {
                return false;
            }
        }
        false
    };
    if is_first(old_dir) {
        return;
    }
    for attempt in 0..256u32 {
        let candidate = versions_dir.join(format!("v-00000000000000000000-probe-{attempt:04}"));
        std::fs::rename(&*old_dir, &candidate).expect("rename old null dir to control iteration order");
        *old_dir = candidate;
        if is_first(old_dir) {
            return;
        }
    }
    panic!("could not arrange old null directory before new null directory in read_dir");
}

/// Negative — two distinct `FsBackend::open` instances on the same root must share one version
/// lock so a second instance cannot delete a version while the first installs protection.
#[tokio::test]
async fn n_two_same_root_instances_serialize_protection_update_and_delete() {
    let (root, backend_a) = backend_with_bucket("two-instances");
    let backend_b = Arc::new(FsBackend::open(&root).expect("second instance on same root"));
    let record = backend_a
        .publish_version(
            "racing",
            "object",
            Some("v1"),
            Some(b"precious"),
            Some(&etag(b"precious").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("record");

    let guard = backend_a.version_lock.lock().await.expect("version lock");
    let pending = tokio::spawn({
        let backend_b = Arc::clone(&backend_b);
        async move { backend_b.delete_object_version("racing", "object", Some("v1")).await }
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        !pending.is_finished(),
        "second backend instance bypassed the first instance's shared-root version lock"
    );

    let path = record.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&path).expect("record");
    encoded.push_str("lock/1 1\nNONE - ON\n");
    std::fs::write(path, encoded).expect("install protection before lock release");
    drop(guard);

    let error = pending
        .await
        .expect("second instance task finishes")
        .expect_err("protected version must refuse deletion");
    assert_eq!(error.code(), &ErrorCode::ACCESS_DENIED);
    assert!(record.path.join(BODY_FILE).exists(), "protected bytes must survive");
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — same-root aliases and concurrent opens share one canonical mutex, distinct roots stay
/// independent, and weak registry entries are pruned once all backends on that root drop.
#[tokio::test]
async fn n_canonical_root_registry_shares_mutex_across_aliases_and_prunes_dead_entries() {
    let base = std::env::temp_dir().join(format!("rustfs-gateway-fs-reg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let real_parent = base.join("real");
    let root_a = real_parent.join("root-a");
    let root_b = real_parent.join("root-b");
    std::fs::create_dir_all(&root_a).expect("root a");
    std::fs::create_dir_all(&root_b).expect("root b");

    let canonical_a = std::fs::canonicalize(&root_a).expect("canonical a");
    let canonical_b = std::fs::canonicalize(&root_b).expect("canonical b");

    // Concurrent opens on root_a must converge on a single local mutex.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = root_a.clone();
        handles.push(std::thread::spawn(move || FsBackend::open(&p).expect("open root_a")));
    }
    let backends: Vec<FsBackend> = handles.into_iter().map(|h| h.join().expect("join")).collect();
    for backend in &backends[1..] {
        assert!(
            backends[0].version_lock.shares_local_mutex_with(&backend.version_lock),
            "concurrent opens on same canonical root must share one mutex"
        );
    }

    // Distinct root gets an independent mutex.
    let backend_b = FsBackend::open(&root_b).expect("open root_b");
    assert!(
        !backends[0].version_lock.shares_local_mutex_with(&backend_b.version_lock),
        "distinct canonical roots must not share one mutex"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias_parent = base.join("alias");
        symlink(&real_parent, &alias_parent).expect("parent symlink alias");
        let aliased = FsBackend::open(alias_parent.join("root-a")).expect("open via parent alias");
        assert!(
            backends[0].version_lock.shares_local_mutex_with(&aliased.version_lock),
            "symlink-parent alias to same canonical root must share the same mutex"
        );
    }

    assert!(RootVersionLock::registry_contains(&canonical_a));
    drop(backends);
    // Opening root_b triggers pruning of dead weak entries (canonical_a).
    let _reopen_b = FsBackend::open(&root_b).expect("reopen root_b to trigger prune");
    assert!(
        !RootVersionLock::registry_contains(&canonical_a),
        "dead canonical root entry must be pruned after last backend drops"
    );
    assert!(RootVersionLock::registry_contains(&canonical_b));
    drop(_reopen_b);
    drop(backend_b);
    let _ = std::fs::remove_dir_all(base);
}

/// Negative — dropping a queued lock waiter after observing real `WouldBlock` must cancel without
/// acquiring the lock or executing any mutation after the holder releases.
#[tokio::test]
async fn n_queued_os_lock_cancellation_exits_without_acquiring_or_mutating() {
    let (root, backend) = backend_with_bucket("queued-cancel");
    let lock_path = backend.version_lock.lock_path().to_path_buf();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open sentinel");
    holder.lock().expect("hold external OS lock");

    let observer = crate::root_lock::test_hooks::WouldBlockObserver::install(lock_path.clone());
    let mutated = Arc::new(AtomicBool::new(false));
    let mut fut = Box::pin({
        let backend = Arc::clone(&backend);
        let mutated = Arc::clone(&mutated);
        async move {
            let _guard = backend.version_lock.lock().await?;
            mutated.store(true, Ordering::SeqCst);
            Ok::<(), rustfs_gateway::HandlerError>(())
        }
    });

    for _ in 0..500 {
        let mut cx = Context::from_waker(Waker::noop());
        if Pin::as_mut(&mut fut).poll(&mut cx).is_ready() || observer.count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(observer.count() > 0, "queued waiter must observe real OS WouldBlock contention");
    // Drop the waiter while external OS lock is still held.
    drop(fut);
    tokio::time::sleep(Duration::from_millis(30)).await;
    drop(holder);
    tokio::time::sleep(Duration::from_millis(30)).await;

    assert!(
        !mutated.load(Ordering::SeqCst),
        "cancelled queued waiter must never run its mutation after lock release"
    );
    // Lock must be freely acquirable by a successor.
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("reopen sentinel");
    probe.try_lock().expect("cancelled waiter must not leave OS lock held");
    drop(probe);
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — once a blocking filesystem critical section starts inside `run_blocking`, aborting
/// the async waiter must NOT release the OS file lock until the blocking worker finishes.
#[tokio::test]
async fn n_started_blocking_mutation_retains_os_lock_until_completion_after_future_drop() {
    struct ReleaseOnDrop(Arc<AtomicBool>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let (root, backend) = backend_with_bucket("started-cancel");
    let lock_path = backend.version_lock.lock_path().to_path_buf();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let _release_guard = ReleaseOnDrop(Arc::clone(&release));

    let guard = backend.version_lock.lock().await.expect("acquire root lock");
    let worker = tokio::spawn({
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        async move {
            let _ = guard
                .run_blocking(move || {
                    entered.store(true, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Ok(())
                })
                .await;
        }
    });

    for _ in 0..500 {
        if entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(entered.load(Ordering::SeqCst), "blocking worker entered critical section");

    // Abort the async task while the blocking worker is still running.
    worker.abort();
    let _ = worker.await;
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Independent probe on the same sentinel must still see WouldBlock!
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open sentinel probe");
    assert!(
        matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "OS lock must remain held while blocking worker is still active after async abort"
    );

    release.store(true, Ordering::SeqCst);
    let mut unlocked = false;
    for _ in 0..200 {
        if probe.try_lock().is_ok() {
            unlocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(unlocked, "OS lock must be released once blocking worker finishes");
    drop(probe);
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — an unreleasing external OS lock must fail closed after the bounded wait timeout
/// rather than hanging indefinitely or proceeding unprotected.
#[tokio::test]
async fn n_os_lock_wait_timeout_fails_closed_when_external_holder_does_not_release() {
    let root = std::env::temp_dir().join(format!("rustfs-gateway-fs-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create root");
    let canonical = std::fs::canonicalize(&root).expect("canonical");
    let lock = RootVersionLock::for_canonical_root(canonical).with_wait_timeout(Duration::from_millis(40));

    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock.lock_path())
        .expect("open sentinel");
    holder.lock().expect("hold external OS lock");

    let err = lock.lock().await.err().expect("contended lock must time out and fail closed");
    assert_eq!(err.code(), &ErrorCode::INTERNAL_ERROR);
    drop(holder);
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — when a post-rename fault leaves two `null` versions on disk and the stale older
/// directory iterates first, explicit `versionId=null` read must return the newest bytes and
/// deleting `versionId=null` must not resurrect the stale older null.
#[tokio::test]
async fn n_duplicate_null_explicit_read_and_delete_select_newest_without_resurrecting_stale() {
    let (root, backend) = backend_with_bucket("dup-null-read-delete");
    let mut old = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"old-stale"),
            Some(&etag(b"old-stale").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old null")
        .path;
    let new = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"new-fresh"),
            Some(&etag(b"new-fresh").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("new null")
        .path;
    force_old_before_new_in_read_dir(&backend.versions_path("racing"), &mut old, &new);

    let unversioned = backend
        .representation("racing", "object", None)
        .await
        .expect("unversioned read");
    assert_eq!(unversioned.bytes, b"new-fresh");

    let explicit = backend
        .representation("racing", "object", Some("null"))
        .await
        .expect("explicit null read");
    assert_eq!(explicit.bytes, b"new-fresh", "explicit versionId=null must select newest null");

    backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect("explicit null delete succeeds");

    let after_unversioned = backend.representation("racing", "object", None).await;
    assert_eq!(
        after_unversioned.err().map(|e| e.code().clone()),
        Some(ErrorCode::NO_SUCH_KEY),
        "deleting newest null must not resurrect stale older null"
    );
    let after_explicit = backend.representation("racing", "object", Some("null")).await;
    assert_eq!(
        after_explicit.err().map(|e| e.code().clone()),
        Some(ErrorCode::NO_SUCH_KEY),
        "explicit versionId=null must stay absent after delete"
    );
    assert!(backend.version_records("racing").await.expect("records").is_empty());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — direct explicit `versionId=null` deletion without a prior read must retire any
/// superseded unprotected null so the stale older object cannot resurface.
#[tokio::test]
async fn n_duplicate_null_direct_explicit_delete_cleans_stale_null_without_resurrection() {
    let (root, backend) = backend_with_bucket("dup-null-direct-delete");
    let mut old = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"stale-v1"),
            Some(&etag(b"stale-v1").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old null")
        .path;
    let new = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"fresh-v2"),
            Some(&etag(b"fresh-v2").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("new null")
        .path;
    force_old_before_new_in_read_dir(&backend.versions_path("racing"), &mut old, &new);

    backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect("direct explicit null delete");

    assert_eq!(
        backend
            .representation("racing", "object", None)
            .await
            .err()
            .map(|e| e.code().clone()),
        Some(ErrorCode::NO_SUCH_KEY),
        "direct explicit delete must not resurrect older null"
    );
    assert!(backend.version_records("racing").await.expect("records").is_empty());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — if a fault leaves two `null` versions and the older one carries active protection,
/// recovery must fail closed with `AccessDenied` and leave both records intact.
#[tokio::test]
async fn n_duplicate_null_with_protected_stale_version_fails_closed_without_deleting_either() {
    let (root, backend) = backend_with_bucket("dup-null-protected");
    let old = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"protected-old"),
            Some(&etag(b"protected-old").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old null");
    let old_record_path = old.path.join(RECORD_FILE);
    let mut encoded = std::fs::read_to_string(&old_record_path).expect("old record");
    encoded.push_str("lock/1 1\nCOMPLIANCE 4102444800 ON\n");
    std::fs::write(&old_record_path, encoded).expect("protect old null");

    let new = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"unprotected-new"),
            Some(&etag(b"unprotected-new").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("new null");

    let del_err = backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect_err("explicit null delete must fail closed when stale null is protected");
    assert_eq!(del_err.code(), &ErrorCode::ACCESS_DENIED);
    assert!(old.path.join(BODY_FILE).exists(), "protected older null must remain");
    assert!(new.path.join(BODY_FILE).exists(), "newer null must remain when cleanup fails closed");

    let put_err = backend
        .publish_object("racing", "object", b"third", &etag(b"third").expect("tag"), &ObjectAttributes::default())
        .await
        .err()
        .expect("subsequent write must also refuse protected duplicate null");
    assert_eq!(put_err.code(), &ErrorCode::ACCESS_DENIED);

    let read_err = backend
        .representation("racing", "object", Some("null"))
        .await
        .err()
        .expect("explicit null read must fail closed when stale null is protected");
    assert_eq!(read_err.code(), &ErrorCode::ACCESS_DENIED);
    assert!(old.path.join(BODY_FILE).exists());
    assert!(new.path.join(BODY_FILE).exists());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — when removing a superseded stale null directory repeatedly fails, explicit null
/// delete must fail closed without deleting the newest null; once the fault clears, recovery
/// deletes both cleanly with zero resurrection.
#[tokio::test]
async fn n_duplicate_null_removal_error_fails_closed_without_deleting_newest_and_recovers() {
    let (root, backend) = backend_with_bucket("dup-null-rm-fail");
    let old = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"stale"),
            Some(&etag(b"stale").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old null");
    let new = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"fresh"),
            Some(&etag(b"fresh").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("new null");
    std::fs::write(new.path.join(SUPERSEDES_NULL_FILE), "supersedes-null/1\n").expect("write intent");

    null_recovery::test_hooks::fail_next_remove_of(old.path.clone());
    let err = backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect_err("persistent stale-null removal error must fail closed");
    assert_eq!(err.code(), &ErrorCode::INTERNAL_ERROR);
    assert!(new.path.join(BODY_FILE).exists(), "newest null must not be deleted while stale remains");
    assert!(new.path.join(SUPERSEDES_NULL_FILE).exists(), "cleanup intent must persist after fault");

    // Once the fault clears, deleting explicit null cleans both cleanly.
    backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect("explicit null delete recovers once fault clears");
    assert!(backend.version_records("racing").await.expect("records").is_empty());
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — an orphaned `.tmp-*` staging directory left by `SIGKILL` beside committed versions
/// must not brick reads, listings, or writes, while a symlinked `.tmp-*` still fails closed.
#[tokio::test]
async fn n_orphaned_tmp_staging_dir_does_not_brick_committed_versions() {
    let (root, backend) = backend_with_bucket("sigkill-tmp-committed");
    backend
        .publish_object(
            "racing",
            "committed",
            b"durable-bytes",
            &etag(b"durable-bytes").expect("tag"),
            &ObjectAttributes::default(),
        )
        .await
        .expect("publish committed object");

    let orphan = backend.versions_path("racing").join(".tmp-777777-1");
    std::fs::create_dir(&orphan).expect("create orphan .tmp-* dir");
    std::fs::write(orphan.join(BODY_FILE), b"half").expect("partial body");
    std::fs::write(orphan.join(RECORD_FILE), b"corrupt-partial-record").expect("corrupt partial record");

    let read = backend
        .representation("racing", "committed", None)
        .await
        .expect("committed version must stay readable beside orphaned .tmp-*");
    assert_eq!(read.bytes, b"durable-bytes");
    let listed = backend
        .current_object_records("racing")
        .await
        .expect("listing must skip orphaned .tmp-*");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, "committed");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = std::env::temp_dir().join(format!("rustfs-gateway-fs-orphan-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).expect("outside dir");
        symlink(&outside, backend.versions_path("racing").join(".tmp-777777-2")).expect("symlink");
        let err = backend
            .version_records("racing")
            .await
            .err()
            .expect("symlinked .tmp-* must fail closed");
        assert_eq!(err.code(), &ErrorCode::INVALID_REQUEST);
        let _ = std::fs::remove_dir_all(outside);
    }
    let _ = std::fs::remove_dir_all(root);
}

async fn prepare_single_part_completion(
    backend: &FsBackend,
    key_str: &str,
    body: &[u8],
) -> (String, impl Fn() -> dto::CompleteMultipartUploadInput) {
    let bucket = BucketName::new("racing").expect("bucket");
    let key = ObjectKey::new(key_str).expect("key");
    let upload_id = backend
        .create_upload_locked(&bucket, &key, None, &ObjectAttributes::default())
        .await
        .expect("create upload");
    backend.store_part("racing", &upload_id, 1, body).await.expect("store part");
    let part_etag = etag(body).expect("part etag");
    let upload_id_clone = upload_id.clone();
    let make_input = move || dto::CompleteMultipartUploadInput {
        bucket: bucket.clone(),
        key: key.clone(),
        upload_id: UploadIdClaim::from_wire(upload_id_clone.clone()),
        multipart_upload: dto::CompletedMultipartUpload {
            parts: vec![dto::CompletedPart {
                e_tag: Some(part_etag.clone()),
                part_number: 1,
                ..dto::CompletedPart::default()
            }],
        },
        ..dto::CompleteMultipartUploadInput::default()
    };
    (upload_id, make_input)
}

/// Negative — cancelling `CompleteMultipartUpload` right after version rename commit must still
/// allow a retry to replay the committed object without publishing a duplicate version.
#[tokio::test]
async fn n_cancelled_post_rename_multipart_completion_still_replays_without_duplicate_version() {
    let (root, backend) = backend_with_bucket("mpu-post-rename-replay");
    let (upload_id, make_input) = prepare_single_part_completion(&backend, "replayed", b"assembled-payload").await;

    let entered = Arc::new(AtomicBool::new(false));
    let mut fut = Box::pin(super::super::staging::test_hooks::pause_at(
        "complete_remove",
        Arc::clone(&entered),
        Handler::<dto::CompleteMultipartUpload>::call(backend.as_ref(), Req::new(make_input(), sse_proof())),
    ));
    for _ in 0..4096 {
        let mut cx = Context::from_waker(Waker::noop());
        if Pin::as_mut(&mut fut).poll(&mut cx).is_ready() || entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(entered.load(Ordering::SeqCst), "completion did not reach post-rename pause");
    drop(fut);

    assert!(
        backend.read_upload_record("racing", &upload_id).is_none(),
        "post-rename cancellation must never restore the committed upload"
    );

    let replayed = Handler::<dto::CompleteMultipartUpload>::call(backend.as_ref(), Req::new(make_input(), sse_proof()))
        .await
        .expect("retry after post-rename cancellation must replay the committed object");
    assert_eq!(replayed.status(), 200);
    assert_eq!(
        backend.version_records("racing").await.expect("records").len(),
        1,
        "replay must not publish a second version"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Negative — if post-rename null cleanup fails during `CompleteMultipartUpload`, the upload must
/// NOT be restored; once the fault clears, a retry reconciles the stale null and replays the
/// committed object without minting another version.
#[tokio::test]
async fn n_multipart_completion_post_rename_cleanup_error_keeps_upload_retired_and_replays() {
    let (root, backend) = backend_with_bucket("mpu-post-rename-cleanup-err");
    let old = backend
        .publish_version(
            "racing",
            "replayed",
            Some("null"),
            Some(b"old-null"),
            Some(&etag(b"old-null").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old null");

    let body = b"multipart-replacement";
    let (upload_id, make_input) = prepare_single_part_completion(&backend, "replayed", body).await;

    null_recovery::test_hooks::fail_next_remove_of(old.path.clone());
    let first = Handler::<dto::CompleteMultipartUpload>::call(backend.as_ref(), Req::new(make_input(), sse_proof())).await;
    assert_eq!(
        first.err().map(|e| e.code().clone()),
        Some(ErrorCode::INTERNAL_ERROR),
        "injected post-rename cleanup fault must surface InternalError"
    );
    assert!(
        backend.read_upload_record("racing", &upload_id).is_none(),
        "post-rename cleanup fault must NEVER restore the retired upload"
    );

    // Retry once the transient fault clears: must reconcile old null and replay the new version.
    let replayed = Handler::<dto::CompleteMultipartUpload>::call(backend.as_ref(), Req::new(make_input(), sse_proof()))
        .await
        .expect("retry after post-rename cleanup fault must reconcile and replay");
    assert_eq!(replayed.status(), 200);
    let records = backend.version_records("racing").await.expect("records");
    assert_eq!(records.len(), 1, "stale null must be retired and no duplicate version published");
    assert_eq!(
        backend
            .representation("racing", "replayed", Some("null"))
            .await
            .expect("read")
            .bytes,
        body
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Positive — obstructing the staged `completion` receipt still allows completion to succeed
/// (preserving best-effort receipt semantics) and causes a subsequent retry to return `NoSuchUpload`.
#[tokio::test]
async fn multipart_completion_receipt_obstruction_stays_best_effort() {
    let (root, backend) = backend_with_bucket("mpu-receipt-best-effort");
    let body = b"still-committed";
    let (_upload_id, make_input) = prepare_single_part_completion(&backend, "best-effort", body).await;

    let first = OBSTRUCT_COMPLETION_RECEIPT
        .scope(
            (),
            Handler::<dto::CompleteMultipartUpload>::call(backend.as_ref(), Req::new(make_input(), sse_proof())),
        )
        .await
        .expect("obstructed completion receipt must not fail completion");
    assert_eq!(first.status(), 200);
    assert_eq!(
        backend
            .representation("racing", "best-effort", None)
            .await
            .expect("read")
            .bytes,
        body
    );

    let retry = Handler::<dto::CompleteMultipartUpload>::call(backend.as_ref(), Req::new(make_input(), sse_proof())).await;
    assert_eq!(
        retry.err().map(|e| e.code().clone()),
        Some(ErrorCode::NO_SUCH_UPLOAD),
        "without a receipt, retry returns NoSuchUpload"
    );
    let _ = std::fs::remove_dir_all(root);
}

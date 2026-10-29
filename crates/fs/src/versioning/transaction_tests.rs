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

//! Cross-process evidence for version deletion versus a protection-record update.
//!
//! Responsible for: observing the real backend deletion and its process-lock boundary.
//! NOT responsible for: a public protection update API or enabling Object Lock.
//! Upstream: version storage tests; downstream: independently observed child results.

use super::*;

/// Child executes the real exact-version deletion, not a modeled decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_delete_child_probe() {
    let Some(root) = std::env::var_os("GATEWAY_TEST_TRANSACTION_ROOT") else {
        eprintln!("skip: transaction probe has no parent fixture");
        return;
    };
    let result_path = std::env::var_os("GATEWAY_TEST_TRANSACTION_RESULT").expect("result path");
    let backend = FsBackend::open(root).expect("open backend");
    if std::env::var_os("GATEWAY_TEST_TRANSACTION_ABORT_QUEUED").is_some() {
        let busy = std::env::var_os("GATEWAY_TEST_TRANSACTION_BUSY").expect("busy path");
        let stopped = std::env::var_os("GATEWAY_TEST_TRANSACTION_STOPPED").expect("stopped path");
        let request = tokio::spawn(async move { backend.delete_object_version("racing", "object", Some("v1")).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&busy).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("deletion must contend");
        request.abort();
        assert!(request.await.expect_err("request was aborted").is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&stopped).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("queued lock worker must stop");
        std::fs::write(result_path, "cancelled").expect("report cancellation");
        return;
    }
    if std::env::var_os("GATEWAY_TEST_TRANSACTION_ABORT_STARTED").is_some() {
        let ready = std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_READY").expect("ready path");
        let release = std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE").expect("release path");
        let aborted = std::env::var_os("GATEWAY_TEST_TRANSACTION_ABORTED").expect("aborted path");
        let backend = std::sync::Arc::new(backend);
        let request_backend = std::sync::Arc::clone(&backend);
        let request = tokio::spawn(async move { request_backend.delete_object_version("racing", "object", Some("v1")).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&ready).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("real removal worker must start");
        request.abort();
        assert!(request.await.expect_err("request was aborted").is_cancelled());
        assert!(backend.version_lock.try_lock().is_err(), "started worker must retain local version lock");
        std::fs::write(aborted, "aborted").expect("report abort");
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !std::path::Path::new(&release).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("release removal");
        return;
    }
    let outcome = backend.delete_object_version("racing", "object", Some("v1")).await;
    let result = match outcome {
        Ok(_) => "deleted",
        Err(error) if error.code() == &ErrorCode::ACCESS_DENIED => "protected",
        Err(error) => panic!("unexpected deletion result: {error:?}"),
    };
    std::fs::write(result_path, result).expect("report actual deletion");
}

/// A cooperating protection updater holds the cross-process boundary until its record is published.
async fn deletion_cannot_pass_an_inflight_protection_update() {
    let (root, backend) = backend_with_bucket("transaction-protection");
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
        .expect("create version");
    let lock_path = root.join(".gateway-version-transaction.lock");
    let busy = root.join("transaction-busy");
    let result = root.join("transaction-result");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .expect("create transaction lock");
    held.lock().expect("hold transaction lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::transaction_tests::transaction_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_TRANSACTION_ROOT", &root)
        .env("GATEWAY_TEST_TRANSACTION_RESULT", &result)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("start deletion");
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let before = std::fs::read_to_string(&result).ok();
    let update = std::fs::OpenOptions::new()
        .append(true)
        .open(record.path.join(RECORD_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"lock/1 1\nCOMPLIANCE 4102444800 ON\n"));
    drop(held);
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    if status.is_err() {
        child.kill().expect("stop child");
        child.wait().expect("reap child");
    }
    assert!(reached.is_ok(), "child must report contention or finish");
    assert!(before.is_none(), "deletion finished before protection publication: {before:?}");
    assert!(busy.exists(), "deletion must observe actual process lock contention");
    assert!(update.is_ok(), "protection update must find the version");
    assert!(status.expect("child completes").success());
    assert_eq!(std::fs::read_to_string(result).expect("deletion result"), "protected");
    assert!(record.path.exists(), "protected version remains");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// An unprotected version is deleted after the contended process lock is released.
async fn unprotected_deletion_completes_after_the_boundary_is_released() {
    let (root, backend) = backend_with_bucket("transaction-unprotected");
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
        .expect("create version");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(".gateway-version-transaction.lock"))
        .expect("create transaction lock");
    lock.lock().expect("hold transaction lock");
    let busy = root.join("unprotected-busy");
    let result = root.join("unprotected-result");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::transaction_tests::transaction_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_TRANSACTION_ROOT", &root)
        .env("GATEWAY_TEST_TRANSACTION_RESULT", &result)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("start deletion");
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let early = result.exists();
    drop(lock);
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    if status.is_err() {
        child.kill().expect("stop child");
        child.wait().expect("reap child");
    }
    assert!(reached.is_ok(), "deletion must contend or finish");
    assert!(!early, "unprotected deletion must wait until lock release");
    assert!(busy.exists(), "deletion must observe actual contention");
    assert!(status.expect("child completes").success());
    assert_eq!(std::fs::read_to_string(result).expect("deletion result"), "deleted");
    assert!(!record.path.exists(), "unprotected version must be removed");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Cancelling a genuinely contended deletion must stop its waiter without removing the version.
async fn cancelled_queued_deletion_does_not_remove_the_version() {
    let (root, backend) = backend_with_bucket("transaction-queued-cancel");
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
        .expect("create version");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(".gateway-version-transaction.lock"))
        .expect("create transaction lock");
    lock.lock().expect("hold transaction lock");
    let busy = root.join("queued-busy");
    let stopped = root.join("queued-stopped");
    let result = root.join("queued-result");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::transaction_tests::transaction_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_TRANSACTION_ROOT", &root)
        .env("GATEWAY_TEST_TRANSACTION_RESULT", &result)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .env("GATEWAY_TEST_TRANSACTION_STOPPED", &stopped)
        .env("GATEWAY_TEST_TRANSACTION_ABORT_QUEUED", "1")
        .spawn()
        .expect("start deletion");
    let status = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    if status.is_err() {
        child.kill().expect("stop child");
        child.wait().expect("reap child");
    }
    assert!(record.path.exists(), "queued cancellation must retain the version");
    assert!(status.expect("child exits with lock still held").success());
    assert!(busy.exists(), "deletion must observe actual contention");
    assert!(stopped.exists(), "queued lock worker must exit before release");
    assert_eq!(std::fs::read_to_string(result).expect("cancellation result"), "cancelled");
    drop(lock);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// An active removal retains the process lock when its awaiting request is cancelled.
async fn started_deletion_keeps_the_boundary_after_request_cancellation() {
    let (root, backend) = backend_with_bucket("transaction-started-cancel");
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
        .expect("create version");
    let ready = root.join("remove-ready");
    let release = root.join("remove-release");
    let aborted = root.join("remove-aborted");
    let busy = root.join("remove-busy");
    let result = root.join("remove-result");
    let launch = || {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "versioning::tests::transaction_tests::transaction_delete_child_probe",
                "--nocapture",
            ])
            .env("GATEWAY_TEST_TRANSACTION_ROOT", &root)
            .env("GATEWAY_TEST_TRANSACTION_RESULT", &result);
        command
    };
    let mut owner = launch()
        .env("GATEWAY_TEST_TRANSACTION_ABORT_STARTED", "1")
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_READY", &ready)
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE", &release)
        .env("GATEWAY_TEST_TRANSACTION_ABORTED", &aborted)
        .spawn()
        .expect("start owner");
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !aborted.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let mut successor = launch()
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("start successor");
    let contended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let early = result.exists();
    let retained_before_release = record.path.exists();
    std::fs::write(&release, "release").expect("release deletion");
    let mut statuses = Vec::new();
    for child in [&mut owner, &mut successor] {
        let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.try_wait().expect("poll child") {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        if status.is_err() {
            child.kill().expect("stop child");
            child.wait().expect("reap child");
        }
        statuses.push(status.expect("child completes"));
    }
    assert!(retained_before_release, "version must remain while the removal worker is held");
    assert!(cancelled.is_ok(), "owner request must be cancelled after removal starts");
    assert!(statuses.iter().all(|status| status.success()), "children must complete");
    assert!(contended.is_ok() && busy.exists(), "successor must observe real contention");
    assert!(!early, "successor must not finish while removal worker is held");
    assert!(!record.path.exists(), "started removal must complete after release");
    assert_eq!(std::fs::read_to_string(result).expect("successor result"), "deleted");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Called by the dedicated integration harness after unrelated unit tests finish.
pub(super) async fn run_transaction_controls() {
    deletion_cannot_pass_an_inflight_protection_update().await;
    println!("completed: deletion_cannot_pass_an_inflight_protection_update");
    unprotected_deletion_completes_after_the_boundary_is_released().await;
    println!("completed: unprotected_deletion_completes_after_the_boundary_is_released");
    cancelled_queued_deletion_does_not_remove_the_version().await;
    println!("completed: cancelled_queued_deletion_does_not_remove_the_version");
    started_deletion_keeps_the_boundary_after_request_cancellation().await;
    println!("completed: started_deletion_keeps_the_boundary_after_request_cancellation");
}

/// The internal lock file is accepted by the actual lifecycle bucket census after deletion.
#[tokio::test]
async fn named_deletion_preserves_lifecycle_bucket_census() {
    let (root, backend) = backend_with_bucket("transaction-census");
    backend
        .delete_object_version("racing", "object", Some("missing"))
        .await
        .expect("delete missing named version");
    assert!(root.join(super::super::transaction::LOCK_FILE).is_file());
    assert_eq!(backend.lifecycle_buckets().await.expect("list lifecycle buckets"), vec!["racing"]);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// A non-file coordination path fails closed without deleting the actual version.
#[tokio::test]
async fn named_deletion_rejects_a_directory_lock_path() {
    let (root, backend) = backend_with_bucket("transaction-bad-lock");
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
        .expect("create version");
    std::fs::create_dir(root.join(super::super::transaction::LOCK_FILE)).expect("create conflicting lock path");
    assert!(backend.delete_object_version("racing", "object", Some("v1")).await.is_err());
    assert!(record.path.exists(), "failed acquisition must not delete version");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Explicit null deletion uses the transaction lock; implicit deletion still does not.
#[tokio::test]
async fn null_and_implicit_deletions_use_their_transaction_boundaries() {
    let (root, backend) = backend_with_bucket("transaction-null");
    backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect("delete null");
    assert!(root.join(super::super::transaction::LOCK_FILE).is_file());
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
    let (implicit_root, implicit_backend) = backend_with_bucket("transaction-implicit");
    implicit_backend
        .delete_object_version("racing", "object", None)
        .await
        .expect("delete current");
    assert!(!implicit_root.join(super::super::transaction::LOCK_FILE).exists());
    drop(implicit_backend);
    std::fs::remove_dir_all(implicit_root).expect("remove test root");
}

/// A symlink at the coordination path cannot redirect the named deletion lock.
#[cfg(unix)]
#[tokio::test]
async fn named_deletion_rejects_a_symlink_lock_path() {
    let (root, backend) = backend_with_bucket("transaction-symlink-lock");
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
        .expect("create version");
    let target = root.join("external-lock-target");
    std::fs::write(&target, "unchanged").expect("create target");
    std::os::unix::fs::symlink(&target, root.join(super::super::transaction::LOCK_FILE)).expect("create symlink");
    assert!(backend.delete_object_version("racing", "object", Some("v1")).await.is_err());
    assert!(record.path.exists());
    assert_eq!(std::fs::read_to_string(target).expect("read target"), "unchanged");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

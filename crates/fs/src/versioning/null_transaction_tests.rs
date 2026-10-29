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

//! Real-process controls for explicit null-version deletion.
//!
//! Responsible for: observing recorded and legacy null deletion under a cooperating root lock.
//! NOT responsible for: implicit deletion, publication, or production protection updates.
//! Upstream: the exact-version handler; downstream: real filesystem state and process locks.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn null_delete_child_probe() {
    let Some(root) = std::env::var_os("GATEWAY_TEST_NULL_ROOT") else {
        eprintln!("skip: null deletion probe has no parent fixture");
        return;
    };
    let result = std::env::var_os("GATEWAY_TEST_NULL_RESULT").expect("result path");
    let backend = FsBackend::open(root).expect("open backend");
    if std::env::var_os("GATEWAY_TEST_NULL_ABORT_QUEUED").is_some() {
        let busy = std::env::var_os("GATEWAY_TEST_TRANSACTION_BUSY").expect("busy path");
        let stopped = std::env::var_os("GATEWAY_TEST_TRANSACTION_STOPPED").expect("stopped path");
        let request = tokio::spawn(async move { backend.delete_object_version("racing", "object", Some("null")).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&busy).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("null deletion must contend");
        request.abort();
        assert!(request.await.expect_err("request was aborted").is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&stopped).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("queued worker must stop");
        std::fs::write(result, "cancelled").expect("report cancellation");
        return;
    }
    if std::env::var_os("GATEWAY_TEST_NULL_ABORT_STARTED").is_some() {
        let ready = std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_READY").expect("ready path");
        let release = std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE").expect("release path");
        let aborted = std::env::var_os("GATEWAY_TEST_NULL_ABORTED").expect("aborted path");
        let backend = std::sync::Arc::new(backend);
        let worker_backend = std::sync::Arc::clone(&backend);
        let request = tokio::spawn(async move { worker_backend.delete_object_version("racing", "object", Some("null")).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&ready).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("real null removal worker must start");
        request.abort();
        assert!(request.await.expect_err("request was aborted").is_cancelled());
        assert!(backend.version_lock.try_lock().is_err(), "null worker must retain local lock");
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
    let outcome = backend.delete_object_version("racing", "object", Some("null")).await;
    let result_value = match outcome {
        Ok(_) => "deleted",
        Err(error) if error.code() == &ErrorCode::ACCESS_DENIED => "protected",
        Err(error) => panic!("unexpected deletion result: {error:?}"),
    };
    std::fs::write(result, result_value).expect("report actual deletion result");
}

async fn observe_null_deletion(legacy: bool, protect: bool) {
    let (root, backend) = backend_with_bucket(if legacy {
        "null-legacy-contention"
    } else {
        "null-record-contention"
    });
    let path = if legacy {
        let path = backend.object_path("racing", "object");
        std::fs::write(&path, b"legacy").expect("write legacy object");
        path
    } else {
        backend
            .publish_version(
                "racing",
                "object",
                Some("null"),
                Some(b"old"),
                Some(&etag(b"old").expect("tag")),
                &ObjectAttributes::default(),
            )
            .await
            .expect("write null version")
            .path
    };
    let result = root.join("null-result");
    let busy = root.join("null-busy");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(super::super::transaction::LOCK_FILE))
        .expect("create lock");
    lock.lock().expect("hold lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::null_transaction_tests::null_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_NULL_ROOT", &root)
        .env("GATEWAY_TEST_NULL_RESULT", &result)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("spawn null deletion");
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let before = std::fs::read_to_string(&result).ok();
    let update = if protect {
        Some(
            std::fs::OpenOptions::new()
                .append(true)
                .open(path.join(RECORD_FILE))
                .and_then(|mut file| std::io::Write::write_all(&mut file, b"lock/1 1\nCOMPLIANCE 4102444800 ON\n")),
        )
    } else {
        None
    };
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
    assert!(reached.is_ok(), "null deletion must contend or finish");
    assert!(before.is_none(), "null deletion completed before lock release: {before:?}");
    assert!(busy.exists(), "null deletion must observe actual contention");
    if let Some(update) = update {
        assert!(update.is_ok(), "protection update must find the version");
    }
    assert!(status.expect("child completes").success());
    assert_eq!(
        std::fs::read_to_string(result).expect("result"),
        if protect { "protected" } else { "deleted" }
    );
    assert_eq!(path.exists(), protect, "actual null state follows the deletion verdict");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

async fn protected_null_record_waits_for_process_boundary() {
    observe_null_deletion(false, true).await;
}

async fn legacy_null_deletion_waits_for_process_boundary() {
    observe_null_deletion(true, false).await;
}

async fn observe_queued_cancellation(legacy: bool) {
    let (root, backend) = backend_with_bucket(if legacy { "null-legacy-queued" } else { "null-record-queued" });
    let path = if legacy {
        let path = backend.object_path("racing", "object");
        std::fs::write(&path, b"legacy").expect("write legacy object");
        path
    } else {
        backend
            .publish_version(
                "racing",
                "object",
                Some("null"),
                Some(b"old"),
                Some(&etag(b"old").expect("tag")),
                &ObjectAttributes::default(),
            )
            .await
            .expect("write null version")
            .path
    };
    let result = root.join("null-result");
    let busy = root.join("null-busy");
    let stopped = root.join("null-stopped");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(super::super::transaction::LOCK_FILE))
        .expect("create lock");
    lock.lock().expect("hold lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::null_transaction_tests::null_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_NULL_ROOT", &root)
        .env("GATEWAY_TEST_NULL_RESULT", &result)
        .env("GATEWAY_TEST_NULL_ABORT_QUEUED", "1")
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .env("GATEWAY_TEST_TRANSACTION_STOPPED", &stopped)
        .spawn()
        .expect("spawn null deletion");
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), async {
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
    assert!(path.exists(), "queued cancellation must retain the null object");
    assert!(status.expect("child exits with lock held").success());
    assert!(busy.exists(), "null deletion must observe actual contention");
    assert!(stopped.exists(), "queued worker must exit before release");
    assert_eq!(std::fs::read_to_string(result).expect("result"), "cancelled");
    drop(lock);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

async fn queued_null_record_cancellation_retains_version() {
    observe_queued_cancellation(false).await;
}

async fn queued_legacy_null_cancellation_retains_object() {
    observe_queued_cancellation(true).await;
}

async fn observe_started_cancellation(legacy: bool) {
    let (root, backend) = backend_with_bucket(if legacy {
        "null-legacy-started"
    } else {
        "null-record-started"
    });
    let path = if legacy {
        let path = backend.object_path("racing", "object");
        std::fs::write(&path, b"legacy").expect("write legacy object");
        path
    } else {
        backend
            .publish_version(
                "racing",
                "object",
                Some("null"),
                Some(b"old"),
                Some(&etag(b"old").expect("tag")),
                &ObjectAttributes::default(),
            )
            .await
            .expect("write null version")
            .path
    };
    let result = root.join("null-result");
    let ready = root.join("null-ready");
    let release = root.join("null-release");
    let aborted = root.join("null-aborted");
    let busy = root.join("null-busy");
    let mut owner = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::null_transaction_tests::null_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_NULL_ROOT", &root)
        .env("GATEWAY_TEST_NULL_RESULT", &result)
        .env("GATEWAY_TEST_NULL_ABORT_STARTED", "1")
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_READY", &ready)
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE", &release)
        .env("GATEWAY_TEST_NULL_ABORTED", &aborted)
        .spawn()
        .expect("spawn null owner");
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !aborted.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let mut successor = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::null_transaction_tests::null_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_NULL_ROOT", &root)
        .env("GATEWAY_TEST_NULL_RESULT", &result)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("spawn successor");
    let contended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let early = result.exists();
    let retained = path.exists();
    std::fs::write(&release, "release").expect("release null worker");
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
    assert!(retained, "null object must remain while removal worker is held");
    assert!(cancelled.is_ok(), "null request must abort after worker starts");
    assert!(statuses.iter().all(|status| status.success()), "children must complete");
    assert!(contended.is_ok() && busy.exists(), "successor must observe actual contention");
    assert!(!early, "successor must not finish before release");
    assert!(!path.exists(), "started null deletion completes after release");
    assert_eq!(std::fs::read_to_string(result).expect("result"), "deleted");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

async fn started_null_record_cancellation_retains_locks() {
    observe_started_cancellation(false).await;
}

async fn started_legacy_null_cancellation_retains_locks() {
    observe_started_cancellation(true).await;
}

/// An invalid transaction path refuses null deletion without touching the stored object.
#[tokio::test]
async fn null_deletion_rejects_a_directory_lock_path() {
    let (root, backend) = backend_with_bucket("null-invalid-lock");
    let record = backend
        .publish_version(
            "racing",
            "object",
            Some("null"),
            Some(b"old"),
            Some(&etag(b"old").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("write null version");
    std::fs::create_dir(root.join(super::super::transaction::LOCK_FILE)).expect("create conflicting lock directory");
    assert!(backend.delete_object_version("racing", "object", Some("null")).await.is_err());
    assert!(record.path.exists(), "failed acquisition must retain null version");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

/// The legacy fallback must reject an unsafe non-file path without removing it.
#[tokio::test]
async fn legacy_null_deletion_rejects_a_directory() {
    let (root, backend) = backend_with_bucket("null-invalid-legacy");
    let path = backend.object_path("racing", "object");
    std::fs::create_dir(&path).expect("create unsafe legacy object");
    let error = backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect_err("reject unsafe object");
    assert_eq!(error.code(), &ErrorCode::INVALID_REQUEST);
    assert!(path.is_dir(), "unsafe legacy path must remain");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

/// A real file removal failure releases both locks and reports an error.
#[tokio::test]
async fn legacy_null_removal_failure_releases_both_locks() {
    let (root, backend) = backend_with_bucket("null-legacy-removal-error");
    let path = backend.object_path("racing", "object");
    let process = super::super::transaction::root_guard(&root).await.expect("process guard");
    let local = backend.version_lock.clone().lock_owned().await;
    let result = super::super::transaction::remove_legacy_file(process, local, &path).await;
    assert!(result.is_err(), "missing file removal must report failure");
    let independent = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(super::super::transaction::LOCK_FILE))
        .expect("open independent lock");
    assert!(independent.try_lock().is_ok(), "process lock must be released after failure");
    assert!(backend.version_lock.try_lock().is_ok(), "local lock must be released after failure");
    drop(independent);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

/// Empty legacy objects are deleted as files, not mistaken for missing objects.
#[tokio::test]
async fn legacy_null_deletion_removes_an_empty_file() {
    let (root, backend) = backend_with_bucket("null-empty-legacy");
    let path = backend.object_path("racing", "object");
    std::fs::write(&path, b"").expect("write empty legacy object");
    backend
        .delete_object_version("racing", "object", Some("null"))
        .await
        .expect("delete null");
    assert!(!path.exists(), "empty legacy object must be removed");
    assert!(
        root.join(super::super::transaction::LOCK_FILE).is_file(),
        "null deletion must acquire the root lock"
    );
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

/// Called by the dedicated integration harness after unrelated unit tests finish.
pub(super) async fn run_null_controls() {
    protected_null_record_waits_for_process_boundary().await;
    println!("completed: protected_null_record_waits_for_process_boundary");
    legacy_null_deletion_waits_for_process_boundary().await;
    println!("completed: legacy_null_deletion_waits_for_process_boundary");
    queued_null_record_cancellation_retains_version().await;
    println!("completed: queued_null_record_cancellation_retains_version");
    queued_legacy_null_cancellation_retains_object().await;
    println!("completed: queued_legacy_null_cancellation_retains_object");
    started_null_record_cancellation_retains_locks().await;
    println!("completed: started_null_record_cancellation_retains_locks");
    started_legacy_null_cancellation_retains_locks().await;
    println!("completed: started_legacy_null_cancellation_retains_locks");
}

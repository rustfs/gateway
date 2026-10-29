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

//! Real-process controls for lifecycle deletion and a cooperating protection update.
//!
//! Responsible for: observing the actual historical-version expiration path.
//! NOT responsible for: public Object Lock operations or non-cooperating writers.
//! Upstream: private lifecycle entry points; downstream: the filesystem and process locks.

use super::*;

struct FileClock(std::path::PathBuf);

impl rustfs_gateway::Clock for FileClock {
    fn now(&self) -> rustfs_gateway::RequestNow {
        let seconds = std::fs::read_to_string(&self.0)
            .expect("read clock")
            .parse()
            .expect("clock seconds");
        rustfs_gateway::RequestNow::from_unix_seconds(seconds)
    }
}

fn rules() -> [dto::LifecycleRule; 1] {
    [dto::LifecycleRule {
        status: dto::Status::ENABLED,
        prefix: Some(String::new()),
        noncurrent_version_expiration: Some(dto::NoncurrentVersionExpiration {
            noncurrent_days: Some(1),
            ..Default::default()
        }),
        ..Default::default()
    }]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_child_probe() {
    let Some(root) = std::env::var_os("GATEWAY_TEST_LIFECYCLE_ROOT") else {
        eprintln!("skip: lifecycle process probe has no parent fixture");
        return;
    };
    let result = std::env::var_os("GATEWAY_TEST_LIFECYCLE_RESULT").expect("result path");
    let record = std::env::var_os("GATEWAY_TEST_LIFECYCLE_RECORD").expect("record path");
    let backend = if let Some(clock_path) = std::env::var_os("GATEWAY_TEST_LIFECYCLE_CLOCK") {
        FsBackend::open_with_clock(root, std::sync::Arc::new(FileClock(clock_path.into()))).expect("open backend")
    } else {
        FsBackend::open(root).expect("open backend")
    };
    let candidates = backend
        .expiring_version_candidates("racing", &rules(), 4102444700)
        .await
        .expect("candidates");
    let expected = if std::env::var_os("GATEWAY_TEST_LIFECYCLE_TWO").is_some() {
        2
    } else {
        1
    };
    assert_eq!(candidates.len(), expected, "the real old versions must be selected");
    if std::env::var_os("GATEWAY_TEST_LIFECYCLE_ABORT_QUEUED").is_some() {
        let busy = std::env::var_os("GATEWAY_TEST_TRANSACTION_BUSY").expect("busy path");
        let stopped = std::env::var_os("GATEWAY_TEST_TRANSACTION_STOPPED").expect("stopped path");
        let request = tokio::spawn(async move {
            backend
                .expire_selected_versions("racing", &rules(), &candidates, 4102444700)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&busy).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("lifecycle must contend");
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
    if std::env::var_os("GATEWAY_TEST_LIFECYCLE_ABORT_STARTED").is_some() {
        let ready = std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_READY").expect("ready path");
        let release = std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE").expect("release path");
        let aborted = std::env::var_os("GATEWAY_TEST_LIFECYCLE_ABORTED").expect("aborted path");
        let backend = std::sync::Arc::new(backend);
        let worker_backend = std::sync::Arc::clone(&backend);
        let request = tokio::spawn(async move {
            worker_backend
                .expire_selected_versions("racing", &rules(), &candidates, 4102444700)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&ready).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("real lifecycle removal worker must start");
        request.abort();
        assert!(request.await.expect_err("request was aborted").is_cancelled());
        assert!(
            backend.version_lock.try_lock().is_err(),
            "lifecycle worker must retain local version lock"
        );
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
    backend
        .expire_selected_versions("racing", &rules(), &candidates, 4102444700)
        .await
        .expect("expire versions");
    std::fs::write(
        result,
        if std::path::Path::new(&record).exists() {
            "retained"
        } else {
            "removed"
        },
    )
    .expect("report actual version state");
}

async fn lifecycle_does_not_pass_an_inflight_protection_update() {
    let (root, backend) = backend_with_bucket("lifecycle-transaction-protection");
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
        .expect("new version");
    let busy = root.join("lifecycle-busy");
    let result = root.join("lifecycle-result");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(super::super::transaction::LOCK_FILE))
        .expect("open lock");
    lock.lock().expect("hold lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::lifecycle_transaction_tests::lifecycle_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_LIFECYCLE_ROOT", &root)
        .env("GATEWAY_TEST_LIFECYCLE_RESULT", &result)
        .env("GATEWAY_TEST_LIFECYCLE_RECORD", &old.path)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("spawn lifecycle process");
    let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let before = std::fs::read_to_string(&result).ok();
    let update = std::fs::OpenOptions::new()
        .append(true)
        .open(old.path.join(RECORD_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"lock/1 1\nCOMPLIANCE 4102444800 ON\n"));
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
    assert!(reached.is_ok(), "lifecycle must contend or finish");
    assert!(before.is_none(), "lifecycle finished before protection publication: {before:?}");
    assert!(busy.exists(), "lifecycle must observe actual lock contention");
    assert!(update.is_ok(), "protection update must find the version");
    assert!(status.expect("child completes").success());
    assert_eq!(std::fs::read_to_string(result).expect("lifecycle result"), "retained");
    assert!(old.path.exists(), "protected historical version remains");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

async fn unprotected_lifecycle_waits_then_removes_the_selected_version() {
    let (root, backend) = backend_with_bucket("lifecycle-transaction-release");
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
        .expect("new version");
    let busy = root.join("lifecycle-busy");
    let result = root.join("lifecycle-result");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(super::super::transaction::LOCK_FILE))
        .expect("open lock");
    lock.lock().expect("hold lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::lifecycle_transaction_tests::lifecycle_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_LIFECYCLE_ROOT", &root)
        .env("GATEWAY_TEST_LIFECYCLE_RESULT", &result)
        .env("GATEWAY_TEST_LIFECYCLE_RECORD", &old.path)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("spawn lifecycle process");
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
    assert!(reached.is_ok(), "lifecycle must contend or finish");
    assert!(!early, "lifecycle must wait until release");
    assert!(busy.exists(), "lifecycle must observe actual contention");
    assert!(status.expect("child completes").success());
    assert_eq!(std::fs::read_to_string(result).expect("lifecycle result"), "removed");
    assert!(!old.path.exists(), "unprotected historical version is removed");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

async fn cancelled_queued_lifecycle_retains_the_version() {
    let (root, backend) = backend_with_bucket("lifecycle-transaction-queued");
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
        .expect("new version");
    let busy = root.join("lifecycle-busy");
    let stopped = root.join("lifecycle-stopped");
    let result = root.join("lifecycle-result");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.join(super::super::transaction::LOCK_FILE))
        .expect("open lock");
    lock.lock().expect("hold lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::lifecycle_transaction_tests::lifecycle_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_LIFECYCLE_ROOT", &root)
        .env("GATEWAY_TEST_LIFECYCLE_RESULT", &result)
        .env("GATEWAY_TEST_LIFECYCLE_RECORD", &old.path)
        .env("GATEWAY_TEST_LIFECYCLE_ABORT_QUEUED", "1")
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .env("GATEWAY_TEST_TRANSACTION_STOPPED", &stopped)
        .spawn()
        .expect("spawn lifecycle process");
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
    assert!(old.path.exists(), "queued cancellation must retain historical version");
    assert!(status.expect("child exits while lock is held").success());
    assert!(busy.exists(), "lifecycle must observe actual contention");
    assert!(stopped.exists(), "queued worker must exit before release");
    assert_eq!(std::fs::read_to_string(result).expect("result"), "cancelled");
    drop(lock);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

async fn started_lifecycle_retains_both_locks_after_cancellation() {
    let (root, backend) = backend_with_bucket("lifecycle-transaction-started");
    let old = backend
        .publish_version(
            "racing",
            "object",
            Some("v2"),
            Some(b"old"),
            Some(&etag(b"old").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old version");
    let newer_old = backend
        .publish_version(
            "racing",
            "object",
            Some("v3"),
            Some(b"new"),
            Some(&etag(b"new").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("second historical version");
    backend
        .publish_version(
            "racing",
            "object",
            Some("v4"),
            Some(b"current"),
            Some(&etag(b"current").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("current version");
    let ready = root.join("lifecycle-ready");
    let release = root.join("lifecycle-release");
    let aborted = root.join("lifecycle-aborted");
    let busy = root.join("lifecycle-busy");
    let result = root.join("lifecycle-result");
    let mut owner = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::lifecycle_transaction_tests::lifecycle_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_LIFECYCLE_ROOT", &root)
        .env("GATEWAY_TEST_LIFECYCLE_RESULT", &result)
        .env("GATEWAY_TEST_LIFECYCLE_RECORD", &old.path)
        .env("GATEWAY_TEST_LIFECYCLE_ABORT_STARTED", "1")
        .env("GATEWAY_TEST_LIFECYCLE_TWO", "1")
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_READY", &ready)
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE", &release)
        .env("GATEWAY_TEST_LIFECYCLE_ABORTED", &aborted)
        .spawn()
        .expect("spawn lifecycle owner");
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !aborted.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let mut successor = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::transaction_tests::transaction_delete_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_TRANSACTION_ROOT", &root)
        .env("GATEWAY_TEST_TRANSACTION_RESULT", &result)
        .env("GATEWAY_TEST_TRANSACTION_BUSY", &busy)
        .spawn()
        .expect("spawn named deletion");
    let contended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let early = result.exists();
    let retained = old.path.exists();
    let first_retained = newer_old.path.exists();
    std::fs::write(&release, "release").expect("release lifecycle worker");
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
    assert!(first_retained, "the started version must remain until its worker is released");
    assert!(retained, "version must remain while lifecycle worker is held");
    assert!(cancelled.is_ok(), "lifecycle request must abort after removal starts");
    assert!(statuses.iter().all(|status| status.success()), "children must complete");
    assert!(contended.is_ok() && busy.exists(), "named deletion must observe real contention");
    assert!(!early, "named deletion must not finish before lifecycle release");
    assert!(!newer_old.path.exists(), "started lifecycle removal completes after release");
    assert!(old.path.exists(), "cancellation must not begin the next historical removal");
    assert_eq!(std::fs::read_to_string(result).expect("successor result"), "deleted");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

/// Called by the dedicated integration harness after unrelated unit tests finish.
pub(super) async fn run_lifecycle_controls() {
    lifecycle_does_not_pass_an_inflight_protection_update().await;
    println!("completed: lifecycle_does_not_pass_an_inflight_protection_update");
    unprotected_lifecycle_waits_then_removes_the_selected_version().await;
    println!("completed: unprotected_lifecycle_waits_then_removes_the_selected_version");
    cancelled_queued_lifecycle_retains_the_version().await;
    println!("completed: cancelled_queued_lifecycle_retains_the_version");
    started_lifecycle_retains_both_locks_after_cancellation().await;
    println!("completed: started_lifecycle_retains_both_locks_after_cancellation");
    lifecycle_rechecks_protection_time_for_each_removal().await;
    println!("completed: lifecycle_rechecks_protection_time_for_each_removal");
}

/// Protection is checked at each real removal, including when the clock advances mid-batch.
async fn lifecycle_rechecks_protection_time_for_each_removal() {
    let (root, backend) = backend_with_bucket("lifecycle-transaction-clock");
    let old = backend
        .publish_version(
            "racing",
            "object",
            Some("v2"),
            Some(b"old"),
            Some(&etag(b"old").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("old version");
    std::fs::OpenOptions::new()
        .append(true)
        .open(old.path.join(RECORD_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"lock/1 1\nCOMPLIANCE 200 OFF\n"))
        .expect("protect old version");
    let newer_old = backend
        .publish_version(
            "racing",
            "object",
            Some("v3"),
            Some(b"new"),
            Some(&etag(b"new").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("second historical version");
    backend
        .publish_version(
            "racing",
            "object",
            Some("v4"),
            Some(b"current"),
            Some(&etag(b"current").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("current version");
    let clock = root.join("lifecycle-clock");
    let ready = root.join("lifecycle-clock-ready");
    let release = root.join("lifecycle-clock-release");
    let result = root.join("lifecycle-clock-result");
    std::fs::write(&clock, "100").expect("set initial clock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::lifecycle_transaction_tests::lifecycle_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_LIFECYCLE_ROOT", &root)
        .env("GATEWAY_TEST_LIFECYCLE_RESULT", &result)
        .env("GATEWAY_TEST_LIFECYCLE_RECORD", &old.path)
        .env("GATEWAY_TEST_LIFECYCLE_CLOCK", &clock)
        .env("GATEWAY_TEST_LIFECYCLE_TWO", "1")
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_READY", &ready)
        .env("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE", &release)
        .spawn()
        .expect("spawn lifecycle process");
    let started = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !ready.exists() && !result.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    std::fs::write(&clock, "200").expect("advance clock");
    std::fs::write(&release, "release").expect("release first removal");
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
    assert!(started.is_ok() && ready.exists(), "the first actual removal must start");
    assert!(status.expect("child completes").success());
    assert!(!newer_old.path.exists(), "first historical version is removed");
    assert!(!old.path.exists(), "retention expiring during the batch must be rechecked");
    assert_eq!(std::fs::read_to_string(result).expect("result"), "removed");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove root");
}

/// An actual removal error stops the batch and releases both synchronization guards.
#[tokio::test]
async fn lifecycle_removal_error_stops_batch_and_releases_guards() {
    let (root, backend) = backend_with_bucket("lifecycle-transaction-removal-error");
    let first = backend
        .publish_version(
            "racing",
            "first",
            Some("v1"),
            Some(b"one"),
            Some(&etag(b"one").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("first version");
    let second = backend
        .publish_version(
            "racing",
            "second",
            Some("v2"),
            Some(b"two"),
            Some(&etag(b"two").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("second version");
    let records = backend.version_records("racing").await.expect("load records");
    let first_record = records
        .iter()
        .find(|record| record.path == first.path)
        .expect("first record")
        .clone();
    let second_record = records
        .iter()
        .find(|record| record.path == second.path)
        .expect("second record")
        .clone();
    let process = super::super::transaction::root_guard(&root).await.expect("process guard");
    let local = backend.version_lock.clone().lock_owned().await;
    std::fs::remove_dir_all(&first.path).expect("inject actual missing directory");
    let result =
        super::super::transaction::remove_versions(process, local, vec![first_record, second_record], backend.clock.clone())
            .await;
    assert!(result.is_err(), "missing removal must fail the batch");
    assert!(second.path.exists(), "the subsequent version must not be removed");
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

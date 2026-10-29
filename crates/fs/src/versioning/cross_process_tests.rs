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

//! Cross-process version coordination experiment.
//!
//! Responsible for: observing real lock contention around a real backend deletion.
//! NOT responsible for: proving the production backend uses this experimental lock.
//! Upstream: process-lock and versioned filesystem fixtures; downstream: test evidence.

use super::*;

/// A child reports actual lock contention before attempting the real deletion.
#[tokio::test]
async fn cross_process_delete_probe() {
    let Some(root) = std::env::var_os("GATEWAY_TEST_CROSS_ROOT") else {
        eprintln!("skip: cross-process deletion probe has no parent fixture");
        return;
    };
    let lock_path = std::env::var_os("GATEWAY_TEST_CROSS_LOCK").expect("parent lock path");
    let busy_path = std::env::var_os("GATEWAY_TEST_CROSS_BUSY").expect("parent contention marker");
    let result_path = std::env::var_os("GATEWAY_TEST_CROSS_RESULT").expect("parent result marker");
    let backend = FsBackend::open(root).expect("open shared root");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .expect("open shared lock");
    match file.try_lock() {
        Err(std::fs::TryLockError::WouldBlock) => {
            std::fs::write(busy_path, b"contended").expect("report actual contention");
            file.lock().expect("acquire after release");
        }
        other => panic!("expected actual contention, got {other:?}"),
    }
    let result = backend.delete_object_version("racing", "object", Some("v1")).await;
    let observed = match result {
        Ok(_) => "deleted",
        Err(error) if error.code() == &ErrorCode::ACCESS_DENIED => "protected",
        Err(error) => panic!("unexpected deletion error: {error:?}"),
    };
    std::fs::write(result_path, observed).expect("report real backend deletion");
}

/// Parent and child serialize a protection update and a real backend deletion.
async fn an_explicit_cross_process_lock_protects_the_actual_version_update() {
    let (root, backend) = backend_with_bucket("cross-lock-experiment");
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
        .expect("persist version");
    let lock_path = root.join("experimental-lock");
    let busy_path = root.join("experimental-busy");
    let result_path = root.join("experimental-result");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .expect("create lock");
    held.lock().expect("acquire parent lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::cross_process_tests::cross_process_delete_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_CROSS_ROOT", &root)
        .env("GATEWAY_TEST_CROSS_LOCK", &lock_path)
        .env("GATEWAY_TEST_CROSS_BUSY", &busy_path)
        .env("GATEWAY_TEST_CROSS_RESULT", &result_path)
        .spawn()
        .expect("start child");
    let contention = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy_path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let update = std::fs::OpenOptions::new()
        .append(true)
        .open(record.path.join(RECORD_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"lock/1 1\nCOMPLIANCE 4102444800 ON\n"));
    drop(held);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let status = match outcome {
        Ok(status) => status,
        Err(_) => {
            child.kill().expect("stop stuck child");
            child.wait().expect("reap child");
            panic!("child did not finish");
        }
    };
    assert!(contention.is_ok(), "child must report an actual failed lock attempt");
    assert!(update.is_ok(), "protected version remains available for update");
    assert!(status.success(), "child must finish after release");
    assert_eq!(std::fs::read_to_string(result_path).expect("child result"), "protected");
    assert!(record.path.exists(), "protected version remains present");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// An unprotected version is deleted after the same cross-process lock is released.
async fn an_explicit_cross_process_lock_allows_an_unprotected_delete_after_release() {
    let (root, backend) = backend_with_bucket("cross-lock-unprotected");
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
        .expect("persist version");
    let lock_path = root.join("experimental-lock");
    let busy_path = root.join("experimental-busy");
    let result_path = root.join("experimental-result");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .expect("create lock");
    held.lock().expect("acquire parent lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::cross_process_tests::cross_process_delete_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_CROSS_ROOT", &root)
        .env("GATEWAY_TEST_CROSS_LOCK", &lock_path)
        .env("GATEWAY_TEST_CROSS_BUSY", &busy_path)
        .env("GATEWAY_TEST_CROSS_RESULT", &result_path)
        .spawn()
        .expect("start child");
    let contention = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy_path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    drop(held);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let status = match outcome {
        Ok(status) => status,
        Err(_) => {
            child.kill().expect("stop stuck child");
            child.wait().expect("reap child");
            panic!("child did not finish");
        }
    };
    assert!(contention.is_ok(), "child must report an actual failed lock attempt");
    assert!(status.success(), "child must finish after release");
    assert_eq!(std::fs::read_to_string(result_path).expect("child result"), "deleted");
    assert!(!record.path.exists(), "unprotected version must be removed");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Baseline probe used only while the sequence-read barrier instrumentation is installed.
#[tokio::test]
async fn version_sequence_race_child_probe() {
    let Some(root) = std::env::var_os("GATEWAY_TEST_SEQ_ROOT") else {
        eprintln!("skip: sequence race probe has no parent fixture");
        return;
    };
    let result_path = std::env::var_os("GATEWAY_TEST_SEQ_RESULT").expect("result path");
    let backend = FsBackend::open(root).expect("open shared root");
    if let Some(aborted) = std::env::var_os("GATEWAY_TEST_SEQ_ABORTED") {
        let ready = std::env::var_os("GATEWAY_TEST_SEQ_READY").expect("ready path");
        let release = std::env::var_os("GATEWAY_TEST_SEQ_RELEASE").expect("release path");
        let request = tokio::spawn(async move { backend.next_version_sequence("racing", &[]).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !std::path::Path::new(&ready).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("reservation starts");
        request.abort();
        assert!(request.await.expect_err("request aborted").is_cancelled());
        std::fs::write(aborted, b"aborted").expect("signal abort");
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !std::path::Path::new(&release).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("release reservation");
    } else {
        let sequence = backend.next_version_sequence("racing", &[]).await.expect("allocate sequence");
        std::fs::write(result_path, sequence.to_string()).expect("report sequence");
    }
}

/// Two processes must not allocate the same persistent version sequence.
async fn n_processes_must_not_allocate_the_same_version_sequence() {
    let (root, backend) = backend_with_bucket("sequence-process-race");
    let release = root.join("seq-release");
    let ready = root.join("seq-ready");
    let busy = root.join("seq-busy");
    let results = [root.join("seq-result-0"), root.join("seq-result-1")];
    let launch = |index: usize| {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "versioning::tests::cross_process_tests::version_sequence_race_child_probe",
                "--nocapture",
            ])
            .env("GATEWAY_TEST_SEQ_ROOT", &root)
            .env("GATEWAY_TEST_SEQ_RESULT", &results[index]);
        if index == 0 {
            command
                .env("GATEWAY_TEST_SEQ_READY", &ready)
                .env("GATEWAY_TEST_SEQ_RELEASE", &release);
        } else {
            command.env("GATEWAY_TEST_SEQ_BUSY", &busy);
        }
        command.spawn().expect("start child")
    };
    let first = launch(0);
    let first_ready = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let second = launch(1);
    let second_contended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    std::fs::write(release, b"release").expect("release first reader");
    let mut statuses = Vec::new();
    for mut child in [first, second] {
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.try_wait().expect("poll child") {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        let status = match outcome {
            Ok(status) => status,
            Err(_) => {
                child.kill().expect("stop child");
                child.wait().expect("reap child");
                panic!("child did not finish");
            }
        };
        statuses.push(status);
    }
    assert!(first_ready.is_ok(), "first process must read the counter while holding the lock");
    assert!(second_contended.is_ok(), "second process must observe actual lock contention");
    assert!(statuses.iter().all(|status| status.success()), "both children must complete");
    let mut allocated: Vec<u64> = results
        .into_iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .expect("child result")
                .parse()
                .expect("sequence")
        })
        .collect();
    allocated.sort_unstable();
    assert_eq!(allocated, [1, 2], "processes must receive distinct sequences");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Child aborts a queued real reservation only after its worker reports contention.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_sequence_child_probe() {
    let Some(root) = std::env::var_os("GATEWAY_TEST_CANCEL_ROOT") else {
        eprintln!("skip: cancellation probe has no parent fixture");
        return;
    };
    let busy = std::env::var_os("GATEWAY_TEST_SEQ_BUSY").expect("busy path");
    let cancelled = std::env::var_os("GATEWAY_TEST_SEQ_CANCELLED").expect("cancelled path");
    let backend = FsBackend::open(root).expect("open shared root");
    let worker = tokio::spawn(async move { backend.next_version_sequence("racing", &[]).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !std::path::Path::new(&busy).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("worker must contend");
    worker.abort();
    assert!(worker.await.expect_err("reservation must be cancelled").is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !std::path::Path::new(&cancelled).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("blocking worker must exit before lock release");
}

/// An aborted queued reservation must exit while another process still holds the lock.
async fn cancelled_queued_reservation_stops_before_lock_release() {
    let (root, backend) = backend_with_bucket("sequence-cancel");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(super::super::super::VERSION_SEQUENCE_LOCK_FILE))
        .expect("open lock");
    lock.lock().expect("hold lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::cross_process_tests::cancelled_sequence_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_CANCEL_ROOT", &root)
        .env("GATEWAY_TEST_SEQ_BUSY", root.join("cancel-busy"))
        .env("GATEWAY_TEST_SEQ_CANCELLED", root.join("cancel-done"))
        .spawn()
        .expect("start child");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    if outcome.is_err() {
        child.kill().expect("stop child");
        child.wait().expect("reap child");
    }
    assert!(outcome.expect("child finishes while lock held").success());
    assert!(
        !backend.bucket_path("racing").join(super::super::SEQUENCE_FILE).exists(),
        "cancelled reservation must not write a counter"
    );
    drop(lock);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Stale temporary data must not prevent a subsequent reservation or be overwritten.
#[tokio::test]
async fn stale_sequence_temporary_file_does_not_block_reservation() {
    let (root, backend) = backend_with_bucket("sequence-stale-temp");
    backend.temporary_id.store(911, std::sync::atomic::Ordering::Relaxed);
    let stale = backend
        .bucket_path("racing")
        .join(format!(".seq-tmp-{}-911", std::process::id()));
    std::fs::write(&stale, b"stale").expect("write stale temporary file");
    assert_eq!(
        backend
            .next_version_sequence("racing", &[])
            .await
            .expect("reserve despite stale file"),
        1
    );
    assert_eq!(std::fs::read(stale).expect("read stale file"), b"stale");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// A terminated lock owner must not prevent another process reserving the sequence.
async fn process_exit_releases_sequence_reservation_lock() {
    let (root, backend) = backend_with_bucket("sequence-killed-owner");
    let ready = root.join("killed-ready");
    let release = root.join("killed-release");
    let result = root.join("after-kill-result");
    let busy = root.join("killed-busy");
    let launch = |result_path: &std::path::Path| {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "versioning::tests::cross_process_tests::version_sequence_race_child_probe",
                "--nocapture",
            ])
            .env("GATEWAY_TEST_SEQ_ROOT", &root)
            .env("GATEWAY_TEST_SEQ_RESULT", result_path);
        command
    };
    let mut owner = launch(&root.join("killed-result"))
        .env("GATEWAY_TEST_SEQ_READY", &ready)
        .env("GATEWAY_TEST_SEQ_RELEASE", &release)
        .spawn()
        .expect("start owner");
    let seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let mut next = launch(&result)
        .env("GATEWAY_TEST_SEQ_BUSY", &busy)
        .spawn()
        .expect("start successor");
    let contended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    owner.kill().expect("terminate owner");
    assert!(!owner.wait().expect("reap owner").success());
    assert!(seen.is_ok(), "owner must read while holding the lock");
    assert!(contended.is_ok(), "successor must observe contention before owner termination");
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(status) = next.try_wait().expect("poll successor") {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    if status.is_err() {
        next.kill().expect("stop successor");
        next.wait().expect("reap successor");
    }
    assert!(status.expect("successor completes").success());
    assert_eq!(std::fs::read_to_string(result).expect("successor result"), "1");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// A legacy missing counter must not put its existing records behind a new counter.
#[tokio::test]
async fn existing_record_floor_wins_over_lower_new_counter() {
    let (root, backend) = backend_with_bucket("sequence-existing-floor");
    let mut existing = backend
        .publish_version(
            "racing",
            "old",
            Some("v1"),
            Some(b"x"),
            Some(&etag(b"x").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("existing version");
    existing.sequence = 99;
    std::fs::remove_file(backend.bucket_path("racing").join(super::super::SEQUENCE_FILE))
        .expect("simulate legacy missing counter");
    assert_eq!(
        backend
            .next_version_sequence("racing", &[])
            .await
            .expect("other instance reserves"),
        1
    );
    assert_eq!(
        backend
            .next_version_sequence("racing", &[existing])
            .await
            .expect("reserve above existing records"),
        100
    );
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// A started reservation retains its process lock after the request is aborted.
async fn aborted_started_reservation_retains_lock_until_counter_published() {
    let (root, backend) = backend_with_bucket("sequence-abort-running");
    let ready = root.join("running-ready");
    let aborted = root.join("running-aborted");
    let release = root.join("running-release");
    let busy = root.join("running-busy");
    let result = root.join("running-result");
    let launch = || {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "versioning::tests::cross_process_tests::version_sequence_race_child_probe",
                "--nocapture",
            ])
            .env("GATEWAY_TEST_SEQ_ROOT", &root)
            .env("GATEWAY_TEST_SEQ_RESULT", &result);
        command
    };
    let mut first = launch()
        .env("GATEWAY_TEST_SEQ_READY", &ready)
        .env("GATEWAY_TEST_SEQ_RELEASE", &release)
        .env("GATEWAY_TEST_SEQ_ABORTED", &aborted)
        .spawn()
        .expect("start owner");
    let aborted_seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !aborted.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let mut second = launch().env("GATEWAY_TEST_SEQ_BUSY", &busy).spawn().expect("start successor");
    let contention = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !busy.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    std::fs::write(&release, b"release").expect("release owner");
    for child in [&mut first, &mut second] {
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.try_wait().expect("poll child") {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        if result.is_err() {
            child.kill().expect("stop child");
            child.wait().expect("reap child");
        }
        assert!(result.expect("child completes").success());
    }
    assert!(aborted_seen.is_ok(), "owner request must be aborted");
    assert!(contention.is_ok(), "successor must observe the aborted owner's lock");
    assert_eq!(std::fs::read_to_string(result).expect("successor result"), "2");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Invalid or exhausted persisted counters fail closed with the previous error code.
#[tokio::test]
async fn invalid_and_exhausted_counters_are_refused_without_replacement() {
    for (tag, data) in [("bad", "not-a-counter\n"), ("overflow", "18446744073709551615\n")] {
        let (root, backend) = backend_with_bucket(tag);
        let counter = backend.bucket_path("racing").join(super::super::SEQUENCE_FILE);
        std::fs::write(&counter, data).expect("create counter");
        let error = backend
            .next_version_sequence("racing", &[])
            .await
            .expect_err("counter must fail");
        assert_eq!(error.code(), &ErrorCode::INTERNAL_ERROR);
        assert_eq!(std::fs::read_to_string(counter).expect("read original counter"), data);
        drop(backend);
        std::fs::remove_dir_all(root).expect("remove test root");
    }
}

/// A real rename failure must not report a successful reservation.
async fn sequence_rename_failure_does_not_report_success() {
    let (root, backend) = backend_with_bucket("sequence-rename-fail");
    let ready = root.join("rename-ready");
    let release = root.join("rename-release");
    let result = root.join("rename-result");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::cross_process_tests::version_sequence_race_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_SEQ_ROOT", &root)
        .env("GATEWAY_TEST_SEQ_RESULT", &result)
        .env("GATEWAY_TEST_SEQ_READY", &ready)
        .env("GATEWAY_TEST_SEQ_RELEASE", &release)
        .spawn()
        .expect("start reservation");
    let seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    let destination = backend.bucket_path("racing").join(super::super::SEQUENCE_FILE);
    std::fs::create_dir(&destination).expect("force rename failure");
    std::fs::write(release, b"release").expect("release reservation");
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
    assert!(seen.is_ok(), "worker must read before destination changes");
    assert!(!status.expect("child completes").success(), "rename failure must be reported");
    assert!(!result.exists(), "no successful result may be written");
    assert!(destination.is_dir(), "conflicting directory remains intact");
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Independent instances in one process share the same persistent sequence authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_instances_allocate_unique_sequences() {
    let (root, first) = backend_with_bucket("sequence-instances");
    let second = FsBackend::open(&root).expect("second instance");
    let (left, right) = tokio::join!(first.next_version_sequence("racing", &[]), second.next_version_sequence("racing", &[]));
    let mut values = [left.expect("first reservation"), right.expect("second reservation")];
    values.sort_unstable();
    assert_eq!(values, [1, 2]);
    drop(second);
    drop(first);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// An injected synchronization error must fail before the counter is published.
async fn sequence_sync_failure_does_not_report_success() {
    let (root, backend) = backend_with_bucket("sequence-sync-fail");
    let result = root.join("sync-result");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "versioning::tests::cross_process_tests::version_sequence_race_child_probe",
            "--nocapture",
        ])
        .env("GATEWAY_TEST_SEQ_ROOT", &root)
        .env("GATEWAY_TEST_SEQ_RESULT", &result)
        .env("GATEWAY_TEST_SEQ_FAIL_SYNC", "1")
        .spawn()
        .expect("start reservation");
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
    assert!(!status.expect("child completes").success(), "sync failure must be reported");
    assert!(!result.exists(), "no successful result may be written");
    let bucket = backend.bucket_path("racing");
    assert!(!bucket.join(super::super::SEQUENCE_FILE).exists(), "counter must not be published");
    assert!(
        std::fs::read_dir(bucket).expect("read bucket").all(|entry| !entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .starts_with(".seq-tmp-")),
        "failed temporary must be removed"
    );
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// The integration harness runs these privately scoped controls in a separate test process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_process_controls_driver() {
    if std::env::var_os("GATEWAY_RUN_PROCESS_CONTROLS").is_none() {
        eprintln!("skip: process controls run from the dedicated integration harness");
        return;
    }
    an_explicit_cross_process_lock_protects_the_actual_version_update().await;
    println!("completed: an_explicit_cross_process_lock_protects_the_actual_version_update");
    an_explicit_cross_process_lock_allows_an_unprotected_delete_after_release().await;
    println!("completed: an_explicit_cross_process_lock_allows_an_unprotected_delete_after_release");
    n_processes_must_not_allocate_the_same_version_sequence().await;
    println!("completed: n_processes_must_not_allocate_the_same_version_sequence");
    cancelled_queued_reservation_stops_before_lock_release().await;
    println!("completed: cancelled_queued_reservation_stops_before_lock_release");
    process_exit_releases_sequence_reservation_lock().await;
    println!("completed: process_exit_releases_sequence_reservation_lock");
    aborted_started_reservation_retains_lock_until_counter_published().await;
    println!("completed: aborted_started_reservation_retains_lock_until_counter_published");
    sequence_rename_failure_does_not_report_success().await;
    println!("completed: sequence_rename_failure_does_not_report_success");
    sequence_sync_failure_does_not_report_success().await;
    println!("completed: sequence_sync_failure_does_not_report_success");
}

/// Existing non-file lock paths fail before any counter is written.
#[tokio::test]
async fn sequence_lock_directory_is_refused() {
    let (root, backend) = backend_with_bucket("sequence-lock-directory");
    let lock = root.join(super::super::super::VERSION_SEQUENCE_LOCK_FILE);
    std::fs::create_dir(&lock).expect("create conflicting directory");
    assert_eq!(
        backend
            .next_version_sequence("racing", &[])
            .await
            .expect_err("reject directory")
            .code(),
        &ErrorCode::INTERNAL_ERROR
    );
    assert!(lock.is_dir(), "conflicting directory remains");
    assert!(!backend.bucket_path("racing").join(super::super::SEQUENCE_FILE).exists());
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// An existing symlink is refused without opening or changing its target.
#[cfg(unix)]
#[tokio::test]
async fn sequence_lock_symlink_is_refused() {
    let (root, backend) = backend_with_bucket("sequence-lock-symlink");
    let target = root.join("unrelated-target");
    std::fs::write(&target, b"unchanged").expect("create target");
    std::os::unix::fs::symlink(&target, root.join(super::super::super::VERSION_SEQUENCE_LOCK_FILE)).expect("create symlink");
    assert_eq!(
        backend
            .next_version_sequence("racing", &[])
            .await
            .expect_err("reject symlink")
            .code(),
        &ErrorCode::INTERNAL_ERROR
    );
    assert_eq!(std::fs::read(&target).expect("read target"), b"unchanged");
    assert!(!backend.bucket_path("racing").join(super::super::SEQUENCE_FILE).exists());
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// The persistent lock file must not hide buckets from the real root census.
#[tokio::test]
async fn bucket_census_remains_available_after_sequence_reservation() {
    let (root, backend) = backend_with_bucket("sequence-census");
    backend.next_version_sequence("racing", &[]).await.expect("reserve sequence");
    assert_eq!(backend.lifecycle_buckets().await.expect("enumerate buckets"), ["racing"]);
    drop(backend);
    std::fs::remove_dir_all(root).expect("remove test root");
}

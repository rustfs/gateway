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

//! Shared-root coordination controls for versioned storage.
//!
//! Responsible for: same-process shared-root version mutex controls.
//! NOT responsible for: cross-process coordination, cancellation or crash-consistent durability.
//! Upstream: versioned filesystem backend; downstream: targeted regression tests.

use super::*;

/// Negative — a second backend cannot delete while the first updates protection.
#[tokio::test]
async fn n_separate_backends_cannot_delete_during_protection_update() {
    let (root, first) = backend_with_bucket("lock-two-backends");
    let record = first
        .publish_version(
            "racing",
            "object",
            Some("v1"),
            Some(b"x"),
            Some(&etag(b"x").expect("tag")),
            &ObjectAttributes::default(),
        )
        .await
        .expect("a persisted version");
    let second = FsBackend::open(&root).expect("open a second backend on the same root");
    let guard = first.version_lock.lock().await;
    let mut delete = tokio::spawn(async move { second.delete_object_version("racing", "object", Some("v1")).await });
    let early = tokio::time::timeout(std::time::Duration::from_millis(250), &mut delete).await;
    let protection = std::fs::OpenOptions::new()
        .append(true)
        .open(record.path.join(RECORD_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"lock/1 1\nCOMPLIANCE 4102444800 ON\n"));
    drop(guard);
    let (finished_early, outcome) = match early {
        Ok(outcome) => (true, outcome.expect("delete task")),
        Err(_) => (false, delete.await.expect("delete task")),
    };
    assert!(protection.is_ok(), "the version must remain for the protection update");
    assert!(!finished_early, "a second backend deleted while protection was being updated");
    assert_eq!(outcome.expect_err("updated protection blocks deletion").code(), &ErrorCode::ACCESS_DENIED);
    assert!(record.path.exists(), "the protected version remains");
    drop(first);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Negative — canonical aliases to the same root must share the version mutex.
#[test]
fn n_canonical_root_aliases_share_version_mutex() {
    let (root, first) = backend_with_bucket("shared-alias");
    let second = FsBackend::open(root.join(".")).expect("open canonical alias");
    let first_guard = first.version_lock.try_lock().expect("first lock");
    let second_blocked = second.version_lock.try_lock().is_err();
    drop(first_guard);
    assert!(second_blocked, "aliases of the same root must share the mutex");
    drop(second);
    drop(first);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Negative — concurrent open calls for one root cannot create separate mutexes.
#[test]
fn n_concurrent_opens_share_one_version_mutex() {
    let (root, initial) = backend_with_bucket("shared-open-race");
    drop(initial);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let root = root.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            FsBackend::open(root).expect("concurrent open")
        }));
    }
    let backends: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("opening thread"))
        .collect();
    let owner = backends[0].version_lock.try_lock().expect("first mutex");
    let blocked = backends[1..]
        .iter()
        .filter(|backend| backend.version_lock.try_lock().is_err())
        .count();
    drop(owner);
    assert_eq!(blocked, 7, "every other same-root instance must observe the held mutex");
    drop(backends);
    std::fs::remove_dir_all(root).expect("remove test root");
}

/// Positive — unrelated roots remain independent, and a dropped root can be reopened.
#[test]
fn different_roots_are_independent_and_a_root_can_be_reopened() {
    let (root_a, first) = backend_with_bucket("shared-root-a");
    let (root_b, second) = backend_with_bucket("shared-root-b");
    let first_guard = first.version_lock.try_lock().expect("first lock");
    let independent = second.version_lock.try_lock().is_ok();
    drop(first_guard);
    assert!(independent, "another root must not share the mutex");
    drop(first);
    let reopened = FsBackend::open(&root_a).expect("reopen after the last owner drops");
    drop(reopened);
    drop(second);
    std::fs::remove_dir_all(root_a).expect("remove first root");
    std::fs::remove_dir_all(root_b).expect("remove second root");
}

/// Negative — the registry cannot keep a dropped root's mutex alive.
#[test]
fn n_registry_does_not_keep_dropped_mutex_alive() {
    let (root, first) = backend_with_bucket("shared-registry-drop");
    let weak = std::sync::Arc::downgrade(&first.version_lock);
    drop(first);
    assert!(weak.upgrade().is_none(), "the registry must not retain the mutex");
    let reopened = FsBackend::open(&root).expect("reopen after last owner dropped");
    drop(reopened);
    std::fs::remove_dir_all(root).expect("remove test root");
}

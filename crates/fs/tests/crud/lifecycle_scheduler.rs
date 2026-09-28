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

//! Background lifecycle-scheduler evidence for the filesystem reference backend.
//!
//! Responsible for: proving cadence-driven sweeps and bounded shutdown through the production
//! service. NOT responsible for: CLI argument parsing or transition actions. Upstream: the
//! one-shot lifecycle executor. Downstream: the reference SUT listener and crate verification gate.

use super::*;
use std::time::Duration;

/// Positive — the configured debug cadence drives expiration without a manual sweep call.
#[tokio::test]
async fn configured_scheduler_expires_on_its_first_cadence() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-scheduled").await;
    super::lifecycle_expiration::put_policy(
        &initial,
        "lc-scheduled",
        super::lifecycle_expiration::EXPIRE_ALL,
        super::lifecycle_expiration::EXPIRE_ALL_MD5,
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-scheduled", "key", b"body")
            .await
            .status(),
        200
    );
    drop(initial);

    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS + 1)))
            .expect("a usable test root")
            .with_lifecycle_debug_interval(Duration::from_secs(1))
            .expect("a non-zero debug interval"),
    );
    let (_, running) = service_with_backend(Arc::clone(&backend));
    let started = std::time::Instant::now();
    let scheduler = backend.start_lifecycle_scheduler().expect("a runtime is active");

    // Wait for the expiry itself rather than a fixed 1.2s: the first sweep runs its filesystem work
    // on the blocking pool after the 1s cadence, and a loaded runner can take longer than any
    // fixed margin to finish it. The next cadence cannot start until a full interval after the
    // first sweep finishes, so shutting down as soon as the expiry is visible still isolates it.
    let deadline = started + Duration::from_secs(30);
    loop {
        let status = super::lifecycle_expiration::get(&running, "lc-scheduled", "key")
            .await
            .status();
        if status == 404 {
            break;
        }
        assert_eq!(status, 200, "the object is either still current or expired");
        assert!(std::time::Instant::now() < deadline, "no sweep expired the object within 30s");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "the object expired before the first 1s cadence"
    );
    let report = scheduler.shutdown().await.expect("the scheduler joins cleanly");
    assert_eq!(report.sweeps, 1);
    assert_eq!(report.expired_objects, 1);
    assert_eq!(report.failed_sweeps, 0);
}

/// Negative — one backend never runs two lifecycle workers concurrently.
#[tokio::test]
async fn n_second_scheduler_is_refused_until_the_first_finishes() {
    let root = TestRoot::new();
    let backend = Arc::new(FsBackend::open(&root.0).expect("a usable test root"));
    let first = backend.start_lifecycle_scheduler().expect("the first scheduler starts");
    assert!(backend.start_lifecycle_scheduler().is_err());
    assert_eq!(first.shutdown().await.expect("the first scheduler stops").sweeps, 0);

    let replacement = backend
        .start_lifecycle_scheduler()
        .expect("a stopped scheduler releases ownership");
    assert_eq!(replacement.shutdown().await.expect("the replacement stops").sweeps, 0);
}

/// Negative — shutdown before the first cadence leaves eligible data untouched permanently.
#[tokio::test]
async fn n_shutdown_before_the_first_cadence_prevents_a_late_sweep() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-stopped").await;
    super::lifecycle_expiration::put_policy(
        &initial,
        "lc-stopped",
        super::lifecycle_expiration::EXPIRE_ALL,
        super::lifecycle_expiration::EXPIRE_ALL_MD5,
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-stopped", "key", b"body")
            .await
            .status(),
        200
    );
    drop(initial);

    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS + 1)))
            .expect("a usable test root")
            .with_lifecycle_debug_interval(Duration::from_secs(1))
            .expect("a non-zero debug interval"),
    );
    let (_, running) = service_with_backend(Arc::clone(&backend));
    let report = backend
        .start_lifecycle_scheduler()
        .expect("a runtime is active")
        .shutdown()
        .await
        .expect("the scheduler joins cleanly");
    assert_eq!(report.sweeps, 0);

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(super::lifecycle_expiration::get(&running, "lc-stopped", "key").await.status(), 200);
}

/// Negative — corrupt state fails one sweep closed but does not permanently kill the worker.
#[tokio::test]
async fn n_corrupt_sweep_is_counted_and_the_next_cadence_recovers() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-recover").await;
    super::lifecycle_expiration::put_policy(
        &initial,
        "lc-recover",
        super::lifecycle_expiration::EXPIRE_ALL,
        super::lifecycle_expiration::EXPIRE_ALL_MD5,
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-recover", "key", b"body")
            .await
            .status(),
        200
    );
    let authority = super::lifecycle::lifecycle_record(&root, "lc-recover");
    let valid = std::fs::read(&authority).expect("the lifecycle authority is readable");
    std::fs::write(&authority, b"corrupt").expect("the lifecycle authority is writable");
    drop(initial);

    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS + 1)))
            .expect("a usable test root")
            .with_lifecycle_debug_interval(Duration::from_secs(1))
            .expect("a non-zero debug interval"),
    );
    let (_, running) = service_with_backend(Arc::clone(&backend));
    let scheduler = backend.start_lifecycle_scheduler().expect("a runtime is active");

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(super::lifecycle_expiration::get(&running, "lc-recover", "key").await.status(), 200);
    std::fs::write(authority, valid).expect("the lifecycle authority is repairable");
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(super::lifecycle_expiration::get(&running, "lc-recover", "key").await.status(), 404);

    let report = scheduler.shutdown().await.expect("the scheduler joins cleanly");
    assert!(report.sweeps >= 2);
    assert_eq!(report.expired_objects, 1);
    assert_eq!(report.failed_sweeps, 1);
}

/// Negative — a public start call outside a Tokio runtime returns an error instead of panicking.
#[test]
fn n_start_outside_a_runtime_is_an_error() {
    let root = TestRoot::new();
    let backend = Arc::new(FsBackend::open(&root.0).expect("a usable test root"));
    let refused = std::thread::spawn(move || backend.start_lifecycle_scheduler().is_err())
        .join()
        .expect("the probe thread does not panic");
    assert!(refused);
}

/// Negative — runtime cancellation cannot strand the single-worker ownership bit.
#[tokio::test]
async fn n_runtime_cancellation_releases_scheduler_ownership() {
    let root = TestRoot::new();
    let backend = Arc::new(FsBackend::open(&root.0).expect("a usable test root"));
    let worker_backend = Arc::clone(&backend);
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a test runtime");
        let scheduler = runtime.block_on(async move {
            worker_backend
                .start_lifecycle_scheduler()
                .expect("the worker runtime is active")
        });
        drop(runtime);
        drop(scheduler);
    })
    .join()
    .expect("the cancellation probe does not panic");

    let replacement = backend.start_lifecycle_scheduler().expect("cancelled ownership is released");
    assert_eq!(replacement.shutdown().await.expect("the replacement stops").sweeps, 0);
}

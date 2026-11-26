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

//! Unit controls for bounded reusable blocking file-transfer worker pools.
//!
//! Responsible for: verifying concurrency ceilings, listener isolation, cancellation state
//! retention, thread reuse, and panic survival in `BlockingFileTransferExecutor`.
//! NOT responsible for: platform `sendfile` syscalls (`sendfile.rs`) or socket readiness
//! (`io_sendfile_tests.rs`).
//! Upstream: `BlockingFileTransferExecutor`. Downstream: OS worker threads.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use super::BlockingFileTransferExecutor;
use crate::io::{deadline_after, test_deadline_now};

const SAFETY_TIMEOUT: Duration = Duration::from_secs(5);
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(2);

struct Stall {
    released: Mutex<bool>,
    changed: Condvar,
}

struct DropNotice(Option<mpsc::Sender<()>>);

impl Drop for DropNotice {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Stall {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    fn wait(&self) {
        let released = self.released.lock().expect("stall mutex is not poisoned");
        let (_released, result) = self
            .changed
            .wait_timeout_while(released, SAFETY_TIMEOUT, |released| !*released)
            .expect("stall mutex is not poisoned");
        assert!(!result.timed_out(), "external safety release did not arrive");
    }

    fn release(&self) {
        *self.released.lock().expect("stall mutex is not poisoned") = true;
        self.changed.notify_all();
    }
}

fn one_worker_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("test runtime builds")
}

#[test]
fn listener_default_keeps_blocking_file_concurrency_inside_its_internal_bound() {
    let executor = BlockingFileTransferExecutor::for_listener();
    let permits = executor.capacity.available_permits();
    assert!((2..=32).contains(&permits));
}

#[test]
fn listeners_share_one_process_wide_file_transfer_bound() {
    let first = BlockingFileTransferExecutor::for_listener();
    let second = BlockingFileTransferExecutor::for_listener();

    assert!(
        Arc::ptr_eq(&first.capacity, &second.capacity),
        "a replacement listener must inherit permits held by detached work from its predecessor"
    );
    assert!(
        Arc::ptr_eq(&first.workers, &second.workers),
        "listeners must share one bounded worker pool"
    );
    assert!(!Arc::ptr_eq(&first.activity, &second.activity));
    assert_eq!(first.limit, second.limit);
}

#[test]
fn listener_idle_wait_does_not_wait_for_another_listeners_cold_job() {
    let runtime = one_worker_runtime();
    let first = BlockingFileTransferExecutor::for_listener();
    let second = BlockingFileTransferExecutor::for_listener();
    let stall = Stall::new();
    let job_stall = Arc::clone(&stall);
    let (entered_tx, entered_rx) = mpsc::channel();
    let transfer = runtime.spawn(async move {
        second
            .run(move |_permit| {
                entered_tx.send(()).expect("test receiver remains alive");
                job_stall.wait();
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    entered_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("second listener's cold job starts");

    if runtime
        .block_on(async { tokio::time::timeout(Duration::from_millis(100), first.wait_idle()).await })
        .is_err()
    {
        stall.release();
        runtime
            .block_on(transfer)
            .expect("transfer task joins after safety release")
            .expect("second listener job succeeds");
        panic!("one listener's idle wait included another listener's cold job");
    }

    stall.release();
    runtime
        .block_on(transfer)
        .expect("transfer task joins")
        .expect("second listener job succeeds");
}

#[test]
fn stalled_job_does_not_block_unrelated_tokio_task() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let stall = Stall::new();
    let job_stall = Arc::clone(&stall);
    let (entered_tx, entered_rx) = mpsc::channel();

    let transfer = runtime.spawn(async move {
        executor
            .run(move |_permit| {
                entered_tx.send(()).expect("test receiver remains alive");
                job_stall.wait();
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    entered_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("blocking job enters before timeout");

    let (witness_tx, witness_rx) = mpsc::channel();
    runtime.spawn(async move {
        witness_tx.send(()).expect("test receiver remains alive");
    });
    witness_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("unrelated Tokio task advances while file work is stalled");

    stall.release();
    runtime
        .block_on(transfer)
        .expect("transfer task joins")
        .expect("blocking job succeeds");
}

#[test]
fn concurrency_limit_waits_without_blocking_runtime() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let stall = Stall::new();
    let first_stall = Arc::clone(&stall);
    let (first_tx, first_rx) = mpsc::channel();

    let first_executor = executor.clone();
    let first = runtime.spawn(async move {
        first_executor
            .run(move |_permit| {
                first_tx.send(()).expect("test receiver remains alive");
                first_stall.wait();
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    first_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("first job acquires the only permit");

    let (queued_tx, queued_rx) = mpsc::channel();
    let (second_tx, second_rx) = mpsc::channel();
    let second = runtime.spawn(async move {
        queued_tx.send(()).expect("test receiver remains alive");
        executor
            .run(move |_permit| {
                second_tx.send(()).expect("test receiver remains alive");
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    queued_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("second job reaches the executor");

    let (witness_tx, witness_rx) = mpsc::channel();
    runtime.spawn(async move {
        witness_tx.send(()).expect("test receiver remains alive");
    });
    witness_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("runtime advances while second job waits for capacity");
    assert!(
        matches!(second_rx.recv_timeout(Duration::from_millis(100)), Err(mpsc::RecvTimeoutError::Timeout)),
        "second blocking job must not enter before the first releases capacity"
    );

    stall.release();
    second_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("second job enters after capacity is released");
    runtime
        .block_on(first)
        .expect("first transfer task joins")
        .expect("first blocking job succeeds");
    runtime
        .block_on(second)
        .expect("second transfer task joins")
        .expect("second blocking job succeeds");
}

#[test]
fn queued_reservation_does_not_enter_the_resource_creation_phase() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let capacity = runtime.block_on(async {
        Arc::clone(&executor.capacity)
            .acquire_owned()
            .await
            .expect("test holds global capacity")
    });
    let queued_executor = executor.clone();
    let (reserved_tx, reserved_rx) = mpsc::channel();
    let reservation = runtime.spawn(async move {
        let reservation = queued_executor
            .reserve_until(deadline_after(Duration::from_secs(2)))
            .await
            .expect("reservation succeeds after capacity release");
        reserved_tx.send(()).expect("test receiver remains alive");
        reservation
    });

    assert!(
        matches!(reserved_rx.recv_timeout(Duration::from_millis(100)), Err(mpsc::RecvTimeoutError::Timeout)),
        "queued work cannot create per-job resources before capacity is reserved"
    );
    drop(capacity);
    reserved_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("resource creation phase starts after capacity is reserved");
    drop(runtime.block_on(reservation).expect("reservation task joins"));
}

#[test]
fn immediate_job_is_handed_off_and_runs_once() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let job_calls = Arc::clone(&calls);

    let (runtime_thread, blocking_thread, value) = runtime.block_on(async move {
        let runtime_thread = std::thread::current().id();
        let (blocking_thread, value) = executor
            .run(move |_permit| {
                job_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>((std::thread::current().id(), 17_u8))
            })
            .await
            .expect("immediate job succeeds");
        (runtime_thread, blocking_thread, value)
    });

    assert_ne!(runtime_thread, blocking_thread);
    assert_eq!(value, 17);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn panicking_job_returns_io_error() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);

    let error = runtime
        .block_on(executor.run(|_permit| -> std::io::Result<()> {
            panic!("test panic must not cross the executor boundary");
        }))
        .expect_err("panic is mapped to an I/O error");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
}

#[test]
fn cancelled_waiter_retains_owned_state_until_the_blocking_job_finishes() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let stall = Stall::new();
    let job_stall = Arc::clone(&stall);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let owned_state = DropNotice(Some(dropped_tx));

    let transfer = runtime.spawn(async move {
        executor
            .run(move |_permit| {
                let _owned_state = owned_state;
                entered_tx.send(()).expect("test receiver remains alive");
                job_stall.wait();
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    entered_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("blocking job owns the transfer state");
    transfer.abort();
    runtime.block_on(async {
        assert!(transfer.await.expect_err("transfer task is cancelled").is_cancelled());
    });
    assert!(
        matches!(dropped_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "cancelling the async waiter must not release state still owned by the syscall"
    );

    stall.release();
    dropped_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("owned state is released after the blocking job exits");
}

#[test]
fn running_job_times_out_while_idle_wait_still_tracks_its_owned_state() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("test runtime builds");
    let executor = BlockingFileTransferExecutor::new(1);
    let stall = Stall::new();
    let job_stall = Arc::clone(&stall);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let transfer_executor = executor.clone();

    runtime.block_on(async {
        let transfer = tokio::spawn(async move {
            transfer_executor
                .run_until(deadline_after(Duration::from_secs(1)), move |_permit| {
                    let _owned_state = DropNotice(Some(dropped_tx));
                    entered_tx.send(()).expect("test receiver remains alive");
                    job_stall.wait();
                    Ok::<_, std::io::Error>(())
                })
                .await
        });
        tokio::task::yield_now().await;
        entered_rx
            .recv_timeout(PROGRESS_TIMEOUT)
            .expect("blocking job starts before its deadline");
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = transfer
            .await
            .expect("transfer task joins at its deadline")
            .expect_err("running work cannot report late success");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        let idle_executor = executor.clone();
        let idle = tokio::spawn(async move {
            idle_executor.wait_idle().await;
        });
        tokio::task::yield_now().await;
        assert!(!idle.is_finished(), "idle wait includes detached blocking work");
        assert!(
            matches!(dropped_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "timing out the async waiter must not release blocking-owned state"
        );

        stall.release();
        idle.await.expect("idle waiter joins after blocking work exits");
        dropped_rx
            .recv_timeout(PROGRESS_TIMEOUT)
            .expect("blocking-owned state drops before the executor becomes idle");
    });
}

#[test]
fn running_file_work_does_not_delay_tokio_runtime_shutdown() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let stall = Stall::new();
    let job_stall = Arc::clone(&stall);
    let (entered_tx, entered_rx) = mpsc::channel();
    runtime.spawn(async move {
        let _ = executor
            .run(move |_permit| {
                entered_tx.send(()).expect("test receiver remains alive");
                job_stall.wait();
                Ok::<_, std::io::Error>(())
            })
            .await;
    });
    entered_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("file work starts before runtime shutdown");

    let (dropped_tx, dropped_rx) = mpsc::channel();
    std::thread::spawn(move || {
        drop(runtime);
        dropped_tx.send(()).expect("test receiver remains alive");
    });
    if dropped_rx.recv_timeout(Duration::from_millis(100)).is_err() {
        stall.release();
        dropped_rx
            .recv_timeout(PROGRESS_TIMEOUT)
            .expect("runtime drop finishes after safety release");
        panic!("Tokio runtime shutdown waited for isolated file work");
    }
    stall.release();
}

#[test]
fn warm_handoff_cost_sample_reports_without_a_wall_time_gate() {
    const SAMPLES: usize = 128;

    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut direct_elapsed = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let started = test_deadline_now();
        std::hint::black_box(sample);
        direct_elapsed.push(started.elapsed());
    }
    let mut isolated_elapsed = Vec::with_capacity(SAMPLES);
    runtime.block_on(async {
        for _ in 0..SAMPLES {
            let started = test_deadline_now();
            let job_calls = Arc::clone(&calls);
            executor
                .run(move |_permit| {
                    job_calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, std::io::Error>(())
                })
                .await
                .expect("warm handoff succeeds");
            isolated_elapsed.push(started.elapsed());
        }
    });
    direct_elapsed.sort_unstable();
    isolated_elapsed.sort_unstable();
    let direct_median = direct_elapsed.get(SAMPLES / 2).copied().expect("direct median sample exists");
    let isolated_median = isolated_elapsed
        .get(SAMPLES / 2)
        .copied()
        .expect("isolated median sample exists");
    let isolated_p95 = isolated_elapsed
        .get(SAMPLES * 95 / 100)
        .copied()
        .expect("isolated p95 sample exists");
    eprintln!(
        "blocking file handoff samples={SAMPLES} direct_median={direct_median:?} isolated_median={isolated_median:?} isolated_p95={isolated_p95:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), SAMPLES, "every sample executes exactly one job");
}

#[test]
fn queued_job_times_out_without_starting_or_losing_owned_state() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("test runtime builds");
    runtime.block_on(async {
        let executor = BlockingFileTransferExecutor::new(1);
        let permit = Arc::clone(&executor.capacity)
            .acquire_owned()
            .await
            .expect("test owns the only permit");
        let calls = Arc::new(AtomicUsize::new(0));
        let job_calls = Arc::clone(&calls);
        let (dropped_tx, dropped_rx) = mpsc::channel();
        let queued_executor = executor.clone();
        let queued = tokio::spawn(async move {
            let owned_state = DropNotice(Some(dropped_tx));
            queued_executor
                .run_until(deadline_after(Duration::from_secs(1)), move |_permit| {
                    let _owned_state = owned_state;
                    job_calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, std::io::Error>(())
                })
                .await
        });
        tokio::task::yield_now().await;
        assert!(!queued.is_finished(), "capacity wait remains pending before its deadline");
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = queued.await.expect("queued task joins").expect_err("capacity wait times out");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "timed-out work never enters the blocking pool");
        dropped_rx
            .recv_timeout(PROGRESS_TIMEOUT)
            .expect("timed-out work releases the state captured by its job");
        drop(permit);
    });
}

#[test]
fn tokio_blocking_pool_saturation_does_not_delay_file_work() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .expect("test runtime builds");
    let stall = Stall::new();
    let blocker_stall = Arc::clone(&stall);
    let (blocker_tx, blocker_rx) = mpsc::channel();
    let blocker = runtime.spawn_blocking(move || {
        blocker_tx.send(()).expect("test receiver remains alive");
        blocker_stall.wait();
    });
    blocker_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("the only global blocking worker is occupied");

    let executor = BlockingFileTransferExecutor::new(1);
    let (entered_tx, entered_rx) = mpsc::channel();
    let transfer = runtime.spawn(async move {
        executor
            .run_until(deadline_after(Duration::from_secs(2)), move |_permit| {
                entered_tx.send(()).expect("test receiver remains alive");
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    if entered_rx.recv_timeout(Duration::from_millis(100)).is_err() {
        stall.release();
        runtime
            .block_on(blocker)
            .expect("blocking control joins after safety release");
        panic!("file work waited behind Tokio's unrelated blocking pool");
    }
    runtime
        .block_on(transfer)
        .expect("transfer task joins")
        .expect("isolated file work succeeds");
    stall.release();
    runtime.block_on(blocker).expect("blocking control joins");
}

/// Negative — repeated handoffs must reuse a bounded set of worker threads instead of spawning
/// a fresh OS thread per chunk handoff.
#[test]
fn n_repeated_handoffs_reuse_bounded_worker_pool_threads() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(1);
    let mut thread_ids = HashSet::new();
    runtime.block_on(async {
        for _ in 0..32 {
            let id = executor
                .run(|_permit| Ok::<_, std::io::Error>(std::thread::current().id()))
                .await
                .expect("pooled handoff succeeds");
            thread_ids.insert(id);
        }
    });
    assert_eq!(
        thread_ids.len(),
        1,
        "limit=1 file transfer pool must reuse one worker thread across 32 handoffs, observed {} threads",
        thread_ids.len()
    );
}

/// Negative — a pool bounded to 2 threads never exceeds 2 OS threads under concurrency and keeps
/// its worker alive after a panicking job.
#[test]
fn n_pool_bounds_threads_under_concurrency_and_survives_panic() {
    let runtime = one_worker_runtime();
    let executor = BlockingFileTransferExecutor::new(2);
    let observed = runtime.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let exec = executor.clone();
            set.spawn(async move {
                exec.run(|_permit| Ok::<_, std::io::Error>(std::thread::current().id()))
                    .await
                    .expect("concurrent pooled job succeeds")
            });
        }
        let mut ids = HashSet::new();
        while let Some(res) = set.join_next().await {
            ids.insert(res.expect("task joins"));
        }
        let panic_err = executor
            .run(|_permit| -> std::io::Result<()> { panic!("worker must survive") })
            .await
            .expect_err("panic maps to io::Error");
        assert_eq!(panic_err.kind(), std::io::ErrorKind::Other);
        for _ in 0..8 {
            let id = executor
                .run(|_permit| Ok::<_, std::io::Error>(std::thread::current().id()))
                .await
                .expect("pool serves work after panic");
            ids.insert(id);
        }
        ids
    });
    assert!(
        !observed.is_empty() && observed.len() <= 2,
        "pool bounded to 2 must never spawn more than 2 worker threads, observed {}",
        observed.len()
    );
}

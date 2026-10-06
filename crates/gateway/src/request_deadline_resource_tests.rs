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

//! Responsible for: measuring operating-system threads retained after policy completion or cancellation.
//! NOT responsible for: elapsed-time performance or a gateway-owned resource counter.
//! Upstream: the private policy deadline. Downstream: isolated libtest subprocesses.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::future::Future;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use super::policy_snapshot_with_timeout;
use crate::clock::{MonotonicClock, SystemMonotonic};
use crate::ext::{PolicyError, PolicySnapshot, PolicySource};
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::Identity;

const CHILD: &str = "GATEWAY_POLICY_TIMER_RESOURCE_CHILD";
const READS: usize = 16;
// The private helper accepts any duration. A long timer keeps the resource observer independent
// of scheduling noise; the public PolicyTimeout still limits deployments to five seconds.
const TIMEOUT: Duration = Duration::from_secs(60);

enum Read {
    Ready,
    YieldOnce,
    Pending,
}

impl PolicySource for Read {
    fn snapshot<'a>(&'a self, _: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        let mut yielded = false;
        Box::pin(std::future::poll_fn(move |context| match self {
            Self::Ready => Poll::Ready(Ok(PolicySnapshot::empty())),
            Self::YieldOnce if yielded => Poll::Ready(Ok(PolicySnapshot::empty())),
            Self::YieldOnce => {
                yielded = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Self::Pending => Poll::Pending,
        }))
    }
}

fn isolated(name: &str, run: impl FnOnce()) {
    if std::env::var(CHILD).as_deref() == Ok(name) {
        run();
        return;
    }
    let test = format!("request_deadline::resource_tests::{name}");
    let output = Command::new(std::env::current_exe().expect("the test executable exists"))
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .output()
        .expect("the isolated test process starts");
    assert!(
        output.status.success(),
        "isolated resource observation failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let observed = String::from_utf8_lossy(&output.stdout);
    assert!(
        observed.contains(&format!("test {test} ... ok")),
        "the isolated process did not run {test}: {observed}"
    );
    print!("{observed}");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}

fn threads() -> Option<usize> {
    #[cfg(target_os = "linux")]
    let count = std::fs::read_dir("/proc/self/task")
        .expect("Linux exposes the current process's tasks")
        .inspect(|entry| {
            entry.as_ref().expect("a task entry is readable");
        })
        .count();
    #[cfg(target_os = "macos")]
    let count = {
        let output = Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
            .expect("macOS provides ps");
        assert!(output.status.success(), "ps could not observe the current process");
        String::from_utf8(output.stdout)
            .expect("ps emits UTF-8 task rows")
            .lines()
            .skip(1)
            .count()
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        assert!(count > 0, "the resource observer must see the process's own threads");
        Some(count)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        println!("SKIP: an operating-system thread observer is available only on Linux and macOS");
        None
    }
}

fn baseline(context: &mut Context<'_>) -> Option<usize> {
    // Warm the existing shared timer before counting. Its one process-wide worker belongs in
    // both controls; only workers retained by individual completed reads are a regression.
    let mut warm = Box::pin(futures_timer::Delay::new(TIMEOUT));
    assert!(warm.as_mut().poll(context).is_pending());
    drop(warm);
    threads()
}

fn wait_for_thread_count(
    expected: usize,
    mut observe: impl FnMut() -> Option<usize>,
    mut retry: impl FnMut() -> bool,
) -> Option<usize> {
    loop {
        let observed = observe();
        if observed == Some(expected) || observed.is_none() || !retry() {
            return observed;
        }
    }
}

/// Positive — an already matching observation needs no settling delay.
#[test]
fn thread_wait_returns_an_immediate_match_without_retrying() {
    assert_eq!(
        wait_for_thread_count(3, || Some(3), || panic!("a matching observation must not wait")),
        Some(3)
    );
}

/// Positive — joined workers can remain visible until the kernel finishes removing their tasks.
#[test]
fn thread_wait_observes_late_task_removal() {
    let mut samples = [Some(7), Some(4), Some(3)].into_iter();
    let mut retries = 0;
    let observed = wait_for_thread_count(
        3,
        || samples.next().expect("stop at the matching observation"),
        || {
            retries += 1;
            assert!(retries <= 2, "the observer wait did not stop at its match");
            true
        },
    );
    assert_eq!((observed, retries), (Some(3), 2));
}

/// Negative — a worker that stays visible must not become an invented baseline on expiry.
#[test]
fn thread_wait_preserves_a_stuck_high_count_at_expiry() {
    let mut retries = 0;
    let observed = wait_for_thread_count(
        3,
        || Some(4),
        || {
            retries += 1;
            assert!(retries <= 3, "the observer wait ignored expiry");
            retries < 3
        },
    );
    assert_eq!((observed, retries), (Some(4), 3));
}

/// Negative — fewer threads than the baseline is not an exact match either.
#[test]
fn thread_wait_preserves_a_stuck_low_count_at_expiry() {
    let mut retries = 0;
    let observed = wait_for_thread_count(
        3,
        || Some(2),
        || {
            retries += 1;
            assert!(retries <= 1, "the observer wait ignored expiry");
            false
        },
    );
    assert_eq!((observed, retries), (Some(2), 1));
}

/// Negative — loss of the measurement is neither a match nor a reason to keep polling.
#[test]
fn thread_wait_preserves_an_unavailable_observer() {
    assert_eq!(
        wait_for_thread_count(3, || None, || panic!("an unavailable observation must stay unavailable")),
        None
    );
}

/// Negative — a later unavailable measurement cannot fall back to an earlier count.
#[test]
fn thread_wait_does_not_reuse_a_count_after_observation_is_lost() {
    let mut samples = [Some(4), None].into_iter();
    let mut retries = 0;
    let observed = wait_for_thread_count(
        3,
        || samples.next().expect("stop when the observer is lost"),
        || {
            retries += 1;
            assert!(retries <= 1, "the observer wait retried an unavailable measurement");
            true
        },
    );
    assert_eq!((observed, retries), (None, 1));
}

/// Negative — a positive but stuck observer must fail to see both held workers and their exit.
#[test]
fn thread_observer_tracks_held_workers_and_their_release() {
    isolated("thread_observer_tracks_held_workers_and_their_release", || {
        const COHORT: usize = 4;
        let mut context = Context::from_waker(Waker::noop());
        let Some(before) = baseline(&mut context) else { return };
        let entered = Arc::new(Barrier::new(COHORT + 1));
        let release = Arc::new(Barrier::new(COHORT + 1));
        let workers: Vec<_> = (0..COHORT)
            .map(|_| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                std::thread::spawn(move || {
                    entered.wait();
                    release.wait();
                })
            })
            .collect();
        entered.wait();
        let held = threads();
        release.wait();
        for worker in workers {
            worker.join().expect("the held worker exits after release");
        }
        // Linux clears the TID that wakes joiners before removing the task from the thread list:
        // <https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c#L926-L959>.
        // Wait for the OS observation itself; a retained worker still fails the exact count below.
        let wait_clock = SystemMonotonic::new();
        let joined = wait_for_thread_count(before, threads, || {
            if wait_clock.monotonic().millis() >= 1_000 {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
            true
        });
        eprintln!("thread observer: baseline={before}, held={held:?}, joined={joined:?}");
        assert_eq!(held, Some(before + COHORT), "the observer did not see the synchronized held workers");
        assert_eq!(joined, Some(before), "the observer did not see the joined workers exit");
    });
}

/// Positive control — a snapshot already in hand does not arm the policy timer.
#[test]
fn immediately_ready_policy_reads_do_not_accumulate_threads() {
    isolated("immediately_ready_policy_reads_do_not_accumulate_threads", || {
        let mut context = Context::from_waker(Waker::noop());
        let Some(before) = baseline(&mut context) else { return };
        for _ in 0..READS {
            let mut read = Box::pin(policy_snapshot_with_timeout(&Read::Ready, None, TIMEOUT));
            assert!(matches!(read.as_mut().poll(&mut context), Poll::Ready(Some(Ok(_)))));
        }
        assert_eq!(threads(), Some(before), "immediately ready policy reads retained timer threads");
    });
}

/// Negative — a successful snapshot after one pending poll cannot retain a per-read worker.
#[test]
fn completed_policy_reads_do_not_accumulate_threads() {
    isolated("completed_policy_reads_do_not_accumulate_threads", || {
        let mut context = Context::from_waker(Waker::noop());
        let Some(before) = baseline(&mut context) else { return };
        for _ in 0..READS {
            let mut read = Box::pin(policy_snapshot_with_timeout(&Read::YieldOnce, None, TIMEOUT));
            assert!(read.as_mut().poll(&mut context).is_pending());
            assert!(matches!(read.as_mut().poll(&mut context), Poll::Ready(Some(Ok(_)))));
        }
        assert_eq!(threads(), Some(before), "completed policy reads retained timer threads");
    });
}

/// Negative — dropping a still-pending policy read cannot retain a per-read worker either.
#[test]
fn dropping_pending_policy_reads_does_not_accumulate_threads() {
    isolated("dropping_pending_policy_reads_does_not_accumulate_threads", || {
        let mut context = Context::from_waker(Waker::noop());
        let Some(before) = baseline(&mut context) else { return };
        for _ in 0..READS {
            let mut read = Box::pin(policy_snapshot_with_timeout(&Read::Pending, None, TIMEOUT));
            assert!(read.as_mut().poll(&mut context).is_pending());
            drop(read);
        }
        assert_eq!(threads(), Some(before), "dropped policy reads retained timer threads");
    });
}

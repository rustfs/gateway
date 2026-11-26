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

//! Listener-scoped tracking for detached peer-loss cleanup and HTTP/2 stream tasks.
//!
//! Responsible for: spawning background tasks outside `connections: JoinSet<()>`, self-reaping
//! completed handles without retaining memory, awaiting idle drain during graceful shutdown, and
//! aborting remaining tasks when the shutdown grace budget expires.
//! NOT responsible for: connection admission permits, request capacity permits, or file-transfer
//! OS threads (`sendfile_task`).
//! Upstream: `conn` listener lifecycle, `request_capacity`, and `send_deadline`. Downstream: Tokio.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::AbortHandle;

/// Tracks listener-owned background tasks that execute outside the main connection `JoinSet`.
#[derive(Clone, Default)]
pub(crate) struct TaskTracker {
    inner: Arc<TrackerInner>,
}

#[derive(Default)]
struct TrackerInner {
    state: Mutex<TrackerState>,
    idle: Notify,
}

#[derive(Default)]
struct TrackerState {
    next_id: u64,
    active: usize,
    aborted: bool,
    handles: HashMap<u64, AbortHandle>,
}

impl std::fmt::Debug for TaskTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = lock_recover(&self.inner.state);
        f.debug_struct("TaskTracker")
            .field("active", &state.active)
            .field("aborted", &state.aborted)
            .finish()
    }
}

impl TaskTracker {
    /// Spawns `future` onto the current Tokio runtime and tracks it until its future has dropped.
    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if let Ok(runtime) = Handle::try_current() {
            self.spawn_on(&runtime, future);
        }
    }

    /// Spawns `future` onto `runtime` and tracks it until its future has dropped.
    ///
    /// If [`Self::abort_all`] has already been called, `future` is dropped immediately without
    /// spawning.
    pub(crate) fn spawn_on<F>(&self, runtime: &Handle, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = lock_recover(&self.inner.state);
        if state.aborted {
            drop(state);
            drop(future);
            return;
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.active = state.active.saturating_add(1);
        let guard = TaskGuard {
            inner: Arc::clone(&self.inner),
            id,
        };
        let handle = runtime.spawn(TrackedFuture { future, _guard: guard });
        state.handles.insert(id, handle.abort_handle());
    }

    /// Waits until every tracked task has finished and dropped its future.
    pub(crate) async fn wait_idle(&self) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if lock_recover(&self.inner.state).active == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Prevents future spawns, aborts every active tracked task, and waits until all have dropped.
    pub(crate) async fn abort_all(&self) {
        let handles: Vec<AbortHandle> = {
            let mut state = lock_recover(&self.inner.state);
            state.aborted = true;
            state.handles.drain().map(|(_, handle)| handle).collect()
        };
        for handle in handles {
            handle.abort();
        }
        self.wait_idle().await;
    }

    #[cfg(test)]
    fn active_and_retained(&self) -> (usize, usize) {
        let state = lock_recover(&self.inner.state);
        (state.active, state.handles.len())
    }
}

pin_project! {
    /// Guarantees `future` is dropped before `_guard` (Rust field declaration drop order), so a
    /// `Drop` implementation inside `future` that spawns another tracked task increments `active`
    /// before this task decrements it.
    struct TrackedFuture<F> {
        #[pin]
        future: F,
        _guard: TaskGuard,
    }
}

impl<F: Future<Output = ()>> Future for TrackedFuture<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        self.project().future.poll(context)
    }
}

struct TaskGuard {
    inner: Arc<TrackerInner>,
    id: u64,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        let notify = {
            let mut state = lock_recover(&self.inner.state);
            state.handles.remove(&self.id);
            state.active = state.active.saturating_sub(1);
            state.active == 0
        };
        if notify {
            self.inner.idle.notify_waiters();
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::TaskTracker;

    struct SpawnOnDrop {
        tracker: TaskTracker,
        active_during_drop: Arc<std::sync::atomic::AtomicUsize>,
        child_started: Arc<Notify>,
        child_release: Arc<Notify>,
        child_finished: Arc<AtomicBool>,
    }

    impl Drop for SpawnOnDrop {
        fn drop(&mut self) {
            self.active_during_drop
                .store(self.tracker.active_and_retained().0, Ordering::SeqCst);
            let started = Arc::clone(&self.child_started);
            let release = Arc::clone(&self.child_release);
            let finished = Arc::clone(&self.child_finished);
            self.tracker.spawn(async move {
                started.notify_one();
                release.notified().await;
                finished.store(true, Ordering::SeqCst);
            });
        }
    }

    struct ReadyWithDropHook {
        _hook: SpawnOnDrop,
    }

    impl std::future::Future for ReadyWithDropHook {
        type Output = ();

        fn poll(self: std::pin::Pin<&mut Self>, _context: &mut std::task::Context<'_>) -> std::task::Poll<()> {
            std::task::Poll::Ready(())
        }
    }

    /// Positive — completed and panicked tasks self-reap without leaking retained handles.
    #[tokio::test]
    async fn completed_and_panicked_tasks_self_reap_without_retaining_handles() {
        let tracker = TaskTracker::default();
        for index in 0..50 {
            tracker.spawn(async move {
                if index % 5 == 0 {
                    panic!("deliberate tracked task panic");
                }
            });
        }
        tokio::time::timeout(Duration::from_secs(2), tracker.wait_idle())
            .await
            .expect("all tracked tasks finish");
        assert_eq!(tracker.active_and_retained(), (0, 0));
    }

    /// Negative — a task whose `Future::drop` spawns a follow-up tracked task must not let
    /// `wait_idle` observe a transient zero count before the follow-up task completes.
    #[tokio::test]
    async fn n_nested_spawn_during_drop_keeps_wait_idle_blocked_until_child_finishes() {
        let tracker = TaskTracker::default();
        let active_during_drop = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let child_started = Arc::new(Notify::new());
        let child_release = Arc::new(Notify::new());
        let child_finished = Arc::new(AtomicBool::new(false));

        let wait_tracker = tracker.clone();
        let parent_tracker = tracker.clone();
        let active_slot = Arc::clone(&active_during_drop);
        let started = Arc::clone(&child_started);
        let release = Arc::clone(&child_release);
        let finished = Arc::clone(&child_finished);
        tracker.spawn(ReadyWithDropHook {
            _hook: SpawnOnDrop {
                tracker: parent_tracker,
                active_during_drop: active_slot,
                child_started: started,
                child_release: release,
                child_finished: finished,
            },
        });
        let mut wait = tokio::spawn(async move {
            wait_tracker.wait_idle().await;
        });

        tokio::time::timeout(Duration::from_secs(2), child_started.notified())
            .await
            .expect("child task spawned during parent future drop");
        assert!(
            active_during_drop.load(Ordering::SeqCst) >= 1,
            "parent TaskGuard dropped before its Future dropped, exposing a zero-active gap"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut wait).await.is_err(),
            "wait_idle completed before child task spawned in drop finished"
        );
        assert!(!child_finished.load(Ordering::SeqCst));

        child_release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), wait)
            .await
            .expect("wait_idle finishes after child completes")
            .expect("wait task joins");
        assert!(child_finished.load(Ordering::SeqCst));
        assert_eq!(tracker.active_and_retained(), (0, 0));
    }

    /// Negative — once `abort_all` runs, active tasks are aborted and later spawns are rejected.
    #[tokio::test]
    async fn n_abort_all_cancels_active_tasks_and_rejects_late_spawns() {
        let tracker = TaskTracker::default();
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        struct MarkDrop(Arc<AtomicBool>);
        impl Drop for MarkDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let entered_clone = Arc::clone(&entered);
        let dropped_clone = Arc::clone(&dropped);
        tracker.spawn(async move {
            let _mark = MarkDrop(dropped_clone);
            entered_clone.notify_one();
            std::future::pending::<()>().await;
        });
        entered.notified().await;

        tokio::time::timeout(Duration::from_secs(2), tracker.abort_all())
            .await
            .expect("abort_all finishes");
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(tracker.active_and_retained(), (0, 0));

        let late_ran = Arc::new(AtomicBool::new(false));
        let late_flag = Arc::clone(&late_ran);
        tracker.spawn(async move {
            late_flag.store(true, Ordering::SeqCst);
        });
        tokio::task::yield_now().await;
        assert!(!late_ran.load(Ordering::SeqCst), "late spawn after abort_all must not run");
        assert_eq!(tracker.active_and_retained(), (0, 0));
    }
}

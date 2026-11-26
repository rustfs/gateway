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

//! Bounded reusable worker pool for file-transfer calls that may wait on storage.
//!
//! Responsible for: keeping blocking file work off Tokio workers on a bounded set of reusable
//! OS worker threads, limiting concurrency, refusing late work and tracking detached jobs through
//! listener drain.
//! NOT responsible for: choosing the progress deadline, socket readiness or sendfile retry policy.
//! Upstream: plaintext file-region response I/O. Downstream: bounded OS worker threads.

use std::collections::VecDeque;
use std::io;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;

use crate::io::deadline_reached;

type BoxedJob = Box<dyn FnOnce() + Send + 'static>;

struct PoolState {
    queue: VecDeque<BoxedJob>,
    spawned: usize,
    idle: usize,
    closed: bool,
}

struct WorkerPoolInner {
    limit: usize,
    state: Mutex<PoolState>,
    available: Condvar,
}

struct WorkerPoolHandle {
    inner: Arc<WorkerPoolInner>,
}

impl WorkerPoolHandle {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(WorkerPoolInner {
                limit,
                state: Mutex::new(PoolState {
                    queue: VecDeque::new(),
                    spawned: 0,
                    idle: 0,
                    closed: false,
                }),
                available: Condvar::new(),
            }),
        })
    }

    fn submit(&self, job: BoxedJob) -> io::Result<()> {
        let should_spawn = {
            let mut state = self.inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed {
                return Err(io::Error::other("blocking file transfer worker pool is closed"));
            }
            state.queue.push_back(job);
            let need_worker = state.idle < state.queue.len() && state.spawned < self.inner.limit;
            if need_worker {
                state.spawned = state.spawned.saturating_add(1);
            }
            self.inner.available.notify_one();
            need_worker
        };
        if should_spawn {
            let inner = Arc::clone(&self.inner);
            if let Err(error) = std::thread::Builder::new()
                .name("gateway-file-transfer".to_owned())
                .spawn(move || worker_loop(inner))
            {
                let mut state = self.inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                state.spawned = state.spawned.saturating_sub(1);
                if state.spawned == 0 {
                    let _ = state.queue.pop_back();
                    return Err(io::Error::other(format!("blocking file transfer thread failed to start: {error}")));
                }
            }
        }
        Ok(())
    }
}

impl Drop for WorkerPoolHandle {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        self.inner.available.notify_all();
    }
}

fn worker_loop(inner: Arc<WorkerPoolInner>) {
    loop {
        let job = {
            let mut state = inner.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(job) = state.queue.pop_front() {
                    break job;
                }
                if state.closed {
                    state.spawned = state.spawned.saturating_sub(1);
                    return;
                }
                state.idle = state.idle.saturating_add(1);
                state = inner.available.wait(state).unwrap_or_else(std::sync::PoisonError::into_inner);
                state.idle = state.idle.saturating_sub(1);
            }
        };
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)) {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(payload)));
        }
    }
}

#[derive(Clone)]
pub(crate) struct BlockingFileTransferExecutor {
    capacity: Arc<Semaphore>,
    activity: Arc<Semaphore>,
    workers: Arc<WorkerPoolHandle>,
    limit: u32,
}

pub(crate) struct BlockingFileTransferPermit {
    _not_send: PhantomData<Rc<()>>,
}

pub(crate) struct BlockingFileTransferReservation {
    capacity: OwnedSemaphorePermit,
    activity: OwnedSemaphorePermit,
    workers: Arc<WorkerPoolHandle>,
}

static PROCESS_FILE_TRANSFER_CAPACITY: OnceLock<(Arc<Semaphore>, Arc<WorkerPoolHandle>, u32)> = OnceLock::new();

impl BlockingFileTransferExecutor {
    pub(crate) fn for_listener() -> Self {
        let (capacity, workers, limit) = PROCESS_FILE_TRANSFER_CAPACITY.get_or_init(|| {
            let limit = std::thread::available_parallelism().map_or(2, usize::from).clamp(2, 32);
            let limit_u32 = u32::try_from(limit).unwrap_or(32);
            let capacity = usize::try_from(limit_u32).unwrap_or(Semaphore::MAX_PERMITS);
            (Arc::new(Semaphore::new(capacity)), WorkerPoolHandle::new(capacity), limit_u32)
        });
        Self {
            capacity: Arc::clone(capacity),
            activity: Arc::new(Semaphore::new(usize::try_from(*limit).unwrap_or(Semaphore::MAX_PERMITS))),
            workers: Arc::clone(workers),
            limit: *limit,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(limit: u32) -> Self {
        assert!(limit > 0, "blocking file transfer limit must be greater than zero");
        let capacity = usize::try_from(limit).unwrap_or(Semaphore::MAX_PERMITS);
        assert!(
            capacity <= Semaphore::MAX_PERMITS,
            "blocking file transfer limit exceeds Tokio's semaphore maximum"
        );
        Self {
            capacity: Arc::new(Semaphore::new(capacity)),
            activity: Arc::new(Semaphore::new(capacity)),
            workers: WorkerPoolHandle::new(capacity),
            limit,
        }
    }

    pub(crate) async fn wait_idle(&self) {
        if let Ok(permits) = Arc::clone(&self.activity).acquire_many_owned(self.limit).await {
            drop(permits);
        }
    }

    #[cfg(test)]
    pub(crate) async fn run<T, F>(&self, job: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(BlockingFileTransferPermit) -> io::Result<T> + Send + 'static,
    {
        let activity = Arc::clone(&self.activity)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("blocking file transfer executor is closed"))?;
        let capacity = Arc::clone(&self.capacity)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("blocking file transfer executor is closed"))?;
        Self::submit(&self.workers, capacity, activity, None, job).await
    }

    #[cfg(test)]
    pub(crate) async fn run_until<T, F>(&self, deadline: Instant, job: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(BlockingFileTransferPermit) -> io::Result<T> + Send + 'static,
    {
        self.reserve_until(deadline).await?.run_until(deadline, job).await
    }

    pub(crate) async fn reserve_until(&self, deadline: Instant) -> io::Result<BlockingFileTransferReservation> {
        let activity = tokio::time::timeout_at(deadline, Arc::clone(&self.activity).acquire_owned())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "blocking file transfer queue made no progress"))?
            .map_err(|_| io::Error::other("blocking file transfer executor is closed"))?;
        let capacity = tokio::time::timeout_at(deadline, Arc::clone(&self.capacity).acquire_owned())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "blocking file transfer queue made no progress"))?
            .map_err(|_| io::Error::other("blocking file transfer executor is closed"))?;
        Ok(BlockingFileTransferReservation {
            capacity,
            activity,
            workers: Arc::clone(&self.workers),
        })
    }

    async fn submit<T, F>(
        workers: &WorkerPoolHandle,
        capacity: OwnedSemaphorePermit,
        activity: OwnedSemaphorePermit,
        deadline: Option<Instant>,
        job: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(BlockingFileTransferPermit) -> io::Result<T> + Send + 'static,
    {
        let (result_sender, result_receiver) = oneshot::channel();
        workers.submit(Box::new(move || {
            let _capacity = capacity;
            let _activity = activity;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                if deadline.is_some_and(deadline_reached) {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "blocking file transfer did not start before its write deadline",
                    ))
                } else {
                    job(BlockingFileTransferPermit { _not_send: PhantomData })
                }
            }));
            match outcome {
                Ok(result) => {
                    let _ = result_sender.send(result);
                }
                Err(payload) => {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(payload)));
                    let _ = result_sender.send(Err(io::Error::other("blocking file transfer worker panicked")));
                }
            }
        }))?;
        let received = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, result_receiver)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "blocking file transfer exceeded its write deadline"))?,
            None => result_receiver.await,
        };
        received.map_err(|_| io::Error::other("blocking file transfer thread failed"))?
    }
}

impl BlockingFileTransferReservation {
    pub(crate) async fn run_until<T, F>(self, deadline: Instant, job: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(BlockingFileTransferPermit) -> io::Result<T> + Send + 'static,
    {
        BlockingFileTransferExecutor::submit(&self.workers, self.capacity, self.activity, Some(deadline), job).await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // Test-only synchronization and deliberate panic injection must terminate the scenario.
#[path = "sendfile_task_tests.rs"]
mod tests;

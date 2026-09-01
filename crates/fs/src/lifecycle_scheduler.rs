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

//! Bounded background lifecycle scheduling for the filesystem reference backend.
//!
//! Responsible for: invoking the one-shot lifecycle executor at the configured cadence, retaining
//! failure counts without killing the worker, and joining after an explicit shutdown.
//! Not responsible for: CLI parsing, transition actions, or the expiration decision itself.
//! Upstream: `FsBackend` debug cadence. Downstream: the reference SUT listener.

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::FsBackend;

struct SchedulerLease(Arc<FsBackend>);

impl Drop for SchedulerLease {
    fn drop(&mut self) {
        self.0.lifecycle_scheduler_running.store(false, Ordering::Release);
    }
}

/// Final observations from one lifecycle scheduler run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LifecycleSchedulerReport {
    /// Number of scheduled sweeps that reached the one-shot executor.
    pub sweeps: u64,
    /// Total current objects expired by successful sweeps.
    pub expired_objects: u64,
    /// Number of sweeps that failed closed.
    pub failed_sweeps: u64,
}

/// An owned shutdown and join handle for one filesystem lifecycle scheduler.
pub struct LifecycleScheduler {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<LifecycleSchedulerReport>>,
}

impl LifecycleScheduler {
    /// Stops scheduling new sweeps and waits for any in-progress sweep to finish.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the scheduler task was cancelled or panicked.
    pub async fn shutdown(mut self) -> io::Result<LifecycleSchedulerReport> {
        self.signal_shutdown();
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("the lifecycle scheduler task is absent"))?;
        task.await
            .map_err(|_| io::Error::other("the lifecycle scheduler task did not finish cleanly"))
    }

    fn signal_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _already_stopped = shutdown.send(());
        }
    }
}

impl Drop for LifecycleScheduler {
    fn drop(&mut self) {
        self.signal_shutdown();
    }
}

impl FsBackend {
    /// Starts a lifecycle worker that waits one configured interval before each sweep.
    ///
    /// A failed sweep is recorded and the next cadence is still attempted. Dropping the returned
    /// handle requests shutdown; callers that need a completion boundary should call
    /// [`LifecycleScheduler::shutdown`].
    ///
    /// # Errors
    ///
    /// Returns an I/O error when called outside a Tokio runtime.
    pub fn start_lifecycle_scheduler(self: &Arc<Self>) -> io::Result<LifecycleScheduler> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("the lifecycle scheduler requires an active Tokio runtime"))?;
        self.lifecycle_scheduler_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "a lifecycle scheduler is already running"))?;
        let lease = SchedulerLease(Arc::clone(self));
        let interval = self.lifecycle_sweep_interval;
        let (shutdown, mut shutdown_requested) = oneshot::channel();
        let task = runtime.spawn(async move {
            let mut report = LifecycleSchedulerReport::default();
            loop {
                tokio::select! {
                    () = tokio::time::sleep(interval) => {
                        report.sweeps = report.sweeps.saturating_add(1);
                        match lease.0.expire_lifecycle_once().await {
                            Ok(expired) => {
                                let expired = u64::try_from(expired).unwrap_or(u64::MAX);
                                report.expired_objects = report.expired_objects.saturating_add(expired);
                            }
                            Err(_) => report.failed_sweeps = report.failed_sweeps.saturating_add(1),
                        }
                    }
                    _ = &mut shutdown_requested => break,
                }
            }
            report
        });
        Ok(LifecycleScheduler {
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
}

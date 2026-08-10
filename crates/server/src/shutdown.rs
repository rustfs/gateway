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

//! Explicit shutdown command, report and observable counters.
//!
//! Responsible for: carrying the grace deadline into the accept loop and returning exact counts.
//! NOT responsible for: dropping listeners or driving Hyper; `conn` owns those transitions.
//! Upstream: the caller. Downstream: the server task.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::ServerError;

/// Counts requests that drained or were forcibly aborted after shutdown began.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Requests that were in flight and completed during the grace period.
    pub drained: usize,
    /// Requests still in flight when the grace deadline forced task cancellation.
    pub aborted: usize,
}

/// One-shot explicit shutdown capability.
pub struct ShutdownTrigger {
    pub(crate) sender: oneshot::Sender<ShutdownCommand>,
}

impl ShutdownTrigger {
    /// Stops accept, asks established HTTP connections to drain, then aborts at `grace`.
    #[must_use = "shutdown does not run until the returned future is awaited"]
    pub async fn trigger(self, grace: Duration) -> ShutdownReport {
        let (reply, receiver) = oneshot::channel();
        if self.sender.send(ShutdownCommand { grace, reply }).is_err() {
            return ShutdownReport::default();
        }
        receiver.await.unwrap_or_default()
    }
}

pub(crate) struct ShutdownCommand {
    pub(crate) grace: Duration,
    pub(crate) reply: oneshot::Sender<ShutdownReport>,
}

/// Live, monotonic counters for deterministic admission assertions and operations.
#[derive(Clone, Default)]
pub struct ServerMetrics {
    pub(crate) inner: Arc<MetricsInner>,
}

#[derive(Default)]
pub(crate) struct MetricsInner {
    pub(crate) accepted: AtomicUsize,
    pub(crate) active: AtomicUsize,
    pub(crate) per_ip_rejected: AtomicUsize,
}

impl ServerMetrics {
    /// Number of sockets accepted from the kernel since startup.
    #[must_use]
    pub fn accepted_connections(&self) -> usize {
        self.inner.accepted.load(Ordering::Relaxed)
    }

    /// Number of accepted connections that still own admission permits.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.inner.active.load(Ordering::Relaxed)
    }

    /// Number of accepted sockets rejected by the per-IP limit before TLS.
    #[must_use]
    pub fn per_ip_rejections(&self) -> usize {
        self.inner.per_ip_rejected.load(Ordering::Relaxed)
    }
}

/// A started server and the explicit capability required to stop it.
pub struct RunningServer {
    /// Kernel-selected listening address.
    pub local_addr: SocketAddr,
    /// Server task. A clean explicit shutdown resolves it to `Ok(())`.
    pub task: JoinHandle<Result<(), ServerError>>,
    /// One-shot shutdown capability; dropping it does not stop the server.
    pub shutdown: ShutdownTrigger,
    /// Observable admission counters.
    pub metrics: ServerMetrics,
}

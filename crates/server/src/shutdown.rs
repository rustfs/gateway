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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    pub(crate) accept_errors: AtomicUsize,
    /// Written by the accept loop, the only owner of the task set it measures.
    pub(crate) connection_tasks: AtomicUsize,
    /// Shared with every connection's `ProgressIo`, which is where the octets are discarded.
    pub(crate) lingering_drained: Arc<AtomicU64>,
    /// Shared with every connection's `ProgressIo`; counts every octet it reads, drain included.
    pub(crate) transport_read: Arc<AtomicU64>,
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

    /// Number of accepted sockets rejected by the per-IP limit before TLS; a client there is one
    /// IPv4 address or one IPv6 `/64`.
    #[must_use]
    pub fn per_ip_rejections(&self) -> usize {
        self.inner.per_ip_rejected.load(Ordering::Relaxed)
    }

    /// Number of failed `accept` calls the listener survived: connections that failed while
    /// queued, accepted sockets with no usable peer address, and descriptor or memory shortages
    /// it waited out. A failure that ends the listener is returned by the server task instead.
    #[must_use]
    pub fn accept_errors(&self) -> usize {
        self.inner.accept_errors.load(Ordering::Relaxed)
    }

    /// Connection tasks the listener still holds a handle to, finished or not, as of the accept
    /// loop's last look at its task set.
    ///
    /// A connection's task keeps its entry after the connection closes until the listener joins
    /// it. This is the count of those entries, so it is the memory the listener retains per
    /// connection: it settles to [`ServerMetrics::active_connections`] once finished tasks are
    /// joined, and a value that keeps growing past it is a leak. See rustfs/gateway#1208.
    #[must_use]
    pub fn retained_connection_tasks(&self) -> usize {
        self.inner.connection_tasks.load(Ordering::Relaxed)
    }

    /// Octets read and discarded by the lingering close, summed over every connection.
    ///
    /// This is the *server's* count of what the drain accepted, and it exists because nothing
    /// else here is. A client's own `write()` returns once the octets are in its send buffer, not
    /// once this process has read them, and a send buffer the kernel auto-tunes into the megabytes
    /// can absorb a whole body while the drain reads nothing — so "the peer got its body out" is
    /// not an observation of the drain, in either direction. See rustfs/gateway#274.
    ///
    /// Counted where the octets are discarded, so it excludes everything the request parser read
    /// before the refusal was written: it is what the linger accepted and nothing else.
    #[must_use]
    pub fn lingering_octets_drained(&self) -> u64 {
        self.inner.lingering_drained.load(Ordering::Relaxed)
    }

    /// Octets read off accepted transports, summed over every connection.
    ///
    /// Everything [`ServerMetrics::lingering_octets_drained`] counts, plus everything the request
    /// parser read before it. The pair is what makes "the peer's whole request was accepted" an
    /// exact statement without having to know how much of a body the parser happened to buffer
    /// alongside a head.
    #[must_use]
    pub fn transport_octets_read(&self) -> u64 {
        self.inner.transport_read.load(Ordering::Relaxed)
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

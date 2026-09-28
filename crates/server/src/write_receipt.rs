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

//! Responsible for: counting a response as drained at shutdown only when the transport has
//! confirmed its bytes reached the socket, not when the response body handed over its final frame.
//! NOT responsible for: request capacity or connection idleness (both are released when the final
//! frame is handed over), or the self-held driver, which reports its own completed writes through
//! `ResponseCompletion::complete`. Upstream: `ConnectionBody` hands a response over; `ProgressIo`
//! reports flushes and the half-close; `run_connection` reports a clean connection end.
//! Downstream: `RequestStats`' drained and aborted counts in the `ShutdownReport`.
//!
//! # What confirms a write
//!
//! HTTP/1.1: Hyper encodes a body frame into its write buffer in the same poll that takes it, and
//! calls the transport's `poll_flush` only after that buffer has been written. A successful flush
//! therefore confirms every response handed over before it. A successful half-close or a clean
//! connection end confirms everything.
//!
//! HTTP/2: h2 queues DATA behind flow control, so a flush confirms nothing about a given stream,
//! and Hyper 1.x exposes no per-stream write receipt. A response handed over after shutdown began
//! is confirmed only by the connection's clean end, which h2 reaches only after every stream's
//! frames are sent. One handed over before shutdown keeps the earlier behaviour and is not counted
//! either way, because nothing observable separates "written long ago" from "still queued".
//!
//! A response still unconfirmed when its connection is torn down after the grace expired counts
//! as aborted: its bytes were not all delivered (rustfs/gateway#657).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::connection_service::RequestStats;

/// Per-connection responses handed to the transport but not yet confirmed written.
pub(crate) struct WriteReceipts {
    stats: Arc<RequestStats>,
    until_flush: AtomicUsize,
    until_close: AtomicUsize,
}

impl WriteReceipts {
    pub(crate) fn new(stats: Arc<RequestStats>) -> Arc<Self> {
        Arc::new(Self {
            stats,
            until_flush: AtomicUsize::new(0),
            until_close: AtomicUsize::new(0),
        })
    }

    /// A response body handed its final frame to the transport.
    pub(crate) fn handed_over(&self, http2: bool) {
        if !http2 {
            self.until_flush.fetch_add(1, Ordering::AcqRel);
        } else if self.stats.is_shutting_down() {
            self.until_close.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// The transport flushed everything the HTTP/1.1 codec had written.
    pub(crate) fn flushed(&self) {
        self.credit(self.until_flush.swap(0, Ordering::AcqRel));
    }

    /// The write side is finished: shut down, or the connection ended cleanly.
    pub(crate) fn closed(&self) {
        self.flushed();
        self.credit(self.until_close.swap(0, Ordering::AcqRel));
    }

    fn credit(&self, confirmed: usize) {
        if confirmed > 0 && self.stats.is_shutting_down() {
            self.stats.add_drained(confirmed);
        }
    }
}

impl Drop for WriteReceipts {
    fn drop(&mut self) {
        let unconfirmed = self.until_flush.load(Ordering::Acquire) + self.until_close.load(Ordering::Acquire);
        if unconfirmed > 0 && self.stats.force_abort.load(Ordering::Acquire) {
            self.stats.add_aborted(unconfirmed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipts() -> (Arc<RequestStats>, Arc<WriteReceipts>) {
        let stats = Arc::new(RequestStats::default());
        (Arc::clone(&stats), WriteReceipts::new(stats))
    }

    #[test]
    fn a_handed_over_response_is_not_drained_before_its_flush() {
        let (stats, receipts) = receipts();
        stats.begin_shutdown();
        receipts.handed_over(false);
        assert_eq!(stats.drained(), 0);
        receipts.flushed();
        assert_eq!(stats.drained(), 1);
    }

    #[test]
    fn a_flush_before_shutdown_is_not_a_drain() {
        let (stats, receipts) = receipts();
        receipts.handed_over(false);
        receipts.flushed();
        stats.begin_shutdown();
        receipts.closed();
        assert_eq!((stats.drained(), stats.aborted()), (0, 0));
    }

    #[test]
    fn a_flush_does_not_confirm_an_http2_response() {
        let (stats, receipts) = receipts();
        stats.begin_shutdown();
        receipts.handed_over(true);
        receipts.flushed();
        assert_eq!(stats.drained(), 0);
        receipts.closed();
        assert_eq!(stats.drained(), 1);
    }

    #[test]
    fn an_unconfirmed_response_torn_down_after_the_grace_is_aborted() {
        let (stats, receipts) = receipts();
        stats.begin_shutdown();
        receipts.handed_over(false);
        receipts.handed_over(true);
        stats.force_abort();
        drop(receipts);
        assert_eq!((stats.drained(), stats.aborted()), (0, 2));
    }

    #[test]
    fn an_unconfirmed_response_dropped_without_a_forced_abort_is_not_counted() {
        let (stats, receipts) = receipts();
        stats.begin_shutdown();
        receipts.handed_over(false);
        drop(receipts);
        assert_eq!((stats.drained(), stats.aborted()), (0, 0));
    }
}

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

//! The counters that make a lost zero-copy path observable.
//!
//! Responsible for: counting how often, and over how many bytes, a payload had to be adapted
//! between the pull and push models. A performance gate can then assert a behaviour — "this
//! transfer performed no adapting copy" — instead of a wall-clock number, which on a shared
//! runner is noise and will be muted within a month.
//! NOT responsible for: exporting anything. There is no metrics registry, no label set and no
//! exporter here; the server layer reads these counters and publishes them however it likes.
//! Upstream: `core::sync::atomic`. Downstream: `adapt`, `payload`, and the server layer.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::adapt::AdaptCost;
use crate::zero_copy::NoZeroCopy;

/// Counters for pull/push adaptation.
///
/// Every conversion between the two models takes a `&StreamMetrics` and records its cost. The
/// parameter is mandatory rather than optional so that an adaptation cannot be performed
/// without the cost being counted somewhere: an optional counter is a counter that is absent
/// exactly on the path nobody looked at.
#[derive(Debug, Default)]
pub struct StreamMetrics {
    adapt_copies_total: AtomicU64,
    adapt_copied_bytes_total: AtomicU64,
    adapt_buffers_total: AtomicU64,
    zero_copy_refusals_not_file_backed: AtomicU64,
    zero_copy_refusals_transport: AtomicU64,
    zero_copy_refusals_obligation: AtomicU64,
    zero_copy_refusals_tls: AtomicU64,
    zero_copy_refusals_http2: AtomicU64,
    zero_copy_refused_bytes_total: AtomicU64,
}

impl StreamMetrics {
    /// A fresh counter set, all at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the cost of one adaptation.
    pub fn record_adapt(&self, cost: &AdaptCost) {
        match cost {
            AdaptCost::Free => {}
            AdaptCost::Buffer { .. } => {
                self.adapt_buffers_total.fetch_add(1, Ordering::Relaxed);
            }
            AdaptCost::Copy { est_bytes } => {
                self.adapt_copies_total.fetch_add(1, Ordering::Relaxed);
                if let Some(bytes) = est_bytes {
                    self.adapt_copied_bytes_total.fetch_add(*bytes, Ordering::Relaxed);
                }
            }
        }
    }

    /// How many adaptations copied every byte through an intermediate buffer.
    ///
    /// This is the counter a performance gate asserts to be zero for a large transfer.
    #[must_use]
    pub fn adapt_copies_total(&self) -> u64 {
        self.adapt_copies_total.load(Ordering::Relaxed)
    }

    /// How many bytes those copying adaptations were expected to move.
    #[must_use]
    pub fn adapt_copied_bytes_total(&self) -> u64 {
        self.adapt_copied_bytes_total.load(Ordering::Relaxed)
    }

    /// How many adaptations needed an owned buffer without copying any byte twice.
    #[must_use]
    pub fn adapt_buffers_total(&self) -> u64 {
        self.adapt_buffers_total.load(Ordering::Relaxed)
    }

    /// Records one refusal of the kernel-side transfer path, attributed to its reason.
    ///
    /// The byte count is the size of the body that had to take the slow path, when it is known.
    /// Counting the refusals without the bytes would make a 4 KiB refusal and a 1 GiB refusal
    /// look alike, and only one of them is worth an operator's afternoon.
    pub fn record_zero_copy_refusal(&self, reason: NoZeroCopy, bytes: Option<u64>) {
        let counter = match reason {
            NoZeroCopy::NotFileBacked => &self.zero_copy_refusals_not_file_backed,
            NoZeroCopy::TransportLacksSendfile => &self.zero_copy_refusals_transport,
            NoZeroCopy::VerificationObligationPresent => &self.zero_copy_refusals_obligation,
            NoZeroCopy::TlsInPath => &self.zero_copy_refusals_tls,
            NoZeroCopy::Http2InPath => &self.zero_copy_refusals_http2,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = bytes {
            self.zero_copy_refused_bytes_total.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// How many times the kernel-side path was refused for this reason.
    #[must_use]
    pub fn zero_copy_refusals(&self, reason: NoZeroCopy) -> u64 {
        match reason {
            NoZeroCopy::NotFileBacked => self.zero_copy_refusals_not_file_backed.load(Ordering::Relaxed),
            NoZeroCopy::TransportLacksSendfile => self.zero_copy_refusals_transport.load(Ordering::Relaxed),
            NoZeroCopy::VerificationObligationPresent => self.zero_copy_refusals_obligation.load(Ordering::Relaxed),
            NoZeroCopy::TlsInPath => self.zero_copy_refusals_tls.load(Ordering::Relaxed),
            NoZeroCopy::Http2InPath => self.zero_copy_refusals_http2.load(Ordering::Relaxed),
        }
    }

    /// How many times the kernel-side path was refused, for any reason.
    #[must_use]
    pub fn zero_copy_refusals_total(&self) -> u64 {
        self.zero_copy_refusals_not_file_backed
            .load(Ordering::Relaxed)
            .saturating_add(self.zero_copy_refusals_transport.load(Ordering::Relaxed))
            .saturating_add(self.zero_copy_refusals_obligation.load(Ordering::Relaxed))
            .saturating_add(self.zero_copy_refusals_tls.load(Ordering::Relaxed))
            .saturating_add(self.zero_copy_refusals_http2.load(Ordering::Relaxed))
    }

    /// How many body bytes took the slow path because the kernel-side path was refused.
    #[must_use]
    pub fn zero_copy_refused_bytes_total(&self) -> u64 {
        self.zero_copy_refused_bytes_total.load(Ordering::Relaxed)
    }
}

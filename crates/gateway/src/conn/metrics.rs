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

//! Observations made by the facade-owned response transport.
//!
//! Responsible for: counting selected self-held connections, named response fallbacks, observed
//! copied-byte progress, and progress returned by kernel-transfer calls. NOT responsible for: payload
//! adaptation refusals, which remain owned by `rustfs-gateway-stream`. Upstream: the self-held
//! connection driver. Downstream: operators and deterministic transport controls.

use core::sync::atomic::{AtomicU64, Ordering};

/// Why a response left the preferred file-region kernel-transfer path.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseFallbackReason {
    /// The application response was not backed by a file region.
    NotFileBacked,
    /// The response bytes still require user-space observation before they reach the socket.
    VerificationRequired,
    /// The compiled target has no supported file-to-socket syscall backend.
    PlatformUnsupported,
}

/// Counters backed only by completed connection I/O observations.
#[derive(Debug, Default)]
pub struct ResponseTransportMetrics {
    selected_connections: AtomicU64,
    fallback_not_file_backed: AtomicU64,
    fallback_verification_required: AtomicU64,
    fallback_platform_unsupported: AtomicU64,
    copied_payload_bytes: AtomicU64,
    kernel_transfer_calls: AtomicU64,
    kernel_transferred_bytes: AtomicU64,
}

impl ResponseTransportMetrics {
    /// Creates an independent zeroed counter set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_selected_connection(&self) {
        self.selected_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_fallback(&self, reason: ResponseFallbackReason) {
        self.fallback_counter(reason).fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_copied_progress(&self, bytes: u64) {
        self.copied_payload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn record_kernel_progress(&self, bytes: u64) {
        self.kernel_transfer_calls.fetch_add(1, Ordering::Relaxed);
        self.kernel_transferred_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// How many accepted sockets selected the self-held driver.
    #[must_use]
    pub fn selected_connections(&self) -> u64 {
        read_counter(&self.selected_connections)
    }

    /// How many responses took one named fallback path.
    #[must_use]
    pub fn fallback_responses(&self, reason: ResponseFallbackReason) -> u64 {
        read_counter(self.fallback_counter(reason))
    }

    /// How many responses took any fallback path.
    #[must_use]
    pub fn fallback_responses_total(&self) -> u64 {
        read_counter(&self.fallback_not_file_backed)
            .saturating_add(read_counter(&self.fallback_verification_required))
            .saturating_add(read_counter(&self.fallback_platform_unsupported))
    }

    /// Payload bytes confirmed written through a copied response path.
    #[must_use]
    pub fn copied_payload_bytes(&self) -> u64 {
        read_counter(&self.copied_payload_bytes)
    }

    /// Successful kernel-transfer calls that returned positive progress.
    #[must_use]
    pub fn kernel_transfer_calls(&self) -> u64 {
        read_counter(&self.kernel_transfer_calls)
    }

    /// Bytes returned by successful kernel-transfer calls.
    #[must_use]
    pub fn kernel_transferred_bytes(&self) -> u64 {
        read_counter(&self.kernel_transferred_bytes)
    }

    fn fallback_counter(&self, reason: ResponseFallbackReason) -> &AtomicU64 {
        match reason {
            ResponseFallbackReason::NotFileBacked => &self.fallback_not_file_backed,
            ResponseFallbackReason::VerificationRequired => &self.fallback_verification_required,
            ResponseFallbackReason::PlatformUnsupported => &self.fallback_platform_unsupported,
        }
    }
}

fn read_counter(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

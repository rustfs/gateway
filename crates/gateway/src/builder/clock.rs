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

//! Deterministic monotonic-clock wiring for elapsed-time and failure-floor measurements.
//!
//! Responsible for: [`ServiceBuilder::monotonic_clock`], which installs an explicit
//! [`MonotonicClock`] in place of the default [`SystemMonotonic`](crate::SystemMonotonic) for
//! request-duration and [`FailureFloor`](rustfs_gateway_sig::timing::FailureFloor) calculations.
//! NOT responsible for: wall-clock signature expiry ([`ServiceBuilder::clock_with_skew_ack`]) or
//! reading OS clocks directly (`crate::clock`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service::Inner::authz_clock`.

use std::sync::Arc;

use super::ServiceBuilder;
use crate::clock::MonotonicClock;

impl ServiceBuilder {
    /// Installs a custom [`MonotonicClock`] for request-duration and
    /// [`FailureFloor`](rustfs_gateway_sig::timing::FailureFloor) measurements in place of the
    /// default [`SystemMonotonic`](crate::SystemMonotonic).
    ///
    /// Defaults to [`SystemMonotonic`](crate::SystemMonotonic) anchored when
    /// [`ServiceBuilder::build`] runs. This source measures elapsed durations only and never
    /// governs wall-clock signature expiry (see [`ServiceBuilder::clock_with_skew_ack`]).
    /// Installing a frozen [`ManualMonotonic`](crate::ManualMonotonic) fails closed for
    /// `FailureFloor` enforcement: elapsed time remains zero, so every refusal waits the full
    /// configured floor regardless of host scheduling.
    #[must_use]
    pub fn monotonic_clock(mut self, clock: impl MonotonicClock) -> Self {
        self.authz_clock = Some(Arc::new(clock));
        self
    }
}

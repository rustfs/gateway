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

//! c-gov-0025: a monotonic reading cannot stand in for the wall-clock reading a signature is
//! judged against.
//!
//! Responsible for: pinning that `MonotonicNow` and `RequestNow` do not convert, so an expiry
//! check cannot be written against the limiter's clock (and the reverse).
//! NOT responsible for: where each clock is read, which `scripts/check_clock_single_source.sh` owns.
//! Upstream: the public clock types. Downstream: the gateway compile-fail harness.

use rustfs_gateway::{ManualMonotonic, MonotonicClock};
use rustfs_gateway::sig::RequestNow;

fn expires(_now: RequestNow) {}

fn main() {
    let limiter_clock = ManualMonotonic::at_millis(0);
    expires(limiter_clock.monotonic());
}

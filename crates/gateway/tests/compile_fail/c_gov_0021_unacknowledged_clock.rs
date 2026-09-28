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

//! c-gov-0021 / rustfs/backlog#1759: a custom wall clock cannot be installed without the
//! acknowledgement.
//!
//! Responsible for: pinning that the unacknowledged `ServiceBuilder::clock` is gone, so a source
//! that is right at assembly and then freezes cannot reach a deployment silently.
//! NOT responsible for: how the acknowledged clock is reported, which `tests/assembly.rs` checks.
//! Upstream: `ServiceBuilder`. Downstream: the gateway compile-fail harness.

use rustfs_gateway::{FixedClock, ServiceBuilder};

fn main() {
    let _builder = ServiceBuilder::new().clock(FixedClock::at_unix_seconds(1_767_225_600));
}

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

//! c-gov-0016: a deployment cannot fill a governor request's bucket, operation or peer itself.
//!
//! Responsible for: pinning that `GovernorRequest` is only built by the framework, from the
//! resolved target and the transport's peer address, never from something a caller parsed.
//! NOT responsible for: which values the framework fills in, which `tests/governor_runtime.rs` checks.
//! Upstream: the public `GovernorRequest` type. Downstream: the gateway compile-fail harness.

use rustfs_gateway::{ClassKind, GovernorRequest};

fn main() {
    let _forged = GovernorRequest::new("GetObject", None, None, None, ClassKind::Unauthenticated);
}

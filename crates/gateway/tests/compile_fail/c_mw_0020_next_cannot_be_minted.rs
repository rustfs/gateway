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

//! c-mw-0020: nothing outside the framework can start an operation-layer chain.
//!
//! Responsible for: pinning that a continuation is received, never built, so no caller can reach
//! a handler through a chain that skipped dispatch and the authorization before it.
//! NOT responsible for: layer ordering, which `tests/middleware.rs` covers.
//! Upstream: the public `Next` type. Downstream: the gateway compile-fail harness.

use rustfs_gateway::Next;
use rustfs_gateway::dto::ListBuckets;

fn main() {
    let _mint = Next::<'static, ListBuckets>::new;
}

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

//! c-mw-0020 and c-mw-0021: an operation layer reaches the handler at most once.
//!
//! Responsible for: pinning that `Next::run` consumes the continuation, so a second call is a
//! moved value rather than a runtime error to report.
//! NOT responsible for: forging `Authorized<O>`, which `azc_0015_forge_authorized.rs` covers.
//! Upstream: the public `Next` type. Downstream: the gateway compile-fail harness.

use rustfs_gateway::{Next, Operation, Req};

fn twice<O: Operation>(next: Next<'_, O>, first: Req<O>, second: Req<O>) {
    let _ = next.run(first);
    let _ = next.run(second);
}

fn main() {}

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

//! c-mw-0015: an observer cannot take the event mutably.
//!
//! Responsible for: pinning that `Observer::on_response` receives a shared reference only.
//! NOT responsible for: observer panic isolation, which `tests/observer_panic.rs` covers.
//! Upstream: the public `Observer` trait. Downstream: the gateway compile-fail harness.

use rustfs_gateway::{Observer, RequestEvent};

struct Rewriter;

impl Observer for Rewriter {
    fn on_response(&self, event: &mut RequestEvent<'_>) {
        event.status = 200;
    }
}

fn main() {}

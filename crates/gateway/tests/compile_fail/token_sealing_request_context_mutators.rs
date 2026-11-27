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

//! ADR-0056: `RequestContextView::{with_bearer_receipt, without_bearer_token}` are not reachable via `rustfs_gateway`.
//!
//! Responsible for: proving facade consumers cannot mutate `RequestContextView` for bearer state.
//! NOT responsible for: runtime context construction.
//! Upstream: `rustfs_gateway::RequestContextView`. Downstream: trybuild gate.

use rustfs_gateway::RequestContextView;

fn main() {
    let context = RequestContextView::detached("op");
    let _ = context.with_bearer_receipt();
}

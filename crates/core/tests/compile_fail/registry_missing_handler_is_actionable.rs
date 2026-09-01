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

//! c-reg-1014: a missing per-operation handler reports the concrete repair shape.
//!
//! Responsible for: pinning `Handler`'s `on_unimplemented` diagnostic for one missing operation.
//! NOT responsible for: runtime completeness checks or handler invocation.
//! Upstream: the trybuild harness. Downstream: backend implementors.

use rustfs_gateway_core::Handler;
use rustfs_gateway_types::dto::RestoreObject;

struct PartialBackend;

fn require_restore<B: Handler<RestoreObject>>() {}

fn main() {
    require_restore::<PartialBackend>();
}

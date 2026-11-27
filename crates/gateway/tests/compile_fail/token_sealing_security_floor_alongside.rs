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

//! ADR-0056: `SecurityFloor::bearer_alongside_signature` is not reachable via `rustfs_gateway`.
//!
//! Responsible for: proving facade consumers cannot call `SecurityFloor::bearer_alongside_signature`.
//! NOT responsible for: runtime floor admission.
//! Upstream: `rustfs_gateway::SecurityFloor`. Downstream: trybuild gate.

use rustfs_gateway::SecurityFloor;

fn main() {
    let floor = SecurityFloor::new();
    let _ = floor.bearer_alongside_signature();
}

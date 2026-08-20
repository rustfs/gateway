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

//! Compile-time or regression support for this module.
//!
//! Responsible for: proving an unresolved upload id cannot be read back out of its claim, so the
//! only route from the wire value to something a backend can act on runs through the exchange.
//! NOT responsible for: the runtime resolution rules, which `tests/upload_capability.rs` owns.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

use rustfs_gateway_core::ops::shared::upload_id::UploadIdClaim;

fn main() {
    let claim = UploadIdClaim::from_wire("conformance-upload-0001");
    let _ = claim.raw;
}

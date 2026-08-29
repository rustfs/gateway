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
//! Responsible for: proving an unresolved upload-id claim cannot be printed or compared as a
//! bearer value. NOT responsible for: runtime ownership resolution. Upstream: the public claim.
//! Downstream: the trybuild contract gate.

use rustfs_gateway_core::ops::shared::upload_id::UploadIdClaim;

fn main() {
    let left = UploadIdClaim::from_wire("left");
    let right = UploadIdClaim::from_wire("right");
    println!("{left}");
    let _ = left == right;
}

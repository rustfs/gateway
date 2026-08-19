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

//! `c-sig-0550`: a SigV2 signature cannot be compared with `==` either.
//!
//! Responsible for: proving the 20-byte SigV2 width shares `Signature`'s missing `PartialEq`, so
//! the SigV2 path cannot grow a second, non-constant-time comparison (side channel T7).
//! NOT responsible for: the runtime comparison, which is `Signature::ct_verify` reached through
//! `sig_v2::verify_presented`.
//! Upstream: `rustfs_gateway_sig::Signature`. Downstream: the SigV2 verifier.

use rustfs_gateway_sig::{CtBytes, Signature};

fn main() {
    let left = Signature::HmacSha1(CtBytes::from_array([0; 20]));
    let right = Signature::HmacSha1(CtBytes::from_array([0; 20]));
    let _ = left == right;
}

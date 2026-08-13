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

//! A signature comparison proof cannot be copied into a second request.
//!
//! Responsible for: proving `SignatureMatch` has no `Copy` implementation.
//! NOT responsible for: producing a comparison proof.
//! Upstream: `rustfs_gateway_sig::SignatureMatch`. Downstream: authentication callers.

use rustfs_gateway_sig::{CtBytes, Signature};

fn main() {
    let left = Signature::HmacSha256(CtBytes::from_array([0; 32]));
    let right = Signature::HmacSha256(CtBytes::from_array([0; 32]));
    let proof = left.ct_verify(&right).unwrap();
    let moved = proof;
    let _ = (moved, proof);
}

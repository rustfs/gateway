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

//! `c-sig-0125`: a verification result cannot be silently discarded.
//!
//! Responsible for: proving the comparison result is `must_use` under the workspace warning gate.
//! NOT responsible for: interpreting a verification rejection.
//! Upstream: `rustfs_gateway_sig::Signature`. Downstream: authentication callers.

#![deny(unused_must_use)]

use rustfs_gateway_sig::{CtBytes, Signature};

fn main() {
    let left = Signature::HmacSha256(CtBytes::from_array([0; 32]));
    let right = Signature::HmacSha256(CtBytes::from_array([0; 32]));
    left.ct_verify(&right);
}

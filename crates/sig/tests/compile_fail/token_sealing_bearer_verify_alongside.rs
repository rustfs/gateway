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

//! ADR-0056: `BearerAdmission::verify_alongside` is not a public inherent method.
//!
//! Responsible for: proving host code cannot mint a `BearerReceipt` via `BearerAdmission::verify_alongside`.
//! NOT responsible for: runtime bearer verification.
//! Upstream: `rustfs_gateway_sig::BearerAdmission`. Downstream: trybuild gate.

use rustfs_gateway_sig::{BearerAdmission, BearerGrant, BearerRefused, BearerTokenRequest, BearerTokenVerifier, Identity};

struct V;
impl BearerTokenVerifier for V {
    fn verify(&self, _: &BearerTokenRequest<'_>) -> Result<BearerGrant, BearerRefused> {
        Err(BearerRefused)
    }
}

fn mint(admission: BearerAdmission, signed: &Identity) {
    let _ = admission.verify_alongside(&V, "/x/a.zip", signed);
}

fn main() {}

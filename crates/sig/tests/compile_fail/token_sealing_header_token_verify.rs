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

//! ADR-0056: `HeaderTokenAdmission::verify` is not a public inherent method.
//!
//! Responsible for: proving host code cannot mint a `Verdict::HeaderToken` via `HeaderTokenAdmission::verify`.
//! NOT responsible for: runtime header-token verification.
//! Upstream: `rustfs_gateway_sig::HeaderTokenAdmission`. Downstream: trybuild gate.

use rustfs_gateway_http::TransportExtensions;
use rustfs_gateway_sig::{HeaderTokenAdmission, HeaderTokenRefused, HeaderTokenVerifier, Identity, RequestNow};

struct Est;
struct V;
impl HeaderTokenVerifier for V {
    type Established = Est;

    fn identity(&self, _: &Est, _: RequestNow) -> Result<Identity, HeaderTokenRefused> {
        Err(HeaderTokenRefused)
    }
}

fn mint(admission: HeaderTokenAdmission, state: &TransportExtensions) {
    let _ = admission.verify(&V, state);
}

fn main() {}

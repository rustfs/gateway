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

//! `c-sig-0377`: a custom verifier cannot return an unproved principal.
//!
//! Responsible for: proving `SignatureVerifier::verify` returns only `Verdict`.
//! NOT responsible for: producing signature or anonymous proof receipts.
//! Upstream: custom authentication input. Downstream: sealed verdict handling.

use rustfs_gateway_sig::{CustomAuthRequest, Identity, SignatureVerifier};

struct WrongVerifier;

impl SignatureVerifier for WrongVerifier {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Identity {
        panic!("the return type must fail before this body matters")
    }
}

fn main() {
    let _ = WrongVerifier;
}

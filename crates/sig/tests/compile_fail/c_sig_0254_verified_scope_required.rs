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

//! `c-sig-0254`: a client-presented scope cannot derive a signing key before verification.
//!
//! Responsible for: proving no public conversion mints `VerifiedScope` from `CredentialScope`.
//! NOT responsible for: the runtime scope checks or HMAC comparison.
//! Upstream: parsed client credentials. Downstream: signing-key derivation.

use rustfs_gateway_sig::{CredentialScope, SecretBytes, VerifiedScope, signing_key};

fn main() {
    let presented = CredentialScope::parse("AKID/20150830/us-east-1/s3/aws4_request").unwrap();
    let secret = SecretBytes::new(b"secret");
    let _ = signing_key(&secret, &VerifiedScope::from_presented(&presented));
}

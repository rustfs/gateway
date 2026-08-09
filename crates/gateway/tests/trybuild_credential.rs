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

//! Compile-time boundaries around the credential-provider contract.
//!
//! Responsible for: proving a provider cannot return a verdict or bare secret, anonymous proof is
//! private, and credential material cannot be printed or compared. NOT responsible for: runtime
//! authentication. Upstream: `rustfs-gateway`. Downstream: none.

#[test]
fn credential_contract_rejects_four_invalid_implementations() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/trybuild/credential/*.rs");
}

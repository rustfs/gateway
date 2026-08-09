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

//! Compile-time authorization boundaries.
//!
//! Responsible for: proving omitted resource declarations and forged proofs do not compile.
//! NOT responsible for: runtime policy outcomes.
//! Upstream: `rustfs_gateway_core::authz`. Downstream: public extension implementors.

#[test]
fn authorization_proofs_are_not_forgeable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/authz_*.rs");
    cases.pass("tests/compile_pass/authz_authorized.rs");
}

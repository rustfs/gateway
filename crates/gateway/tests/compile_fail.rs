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

//! Consolidated compile-fail contracts for the gateway facade.
//!
//! Responsible for: running every gateway trybuild fixture through one synthetic test project.
//! NOT responsible for: runtime gateway behavior or fixture implementation.
//! Upstream: gateway compile-fail fixtures. Downstream: Cargo's test harness.

#[test]
fn gateway_compile_fail_contracts_are_enforced() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/azc_*.rs");
    cases.compile_fail("tests/compile_fail/error_resolution_*.rs");
    cases.compile_fail("tests/trybuild/credential/*.rs");
}

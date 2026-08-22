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

//! Compile-time authorization and signature-secret boundaries.
//!
//! Responsible for: proving omitted resource declarations, forged proofs, a forged upload
//! handle, and serialization of a signature session token do not compile, using one shared
//! trybuild project.
//! NOT responsible for: runtime policy outcomes or signature verification.
//! Upstream: `rustfs_gateway_core::authz`, `rustfs_gateway_sig::SessionToken`. Downstream: public
//! extension implementors and serialization callers.

#[test]
fn compile_time_contracts_are_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/authz_*.rs");
    cases.pass("tests/compile_pass/authz_authorized.rs");
    cases.compile_fail("tests/compile_fail/c_err_1010_*.rs");
    cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");
    cases.compile_fail("tests/compile_fail/c_sig_0123_*.rs");
    cases.compile_fail("tests/compile_fail/committed_*.rs");
    cases.compile_fail("tests/compile_fail/error_resolution_*.rs");
    cases.compile_fail("tests/compile_fail/upload_*.rs");
}

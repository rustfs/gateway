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

//! Compile-time boundaries for the P2 signature contracts.
//!
//! Responsible for: executing independently named compile-fail cases from P2-01 through P2-06.
//! NOT responsible for: runtime parsing, verification, or the colocated rustdoc examples.
//! Upstream: `rustfs_gateway_sig` public types. Downstream: downstream implementors.

#[test]
fn p2_01_compile_time_boundaries_are_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs");
}

#[test]
fn p2_02_compile_time_boundaries_are_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_01[12][0-9]_*.rs");
    cases.compile_fail("tests/compile_fail/p2_02_*_cannot_*.rs");
}

#[test]
fn p2_03_compile_time_boundaries_are_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_025[34]_*.rs");
}

#[test]
fn p2_04_compile_time_boundaries_are_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_034[56]_*.rs");
    cases.compile_fail("tests/compile_fail/c_sig_0354_*.rs");
    cases.compile_fail("tests/compile_fail/c_sig_0377_*.rs");
}

#[test]
fn p2_06_compile_time_boundaries_are_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_0550_*.rs");
    cases.compile_fail("tests/compile_fail/c_sig_0555_*.rs");
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
#[test]
fn p2_04_danger_ack_compile_time_boundary_is_not_openable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_0376_*.rs");
}

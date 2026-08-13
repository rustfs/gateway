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

//! Cross-crate construction policy for `OperationSpec`.
//!
//! Responsible for: proving downstream code uses the additive builder rather than a struct
//! literal. NOT responsible for: registry validation. Upstream: `OperationSpec`. Downstream:
//! extension operation authors.

#[test]
fn c_dto_n008_operation_spec_requires_its_builder_across_a_crate_boundary() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/operation_spec_literal.rs");
    cases.pass("tests/compile_pass/operation_spec_builder.rs");
}

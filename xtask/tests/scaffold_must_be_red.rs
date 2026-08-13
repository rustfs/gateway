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

//! Source-level mutation controls for the operation scaffold.
//!
//! Responsible for: proving the handler template contains the one failure `new-op` accepts and
//! rejects a default-return fake. NOT responsible for: compiling a scaffold in the real tree.
//! Upstream: `xtask/templates`. Downstream: the `new-op` runtime self-check.

const OPERATION: &str = include_str!("../templates/operation.rs.tmpl");
const TEST: &str = include_str!("../templates/operation_test.rs.tmpl");
const CASE: &str = include_str!("../templates/conformance.toml.tmpl");

fn is_must_red(template: &str) -> bool {
    template.contains("todo!(\"SCAFFOLD handler is not implemented\")")
        && !template.contains("Ok(Default::default())")
        && !template.contains("Ok(crate::handler::Resp::new(String::new()))")
}

#[test]
fn the_checked_in_handler_template_is_intentionally_red() {
    assert!(is_must_red(OPERATION));
}

#[test]
fn the_operation_template_uses_the_additive_spec_builder() {
    assert!(OPERATION.contains("OperationSpec::builder("));
    assert!(!OPERATION.contains("= OperationSpec {"));
}

#[test]
fn a_default_return_mutation_is_detected() {
    let fake_green = OPERATION.replace(
        "todo!(\"SCAFFOLD handler is not implemented\")",
        "Ok(crate::handler::Resp::new(String::new()))",
    );
    assert!(!is_must_red(&fake_green));
}

#[test]
fn the_generated_case_demands_a_response_the_scaffold_cannot_produce() {
    assert!(CASE.contains("status = 200"));
    assert!(CASE.contains("exact_utf8 = \"implemented\""));
    assert!(CASE.contains("SCAFFOLD: implement before merge"));
}

#[test]
fn the_generated_test_invokes_the_registered_handler_against_the_case_expectation() {
    assert!(TEST.contains("authorize_and_invoke_no_derived"));
    assert!(TEST.contains("include_str!(\"../../../conformance/cases/scaffold/{{SNAKE}}_smoke.toml\")"));
    assert!(TEST.contains("assert_eq!(response.output().map(String::as_str), Some(expected_body))"));
}

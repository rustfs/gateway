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

//! Mutation checks for boolean spelling selected by a typed codec rule.
//!
//! Responsible for: proving boolean spelling is sourced from the typed quirk value.
//! NOT responsible for: executing wire-level cases. Upstream: lowered codegen artifacts.
//! Downstream: the codegen test gate.

use rustfs_gateway_model::{BooleanSpellingValue, CodecValue};

use super::codegen_tests::artifacts;

#[test]
fn bypass_governance_boolean_spelling_comes_from_the_quirk_value() {
    let artifacts = artifacts();
    let operation = artifacts
        .operations
        .iter()
        .find(|operation| operation.operation == "PutObjectRetention")
        .expect("PutObjectRetention is lowered");
    let current = crate::emit::codec::operation_for_test(operation, &artifacts.codec_rules, &artifacts.error_codes)
        .expect("the current boolean policy renders");
    assert!(current.contains("value::boolean(raw, \"BypassGovernanceRetention\")?"));

    let mut rules = artifacts.codec_rules;
    rules
        .get_mut("q-lock-0012")
        .expect("the boolean quirk has a typed codec rule")
        .current = CodecValue::BooleanSpelling(BooleanSpellingValue::LowercaseOnly);
    let mutant =
        crate::emit::codec::operation_for_test(operation, &rules, &artifacts.error_codes).expect("the boolean mutant renders");
    assert!(mutant.contains("value::boolean_lowercase(raw, \"BypassGovernanceRetention\")?"));
}

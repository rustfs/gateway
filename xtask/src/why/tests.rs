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

//! Unit controls for reverse-trace completeness.
//!
//! Responsible for: proving complete and incomplete answers select opposite process outcomes.
//! NOT responsible for: loading repository evidence or exercising the process boundary.
//! Upstream: `why` answer construction. Downstream: the `cargo xtask why` exit contract.

use super::*;

#[test]
fn an_incomplete_answer_is_a_failure_and_names_the_missing_cases() {
    let answer = empty_answer("q-test-0001");

    assert!(!answer_succeeds(&answer));
    assert!(render_text(&answer).contains("CASES     NONE — this is a bug"));
}

#[test]
fn a_complete_answer_with_a_case_is_a_success() {
    let mut answer = empty_answer("q-test-0001");
    answer.complete = true;
    answer.cases.push(CaseLine {
        id: "c-test-0001".to_owned(),
        title: "case".to_owned(),
    });

    assert!(answer_succeeds(&answer));
    assert!(render_text(&answer).contains("CASES     c-test-0001 — case"));
}

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

//! Safe failure summaries for the crate feedback test.
//!
//! Responsible for: identifying the execution phase and failing rule names.
//! NOT responsible for: printing target data, diagnostic messages, or credentials.
//! Upstream: feedback-case tests. Downstream: test failure output.

use crate::report::CaseOutcome;

pub(super) fn summary(outcome: &CaseOutcome) -> String {
    let rules = outcome
        .failures()
        .into_iter()
        .map(|diagnostic| diagnostic.rule.as_str())
        .collect::<Vec<_>>();
    format!(
        "{}: {} at {}; failing rules: {}",
        outcome.id,
        outcome.verdict.as_str(),
        outcome.phase.as_str(),
        rules.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Diagnostic;
    use crate::report::{Phase, Verdict};

    #[test]
    fn failing_rules_are_reported_without_untrusted_messages() {
        let outcome = CaseOutcome {
            id: "case".to_owned(),
            domain: "test".to_owned(),
            relative: "test/case.toml".to_owned(),
            title: None,
            verdict: Verdict::Failed,
            phase: Phase::Execute,
            skip_reason: None,
            transport_limited: false,
            diagnostics: vec![
                Diagnostic::deny("expect/status", "/expect/status", "private-data-marker"),
                Diagnostic::deny("expect/connection_after", "/expect/connection_after", "secret-marker"),
                Diagnostic::warn("advisory", "", "warning-marker"),
            ],
            quirks: Vec::new(),
            evidence: Vec::new(),
        };
        let result = summary(&outcome);
        assert!(!result.contains("private-data-marker"));
        assert!(!result.contains("secret-marker"));
        assert!(!result.contains("warning-marker"));
        assert_eq!(result, "case: failed at execute; failing rules: expect/status, expect/connection_after");
    }
}

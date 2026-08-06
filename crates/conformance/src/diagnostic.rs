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

//! The one diagnostic shape every phase of the runner produces.
//!
//! Responsible for: the "what failed / where / which rule" triple that a conformance failure must
//! carry to be actionable — a rule name a maintainer can grep for, a pointer into the case file,
//! and expected-versus-actual prose. A failure that cannot be traced back to a field of a case
//! file is a failure someone will eventually silence rather than fix.
//! NOT responsible for: deciding whether a diagnostic fails the run (`crate::report`), or
//! producing any of them (`crate::schema`, `crate::lint`, `crate::expect`).
//! Upstream: nothing. Downstream: `crate::corpus`, `crate::lint`, `crate::expect`,
//! `crate::report`.

use crate::schema::Violation;
use core::fmt;

/// Whether a diagnostic fails its case or merely annotates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The case is unusable or wrong. It fails.
    Deny,
    /// The case runs, but something about it should be looked at. It does not fail.
    ///
    /// Reserved for conventions the corpus documents but that are not yet uniformly applied —
    /// a warning that fails the build gets suppressed, and a suppressed rule teaches nothing.
    Warn,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Deny => f.write_str("deny"),
            Severity::Warn => f.write_str("warn"),
        }
    }
}

/// One finding about a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Whether this fails the case.
    pub severity: Severity,
    /// A stable, greppable rule name, e.g. `schema/additionalProperties` or `lint/golden-missing`.
    pub rule: String,
    /// Where in the case document the finding sits, as a JSON pointer. Empty for whole-file
    /// findings such as a parse error.
    pub pointer: String,
    /// Expected versus actual, in the author's terms.
    pub message: String,
}

impl Diagnostic {
    /// A failing finding.
    #[must_use]
    pub fn deny(rule: &str, pointer: &str, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Deny,
            rule: rule.to_owned(),
            pointer: pointer.to_owned(),
            message: message.into(),
        }
    }

    /// A non-failing finding.
    #[must_use]
    pub fn warn(rule: &str, pointer: &str, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Warn,
            rule: rule.to_owned(),
            pointer: pointer.to_owned(),
            message: message.into(),
        }
    }

    /// Lifts a schema violation, keeping the keyword as the rule name.
    #[must_use]
    pub fn from_violation(violation: &Violation) -> Diagnostic {
        Diagnostic {
            severity: Severity::Deny,
            rule: format!("schema/{}", violation.keyword),
            pointer: violation.pointer.clone(),
            message: violation.message.clone(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = if self.pointer.is_empty() {
            String::new()
        } else {
            format!(" at {}", self.pointer)
        };
        write!(f, "[{}]{location}: {}", self.rule, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_violation_keeps_its_keyword_as_the_rule_name() {
        let violation = Violation {
            pointer: "/case/id".to_owned(),
            keyword: "pattern".to_owned(),
            message: "nope".to_owned(),
        };
        let diagnostic = Diagnostic::from_violation(&violation);
        assert_eq!(diagnostic.rule, "schema/pattern");
        assert_eq!(diagnostic.severity, Severity::Deny);
    }

    #[test]
    fn a_whole_file_diagnostic_renders_without_a_pointer() {
        let rendered = Diagnostic::deny("corpus/parse", "", "bad").to_string();
        assert_eq!(rendered, "[corpus/parse]: bad");
    }
}

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

//! Per-case production transport parity comparison.
//!
//! Responsible for: comparing verdict, phase, failure text and skip reason for every case in two
//! reports. NOT responsible for: running either target or deciding whether a common failure is a
//! regression. Upstream: `crate::cli`. Downstream: the deterministic parity gate.

use std::collections::{BTreeMap, BTreeSet};

use crate::report::{CaseOutcome, Report};
use crate::value::Value;

/// The fields whose equality defines one case's transport parity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseResult {
    /// Rendered verdict.
    pub verdict: String,
    /// Runner phase in which the verdict was reached.
    pub phase: String,
    /// Reason a case could not run, when skipped.
    pub skip_reason: Option<String>,
    /// Deny-level assertion diagnostics in evaluation order.
    pub failures: Vec<String>,
}

/// One case whose two production transport results differ.
#[derive(Debug, Eq, PartialEq)]
pub struct Difference {
    /// Case id, or the id missing from one report.
    pub id: String,
    /// Hyper result, absent when Hyper omitted the case.
    pub hyper: Option<CaseResult>,
    /// Self-held result, absent when the self-held run omitted the case.
    pub conn: Option<CaseResult>,
}

/// Summary of comparing two serialized production reports.
#[derive(Debug, Eq, PartialEq)]
pub struct Comparison {
    /// Cases present in either report.
    pub case_count: usize,
    /// Cases that failed identically on both transports.
    pub common_failures: usize,
    /// Per-case differences.
    pub differences: Vec<Difference>,
}

/// Returns every per-case result difference in case-id order.
#[must_use]
pub fn compare(hyper: &Report, conn: &Report) -> Vec<Difference> {
    compare_results(results(hyper), results(conn))
}

/// Compares two machine-readable reports produced by isolated processes.
///
/// # Errors
///
/// Returns an error when either document is malformed or omits a parity field.
pub fn compare_json(hyper: &str, conn: &str) -> Result<Comparison, String> {
    let hyper = parse_results("hyper", hyper)?;
    let conn = parse_results("self-held", conn)?;
    let case_count = hyper.keys().chain(conn.keys()).collect::<BTreeSet<_>>().len();
    let common_failures = hyper
        .iter()
        .filter(|(id, result)| result.verdict == "failed" && conn.get(*id) == Some(*result))
        .count();
    let differences = compare_results(hyper, conn);
    Ok(Comparison {
        case_count,
        common_failures,
        differences,
    })
}

/// Capability expected from independently loaded and selected corpus metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedCapability {
    /// Both production drivers must report the same result.
    Shared,
    /// The script executes on Hyper and is explicitly unsupported by the self-held driver.
    HyperScriptedH2,
}

/// Complete selected-case comparison with capability differences kept distinct from equality.
#[derive(Debug)]
pub(crate) struct SelectedComparison {
    /// Number of independently selected cases represented in both reports.
    pub case_count: usize,
    /// Results that match exactly on the shared capability surface.
    pub identical_count: usize,
    /// Cases that failed identically on both transports, with both results.
    pub common_failures: Vec<Difference>,
    /// Unexpected differences, including capability-contract violations.
    pub differences: Vec<Difference>,
    /// Measured Hyper passes paired with the expected self-held capability refusal.
    pub capability_differences: Vec<Difference>,
}

/// Compares reports against the parent's independently selected complete case census.
///
/// # Errors
///
/// Returns an error for malformed reports or a mismatch with the selected case census.
pub(crate) fn compare_selected_json(
    hyper: &str,
    conn: &str,
    selected: &BTreeMap<String, ExpectedCapability>,
) -> Result<SelectedComparison, String> {
    let hyper = parse_results("hyper", hyper)?;
    let conn = parse_results("self-held", conn)?;
    if !hyper.keys().eq(selected.keys()) || !conn.keys().eq(selected.keys()) {
        return Err("production reports must each contain exactly the independently selected case census".to_owned());
    }
    let mut comparison = SelectedComparison {
        case_count: selected.len(),
        identical_count: 0,
        common_failures: Vec::new(),
        differences: Vec::new(),
        capability_differences: Vec::new(),
    };
    for (id, capability) in selected {
        let hyper_result = hyper.get(id);
        let conn_result = conn.get(id);
        let difference = || Difference {
            id: id.clone(),
            hyper: hyper_result.cloned(),
            conn: conn_result.cloned(),
        };
        match capability {
            ExpectedCapability::Shared if hyper_result == conn_result => {
                comparison.identical_count += 1;
                if hyper_result.is_some_and(|result| result.verdict == "failed") {
                    comparison.common_failures.push(difference());
                }
            }
            ExpectedCapability::HyperScriptedH2
                if hyper_result.is_some_and(|result| {
                    result.verdict == "passed"
                        && result.phase == "execute"
                        && result.skip_reason.is_none()
                        && result.failures.is_empty()
                }) && conn_result.is_some_and(|result| {
                    result.verdict == "skipped"
                        && result.phase == "execute"
                        && result.skip_reason.as_deref() == Some(SELF_HELD_H2_REFUSAL)
                        && result.failures.is_empty()
                }) =>
            {
                comparison.capability_differences.push(difference());
            }
            _ => comparison.differences.push(difference()),
        }
    }
    Ok(comparison)
}

const SELF_HELD_H2_REFUSAL: &str = "environment: the production self-held driver speaks HTTP/1.1 only; authored HTTP/2 frames run on the production Hyper driver";

fn compare_results(hyper: BTreeMap<String, CaseResult>, conn: BTreeMap<String, CaseResult>) -> Vec<Difference> {
    hyper
        .keys()
        .chain(conn.keys())
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|id| {
            let hyper_result = hyper.get(id).cloned();
            let conn_result = conn.get(id).cloned();
            (hyper_result != conn_result).then(|| Difference {
                id: id.to_owned(),
                hyper: hyper_result,
                conn: conn_result,
            })
        })
        .collect()
}

fn results(report: &Report) -> BTreeMap<String, CaseResult> {
    report
        .outcomes
        .iter()
        .map(|outcome| (outcome.id.clone(), result(outcome)))
        .collect()
}

fn result(outcome: &CaseOutcome) -> CaseResult {
    CaseResult {
        verdict: format!("{:?}", outcome.verdict).to_ascii_lowercase(),
        phase: format!("{:?}", outcome.phase).to_ascii_lowercase(),
        skip_reason: outcome.skip_reason.clone(),
        failures: outcome.failures().iter().map(ToString::to_string).collect(),
    }
}

fn parse_results(name: &str, input: &str) -> Result<BTreeMap<String, CaseResult>, String> {
    let document = crate::json::parse(input).map_err(|error| format!("{name} report: {error}"))?;
    let cases = document
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{name} report: `cases` must be an array"))?;
    let mut results = BTreeMap::new();
    for (index, case) in cases.iter().enumerate() {
        let field = |key| {
            case.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} report: case {index} requires string field `{key}`"))
        };
        let id = field("id")?;
        let failures = case
            .get("failures")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{name} report: case {index} requires array field `failures`"))?
            .iter()
            .map(|failure| {
                failure
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{name} report: case {index} has a non-string failure"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reason = field("reason")?;
        let result = CaseResult {
            verdict: field("verdict")?,
            phase: field("phase")?,
            skip_reason: (!reason.is_empty()).then_some(reason),
            failures,
        };
        if results.insert(id.clone(), result).is_some() {
            return Err(format!("{name} report: duplicate case `{id}`"));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Diagnostic;
    use crate::report::{CaseOutcome, Phase, Verdict};

    fn report(outcomes: Vec<CaseOutcome>) -> Report {
        Report {
            target: "target".to_owned(),
            transport: "transport".to_owned(),
            profile: "aws".to_owned(),
            outcomes,
            filtered_out: 0,
            left_to_other_shards: 0,
            notes: Vec::new(),
            polarity: (1, 1),
            validate_only: false,
        }
    }

    fn outcome(id: &str, verdict: Verdict) -> CaseOutcome {
        CaseOutcome {
            id: id.to_owned(),
            domain: "object".to_owned(),
            relative: format!("cases/object/{id}.toml"),
            title: None,
            verdict,
            phase: Phase::Execute,
            skip_reason: None,
            transport_limited: false,
            diagnostics: Vec::new(),
            quirks: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn equal_results_have_no_difference() {
        let hyper = report(vec![outcome("c-object-0001", Verdict::Passed)]);
        let conn = report(vec![outcome("c-object-0001", Verdict::Passed)]);
        assert!(compare(&hyper, &conn).is_empty());
    }

    #[test]
    fn a_missing_case_is_a_difference() {
        let hyper = report(vec![outcome("c-object-0001", Verdict::Passed)]);
        assert_eq!(compare(&hyper, &report(Vec::new())).len(), 1);
    }

    #[test]
    fn a_verdict_difference_is_reported() {
        let hyper = report(vec![outcome("c-object-0001", Verdict::Passed)]);
        let conn = report(vec![outcome("c-object-0001", Verdict::Failed)]);
        assert_eq!(compare(&hyper, &conn).len(), 1);
    }

    #[test]
    fn a_failure_text_difference_is_reported() {
        let mut hyper_outcome = outcome("c-object-0001", Verdict::Failed);
        hyper_outcome
            .diagnostics
            .push(Diagnostic::deny("expect/status", "/expect/status", "hyper failure"));
        let mut conn_outcome = outcome("c-object-0001", Verdict::Failed);
        conn_outcome
            .diagnostics
            .push(Diagnostic::deny("expect/status", "/expect/status", "conn failure"));
        assert_eq!(compare(&report(vec![hyper_outcome]), &report(vec![conn_outcome])).len(), 1);
    }

    #[test]
    fn rendered_reports_compare_without_sharing_process_state() {
        let hyper = report(vec![outcome("c-object-0001", Verdict::Passed)]).render_json();
        let conn = report(vec![outcome("c-object-0001", Verdict::Passed)]).render_json();
        let comparison = compare_json(&hyper, &conn).expect("rendered reports are valid");
        assert!(comparison.differences.is_empty());
        assert_eq!(comparison.case_count, 1);
        assert_eq!(comparison.common_failures, 0);
    }

    #[test]
    fn malformed_report_is_rejected() {
        let error = compare_json("not json", "not json").expect_err("invalid JSON must fail closed");
        assert!(error.contains("hyper report"));
    }

    #[test]
    fn report_missing_a_case_field_is_rejected() {
        let missing_phase = r#"{"cases":[{"id":"c-object-0001","verdict":"passed","reason":"","failures":[]}]}"#;
        let error = compare_json(missing_phase, missing_phase).expect_err("missing phase must fail closed");
        assert!(error.contains("phase"));
    }
}

#[cfg(test)]
mod capability_tests;

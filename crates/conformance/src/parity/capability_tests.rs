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

//! Responsible for: census-bound classification of expected production capability differences.
//! NOT responsible for: deriving capabilities from corpus metadata or accepting child exit codes.
//! Upstream: the parity comparison API; downstream: assertion and mutation controls.

use super::*;

const REFUSAL: &str = "environment: the production self-held driver speaks HTTP/1.1 only; authored HTTP/2 frames run on the production Hyper driver";

fn row(id: &str, verdict: &str, phase: &str, reason: &str, failures: &str) -> String {
    format!(r#"{{"id":"{id}","verdict":"{verdict}","phase":"{phase}","reason":"{reason}","failures":{failures}}}"#)
}

fn passed(id: &str) -> String {
    row(id, "passed", "execute", "", "[]")
}

fn unsupported(id: &str) -> String {
    row(id, "skipped", "execute", REFUSAL, "[]")
}

fn report(rows: &[String]) -> String {
    format!(r#"{{"cases":[{}]}}"#, rows.join(","))
}

fn selected(entries: &[(&str, ExpectedCapability)]) -> BTreeMap<String, ExpectedCapability> {
    entries
        .iter()
        .map(|(id, capability)| ((*id).to_owned(), *capability))
        .collect()
}

fn denied(hyper: &[String], conn: &[String], census: &BTreeMap<String, ExpectedCapability>) {
    match compare_selected_json(&report(hyper), &report(conn), census) {
        Err(_) => {}
        Ok(result) => assert!(!result.differences.is_empty(), "invalid reports must not be accepted: {result:?}"),
    }
}

#[test]
fn selected_h2_pass_and_refusal_are_retained_as_capability_difference() {
    // Deliberately not an h2-prefixed ID: metadata, not the name, grants this classification.
    let id = "c-wire-0042";
    let hyper = report(&[passed(id)]);
    let conn = report(&[unsupported(id)]);
    let comparison = compare_selected_json(&hyper, &conn, &selected(&[(id, ExpectedCapability::HyperScriptedH2)]))
        .expect("complete selected reports");
    assert_eq!(comparison.case_count, 1);
    assert_eq!(comparison.identical_count, 0);
    assert_eq!(comparison.common_failures, 0);
    assert!(comparison.differences.is_empty());
    assert_eq!(comparison.capability_differences.len(), 1);
    let difference = &comparison.capability_differences[0];
    assert_eq!(difference.id, id);
    assert_eq!(difference.hyper.as_ref().expect("Hyper row").verdict, "passed");
    let refused = difference.conn.as_ref().expect("self-held row");
    assert_eq!(refused.verdict, "skipped");
    assert_eq!(refused.phase, "execute");
    assert_eq!(refused.skip_reason.as_deref(), Some(REFUSAL));
    assert!(refused.failures.is_empty());
    assert_eq!(compare_json(&hyper, &conn).expect("strict comparison").differences.len(), 1);
}

#[test]
fn mixed_census_counts_shared_results_separately() {
    let comparison = compare_selected_json(
        &report(&[passed("c-h2-0001"), passed("c-object-0001")]),
        &report(&[unsupported("c-h2-0001"), passed("c-object-0001")]),
        &selected(&[
            ("c-h2-0001", ExpectedCapability::HyperScriptedH2),
            ("c-object-0001", ExpectedCapability::Shared),
        ]),
    )
    .expect("mixed complete reports");
    assert_eq!(comparison.case_count, 2);
    assert_eq!(comparison.identical_count, 1);
    assert_eq!(comparison.common_failures, 0);
    assert_eq!(comparison.capability_differences.len(), 1);
    assert!(comparison.differences.is_empty());
}

#[test]
fn both_omitted_selected_cases_are_not_an_empty_success() {
    for capability in [ExpectedCapability::Shared, ExpectedCapability::HyperScriptedH2] {
        denied(&[], &[], &selected(&[("c-h2-0001", capability)]));
    }
}

#[test]
fn either_omitted_case_is_rejected() {
    let census = selected(&[("c-h2-0001", ExpectedCapability::HyperScriptedH2)]);
    denied(&[passed("c-h2-0001")], &[], &census);
    denied(&[], &[unsupported("c-h2-0001")], &census);
}

#[test]
fn matching_extra_cases_cannot_expand_the_selected_census() {
    let census = selected(&[("c-object-0001", ExpectedCapability::Shared)]);
    let rows = [passed("c-object-0001"), passed("c-object-0002")];
    denied(&rows, &rows, &census);
    denied(&[passed("c-object-0002")], &[passed("c-object-0002")], &BTreeMap::new());
}

#[test]
fn extra_cases_on_either_side_cannot_hide_behind_a_valid_shared_row() {
    let census = selected(&[("c-object-0001", ExpectedCapability::Shared)]);
    let complete = [passed("c-object-0001")];
    let extra = [passed("c-object-0001"), passed("c-object-0002")];
    denied(&extra, &complete, &census);
    denied(&complete, &extra, &census);
}

#[test]
fn shared_common_failures_remain_visible_and_are_not_capability_differences() {
    let id = "c-object-0001";
    let failed = report(&[row(id, "failed", "execute", "", r#"["expect/status"]"#)]);
    let result = compare_selected_json(&failed, &failed, &selected(&[(id, ExpectedCapability::Shared)]))
        .expect("complete shared failures");
    assert_eq!(result.case_count, 1);
    assert_eq!(result.identical_count, 1);
    assert_eq!(result.common_failures, 1);
    assert!(result.capability_differences.is_empty());
    assert!(result.differences.is_empty());
}

#[test]
fn duplicate_case_rows_fail_closed_on_either_side() {
    let census = selected(&[("c-h2-0001", ExpectedCapability::HyperScriptedH2)]);
    denied(&[passed("c-h2-0001"), passed("c-h2-0001")], &[unsupported("c-h2-0001")], &census);
    denied(&[passed("c-h2-0001")], &[unsupported("c-h2-0001"), unsupported("c-h2-0001")], &census);
}

#[test]
fn shared_metadata_does_not_trust_a_domain_name_or_refusal_text() {
    denied(
        &[passed("c-h2-0001")],
        &[unsupported("c-h2-0001")],
        &selected(&[("c-h2-0001", ExpectedCapability::Shared)]),
    );
}

#[test]
fn expected_h2_hyper_result_must_be_a_clean_execution_pass() {
    let id = "c-h2-0001";
    let census = selected(&[(id, ExpectedCapability::HyperScriptedH2)]);
    for bad in [
        row(id, "failed", "execute", "", r#"["expect/status"]"#),
        row(id, "failed", "execute", "", "[]"),
        row(id, "skipped", "execute", "", "[]"),
        row(id, "skipped", "execute", REFUSAL, "[]"),
        row(id, "passed", "schema", "", "[]"),
        row(id, "passed", "execute", "unexpected reason", "[]"),
        row(id, "passed", "execute", "", r#"["expect/status"]"#),
    ] {
        denied(&[bad], &[unsupported(id)], &census);
    }
}

#[test]
fn expected_h2_conn_result_must_be_the_exact_clean_capability_refusal() {
    let id = "c-h2-0001";
    let census = selected(&[(id, ExpectedCapability::HyperScriptedH2)]);
    for bad in [
        passed(id),
        row(id, "failed", "execute", REFUSAL, "[]"),
        row(id, "skipped", "execute", "environment: listener failed", "[]"),
        row(
            id,
            "skipped",
            "execute",
            REFUSAL.strip_prefix("environment: ").expect("fixture prefix"),
            "[]",
        ),
        row(id, "skipped", "convention", REFUSAL, "[]"),
        row(id, "skipped", "execute", "", "[]"),
        row(id, "skipped", "execute", REFUSAL, r#"["unexpected denial"]"#),
    ] {
        denied(&[passed(id)], &[bad], &census);
    }
}

#[test]
fn matching_h2_failures_or_skips_cannot_be_counted_as_shared_parity() {
    let id = "c-h2-0001";
    let census = selected(&[(id, ExpectedCapability::HyperScriptedH2)]);
    for bad in [unsupported(id), row(id, "failed", "execute", "", r#"["expect/status"]"#)] {
        denied(std::slice::from_ref(&bad), std::slice::from_ref(&bad), &census);
    }
}

#[test]
fn malformed_and_incomplete_reports_remain_errors() {
    let id = "c-h2-0001";
    let census = selected(&[(id, ExpectedCapability::HyperScriptedH2)]);
    let complete = report(&[passed(id)]);
    for bad in ["not json", r#"{}"#, r#"{"cases":[{"id":"c-h2-0001"}]}"#] {
        assert!(compare_selected_json(bad, &complete, &census).is_err());
        assert!(compare_selected_json(&complete, bad, &census).is_err());
    }
}

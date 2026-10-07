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

//! Tests for [`crate::report`]: the verdict ladder, the validate-only report shape, and the
//! baseline ratchet.
//!
//! Responsible for: holding the report test suite in a sibling module so the source-size bound
//! keeps the implementation itself readable.
//! NOT responsible for: testing anything outside `crate::report`'s own conclusions.
//! Upstream: `crate::report`, `crate::json`, `crate::diagnostic`, `crate::value`. Downstream:
//! nothing — test-only code.

use crate::diagnostic::Diagnostic;
use crate::json;
use crate::report::{Baseline, CaseOutcome, Phase, Report, RunContext, Verdict};
use crate::value::Value;

fn outcome(id: &str, domain: &str, verdict: Verdict) -> CaseOutcome {
    CaseOutcome {
        id: id.to_owned(),
        domain: domain.to_owned(),
        relative: format!("cases/{domain}/{id}.toml"),
        title: Some("a title".to_owned()),
        verdict,
        phase: Phase::Execute,
        skip_reason: (verdict == Verdict::Skipped).then(|| "no target".to_owned()),
        transport_limited: false,
        diagnostics: if verdict == Verdict::Failed {
            vec![Diagnostic::deny(
                "expect/status",
                "/expect/status",
                "expected 200, observed 500",
            )]
        } else {
            Vec::new()
        },
        quirks: vec!["q-etag-0001".to_owned()],
        evidence: vec!["https://example.test/a".to_owned()],
    }
}

fn report() -> Report {
    Report {
        target: "scripted".to_owned(),
        transport: "hyper".to_owned(),
        profile: "aws".to_owned(),
        outcomes: vec![
            outcome("c-etag-0001", "etag", Verdict::Passed),
            outcome("c-sig-0001", "sig", Verdict::Failed),
            outcome("c-mpu-0001", "mpu", Verdict::Skipped),
        ],
        filtered_out: 0,
        left_to_other_shards: 0,
        notes: vec!["the facade must expose: a service entry point".to_owned()],
        polarity: (2, 1),
        validate_only: false,
    }
}

/// A report in the shape `validate` produces: every case checked, none executed.
fn validated_report() -> Report {
    Report {
        outcomes: vec![
            outcome("c-etag-0001", "etag", Verdict::Validated),
            outcome("c-sig-0001", "sig", Verdict::Failed),
        ],
        notes: Vec::new(),
        validate_only: true,
        ..report()
    }
}

#[test]
fn the_text_report_groups_by_capability_domain() {
    let rendered = report().render_text(None);
    assert!(rendered.contains("etag/  1 case(s)"));
    assert!(rendered.contains("sig/  1 case(s)"));
    assert!(rendered.contains("summary: 1 passed, 1 failed, 1 skipped"));
}

/// Negative — the summary of a corpus check must not spell the word a run's summary spells.
#[test]
fn a_validate_only_summary_counts_validated_rather_than_passed() {
    let rendered = validated_report().render_text(None);
    assert!(
        !rendered.contains("passed"),
        "a corpus check reports a pass it never observed:\n{rendered}"
    );
    assert!(rendered.contains("summary: 1 validated, 1 failed"), "{rendered}");
    assert!(rendered.contains("etag/  1 case(s): 1 validated, 0 failed"), "{rendered}");
}

/// Negative — the banner must not name a target, a transport or a profile it never reached.
///
/// The verdict alone does not cover this: an agent scanning the head of the report reads
/// `target rustfs-gateway assembled in process ... transport hyper` and concludes a service
/// answered.
#[test]
fn a_validate_only_report_names_no_target_and_no_transport() {
    let rendered = validated_report().render_text(None);
    assert!(!rendered.contains("scripted"), "the target it never contacted:\n{rendered}");
    assert!(!rendered.contains("transport"), "the transport it never opened:\n{rendered}");
    assert!(!rendered.contains("profile"), "the profile it never claimed:\n{rendered}");
    assert!(rendered.contains("no case was executed"), "{rendered}");
}

/// A reader holding a validate-only report is told which command does measure.
#[test]
fn a_validate_only_report_names_the_command_that_executes() {
    assert!(
        validated_report()
            .render_text(None)
            .contains("conformance run --filter \'<case-id>\'")
    );
}

/// Negative — a run report keeps its banner and its `passed` tally exactly as it was.
#[test]
fn an_executed_report_still_names_its_target_and_counts_passes() {
    let rendered = report().render_text(None);
    assert!(rendered.contains("target    scripted"), "{rendered}");
    assert!(rendered.contains("transport hyper"), "{rendered}");
    assert!(rendered.contains("summary: 1 passed, 1 failed, 1 skipped"), "{rendered}");
    assert!(!rendered.contains("validated"), "{rendered}");
}

/// Negative — JUnit has no third colour, and a bare `<testcase/>` is how a dashboard draws
/// "this ran and held". A validated case must not reach that shape.
#[test]
fn a_validated_case_is_not_a_junit_pass() {
    let rendered = validated_report().render_junit();
    assert!(rendered.contains("tests=\"2\" failures=\"1\" skipped=\"1\""), "{rendered}");
    assert!(rendered.contains("no assertion was evaluated"), "{rendered}");
    assert!(
        !rendered.contains("name=\"c-etag-0001\"/>"),
        "the validated case is rendered as a JUnit pass:\n{rendered}"
    );
}

/// The machine-readable report carries the distinction too — a consumer that only reads JSON
/// must not have to infer it from the command line that produced the file.
#[test]
fn the_json_report_spells_the_validated_verdict() {
    let rendered = validated_report().render_json();
    assert!(rendered.contains("\"verdict\": \"validated\""), "{rendered}");
    assert!(json::parse(&rendered).is_ok(), "{rendered}");
}

/// Negative — the machine-readable report must not name a target it never contacted either.
///
/// The text banner was the half of this defect a reader sees; `validate --json <file>` writes
/// the same claim through the same flag a run uses, and a consumer holding only that file has
/// nothing else to go on. The per-case verdict already says `validated`; the header still said
/// a service answered.
#[test]
fn a_validate_only_json_report_names_no_target_and_no_transport() {
    let rendered = validated_report().render_json();
    assert!(rendered.contains("\"validate_only\": true"), "{rendered}");
    assert!(!rendered.contains("\"scripted\""), "the target it never contacted:\n{rendered}");
    assert!(!rendered.contains("\"hyper\""), "the transport it never opened:\n{rendered}");
    assert!(json::parse(&rendered).is_ok(), "{rendered}");
}

/// Negative — a run's JSON keeps naming its target, which is what the field is for.
#[test]
fn an_executed_json_report_still_names_its_target() {
    let rendered = report().render_json();
    assert!(rendered.contains("\"validate_only\": false"), "{rendered}");
    assert!(rendered.contains("\"target\": \"scripted\""), "{rendered}");
    assert!(rendered.contains("\"transport\": \"hyper\""), "{rendered}");
}

/// Negative — a case that was never executed cannot pay off a baseline failure.
#[test]
fn a_validated_case_is_not_an_improvement_over_a_recorded_failure() {
    let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "failed"}}"#).expect("valid baseline");
    assert!(
        validated_report().improvements(Some(&baseline)).is_empty(),
        "a corpus check tightened the ratchet without running anything"
    );
}

/// Negative — and it cannot hide one either: a schema or convention failure is still a
/// regression, which is what keeps `validate`\'s exit status meaningful.
#[test]
fn a_validate_only_report_still_regresses_on_a_convention_failure() {
    let subject = validated_report();
    // By id, not by count. A count of one is satisfied by whichever of the two cases the
    // filter happens to select, so `regressions()` could pick the validated case instead of
    // the failed one and this would still read green.
    let regressed: Vec<&str> = subject.regressions(None).iter().map(|o| o.id.as_str()).collect();
    assert_eq!(regressed, ["c-sig-0001"], "the failed case is the only regression");
}

#[test]
fn a_failure_carries_the_file_the_quirks_and_the_evidence() {
    let rendered = report().render_text(None);
    assert!(rendered.contains("file: cases/sig/c-sig-0001.toml"));
    assert!(rendered.contains("quirks: q-etag-0001"));
    assert!(rendered.contains("evidence: https://example.test/a"));
}

#[test]
fn a_skip_always_states_its_reason() {
    let rendered = report().render_text(None);
    assert!(rendered.contains("reason: no target"));
}

#[test]
fn without_a_baseline_every_failure_is_a_regression() {
    assert_eq!(report().regressions(None).len(), 1);
}

/// The baseline that records exactly what [`report`] concludes, which is the shape the
/// repository's own `conformance/baseline.json` is required to have: a row per case.
fn matching_baseline() -> Baseline {
    Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "skipped"}}"#)
        .expect("valid baseline")
}

#[test]
fn a_baseline_tolerates_a_recorded_failure() {
    assert!(report().regressions(Some(&matching_baseline())).is_empty());
}

#[test]
fn a_baseline_does_not_tolerate_a_new_failure() {
    let baseline =
        Baseline::from_json(r#"{"cases": {"c-etag-0001": "failed", "c-sig-0001": "passed", "c-mpu-0001": "skipped"}}"#)
            .expect("valid baseline");
    let subject = report();
    let regressions = subject.regressions(Some(&baseline));
    assert_eq!(regressions.len(), 1);
    assert_eq!(regressions[0].id, "c-sig-0001");
}

/// The rule that makes a `passed` row worth writing down.
///
/// Under the previous comparison this read green: only a failure could regress, so a family
/// that stopped executing altogether — rustfs/gateway#203's `object/` domain against
/// `Unwired`, rustfs/gateway#214's thirty-nine lost `acl` cases — was indistinguishable from
/// a family that ran and passed.
#[test]
fn a_recorded_pass_that_now_skips_is_a_regression() {
    let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
        .expect("valid baseline");
    let subject = report();
    let regressions = subject.regressions(Some(&baseline));
    assert_eq!(regressions.len(), 1);
    assert_eq!(regressions[0].id, "c-mpu-0001");
}

/// A skip the baseline already records is not news, and neither is one that turns into a pass.
#[test]
fn a_recorded_skip_may_keep_skipping_and_may_improve() {
    assert!(report().regressions(Some(&matching_baseline())).is_empty());
    let recovered =
        Baseline::from_json(r#"{"cases": {"c-etag-0001": "skipped", "c-sig-0001": "failed", "c-mpu-0001": "skipped"}}"#)
            .expect("valid baseline");
    let subject = report();
    let improvements = subject.improvements(Some(&recovered));
    assert_eq!(improvements.len(), 1);
    assert_eq!(improvements[0].id, "c-etag-0001");
}

/// A case with no row is read as one that ought to pass, so forgetting the row cannot buy
/// silence for a case that skips.
///
/// This is the half that makes the completeness policy enforceable rather than decorative:
/// without it, deleting a row is strictly weaker than editing one, and
/// `scripts/check_baseline_ratchet.sh` only ever looked at the rows that were there.
#[test]
fn a_case_with_no_row_is_expected_to_pass() {
    let baseline = Baseline::from_json(r#"{"cases": {"c-sig-0001": "failed"}}"#).expect("valid baseline");
    let subject = report();
    let regressions = subject.regressions(Some(&baseline));
    assert_eq!(regressions.len(), 1);
    assert_eq!(regressions[0].id, "c-mpu-0001", "an unrecorded skip is a regression");
}

/// A case that declares it does not apply to this run is not evidence about the target, in
/// either direction.
///
/// The shape this stops: a baseline recorded under `--profile aws` replayed under
/// `--profile minio` would otherwise report every `aws`-only case as a regression, because
/// the *run's own options* turned it into a skip before any request went out.
#[test]
fn a_case_that_does_not_apply_to_this_run_is_neither_a_regression_nor_an_improvement() {
    let mut subject = report();
    subject.outcomes[2].phase = Phase::Convention;
    subject.outcomes[2].skip_reason = Some("case.applies_to.profiles is [aws]".to_owned());
    let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
        .expect("valid baseline");
    assert!(
        subject.regressions(Some(&baseline)).is_empty(),
        "a profile-gated skip is the run's own doing, not the target's"
    );
    assert!(subject.improvements(Some(&baseline)).is_empty());
}

/// The control for the case above: the same verdict reached at [`Phase::Execute`] — the target
/// was asked and could not answer — is a regression.
#[test]
fn a_skip_the_target_caused_is_still_a_regression() {
    let subject = report();
    assert_eq!(subject.outcomes[2].phase, Phase::Execute);
    let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
        .expect("valid baseline");
    let regressions = subject.regressions(Some(&baseline));
    assert_eq!(regressions.len(), 1);
    assert_eq!(regressions[0].id, "c-mpu-0001");
}

/// A regression line names the verdict, because a regression is no longer always a failure.
///
/// Without it a reader who sees `regression: c-mpu-0001` goes looking for a failed assertion
/// that does not exist, and the actual finding — the case stopped running at all — is the one
/// thing the line does not say.
#[test]
fn a_regression_line_says_which_verdict_it_is() {
    let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "passed", "c-sig-0001": "failed", "c-mpu-0001": "passed"}}"#)
        .expect("valid baseline");
    let rendered = report().render_text(Some(&baseline));
    assert!(
        rendered.contains("regression: c-mpu-0001 is skipped (cases/mpu/c-mpu-0001.toml)"),
        "{rendered}"
    );
}

#[test]
fn the_verdict_ladder_puts_a_skip_between_a_failure_and_a_pass() {
    assert!(Verdict::Failed.rank() < Verdict::Skipped.rank());
    assert!(Verdict::Skipped.rank() < Verdict::Passed.rank());
}

#[test]
fn an_improvement_is_reported_so_the_ratchet_can_tighten() {
    let baseline = Baseline::from_json(r#"{"cases": {"c-etag-0001": "failed"}}"#).expect("valid baseline");
    assert_eq!(report().improvements(Some(&baseline)).len(), 1);
}

#[test]
fn a_baseline_with_an_unknown_verdict_is_refused() {
    assert!(Baseline::from_json(r#"{"cases": {"c-etag-0001": "flaky"}}"#).is_err());
}

#[test]
fn a_rendered_baseline_reloads() {
    let rendered = Baseline::render(&report());
    let baseline = Baseline::from_json(&rendered).expect("round trip");
    assert_eq!(baseline.expected("c-sig-0001"), Some(Verdict::Failed));
}

#[test]
fn the_junit_document_escapes_and_counts() {
    let rendered = report().render_junit();
    assert!(rendered.contains("tests=\"3\" failures=\"1\" skipped=\"1\""));
    assert!(rendered.contains("<skipped message=\"no target\"/>"));
    assert!(rendered.contains("<failure message=\"expect/status\">"));
}

#[test]
fn junit_escapes_markup_in_a_failure_message() {
    let mut subject = report();
    subject.outcomes[1].diagnostics = vec![Diagnostic::deny(
        "expect/body",
        "/expect/body",
        "expected <Prefix/> observed <Prefix></Prefix>",
    )];
    let rendered = subject.render_junit();
    assert!(rendered.contains("&lt;Prefix/&gt;"));
    assert!(!rendered.contains("observed <Prefix>"));
}

#[test]
fn the_json_report_is_parseable() {
    let rendered = report().render_json();
    let parsed = json::parse(&rendered).expect("valid JSON");
    assert_eq!(parsed.path("cases").and_then(Value::as_array).map(<[Value]>::len), Some(3));
}

// The run context: what the JSON and JUnit renderers say about the endpoint, the build and a
// ruling, beyond the verdicts.

fn ruled() -> crate::rulings::Rulings {
    crate::rulings::Rulings::parse(
        "[[ruling]]\nid = \"c-sig-0001\"\nverdict = \"accepted-change\"\nissue = \"rustfs/backlog#2684\"\n\
         approved_by = \"maintainer\"\nexpires = \"2027-01-31\"\n",
    )
    .expect("a complete ruling")
}

/// Positive — the JSON report carries what the run observed about its target and its ledger.
#[test]
fn the_json_report_names_the_endpoint_the_build_and_the_ruling() {
    let rulings = ruled();
    let context = RunContext {
        endpoint: Some("http://127.0.0.1:9100"),
        target_build: Some("RustFS"),
        rulings: Some(("rulings.toml", &rulings)),
    };
    let document = json::parse(&report().render_json_in(&context)).expect("well-formed JSON");
    assert_eq!(document.get("endpoint").and_then(Value::as_str), Some("http://127.0.0.1:9100"));
    assert_eq!(document.get("target_build").and_then(Value::as_str), Some("RustFS"));
    assert_eq!(document.get("rulings").and_then(Value::as_str), Some("rulings.toml"));
    let cases = document.get("cases").and_then(Value::as_array).expect("cases");
    let failed = cases
        .iter()
        .find(|c| c.get("id").and_then(Value::as_str) == Some("c-sig-0001"))
        .expect("the failure");
    assert_eq!(
        failed.get("verdict").and_then(Value::as_str),
        Some("failed"),
        "a ruled failure stays a failure"
    );
    let ruling = failed.get("ruling").expect("ruling key");
    assert_eq!(ruling.get("verdict").and_then(Value::as_str), Some("accepted-change"));
    assert_eq!(ruling.get("approved_by").and_then(Value::as_str), Some("maintainer"));
    assert_eq!(ruling.get("expires").and_then(Value::as_str), Some("2027-01-31"));
    let rendered = report().render_json_in(&context);
    assert!(
        rendered.contains("\"id\": \"c-etag-0001\"") && rendered.contains("\"ruling\": null"),
        "an unruled case carries null, not a missing key: {rendered}"
    );
}

/// Negative — a run without an endpoint or a ledger says so with `null`, never with a name it
/// did not observe.
#[test]
fn a_run_without_an_endpoint_or_a_ledger_reports_null_not_a_name() {
    // The reader models `null` as an empty table, so the literal is checked on the text.
    let rendered = report().render_json();
    json::parse(&rendered).expect("well-formed JSON");
    for key in ["endpoint", "target_build", "rulings"] {
        assert!(rendered.contains(&format!("\"{key}\": null")), "{key}: {rendered}");
    }
    let validated = validated_report().render_json_in(&RunContext {
        endpoint: Some("http://127.0.0.1:9100"),
        target_build: Some("RustFS"),
        rulings: None,
    });
    json::parse(&validated).expect("well-formed JSON");
    assert!(
        validated.contains("\"endpoint\": null") && validated.contains("\"target_build\": null"),
        "a validate-only run contacted no target, whatever the caller passed: {validated}"
    );
}

/// Negative — JUnit has no colour for "failed, but ruled", and must not borrow green.
#[test]
fn a_ruled_failure_stays_a_junit_failure_with_the_ruling_noted() {
    let rulings = ruled();
    let context = RunContext {
        endpoint: None,
        target_build: None,
        rulings: Some(("rulings.toml", &rulings)),
    };
    let rendered = report().render_junit_in(&context);
    assert!(rendered.contains("failures=\"1\""), "{rendered}");
    assert!(rendered.contains("<failure message=\"expect/status\">"), "{rendered}");
    assert!(
        rendered.contains("ruling: accepted-change rustfs/backlog#2684 approved by maintainer, expires 2027-01-31"),
        "{rendered}"
    );
    let unruled = report().render_junit();
    assert!(!unruled.contains("ruling:"), "{unruled}");
}

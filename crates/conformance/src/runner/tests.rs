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

//! Tests for the execution engine.
//!
//! Responsible for: proving the runner reaches a stated conclusion for every case in the real
//! corpus, that a case which cannot run is skipped with its reason rather than dropped, and that
//! a capture taken from one exchange reaches the next one before it is signed.
//! NOT responsible for: the assertions themselves (`crate::expect`).
//! Upstream: `super`. Downstream: nothing.

use super::*;
use crate::observation::Observation;
use crate::sut::{Scripted, Unwired};
use std::sync::OnceLock;

fn corpus() -> &'static Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let root = Corpus::discover_root().expect("the repository corpus");
        prepare_corpus(&root).expect("the corpus loads")
    })
}

/// Negative — parallel runner tests share one prepared corpus instead of reparsing it per test.
#[test]
fn the_repository_corpus_fixture_is_initialized_once() {
    assert!(std::ptr::eq(corpus(), corpus()));
}

#[test]
fn every_case_in_the_repository_corpus_reaches_a_conclusion() {
    let corpus = corpus();
    let mut sut = Unwired;
    let report = run(corpus, &mut sut, &RunOptions::default());
    assert_eq!(report.outcomes.len(), corpus.cases().len());
    assert!(report.outcomes.len() >= 22, "only {} cases", report.outcomes.len());
    for outcome in &report.outcomes {
        assert!(
            outcome.verdict != Verdict::Skipped || outcome.skip_reason.is_some(),
            "{} was skipped without a reason",
            outcome.id
        );
    }
}

#[test]
fn with_no_target_every_runnable_case_is_skipped_and_says_why() {
    let corpus = corpus();
    let mut sut = Unwired;
    let report = run(corpus, &mut sut, &RunOptions::default());
    let skipped: Vec<&CaseOutcome> = report.outcomes.iter().filter(|o| o.verdict == Verdict::Skipped).collect();
    assert_eq!(skipped.len(), report.outcomes.len(), "no case may pass without a target");
    assert!(
        skipped
            .iter()
            .all(|o| o.skip_reason.as_deref().is_some_and(|r| r.contains("facade")))
    );
}

#[test]
fn validate_only_validates_the_corpus_without_touching_a_target() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        validate_only: true,
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    let failed: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|o| o.verdict != Verdict::Validated)
        .map(|o| o.id.as_str())
        .collect();
    assert!(failed.is_empty(), "these cases are not internally consistent: {failed:?}");
}

/// Negative — a validate-only run must not be readable as a run that measured something.
///
/// The defect: `validate` set `Verdict::Passed` and the renderer printed the same target banner,
/// the same `1 passed`, and the same summary line a real run prints. `AGENTS.md` sent an agent to
/// `conformance validate --filter '<case-id>'` after changing one case, so a new case whose every
/// assertion was wrong read green through the one command the feedback-loop table names.
#[test]
fn a_validate_only_run_never_renders_as_an_execution_result() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        validate_only: true,
        filter: Some("c-etag-0001".to_owned()),
        ..RunOptions::default()
    };
    let rendered = run(corpus, &mut sut, &options).render_text(None);
    assert!(
        !rendered.contains("passed"),
        "a validate-only report claims a pass, and nothing was executed:\n{rendered}"
    );
    assert!(
        !rendered.contains("target "),
        "a validate-only report names a target it never contacted:\n{rendered}"
    );
    assert!(
        !rendered.contains("transport "),
        "a validate-only report names a transport it never opened:\n{rendered}"
    );
}

/// Negative — the verdict itself, not only its rendering, must differ from an executed pass.
///
/// The rendering test above would still hold if the renderer special-cased the word while the
/// verdict stayed `Passed`; every other consumer — the JSON report, the JUnit document, the
/// baseline — reads the verdict.
#[test]
fn a_validate_only_verdict_is_not_the_verdict_an_executed_case_gets() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        validate_only: true,
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert!(!report.outcomes.is_empty(), "the corpus is empty");
    let claimed: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Passed)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(
        claimed.is_empty(),
        "these cases were never executed and are recorded as passed: {claimed:?}"
    );
}

#[test]
fn a_filter_selects_by_directory_prefix() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        filter: Some("etag/".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].id, "c-etag-0001");
    assert!(report.filtered_out > 0);
}

#[test]
fn a_filter_that_matches_nothing_runs_nothing() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        filter: Some("no-such-domain/".to_owned()),
        ..RunOptions::default()
    };
    assert!(run(corpus, &mut sut, &options).outcomes.is_empty());
}

#[test]
fn glob_wildcards_match_within_the_path() {
    assert!(glob_contains("etag/", "cases/etag/c-etag-0001.toml"));
    assert!(glob_contains("*mpu*", "cases/mpu/c-mpu-0001.toml"));
    assert!(glob_contains("c-object-000?", "c-object-0007"));
    assert!(!glob_contains("c-object-000?", "c-object-0016"));
    assert!(!glob_contains("sig/", "cases/etag/c-etag-0001.toml"));
}

#[test]
fn a_profile_gate_skips_with_the_gate_named() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        profile: Profile::Minio,
        filter: Some("etag/".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].verdict, Verdict::Skipped);
    assert!(
        report.outcomes[0]
            .skip_reason
            .as_deref()
            .is_some_and(|r| r.contains("applies_to.profiles"))
    );
}

#[test]
fn a_scripted_target_that_answers_correctly_makes_a_case_pass() {
    let corpus = corpus();
    let body = b"hello world".to_vec();
    let headers = vec![
        ("content-type".to_owned(), "text/plain; charset=utf-8".to_owned()),
        ("content-length".to_owned(), "11".to_owned()),
        ("etag".to_owned(), "\"5eb63bbbe01eeed093cb22bb8f5acdc3\"".to_owned()),
        ("last-modified".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned()),
        ("accept-ranges".to_owned(), "bytes".to_owned()),
    ];
    let mut observation = Observation::response(200, headers, body);
    observation.connection_after = Some(crate::observation::ConnectionState::Open);
    let mut sut = Scripted::new().with("c-object-0001", 0, observation);
    let options = RunOptions {
        filter: Some("c-object-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].verdict, Verdict::Passed, "{:?}", report.outcomes[0].diagnostics);
}

/// Negative — `Validated` belongs to `validate` alone and must never appear over an execution.
///
/// The distinction is only worth having in one direction as well as the other: a runner that
/// reached for the new verdict on a run that *did* measure something would understate a real pass
/// and, through `improvements`, quietly stop the baseline ratchet from tightening.
#[test]
fn a_run_that_executes_records_a_pass_not_a_validation() {
    let corpus = corpus();
    let body = b"hello world".to_vec();
    let headers = vec![
        ("content-type".to_owned(), "text/plain; charset=utf-8".to_owned()),
        ("content-length".to_owned(), "11".to_owned()),
        ("etag".to_owned(), "\"5eb63bbbe01eeed093cb22bb8f5acdc3\"".to_owned()),
        ("last-modified".to_owned(), "Fri, 02 Jan 2026 03:04:05 GMT".to_owned()),
        ("accept-ranges".to_owned(), "bytes".to_owned()),
    ];
    let mut observation = Observation::response(200, headers, body);
    observation.connection_after = Some(crate::observation::ConnectionState::Open);
    let mut sut = Scripted::new().with("c-object-0001", 0, observation);
    let options = RunOptions {
        filter: Some("c-object-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert!(!report.validate_only, "this run is not a corpus check");
    let outcome = report.outcomes.first().expect("c-object-0001 is selected");
    assert_ne!(
        outcome.verdict,
        Verdict::Validated,
        "a case that a target answered is recorded as merely validated"
    );
    assert_eq!(outcome.verdict, Verdict::Passed, "{:?}", outcome.diagnostics);
}

#[test]
fn a_scripted_target_that_answers_wrongly_makes_the_same_case_fail() {
    let corpus = corpus();
    let mut sut = Scripted::new().with("c-object-0001", 0, Observation::response(500, Vec::new(), Vec::new()));
    let options = RunOptions {
        filter: Some("c-object-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert_eq!(report.outcomes[0].verdict, Verdict::Failed);
    let rules: Vec<&str> = report.outcomes[0].failures().iter().map(|d| d.rule.as_str()).collect();
    assert!(rules.contains(&"expect/status"), "{rules:?}");
    assert!(rules.contains(&"expect/body.exact_utf8"), "{rules:?}");
}

#[test]
fn a_failure_names_the_exchange_it_came_from() {
    let corpus = corpus();
    let mut sut = Scripted::new()
        .with("c-object-0002", 0, Observation::response(500, Vec::new(), Vec::new()))
        .with("c-object-0002", 1, Observation::response(500, Vec::new(), Vec::new()));
    let options = RunOptions {
        filter: Some("c-object-0002".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    let messages: Vec<&str> = report.outcomes[0].failures().iter().map(|d| d.message.as_str()).collect();
    assert!(messages.iter().any(|m| m.starts_with("exchange #1 head")), "{messages:?}");
    assert!(messages.iter().any(|m| m.starts_with("exchange #2 get-agrees")), "{messages:?}");
}

#[test]
fn a_capture_from_one_exchange_is_substituted_into_the_next_request() {
    let corpus = corpus();
    let page1 = Observation::response(
        200,
        vec![("content-type".to_owned(), "application/xml".to_owned())],
        b"<R><NextContinuationToken>tok-99</NextContinuationToken></R>".to_vec(),
    );
    let page2 = Observation::response(200, Vec::new(), Vec::new());
    let mut sut = Scripted::new().with("c-list-0001", 0, page1).with("c-list-0001", 1, page2);
    let options = RunOptions {
        filter: Some("c-list-0001".to_owned()),
        ..RunOptions::default()
    };
    let _ = run(corpus, &mut sut, &options);
    let second = sut.seen.get(1).expect("a second request was sent");
    let target = second.get("target").and_then(Value::as_str).unwrap_or_default();
    assert!(target.contains("continuation-token=tok-99"), "{target}");
    assert!(!target.contains("${capture."), "{target}");
}

#[test]
fn an_unbound_capture_fails_the_case_instead_of_sending_a_literal_placeholder() {
    let corpus = corpus();
    let page1 = Observation::response(200, Vec::new(), b"<R></R>".to_vec());
    let mut sut =
        Scripted::new()
            .with("c-list-0001", 0, page1)
            .with("c-list-0001", 1, Observation::response(200, Vec::new(), Vec::new()));
    let options = RunOptions {
        filter: Some("c-list-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert_eq!(report.outcomes[0].verdict, Verdict::Failed);
    let rules: Vec<&str> = report.outcomes[0].failures().iter().map(|d| d.rule.as_str()).collect();
    assert!(rules.contains(&"runner/interpolation"), "{rules:?}");
}

#[test]
fn setup_captures_reach_the_first_request() {
    let corpus = corpus();
    let mut sut = Scripted::new()
        .with_setup_capture("upload_id", "upload-42")
        .with_setup_capture("part1_etag", "\"part-1-digest\"")
        .with("c-mpu-0001", 0, Observation::response(200, Vec::new(), Vec::new()));
    let options = RunOptions {
        filter: Some("c-mpu-0001".to_owned()),
        ..RunOptions::default()
    };
    let _ = run(corpus, &mut sut, &options);
    let first = sut.seen.first().expect("a request was sent");
    let target = first.get("target").and_then(Value::as_str).unwrap_or_default();
    assert!(target.contains("uploadId=upload-42"), "{target}");
    // The body too, and from a second capture. Both halves of the case are interpolated from setup,
    // and a substitution that reached only the target would leave the body carrying the literal
    // `${capture.part1_etag}` — which the service would read as a part digest nothing has.
    let body = first
        .get("body")
        .and_then(|body| body.get("utf8"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(body.contains("<ETag>\"part-1-digest\"</ETag>"), "{body}");
    assert!(!body.contains("${capture."), "{body}");
}

#[test]
fn an_environment_failure_is_a_skip_not_a_red_case() {
    let corpus = corpus();
    let mut sut = Scripted::new();
    let options = RunOptions {
        filter: Some("c-cond-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut sut, &options);
    assert_eq!(report.outcomes[0].verdict, Verdict::Skipped);
    assert!(
        report.outcomes[0]
            .skip_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("environment:"))
    );
}

// --- `${capture.<name>}` inside an `expect` block -----------------------------------------------
//
// Until this branch only `request` was interpolated, so `etag = "${capture.tag}"` in an expectation
// compared an observed header against the seventeen literal characters of the reference. That is
// the shape `AGENTS.md` lists eight times: a check that cannot pass reads as a red case, and its
// mirror — `not_contains_utf8 = ["${capture.tag}"]` — is a check that cannot *fail*. The tests
// below drive both directions through the real engine rather than asserting on the substitution
// helper, because the helper was never the broken part.

struct NoGoldens;

impl GoldenSource for NoGoldens {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        Err(format!("this test declares no golden `{relative}`"))
    }
}

/// A case built in memory rather than read from the corpus, so an expectation can be written that
/// the shipped corpus deliberately does not contain.
fn synthetic(id: &str, source: &str) -> Case {
    Case {
        id: id.to_owned(),
        domain: "synthetic".to_owned(),
        path: std::path::PathBuf::from(format!("cases/synthetic/{id}.toml")),
        relative: format!("cases/synthetic/{id}.toml"),
        document: Some(crate::toml::parse(source).expect("the test case is valid TOML")),
        diagnostics: Vec::new(),
    }
}

fn drive(case: &Case, sut: &mut dyn Sut) -> CaseOutcome {
    let mut notes = Vec::new();
    run_case(case, sut, &RunOptions::default(), &NoGoldens, &mut notes)
}

/// Two exchanges: the first publishes an entity tag in its body, the second asserts the header the
/// object carries *is that value*.
const ECHOES_A_CAPTURED_TAG: &str = r#"
[[exchanges]]
name = "the completion publishes a tag"
[exchanges.request]
method = "POST"
target = "/b/k?uploadId=u"
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.capture]
tag = { xml_text = "ETag" }

[[exchanges]]
name = "the object carries the same tag"
[exchanges.request]
method = "HEAD"
target = "/b/k"
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.headers_present]
etag = "${capture.tag}"
"#;

fn completion(body: &'static str) -> Observation {
    Observation::response(
        200,
        vec![("content-type".to_owned(), "application/xml".to_owned())],
        body.as_bytes().to_vec(),
    )
}

fn head_with_etag(etag: &str) -> Observation {
    Observation::response(200, vec![("etag".to_owned(), etag.to_owned())], Vec::new())
}

#[test]
fn a_capture_reaches_the_expect_block_of_a_later_exchange() {
    let case = synthetic("s-expect-0001", ECHOES_A_CAPTURED_TAG);
    let mut sut = Scripted::new()
        .with("s-expect-0001", 0, completion("<R><ETag>\"abc-1\"</ETag></R>"))
        .with("s-expect-0001", 1, head_with_etag("\"abc-1\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(
        outcome.verdict,
        Verdict::Passed,
        "{:?}",
        outcome.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

/// The control for the test above, and the one that makes it worth having. An expectation that was
/// substituted still has to be *compared*: a runner that dropped the reference, or replaced it with
/// a wildcard, would pass both.
#[test]
fn a_substituted_expectation_still_fails_when_the_value_differs() {
    let case = synthetic("s-expect-0002", ECHOES_A_CAPTURED_TAG);
    let mut sut = Scripted::new()
        .with("s-expect-0002", 0, completion("<R><ETag>\"abc-1\"</ETag></R>"))
        .with("s-expect-0002", 1, head_with_etag("\"abc-2\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    let messages: Vec<&str> = outcome.failures().iter().map(|d| d.message.as_str()).collect();
    assert!(
        messages.iter().any(|m| m.contains("expected `etag: \"abc-1\"`")),
        "the failure must name the substituted value, not the reference: {messages:?}"
    );
    assert!(
        !messages.iter().any(|m| m.contains("${capture.")),
        "an unsubstituted reference reached the comparison: {messages:?}"
    );
}

/// The mirror direction, and the one that was silently vacuous: a body that *must not* contain the
/// captured value. Under the old runner this compared against the literal reference and could
/// never fail, so the case below is the negative control for the whole change.
const REFUSES_A_CAPTURED_TAG: &str = r#"
[[exchanges]]
[exchanges.request]
method = "POST"
target = "/b/k?uploadId=u"
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.capture]
tag = { xml_text = "ETag" }

[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k?attributes"
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.body]
not_contains_utf8 = ["${capture.tag}"]
"#;

#[test]
fn a_not_contains_naming_a_capture_fires_when_the_value_is_there() {
    let case = synthetic("s-expect-0003", REFUSES_A_CAPTURED_TAG);
    let mut sut = Scripted::new()
        .with("s-expect-0003", 0, completion("<R><ETag>abc-1</ETag></R>"))
        .with("s-expect-0003", 1, completion("<A><ETag>abc-1</ETag></A>"));
    let outcome = drive(&case, &mut sut);
    assert_eq!(
        outcome.verdict,
        Verdict::Failed,
        "a `not_contains` naming a capture that is present must fire"
    );
}

#[test]
fn the_same_not_contains_holds_when_the_value_is_absent() {
    let case = synthetic("s-expect-0004", REFUSES_A_CAPTURED_TAG);
    let mut sut = Scripted::new()
        .with("s-expect-0004", 0, completion("<R><ETag>abc-1</ETag></R>"))
        .with("s-expect-0004", 1, completion("<A><ETag>def-2</ETag></A>"));
    let outcome = drive(&case, &mut sut);
    assert_eq!(
        outcome.verdict,
        Verdict::Passed,
        "{:?}",
        outcome.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

#[test]
fn an_unbound_capture_in_an_expectation_fails_the_case_and_names_the_field() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.headers_present]
etag = "${capture.never_bound}"
"#;
    let case = synthetic("s-expect-0005", source);
    let mut sut = Scripted::new().with("s-expect-0005", 0, head_with_etag("\"abc\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    let failure = outcome
        .failures()
        .into_iter()
        .find(|d| d.rule == "runner/interpolation")
        .cloned()
        .expect("the interpolation failure is reported");
    assert!(failure.pointer.ends_with("/expect"), "the field is named: {}", failure.pointer);
    assert!(failure.message.contains("never_bound"), "{}", failure.message);
}

#[test]
fn a_computed_form_in_an_expectation_is_refused_rather_than_compared_literally() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect]
kind = "response"
status = 200
[exchanges.expect.headers_present]
etag = "${md5(body)}"
"#;
    let case = synthetic("s-expect-0006", source);
    let mut sut = Scripted::new().with("s-expect-0006", 0, head_with_etag("\"abc\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    let rules: Vec<&str> = outcome.failures().iter().map(|d| d.rule.as_str()).collect();
    assert!(rules.contains(&"runner/interpolation"), "{rules:?}");
}

/// The one place substitution cannot reach, made loud rather than left silent. A reference in a
/// field *name* is not something the walk can resolve — a header name is not a value — so it is
/// refused. Leaving it alone would put a `${capture.x}` in the corpus that nothing ever touches
/// and that reads, afterwards, exactly like one that had been resolved.
#[test]
fn a_reference_in_a_field_name_is_refused_rather_than_left_where_it_stands() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect]
status = 200
[exchanges.expect.headers_present]
"${capture.header_name}" = "x"
"#;
    let case = synthetic("s-expect-0007", source);
    let mut sut = Scripted::new().with("s-expect-0007", 0, head_with_etag("\"abc\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    let failure = outcome
        .failures()
        .into_iter()
        .find(|d| d.rule == "runner/interpolation")
        .cloned()
        .expect("the interpolation failure is reported");
    assert!(failure.message.contains("field name"), "{}", failure.message);
}

/// The control: the request half is refused the same way, so this is a property of the walk rather
/// than of the expectation it was added for.
#[test]
fn a_reference_in_a_request_field_name_is_refused_too() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.request.headers]
"${capture.header_name}" = "x"
"#;
    let case = synthetic("s-expect-0008", source);
    let mut sut = Scripted::new().with("s-expect-0008", 0, head_with_etag("\"abc\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    let pointers: Vec<&str> = outcome
        .failures()
        .iter()
        .filter(|d| d.rule == "runner/interpolation")
        .map(|d| d.pointer.as_str())
        .collect();
    assert!(pointers.iter().any(|p| p.ends_with("/request")), "{pointers:?}");
}

/// And the other direction: an ordinary field name is untouched, so the refusal above is a rule
/// about `${`, not about names.
#[test]
fn an_ordinary_field_name_is_left_exactly_as_written() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect]
status = 200
[exchanges.expect.headers_present]
etag = "\"abc\""
"#;
    let case = synthetic("s-expect-0009", source);
    let mut sut = Scripted::new().with("s-expect-0009", 0, head_with_etag("\"abc\""));
    let outcome = drive(&case, &mut sut);
    assert_eq!(
        outcome.verdict,
        Verdict::Passed,
        "{:?}",
        outcome.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

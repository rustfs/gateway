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

//! Tests for the corpus conventions.
//!
//! Responsible for: proving each convention check fires — an identifier that disagrees with its
//! file, a capture reference nothing produces, a `${...}` written where substitution cannot reach
//! it — and that the shipped corpus violates none of them. Negative cases outnumber positive ones:
//! for every "this is accepted" there is at least one "and this is what is refused".
//! NOT responsible for: schema validation (`crate::schema`) or execution (`crate::runner`).
//! Upstream: `super`. Downstream: nothing.

use super::*;
use crate::corpus::{Case, Corpus};
use crate::diagnostic::Severity;

fn linted() -> Corpus {
    let root = Corpus::discover_root().expect("the repository corpus");
    let mut corpus = Corpus::load(&root).expect("the corpus loads");
    lint(&mut corpus);
    corpus
}

#[test]
fn the_repository_corpus_has_no_denied_convention_violation() {
    let corpus = linted();
    let denied: Vec<String> = corpus
        .cases()
        .iter()
        .flat_map(|case| {
            case.diagnostics
                .iter()
                .filter(|d| d.severity == Severity::Deny)
                .map(move |d| format!("{}: {d}", case.relative))
        })
        .collect();
    assert!(denied.is_empty(), "convention violations:\n{}", denied.join("\n"));
}

#[test]
fn negative_cases_outnumber_positive_ones() {
    let (negative, positive) = polarity_balance(&linted());
    assert!(negative >= positive, "{negative} negative versus {positive} positive");
}

#[test]
fn every_case_declares_a_rationale_and_evidence() {
    let corpus = linted();
    for case in corpus.cases() {
        // `get`, not `read`: `caseMeta.rationale` is declared inert in `crate::keys`, and a
        // test recording it would contradict that declaration.
        let rationale = case.document.as_ref().and_then(|doc| doc.path("case/rationale"));
        assert!(rationale.is_some(), "{} has no rationale", case.relative);
        let evidence = case
            .document
            .as_ref()
            .and_then(|doc| doc.path("case/evidence"))
            .and_then(Value::as_array)
            .map(<[Value]>::len)
            .unwrap_or(0);
        assert!(evidence > 0, "{} has no evidence", case.relative);
    }
}

#[test]
fn a_case_whose_identifier_disagrees_with_its_file_is_denied() {
    let root = Corpus::discover_root().expect("the repository corpus");
    let mut corpus = Corpus::load(&root).expect("the corpus loads");
    let case = &mut corpus.cases_mut()[0];
    if let Some(document) = case.document.as_mut()
        && let Some(meta) = document.get_mut("case")
    {
        meta.insert("id", Value::String("c-etag-9999".to_owned()));
    }
    lint(&mut corpus);
    let found = corpus.cases()[0].diagnostics.iter().any(|d| d.rule == "lint/id-file-name");
    assert!(found, "{:?}", corpus.cases()[0].diagnostics);
}

#[test]
fn an_unresolved_capture_reference_is_denied() {
    let root = Corpus::discover_root().expect("the repository corpus");
    let mut corpus = Corpus::load(&root).expect("the corpus loads");
    for case in corpus.cases_mut() {
        if case.id != "c-cond-0001" {
            continue;
        }
        if let Some(document) = case.document.as_mut()
            && let Some(request) = document.get_mut("request")
        {
            request.insert("target", Value::String("/b/${capture.nothing}".to_owned()));
        }
    }
    lint(&mut corpus);
    let case = corpus
        .cases()
        .iter()
        .find(|case| case.id == "c-cond-0001")
        .expect("c-cond-0001");
    assert!(
        case.diagnostics.iter().any(|d| d.rule == "lint/capture-unresolved"),
        "{:?}",
        case.diagnostics
    );
}

#[test]
fn a_computed_interpolation_form_is_denied_rather_than_invented() {
    let root = Corpus::discover_root().expect("the repository corpus");
    let mut corpus = Corpus::load(&root).expect("the corpus loads");
    for case in corpus.cases_mut() {
        if case.id != "c-cond-0001" {
            continue;
        }
        if let Some(document) = case.document.as_mut()
            && let Some(request) = document.get_mut("request")
        {
            request.insert("target", Value::String("/b/${md5(body)}".to_owned()));
        }
    }
    lint(&mut corpus);
    let case = corpus
        .cases()
        .iter()
        .find(|case| case.id == "c-cond-0001")
        .expect("c-cond-0001");
    assert!(
        case.diagnostics.iter().any(|d| d.rule == "lint/interpolation-unsupported"),
        "{:?}",
        case.diagnostics
    );
}

/// A case built in memory, so a reference the shipped corpus does not contain can be linted.
fn synthetic(source: &str) -> Case {
    Case {
        id: "s-lint-0001".to_owned(),
        domain: "synthetic".to_owned(),
        path: std::path::PathBuf::from("cases/synthetic/s-lint-0001.toml"),
        relative: "cases/synthetic/s-lint-0001.toml".to_owned(),
        document: Some(crate::toml::parse(source).expect("the test case is valid TOML")),
        diagnostics: Vec::new(),
    }
}

fn denials(source: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    check_interpolation(&synthetic(source), &mut out);
    out.into_iter().filter(|d| d.severity == Severity::Deny).collect()
}

/// A capture bound by an earlier exchange may be named in a later expectation. This is the
/// spelling the runner now substitutes, so the lint must not stand in its way.
const PRODUCED_THEN_ASSERTED: &str = r#"
[[exchanges]]
[exchanges.request]
method = "POST"
target = "/b/k?uploadId=u"
[exchanges.expect]
status = 200
[exchanges.expect.capture]
tag = { xml_text = "ETag" }

[[exchanges]]
[exchanges.request]
method = "HEAD"
target = "/b/k"
[exchanges.expect.headers_present]
etag = "${capture.tag}"
"#;

#[test]
fn an_expectation_may_name_a_capture_an_earlier_exchange_produced() {
    assert!(denials(PRODUCED_THEN_ASSERTED).is_empty(), "{:?}", denials(PRODUCED_THEN_ASSERTED));
}

#[test]
fn an_expectation_naming_a_capture_nothing_produces_is_denied() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect.body]
not_contains_utf8 = ["${capture.never_bound}"]
"#;
    let denied = denials(source);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].rule, "lint/capture-unresolved");
    assert!(denied[0].pointer.ends_with("/expect"), "{}", denied[0].pointer);
    assert!(denied[0].message.contains("never_bound"), "{}", denied[0].message);
}

/// The ordering rule, stated where it can fail. An expectation is judged *before* its own
/// captures are collected, so naming a value this same exchange is about to bind is a
/// reference to nothing — and it would read as an assertion that had been substituted.
#[test]
fn an_expectation_may_not_name_the_capture_its_own_exchange_binds() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect]
status = 200
[exchanges.expect.capture]
tag = { xml_text = "ETag" }
[exchanges.expect.headers_present]
etag = "${capture.tag}"
"#;
    let denied = denials(source);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].rule, "lint/capture-unresolved");
}

#[test]
fn a_computed_form_in_an_expectation_is_denied_by_name() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.expect.headers_present]
etag = "${md5(body)}"
"#;
    let denied = denials(source);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].rule, "lint/interpolation-unsupported");
    assert!(denied[0].pointer.ends_with("/expect"), "{}", denied[0].pointer);
}

#[test]
fn a_reference_written_in_a_field_name_is_denied_at_load() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.request.headers]
"${capture.header_name}" = "x"
"#;
    let denied = denials(source);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].rule, "lint/interpolation-in-field-name");
    assert!(denied[0].pointer.ends_with("/request"), "{}", denied[0].pointer);
}

/// The other direction: an ordinary field name is not a finding, so the rule is about `${`
/// rather than about names.
#[test]
fn an_ordinary_field_name_is_not_a_finding() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/k"
[exchanges.request.headers]
"if-match" = "\"abc\""
"#;
    assert!(denials(source).is_empty(), "{:?}", denials(source));
}

/// The control on the whole rule: the request half is still scanned, and still on its own
/// pointer, so widening the walk did not swallow the check that was already there.
#[test]
fn the_request_half_is_still_scanned_and_still_named_as_the_request() {
    let source = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/b/${capture.never_bound}"
"#;
    let denied = denials(source);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].rule, "lint/capture-unresolved");
    assert!(denied[0].pointer.ends_with("/request"), "{}", denied[0].pointer);
}

/// The three operations the model marks as able to fail after a `200`, lowered by
/// `cargo xtask codegen` and read here as the authority [`COMMITS_HEAD_EARLY`] is measured against.
///
/// Included rather than restated. A hand-written second copy of a generated list is a copy that can
/// disagree with it, and the disagreement would be silent in exactly the direction that matters: a
/// fourth operation gaining the property in the model, no case being allowed to declare a fault
/// against it, and nobody finding out until somebody read both files.
#[allow(dead_code, unreachable_pub)]
mod generated_error_codes {
    include!("../../../../generated/error_codes.rs");
}

/// Positive — the lint's list of head-committing operations is the generated one, in order.
#[test]
fn the_committed_operations_are_the_ones_the_model_lowered() {
    assert_eq!(COMMITS_HEAD_EARLY, generated_error_codes::ERROR_AFTER_200);
}

/// Negative — a fault declared after a commit, on an operation that has no commit, is denied.
///
/// `PutObject` answers when it is done, so there is no moment in it at which a status has been sent
/// and an outcome has not. A case declaring one would be run anyway: the fixture would arm nothing,
/// the request would succeed or be refused on its own terms, and the case would report whatever
/// that happened to be. The point of denying is that the scenario does not exist, not that the
/// wording is wrong.
#[test]
fn a_fault_after_a_commit_on_an_operation_that_does_not_commit_is_denied() {
    let root = Corpus::discover_root().expect("the repository corpus");
    let mut corpus = Corpus::load(&root).expect("the corpus loads");
    for case in corpus.cases_mut() {
        if case.id != "c-copy-0038" {
            continue;
        }
        if let Some(document) = case.document.as_mut()
            && let Some(fault) = document.get_mut("setup").and_then(|setup| setup.get_mut("fault"))
        {
            fault.insert("operation", Value::String("PutObject".to_owned()));
        }
    }
    lint(&mut corpus);
    let case = corpus
        .cases()
        .iter()
        .find(|case| case.id == "c-copy-0038")
        .expect("c-copy-0038");
    assert!(
        case.diagnostics.iter().any(|d| d.rule == "lint/fault-after-commit"),
        "{:?}",
        case.diagnostics
    );
}

/// Negative — the rule fires on the point, not on the presence of a fault.
///
/// The same operation with no `after_commit` is not denied, because the denial is about a moment
/// that does not exist in that operation rather than about faults being unwelcome. Without this the
/// rule above would be satisfied by a check that denied every fault it saw.
#[test]
fn a_fault_at_no_declared_point_is_not_denied_for_the_operation_that_carries_it() {
    let root = Corpus::discover_root().expect("the repository corpus");
    let mut corpus = Corpus::load(&root).expect("the corpus loads");
    for case in corpus.cases_mut() {
        if case.id != "c-copy-0038" {
            continue;
        }
        if let Some(document) = case.document.as_mut()
            && let Some(fault) = document.get_mut("setup").and_then(|setup| setup.get_mut("fault"))
        {
            fault.insert("operation", Value::String("PutObject".to_owned()));
            fault.insert("at", Value::String("before_commit".to_owned()));
        }
    }
    lint(&mut corpus);
    let case = corpus
        .cases()
        .iter()
        .find(|case| case.id == "c-copy-0038")
        .expect("c-copy-0038");
    assert!(
        !case.diagnostics.iter().any(|d| d.rule == "lint/fault-after-commit"),
        "{:?}",
        case.diagnostics
    );
}

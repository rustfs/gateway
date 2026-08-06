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

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("the repository corpus");
    prepare_corpus(&root).expect("the corpus loads")
}

#[test]
fn every_case_in_the_repository_corpus_reaches_a_conclusion() {
    let corpus = corpus();
    let mut sut = Unwired;
    let report = run(&corpus, &mut sut, &RunOptions::default());
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
    let report = run(&corpus, &mut sut, &RunOptions::default());
    let skipped: Vec<&CaseOutcome> = report.outcomes.iter().filter(|o| o.verdict == Verdict::Skipped).collect();
    assert_eq!(skipped.len(), report.outcomes.len(), "no case may pass without a target");
    assert!(
        skipped
            .iter()
            .all(|o| o.skip_reason.as_deref().is_some_and(|r| r.contains("facade")))
    );
}

#[test]
fn validate_only_passes_the_corpus_without_touching_a_target() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        validate_only: true,
        ..RunOptions::default()
    };
    let report = run(&corpus, &mut sut, &options);
    let failed: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|o| o.verdict != Verdict::Passed)
        .map(|o| o.id.as_str())
        .collect();
    assert!(failed.is_empty(), "these cases are not internally consistent: {failed:?}");
}

#[test]
fn a_filter_selects_by_directory_prefix() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        filter: Some("etag/".to_owned()),
        ..RunOptions::default()
    };
    let report = run(&corpus, &mut sut, &options);
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
    assert!(run(&corpus, &mut sut, &options).outcomes.is_empty());
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
    let report = run(&corpus, &mut sut, &options);
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
    let report = run(&corpus, &mut sut, &options);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].verdict, Verdict::Passed, "{:?}", report.outcomes[0].diagnostics);
}

#[test]
fn a_scripted_target_that_answers_wrongly_makes_the_same_case_fail() {
    let corpus = corpus();
    let mut sut = Scripted::new().with("c-object-0001", 0, Observation::response(500, Vec::new(), Vec::new()));
    let options = RunOptions {
        filter: Some("c-object-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(&corpus, &mut sut, &options);
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
    let report = run(&corpus, &mut sut, &options);
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
    let _ = run(&corpus, &mut sut, &options);
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
    let report = run(&corpus, &mut sut, &options);
    assert_eq!(report.outcomes[0].verdict, Verdict::Failed);
    let rules: Vec<&str> = report.outcomes[0].failures().iter().map(|d| d.rule.as_str()).collect();
    assert!(rules.contains(&"runner/interpolation"), "{rules:?}");
}

#[test]
fn setup_captures_reach_the_first_request() {
    let corpus = corpus();
    let mut sut = Scripted::new().with_setup_capture("upload_id", "upload-42").with(
        "c-mpu-0001",
        0,
        Observation::response(200, Vec::new(), Vec::new()),
    );
    let options = RunOptions {
        filter: Some("c-mpu-0001".to_owned()),
        ..RunOptions::default()
    };
    let _ = run(&corpus, &mut sut, &options);
    let first = sut.seen.first().expect("a request was sent");
    let target = first.get("target").and_then(Value::as_str).unwrap_or_default();
    assert!(target.contains("uploadId=upload-42"), "{target}");
}

#[test]
fn an_environment_failure_is_a_skip_not_a_red_case() {
    let corpus = corpus();
    let mut sut = Scripted::new();
    let options = RunOptions {
        filter: Some("c-cond-0001".to_owned()),
        ..RunOptions::default()
    };
    let report = run(&corpus, &mut sut, &options);
    assert_eq!(report.outcomes[0].verdict, Verdict::Skipped);
    assert!(
        report.outcomes[0]
            .skip_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("environment:"))
    );
}

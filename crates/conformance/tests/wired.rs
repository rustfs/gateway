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

//! The gate that says a target is wired and the suite really ran against it.
//!
//! Responsible for: proving, through the public API only, that the in-process target signs a
//! request, reaches a handler, and produces a judged verdict — and that the corpus is not
//! silently back to reporting a hundred and fifty-seven skips. A suite that stops asserting
//! anything looks exactly like a green one from every other angle, so this is the assertion that
//! has to exist before the baseline means anything.
//! NOT responsible for: what any particular case concludes. That is the baseline's job, and it is
//! meant to change.
//! Upstream: the published API of `rustfs_gateway_conformance`. Downstream: nothing.

use rustfs_gateway_conformance::corpus::Corpus;
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::Verdict;
use rustfs_gateway_conformance::runner::{self, RunOptions};

fn run(filter: &str) -> rustfs_gateway_conformance::report::Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some(filter.to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

/// Positive — the whole path works end to end: fixtures established, request signed, signature
/// verified, handler reached, response judged. `c-range-0001` is the case that exercises all of
/// it with nothing else in the way.
#[test]
fn a_signed_request_reaches_a_handler_and_the_case_is_judged() {
    let report = run("c-range-0001");
    let outcome = report.outcomes.first().expect("one case selected");
    assert_eq!(
        outcome.verdict,
        Verdict::Passed,
        "{}: {:?}",
        outcome.id,
        outcome.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

/// The property the whole run rests on: cases are *executed*. A regression that unwired the target
/// would leave every verdict a skip, the corpus checks would still be green, and nothing else in
/// this crate would notice.
#[test]
fn the_corpus_is_executed_rather_than_skipped() {
    let report = run("range/");
    let executed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict != Verdict::Skipped)
        .count();
    assert!(
        executed >= report.outcomes.len() / 2,
        "only {executed} of {} cases executed; the target looks unwired",
        report.outcomes.len()
    );
    assert!(
        report.outcomes.iter().any(|outcome| outcome.verdict == Verdict::Passed),
        "no case passed, which means nothing was actually measured"
    );
}

/// Negative — a case the in-process transport cannot express is skipped *with its reason*, never
/// answered from an approximation. `c-chunked-0001` half-closes the connection, which needs a
/// socket.
#[test]
fn a_case_needing_a_socket_is_skipped_with_the_capability_named() {
    let report = run("c-chunked-0001");
    let outcome = report.outcomes.first().expect("one case selected");
    assert_eq!(outcome.verdict, Verdict::Skipped);
    let reason = outcome.skip_reason.as_deref().unwrap_or_default();
    assert!(reason.contains("half_close"), "{reason}");
}

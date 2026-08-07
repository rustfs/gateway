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

use rustfs_gateway_conformance::conn::Conn;
use rustfs_gateway_conformance::corpus::Corpus;
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{CaseOutcome, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};
use rustfs_gateway_conformance::sut::Transport;

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

/// The same, over a real TCP connection.
fn run_over_a_socket(filter: &str) -> rustfs_gateway_conformance::report::Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = Conn::new(root);
    let options = RunOptions {
        filter: Some(filter.to_owned()),
        transport: Transport::Conn,
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

fn only(report: &rustfs_gateway_conformance::report::Report) -> &CaseOutcome {
    report.outcomes.first().expect("one case selected")
}

fn failures(outcome: &CaseOutcome) -> Vec<String> {
    outcome.failures().iter().map(ToString::to_string).collect()
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

// -- The socket transport ------------------------------------------------------------------------

/// **Negative — the assertion the socket transport exists for.**
///
/// `c-sig-0001` signs correctly, rewrites one canonical query component, and asserts that the
/// refusal arrived with **none** of the body written — `body_bytes_sent_at_response = 0` — and that
/// the connection was closed afterwards. Neither is answerable in process: there is no socket to
/// close, and a client that wrote its body in one call would have written all of it.
///
/// This is the case whose rationale says its body is "deliberately paced with `delay_ms`". If it
/// goes red on `request_progress`, the pacing has stopped being driven by the peer and the number
/// is the size of a kernel buffer again.
#[test]
fn the_paced_early_refusal_case_is_green_over_a_socket_and_red_without_one() {
    let over_a_socket = run_over_a_socket("c-sig-0001");
    let socket_outcome = only(&over_a_socket);
    assert_eq!(
        socket_outcome.verdict,
        Verdict::Passed,
        "{}: {:?}",
        socket_outcome.id,
        failures(socket_outcome)
    );

    // The control. One test alone proves nothing here: a transport that reported `closed` and `0`
    // unconditionally would satisfy the assertion above, and this is what says the corpus can still
    // tell the two targets apart.
    let in_process = run("c-sig-0001");
    let process_outcome = only(&in_process);
    assert_eq!(process_outcome.verdict, Verdict::Failed);
    assert!(
        failures(process_outcome)
            .iter()
            .any(|failure| failure.contains("connection_after")),
        "{:?}",
        failures(process_outcome)
    );
}

/// Negative — a truncated part is refused and never appears in the listing, which needs a client
/// that can stop sending in the middle of a declared length.
///
/// Both halves matter and only the second is falsifiable by the implementation: the status could be
/// right while the partial part was still stored, and the second exchange is what would catch it.
#[test]
fn a_truncated_upload_is_refused_and_leaves_nothing_behind() {
    let report = run_over_a_socket("c-mpu-0043");
    let outcome = only(&report);
    assert_eq!(outcome.verdict, Verdict::Passed, "{:?}", failures(outcome));

    // In process the same case cannot even be attempted, and says so rather than passing.
    let in_process = run("c-mpu-0043");
    assert_eq!(only(&in_process).verdict, Verdict::Skipped);
}

/// Negative — a case whose assertion the socket still cannot reach is **skipped with the reason**,
/// not answered from an approximation.
///
/// `c-cond-0013` is the sharp one: this transport really can put both requests on the wire before
/// reading either response, so the tempting move is to call the flag honoured and let the case run.
/// It would then be judged against a strictly ordered pair — the loser meets an object that is
/// simply there — and fail on the code, which is failing for a reason the case is not about. That
/// reads in a report exactly like failing for the right one.
#[test]
fn a_case_the_socket_still_cannot_stage_is_skipped_rather_than_answered() {
    let report = run_over_a_socket("c-cond-0013");
    let outcome = only(&report);
    assert_eq!(outcome.verdict, Verdict::Skipped, "{:?}", failures(outcome));
    let reason = outcome.skip_reason.as_deref().unwrap_or_default();
    assert!(reason.contains("race"), "{reason}");
}

/// Negative — an exchange whose outcome is true by construction says so on the case.
///
/// `c-mpu-0039`'s first exchange closes the connection itself, after which "no response arrived" and
/// "the socket is closed" are facts about a socket this client tore down — they cannot fail. The
/// case is worth running for its *later* exchange, which asserts the completion happened anyway, so
/// the honest handling is to run it and carry the warning rather than to let a green line stand for
/// a measurement nobody made.
#[test]
fn an_outcome_true_by_construction_is_warned_about_on_the_case() {
    let report = run_over_a_socket("c-mpu-0039");
    let outcome = only(&report);
    assert_eq!(outcome.verdict, Verdict::Passed, "{:?}", failures(outcome));
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule == "harness/by-construction"),
        "{:?}",
        outcome.diagnostics.iter().map(|d| d.rule.clone()).collect::<Vec<_>>()
    );
}

/// The property a socket run rests on, and the one a `--transport conn` that quietly ran in process
/// would have hidden: cases are executed *over a connection*, and they conclude.
#[test]
fn the_corpus_really_runs_over_a_connection() {
    let report = run_over_a_socket("cond/");
    let executed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict != Verdict::Skipped)
        .count();
    assert!(
        executed >= report.outcomes.len() / 2,
        "only {executed} of {} cases executed over a socket",
        report.outcomes.len()
    );
    assert!(report.outcomes.iter().any(|outcome| outcome.verdict == Verdict::Passed));
    assert_eq!(report.transport, "conn");
}

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

//! The `--rulings` contract on the command line.
//!
//! Responsible for: the option's refusals (`validate` evaluates nothing, `--baseline` is a second
//! ledger), the ledger's binding to the corpus, and the exit-code matrix at the end of a run —
//! an unruled failure, an unruled skip and an expired ruling each exit 1, a fully ruled run exits 0.
//! NOT responsible for: reading or judging a ledger, which `crate::rulings` owns.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::tests::{args, corpus};
use super::*;
use crate::observation::Observation;
use crate::report::{CaseOutcome, Phase};
use crate::rulings::Rulings;
use crate::sut::Scripted;
use std::path::Path;

/// A ledger file in the test's own scratch directory, removed on drop.
struct Ledger(PathBuf);

impl Ledger {
    fn write(name: &str, text: &str) -> Ledger {
        let path = std::env::temp_dir().join(format!("gateway-rulings-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, text).expect("write ledger");
        Ledger(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn ruling(id: &str, expires: &str) -> String {
    format!(
        "[[ruling]]\nid = \"{id}\"\nverdict = \"legacy-identical\"\nissue = \"rustfs/backlog#2684\"\n\
         approved_by = \"maintainer\"\nexpires = \"{expires}\"\n"
    )
}

/// The wrong answer to `c-object-0001`, so the case is red under `run`.
fn wrong_answer() -> Observation {
    Observation::response(
        500,
        vec![("content-type".to_owned(), "application/xml".to_owned())],
        b"<Error><Code>InternalError</Code></Error>".to_vec(),
    )
}

fn run_with(ledger: &Path) -> Options {
    let mut options = Options::parse(&args(&["run", "--filter", "c-object-0001"]))
        .expect("parses")
        .expect("not help");
    options.rulings = Some(ledger.to_path_buf());
    options
}

fn outcome(id: &str, verdict: Verdict, phase: Phase) -> CaseOutcome {
    CaseOutcome {
        id: id.to_owned(),
        domain: "object".to_owned(),
        relative: format!("cases/object/{id}.toml"),
        title: None,
        verdict,
        phase,
        skip_reason: (verdict == Verdict::Skipped).then(|| "no target".to_owned()),
        transport_limited: false,
        diagnostics: Vec::new(),
        quirks: Vec::new(),
        evidence: Vec::new(),
    }
}

fn report_of(outcomes: Vec<CaseOutcome>) -> Report {
    Report {
        target: "scripted".to_owned(),
        transport: "conn".to_owned(),
        profile: "rustfs".to_owned(),
        outcomes,
        filtered_out: 0,
        left_to_other_shards: 0,
        notes: Vec::new(),
        polarity: (1, 0),
        validate_only: false,
    }
}

// Negative — where the option is refused.

#[test]
fn validate_refuses_rulings() {
    let error = Options::parse(&args(&["validate", "--rulings", "ledger.toml"])).expect_err("validate judges nothing");
    assert!(error.contains("--rulings") && error.contains("validate"), "{error}");
}

#[test]
fn baseline_audit_keys_and_diff_transports_refuse_rulings() {
    for command in ["baseline", "audit-keys", "diff-transports"] {
        let error = Options::parse(&args(&[command, "--rulings", "ledger.toml"])).expect_err(command);
        assert!(error.contains("--rulings"), "{command}: {error}");
    }
}

#[test]
fn rulings_and_a_baseline_are_not_combined() {
    let error =
        Options::parse(&args(&["run", "--rulings", "ledger.toml", "--baseline", "baseline.json"])).expect_err("two ledgers");
    assert!(error.contains("--rulings") && error.contains("--baseline"), "{error}");
}

#[test]
fn a_rulings_option_without_its_value_is_a_usage_error() {
    assert!(Options::parse(&args(&["run", "--rulings"])).is_err());
}

#[test]
fn a_rulings_option_parses_for_run() {
    let options = Options::parse(&args(&["run", "--rulings", "ledger.toml"]))
        .expect("parses")
        .expect("not help");
    assert_eq!(options.rulings, Some(PathBuf::from("ledger.toml")));
}

// The exit-code matrix.

#[test]
fn a_failed_case_without_a_ruling_exits_regression() {
    let ledger = Ledger::write("empty", "");
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(
        execute_prepared(&run_with(ledger.path()), &mut sut, &corpus().1, None),
        ExitCode::from(exit::REGRESSION)
    );
}

#[test]
fn an_expired_ruling_exits_regression() {
    let ledger = Ledger::write("expired", &ruling("c-object-0001", "2020-01-01"));
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(
        execute_prepared(&run_with(ledger.path()), &mut sut, &corpus().1, None),
        ExitCode::from(exit::REGRESSION)
    );
}

#[test]
fn a_run_with_every_failure_ruled_exits_success() {
    let ledger = Ledger::write("ruled", &ruling("c-object-0001", "2099-12-31"));
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(
        execute_prepared(&run_with(ledger.path()), &mut sut, &corpus().1, None),
        ExitCode::from(exit::SUCCESS)
    );
}

#[test]
fn a_ruling_for_a_case_the_corpus_lacks_is_a_usage_error() {
    let ledger = Ledger::write("unknown", &ruling("c-nope-9999", "2099-12-31"));
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(
        execute_prepared(&run_with(ledger.path()), &mut sut, &corpus().1, None),
        ExitCode::from(exit::USAGE)
    );
    assert!(
        sut.seen.is_empty(),
        "a ledger the corpus cannot honour must be refused before any exchange"
    );
}

#[test]
fn a_malformed_ledger_is_a_usage_error_before_any_exchange() {
    let ledger = Ledger::write("malformed", "[[ruling]]\nid = \"c-object-0001\"\n");
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(
        execute_prepared(&run_with(ledger.path()), &mut sut, &corpus().1, None),
        ExitCode::from(exit::USAGE)
    );
    assert!(sut.seen.is_empty());
}

#[test]
fn an_unreadable_ledger_is_an_environment_error() {
    let missing = std::env::temp_dir().join(format!("gateway-rulings-{}-missing.toml", std::process::id()));
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(
        execute_prepared(&run_with(&missing), &mut sut, &corpus().1, None),
        ExitCode::from(exit::ENVIRONMENT)
    );
}

#[test]
fn a_skipped_case_without_a_ruling_exits_regression_and_with_one_exits_success() {
    let report = report_of(vec![
        outcome("c-object-0001", Verdict::Passed, Phase::Execute),
        outcome("c-object-0002", Verdict::Skipped, Phase::Execute),
    ]);
    let empty = Rulings::parse("").expect("empty");
    let today = crate::rulings::civil_day("2026-10-07").expect("a date");
    assert_eq!(
        status_code_under_rulings(&report, &empty.judge(&report, today), Command::Run),
        exit::REGRESSION
    );
    let ruled = Rulings::parse(&ruling("c-object-0002", "2026-12-31")).expect("ruled");
    assert_eq!(
        status_code_under_rulings(&report, &ruled.judge(&report, today), Command::Run),
        exit::SUCCESS
    );
}

#[test]
fn a_declared_inapplicable_skip_needs_a_ruling_too() {
    let report = report_of(vec![
        outcome("c-object-0001", Verdict::Passed, Phase::Execute),
        outcome("c-object-0002", Verdict::Skipped, Phase::Convention),
    ]);
    let empty = Rulings::parse("").expect("empty");
    let today = crate::rulings::civil_day("2026-10-07").expect("a date");
    assert_eq!(
        status_code_under_rulings(&report, &empty.judge(&report, today), Command::Run),
        exit::REGRESSION
    );
}

#[test]
fn an_all_skipped_run_under_rulings_is_still_an_environment_failure() {
    let report = report_of(vec![outcome("c-object-0001", Verdict::Skipped, Phase::Execute)]);
    let ruled = Rulings::parse(&ruling("c-object-0001", "2026-12-31")).expect("ruled");
    let today = crate::rulings::civil_day("2026-10-07").expect("a date");
    assert_eq!(
        status_code_under_rulings(&report, &ruled.judge(&report, today), Command::Run),
        exit::ENVIRONMENT,
        "a ruling must not turn a run in which nothing executed into a pass"
    );
}

/// Negative — a ruled failure is written as a failure, with the ruling beside it, never as a pass.
#[test]
fn the_json_report_keeps_a_ruled_failure_red_and_names_its_ruling() {
    let ledger = Ledger::write("json", &ruling("c-object-0001", "2099-12-31"));
    let json_path = std::env::temp_dir().join(format!("gateway-rulings-{}-report.json", std::process::id()));
    let mut options = run_with(ledger.path());
    options.json = Some(json_path.clone());
    let mut sut = Scripted::new().with("c-object-0001", 0, wrong_answer());
    assert_eq!(execute_prepared(&options, &mut sut, &corpus().1, None), ExitCode::from(exit::SUCCESS));
    let json = std::fs::read_to_string(&json_path).expect("the report was written");
    let _ = std::fs::remove_file(&json_path);
    let document = crate::json::parse(&json).expect("well-formed JSON");
    let case = document
        .get("cases")
        .and_then(crate::value::Value::as_array)
        .and_then(|cases| cases.first())
        .expect("one case");
    assert_eq!(case.get("verdict").and_then(crate::value::Value::as_str), Some("failed"));
    let ruling = case.get("ruling").expect("the ruling key");
    assert_eq!(ruling.get("verdict").and_then(crate::value::Value::as_str), Some("legacy-identical"));
    assert_eq!(ruling.get("issue").and_then(crate::value::Value::as_str), Some("rustfs/backlog#2684"));
    assert_eq!(
        document.get("rulings").and_then(crate::value::Value::as_str),
        Some(ledger.path().to_str().expect("UTF-8 path"))
    );
    assert_eq!(document.get("profile").and_then(crate::value::Value::as_str), Some("aws"));
}

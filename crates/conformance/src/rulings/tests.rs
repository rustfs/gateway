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

//! Tests for [`crate::rulings`]: the ledger reader, the binding to the corpus and the judgement.
//!
//! Responsible for: holding the rulings test suite in a sibling module so the source-size bound
//! keeps the reader itself readable. Negative cases outnumber positive ones on purpose: a ledger
//! that accepts a half-written row is a ledger that excuses a failure nobody reviewed.
//! NOT responsible for: the exit code, which `crate::cli::rulings_tests` owns.
//! Upstream: `crate::rulings`, `crate::report`. Downstream: nothing — test-only code.

use super::*;
use crate::report::{CaseOutcome, Phase, Report, Verdict};

const COMPLETE: &str = "\
[[ruling]]
id = \"c-sig-0001\"
verdict = \"legacy-identical\"
issue = \"rustfs/backlog#2684\"
approved_by = \"maintainer\"
expires = \"2027-01-31\"
";

fn outcome(id: &str, verdict: Verdict, phase: Phase) -> CaseOutcome {
    CaseOutcome {
        id: id.to_owned(),
        domain: "sig".to_owned(),
        relative: format!("cases/sig/{id}.toml"),
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

fn report(outcomes: Vec<CaseOutcome>) -> Report {
    Report {
        target: "scripted".to_owned(),
        transport: "hyper".to_owned(),
        profile: "rustfs".to_owned(),
        outcomes,
        filtered_out: 0,
        left_to_other_shards: 0,
        notes: Vec::new(),
        polarity: (1, 0),
        validate_only: false,
    }
}

fn day(text: &str) -> i64 {
    civil_day(text).expect("a calendar date")
}

/// A row with one field dropped, so each refusal is measured on its own.
fn without(field: &str) -> String {
    COMPLETE
        .lines()
        .filter(|line| !line.starts_with(field))
        .collect::<Vec<_>>()
        .join("\n")
}

// Negative — the reader refuses every incomplete row.

#[test]
fn a_ruling_without_approved_by_is_refused() {
    let error = Rulings::parse(&without("approved_by")).expect_err("no approver");
    assert!(error.contains("approved_by"), "{error}");
}

#[test]
fn a_ruling_without_an_issue_is_refused() {
    let error = Rulings::parse(&without("issue")).expect_err("no issue");
    assert!(error.contains("issue"), "{error}");
}

#[test]
fn a_ruling_without_an_expiry_is_refused() {
    let error = Rulings::parse(&without("expires")).expect_err("no expiry");
    assert!(error.contains("expires"), "{error}");
}

#[test]
fn a_ruling_without_an_id_is_refused() {
    let error = Rulings::parse(&without("id")).expect_err("no id");
    assert!(error.contains("id"), "{error}");
}

#[test]
fn a_ruling_with_an_unknown_verdict_is_refused() {
    let text = COMPLETE.replace("legacy-identical", "excused");
    let error = Rulings::parse(&text).expect_err("not a verdict");
    assert!(error.contains("excused"), "{error}");
    assert!(error.contains("legacy-identical") && error.contains("accepted-change"), "{error}");
}

#[test]
fn a_ruling_with_an_unreadable_expiry_is_refused() {
    for spelling in ["2027-1-31", "tomorrow", "2027-13-01", "20270131", "2027-01-31T00:00:00Z"] {
        let text = COMPLETE.replace("2027-01-31", spelling);
        let error = Rulings::parse(&text).expect_err(spelling);
        assert!(error.contains(spelling), "{spelling}: {error}");
    }
}

#[test]
fn a_ruling_with_an_unknown_key_is_refused() {
    let text = format!("{COMPLETE}note = \"left over\"\n");
    let error = Rulings::parse(&text).expect_err("unknown key");
    assert!(error.contains("note"), "{error}");
}

#[test]
fn an_empty_approver_is_refused() {
    let text = COMPLETE.replace("\"maintainer\"", "\"\"");
    let error = Rulings::parse(&text).expect_err("empty approver");
    assert!(error.contains("approved_by"), "{error}");
}

#[test]
fn a_duplicate_ruling_id_is_refused() {
    let text = format!("{COMPLETE}\n{COMPLETE}");
    let error = Rulings::parse(&text).expect_err("duplicate");
    assert!(error.contains("c-sig-0001"), "{error}");
}

#[test]
fn an_issue_that_is_not_a_repository_reference_is_refused() {
    for spelling in ["2684", "#2684", "rustfs/backlog", "backlog#2684", "rustfs/backlog#"] {
        let text = COMPLETE.replace("rustfs/backlog#2684", spelling);
        let error = Rulings::parse(&text).expect_err(spelling);
        assert!(error.contains("issue"), "{spelling}: {error}");
    }
}

#[test]
fn a_top_level_key_other_than_ruling_is_refused() {
    let error = Rulings::parse("[[verdict]]\nid = \"c-sig-0001\"\n").expect_err("wrong table");
    assert!(error.contains("verdict"), "{error}");
}

#[test]
fn a_ruling_that_is_not_a_table_is_refused() {
    let error = Rulings::parse("ruling = \"c-sig-0001\"\n").expect_err("not an array of tables");
    assert!(error.contains("ruling"), "{error}");
}

#[test]
fn a_ruling_for_an_unknown_case_id_is_an_error() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    let error = rulings.bind(["c-sig-0002", "c-etag-0001"]).expect_err("names no case");
    assert!(error.contains("c-sig-0001"), "{error}");
    rulings.bind(["c-sig-0001"]).expect("bound");
}

// Positive — a complete ledger is read, and an empty one is a ledger.

#[test]
fn a_complete_ledger_is_read_and_looked_up_by_id() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    assert_eq!(rulings.len(), 1);
    let ruling = rulings.get("c-sig-0001").expect("present");
    assert_eq!(ruling.verdict, RulingVerdict::LegacyIdentical);
    assert_eq!(ruling.issue, "rustfs/backlog#2684");
    assert_eq!(ruling.approved_by, "maintainer");
    assert_eq!(ruling.expires, "2027-01-31");
    assert!(rulings.get("c-sig-0002").is_none());
}

#[test]
fn an_empty_ledger_holds_no_ruling() {
    let rulings = Rulings::parse("").expect("empty is a ledger");
    assert!(rulings.is_empty());
    rulings.bind(["c-sig-0001"]).expect("nothing to bind");
}

#[test]
fn both_verdict_spellings_are_read() {
    let text = COMPLETE.replace("legacy-identical", "accepted-change");
    let ruling = Rulings::parse(&text).expect("complete");
    assert_eq!(ruling.get("c-sig-0001").map(|r| r.verdict), Some(RulingVerdict::AcceptedChange));
}

// Expiry — the day after the date, not the date itself.

#[test]
fn a_ruling_expires_the_day_after_its_date() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    let ruling = rulings.get("c-sig-0001").expect("present");
    assert!(!ruling.is_expired(day("2027-01-30")));
    assert!(!ruling.is_expired(day("2027-01-31")));
    assert!(ruling.is_expired(day("2027-02-01")));
}

#[test]
fn a_calendar_day_counts_from_the_epoch() {
    assert_eq!(day("1970-01-01"), 0);
    assert_eq!(day("1970-01-02"), 1);
    assert_eq!(day("2024-03-01") - day("2024-02-28"), 2);
    assert!(civil_day("1969-12-31").expect("before the epoch") < 0);
}

// Judgement — what a finished report owes the ledger.

#[test]
fn a_failed_case_without_a_ruling_is_unruled() {
    let rulings = Rulings::parse("").expect("empty");
    let report = report(vec![outcome("c-sig-0001", Verdict::Failed, Phase::Execute)]);
    let judgement = rulings.judge(&report, day("2026-10-07"));
    assert_eq!(judgement.unruled.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), ["c-sig-0001"]);
    assert!(judgement.blocks());
}

#[test]
fn a_skipped_case_without_a_ruling_is_unruled() {
    let rulings = Rulings::parse("").expect("empty");
    let report = report(vec![
        outcome("c-sig-0001", Verdict::Skipped, Phase::Execute),
        outcome("c-sig-0002", Verdict::Skipped, Phase::Convention),
    ]);
    let judgement = rulings.judge(&report, day("2026-10-07"));
    assert_eq!(judgement.unruled.len(), 2, "a declared-inapplicable skip needs a ruling too");
    assert!(judgement.blocks());
}

#[test]
fn an_expired_ruling_is_reported_expired_not_ruled() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    let report = report(vec![outcome("c-sig-0001", Verdict::Failed, Phase::Execute)]);
    let judgement = rulings.judge(&report, day("2027-02-01"));
    assert!(judgement.ruled.is_empty());
    assert_eq!(judgement.expired.len(), 1);
    assert!(judgement.blocks());
}

#[test]
fn a_passed_case_needs_no_ruling_and_its_ruling_is_stale() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    let report = report(vec![
        outcome("c-sig-0001", Verdict::Passed, Phase::Execute),
        outcome("c-sig-0002", Verdict::Passed, Phase::Execute),
    ]);
    let judgement = rulings.judge(&report, day("2026-10-07"));
    assert!(judgement.unruled.is_empty());
    assert_eq!(judgement.stale.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["c-sig-0001"]);
    assert!(!judgement.blocks(), "a stale ruling is a note, not a failure");
}

#[test]
fn a_ruled_failure_does_not_block() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    let report = report(vec![outcome("c-sig-0001", Verdict::Failed, Phase::Execute)]);
    let judgement = rulings.judge(&report, day("2026-10-07"));
    assert_eq!(judgement.ruled.len(), 1);
    assert!(!judgement.blocks());
    let rendered = judgement.render("ledger.toml");
    assert!(rendered.contains("1 ruled, 0 unruled, 0 expired"), "{rendered}");
    assert!(rendered.contains("rustfs/backlog#2684"), "{rendered}");
}

#[test]
fn the_rendered_judgement_names_every_unruled_and_expired_case() {
    let rulings = Rulings::parse(COMPLETE).expect("complete");
    let report = report(vec![
        outcome("c-sig-0001", Verdict::Failed, Phase::Execute),
        outcome("c-sig-0002", Verdict::Skipped, Phase::Execute),
    ]);
    let rendered = rulings.judge(&report, day("2027-02-01")).render("ledger.toml");
    assert!(rendered.contains("expired  c-sig-0001"), "{rendered}");
    assert!(rendered.contains("unruled  c-sig-0002"), "{rendered}");
    assert!(rendered.contains("0 ruled, 1 unruled, 1 expired"), "{rendered}");
}

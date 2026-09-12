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

//! Process-boundary checks for persistence coverage and migration closure.
//!
//! Responsible for: observing real CLI output and exit status when acceptance is blocked.
//! Not responsible for: defining codecs, corpus fixtures, or library acceptance rules.
//! Upstream: the shipped goldens binaries. Downstream: the persistence migration gate.

use std::process::{Command, Output};

fn corpus_report() -> Output {
    Command::new(env!("CARGO_BIN_EXE_corpus-report"))
        .output()
        .expect("run corpus-report")
}

#[test]
fn sample_regression_commands_remain_successful() {
    let corpus = corpus_report();
    assert!(corpus.status.success(), "{corpus:?}");
    let four_way = Command::new(env!("CARGO_BIN_EXE_four-way"))
        .arg("--all")
        .output()
        .expect("run four-way");
    assert!(four_way.status.success(), "{four_way:?}");
    assert!(String::from_utf8_lossy(&four_way.stdout).starts_with("D1..D5 all clean, 183 samples across 13 families"));
}

#[test]
fn n_corpus_report_discloses_blocked_acceptance_rows() {
    let output = corpus_report();
    let text = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(text.contains("P9-01 acceptance census: passed=36 blocked=3 total=39"), "{text}");
    assert_eq!(text.lines().filter(|line| line.starts_with("g-")).count(), 39);
    for row in [
        "g-d1-003: blocked issue=https://github.com/rustfs/backlog/issues/2104",
        "g-d4-001: blocked issue=https://github.com/rustfs/backlog/issues/2096",
        "g-d5-001: blocked issue=https://github.com/rustfs/backlog/issues/2096",
    ] {
        assert!(text.contains(row), "missing {row}");
    }
}

#[test]
fn n_corpus_report_discloses_missing_approved_source() {
    let output = corpus_report();
    let text = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(text.contains("persisted metadata sources: 3/4 approved sources present"), "{text}");
    for row in [
        "a-repository-fixture: writer=n/a witnessed=",
        "b-client-matrix: writer=n/a witnessed=",
        "c-minio-migration-export: writer=minio@",
        "d-prime-historical-writer-matrix: absent",
    ] {
        assert!(text.contains(row), "missing {row}");
    }
    assert!(text.contains("approved persisted-metadata source absent: d-prime-historical-writer-matrix"));
}

#[test]
fn n_strict_closure_refuses_missing_historical_writers() {
    let output = Command::new(env!("CARGO_BIN_EXE_corpus-report"))
        .arg("--require-closure")
        .output()
        .expect("run strict closure");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).expect("UTF-8 diagnostic");
    assert_eq!(
        diagnostic,
        "migration closure failed: ApprovedSourceAbsent { source: \"d-prime-historical-writer-matrix\", cases: [\"g-d4-001\", \"g-d5-001\"] }\n"
    );
}

#[test]
fn n_unknown_or_combined_modes_are_rejected() {
    for args in [vec!["--all"], vec!["--require-closure", "--all"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_corpus-report"))
            .args(args)
            .output()
            .expect("run corpus-report");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&output.stderr), "usage: corpus-report [--require-closure]\n");
    }
}

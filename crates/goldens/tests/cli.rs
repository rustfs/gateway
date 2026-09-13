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
    assert!(String::from_utf8_lossy(&four_way.stdout).starts_with("D1..D5 all clean, 206 samples across 13 families"));
}

#[test]
fn corpus_report_discloses_every_acceptance_row_as_passed() {
    let output = corpus_report();
    let text = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(text.contains("P9-01 acceptance census: passed=39 blocked=0 total=39"), "{text}");
    assert_eq!(text.lines().filter(|line| line.starts_with("g-")).count(), 39);
    assert!(!text.contains("blocked issue="), "{text}");
    for row in [
        "g-d1-003: passed source=crates/goldens/src/lifecycle.rs::UNKNOWN_TOP_LEVEL_SUBTREES",
        "g-d4-001: passed source=crates/goldens/src/historical_writer.rs::append",
        "g-d5-001: passed source=crates/goldens/src/historical_writer.rs::append",
    ] {
        assert!(text.contains(row), "missing {row}");
    }
    assert!(!text.contains("issues/2096"), "{text}");
}

/// Source (d′) is collected: the report names every writer version, and nothing reads absent.
#[test]
fn corpus_report_lists_every_approved_source_and_historical_writer() {
    let output = corpus_report();
    let text = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(text.contains("persisted metadata sources: 4/4 approved sources present"), "{text}");
    for row in [
        "a-repository-fixture: writer=n/a witnessed=",
        "b-client-matrix: writer=n/a witnessed=",
        "c-minio-migration-export: writer=minio@",
        "d-prime-historical-writer-matrix: writer=rustfs@1.0.0-alpha.64 witnessed=",
        "d-prime-historical-writer-matrix: writer=rustfs@1.0.0-alpha.94 witnessed=",
        "d-prime-historical-writer-matrix: writer=rustfs@v1.0.0-beta.1 witnessed=",
        "d-prime-historical-writer-matrix: writer=rustfs@1.0.0-beta.12 witnessed=",
        "d-prime-historical-writer-matrix: writer=minio@RELEASE.2025-04-22T22-12-26Z witnessed=",
        "d-prime-historical-writer-matrix: writer=minio@RELEASE.2025-09-07T16-13-09Z witnessed=",
    ] {
        assert!(text.contains(row), "missing {row}");
    }
    assert!(!text.contains(": absent"), "{text}");
    assert!(!text.contains("approved persisted-metadata source absent"), "{text}");
}

/// Every source is present and no case is blocked, so strict closure exits zero and prints the
/// fully passed census on standard output.
#[test]
fn strict_closure_succeeds_on_the_real_evidence() {
    let output = Command::new(env!("CARGO_BIN_EXE_corpus-report"))
        .arg("--require-closure")
        .output()
        .expect("run strict closure");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let census = String::from_utf8(output.stdout).expect("UTF-8 census");
    assert!(census.starts_with("P9-01 acceptance census: passed=39 blocked=0 total=39\n"), "{census}");
    assert!(!census.contains("blocked issue="), "{census}");
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

/// A non-UTF-8 argument is a usage error with status 1, not a panic with status 101.
#[cfg(unix)]
#[test]
fn n_non_utf8_argument_is_a_usage_error_not_a_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let output = Command::new(env!("CARGO_BIN_EXE_corpus-report"))
        .arg(OsStr::from_bytes(b"--require-closure\xff"))
        .output()
        .expect("run corpus-report");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8_lossy(&output.stderr), "usage: corpus-report [--require-closure]\n");
}

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

/// Every source is present, no P9-01 case is blocked, every decided refusal re-proves, and no
/// refusal boundary moves under any pinned s3s revision since rustfs/gateway#740: strict closure
/// exits zero, prints the whole verdict on standard output and nothing on standard error.
#[test]
fn strict_closure_holds_under_every_revision() {
    let output = Command::new(env!("CARGO_BIN_EXE_corpus-report"))
        .arg("--require-closure")
        .output()
        .expect("run strict closure");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("UTF-8 verdict");
    assert!(text.contains("P9-01 acceptance census: passed=39 blocked=0 total=39\n"), "{text}");
    assert!(text.contains("oracle admission: revisions=3 open-findings=0\n"), "{text}");
    assert!(!text.contains("finding "), "{text}");
    assert!(text.contains("request divergences: rulings=66 "), "{text}");
    assert_eq!(text.lines().filter(|line| line.starts_with("divergence rd-")).count(), 66, "{text}");
}

/// The ordinary report shows every revision's D1-D5, widening and refusal evidence.
#[test]
fn ordinary_report_shows_evidence_per_oracle_revision() {
    let output = Command::new(env!("CARGO_BIN_EXE_corpus-report"))
        .output()
        .expect("run corpus report");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(text.contains("P9-01 acceptance census: passed=39 blocked=0 total=39\n"), "{text}");
    assert!(text.contains("oracle admission: revisions=3 open-findings=0\n"), "{text}");
    assert!(
        text.contains("migration inventory: decided-refusals=1 rollback-constraints=1\nrefusal persisted-doctype decision=https://github.com/rustfs/gateway/issues/469 "),
        "{text}"
    );
    assert!(
        text.contains(
            "request divergences: rulings=66 keep-gateway=37 align-s3s=11 align-aws=2 rustfs-profile=16 open-follow-ups=10 landed=22\n\
             divergence rd-put-0001 operation=PutObject ruling=rustfs-profile follow-up=c-object-0058 "
        ),
        "{text}"
    );
    // The baseline predates the two `BlockedEncryptionTypes` samples (rustfs/gateway#740), so it
    // widens them; the rollback and candidate revisions run them through D1-D5.
    for (oracle, samples, widened) in [
        ("baseline s3s@9c4690d8", 206, 2),
        ("rollback s3s@bdcb6259", 208, 0),
        ("candidate s3s@0.17.0", 208, 0),
    ] {
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("oracle {oracle} build=")))
            .unwrap_or_else(|| panic!("missing {oracle} in {text}"));
        assert!(
            line.contains(&format!(": d1-d5 samples={samples} widened={widened} families=13 ")),
            "{line}"
        );
        assert!(line.ends_with(" moved-refusals=0"), "{line}");
    }
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

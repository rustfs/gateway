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

//! The `--shard` partition over a selection.
//!
//! Responsible for: proving the shards cover the selection exactly once, in corpus order, and
//! that a partial run says so. NOT responsible for: the command line, which `cli::shard_tests`
//! owns.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::tests::corpus;
use super::*;
use crate::sut::Unwired;

#[test]
fn shards_partition_the_selection_exactly_once_in_corpus_order() {
    let corpus = corpus();
    let whole: Vec<String> = run(
        corpus,
        &mut Unwired,
        &RunOptions {
            filter: Some("mpu/".to_owned()),
            ..RunOptions::default()
        },
    )
    .outcomes
    .into_iter()
    .map(|outcome| outcome.id)
    .collect();
    assert!(whole.len() >= 3, "the mpu family is large enough to shard three ways");
    let mut seen = Vec::new();
    for index in 0..3 {
        let options = RunOptions {
            filter: Some("mpu/".to_owned()),
            shard: Some(Shard { index, count: 3 }),
            ..RunOptions::default()
        };
        let report = run(corpus, &mut Unwired, &options);
        let ids: Vec<String> = report.outcomes.iter().map(|outcome| outcome.id.clone()).collect();
        // Each shard takes every third selected case starting at its index, in corpus order.
        let expected: Vec<String> = whole.iter().skip(index).step_by(3).cloned().collect();
        assert_eq!(ids, expected, "shard {index}/3");
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.starts_with(&format!("shard {index}/3: {} selected case(s) ran here", ids.len()))),
            "a partial run must say so on the report: {:?}",
            report.notes
        );
        seen.extend(ids);
    }
    seen.sort();
    let mut all = whole.clone();
    all.sort();
    assert_eq!(seen, all, "the three shards together are the whole selection, each case exactly once");
}

#[test]
fn a_shard_never_owns_a_case_the_filter_or_the_slow_rule_excluded() {
    let corpus = corpus();
    let options = RunOptions {
        filter: Some("no-such-domain/".to_owned()),
        shard: Some(Shard { index: 0, count: 2 }),
        ..RunOptions::default()
    };
    let report = run(corpus, &mut Unwired, &options);
    assert!(report.outcomes.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note == "shard 0/2: 0 selected case(s) ran here, 0 belong to the other shards")
    );
}

#[test]
fn a_single_shard_is_the_whole_selection_and_no_shard_note_appears_without_one() {
    let corpus = corpus();
    let plain = run(
        corpus,
        &mut Unwired,
        &RunOptions {
            filter: Some("etag/".to_owned()),
            ..RunOptions::default()
        },
    );
    let single = run(
        corpus,
        &mut Unwired,
        &RunOptions {
            filter: Some("etag/".to_owned()),
            shard: Some(Shard { index: 0, count: 1 }),
            ..RunOptions::default()
        },
    );
    assert_eq!(single.outcomes.len(), plain.outcomes.len());
    assert!(!plain.notes.iter().any(|note| note.starts_with("shard ")));
    assert!(single.notes.iter().any(|note| note.starts_with("shard 0/1: ")));
}

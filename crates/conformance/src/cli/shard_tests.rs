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

//! The `--shard` contract on the command line.
//!
//! Responsible for: parsing, forwarding to the parity children, and the partial-run exit code.
//! NOT responsible for: the partition itself, which `runner::shard_tests` owns.
//! Upstream: `super`. Downstream: Cargo's test harness.

#[cfg(feature = "production-transports")]
use std::path::PathBuf;

use super::tests::{args, corpus};
use super::*;

#[test]
fn a_shard_option_parses() {
    let options = Options::parse(&args(&["diff-transports", "--exclude-slow", "--shard", "1/3"]))
        .expect("parses")
        .expect("not help");
    assert_eq!(options.shard, Some(Shard { index: 1, count: 3 }));
}

#[cfg(feature = "production-transports")]
#[test]
fn a_shard_option_reaches_both_transport_children() {
    let options = Options::parse(&args(&["diff-transports", "--exclude-slow", "--shard", "1/3"]))
        .expect("parses")
        .expect("not help");
    let arguments = parity::transport_child_args(&options, &corpus().0, Transport::Conn, PathBuf::from("report.json"));
    let position = arguments
        .iter()
        .position(|argument| argument == "--shard")
        .expect("shard forwarded");
    assert_eq!(arguments.get(position + 1).map(String::as_str), Some("1/3"));
    let without = Options::parse(&args(&["diff-transports"]))
        .expect("parses")
        .expect("not help");
    assert!(
        !parity::transport_child_args(&without, &corpus().0, Transport::Hyper, PathBuf::from("r.json"))
            .contains(&"--shard".to_owned())
    );
}

#[test]
fn a_malformed_shard_is_a_usage_error() {
    for text in ["3/3", "0/0", "x/2", "1", "1/", "/2", "-1/2", "1/two"] {
        let error = Options::parse(&args(&["run", "--shard", text])).expect_err(text);
        assert!(error.contains("--shard"), "{text}: {error}");
    }
    assert_eq!(Shard::parse("0/1"), Ok(Shard { index: 0, count: 1 }));
    assert_eq!(Shard::parse("4/5"), Ok(Shard { index: 4, count: 5 }));
}

/// Negative and positive — a shard that owns none of a non-empty selection is a partial run.
#[test]
fn an_empty_shard_of_a_non_empty_selection_is_not_an_empty_selection() {
    let (root, corpus) = corpus();
    let mut sut = InProcess::new(root.clone());
    // `etag/` selects one case, so the second of two shards owns none of it.
    let empty_shard = RunOptions {
        filter: Some("etag/".to_owned()),
        transport: Transport::Hyper,
        profile: Profile::Aws,
        include_slow: true,
        validate_only: false,
        shard: Some(Shard { index: 1, count: 2 }),
    };
    let report = runner::run(corpus, &mut sut, &empty_shard);
    assert!(report.outcomes.is_empty());
    assert_eq!(report.left_to_other_shards, 1);
    assert_eq!(status_code(&report, None, Command::Run), exit::SUCCESS);
    // The same shard over a filter that selects nothing is still an empty selection.
    let nothing = RunOptions {
        filter: Some("no-such-domain/".to_owned()),
        ..empty_shard
    };
    let report = runner::run(corpus, &mut sut, &nothing);
    assert!(report.outcomes.is_empty());
    assert_eq!(report.left_to_other_shards, 0);
    assert_eq!(status_code(&report, None, Command::Run), exit::ENVIRONMENT);
}

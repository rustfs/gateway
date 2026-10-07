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
//! Responsible for: proving `conformance baseline` renders the reference evaluation the gate holds,
//! not the selected transport's run (rustfs/gateway#985).
//! NOT responsible for: rendering the document or the reference rule itself (`runner::reference`).
//! Upstream: `super::evaluate`. Downstream: the repository verification gate.

#![allow(clippy::expect_used)]

use super::*;
use crate::sut::Unwired;

fn options(command: Command, filter: &str) -> Options {
    Options {
        command,
        filter: Some(filter.to_owned()),
        transport: Transport::Hyper,
        profile: Profile::Aws,
        root: None,
        endpoint: None,
        ca_cert: None,
        external_fixtures: false,
        baseline: None,
        rulings: None,
        json: None,
        junit: None,
        exclude_slow: false,
        shard: None,
    }
}

fn verdict(command: Command, filter: &str) -> Verdict {
    let root = Corpus::discover_root().expect("the corpus is available");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let options = options(command, filter);
    let run_options = RunOptions {
        filter: options.filter.clone(),
        ..RunOptions::default()
    };
    let report = evaluate(&options, &mut Unwired, &corpus, &run_options);
    report.outcomes.first().expect("one case is selected").verdict
}

/// Positive — `baseline` ignores the unwired target and records the reference verdict: a case that
/// needs a socket (`connection_after = "closed"`) passes on production Hyper.
#[test]
fn baseline_renders_the_reference_evaluation_not_the_selected_target() {
    assert_eq!(verdict(Command::Baseline, "c-sig-0001"), Verdict::Passed);
}

/// Negative — `run` still judges the target it was given, here one that executes nothing.
#[test]
fn run_still_judges_the_selected_target() {
    assert_ne!(verdict(Command::Run, "c-sig-0001"), Verdict::Passed);
}

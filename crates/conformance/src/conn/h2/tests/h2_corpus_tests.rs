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

//! Responsible for: executing the named HTTP/2 corpus family through the production Hyper transport.
//! NOT responsible for: synthetic peer fixtures, baseline allowances, or replacing case assertions.
//! Upstream: committed h2 cases and the normal runner; downstream: a real Hyper socket listener.

use super::*;
use crate::corpus::Corpus;
use crate::report::Verdict;
use crate::runner::{self, RunOptions};

#[test]
fn the_named_h2_corpus_runs_all_cases_on_production_hyper() {
    let root = Corpus::discover_root().expect("the real corpus is available");
    let corpus = runner::prepare_corpus(&root).expect("the real corpus loads");
    let mut target = Conn::production(root, ProductionDriver::Hyper);
    let options = RunOptions {
        filter: Some("c-h2-*".to_owned()),
        ..RunOptions::default()
    };
    let report = runner::run(&corpus, &mut target, &options);
    let ids: Vec<_> = report.outcomes.iter().map(|outcome| outcome.id.clone()).collect();
    assert_eq!(
        ids,
        (1..=21).map(|index| format!("c-h2-{index:04}")).collect::<Vec<_>>(),
        "missing or unexecuted named case"
    );
    for outcome in &report.outcomes {
        println!(
            "{}: {:?}, failures={:?}, skip={:?}",
            outcome.id,
            outcome.verdict,
            outcome.failures(),
            outcome.skip_reason
        );
    }
    // c-h2-0010 proves nothing unless its client GOAWAY, authored after the request head, was
    // written before the response ended the exchange. c-h2-0008 and c-h2-0009 write their control
    // frame before HEADERS, so the exact wire-image test in h2_client_control_tests covers them.
    for outcome in report.outcomes.iter().filter(|outcome| outcome.id == "c-h2-0010") {
        assert!(
            outcome
                .warnings()
                .iter()
                .all(|warning| !warning.message.contains("before all authored")),
            "{}: {:?}",
            outcome.id,
            outcome.warnings()
        );
    }
    for outcome in &report.outcomes {
        assert_eq!(
            outcome.verdict,
            Verdict::Passed,
            "{}: failures={:?}, skip={:?}",
            outcome.id,
            outcome.failures(),
            outcome.skip_reason
        );
    }
}

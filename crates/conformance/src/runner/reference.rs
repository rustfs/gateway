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

//! The reference evaluation `conformance/baseline.json` records, shared by the refresh command and
//! the whole-corpus gate so the two cannot disagree (rustfs/gateway#985).
//! Responsible for: running the corpus in process, then re-running on the production Hyper driver
//! exactly the cases the in-process target cannot judge — refused for want of a socket, or failed
//! only on `connection_after`, which that target reports as `open` by construction.
//! NOT responsible for: judging a case, rendering the baseline, or external endpoints.
//! Upstream: `crate::cli` (`conformance baseline`) and `tests/corpus.rs`. Downstream: `super::run`.

use super::{Corpus, Phase, Report, RunOptions, Severity, Verdict};
use crate::report::CaseOutcome;

/// Whether the in-process outcome is a limit of that target rather than a fact about the service.
pub(crate) fn needs_a_socket(outcome: &CaseOutcome) -> bool {
    match outcome.verdict {
        // An environment refusal while executing is a transport limit; a gate, a filter or a
        // convention skip is not.
        Verdict::Skipped => outcome.phase == Phase::Execute,
        Verdict::Failed => {
            let mut failures = outcome
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity == Severity::Deny)
                .peekable();
            failures.peek().is_some() && failures.all(|diagnostic| diagnostic.rule == "expect/connection_after")
        }
        _ => false,
    }
}

/// The reference evaluation: in process, with the cases that need a socket executed on the
/// production Hyper driver. Without `production-transports` it is the in-process run alone.
#[must_use]
pub fn reference_report(corpus: &Corpus, options: &RunOptions) -> Report {
    let root = corpus.root().to_path_buf();
    let mut report = super::run(corpus, &mut crate::inprocess::InProcess::new(root.clone()), options);
    #[cfg(feature = "production-transports")]
    {
        let rerun: Vec<String> = report
            .outcomes
            .iter()
            .filter(|outcome| needs_a_socket(outcome))
            .map(|outcome| outcome.id.clone())
            .collect();
        let mut hyper = crate::conn::Conn::production(root, crate::production::ProductionDriver::Hyper);
        for id in rerun {
            let one = RunOptions {
                filter: Some(id.clone()),
                shard: None,
                ..options.clone()
            };
            let executed = super::run(corpus, &mut hyper, &one)
                .outcomes
                .into_iter()
                .find(|outcome| outcome.id == id);
            if let (Some(executed), Some(slot)) = (executed, report.outcomes.iter_mut().find(|outcome| outcome.id == id)) {
                *slot = executed;
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Diagnostic;

    fn outcome(verdict: Verdict, phase: Phase, diagnostics: Vec<Diagnostic>) -> CaseOutcome {
        CaseOutcome {
            id: "c-test-0001".to_owned(),
            domain: "test".to_owned(),
            relative: "cases/test/c-test-0001.toml".to_owned(),
            title: None,
            verdict,
            phase,
            skip_reason: None,
            diagnostics,
            quirks: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn deny(rule: &str) -> Diagnostic {
        Diagnostic::deny(rule, "/expect", "x")
    }

    #[test]
    fn only_transport_limits_are_re_run_on_a_socket() {
        assert!(needs_a_socket(&outcome(Verdict::Skipped, Phase::Execute, Vec::new())));
        assert!(needs_a_socket(&outcome(
            Verdict::Failed,
            Phase::Execute,
            vec![
                deny("expect/connection_after"),
                Diagnostic::warn("harness/by-construction", "/expect", "x")
            ]
        )));
        for (verdict, phase, diagnostics) in [
            (Verdict::Passed, Phase::Execute, Vec::new()),
            (Verdict::Skipped, Phase::Convention, Vec::new()),
            (Verdict::Failed, Phase::Execute, vec![deny("expect/status")]),
            (
                Verdict::Failed,
                Phase::Execute,
                vec![deny("expect/connection_after"), deny("expect/status")],
            ),
            (Verdict::Failed, Phase::Execute, Vec::new()),
        ] {
            assert!(
                !needs_a_socket(&outcome(verdict, phase, diagnostics.clone())),
                "{verdict:?} {diagnostics:?}"
            );
        }
    }
}

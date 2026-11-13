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

//! The conclusion of a case the target did not let run to its assertions.
//!
//! Responsible for: telling apart what the harness cannot do — a skip that states its reason —
//! from what the target did: refused a fixture step, or stopped answering. Those two are failed
//! cases, because a skip claims the harness lacked a capability and here it did not
//! (rustfs/gateway#1607). NOT responsible for: aborting the run once the endpoint is lost
//! (`super::run`), or deciding the exit code (`crate::cli`). Upstream: `super::run_case`,
//! `super::reference`; downstream: `crate::report`.

use crate::diagnostic::Diagnostic;
use crate::report::{CaseOutcome, Verdict};
use crate::sut::SutError;

/// The rule a case fails under when the external endpoint stopped answering during it; the runner
/// aborts the run on the first outcome that carries it.
pub(super) const ENDPOINT_LOST: &str = "runner/endpoint-lost";

/// Turns a target-level failure into the case's conclusion.
///
/// The long-form explanation — what the facade would have to expose — is a property of the run
/// rather than of each case, so it goes into the report's notes once instead of onto every line.
pub(super) fn not_run(mut outcome: CaseOutcome, error: &SutError, notes: &mut Vec<String>) -> CaseOutcome {
    let failure = match error {
        SutError::Unreachable(reason) => Some(Diagnostic::deny(
            ENDPOINT_LOST,
            "",
            format!("the external endpoint stopped answering: {reason}"),
        )),
        SutError::Refused(reason) => Some(Diagnostic::deny("runner/fixture-refused", "/setup", reason.clone())),
        _ => None,
    };
    if let Some(failure) = failure {
        outcome.diagnostics.push(failure);
        outcome.verdict = Verdict::Failed;
        return outcome;
    }
    outcome.verdict = Verdict::Skipped;
    outcome.transport_limited = matches!(error, SutError::TransportLimit(_));
    outcome.skip_reason = Some(match error {
        SutError::NotWired { reason, missing } => {
            for item in missing {
                let note = format!("the facade must expose: {item}");
                if !notes.contains(&note) {
                    notes.push(note);
                }
            }
            reason.clone()
        }
        SutError::Environment(reason)
        | SutError::TransportLimit(reason)
        | SutError::Unreachable(reason)
        | SutError::Refused(reason) => format!("environment: {reason}"),
    });
    outcome
}

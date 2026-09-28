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

//! The mutation matrix's words: one row per rule, the closing summary, and the reachability
//! refinement of a `SURVIVED` row.
//!
//! Responsible for: rendering an [`Outcome`], and turning a `SURVIVED` plus a coverage
//! [`Reach`] into the row's final outcome and note.
//! NOT responsible for: measuring anything; `super::classify` and `super::reach` do that.
//! Upstream: `super::run`. Downstream: the operator reading the matrix.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::Outcome;
use super::reach::Reach;

/// Applies a coverage answer to a judged outcome.
///
/// Only a `SURVIVED` row changes, and only `Unreached` changes its label: a reached or unknown
/// answer keeps `SURVIVED` and becomes a note, because neither proves the corpus is not the gap.
pub(super) fn refine(outcome: Outcome, reach: Option<Reach>) -> (Outcome, Option<String>) {
    match (outcome, reach) {
        (Outcome::Survived, Some(Reach::Unreached(evidence))) => (Outcome::SurvivedUnreached(evidence), None),
        (Outcome::Survived, Some(Reach::Reached)) => (
            Outcome::Survived,
            Some("reachability: the changed code executed during the corpus run, so this is a corpus gap".to_owned()),
        ),
        (Outcome::Survived, Some(Reach::Unknown(why))) => {
            (Outcome::Survived, Some(format!("reachability: not established — {why}")))
        }
        (outcome, _) => (outcome, None),
    }
}

pub(super) fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Killed { by, declared: true } => format!("KILLED by {}", by.join(", ")),
        Outcome::Killed { by, declared: false } => {
            format!("KILLED by {} — none of them is a case this rule's ledger row names", by.join(", "))
        }
        Outcome::KilledByCompile(unit) => {
            format!("KILLED_BY_COMPILE — `{unit}` does not build under the mutation; no case was consulted")
        }
        Outcome::Survived => "SURVIVED — the mutation reached a file the gateway compiles, a case that could have \
             gone red did not, and that is a corpus gap OR a lowered value nothing reads, which the freshness \
             control cannot tell apart (rustfs/gateway#242); `--reachability` separates the two where coverage can"
            .to_owned(),
        Outcome::SurvivedUnreached(evidence) => format!(
            "SURVIVED_UNREACHED — a coverage rerun of the mutated tree executed none of the changed \
             lines ({evidence}); the mutated code never ran, so this is a dead source, not a corpus gap"
        ),
        Outcome::Unwitnessed(why) => format!(
            "UNWITNESSED — {why}; this is a defect in the rule's ledger row, not a gap a new assertion in \
             those cases would close"
        ),
        Outcome::Inert(why) | Outcome::Unplannable(why) | Outcome::Unsupported(why) | Outcome::NotMeasured(why) => {
            format!("{} — {why}", outcome.label())
        }
    }
}

pub(super) fn summary(results: &[(String, String, Outcome)]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, _, outcome) in results {
        *counts.entry(outcome.label()).or_default() += 1;
    }
    let mut out = String::from("\nmatrix: ");
    let rendered: Vec<String> = counts.iter().map(|(label, count)| format!("{count} {label}")).collect();
    out.push_str(&rendered.join(", "));
    let _ = writeln!(out, " (of {} rule(s))", results.len());
    if results.iter().all(|(_, _, outcome)| outcome.is_pass()) {
        out.push_str("every rule was killed by a case its ledger row names\n");
    } else {
        out.push_str("not every rule was killed by a case it names; the rows above that are not KILLED are the work left\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreached_survivor_is_a_dead_source() {
        let (outcome, note) = refine(Outcome::Survived, Some(Reach::Unreached("a.rs:3-3".to_owned())));
        assert_eq!(outcome, Outcome::SurvivedUnreached("a.rs:3-3".to_owned()));
        assert_eq!(outcome.label(), "SURVIVED_UNREACHED");
        assert!(!outcome.is_pass(), "a dead source is still work left");
        assert!(note.is_none());
        assert!(describe(&outcome).contains("a.rs:3-3"));
    }

    #[test]
    fn n_a_reached_survivor_stays_a_corpus_gap() {
        let (outcome, note) = refine(Outcome::Survived, Some(Reach::Reached));
        assert_eq!(outcome, Outcome::Survived);
        assert!(note.is_some_and(|note| note.contains("corpus gap")));
    }

    #[test]
    fn n_an_unknown_reach_keeps_survived_and_says_why() {
        let (outcome, note) = refine(Outcome::Survived, Some(Reach::Unknown("no profile".to_owned())));
        assert_eq!(outcome, Outcome::Survived);
        assert!(note.is_some_and(|note| note.contains("no profile")));
    }

    #[test]
    fn n_without_a_coverage_run_survived_is_unchanged() {
        assert_eq!(refine(Outcome::Survived, None), (Outcome::Survived, None));
    }

    #[test]
    fn n_only_a_survivor_is_refined() {
        let killed = Outcome::Killed {
            by: vec!["c-x-0001".to_owned()],
            declared: true,
        };
        let (outcome, note) = refine(killed.clone(), Some(Reach::Unreached("a.rs:1-1".to_owned())));
        assert_eq!(outcome, killed, "a kill is never relabelled by coverage");
        assert!(note.is_none());
    }
}

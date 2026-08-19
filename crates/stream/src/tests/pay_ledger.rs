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

//! The `c-pay-*` ledger: every payload case the task names, and how each one is proved.
//!
//! Responsible for: holding all twenty-eight rows in one table, running the ones proved here,
//! and refusing the three ways a ledger rots — a row that names no proof, a proof that did not
//! actually observe anything, and a row deferred to nobody.
//! NOT responsible for: the assertions themselves. They live in `pay_cases` and `pay_scale`,
//! one function per row, so a row and its proof can be read side by side.
//! Upstream: the two sibling case modules and the crate's public surface. Downstream: nothing.
//!
//! # Why this is a table in Rust and not a directory of cases
//!
//! The repository's case corpus is an HTTP request/response harness: its frozen schema requires
//! every case to carry a request and an expectation, and the schema is a protected file. Half
//! of these rows have no wire exchange to express — `caps()` on an in-memory payload, the cost
//! of an adapter, the refusal a transport gets back — so expressing them as corpus cases would
//! mean widening a frozen schema to hold assertions that are not about the wire at all.
//!
//! The other half of that trade is the reason this file is a test target and not a document:
//! a family that lives only in the corpus can be loaded, listed and counted while nothing ever
//! executes it, and a case that never ran prints the same colour as a case that passed. Every
//! row proved here runs under `cargo test`.
//!
//! # What each of the three bindings is worth
//!
//! * `Bound` — the assertion runs in this target. The row declares how many separate
//!   observations its function makes, and the runner compares that against what the function
//!   reports, so a body that returns early stops matching its row.
//! * `Guard` — the assertion is a named negative case in the guard self-test, where a mutation
//!   is planted and the guard must go red. The ledger checks that the named case still exists,
//!   so renaming it away goes red here rather than silently unbinding the row.
//! * `Deferred` — not proved yet. The row must name the issue that owns it; a deferral with no
//!   owner is the shape a permanent gap takes.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::{pay_cases, pay_scale};

/// Whether a row asserts required behaviour or a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Polarity {
    /// The row asserts what a well-formed payload must do.
    Positive,
    /// The row asserts a refusal, a named reason, or a safe termination.
    Negative,
}

/// A case body. It returns the number of separate observations it made.
///
/// The count is what stops a row from being satisfied by an empty function. An assertion that
/// was deleted, or a body that returned before reaching its second half, reports fewer
/// observations than its row declares and the runner rejects it — which is the difference
/// between "this row is proved" and "this row names something that compiles".
pub(crate) type Case = fn() -> u32;

/// A counter that makes each assertion in a case body countable as well as checkable.
pub(crate) struct Checks {
    count: u32,
}

impl Checks {
    /// A fresh counter.
    pub(crate) fn new() -> Self {
        Self { count: 0 }
    }

    /// Asserts one observation, naming the case and what was expected.
    pub(crate) fn that(&mut self, id: &str, what: &str, holds: bool) {
        assert!(holds, "{id}: {what}");
        self.count += 1;
    }

    /// How many observations were made.
    pub(crate) fn count(&self) -> u32 {
        self.count
    }
}

/// How a row is proved.
pub(crate) enum Binding {
    /// Proved by a function in this crate's tests.
    Bound {
        /// The function that makes the observations.
        run: Case,
        /// How many observations it must make.
        checks: u32,
    },
    /// Proved by a named negative case in `scripts/test_guard_scripts.sh`.
    Guard(&'static str),
    /// Not proved yet, with the issue that owns the gap.
    Deferred {
        /// The issue that owns the remaining work.
        owner: &'static str,
        /// Why it cannot be proved at this layer today.
        why: &'static str,
    },
}

/// One row of the ledger.
pub(crate) struct Row {
    /// The case id.
    pub(crate) id: &'static str,
    /// Whether the row asserts behaviour or refusal.
    pub(crate) polarity: Polarity,
    /// What the row asserts, in one line.
    pub(crate) statement: &'static str,
    /// How the row is proved.
    pub(crate) binding: Binding,
}

use Polarity::{Negative, Positive};

/// Every `c-pay-*` row, in id order.
pub(crate) const LEDGER: &[Row] = &[
    Row {
        id: "c-pay-0001",
        polarity: Positive,
        statement: "an in-memory payload advertises in-memory, both models, and a known length",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0001,
            checks: 6,
        },
    },
    Row {
        id: "c-pay-0002",
        polarity: Positive,
        statement: "a file payload asked by a transport with a kernel-side path yields its region",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0002,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0003",
        polarity: Positive,
        statement: "a three-segment payload is borrowed as three segments, none of them copied",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0003,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0004",
        polarity: Positive,
        statement: "a pull payload consumed through the pull model costs nothing and moves no counter",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0004,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0005",
        polarity: Positive,
        statement: "a push payload consumed through the push model costs nothing and moves no counter",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0005,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0006",
        polarity: Positive,
        statement: "an in-memory payload read through the pull model costs nothing and keeps its bytes",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0006,
            checks: 4,
        },
    },
    Row {
        id: "c-pay-0007",
        polarity: Positive,
        statement: "an empty payload declares a length of exactly zero, not an unknown length",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0007,
            checks: 4,
        },
    },
    Row {
        id: "c-pay-0008",
        polarity: Positive,
        statement: "a gibibyte through the native model performs no adapting copy, and the instrument that says so can see one",
        binding: Binding::Bound {
            run: pay_scale::c_pay_0008,
            checks: 15,
        },
    },
    Row {
        id: "c-pay-0009",
        polarity: Positive,
        statement: "a payload of unknown length is framed without a declared length",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1690",
            why: "framing is the wire layer's; this crate holds no header name and no transfer coding",
        },
    },
    Row {
        id: "c-pay-0020",
        polarity: Negative,
        statement: "an in-memory payload refuses the kernel-side path as not file backed and comes back whole",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0020,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0021",
        polarity: Negative,
        statement: "a transport with no kernel-side path is told so by name, and the refusal is counted with its bytes",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0021,
            checks: 6,
        },
    },
    Row {
        id: "c-pay-0022",
        polarity: Negative,
        statement: "an outstanding verification refuses first, ahead of every cheaper reason",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0022,
            checks: 7,
        },
    },
    Row {
        id: "c-pay-0023",
        polarity: Negative,
        statement: "encryption in the path refuses by name and is counted apart from the other reasons",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0023,
            checks: 6,
        },
    },
    Row {
        id: "c-pay-0024",
        polarity: Negative,
        statement: "a push payload read through the pull model costs a copy, and the copy is counted in bytes",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0024,
            checks: 6,
        },
    },
    Row {
        id: "c-pay-0025",
        polarity: Negative,
        statement: "a pull payload read through the push model costs an owned buffer, counted apart from a copy",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0025,
            checks: 6,
        },
    },
    Row {
        id: "c-pay-0026",
        polarity: Negative,
        statement: "a runtime escape hatch declared on a payload type fails the build",
        binding: Binding::Guard("stream payload exposing an as_any escape hatch"),
    },
    Row {
        id: "c-pay-0027",
        polarity: Negative,
        statement: "an unregistered runtime type test outside the data plane fails the build",
        binding: Binding::Guard("a downcast outside the payload data plane that nobody registered"),
    },
    Row {
        id: "c-pay-0028",
        polarity: Negative,
        statement: "a gibibyte that loses the kernel-side path is attributed and sized, never silently degraded",
        binding: Binding::Bound {
            run: pay_scale::c_pay_0028,
            checks: 9,
        },
    },
    Row {
        id: "c-pay-0029",
        polarity: Negative,
        statement: "more segments than one vectored write accepts are written in batches, not flattened uncounted",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1690",
            why: "a write strategy belongs to a transport; this crate has none and must not grow one",
        },
    },
    Row {
        id: "c-pay-0030",
        polarity: Negative,
        statement: "a producer never runs ahead of its consumer, and the measurement that says so catches one that does",
        binding: Binding::Bound {
            run: pay_scale::c_pay_0030,
            checks: 8,
        },
    },
    Row {
        id: "c-pay-0031",
        polarity: Negative,
        statement: "a body that stops short of its declared length fails as incomplete instead of ending",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0031,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0032",
        polarity: Negative,
        statement: "a body that overruns its declared length fails at the overrunning chunk",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0032,
            checks: 6,
        },
    },
    Row {
        id: "c-pay-0033",
        polarity: Negative,
        statement: "a file range whose end does not fit in a u64 is refused at construction",
        binding: Binding::Bound {
            run: pay_cases::c_pay_0033,
            checks: 5,
        },
    },
    Row {
        id: "c-pay-0060",
        polarity: Negative,
        statement: "a client reset mid-transfer cancels the producer and releases what it held",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1699",
            why: "needs a real socket and a resident-memory instrument with a positive control; a counter cannot stand in",
        },
    },
    Row {
        id: "c-pay-0061",
        polarity: Negative,
        statement: "a one-byte-a-second reader does not let the in-flight window grow, and does not disturb other connections",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1699",
            why: "needs a real socket, a resident-memory instrument and a latency distribution across connections",
        },
    },
    Row {
        id: "c-pay-0062",
        polarity: Negative,
        statement: "a consumer that stops consuming stops the read side, and trips the between-reads deadline",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1699",
            why: "the deadline it asserts is the server's, and the evidence has to come from the socket",
        },
    },
    Row {
        id: "c-pay-0063",
        polarity: Negative,
        statement: "a zero window mid-response trips the between-writes deadline and propagates cancellation",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1699",
            why: "requires driving a real receive window; nothing at this layer can observe one",
        },
    },
    Row {
        id: "c-pay-0064",
        polarity: Negative,
        statement: "many slow readers at once stay under a per-connection bound and a total bound",
        binding: Binding::Deferred {
            owner: "rustfs/backlog#1699",
            why: "a total memory bound across hundreds of connections is a process-level measurement",
        },
    },
];

/// How many rows must be proved here or by a guard.
///
/// A floor rather than a total, so that binding a new row cannot be paid for by quietly
/// deferring an existing one: the two would cancel out in a count. Raise it when a row moves
/// from `Deferred` to a real binding.
const PROVED_FLOOR: usize = 21;

/// The id groups the task enumerates: the positive rows, the negative rows, and the
/// concurrency rows.
///
/// Expressed as ranges rather than as a second copy of the id list, so that this is an
/// independent statement of what the family contains and not the same list typed twice.
const ID_GROUPS: &[(u32, u32, Polarity)] = &[(1, 9, Positive), (20, 33, Negative), (60, 64, Negative)];

fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

/// Positive — every row proved in this target runs, and reports exactly the observations it declared.
#[test]
fn every_bound_row_runs_and_observes_what_it_declared() {
    let mut ran = 0usize;
    for row in LEDGER {
        if let Binding::Bound { run, checks } = &row.binding {
            let observed = run();
            assert_eq!(
                observed, *checks,
                "{}: the ledger declares {checks} observation(s) and the case made {observed}; \
                 a body that stopped early proves less than its row claims",
                row.id
            );
            ran += 1;
        }
    }
    assert!(ran > 0, "no row in the ledger is proved by a case body");
}

/// Positive — the ledger holds exactly the ids the task enumerates, once each and in order.
#[test]
fn the_ledger_holds_every_id_the_family_names_and_no_other() {
    let expected: BTreeSet<String> = ID_GROUPS
        .iter()
        .flat_map(|(first, last, _)| (*first..=*last).map(|n| format!("c-pay-{n:04}")))
        .collect();
    let actual: BTreeSet<String> = LEDGER.iter().map(|row| row.id.to_owned()).collect();

    let missing: Vec<&String> = expected.difference(&actual).collect();
    let extra: Vec<&String> = actual.difference(&expected).collect();
    assert!(missing.is_empty(), "the ledger is missing {missing:?}");
    assert!(extra.is_empty(), "the ledger holds {extra:?}, which the family does not name");
    assert_eq!(LEDGER.len(), expected.len(), "a row is duplicated");

    let ids: Vec<&str> = LEDGER.iter().map(|row| row.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "the ledger is not in id order, so a duplicate is easy to miss");
}

/// Negative — the polarity a row declares matches the group it belongs to, and refusals stay in
/// the majority.
///
/// Both halves matter. The count alone can be satisfied by mislabelling a positive row as
/// negative, which is the cheapest way to pass a negative-majority rule without writing a
/// negative case.
#[test]
fn every_row_declares_the_polarity_of_its_group_and_refusals_are_the_majority() {
    for row in LEDGER {
        let number: u32 = row
            .id
            .trim_start_matches("c-pay-")
            .parse()
            .expect("a row id ends in four digits");
        let group = ID_GROUPS
            .iter()
            .find(|(first, last, _)| (*first..=*last).contains(&number))
            .expect("every row belongs to a group");
        assert_eq!(row.polarity, group.2, "{} declares the wrong polarity for its group", row.id);
    }

    let negative = LEDGER.iter().filter(|row| row.polarity == Negative).count();
    let positive = LEDGER.iter().filter(|row| row.polarity == Positive).count();
    assert!(negative >= positive, "{negative} negative versus {positive} positive");
}

/// Negative — a row bound to a guard case names one that still exists.
///
/// The guard self-test is the only place these two rows are executed, so a renamed case would
/// unbind them silently. The file must exist: a missing input here is a failure, never a skip,
/// because "the guard suite moved" and "the guard suite proves this row" look identical from a
/// green line.
#[test]
fn every_guard_row_names_a_case_that_still_exists() {
    let path = repo_root().join("scripts/test_guard_scripts.sh");
    let suite = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the guard self-test must be readable at {}: {error}", path.display()));
    let mut checked = 0usize;
    for row in LEDGER {
        if let Binding::Guard(case) = &row.binding {
            // Quoted, and not on a commented-out line. A plain substring search would be
            // satisfied by the case name surviving in a comment after the case itself was
            // deleted, which is the exact shape of a binding that binds nothing.
            let quoted = format!("'{case}'");
            let live = suite
                .lines()
                .any(|line| line.contains(&quoted) && !line.trim_start().starts_with('#'));
            assert!(
                live,
                "{} names the guard case '{case}', which no longer appears as a live case in \
                 scripts/test_guard_scripts.sh",
                row.id
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no row is bound to a guard case; the check above proved nothing");
}

/// Negative — a deferred row names the issue that owns it and says why it cannot be proved here.
#[test]
fn every_deferred_row_names_an_owner_and_a_reason() {
    for row in LEDGER {
        if let Binding::Deferred { owner, why } = &row.binding {
            assert!(
                owner.starts_with("rustfs/") && owner.contains('#'),
                "{} defers to '{owner}', which is not an issue reference; a deferral with no owner never comes back",
                row.id
            );
            assert!(
                why.len() >= 40,
                "{} defers with no usable reason; the next reader has to be able to tell a gap from a decision",
                row.id
            );
        }
    }
}

/// Negative — the number of proved rows does not fall.
#[test]
fn the_family_keeps_at_least_the_rows_it_has_already_proved() {
    let proved = LEDGER
        .iter()
        .filter(|row| !matches!(row.binding, Binding::Deferred { .. }))
        .count();
    assert!(
        proved >= PROVED_FLOOR,
        "{proved} of {} rows are proved, the floor is {PROVED_FLOOR}; a row was unbound rather than fixed",
        LEDGER.len()
    );
}

/// Negative — a row states what it asserts, in a sentence somebody can check it against.
#[test]
fn every_row_states_what_it_asserts() {
    for row in LEDGER {
        assert!(
            row.statement.len() >= 40,
            "{} carries no usable statement; a row nobody can read is a row nobody can delete",
            row.id
        );
    }
}

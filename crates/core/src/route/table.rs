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

//! The ordered first-match route table, and everything it refuses to be built from.
//!
//! Responsible for: [`RouteTable::build`] and the four build-time refusals (same-precedence
//! conflict, undeclared cross-precedence shadowing, a stale declaration, a selector that is empty
//! or self-contradictory), and [`RouteTable::resolve`] — the readable first-match matcher.
//! NOT responsible for: deciding overlap (`lattice`), the compiled fast form (`compiled`), which
//! parameters an operation requires (`crate::registry`), or rendering an error to the wire.
//! Upstream: `lattice`, `selector`, `shadowing`, `shape`. Downstream: `compiled`, `explain`,
//! `crate::dispatch`.
//!
//! # Ordered, not disjoint
//!
//! The first draft of this table required global unambiguity: no two selectors may accept the same
//! request, or the service refuses to start. That model does not describe S3.
//! `GET /bucket?acl&tagging` names two subresources, and AWS answers it — it picks one by a fixed
//! internal order and ignores the other. Expressing that in a disjoint table means writing
//! `Present("acl") ∧ Absent("cors") ∧ Absent("encryption") ∧ …` on every subresource operation:
//! quadratically many `Absent` predicates, all of which have to be edited whenever AWS adds a
//! subresource. On top of that, the SDKs append `?x-id=<OperationName>` to almost every request,
//! so any rule of the form "an unrecognised query key is an ambiguity" rejects ordinary traffic.
//!
//! So the table is ordered. `precedence` is a `u16` assigned by codegen from the route overlay;
//! lower is tried first; the first entry whose selector accepts the request wins. What remains
//! forbidden is an overlap *within* one precedence, because there the winner would be decided by
//! sort order — an accident nobody reviewed.
//!
//! # Precedence bands
//!
//! | Band | Contents |
//! |---|---|
//! | `0..=99` | Literal paths and special host classes |
//! | `100..=199` | ARN-shaped targets |
//! | `200..=699` | Subresource operations, narrower first |
//! | `700..=799` | POST Object |
//! | `800..=899` | Plain object and bucket operations |
//! | `900..=999` | The fallback |
//!
//! Only the last band is enforced here, and only in one direction: an empty selector matches every
//! request, so it is refused outside [`FALLBACK_BAND`]. The rest is documentation for the overlay
//! that assigns the numbers.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::RangeInclusive;

use super::lattice::{Constraints, Contradiction, OverlapError, overlap_witness};
use super::selector::{RouteEntry, RouteRequestParts, RouteSelector};
use super::shadowing::{ShadowingDecls, ShadowingPolicy};
use super::shape::RequestShape;

/// The precedence band an all-matching selector is allowed to live in.
pub const FALLBACK_BAND: RangeInclusive<u16> = 900..=999;

/// One side of a conflict report: who, at what precedence, with which predicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorReport {
    /// The operation name.
    pub op_name: &'static str,
    /// Its precedence.
    pub precedence: u16,
    /// The full conjunction, rendered.
    pub selector: String,
}

impl SelectorReport {
    fn of(entry: &RouteEntry) -> Self {
        Self {
            op_name: entry.op_name,
            precedence: entry.precedence,
            selector: entry.selector.to_string(),
        }
    }
}

impl fmt::Display for SelectorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (precedence {}): {}", self.op_name, self.precedence, self.selector)
    }
}

/// Why a route table refused to be built. Every variant is a startup failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteBuildError {
    /// Two entries at the same precedence accept the same request.
    ///
    /// Carries both selectors in full and a request that reaches both, because "these two conflict"
    /// is not something a reviewer can check and `GET /<bucket>?acl&tagging` is.
    Conflict {
        /// The precedence they share.
        precedence: u16,
        /// The earlier entry.
        a: SelectorReport,
        /// The later entry.
        b: SelectorReport,
        /// A request both accept.
        witness: Box<RequestShape>,
    },
    /// Two entries at different precedences overlap, and no declaration says which wins or why.
    UndeclaredShadowing {
        /// The entry with the lower precedence.
        winner: SelectorReport,
        /// The entry it hides.
        shadowed: SelectorReport,
        /// A request that reaches the winner and would otherwise have reached the shadowed entry.
        witness: Box<RequestShape>,
        /// Whether the shadowed entry is unreachable altogether, rather than partly hidden.
        total: bool,
    },
    /// A declaration that does not describe anything the table actually does.
    ///
    /// Declarations rot the moment a selector changes. An unchecked one is worse than none: it
    /// reads as a reviewed decision about behaviour that no longer exists.
    StaleShadowing {
        /// The declared winner.
        winner: &'static str,
        /// The declared shadowed operation.
        shadowed: &'static str,
        /// What is wrong with it.
        why: &'static str,
    },
    /// A declaration with no evidence. An ordering nobody sourced is a guess with a comment.
    UnsourcedShadowing {
        /// The declared winner.
        winner: &'static str,
        /// The declared shadowed operation.
        shadowed: &'static str,
    },
    /// An empty selector outside the fallback band: it would swallow every request before it.
    EmptySelectorOutsideFallback {
        /// The operation.
        op_name: &'static str,
        /// Where it was placed.
        precedence: u16,
    },
    /// A selector no request can satisfy — dead weight that reads as coverage.
    UnsatisfiableSelector {
        /// The operation.
        op_name: &'static str,
        /// The two constraints that cannot hold at once.
        contradiction: Contradiction,
    },
    /// A predicate this crate cannot evaluate: a header name that is not a valid lowercase name,
    /// a path literal that does not start with `/`.
    InvalidPredicate {
        /// The operation.
        op_name: &'static str,
        /// What is wrong.
        detail: String,
    },
    /// Two entries claim the same operation name.
    DuplicateOperation {
        /// The name claimed twice.
        op_name: &'static str,
    },
    /// The overlap decision contradicted the matcher. A bug in this crate, not in the table.
    Inconsistent(OverlapError),
}

impl fmt::Display for RouteBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict {
                precedence,
                a,
                b,
                witness,
            } => write!(
                f,
                "route conflict at precedence {precedence}:\n  {a}\n  {b}\n  both reachable by: {witness}\n\
                 hint: give them different precedence in the route overlay, and record the reason",
            ),
            Self::UndeclaredShadowing {
                winner,
                shadowed,
                witness,
                total,
            } => {
                let scope = if *total {
                    "and is unreachable altogether"
                } else {
                    "for the requests they share"
                };
                write!(
                    f,
                    "undeclared shadowing:\n  winner:   {winner}\n  shadowed: {shadowed} {scope}\n  \
                     witness:  {witness}\nhint: add a shadowing declaration with a reason and evidence",
                )
            }
            Self::StaleShadowing { winner, shadowed, why } => {
                write!(f, "stale shadowing declaration {winner} over {shadowed}: {why}")
            }
            Self::UnsourcedShadowing { winner, shadowed } => {
                write!(f, "shadowing declaration {winner} over {shadowed} carries no evidence")
            }
            Self::EmptySelectorOutsideFallback { op_name, precedence } => write!(
                f,
                "{op_name} has an empty selector at precedence {precedence}: an empty conjunction \
                 matches every request and is only allowed in the fallback band {}..={}",
                FALLBACK_BAND.start(),
                FALLBACK_BAND.end(),
            ),
            Self::UnsatisfiableSelector { op_name, contradiction } => {
                write!(f, "{op_name} can never match: {contradiction}")
            }
            Self::InvalidPredicate { op_name, detail } => write!(f, "{op_name} has an unusable predicate: {detail}"),
            Self::DuplicateOperation { op_name } => write!(f, "{op_name} appears twice in the route table"),
            Self::Inconsistent(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RouteBuildError {}

impl From<OverlapError> for RouteBuildError {
    fn from(error: OverlapError) -> Self {
        Self::Inconsistent(error)
    }
}

/// The ordered first-match route table.
///
/// Built once, at startup, from data. Every check that can be made about the table as a whole is
/// made here, so that request time is a scan and nothing else.
#[derive(Clone, Debug)]
pub struct RouteTable {
    entries: Box<[RouteEntry]>,
    constraints: Box<[Constraints]>,
    shadowing: ShadowingDecls,
}

impl RouteTable {
    /// Builds the table, or refuses.
    ///
    /// Neither this nor [`RouteTable::resolve`] is `async`, and neither accepts a store, a
    /// repository, or any other handle. Routing runs before the signature is verified: a router
    /// that could await or read storage would be an unauthenticated amplifier, and the only
    /// durable way to say so is to make it unspellable. `crates/core/tests/purity_guard.rs`
    /// asserts it over the source.
    ///
    /// # Errors
    ///
    /// [`RouteBuildError`], and every variant of it means the service does not start.
    pub fn build(entries: Vec<RouteEntry>, shadowing: &ShadowingDecls) -> Result<Self, RouteBuildError> {
        let mut entries = entries;
        // Stable within a precedence by name, so a table built from a differently ordered input
        // renders the same golden file and reports the same conflict pair first.
        entries.sort_by(|a, b| a.precedence.cmp(&b.precedence).then_with(|| a.op_name.cmp(b.op_name)));

        let mut seen = BTreeSet::new();
        for entry in &entries {
            if !seen.insert(entry.op_name) {
                return Err(RouteBuildError::DuplicateOperation { op_name: entry.op_name });
            }
            validate_predicates(entry)?;
            if entry.selector.predicates().is_empty() && !FALLBACK_BAND.contains(&entry.precedence) {
                return Err(RouteBuildError::EmptySelectorOutsideFallback {
                    op_name: entry.op_name,
                    precedence: entry.precedence,
                });
            }
        }

        let mut constraints = Vec::with_capacity(entries.len());
        for entry in &entries {
            let normalised =
                Constraints::of(&entry.selector).map_err(|contradiction| RouteBuildError::UnsatisfiableSelector {
                    op_name: entry.op_name,
                    contradiction,
                })?;
            // An empty conjunction normalises to the top element. Cross-checking the two spellings
            // keeps `is_top` honest if a predicate is ever added that normalises to nothing.
            if normalised.is_top() && !FALLBACK_BAND.contains(&entry.precedence) {
                return Err(RouteBuildError::EmptySelectorOutsideFallback {
                    op_name: entry.op_name,
                    precedence: entry.precedence,
                });
            }
            constraints.push(normalised);
        }

        let table = Self {
            entries: entries.into_boxed_slice(),
            constraints: constraints.into_boxed_slice(),
            shadowing: *shadowing,
        };
        // Declarations first: a declaration that has rotted is a more specific diagnostic than the
        // undeclared overlap it fails to cover, and reporting the vaguer one first sends the
        // reader to add a declaration that is already there.
        table.check_declarations()?;
        table.check_overlaps()?;
        Ok(table)
    }

    /// Every pair, once. Same precedence is a conflict; different precedence needs a declaration.
    fn check_overlaps(&self) -> Result<(), RouteBuildError> {
        for (index, entry) in self.entries.iter().enumerate() {
            for (other_index, other) in self.entries.iter().enumerate().skip(index.saturating_add(1)) {
                let (Some(mine), Some(theirs)) = (self.constraints.get(index), self.constraints.get(other_index)) else {
                    continue;
                };
                let Some(witness) = overlap_witness(&entry.selector, mine, &other.selector, theirs)? else {
                    continue;
                };
                if entry.precedence == other.precedence {
                    return Err(RouteBuildError::Conflict {
                        precedence: entry.precedence,
                        a: SelectorReport::of(entry),
                        b: SelectorReport::of(other),
                        witness: Box::new(witness),
                    });
                }
                // Sorted, so `entry` is the winner.
                let total = theirs.refines(mine);
                let needs_declaration = match self.shadowing.policy() {
                    ShadowingPolicy::EveryOverlap => true,
                    ShadowingPolicy::TotalOnly => total,
                };
                if needs_declaration && self.shadowing.find(entry.op_name, other.op_name).is_none() {
                    return Err(RouteBuildError::UndeclaredShadowing {
                        winner: SelectorReport::of(entry),
                        shadowed: SelectorReport::of(other),
                        witness: Box::new(witness),
                        total,
                    });
                }
            }
        }
        Ok(())
    }

    /// Every declaration must describe an overlap that exists, in the direction it claims.
    fn check_declarations(&self) -> Result<(), RouteBuildError> {
        for decl in self.shadowing.all() {
            if decl.evidence.is_empty() {
                return Err(RouteBuildError::UnsourcedShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                });
            }
            let (Some(winner), Some(shadowed)) = (self.index_of(decl.winner), self.index_of(decl.shadowed)) else {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "one of the two operations is not in the route table",
                });
            };
            let (Some(winner_entry), Some(shadowed_entry)) = (self.entries.get(winner), self.entries.get(shadowed)) else {
                continue;
            };
            if winner_entry.precedence >= shadowed_entry.precedence {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "the declared winner does not have the lower precedence",
                });
            }
            let (Some(winner_constraints), Some(shadowed_constraints)) =
                (self.constraints.get(winner), self.constraints.get(shadowed))
            else {
                continue;
            };
            let overlaps =
                overlap_witness(&winner_entry.selector, winner_constraints, &shadowed_entry.selector, shadowed_constraints)?
                    .is_some();
            if !overlaps {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "the two selectors do not overlap, so nothing is being shadowed",
                });
            }
            if self.shadowing.policy() == ShadowingPolicy::TotalOnly && !shadowed_constraints.refines(winner_constraints) {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "the overlap is partial, and the policy in force only asks about unreachable routes",
                });
            }
        }
        Ok(())
    }

    /// The readable first-match matcher.
    ///
    /// Allocates nothing and holds nothing: it walks a slice of entries, evaluating predicates
    /// that are all constant-time. `compiled` turns this into an array index for the hot shapes
    /// and is required to agree with it on every request.
    #[must_use]
    pub fn resolve(&self, request: &RouteRequestParts<'_>) -> Option<&RouteEntry> {
        self.entries.iter().find(|entry| entry.selector.matches(request))
    }

    /// [`RouteTable::resolve`], also reporting how many predicates were evaluated.
    #[must_use]
    pub fn resolve_counted(&self, request: &RouteRequestParts<'_>) -> (Option<&RouteEntry>, usize) {
        let mut evaluations = 0;
        let found = self
            .entries
            .iter()
            .find(|entry| entry.selector.matches_counted(request, &mut evaluations));
        (found, evaluations)
    }

    /// The entries, in precedence order.
    #[must_use]
    pub fn entries(&self) -> &[RouteEntry] {
        &self.entries
    }

    /// The shadowing declarations this table was checked against.
    #[must_use]
    pub fn shadowing(&self) -> &ShadowingDecls {
        &self.shadowing
    }

    /// Where an operation sits in the table.
    #[must_use]
    pub fn index_of(&self, op_name: &str) -> Option<usize> {
        self.entries.iter().position(|entry| entry.op_name == op_name)
    }

    /// A stable text rendering of the whole table, for the golden file.
    ///
    /// A model upgrade can change the routing of an operation nobody touched — a new query
    /// parameter turns a unique selector into an overlapping one. A golden diff is where that
    /// becomes visible in review rather than in production.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&format!(
                "{:>5}  {:<40} {:<20} {}\n",
                entry.precedence, entry.op_name, entry.path_shape, entry.selector
            ));
        }
        out
    }
}

/// Rejects predicates this crate could not evaluate faithfully.
fn validate_predicates(entry: &RouteEntry) -> Result<(), RouteBuildError> {
    for predicate in entry.selector.predicates() {
        if let Some(name) = predicate.header_name()
            && !is_lowercase_token(name)
        {
            return Err(RouteBuildError::InvalidPredicate {
                op_name: entry.op_name,
                detail: format!("header name {name:?} is not a lowercase HTTP token"),
            });
        }
        if let super::selector::Predicate::PathLiteral(path) = predicate
            && !path.starts_with('/')
        {
            return Err(RouteBuildError::InvalidPredicate {
                op_name: entry.op_name,
                detail: format!("path literal {path:?} does not start with '/'"),
            });
        }
        if let super::selector::Predicate::HeaderPrefix(name, prefix) = predicate
            && prefix.is_empty()
        {
            return Err(RouteBuildError::InvalidPredicate {
                op_name: entry.op_name,
                detail: format!("header prefix for {name:?} is empty; use HeaderPresent to test for the header alone"),
            });
        }
    }
    Ok(())
}

/// Whether a header name is already in the canonical lowercase form the predicates assume.
fn is_lowercase_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The rendered selector of an entry, for callers that want it without a table.
#[must_use]
pub fn render_selector(selector: &RouteSelector) -> String {
    selector.to_string()
}

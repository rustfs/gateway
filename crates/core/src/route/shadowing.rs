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

//! The reviewed record of which route wins when two of them accept the same request.
//!
//! Responsible for: [`ShadowingDecl`] (winner, shadowed, reason, evidence), the collection type
//! the table consults, [`ShadowingPolicy`] — how much of the overlap surface must be declared —
//! and mounting the generated record as the one ordered sequence consumers read.
//! NOT responsible for: computing overlap (`lattice`), or the same-precedence case, which is never
//! a declaration and always a build failure (`table`).
//! Upstream: nothing. Downstream: `table`, `explain`.
//!
//! # Where these come from
//!
//! Nowhere in this file. Every declaration is written in `model/overlays/route.toml` — the one
//! sanctioned hand-written protocol-exception source and a protected file — and lowered by
//! `cargo xtask codegen` into `generated/route_shadowing.rs`, which [`SHADOWING`] mounts. A
//! `ShadowingDecl` literal written by hand anywhere in this tree is refused by
//! `scripts/check_route_shadowing_authority.sh`, because a second source is a second set of
//! reasons, and two sets of reasons drift.
//!
//! A dialect's declarations do not live here at all: they arrive with the
//! [`crate::dialect::Dialect`] a deployment installs, are appended by [`ShadowingDecls::and`], and
//! are checked by the same [`super::table::RouteTable::build`] that checks these ones.

use std::borrow::Cow;

/// One reviewed decision: this operation wins over that one, and here is why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowingDecl {
    /// The operation with the lower (earlier) precedence.
    pub winner: &'static str,
    /// The operation it hides for the overlapping requests.
    pub shadowed: &'static str,
    /// Why this order is correct. Written by a human; read by whoever changes the order.
    pub reason: &'static str,
    /// Where the reason comes from. Must be non-empty: an unsourced ordering is a guess.
    pub evidence: &'static [&'static str],
}

/// How much of the cross-precedence overlap surface must be declared.
///
/// # The trade-off, stated rather than buried
///
/// [`EveryOverlap`](ShadowingPolicy::EveryOverlap) is what the design asks for and what this crate
/// defaults to: every cross-precedence overlap is a reviewed decision. It is also quadratic. Once
/// all thirty-odd bucket subresources are in the table, every `?acl` / `?tagging` pair overlaps —
/// a client would have to send both keys in one request to reach it — and the strict policy asks
/// for several hundred declarations that all say the same thing.
///
/// [`TotalOnly`](ShadowingPolicy::TotalOnly) keeps the guarantee that matters and drops the
/// paperwork that does not: a declaration is required only when the shadowed selector accepts
/// *nothing* the winner does not also accept, which is the case where the shadowed route is
/// unreachable — a dead operation, the `?analytics` with and without `id` defect. Partial overlaps
/// remain legal, are still reported by `explain`, and are still stable across releases because
/// precedence, not source order, decides them.
///
/// Switching the default is a maintainer decision, which is why both exist and neither is hidden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShadowingPolicy {
    /// Every cross-precedence overlap needs a declaration.
    #[default]
    EveryOverlap,
    /// Only an overlap that makes the shadowed route unreachable needs a declaration.
    TotalOnly,
}

/// The declarations a table is checked against.
///
/// A slice of groups rather than one flat slice, because the in-tree table is written in several
/// files and a compile-time concatenation of them would need either an indexing loop or a
/// placeholder element that is never a real declaration. Callers never see the seams:
/// [`ShadowingDecls::iter`] reads every group end to end in source order, which is the only order
/// anything here depends on.
///
/// The group list is a [`Cow`] rather than a plain slice because a dialect's declarations arrive at
/// assembly time, one group per dialect, and the count is not known until then — see
/// [`ShadowingDecls::and`]. Every declaration inside a group is still `&'static`: what varies is
/// how many groups there are, not where any of them lives.
#[derive(Clone, Debug, Default)]
pub struct ShadowingDecls {
    groups: Cow<'static, [&'static [ShadowingDecl]]>,
    policy: ShadowingPolicy,
}

impl ShadowingDecls {
    /// An empty set: every cross-precedence overlap will be reported as undeclared.
    pub const NONE: Self = Self {
        groups: Cow::Borrowed(&[]),
        policy: ShadowingPolicy::EveryOverlap,
    };

    /// Wraps the groups a table's declarations are written in, read one after the other.
    ///
    /// One group is the ordinary case for a caller outside this module — `over(&[DECLS])` — and
    /// the in-tree table passes one group per file.
    #[must_use]
    pub const fn over(groups: &'static [&'static [ShadowingDecl]]) -> Self {
        Self {
            groups: Cow::Borrowed(groups),
            policy: ShadowingPolicy::EveryOverlap,
        }
    }

    /// The same declarations plus one more group.
    ///
    /// How a dialect's declarations reach the table: [`crate::registry::RouterBuilder::build`]
    /// folds one group per installed dialect onto [`SHADOWING`]. Appending rather than
    /// replacing is the point — a dialect can declare the overlaps its own row creates and cannot
    /// touch the reviewed record for the generated table.
    #[must_use]
    pub fn and(mut self, group: &'static [ShadowingDecl]) -> Self {
        self.groups.to_mut().push(group);
        self
    }

    /// The same declarations under a different policy. See [`ShadowingPolicy`].
    #[must_use]
    pub const fn with_policy(mut self, policy: ShadowingPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> ShadowingPolicy {
        self.policy
    }

    /// Every declaration, in source order, every group.
    pub fn iter(&self) -> impl Iterator<Item = &'static ShadowingDecl> {
        self.groups.iter().copied().flat_map(<[ShadowingDecl]>::iter)
    }

    /// The declaration covering this ordered pair, if there is one.
    #[must_use]
    pub fn find(&self, winner: &str, shadowed: &str) -> Option<&'static ShadowingDecl> {
        self.iter().find(|decl| decl.winner == winner && decl.shadowed == shadowed)
    }
}
/// The generated record. Data only; [`ShadowingDecl`] above is its vocabulary.
///
/// Mounted in a module of its own so that the crate-wide `missing_docs = "deny"` can be lifted for
/// exactly one item — the generated `SHADOWING` constant, which the emitter does not write a doc
/// comment for.
#[allow(missing_docs, reason = "the emitter writes data, not rustdoc; see the module docs")]
#[allow(
    unreachable_pub,
    reason = "the emitter writes `pub`; this module is the constant's only reader"
)]
mod data {
    use super::ShadowingDecl;

    include!("../../generated/route_shadowing.rs");
}

/// The reviewed cross-precedence shadowing record for the generated table.
///
/// One group, because the overlay is one file. A second group here would be a second authority;
/// the only other group any table ever sees is a dialect's, appended at assembly time by
/// [`ShadowingDecls::and`].
pub const SHADOWING: ShadowingDecls = ShadowingDecls::over(&[data::SHADOWING]);

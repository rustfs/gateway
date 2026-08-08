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
//! and the pairing of the table's two halves (`shadowing_bucket.rs`, `shadowing_object.rs`) into
//! the one ordered sequence consumers read.
//! NOT responsible for: computing overlap (`lattice`), or the same-precedence case, which is never
//! a declaration and always a build failure (`table`).
//! Upstream: nothing. Downstream: `table`, `explain`.
//!
//! # Where these belong
//!
//! The issue places the declarations in `model/overlays/route.toml`, the one sanctioned
//! hand-written protocol-exception source, loaded by codegen. That file is outside this task's
//! file scope, so [`PROVISIONAL_SHADOWING`] carries the declarations the generated table needs
//! today, in the same four fields the overlay will use, with the loader left to P4-06. It is one
//! declaration; the type, not the storage, is what the rest of the crate depends on.

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
#[derive(Clone, Copy, Debug, Default)]
pub struct ShadowingDecls {
    groups: &'static [&'static [ShadowingDecl]],
    policy: ShadowingPolicy,
}

impl ShadowingDecls {
    /// An empty set: every cross-precedence overlap will be reported as undeclared.
    pub const NONE: Self = Self {
        groups: &[],
        policy: ShadowingPolicy::EveryOverlap,
    };

    /// Wraps the groups a table's declarations are written in, read one after the other.
    ///
    /// One group is the ordinary case for a caller outside this module — `over(&[DECLS])` — and
    /// the in-tree table passes one group per file.
    #[must_use]
    pub const fn over(groups: &'static [&'static [ShadowingDecl]]) -> Self {
        Self {
            groups,
            policy: ShadowingPolicy::EveryOverlap,
        }
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
/// The declarations the generated table needs today.
///
/// Every entry is the same shape: two bucket-level operations distinguished by different query
/// keys, reachable together only by a client that sends both keys at once. Precedence, which
/// codegen assigns, decides the winner; a row here records that somebody looked at it and agreed.
///
/// The listing family adds one wrinkle the subresources do not have. `ListObjects` is the meaning
/// of a `GET` on a bucket that nothing else claimed, so its selector pins no query key and it
/// therefore overlaps every other bucket-level `GET` in the table. It is last in the band for
/// exactly that reason, and the rows below are what "last" is allowed to mean.
///
/// # Why the table lives in several files
///
/// The declarations outgrew the 800-line file ceiling, and the split follows the one seam the
/// table already has: which target the overlapping selectors address. Bucket-target pairs live in
/// `shadowing_bucket.rs`, object-target pairs in `shadowing_object.rs`, and
/// [`ShadowingDecls::over`] reads the groups end to end — so every consumer still sees one
/// ordered sequence, and a declaration added to the wrong half is a review comment rather than a
/// behaviour change.
///
/// The bucket half is now two files rather than one. The `?acl` band sits ahead of every other
/// bucket subresource, so it wins a pair against each of them and against each listing, and those
/// seventeen declarations pushed `shadowing_bucket.rs` over the ceiling on their own.
/// `shadowing_bucket_acl.rs` is the second bucket group: the same seam, the same declaration
/// type, one more group in the list — not a second way of grouping. The next band that overflows
/// gets a group of its own the same way, which is why the field is a list and no longer a pair.
pub const PROVISIONAL_SHADOWING: ShadowingDecls = ShadowingDecls::over(&[
    super::shadowing_bucket::DECLS,
    super::shadowing_bucket_acl::DECLS,
    super::shadowing_object::DECLS,
]);

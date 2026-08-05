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
//! the table consults, and [`ShadowingPolicy`] — how much of the overlap surface must be declared.
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
#[derive(Clone, Copy, Debug, Default)]
pub struct ShadowingDecls {
    decls: &'static [ShadowingDecl],
    policy: ShadowingPolicy,
}

impl ShadowingDecls {
    /// An empty set: every cross-precedence overlap will be reported as undeclared.
    pub const NONE: Self = Self {
        decls: &[],
        policy: ShadowingPolicy::EveryOverlap,
    };

    /// Wraps a static declaration list.
    #[must_use]
    pub const fn new(decls: &'static [ShadowingDecl]) -> Self {
        Self {
            decls,
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

    /// Every declaration, in source order.
    #[must_use]
    pub const fn all(&self) -> &'static [ShadowingDecl] {
        self.decls
    }

    /// The declaration covering this ordered pair, if there is one.
    #[must_use]
    pub fn find(&self, winner: &str, shadowed: &str) -> Option<&'static ShadowingDecl> {
        self.decls
            .iter()
            .find(|decl| decl.winner == winner && decl.shadowed == shadowed)
    }
}

/// The declarations the generated table needs today.
///
/// One entry, and it is the shape that will recur: two bucket-level operations distinguished by
/// different query keys, reachable together only by a client that sends both keys at once. The
/// order is decided by precedence, which codegen assigns; this records that somebody looked at it.
pub static PROVISIONAL_SHADOWING: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "GetBucketLocation",
    shadowed: "ListObjectsV2",
    reason: "A request carrying both ?location and ?list-type=2 asks two questions at once. \
             AWS documents neither combination, so the answer is fixed here rather than left to \
             source order: the subresource band (300) is tried before the listing band (600), so \
             ?location wins and the listing is ignored.",
    evidence: &[
        // Both URLs are AWS's own operation references. The one-sentence summaries are written
        // here rather than quoted, per the provenance rule.
        "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html \
         — GetBucketLocation is selected by the ?location subresource alone and takes no other query input.",
        "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html \
         — ListObjectsV2 is selected by list-type=2 and treats unrecognised query keys as inert.",
    ],
}];

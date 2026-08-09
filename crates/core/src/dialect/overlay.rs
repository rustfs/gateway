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

//! The dialect overlay: the reviewed record of every operation a deployment adds to this gateway.
//!
//! Responsible for: [`DialectOverlay`] and [`OverlayRow`] — the five facts about a vendor operation
//! a reviewer has to see — the vendor-segment grammar, and [`RESERVED_HOST_CLASSES`].
//! NOT responsible for: checking a row against the code that declares it (`super`), route overlap
//! (`crate::route`), or the registration rules an operation passes whoever declared it
//! (`crate::registry::reject`).
//! Upstream: `crate::op`, `crate::route`. Downstream: [`super::DialectBuilder`],
//! [`crate::registry::RouterBuilder`].
//!
//! # Where the overlay lives, and why it is Rust rather than TOML
//!
//! One overlay per dialect, in one file inside the crate that owns the dialect —
//! `crates/core/examples/dialect_overlay.rs` is the worked example, and a real dialect crate puts
//! its own beside its operation modules. `grep` for the vendor prefix finds the whole surface a
//! deployment added, which is the property ADR-0003 exists to protect.
//!
//! `model/overlays/**` is deliberately *not* where this goes. That tree is the hand-written
//! exception source for the **pinned AWS model**: every file under it names an operation or a shape
//! the model defines, and codegen fails on a name the model does not have. A dialect operation is
//! by definition not in the model, so a row for it there would be an entry codegen has to be taught
//! to skip — and the tree is a Protected File, so teaching it that is a Breaking Change to buy
//! nothing.
//!
//! TOML was the other candidate and was rejected for two measured reasons. Every string the route
//! table holds is `&'static` — [`crate::route::RouteEntry::op_name`],
//! [`crate::route::Predicate::QueryPresent`], [`crate::registry::OperationSpec::name`] — so a
//! document parsed at start-up would have to leak every string it read in order to reach the table
//! at all. And ring 1 has no TOML reader: `rustfs-gateway-model` and
//! `rustfs-gateway-conformance` each have one, both are build-time or test-time crates this crate
//! must not depend on, and a third reader in the protocol kernel is a parser on the start-up path
//! that exists to read data the compiler could have checked.
//!
//! What a data format would have bought is that the overlay can disagree with the code. That is
//! kept: the overlay is a *second* statement of the same five facts, and [`super::DialectBuilder`]
//! refuses the dialect when the two disagree — the same arrangement as
//! [`crate::route::ShadowingDecl`], which is also hand-written data checked against the table it
//! describes.

use crate::op::ResourceShape;
use crate::route::HostClass;

/// The endpoint families a dialect may not put an operation on.
///
/// Each of these faces carries constraints written for it and for nothing else: S3 Express signs
/// with a different service and validates bucket names differently, Object Lambda serves a literal
/// path that is not a bucket at all, the website endpoint is a second protocol over the same method
/// and path shapes, and Outposts changes region resolution and the resource an authorizer is asked
/// about. An added row on one of them inherits the face without any of the checks, which is the
/// cheapest way to reach a surface nobody reviewed.
///
/// [`HostClass::Standard`], [`HostClass::Accelerate`] and [`HostClass::Dualstack`] are absent on
/// purpose: those three are the ordinary REST endpoint under three hostnames, and a dialect
/// operation on them is exactly as constrained as one on the default face.
pub const RESERVED_HOST_CLASSES: &[HostClass] = &[
    HostClass::S3Express,
    HostClass::ObjectLambda,
    HostClass::Website,
    HostClass::Outposts,
];

/// One reviewed record: what a vendor operation is called, where it sits, what it asks for, and
/// where its shape came from.
///
/// Every field restates something the operation's own declaration already says. That is the point:
/// [`super::DialectBuilder::build`] refuses a dialect whose row and whose code disagree, so the row
/// cannot rot into a description of behaviour that no longer exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayRow {
    /// The operation name, `vendor:Name`, matching [`crate::op::Operation::NAME`].
    pub name: &'static str,
    /// Position in the ordered first-match table, matching the declared route.
    ///
    /// The one number a reviewer must see, because precedence is the whole of what a dialect row
    /// can and cannot shadow: the table is first-match, so a row's band decides which standard
    /// operations it stands in front of.
    pub precedence: u16,
    /// The routing conjunction, rendered exactly as [`crate::route::render_selector`] writes it.
    ///
    /// A string rather than a predicate list so that the row reads the way the route-table golden
    /// reads, and so that a reviewer comparing the two is comparing the same text.
    pub selector: &'static str,
    /// The IAM action, matching the operation's [`crate::op::AuthRequirement`].
    pub action: &'static str,
    /// What the action is about, matching the operation's [`crate::op::AuthRequirement`].
    pub resource: ResourceShape,
    /// The default success status, matching [`crate::registry::OperationSpec::success_status`].
    pub success_status: u16,
    /// Whether this operation is reachable with no credentials at all.
    ///
    /// Checked in both directions against [`rustfs_gateway_sig::OperationFloor::allows_anonymous`].
    /// A dialect that could quietly mount an anonymous operation would let an attacker choose the
    /// authentication strength by choosing the operation — the shape of `GHSA-5qfg-mf7r-jp3w` and
    /// `GHSA-3473-5353-xhwh` — so the acknowledgement lives here, where a reviewer reads it,
    /// rather than only in the code that sets the floor.
    pub anonymous: bool,
    /// Where the wire shape comes from: one URL per source. Must be non-empty.
    ///
    /// Same rule as [`crate::route::ShadowingDecl::evidence`], and for the same reason — a claim
    /// about another implementation's wire behaviour that nobody can check is a guess with a
    /// comment. Store a link and a sentence you wrote; never paste another project's prose.
    pub evidence: &'static [&'static str],
}

/// Everything one dialect adds, as its author recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialectOverlay {
    /// The dialect's name, as a start-up report prints it: `"minio"`, `"rustfs"`.
    pub name: &'static str,
    /// The namespace segment every operation in this dialect must carry.
    ///
    /// Separate from [`DialectOverlay::name`] because the two answer different questions — the name
    /// identifies the assembly unit, the vendor is what appears in every operation name — and
    /// because a dialect that shipped operations under a segment other than its own would make
    /// "who added this operation?" unanswerable from the name.
    pub vendor: &'static str,
    /// One row per operation this dialect adds.
    pub operations: &'static [OverlayRow],
}

impl DialectOverlay {
    /// The row for an operation name, if this overlay has one.
    #[must_use]
    pub fn row(&self, name: &str) -> Option<&'static OverlayRow> {
        self.operations.iter().find(|row| row.name == name)
    }

    /// Whether the vendor segment is a lowercase ASCII token: letters, digits and `-`.
    ///
    /// Narrow on purpose. The segment ends up in log lines, audit records and policy actions, and
    /// the set of spellings a reader has to be able to tell apart is smaller when case is not one
    /// of the dimensions.
    #[must_use]
    pub fn vendor_is_well_formed(&self) -> bool {
        !self.vendor.is_empty()
            && self
                .vendor
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }
}

/// The vendor segment of a `vendor:Name` operation name, if it has one.
#[must_use]
pub fn vendor_of(name: &str) -> Option<&str> {
    name.split_once(':').map(|(vendor, _)| vendor)
}

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

//! How a deployment adds an operation AWS does not define, and everything that refuses.
//!
//! Responsible for: [`Dialect`] — one assembly unit of vendor operations — [`DialectBuilder`], the
//! cross-check between the overlay and the code that declares each row, and [`DialectError`], the
//! single answer to "why was this dialect refused".
//! NOT responsible for: the registration rules an operation passes whoever declared it
//! (`crate::registry::reject`, reached from here so a dialect cannot be the path around them),
//! route overlap (`crate::route::RouteTable::build`, reached from
//! [`crate::registry::RouterBuilder::build`]), installing a handler
//! ([`crate::registry::RouterBuilder::handle_without_codec`]), or anything per request.
//! Upstream: `crate::op`, `crate::route`, `crate::registry`. Downstream:
//! [`crate::registry::RouterBuilder::dialect`].
//!
//! ```text
//!   overlay.rs  the reviewed record: name, precedence, selector, spec, evidence, claims
//!   claimed.rs  operations served inside the dialect's own path-prefix claims (ADR-0024)
//!   error.rs    every refusal, as one enum
//!   mod.rs      assembly: the record checked against the code, or a list of refusals
//! ```
//!
//! # A dialect is an assembly unit, not a cargo feature
//!
//! A feature is chosen at compile time, is not composable, and forces anybody who wants their own
//! dialect to fork. A [`Dialect`] is a value: a deployment builds two of them and installs both, and
//! a conflict between them is a start-up failure with both sources named rather than whichever one
//! the linker happened to see last.
//!
//! # What a dialect may do, and what it may not
//!
//! | Dimension | A dialect may | A dialect may not |
//! |---|---|---|
//! | Operations | add a **new** `vendor:Name` operation with its own route row | take an AWS name, in any case; stand in front of a standard row without declaring it |
//! | Routing | choose its own precedence, and declare the overlaps that choice creates | change a standard operation's row: [`crate::registry::OperationSpec`] is `&'static` data this crate owns, and there is no method that mutates one |
//! | Authorisation | declare its own action and resource shape | omit them — [`crate::registry::RegistryError::MissingAuthRequirement`] is refused here as well as at registration |
//!
//! # Why registration is still explicit
//!
//! [`DialectBuilder::declare`] records a route and cross-checks a row. It does **not** install a
//! handler: that stays a separate [`crate::registry::RouterBuilder::handle_without_codec`] call
//! somebody wrote, because ADR-0003 bans the link-time collection that would make it implicit, and
//! because a route with no handler is a legitimate state — it answers `501`, which is what a
//! backend that has not implemented an operation should say.

mod claimed;
mod error;
mod overlay;

use std::collections::BTreeSet;

pub use self::claimed::{ClaimedOperation, ClaimedRoute, ClaimedRow, render_claimed_route, render_claimed_rows};
pub use self::error::DialectError;
pub use self::overlay::{DialectOverlay, OverlayRow, RESERVED_HOST_CLASSES, vendor_of};
pub use crate::route::BucketParam;

use crate::op::Operation;
use crate::registry::reject;
use crate::route::{PathClaim, Predicate, RouteEntry, RouteSelector, ShadowingDecl, render_selector};

/// Where a dialect wants its operation in the ordered table, and what that choice hides.
///
/// Hand-written, because the generated table is generated from the pinned AWS model and a vendor
/// operation is not in it. Everything else about the operation comes from its type.
#[derive(Clone, Copy, Debug)]
pub struct DialectRoute {
    /// Position in the ordered first-match table. Lower is tried first.
    ///
    /// See `crate::route`'s band table. A dialect row is only reachable if it sits ahead of every
    /// standard row that would otherwise accept the same request — and each of those is an overlap
    /// that has to be declared.
    pub precedence: u16,
    /// The routing conjunction.
    pub selector: &'static [Predicate],
    /// The path shape this operation advertises, for the reverse index and for explanations.
    pub path_shape: &'static str,
    /// The overlaps this placement creates, each with a reason and a source.
    ///
    /// Empty is legitimate and common: a row whose selector cannot be satisfied at the same time as
    /// any standard row — an admin call on a path literal, say — shadows nothing.
    pub shadows: &'static [ShadowingDecl],
}

/// One operation a dialect contributes: its route row and the overlaps that row declares.
#[derive(Clone, Debug)]
pub struct DialectOperation {
    name: &'static str,
    entry: RouteEntry,
    shadows: &'static [ShadowingDecl],
}

impl DialectOperation {
    /// The operation name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The route row this operation adds to the table.
    #[must_use]
    pub const fn entry(&self) -> &RouteEntry {
        &self.entry
    }

    /// The overlaps the row declares.
    #[must_use]
    pub const fn shadows(&self) -> &'static [ShadowingDecl] {
        self.shadows
    }
}

/// Everything one dialect adds, assembled and checked.
///
/// Produced only by [`DialectBuilder::build`], so a value of this type is one whose overlay and
/// whose code were compared and agreed. [`crate::registry::RouterBuilder::dialect`] takes it from
/// there.
#[derive(Clone, Debug)]
pub struct Dialect {
    name: &'static str,
    operations: Vec<DialectOperation>,
    claims: &'static [PathClaim],
    claimed: Vec<ClaimedOperation>,
}

impl Dialect {
    /// Begins assembling the dialect this overlay describes.
    ///
    /// The overlay's claims are checked here: each against the claim rules, and each pair for
    /// whether they could cover one path.
    #[must_use]
    pub fn assemble(overlay: &'static DialectOverlay) -> DialectBuilder {
        let mut errors = Vec::new();
        if !overlay.vendor_is_well_formed() {
            errors.push(DialectError::MalformedVendor {
                dialect: overlay.name,
                vendor: overlay.vendor,
            });
        }
        for (index, claim) in overlay.claims.iter().enumerate() {
            if let Some(rejection) = claim.rejection() {
                errors.push(DialectError::RefusedClaim {
                    dialect: overlay.name,
                    prefix: claim.prefix,
                    rejection,
                });
            }
            for later in overlay.claims.iter().skip(index.saturating_add(1)) {
                if claim.overlaps(later) {
                    errors.push(DialectError::OverlappingClaims {
                        dialect: overlay.name,
                        first: claim.prefix,
                        second: later.prefix,
                    });
                }
            }
        }
        DialectBuilder {
            overlay,
            operations: Vec::new(),
            claimed: Vec::new(),
            attempted: BTreeSet::new(),
            used_claims: BTreeSet::new(),
            errors,
        }
    }

    /// The path prefixes this dialect claims away from S3 routing.
    #[must_use]
    pub const fn claims(&self) -> &'static [PathClaim] {
        self.claims
    }

    /// The operations it serves inside those claims, in declaration order.
    #[must_use]
    pub fn claimed_operations(&self) -> &[ClaimedOperation] {
        &self.claimed
    }

    /// The dialect's name, as a start-up report prints it.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The operations it contributes to the S3 table, in declaration order.
    #[must_use]
    pub fn operations(&self) -> &[DialectOperation] {
        &self.operations
    }

    /// Every operation name it contributes, S3-table rows first and then claimed routes, each in
    /// declaration order. For a start-up report and for assertions.
    pub fn operation_names(&self) -> impl Iterator<Item = &'static str> {
        self.operations
            .iter()
            .map(DialectOperation::name)
            .chain(self.claimed.iter().map(ClaimedOperation::name))
    }
}

/// Collects a dialect's operations and reports every reason it cannot be assembled.
///
/// Refusals accumulate rather than short-circuiting, for the reason
/// [`crate::registry::RouterBuilder`] gives: a dialect author fixing the first of six mismatches
/// and re-running six times is six start-up cycles, and the natural chained-`?` spelling reports
/// the first and hides the rest.
#[derive(Debug)]
pub struct DialectBuilder {
    overlay: &'static DialectOverlay,
    operations: Vec<DialectOperation>,
    /// Accepted claimed routes (`claimed`).
    claimed: Vec<ClaimedOperation>,
    /// Every claim prefix some row's template sits inside, accepted or not, so that a rejected row
    /// does not also report its claim as unused.
    used_claims: BTreeSet<&'static str>,
    /// Every name `declare` was called with, accepted or not.
    ///
    /// Separate from the accepted list so that one rejected declaration is one refusal.
    /// Checking [`DialectError::DeclaredNowhere`] against the accepted list instead would report a
    /// second, misleading refusal for every row whose declaration failed for another reason —
    /// "nothing declares this row" is not what went wrong, and the real reason is then one line of
    /// two rather than the answer.
    attempted: BTreeSet<&'static str>,
    errors: Vec<DialectError>,
}

impl DialectBuilder {
    /// Declares that this dialect adds `O`, at this place in the table.
    ///
    /// Everything except the route comes from the type: the name from [`Operation::NAME`], the
    /// action, resource and success status from [`Operation::spec`], and whether the operation is
    /// anonymously reachable from [`Operation::floor`]. The overlay row is then compared with all
    /// of them, and any disagreement is collected.
    #[must_use]
    pub fn declare<O: Operation>(mut self, route: DialectRoute) -> Self {
        let before = self.errors.len();
        self.attempted.insert(O::NAME);
        self.check::<O>(&route);
        if self.errors.len() == before {
            self.operations.push(DialectOperation {
                name: O::NAME,
                entry: RouteEntry {
                    precedence: route.precedence,
                    selector: RouteSelector::new(route.selector),
                    op_name: O::NAME,
                    path_shape: route.path_shape,
                },
                shadows: route.shadows,
            });
        }
        self
    }

    /// Every rule one declaration passes, in the order a fixer walks them.
    ///
    /// Identity first (the rules every registration passes anywhere), then the namespace this
    /// dialect owns, then the overlay row and the five facts it restates.
    fn check<O: Operation>(&mut self, route: &DialectRoute) {
        let name = O::NAME;
        if self.is_declared(name) {
            self.errors.push(DialectError::DeclaredTwice { name });
            return;
        }
        // The registry's own rules, reached from here rather than restated: a dialect must not be
        // a second, laxer door to the same registrations.
        if let Err(error) = reject::check_operation::<O>() {
            self.errors.push(DialectError::Registration(error));
            return;
        }
        if vendor_of(name) != Some(self.overlay.vendor) {
            self.errors.push(DialectError::WrongVendor {
                name,
                vendor: self.overlay.vendor,
            });
            return;
        }
        if route.selector.is_empty() {
            self.errors.push(DialectError::EmptySelector { name });
            return;
        }
        for predicate in route.selector {
            if let Predicate::HostClass(class) = *predicate
                && RESERVED_HOST_CLASSES.contains(&class)
            {
                self.errors.push(DialectError::ReservedHostClass { name, class });
                return;
            }
        }

        self.check_record::<O>(route.precedence, render_selector(&RouteSelector::new(route.selector)));
    }

    /// Whether an S3-table row or a claimed route already declares this name.
    fn is_declared(&self, name: &str) -> bool {
        self.operations.iter().any(|declared| declared.name == name)
            || self.claimed.iter().any(|declared| declared.name() == name)
    }

    /// The overlay row and the five facts it restates, for a declaration of either kind:
    /// `declared_selector` is the rendered selector for an S3-table row and the rendered rows for
    /// a claimed route. Returns whether every check passed.
    fn check_record<O: Operation>(&mut self, precedence: u16, declared_selector: String) -> bool {
        let name = O::NAME;
        let Some(row) = self.overlay.row(name) else {
            self.errors.push(DialectError::NotInOverlay { name });
            return false;
        };
        if row.evidence.is_empty() {
            self.errors.push(DialectError::UnsourcedOperation { name });
            return false;
        }
        if row.precedence != precedence {
            self.errors.push(DialectError::PrecedenceMismatch {
                name,
                declared: precedence,
                overlay: row.precedence,
            });
            return false;
        }
        if declared_selector != row.selector {
            self.errors.push(DialectError::SelectorMismatch {
                name,
                declared: declared_selector,
                overlay: row.selector,
            });
            return false;
        }

        let spec = O::spec();
        if spec.success_status != row.success_status {
            self.errors.push(DialectError::StatusMismatch {
                name,
                declared: spec.success_status,
                overlay: row.success_status,
            });
            return false;
        }
        // `check_operation` has already refused a spec with no action, so this is not the missing
        // case; it is the case where the row and a present action disagree.
        if let Some(auth) = spec.auth {
            // The rendered requirement, so an any-of rule or a subject the overlay does not spell
            // out is a mismatch rather than a record that names only the first action (ADR-0025).
            let declared = auth.render();
            if declared != row.action {
                self.errors.push(DialectError::ActionMismatch {
                    name,
                    declared,
                    overlay: row.action,
                });
                return false;
            }
            if auth.resource != row.resource {
                self.errors.push(DialectError::ResourceMismatch {
                    name,
                    declared: auth.resource,
                    overlay: row.resource,
                });
                return false;
            }
        }

        match (O::floor().allows_anonymous(), row.anonymous) {
            (true, false) => {
                self.errors.push(DialectError::AnonymousNotAcknowledged { name });
                false
            }
            (false, true) => {
                self.errors.push(DialectError::StaleAnonymousAcknowledgement { name });
                false
            }
            (true, true) | (false, false) => true,
        }
    }

    /// The assembled dialect, or every reason it was refused.
    ///
    /// # Errors
    ///
    /// Every [`DialectError`] collected by [`DialectBuilder::declare`], one
    /// [`DialectError::DeclaredNowhere`] per overlay row nothing declared, and one
    /// [`DialectError::ForeignShadowing`] per declaration that is about two operations this dialect
    /// does not own.
    pub fn build(mut self) -> Result<Dialect, Vec<DialectError>> {
        for row in self.overlay.operations {
            if !self.attempted.contains(row.name) {
                self.errors.push(DialectError::DeclaredNowhere { name: row.name });
            }
        }
        for claim in self.overlay.claims {
            if !self.used_claims.contains(claim.prefix) {
                self.errors.push(DialectError::UnusedClaim {
                    dialect: self.overlay.name,
                    prefix: claim.prefix,
                });
            }
        }
        // Checked here rather than in `declare`, because a dialect's second operation is a
        // legitimate party to the first one's declaration and is not known yet at that point.
        let mine: BTreeSet<&'static str> = self
            .operations
            .iter()
            .map(|operation| operation.name)
            .chain(self.claimed.iter().map(ClaimedOperation::name))
            .collect();
        let declarations = self
            .operations
            .iter()
            .flat_map(|operation| operation.shadows)
            .chain(self.claimed.iter().flat_map(ClaimedOperation::shadows));
        for decl in declarations {
            if !mine.contains(decl.winner) && !mine.contains(decl.shadowed) {
                self.errors.push(DialectError::ForeignShadowing {
                    dialect: self.overlay.name,
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                });
            }
        }
        if self.errors.is_empty() {
            Ok(Dialect {
                name: self.overlay.name,
                operations: self.operations,
                claims: self.overlay.claims,
                claimed: self.claimed,
            })
        } else {
            Err(self.errors)
        }
    }
}

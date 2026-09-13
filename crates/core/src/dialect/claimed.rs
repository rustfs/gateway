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

//! Operations a dialect serves inside its own path-prefix claims (ADR-0024).
//!
//! Responsible for: [`ClaimedRow`] and [`ClaimedRoute`] — what the code declares — and
//! [`DialectBuilder::declare_claimed`], which checks every row against the dialect's claims and the
//! whole route against the overlay row before a [`ClaimedOperation`] exists.
//! NOT responsible for: the claim and template grammar (`crate::route::claim`), overlaps between
//! claimed rows (`crate::route::ClaimedTable::build`, reached from
//! [`crate::registry::RouterBuilder::build`]), or the S3-table rows (`super`).
//! Upstream: `super`, `crate::route`. Downstream: [`crate::registry::RouterBuilder::dialect`].
//!
//! # Why a claimed operation may have several rows
//!
//! RustFS serves 251 of its admin routes at a second prefix too, `/minio/admin/…`, and that alias
//! is where it seals request and response bodies with the caller's secret. One operation, one
//! action, one handler, several paths: each path is one [`ClaimedRow`], and the overlay records all
//! of them, so an alias is reviewed exactly like the canonical row.
//!
//! # Why a claimed operation is service-level
//!
//! Inside a claim the path is not S3 addressing, so it names no bucket and no key. An operation
//! that declared a bucket or object resource would be authorised against a resource nothing
//! supplies, so it is refused.

use crate::op::{Operation, ResourceShape};
use crate::registry::reject;
use crate::route::{
    ClaimedEntry, PathTemplate, Predicate, RouteEntry, RouteSelector, ShadowingDecl, claimed_selector_fault, render_claimed_row,
};

use super::{DialectBuilder, DialectError, vendor_of};

/// One path an operation is served at, inside a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimedRow {
    /// The path template: literal segments and whole-segment `{parameters}`, starting with the
    /// claim's own segments.
    pub template: &'static str,
    /// Exactly one method, and optionally query or header predicates. Never a target, a path
    /// literal, a host class or an ARN form: the claim decides those.
    pub selector: &'static [Predicate],
}

/// Where a dialect serves one claimed operation.
#[derive(Clone, Copy, Debug)]
pub struct ClaimedRoute {
    /// Order among overlapping rows inside one claim. Lower is tried first.
    pub precedence: u16,
    /// Every path the operation is served at; the first is the canonical one by convention.
    pub rows: &'static [ClaimedRow],
    /// The overlaps with other claimed rows this placement creates, each with a reason and a
    /// source. Never about an S3 row: a claimed row cannot overlap one.
    pub shadows: &'static [ShadowingDecl],
}

/// One operation a dialect serves inside its claims: its rows and their declarations.
#[derive(Clone, Debug)]
pub struct ClaimedOperation {
    name: &'static str,
    precedence: u16,
    entries: Vec<ClaimedEntry>,
    shadows: &'static [ShadowingDecl],
}

impl ClaimedOperation {
    /// The operation name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Its precedence among claimed rows.
    #[must_use]
    pub const fn precedence(&self) -> u16 {
        self.precedence
    }

    /// Its rows, alias rows included, in declaration order.
    #[must_use]
    pub fn entries(&self) -> &[ClaimedEntry] {
        &self.entries
    }

    /// The overlaps its rows declare.
    #[must_use]
    pub const fn shadows(&self) -> &'static [ShadowingDecl] {
        self.shadows
    }
}

/// Renders a claimed route's rows the way an overlay records them: each row as
/// `PathTemplate("…") ∧ Method(…)`, joined by ` ∨ `.
#[must_use]
pub fn render_claimed_rows(rows: &[ClaimedRow]) -> String {
    rows.iter()
        .map(|row| render_claimed_row(row.template, &RouteSelector::new(row.selector)))
        .collect::<Vec<_>>()
        .join(" ∨ ")
}

impl DialectBuilder {
    /// Declares that this dialect serves `O` inside its path-prefix claims, at every row of
    /// `route`.
    ///
    /// Everything except the rows comes from the type, as for [`DialectBuilder::declare`]; the
    /// overlay row must record every row, rendered by [`render_claimed_rows`], and a service-level
    /// resource.
    #[must_use]
    pub fn declare_claimed<O: Operation>(mut self, route: ClaimedRoute) -> Self {
        let before = self.errors.len();
        self.attempted.insert(O::NAME);
        let entries = self.check_claimed::<O>(&route);
        if self.errors.len() == before
            && let Some(entries) = entries
        {
            self.claimed.push(ClaimedOperation {
                name: O::NAME,
                precedence: route.precedence,
                entries,
                shadows: route.shadows,
            });
        }
        self
    }

    /// Identity, namespace, every row, then the overlay row and the facts it restates.
    fn check_claimed<O: Operation>(&mut self, route: &ClaimedRoute) -> Option<Vec<ClaimedEntry>> {
        let name = O::NAME;
        if self.is_declared(name) {
            self.errors.push(DialectError::DeclaredTwice { name });
            return None;
        }
        if let Err(error) = reject::check_operation::<O>() {
            self.errors.push(DialectError::Registration(error));
            return None;
        }
        if vendor_of(name) != Some(self.overlay.vendor) {
            self.errors.push(DialectError::WrongVendor {
                name,
                vendor: self.overlay.vendor,
            });
            return None;
        }
        if route.rows.is_empty() {
            self.errors.push(DialectError::EmptyClaimedRoute { name });
            return None;
        }
        let mut entries = Vec::with_capacity(route.rows.len());
        for (index, row) in route.rows.iter().enumerate() {
            let template = match PathTemplate::parse(row.template) {
                Ok(template) => template,
                Err(rejection) => {
                    self.errors.push(DialectError::MalformedTemplate {
                        name,
                        template: row.template,
                        rejection,
                    });
                    return None;
                }
            };
            let Some(claim) = self.overlay.claims.iter().find(|claim| template.is_within(claim)) else {
                self.errors.push(DialectError::TemplateOutsideClaims {
                    name,
                    template: row.template,
                });
                return None;
            };
            self.used_claims.insert(claim.prefix);
            if let Some(why) = claimed_selector_fault(row.selector) {
                self.errors.push(DialectError::ClaimedRowSelector {
                    name,
                    template: row.template,
                    why,
                });
                return None;
            }
            if route.rows.iter().take(index).any(|earlier| earlier == row) {
                self.errors.push(DialectError::DuplicateClaimedRow {
                    name,
                    template: row.template,
                });
                return None;
            }
            entries.push(ClaimedEntry::new(
                RouteEntry {
                    precedence: route.precedence,
                    selector: RouteSelector::new(row.selector),
                    op_name: name,
                    path_shape: row.template,
                },
                template,
                *claim,
            ));
        }
        if !self.check_record::<O>(route.precedence, render_claimed_rows(route.rows)) {
            return None;
        }
        if let Some(auth) = O::spec().auth
            && auth.resource != ResourceShape::Service
        {
            self.errors.push(DialectError::ClaimedOperationNamesAResource {
                name,
                resource: auth.resource,
            });
            return None;
        }
        Some(entries)
    }
}

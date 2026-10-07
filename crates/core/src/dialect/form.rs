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

//! Operations a dialect serves behind a form claim (ADR-0041).
//!
//! Responsible for: [`FormRoute`] — what the code declares — and [`DialectBuilder::declare_form`],
//! which checks the claim's grammar, its uniqueness inside the dialect, the operation's
//! service-level resource and the overlay row before a [`FormOperation`] exists.
//! NOT responsible for: the claim grammar and the request test (`crate::route::FormClaim`),
//! overlaps between dialects or with path claims (`crate::route::ClaimedTable::with_forms`, reached
//! from [`crate::registry::RouterBuilder::build`]), or path-claimed rows (`super::claimed`).
//! Upstream: `super`, `crate::route`. Downstream: [`crate::registry::RouterBuilder::dialect`].
//!
//! # Why one operation per form claim
//!
//! A form claim already decides the method, the path and the media type, and reads nothing else;
//! there is nothing left for a second row to select on. One claim, one operation, and the overlay
//! row records the claim as that operation's selector.

use crate::op::{Operation, ResourceShape};
use crate::registry::reject;
use crate::route::{FormClaim, RouteEntry, RouteSelector};

use super::{DialectBuilder, DialectError, vendor_of};

/// Where a dialect serves one operation behind a form claim.
#[derive(Clone, Copy, Debug)]
pub struct FormRoute {
    /// The operation's place in the overlay's record. A form claim overlaps no row, so the number
    /// orders nothing; it is reviewed like every other row's.
    pub precedence: u16,
    /// The claim.
    pub claim: &'static FormClaim,
}

/// One operation a dialect serves behind a form claim.
#[derive(Clone, Debug)]
pub struct FormOperation {
    name: &'static str,
    claim: FormClaim,
    entry: RouteEntry,
}

impl FormOperation {
    /// The operation name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The claim it answers.
    #[must_use]
    pub const fn claim(&self) -> &FormClaim {
        &self.claim
    }

    /// Its route entry: the operation, its precedence and an empty selector.
    #[must_use]
    pub const fn entry(&self) -> &RouteEntry {
        &self.entry
    }
}

impl DialectBuilder {
    /// Declares that this dialect serves `O` behind `route`'s form claim.
    ///
    /// Everything except the claim comes from the type, as for [`DialectBuilder::declare`]; the
    /// overlay row must record the claim as rendered by [`FormClaim::render`], and a service-level
    /// resource.
    #[must_use]
    pub fn declare_form<O: Operation>(mut self, route: FormRoute) -> Self {
        let before = self.errors.len();
        self.attempted.insert(O::NAME);
        self.check_form::<O>(&route);
        if self.errors.len() == before {
            self.forms.push(FormOperation {
                name: O::NAME,
                claim: *route.claim,
                entry: RouteEntry {
                    precedence: route.precedence,
                    selector: RouteSelector::new(&[]),
                    op_name: O::NAME,
                    path_shape: route.claim.path,
                },
            });
        }
        self
    }

    /// Identity, namespace, the claim, the resource, then the overlay row and the facts it restates.
    fn check_form<O: Operation>(&mut self, route: &FormRoute) {
        let name = O::NAME;
        if self.is_declared(name) {
            self.errors.push(DialectError::DeclaredTwice { name });
            return;
        }
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
        if let Some(rejection) = route.claim.rejection() {
            self.errors.push(DialectError::RefusedFormClaim { name, rejection });
            return;
        }
        if let Some(earlier) = self.forms.iter().find(|earlier| earlier.claim.overlaps(route.claim)) {
            self.errors.push(DialectError::OverlappingFormClaims {
                name,
                earlier: earlier.name,
            });
            return;
        }
        match O::spec().auth.map(|auth| auth.resource) {
            Some(ResourceShape::Service) | None => {}
            Some(resource) => {
                self.errors
                    .push(DialectError::ClaimedOperationNamesAResource { name, resource });
                return;
            }
        }
        let _ = self.check_record::<O>(route.precedence, route.claim.render());
    }
}

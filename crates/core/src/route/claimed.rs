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

//! The claimed rows and the table that routes a claimed request without consulting the S3 table
//! (ADR-0024).
//!
//! Responsible for: [`ClaimedEntry`] — one reviewed row inside a claim — [`InstalledFormClaim`] —
//! one form claim and its operation (ADR-0041) — [`ClaimedTable`], which decides whether a request
//! is inside an installed claim and which row accepts it, and the build-time refusals: a
//! same-precedence conflict, an undeclared cross-precedence overlap, and a stale or unsourced
//! declaration inside a path claim, exactly as the S3 table applies them to its rows, and a refused,
//! overlapping or path-claimed form claim.
//! NOT responsible for: the claim and template grammar or the parameter values (`claim`), the S3
//! table (`table`, `compiled`), or whether a dialect may claim a prefix (`crate::dialect`).
//! Upstream: `claim`, `selector`, `lattice`, `shadowing`, `shape`, `table`. Downstream:
//! `crate::dispatch::Router`, `crate::dialect`, `crate::registry::RouterBuilder`.

use super::claim::{PathClaim, PathTemplate};
use super::form_claim::FormClaim;
use super::lattice::{Constraints, OverlapError};
use super::selector::{HostClass, Predicate, RouteEntry, RouteRequestParts, RouteSelector, TargetKind};
use super::shadowing::{ShadowingDecls, ShadowingPolicy};
use super::shape::RequestShape;
use super::table::{RouteBuildError, SelectorReport, validate_predicates};

// ── the claimed rows ─────────────────────────────────────────────────────────────────────────

/// Renders one claimed row the way an overlay records it.
#[must_use]
pub fn render_claimed_row(template: &str, selector: &RouteSelector) -> String {
    if selector.predicates().is_empty() {
        format!("PathTemplate({template:?})")
    } else {
        format!("PathTemplate({template:?}) ∧ {selector}")
    }
}

/// Why a claimed row's selector is refused, or `None` when it is usable.
///
/// A claimed row names at most one method and may add query and header predicates. No method
/// predicate means every method, including extension tokens (ADR-0038). Everything else
/// the claim already decides: the target (the path is not a bucket or a key), the path (the
/// template), the endpoint face (standard only) and the ARN form (none).
#[must_use]
pub(crate) fn claimed_selector_fault(predicates: &[Predicate]) -> Option<&'static str> {
    let mut methods = 0_usize;
    for predicate in predicates {
        match predicate {
            Predicate::Method(_) => methods = methods.saturating_add(1),
            Predicate::Target(_) => {
                return Some("a claimed row names no S3 target; inside a claim the path is not a bucket or a key");
            }
            Predicate::PathLiteral(_) => {
                return Some("the template is the row's path; a path literal beside it would be a second one");
            }
            Predicate::HostClass(_) => {
                return Some("a claim applies on the standard endpoint only, so a row names no endpoint face");
            }
            Predicate::ArnForm(_) => return Some("a claimed path holds no ARN"),
            _ => {}
        }
    }
    (methods > 1).then_some("a claimed row names at most one method")
}

/// Where a claimed route's authorisation bucket comes from (ADR-0025, ADR-0026).
///
/// Either way the raw, still-encoded value meets the path-style S3 bucket rules
/// (`codec::bucket_label`) before anything is authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BucketParam {
    /// A template parameter: its raw segment is the bucket (`/quota/{bucket}`).
    Path(&'static str),
    /// A query parameter, present exactly once: its raw value is the bucket
    /// (`get-bucket-quota?bucket=`). A repeated, malformed, absent or empty parameter is a `400`.
    Query(&'static str),
}

impl BucketParam {
    /// The parameter's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Path(name) | Self::Query(name) => name,
        }
    }
}

/// One claimed row: the route entry, its template and the claim it is inside.
///
/// Produced only by [`crate::dialect::DialectBuilder::declare_claimed`], after the overlay review:
///
/// ```compile_fail,E0624
/// use rustfs_gateway_core::route::{ClaimedEntry, PathClaim, PathTemplate, RouteEntry};
/// fn forge(entry: RouteEntry, template: PathTemplate, claim: PathClaim) -> ClaimedEntry {
///     ClaimedEntry::new(entry, template, claim)
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ClaimedEntry {
    entry: RouteEntry,
    template: PathTemplate,
    claim: PathClaim,
    bucket_param: Option<BucketParam>,
}

impl ClaimedEntry {
    pub(crate) fn new(entry: RouteEntry, template: PathTemplate, claim: PathClaim) -> Self {
        Self {
            entry,
            template,
            claim,
            bucket_param: None,
        }
    }

    /// This row, binding `param` as the authorisation bucket (ADR-0025, ADR-0026). The dialect
    /// checks a template parameter against the template, and a query parameter's spelling, before
    /// it builds one.
    pub(crate) const fn with_bucket_param(mut self, param: Option<BucketParam>) -> Self {
        self.bucket_param = param;
        self
    }

    /// The parameter whose raw value is the request's bucket, when the operation is authorised on
    /// a bucket; `None` for a service-level claimed row.
    #[must_use]
    pub const fn bucket_param(&self) -> Option<BucketParam> {
        self.bucket_param
    }

    /// The route entry: the operation, its precedence and its method, query and header predicates.
    #[must_use]
    pub const fn entry(&self) -> &RouteEntry {
        &self.entry
    }

    /// The path template.
    #[must_use]
    pub const fn template(&self) -> &PathTemplate {
        &self.template
    }

    /// The claim the row is inside.
    #[must_use]
    pub const fn claim(&self) -> &PathClaim {
        &self.claim
    }

    fn report(&self) -> SelectorReport {
        SelectorReport {
            op_name: self.entry.op_name,
            precedence: self.entry.precedence,
            selector: render_claimed_row(self.template.as_str(), &self.entry.selector),
        }
    }
}

/// A claim as installed: the dialect that brought it, and the claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstalledClaim {
    /// The dialect's name.
    pub dialect: &'static str,
    /// The claim.
    pub claim: PathClaim,
}

/// A form claim as installed: the dialect that brought it, the claim, and the one operation that
/// answers every request inside it (ADR-0041).
///
/// Produced only by [`crate::registry::RouterBuilder::dialect`] from an assembled dialect, so the
/// overlay review has already compared the claim with the operation's record.
#[derive(Clone, Debug)]
pub struct InstalledFormClaim {
    dialect: &'static str,
    claim: FormClaim,
    entry: RouteEntry,
}

impl InstalledFormClaim {
    pub(crate) const fn new(dialect: &'static str, claim: FormClaim, entry: RouteEntry) -> Self {
        Self { dialect, claim, entry }
    }

    /// The dialect that installed it.
    #[must_use]
    pub const fn dialect(&self) -> &'static str {
        self.dialect
    }

    /// The claim.
    #[must_use]
    pub const fn claim(&self) -> &FormClaim {
        &self.claim
    }

    /// The route entry of the operation that answers inside it. Its selector is empty: the claim
    /// decides the method, the path and the media type, and nothing else is read.
    #[must_use]
    pub const fn entry(&self) -> &RouteEntry {
        &self.entry
    }
}

/// What the claim table says about one request.
#[derive(Clone, Copy, Debug)]
pub enum ClaimLookup<'a> {
    /// No claim covers the request: S3 routing decides it.
    Outside,
    /// A claim covers the request. S3 routing never sees it; `entry` is the claimed row that
    /// accepts it, or `None` when none does.
    Inside {
        /// The covering claim.
        claim: &'a InstalledClaim,
        /// The accepting row.
        entry: Option<&'a ClaimedEntry>,
    },
    /// A form claim covers the request, on whatever host it arrived (ADR-0041). Its one operation
    /// answers it; neither a path claim nor S3 routing sees it.
    Form {
        /// The covering form claim and its operation.
        claim: &'a InstalledFormClaim,
    },
}

impl<'a> ClaimLookup<'a> {
    /// The accepting claimed row, when a path claim covers the request and a row accepts it.
    /// `None` for a form claim, which has no rows: [`ClaimLookup::route_entry`] names its operation.
    #[must_use]
    pub const fn entry(&self) -> Option<&'a ClaimedEntry> {
        match self {
            Self::Outside | Self::Form { .. } => None,
            Self::Inside { entry, .. } => *entry,
        }
    }

    /// The route entry of the operation that answers, inside either kind of claim.
    #[must_use]
    pub fn route_entry(&self) -> Option<&'a RouteEntry> {
        match self {
            Self::Outside => None,
            Self::Inside { entry, .. } => entry.map(ClaimedEntry::entry),
            Self::Form { claim } => Some(claim.entry()),
        }
    }

    /// Whether a claim of either kind covers the request.
    #[must_use]
    pub const fn is_inside(&self) -> bool {
        matches!(self, Self::Inside { .. } | Self::Form { .. })
    }
}

/// Every installed claim and every claimed row, checked as a whole at start-up.
#[derive(Clone, Debug, Default)]
pub struct ClaimedTable {
    claims: Box<[InstalledClaim]>,
    /// Each row with the index of its claim, sorted by claim, then precedence, then name.
    entries: Box<[(usize, ClaimedEntry)]>,
    /// Every form claim, in installation order (ADR-0041).
    forms: Box<[InstalledFormClaim]>,
}

impl ClaimedTable {
    /// Builds the table, or refuses.
    ///
    /// Not `async`, and it takes no store: see the invariant in [`crate::route`].
    ///
    /// # Errors
    ///
    /// [`RouteBuildError::RefusedClaim`], [`RouteBuildError::OverlappingClaims`] when two claims
    /// could cover one path, [`RouteBuildError::UnclaimedRow`] for a row outside every installed
    /// claim, and the S3 table's own refusals applied inside each claim: a same-precedence
    /// [`RouteBuildError::Conflict`], an undeclared cross-precedence overlap, and a stale or
    /// unsourced declaration.
    pub fn build(
        claims: Vec<InstalledClaim>,
        entries: Vec<ClaimedEntry>,
        shadowing: &ShadowingDecls,
    ) -> Result<Self, RouteBuildError> {
        for installed in &claims {
            if let Some(rejection) = installed.claim.rejection() {
                return Err(RouteBuildError::RefusedClaim {
                    prefix: installed.claim.prefix,
                    rejection,
                });
            }
        }
        for (index, first) in claims.iter().enumerate() {
            for second in claims.iter().skip(index.saturating_add(1)) {
                if first.claim.overlaps(&second.claim) {
                    return Err(RouteBuildError::OverlappingClaims {
                        first_dialect: first.dialect,
                        first: first.claim.prefix,
                        second_dialect: second.dialect,
                        second: second.claim.prefix,
                    });
                }
            }
        }
        let mut owned = Vec::with_capacity(entries.len());
        for entry in entries {
            let owner = claims
                .iter()
                .position(|installed| installed.claim == entry.claim && entry.template.is_within(&installed.claim));
            let Some(owner) = owner else {
                return Err(RouteBuildError::UnclaimedRow {
                    op_name: entry.entry.op_name,
                    template: entry.template.as_str(),
                });
            };
            validate_predicates(&entry.entry)?;
            if let Some(why) = claimed_selector_fault(entry.entry.selector.predicates()) {
                return Err(RouteBuildError::InvalidPredicate {
                    op_name: entry.entry.op_name,
                    detail: why.to_owned(),
                });
            }
            owned.push((owner, entry));
        }
        owned.sort_by(|(a_owner, a), (b_owner, b)| {
            a_owner
                .cmp(b_owner)
                .then(a.entry.precedence.cmp(&b.entry.precedence))
                .then_with(|| a.entry.op_name.cmp(b.entry.op_name))
                .then_with(|| a.template.as_str().cmp(b.template.as_str()))
        });
        let mut constraints = Vec::with_capacity(owned.len());
        for (_, entry) in &owned {
            let normalised =
                Constraints::of(&entry.entry.selector).map_err(|contradiction| RouteBuildError::UnsatisfiableSelector {
                    op_name: entry.entry.op_name,
                    contradiction,
                })?;
            constraints.push(normalised);
        }
        let table = Self {
            claims: claims.into_boxed_slice(),
            entries: owned.into_boxed_slice(),
            forms: Box::default(),
        };
        // Declarations first, for the reason `RouteTable::build` gives: a rotted declaration is a
        // more specific diagnostic than the undeclared overlap it fails to cover.
        table.check_declarations(shadowing, &constraints)?;
        table.check_overlaps(shadowing, &constraints)?;
        Ok(table)
    }

    /// Whether a claim covers the request and, if so, which claimed row accepts it.
    ///
    /// Not `async`, holds nothing, allocates nothing. A form claim is asked first, on every host
    /// (ADR-0041). Otherwise a virtual-hosted request, a request on a face other than the standard
    /// endpoint, and a request with an ARN in the bucket position are never inside a claim.
    #[must_use]
    pub fn lookup(&self, request: &RouteRequestParts<'_>) -> ClaimLookup<'_> {
        if let Some(claim) = self.forms.iter().find(|form| form.claim.covers(request)) {
            return ClaimLookup::Form { claim };
        }
        if self.claims.is_empty()
            || request.host_named_bucket
            || request.host_class != HostClass::Standard
            || request.arn_form.is_some()
        {
            return ClaimLookup::Outside;
        }
        let Some((index, claim)) = self
            .claims
            .iter()
            .enumerate()
            .find(|(_, installed)| installed.claim.covers(request.path))
        else {
            return ClaimLookup::Outside;
        };
        let entry = self
            .entries
            .iter()
            .filter(|(owner, _)| *owner == index)
            .map(|(_, entry)| entry)
            .find(|entry| entry.template.matches(request.path) && entry.entry.selector.matches(request));
        ClaimLookup::Inside { claim, entry }
    }

    /// The same table with `forms` installed beside its path claims (ADR-0041).
    ///
    /// # Errors
    ///
    /// [`RouteBuildError::OverlappingFormClaims`] when two could cover one request, and
    /// [`RouteBuildError::FormClaimInsideClaim`] for one whose path an installed path claim covers.
    /// The grammar ([`super::FormClaim::rejection`]) is the dialect's to check: every claim here
    /// comes from an assembled dialect.
    pub fn with_forms(mut self, forms: Vec<InstalledFormClaim>) -> Result<Self, RouteBuildError> {
        for (index, form) in forms.iter().enumerate() {
            if let Some(installed) = self.claims.iter().find(|installed| installed.claim.covers(form.claim.path)) {
                return Err(RouteBuildError::FormClaimInsideClaim {
                    op_name: form.entry.op_name,
                    claim: installed.claim.prefix,
                });
            }
            if let Some(later) = forms
                .iter()
                .skip(index.saturating_add(1))
                .find(|later| later.claim.overlaps(&form.claim))
            {
                return Err(RouteBuildError::OverlappingFormClaims {
                    first: form.entry.op_name,
                    second: later.entry.op_name,
                });
            }
        }
        self.forms = forms.into_boxed_slice();
        Ok(self)
    }

    /// Every installed path claim, in installation order.
    #[must_use]
    pub fn claims(&self) -> &[InstalledClaim] {
        &self.claims
    }

    /// Every installed form claim, in installation order.
    #[must_use]
    pub fn forms(&self) -> &[InstalledFormClaim] {
        &self.forms
    }

    /// Every claimed row, by claim and then precedence.
    pub fn entries(&self) -> impl Iterator<Item = &ClaimedEntry> {
        self.entries.iter().map(|(_, entry)| entry)
    }

    /// Whether no claim of either kind is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.forms.is_empty()
    }

    /// A request both rows accept, or `None` when no request does.
    fn overlap(&self, a: usize, b: usize, constraints: &[Constraints]) -> Result<Option<RequestShape>, RouteBuildError> {
        let (Some((a_owner, first)), Some((b_owner, second))) = (self.entries.get(a), self.entries.get(b)) else {
            return Ok(None);
        };
        if a_owner != b_owner {
            return Ok(None);
        }
        let Some(path) = first.template.overlap_path(&second.template) else {
            return Ok(None);
        };
        let (Some(mine), Some(theirs)) = (constraints.get(a), constraints.get(b)) else {
            return Ok(None);
        };
        let Some(meet) = mine.meet(theirs) else {
            return Ok(None);
        };
        let mut shape = meet.witness();
        shape.path = path;
        shape.target = TargetKind::Object;
        shape.host_class = HostClass::Standard;
        shape.arn_form = None;
        // Run through the ordinary matchers, as `lattice::overlap_witness` does: a witness only the
        // overlap decision believes in is a bug in this file, not an overlap.
        let agrees = shape.materialise().map(|materialised| {
            let parts = materialised.parts();
            first.template.matches(parts.path)
                && second.template.matches(parts.path)
                && first.entry.selector.matches(&parts)
                && second.entry.selector.matches(&parts)
        });
        match agrees {
            Some(true) => Ok(Some(shape)),
            Some(false) => Err(RouteBuildError::Inconsistent(OverlapError::Inconsistent {
                witness: Box::new(shape),
                reason: "the claim table reported an overlap the matcher does not agree with",
            })),
            None => Err(RouteBuildError::Inconsistent(OverlapError::Inconsistent {
                witness: Box::new(shape),
                reason: "the witness cannot be expressed as an acceptable request",
            })),
        }
    }

    /// Every pair of rows of two operations inside one claim, once.
    fn check_overlaps(&self, shadowing: &ShadowingDecls, constraints: &[Constraints]) -> Result<(), RouteBuildError> {
        for a in 0..self.entries.len() {
            for b in a.saturating_add(1)..self.entries.len() {
                let (Some((_, first)), Some((_, second))) = (self.entries.get(a), self.entries.get(b)) else {
                    continue;
                };
                if first.entry.op_name == second.entry.op_name {
                    continue;
                }
                let Some(witness) = self.overlap(a, b, constraints)? else {
                    continue;
                };
                if first.entry.precedence == second.entry.precedence {
                    return Err(RouteBuildError::Conflict {
                        precedence: first.entry.precedence,
                        a: first.report(),
                        b: second.report(),
                        witness: Box::new(witness),
                    });
                }
                // Sorted within a claim, so `first` is the winner.
                let total = second.template.refines(&first.template)
                    && constraints
                        .get(b)
                        .zip(constraints.get(a))
                        .is_some_and(|(theirs, mine)| theirs.refines(mine));
                let needs_declaration = match shadowing.policy() {
                    ShadowingPolicy::EveryOverlap => true,
                    ShadowingPolicy::TotalOnly => total,
                };
                if needs_declaration && shadowing.find(first.entry.op_name, second.entry.op_name).is_none() {
                    return Err(RouteBuildError::UndeclaredShadowing {
                        winner: first.report(),
                        shadowed: second.report(),
                        witness: Box::new(witness),
                        total,
                    });
                }
            }
        }
        Ok(())
    }

    /// Every declaration must describe an overlap between two claimed rows, in its direction.
    fn check_declarations(&self, shadowing: &ShadowingDecls, constraints: &[Constraints]) -> Result<(), RouteBuildError> {
        for decl in shadowing.iter() {
            if decl.evidence.is_empty() {
                return Err(RouteBuildError::UnsourcedShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                });
            }
            let rows_of = |name: &str| {
                self.entries
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, entry))| entry.entry.op_name == name)
                    .map(|(index, (_, entry))| (index, entry.entry.precedence))
                    .collect::<Vec<_>>()
            };
            let (winners, shadowed) = (rows_of(decl.winner), rows_of(decl.shadowed));
            let (Some((_, winner_precedence)), Some((_, shadowed_precedence))) = (winners.first(), shadowed.first()) else {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "one of the two operations has no claimed row",
                });
            };
            if winner_precedence >= shadowed_precedence {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "the declared winner does not have the lower precedence",
                });
            }
            let mut overlapping = false;
            let mut total = false;
            for (winner, _) in &winners {
                for (hidden, _) in &shadowed {
                    if self.overlap(*winner, *hidden, constraints)?.is_some() {
                        overlapping = true;
                        let (Some((_, winner_entry)), Some((_, hidden_entry))) =
                            (self.entries.get(*winner), self.entries.get(*hidden))
                        else {
                            continue;
                        };
                        total |= hidden_entry.template.refines(&winner_entry.template)
                            && constraints
                                .get(*hidden)
                                .zip(constraints.get(*winner))
                                .is_some_and(|(theirs, mine)| theirs.refines(mine));
                    }
                }
            }
            if !overlapping {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "the two claimed rows do not overlap, so nothing is being shadowed",
                });
            }
            if shadowing.policy() == ShadowingPolicy::TotalOnly && !total {
                return Err(RouteBuildError::StaleShadowing {
                    winner: decl.winner,
                    shadowed: decl.shadowed,
                    why: "the overlap is partial, and the policy in force only asks about unreachable routes",
                });
            }
        }
        Ok(())
    }
}

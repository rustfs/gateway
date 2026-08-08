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
//!   overlay.rs  the reviewed record: name, precedence, selector, spec, evidence
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

mod overlay;

use std::collections::BTreeSet;
use std::fmt;

pub use self::overlay::{DialectOverlay, OverlayRow, RESERVED_HOST_CLASSES, vendor_of};

use crate::op::{Operation, ResourceShape};
use crate::registry::{RegistryError, reject};
use crate::route::{HostClass, Predicate, RouteEntry, RouteSelector, ShadowingDecl, render_selector};

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

/// Why a dialect could not be assembled. Every variant is a start-up failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialectError {
    /// The operation failed one of the rules every registration passes.
    ///
    /// Reached from here as well as from [`crate::registry::Registry::register_handler`], so that a
    /// dialect is refused at assembly rather than at the registration a deployment might not have
    /// written yet. The rule set is `crate::registry::reject`'s and is not duplicated.
    Registration(RegistryError),
    /// The dialect's own vendor segment is not a lowercase ASCII token.
    MalformedVendor {
        /// The dialect name.
        dialect: &'static str,
        /// The segment as declared.
        vendor: &'static str,
    },
    /// An operation whose namespace is not this dialect's vendor.
    WrongVendor {
        /// The operation.
        name: &'static str,
        /// The segment this dialect's operations must carry.
        vendor: &'static str,
    },
    /// An operation declared in code with no row in the overlay.
    NotInOverlay {
        /// The operation.
        name: &'static str,
    },
    /// A row in the overlay that no code declares.
    DeclaredNowhere {
        /// The operation the row names.
        name: &'static str,
    },
    /// One operation declared twice in one dialect.
    DeclaredTwice {
        /// The operation.
        name: &'static str,
    },
    /// The declared precedence and the recorded one disagree.
    PrecedenceMismatch {
        /// The operation.
        name: &'static str,
        /// What the code says.
        declared: u16,
        /// What the overlay records.
        overlay: u16,
    },
    /// The declared selector and the recorded one disagree.
    SelectorMismatch {
        /// The operation.
        name: &'static str,
        /// The rendered conjunction the code declares.
        declared: String,
        /// The conjunction the overlay records.
        overlay: &'static str,
    },
    /// The declared action and the recorded one disagree.
    ActionMismatch {
        /// The operation.
        name: &'static str,
        /// What the spec says.
        declared: &'static str,
        /// What the overlay records.
        overlay: &'static str,
    },
    /// The declared resource shape and the recorded one disagree.
    ResourceMismatch {
        /// The operation.
        name: &'static str,
        /// What the spec says.
        declared: ResourceShape,
        /// What the overlay records.
        overlay: ResourceShape,
    },
    /// The declared success status and the recorded one disagree.
    StatusMismatch {
        /// The operation.
        name: &'static str,
        /// What the spec says.
        declared: u16,
        /// What the overlay records.
        overlay: u16,
    },
    /// An overlay row with no evidence.
    UnsourcedOperation {
        /// The operation.
        name: &'static str,
    },
    /// The operation's floor admits anonymous requests and the overlay does not say so.
    AnonymousNotAcknowledged {
        /// The operation.
        name: &'static str,
    },
    /// The overlay says the operation is anonymously reachable and its floor no longer admits that.
    StaleAnonymousAcknowledgement {
        /// The operation.
        name: &'static str,
    },
    /// A shadowing declaration about two operations this dialect does not own.
    ///
    /// A dialect accounts for the overlaps *its own* row creates, in either direction — its row in
    /// front of a standard one, or behind it. A declaration naming two operations it did not add is
    /// a dialect signing off on a routing decision in somebody else's table: today every standard
    /// pair is already declared, so it would be duplication, and the moment a model upgrade
    /// introduces a new standard pair it would be a dialect quietly approving a routing change the
    /// reviewers of the generated table never saw.
    ForeignShadowing {
        /// The dialect that carried it.
        dialect: &'static str,
        /// The declared winner.
        winner: &'static str,
        /// The declared shadowed operation.
        shadowed: &'static str,
    },
    /// A selector with no predicates: it would accept every request that reached its precedence.
    EmptySelector {
        /// The operation.
        name: &'static str,
    },
    /// The selector pins an endpoint family reserved for the operations AWS defines on it.
    ReservedHostClass {
        /// The operation.
        name: &'static str,
        /// The face it claimed.
        class: HostClass,
    },
}

impl DialectError {
    /// The operation the refusal is about, when it is about one.
    #[must_use]
    pub const fn operation(&self) -> Option<&'static str> {
        match self {
            Self::Registration(error) => Some(error.operation()),
            Self::MalformedVendor { .. } => None,
            Self::WrongVendor { name, .. }
            | Self::NotInOverlay { name }
            | Self::DeclaredNowhere { name }
            | Self::DeclaredTwice { name }
            | Self::PrecedenceMismatch { name, .. }
            | Self::SelectorMismatch { name, .. }
            | Self::ActionMismatch { name, .. }
            | Self::ResourceMismatch { name, .. }
            | Self::StatusMismatch { name, .. }
            | Self::UnsourcedOperation { name }
            | Self::AnonymousNotAcknowledged { name }
            | Self::StaleAnonymousAcknowledgement { name }
            | Self::EmptySelector { name }
            | Self::ReservedHostClass { name, .. } => Some(name),
            Self::ForeignShadowing { .. } => None,
        }
    }
}

impl fmt::Display for DialectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(error) => write!(f, "{error}"),
            Self::MalformedVendor { dialect, vendor } => write!(
                f,
                "the dialect {dialect} declares the vendor segment {vendor:?}, which is not a \
                 lowercase ASCII token"
            ),
            Self::WrongVendor { name, vendor } => write!(
                f,
                "{name} is not in the {vendor:?} namespace; a dialect may only add operations under \
                 its own vendor segment, or nobody can tell from a name which dialect added it"
            ),
            Self::NotInOverlay { name } => write!(
                f,
                "{name} is declared in code and has no row in the dialect overlay; the row is where \
                 the precedence and the evidence are reviewed"
            ),
            Self::DeclaredNowhere { name } => write!(
                f,
                "the dialect overlay has a row for {name} and no code declares it; a row nothing \
                 declares reads as a reviewed decision about behaviour that does not exist"
            ),
            Self::DeclaredTwice { name } => write!(f, "{name} is declared twice by one dialect"),
            Self::PrecedenceMismatch { name, declared, overlay } => {
                write!(f, "{name} is declared at precedence {declared} and the overlay records {overlay}")
            }
            Self::SelectorMismatch { name, declared, overlay } => {
                write!(f, "{name} is declared as `{declared}` and the overlay records `{overlay}`")
            }
            Self::ActionMismatch { name, declared, overlay } => {
                write!(f, "{name} is authorised against {declared:?} and the overlay records {overlay:?}")
            }
            Self::ResourceMismatch { name, declared, overlay } => {
                write!(f, "{name} names a {declared:?} resource and the overlay records {overlay:?}")
            }
            Self::StatusMismatch { name, declared, overlay } => {
                write!(f, "{name} succeeds with {declared} and the overlay records {overlay}")
            }
            Self::UnsourcedOperation { name } => write!(
                f,
                "the dialect overlay row for {name} carries no evidence; a wire shape nobody sourced \
                 is a guess with a comment"
            ),
            Self::AnonymousNotAcknowledged { name } => write!(
                f,
                "{name} has a security floor that admits anonymous requests and its overlay row does \
                 not acknowledge it; an anonymous operation a reviewer cannot see is how an attacker \
                 picks the authentication strength by picking the operation"
            ),
            Self::StaleAnonymousAcknowledgement { name } => write!(
                f,
                "the dialect overlay row for {name} says it is anonymously reachable and its security \
                 floor does not admit anonymous requests"
            ),
            Self::ForeignShadowing {
                dialect,
                winner,
                shadowed,
            } => write!(
                f,
                "the dialect {dialect} declares that {winner} shadows {shadowed}, and it added \
                 neither; a dialect accounts for the overlaps its own rows create and for no others"
            ),
            Self::EmptySelector { name } => write!(
                f,
                "{name} has an empty selector, which accepts every request that reaches its \
                 precedence; a vendor operation has to say what it is about"
            ),
            Self::ReservedHostClass { name, class } => write!(
                f,
                "{name} pins the reserved endpoint family {}; that face carries constraints written \
                 for the operations AWS defines on it, and an added row would inherit the face \
                 without the checks",
                class.as_str()
            ),
        }
    }
}

impl std::error::Error for DialectError {}

impl From<RegistryError> for DialectError {
    fn from(error: RegistryError) -> Self {
        Self::Registration(error)
    }
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
}

impl Dialect {
    /// Begins assembling the dialect this overlay describes.
    #[must_use]
    pub fn assemble(overlay: &'static DialectOverlay) -> DialectBuilder {
        let mut errors = Vec::new();
        if !overlay.vendor_is_well_formed() {
            errors.push(DialectError::MalformedVendor {
                dialect: overlay.name,
                vendor: overlay.vendor,
            });
        }
        DialectBuilder {
            overlay,
            operations: Vec::new(),
            attempted: BTreeSet::new(),
            errors,
        }
    }

    /// The dialect's name, as a start-up report prints it.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The operations it contributes, in declaration order.
    #[must_use]
    pub fn operations(&self) -> &[DialectOperation] {
        &self.operations
    }

    /// Their names, in declaration order. For a start-up report and for assertions.
    pub fn operation_names(&self) -> impl Iterator<Item = &'static str> {
        self.operations.iter().map(DialectOperation::name)
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
        if self.operations.iter().any(|declared| declared.name == name) {
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

        let Some(row) = self.overlay.row(name) else {
            self.errors.push(DialectError::NotInOverlay { name });
            return;
        };
        if row.evidence.is_empty() {
            self.errors.push(DialectError::UnsourcedOperation { name });
            return;
        }
        if row.precedence != route.precedence {
            self.errors.push(DialectError::PrecedenceMismatch {
                name,
                declared: route.precedence,
                overlay: row.precedence,
            });
            return;
        }
        let declared_selector = render_selector(&RouteSelector::new(route.selector));
        if declared_selector != row.selector {
            self.errors.push(DialectError::SelectorMismatch {
                name,
                declared: declared_selector,
                overlay: row.selector,
            });
            return;
        }

        let spec = O::spec();
        if spec.success_status != row.success_status {
            self.errors.push(DialectError::StatusMismatch {
                name,
                declared: spec.success_status,
                overlay: row.success_status,
            });
            return;
        }
        // `check_operation` has already refused a spec with no action, so this is not the missing
        // case; it is the case where the row and a present action disagree.
        if let Some(auth) = spec.auth {
            if auth.action != row.action {
                self.errors.push(DialectError::ActionMismatch {
                    name,
                    declared: auth.action,
                    overlay: row.action,
                });
                return;
            }
            if auth.resource != row.resource {
                self.errors.push(DialectError::ResourceMismatch {
                    name,
                    declared: auth.resource,
                    overlay: row.resource,
                });
                return;
            }
        }

        match (O::floor().allows_anonymous(), row.anonymous) {
            (true, false) => self.errors.push(DialectError::AnonymousNotAcknowledged { name }),
            (false, true) => self.errors.push(DialectError::StaleAnonymousAcknowledgement { name }),
            (true, true) | (false, false) => {}
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
        // Checked here rather than in `declare`, because a dialect's second operation is a
        // legitimate party to the first one's declaration and is not known yet at that point.
        let mine: BTreeSet<&'static str> = self.operations.iter().map(|operation| operation.name).collect();
        for operation in &self.operations {
            for decl in operation.shadows {
                if !mine.contains(decl.winner) && !mine.contains(decl.shadowed) {
                    self.errors.push(DialectError::ForeignShadowing {
                        dialect: self.overlay.name,
                        winner: decl.winner,
                        shadowed: decl.shadowed,
                    });
                }
            }
        }
        if self.errors.is_empty() {
            Ok(Dialect {
                name: self.overlay.name,
                operations: self.operations,
            })
        } else {
            Err(self.errors)
        }
    }
}

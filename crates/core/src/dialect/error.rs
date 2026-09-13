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

//! Every reason a dialect is refused, as one enum.
//!
//! Responsible for: [`DialectError`], its operation accessor and its rendering.
//! NOT responsible for: deciding any refusal; `super` (the overlay cross-check) and
//! `super::claimed` (claimed routes) push these.
//! Upstream: `crate::registry::RegistryError`, `crate::route`'s claim and template rejections.
//! Downstream: `super`, `super::claimed`, and every caller of `DialectBuilder::build`.

use std::fmt;

use crate::op::ResourceShape;
use crate::registry::RegistryError;
use crate::route::{ClaimRejection, HostClass, TemplateRejection};

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
        /// What the spec says, rendered by `AuthRequirement::render`.
        declared: String,
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
    /// A path-prefix claim the claim rules refuse (ADR-0024); among them, a claim shallower than two
    /// segments, which would take a whole bucket away from S3.
    RefusedClaim {
        /// The dialect name.
        dialect: &'static str,
        /// The prefix as written.
        prefix: &'static str,
        /// The rule it breaks.
        rejection: ClaimRejection,
    },
    /// Two claims of one dialect could cover one path.
    OverlappingClaims {
        /// The dialect name.
        dialect: &'static str,
        /// The first prefix.
        first: &'static str,
        /// The second prefix.
        second: &'static str,
    },
    /// A claim no claimed row is inside: it would take its namespace away from S3 to answer
    /// nothing.
    UnusedClaim {
        /// The dialect name.
        dialect: &'static str,
        /// The prefix.
        prefix: &'static str,
    },
    /// A claimed route with no row.
    EmptyClaimedRoute {
        /// The operation.
        name: &'static str,
    },
    /// A claimed row whose template the template grammar refuses.
    MalformedTemplate {
        /// The operation.
        name: &'static str,
        /// The template as written.
        template: &'static str,
        /// The rule it breaks.
        rejection: TemplateRejection,
    },
    /// A claimed row outside every claim of its own dialect.
    TemplateOutsideClaims {
        /// The operation.
        name: &'static str,
        /// The template as written.
        template: &'static str,
    },
    /// A claimed row whose selector restates what the claim decides, or names other than one
    /// method.
    ClaimedRowSelector {
        /// The operation.
        name: &'static str,
        /// The row's template.
        template: &'static str,
        /// Why.
        why: &'static str,
    },
    /// The same claimed row twice in one route.
    DuplicateClaimedRow {
        /// The operation.
        name: &'static str,
        /// The row's template.
        template: &'static str,
    },
    /// A claimed operation declaring a bucket or object resource: inside a claim the path names
    /// neither, so the authorizer would be asked about a resource nothing supplies.
    ClaimedOperationNamesAResource {
        /// The operation.
        name: &'static str,
        /// What it declares.
        resource: ResourceShape,
    },
    /// A claimed route whose bound bucket parameter cannot supply the bucket (ADR-0025): a row's
    /// template lacks it, or the operation is not authorised on a bucket.
    ClaimedBucketParam {
        /// The operation.
        name: &'static str,
        /// The parameter as declared.
        param: &'static str,
        /// Why.
        why: &'static str,
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
            | Self::ReservedHostClass { name, .. }
            | Self::EmptyClaimedRoute { name }
            | Self::MalformedTemplate { name, .. }
            | Self::TemplateOutsideClaims { name, .. }
            | Self::ClaimedRowSelector { name, .. }
            | Self::DuplicateClaimedRow { name, .. }
            | Self::ClaimedOperationNamesAResource { name, .. }
            | Self::ClaimedBucketParam { name, .. } => Some(name),
            Self::ForeignShadowing { .. }
            | Self::RefusedClaim { .. }
            | Self::OverlappingClaims { .. }
            | Self::UnusedClaim { .. } => None,
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
            Self::RefusedClaim {
                dialect,
                prefix,
                rejection,
            } => write!(f, "the dialect {dialect} claims {prefix:?}, which is refused: {rejection}"),
            Self::OverlappingClaims { dialect, first, second } => write!(
                f,
                "the dialect {dialect} claims both {first:?} and {second:?}, which could cover one path"
            ),
            Self::UnusedClaim { dialect, prefix } => write!(
                f,
                "the dialect {dialect} claims {prefix:?} and serves no row inside it; the claim would take the \
                 namespace away from S3 to answer nothing"
            ),
            Self::EmptyClaimedRoute { name } => write!(f, "{name} is declared as a claimed route with no row"),
            Self::MalformedTemplate {
                name,
                template,
                rejection,
            } => write!(f, "{name} has the claimed row {template:?}, which is refused: {rejection}"),
            Self::TemplateOutsideClaims { name, template } => write!(
                f,
                "{name} has the claimed row {template:?}, which starts with none of its dialect's claims"
            ),
            Self::ClaimedRowSelector { name, template, why } => {
                write!(f, "{name} has the claimed row {template:?}, whose selector is refused: {why}")
            }
            Self::DuplicateClaimedRow { name, template } => {
                write!(f, "{name} declares the claimed row {template:?} twice")
            }
            Self::ClaimedOperationNamesAResource { name, resource } => write!(
                f,
                "{name} is served inside a claim and declares a {resource:?} resource; inside a claim the path \
                 names no bucket or key, so a claimed operation is service-level unless a template \
                 parameter is bound as its bucket"
            ),
            Self::ClaimedBucketParam { name, param, why } => {
                write!(f, "{name} binds the template parameter {param:?} as its bucket, which is refused: {why}")
            }
        }
    }
}

impl std::error::Error for DialectError {}

impl From<RegistryError> for DialectError {
    fn from(error: RegistryError) -> Self {
        Self::Registration(error)
    }
}

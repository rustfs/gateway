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

//! What an operation is, as a type: its name, its origin, its input and output, its authorisation.
//!
//! Responsible for: [`Operation`] — the trait one type per S3 operation implements —
//! [`OperationOrigin`] and the sealed [`StandardOperation`] token that decides whether a name may
//! be an AWS one, [`AuthRequirement`], and [`HasOperation`], the reverse mapping from an input type
//! back to its operation.
//! NOT responsible for: implementing any handler (`crate::handler`), storing registrations
//! (`crate::registry`), routing (`crate::route`), or encoding and decoding, which arrive with the
//! generated codecs and are not part of this trait yet.
//! Upstream: `crate::registry`'s [`crate::registry::OperationSpec`], `crate::route`'s generated
//! table, `rustfs-gateway-sig`'s `OperationFloor`. Downstream: `crate::handler`,
//! `crate::registry::RouterBuilder`, and every operation module under `crate::ops`.
//!
//! # Why the operation is a type and not an enum variant
//!
//! The whole point of dispatching per operation is that `Handler<GetObject>` and
//! `Handler<PutObject>` are different obligations a backend can satisfy separately. That needs one
//! type per operation, carrying its input and output as associated types, so a handler signature
//! cannot name the wrong pair.
//!
//! # Why the standard-name set has no second source
//!
//! [`standard_operation_names`] is derived from the generated route table: an operation AWS defines
//! has a route row, and there is nowhere else for the set to come from. A hand-written list beside
//! the table is the classic drift: the table gains an operation, the list does not, and a third
//! party is allowed to register itself under the new AWS name.
//!
//! # Why a third party cannot claim to be standard
//!
//! [`OperationOrigin::Standard`] carries a [`StandardOperation`] token whose only field is private,
//! so it can be constructed in this crate and nowhere else. A downstream crate can write
//! `impl Operation for MyOp`, but it cannot write `const ORIGIN: OperationOrigin =
//! OperationOrigin::Standard(..)`, because it cannot produce the token. The registry then holds it
//! to the namespaced-name rule.

use rustfs_gateway_sig::OperationFloor;

use crate::authz::{ActionRule, DerivedResourceError, DerivedResourceSet, SubjectRule, WhenAbsent};
use crate::registry::OperationSpec;
use crate::route::ROUTES;

/// Proof that an operation is one of the AWS-defined operations this crate ships.
///
/// The field is private, so the token can only be produced inside `rustfs-gateway-core`. That is
/// the whole mechanism: a downstream crate cannot declare itself standard, so
/// `crate::registry` can refuse a third-party operation that borrows an AWS name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StandardOperation(());

impl StandardOperation {
    /// The token, obtainable only from inside this crate.
    pub(crate) const TOKEN: Self = Self(());
}

/// Who defined an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperationOrigin {
    /// An AWS-defined operation, shipped by this crate. Its name is in the generated route table.
    Standard(StandardOperation),
    /// An operation defined outside this crate: an admin API, an STS call, a vendor dialect.
    ///
    /// Its name must be namespaced (`vendor:Name`), and it may not collide with an AWS name.
    ThirdParty,
}

impl OperationOrigin {
    /// Whether this is an AWS-defined operation.
    #[must_use]
    pub const fn is_standard(&self) -> bool {
        matches!(self, Self::Standard(_))
    }
}

/// What kind of resource an operation's action is about.
///
/// Mirrors [`crate::route::TargetKind`] rather than reusing it: the target is what the *path*
/// addresses, this is what the *policy* is written against, and the two are allowed to differ —
/// `ListObjectsV2` addresses a bucket and is authorised against the bucket, while `PutObject`
/// addresses an object and is authorised against the object and its bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceShape {
    /// The service itself: `ListBuckets`.
    Service,
    /// A bucket: `arn:aws:s3:::bucket`.
    Bucket,
    /// An object inside a bucket: `arn:aws:s3:::bucket/key`.
    Object,
}

/// The action an operation is authorised against, and the resource that action names.
///
/// An operation without one cannot be expressed in the authorisation model at all, which is the
/// structural form of rustfs/rustfs#4845: a custom route that never reached `authorize_request`
/// because nothing said what permission it needed. So this is not `Option` because the field is
/// optional in spirit — it is `Option` on [`OperationSpec`] precisely so that registration can
/// refuse the `None`.
///
/// P4-05 owns the full authorisation shape (condition keys, two-stage resources for copy, derived
/// resources). This is the minimum the registry needs to refuse an operation nobody can authorise.
///
/// ADR-0025 adds two private facts, set only through the constructors below: how several actions
/// combine ([`ActionRule`]), and whose account the operation acts on ([`SubjectRule`]). They are
/// private so a requirement cannot be written as a literal that skips them:
///
/// ```compile_fail
/// use rustfs_gateway_core::{AuthRequirement, ResourceShape};
/// let literal = AuthRequirement { action: "admin:A", resource: ResourceShape::Service };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthRequirement {
    /// The IAM action, in its wire spelling: `s3:GetObject`. For an any-of or all-of rule, the
    /// first of its actions.
    pub action: &'static str,
    /// What the action is about.
    pub resource: ResourceShape,
    rule: ActionRule,
    subject: Option<SubjectRule>,
}

impl AuthRequirement {
    /// An action and the resource shape it names.
    #[must_use]
    pub const fn new(action: &'static str, resource: ResourceShape) -> Self {
        Self {
            action,
            resource,
            rule: ActionRule::One,
            subject: None,
        }
    }

    /// Allowed when at least one of `actions` is: RustFS's `evaluate_admin_actions`. Registration
    /// refuses fewer than two actions and a repeated one.
    #[must_use]
    pub const fn any_of(actions: &'static [&'static str], resource: ResourceShape) -> Self {
        Self {
            action: first_action(actions),
            resource,
            rule: ActionRule::AnyOf(actions),
            subject: None,
        }
    }

    /// Allowed only when every one of `actions` is. Registration refuses fewer than two actions
    /// and a repeated one.
    #[must_use]
    pub const fn all_of(actions: &'static [&'static str], resource: ResourceShape) -> Self {
        Self {
            action: first_action(actions),
            resource,
            rule: ActionRule::AllOf(actions),
            subject: None,
        }
    }

    /// This requirement, about the account `subject` names. The facade extracts the subject before
    /// authentication and hands it to both authorizer stages and to the handler (ADR-0025).
    #[must_use]
    pub const fn about_subject(mut self, subject: SubjectRule) -> Self {
        self.subject = Some(subject);
        self
    }

    /// How the actions combine.
    #[must_use]
    pub const fn rule(&self) -> ActionRule {
        self.rule
    }

    /// Whose account the operation acts on, when that is part of its authorisation.
    #[must_use]
    pub const fn subject(&self) -> Option<SubjectRule> {
        self.subject
    }

    /// Every action the facade asks about, in declaration order.
    #[must_use]
    pub fn actions(&self) -> &[&'static str] {
        match self.rule {
            ActionRule::One => core::slice::from_ref(&self.action),
            ActionRule::AllOf(actions) | ActionRule::AnyOf(actions) => actions,
        }
    }

    /// Whether every action is spelled `service:Action` with both halves non-empty.
    ///
    /// Checked at registration rather than here: a `const fn` that could fail would either panic in
    /// a const context or return a `Result` every declaration has to unwrap, and both are worse
    /// than one check in the one place registration happens.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.actions().iter().all(|action| is_well_formed_action(action))
    }

    /// Why the rule itself cannot be registered, or `None`. The spelling of each action is
    /// [`Self::is_well_formed`]'s.
    #[must_use]
    pub fn fault(&self) -> Option<&'static str> {
        if let ActionRule::AllOf(actions) | ActionRule::AnyOf(actions) = self.rule {
            if actions.len() < 2 {
                return Some("an any-of or all-of rule names at least two actions; one action is `AuthRequirement::new`");
            }
            if actions
                .iter()
                .enumerate()
                .any(|(index, action)| actions.iter().take(index).any(|earlier| earlier == action))
            {
                return Some("an any-of or all-of rule names each action once");
            }
        }
        match self.subject {
            Some(SubjectRule::Caller) if self.rule != ActionRule::One => {
                Some("an own-account operation names exactly one action")
            }
            Some(SubjectRule::Caller) if self.resource != ResourceShape::Service => {
                Some("an own-account operation is about the caller, not a bucket or an object")
            }
            Some(subject) => subject.fault(),
            None => None,
        }
    }

    /// The requirement as an overlay records it: the action alone for one action, and otherwise
    /// the rule and the subject spelled out, so a reviewer reads every action that decides.
    #[must_use]
    pub fn render(&self) -> String {
        let mut rendered = match self.rule {
            ActionRule::One => self.action.to_owned(),
            ActionRule::AllOf(actions) => format!("allOf({})", actions.join(", ")),
            ActionRule::AnyOf(actions) => format!("anyOf({})", actions.join(", ")),
        };
        match self.subject {
            Some(SubjectRule::Caller) => rendered.push_str(" about caller"),
            Some(SubjectRule::Query { param, when_absent }) => {
                let absent = match when_absent {
                    WhenAbsent::Caller => "caller",
                    WhenAbsent::Refuse => "refused",
                };
                rendered.push_str(&format!(" about query({param}, absent={absent})"));
            }
            None => {}
        }
        rendered
    }
}

/// The first action, or the empty (and so refused) action for an empty set.
const fn first_action(actions: &'static [&'static str]) -> &'static str {
    match actions {
        [first, ..] => first,
        [] => "",
    }
}

fn is_well_formed_action(action: &str) -> bool {
    match action.split_once(':') {
        Some((service, name)) => {
            !service.is_empty() && !name.is_empty() && !name.contains(':') && !action.contains(char::is_whitespace)
        }
        None => false,
    }
}

/// One S3 operation, as a type.
///
/// One of the two traits in this workspace allowed to use RPITIT (`impl Future` in return
/// position); see ADR-0002. Neither this trait nor [`crate::handler::Handler`] is ever reached
/// through `dyn`, because registration erases both behind a closure.
///
/// # Implementing one
///
/// Standard operations are implemented here, one per file under `crate::ops`. A third party
/// implements this for its own marker type, with a namespaced [`Operation::NAME`] and the default
/// [`OperationOrigin::ThirdParty`] origin.
pub trait Operation: Send + Sync + 'static {
    /// The operation name. For an AWS operation, the official name; otherwise `vendor:Name`.
    const NAME: &'static str;

    /// Who defined it. Defaults to a third party, which is the answer that is never a mistake:
    /// only this crate can produce the token the other answer needs.
    const ORIGIN: OperationOrigin = OperationOrigin::ThirdParty;

    /// The decoded request.
    type Input: Send + 'static;

    /// The response before it is encoded.
    type Output: Send + 'static;

    /// Resources found only after the typed input has been decoded.
    ///
    /// There is deliberately no default. Operations without any write
    /// `type DerivedResources = NoDerived` and return the ZST explicitly.
    type DerivedResources: DerivedResourceSet;

    /// Extracts every resource that requires the second authorization stage.
    fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError>;

    /// Removes any raw representation whose normalized resource now lives in
    /// [`Self::DerivedResources`].
    ///
    /// Copy operations clear `x-amz-copy-source` here, so a handler cannot parse a second value
    /// after policy approved the first. Operations whose typed input is already the canonical
    /// resource representation implement this as an explicit no-op.
    fn seal_derived_input(input: &mut Self::Input);

    /// What this operation requires of a request once routing has chosen it.
    ///
    /// Must carry [`OperationSpec::name`] equal to [`Operation::NAME`]; registration refuses the
    /// pair when they disagree, because two names for one operation is how a required parameter
    /// ends up checked against the wrong spec.
    fn spec() -> &'static OperationSpec;

    /// What this operation tells the security floor about itself.
    ///
    /// The floor is what makes admin, STS and dialect operations travel the same authentication
    /// path as `GetObject`: an operation that never declared a floor never reaches registration.
    fn floor() -> &'static OperationFloor;
}

/// The reverse mapping: from an input type back to the operation it belongs to.
///
/// This exists for the migration. It lets a compatibility layer define
/// `type S3Request<I> = Req<<I as HasOperation>::Op>`, so that thousands of existing
/// `fn get_object(&self, req: S3Request<GetObjectInput>)` signatures keep compiling with no edit
/// at the call site. Landing it late means every one of those signatures has to change twice.
pub trait HasOperation: Sized {
    /// The operation whose input this type is.
    type Op: Operation<Input = Self>;
}

/// Every AWS operation name this build knows, sorted and deduplicated.
///
/// Derived from the generated route table, which is the only place the set exists. Allocates, so
/// it belongs at build time — the per-request path never calls it.
#[must_use]
pub fn standard_operation_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ROUTES.iter().map(|row| row.operation).collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Every AWS operation for which this build generated a handler registration surface.
///
/// Route-only rows remain in [`standard_operation_names`] so a third party cannot claim an AWS
/// name, but they are absent here because no truthful input/output type or codec exists to handle.
pub(crate) fn standard_handler_operation_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ROUTES
        .iter()
        .filter(|row| row.handler_registration)
        .map(|row| row.operation)
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Whether a name is one of the AWS operation names in the generated route table.
#[must_use]
pub fn is_standard_operation_name(name: &str) -> bool {
    ROUTES.iter().any(|row| row.operation == name)
}

/// The AWS operation name a candidate collides with when ASCII case is ignored.
///
/// Case-insensitive on purpose: `getobject` is not the AWS name, but a registry that accepted it
/// would leave two entries a human reads as one, and the interesting question about a third party
/// that registers `getobject` is not whether it typed the case correctly.
#[must_use]
pub fn standard_operation_name_ignoring_case(name: &str) -> Option<&'static str> {
    ROUTES
        .iter()
        .map(|row| row.operation)
        .find(|candidate| candidate.eq_ignore_ascii_case(name))
}

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

//! What registration refuses, and why each refusal is a security decision rather than tidiness.
//!
//! Responsible for: [`RegistryError`] and [`check_operation`] — the rules an operation passes
//! before it can be registered at all.
//! NOT responsible for: route overlap (that is `crate::route`'s build-time decision, reached
//! through [`super::RouterBuilder::build`]), calling a handler, or anything per request.
//! Upstream: `crate::op`, `crate::error`. Downstream: [`super::Registry`],
//! [`super::RouterBuilder`].
//!
//! # The rule that matters most
//!
//! [`RegistryError::MissingAuthRequirement`] is the structural form of rustfs/rustfs#4845. There,
//! custom routes (admin, console, STS) were mounted beside the S3 surface and the authorisation
//! check simply was not on their path — each one had to remember to call it, and one did not.
//! An operation that cannot say which action authorises it cannot be registered here, so there is
//! no path on which the question can be skipped: not for admin operations, not for dialect
//! operations, not for anything a third party adds later.
//!
//! # The namespace rules
//!
//! A third party names its operations `vendor:Name`. The colon is not decoration: it makes
//! "is this operation AWS's?" answerable by looking at the name, which is what the route table,
//! the posture report and the audit log all end up doing. And a third party may not take an AWS
//! name at all, in either case spelling — otherwise a plugin can shadow `GetObject` by registering
//! first, and every later reader of the registry sees a name they will read as the AWS one.

use std::fmt;

use crate::authz::{ActionRule, SubjectRule};
use crate::error::{DisallowedPreAuthCode, PreAuthError};
use crate::op::{AuthRequirement, Operation, is_standard_operation_name, standard_operation_name_ignoring_case};
use crate::registry::OperationSpec;

/// Action namespaces an IAM policy is written in, which an own-account or anonymous operation's
/// label may not borrow.
const IAM_SERVICES: &[&str] = &["admin", "iam", "kms", "s3", "s3express", "sts"];

/// Why an operation could not be registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// Two registrations for one operation name.
    ///
    /// Never an overwrite: "the last registration wins" is how a plugin loaded later replaces the
    /// handler for an operation nobody expected it to touch.
    Duplicate {
        /// The name registered twice.
        name: &'static str,
    },
    /// A standard operation whose spec opts in to receiving the caller's secret (ADR-0024).
    ///
    /// No AWS operation needs the key to serve a request, so a standard spec that asks for it is a
    /// secret travelling to every handler of that operation for nothing.
    StandardOperationReceivesCallerSecret {
        /// The operation.
        name: &'static str,
    },
    /// A required parameter declares a code that cannot be raised before authentication.
    ///
    /// Checked once, here, so that the per-request path has no failure mode of its own.
    UnusableMissingError {
        /// The operation.
        name: &'static str,
        /// The parameter.
        param: &'static str,
        /// What is wrong with the code.
        source: DisallowedPreAuthCode,
    },
    /// The operation declares no action, so no authorisation decision can be made about it.
    MissingAuthRequirement {
        /// The operation.
        name: &'static str,
    },
    /// An operation has no handler-execution deadline class.
    MissingHandlerDeadlineClass {
        /// The operation.
        name: &'static str,
    },
    /// The operation declares an action that is not spelled `service:Action`.
    MalformedAuthAction {
        /// The operation.
        name: &'static str,
        /// The action as declared.
        action: &'static str,
    },
    /// The operation's action rule or subject rule cannot be authorised as declared (ADR-0025).
    InvalidAuthRule {
        /// The operation.
        name: &'static str,
        /// Why, as a constant.
        why: &'static str,
    },
    /// A third-party operation whose name is not `vendor:Name`.
    NameNotNamespaced {
        /// The name as declared.
        name: &'static str,
    },
    /// A third-party operation using an AWS operation name.
    NameCollidesWithStandard {
        /// The name as declared.
        name: &'static str,
        /// The AWS name it collides with, which may differ only in case.
        standard: &'static str,
    },
    /// An operation claiming to be AWS-defined under a name the route table does not have.
    ///
    /// Only reachable from inside this crate, since the token that claims standard origin cannot
    /// be constructed elsewhere. It fires when an operation module is added and its route row is
    /// not — the failure mode being a standard operation that nothing can route to.
    UnknownStandardOperation {
        /// The name as declared.
        name: &'static str,
    },
    /// [`Operation::NAME`] and the name in its spec disagree.
    SpecNameMismatch {
        /// The operation's own name.
        name: &'static str,
        /// The name its spec carries.
        spec: &'static str,
    },
    /// [`Operation::NAME`] and the name in its security floor disagree.
    ///
    /// The floor is what decides whether a presigned URL may reach this operation. A floor
    /// registered under another name is a floor that describes a different operation.
    FloorNameMismatch {
        /// The operation's own name.
        name: &'static str,
        /// The name its floor carries.
        floor: &'static str,
    },
}

impl RegistryError {
    /// The operation the refusal is about.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Duplicate { name }
            | Self::StandardOperationReceivesCallerSecret { name }
            | Self::UnusableMissingError { name, .. }
            | Self::MissingAuthRequirement { name }
            | Self::MissingHandlerDeadlineClass { name }
            | Self::MalformedAuthAction { name, .. }
            | Self::InvalidAuthRule { name, .. }
            | Self::NameNotNamespaced { name }
            | Self::NameCollidesWithStandard { name, .. }
            | Self::UnknownStandardOperation { name }
            | Self::SpecNameMismatch { name, .. }
            | Self::FloorNameMismatch { name, .. } => name,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { name } => write!(f, "{name} is registered twice"),
            Self::StandardOperationReceivesCallerSecret { name } => write!(
                f,
                "{name} is a standard operation and opts in to receiving the caller's secret; no AWS \
                 operation needs the key to serve a request"
            ),
            Self::UnusableMissingError { name, param, source } => {
                write!(f, "{name}: required parameter {param:?} declares an unusable code: {source}")
            }
            Self::MissingAuthRequirement { name } => write!(
                f,
                "{name} declares no authorisation action; an operation nobody can authorise is an \
                 operation whose authorisation check can be forgotten"
            ),
            Self::MissingHandlerDeadlineClass { name } => {
                write!(f, "{name} declares no handler deadline class")
            }
            Self::MalformedAuthAction { name, action } => {
                write!(f, "{name} declares the action {action:?}, which is not spelled `service:Action`")
            }
            Self::InvalidAuthRule { name, why } => write!(f, "{name}: {why}"),
            Self::NameNotNamespaced { name } => write!(
                f,
                "{name} is defined outside this crate and must be named `vendor:Name`, so that an \
                 AWS operation and a third-party one can be told apart by their names alone"
            ),
            Self::NameCollidesWithStandard { name, standard } => {
                write!(f, "{name} is defined outside this crate and collides with the AWS operation {standard}")
            }
            Self::UnknownStandardOperation { name } => write!(
                f,
                "{name} claims to be an AWS operation, but the generated route table has no row for \
                 it, so no request could ever reach it"
            ),
            Self::SpecNameMismatch { name, spec } => write!(f, "{name} carries a spec named {spec}"),
            Self::FloorNameMismatch { name, floor } => write!(f, "{name} carries a security floor named {floor}"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Every rule an operation passes before it may be registered.
///
/// # Errors
///
/// The first [`RegistryError`] the operation fails. Order is deliberate: identity first (the name
/// and the two places it is repeated), then the namespace rules, then authorisation, then the
/// per-parameter codes. A caller that fixes the first error and re-runs walks the list.
pub(crate) fn check_operation<O: Operation>() -> Result<(), RegistryError> {
    let name = O::NAME;
    let spec = O::spec();
    if spec.name != name {
        return Err(RegistryError::SpecNameMismatch { name, spec: spec.name });
    }
    let floor = O::floor().name();
    if floor != name {
        return Err(RegistryError::FloorNameMismatch { name, floor });
    }

    if O::ORIGIN.is_standard() {
        // First, so it holds for every standard-origin operation, whether or not the table has it.
        if spec.receives_caller_secret() {
            return Err(RegistryError::StandardOperationReceivesCallerSecret { name });
        }
        if spec
            .auth
            .is_some_and(|auth| auth.rule() != ActionRule::One || auth.subject().is_some())
        {
            return Err(RegistryError::InvalidAuthRule {
                name,
                why: "a standard operation is authorised by its one generated action, about no subject",
            });
        }
        if !is_standard_operation_name(name) {
            return Err(RegistryError::UnknownStandardOperation { name });
        }
    } else {
        if let Some(standard) = standard_operation_name_ignoring_case(name) {
            return Err(RegistryError::NameCollidesWithStandard { name, standard });
        }
        if !is_namespaced(name) {
            return Err(RegistryError::NameNotNamespaced { name });
        }
        check_spec(spec)?;
        return check_dialect_actions(spec, O::floor().allows_anonymous());
    }

    check_spec(spec)
}

/// Which namespace a dialect operation's actions may be in, by who can reach it.
///
/// | The operation | Its actions, the every-account action included |
/// |---|---|
/// | anonymous by its own floor's opt-in | its own vendor's labels only, and it is about no account |
/// | about the caller's own account | its own vendor's label only (checked in [`check_spec`]) |
/// | any other dialect operation | its own vendor's labels, or an IAM service's actions |
///
/// Everything else is refused. An anonymous request carries no identity for an IAM policy to be
/// evaluated against, so an `admin:` or `s3:` spelling there would read as a policy check that
/// never happens, and an authorizer that grants it to "everyone" would open an admin surface to
/// unauthenticated callers. Another vendor's label lets one dialect answer questions in a
/// namespace another dialect owns. Delegating anonymous admission at service level (ADR-0021) is
/// not an opt-in: it is the deployment's decision, and its authorizer decides those requests.
fn check_dialect_actions(spec: &'static OperationSpec, anonymous: bool) -> Result<(), RegistryError> {
    let name = spec.name;
    let Some(auth) = spec.auth else {
        return Err(RegistryError::MissingAuthRequirement { name });
    };
    let vendor = name.split_once(':').map(|(vendor, _)| vendor);
    let service = |action: &'static str| action.split_once(':').map(|(service, _)| service);
    let is_own_label = |action| service(action) == vendor && vendor.is_some_and(|vendor| !IAM_SERVICES.contains(&vendor));
    let mut actions = auth.actions().iter().copied().chain(auth.everyone_action());
    if anonymous {
        if auth.subject().is_some() {
            return Err(RegistryError::InvalidAuthRule {
                name,
                why: "an anonymous operation is about no account: an anonymous request has no caller, and nobody \
                      named in it can be authorised against one",
            });
        }
        if !actions.all(is_own_label) {
            return Err(RegistryError::InvalidAuthRule {
                name,
                why: "an anonymous operation's action is in the operation's own vendor namespace, never an IAM \
                      service's",
            });
        }
        return Ok(());
    }
    if !actions.all(|action| is_own_label(action) || service(action).is_some_and(|service| IAM_SERVICES.contains(&service))) {
        return Err(RegistryError::InvalidAuthRule {
            name,
            why: "a dialect operation's action is in its own vendor namespace or an IAM service's, never another \
                  vendor's",
        });
    }
    Ok(())
}

/// The rules that hold for a spec whoever declared it.
///
/// # Errors
///
/// [`RegistryError::MissingHandlerDeadlineClass`] when the operation cannot be bounded,
/// [`RegistryError::MissingAuthRequirement`] or [`RegistryError::MalformedAuthAction`] when it
/// cannot be authorised, and [`RegistryError::UnusableMissingError`] for a required parameter
/// whose code could not be raised before authentication.
pub(crate) fn check_spec(spec: &'static OperationSpec) -> Result<(), RegistryError> {
    let name = spec.name;
    if spec.deadline_class().is_none() {
        return Err(RegistryError::MissingHandlerDeadlineClass { name });
    }
    let Some(auth) = spec.auth else {
        return Err(RegistryError::MissingAuthRequirement { name });
    };
    if let Some(action) = auth
        .actions()
        .iter()
        .find(|action| !AuthRequirement::new(action, auth.resource).is_well_formed())
    {
        return Err(RegistryError::MalformedAuthAction { name, action });
    }
    if let Some(why) = auth.fault() {
        return Err(RegistryError::InvalidAuthRule { name, why });
    }
    // An own-account operation evaluates no IAM action in RustFS. Its action is therefore a label
    // in the operation's own vendor namespace, which no IAM policy grants or denies by accident,
    // and never `admin:` or `s3:` spelling that a reviewer would read as a policy check (ADR-0025).
    if auth.subject() == Some(SubjectRule::Caller) {
        let vendor = name.split_once(':').map(|(vendor, _)| vendor);
        let service = auth.action.split_once(':').map(|(service, _)| service);
        if vendor != service || service.is_some_and(|service| IAM_SERVICES.contains(&service)) {
            return Err(RegistryError::InvalidAuthRule {
                name,
                why: "an own-account operation's action is in the operation's own vendor namespace, never an IAM \
                      service's",
            });
        }
    }

    for param in spec.required_params {
        PreAuthError::with_code(param.missing_error.clone(), param.message).map_err(|source| {
            RegistryError::UnusableMissingError {
                name,
                param: param.name,
                source,
            }
        })?;
    }
    Ok(())
}

/// Whether a name is `vendor:Name` with both halves non-empty and exactly one colon.
fn is_namespaced(name: &str) -> bool {
    match name.split_once(':') {
        Some((vendor, operation)) => {
            !vendor.is_empty()
                && !operation.is_empty()
                && !operation.contains(':')
                && !name.contains(char::is_whitespace)
                && name.is_ascii()
        }
        None => false,
    }
}

#[cfg(test)]
#[path = "reject_rule_tests.rs"]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod rule_tests;

#[cfg(test)]
mod tests {
    use rustfs_gateway_sig::{OperationFloor, SigService};

    use super::{RegistryError, check_operation, is_namespaced};
    use crate::op::{AuthRequirement, Operation, OperationOrigin, ResourceShape, StandardOperation};
    use crate::registry::{HandlerDeadlineClass, OperationSpec};

    /// An operation claiming AWS origin under a name the route table does not have.
    ///
    /// It can only be written here: [`StandardOperation`]'s field is private, so no crate outside
    /// this one can produce the token this declaration needs. That is the point of the test as much
    /// as the refusal is — a third party cannot reach this state at all.
    ///
    /// The name is `WriteGetObjectResponse`, which the pinned model defines but the gateway excludes.
    /// It was `UpdateObjectEncryption` until that operation gained a row; the rule under test is
    /// unchanged, and the example simply has to be an operation that is still rowless — a property
    /// of the table, not of the check.
    struct NotInTheTable;

    static SPEC: OperationSpec = OperationSpec::builder("WriteGetObjectResponse", 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
        .build();

    static FLOOR: OperationFloor = OperationFloor::builtin("WriteGetObjectResponse", SigService::S3);

    impl Operation for NotInTheTable {
        const NAME: &'static str = "WriteGetObjectResponse";
        const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);
        type Input = ();
        type Output = ();
        type DerivedResources = crate::NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::DerivedResourceError> {
            Ok(crate::NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &SPEC
        }

        fn floor() -> &'static OperationFloor {
            &FLOOR
        }
    }

    /// Negative -- an AWS operation with no route row could never be reached, so it is refused.
    #[test]
    fn a_standard_operation_the_route_table_does_not_have_is_refused() {
        assert_eq!(
            check_operation::<NotInTheTable>(),
            Err(RegistryError::UnknownStandardOperation {
                name: "WriteGetObjectResponse"
            })
        );
    }

    /// [`NotInTheTable`] again, with a spec that opts in to the caller's secret, and without.
    ///
    /// The same rowless name, so the negative control fails for the other, already-pinned reason
    /// and the difference between the two answers is the opt-in alone.
    struct SecretHungry<const OPTED_IN: bool>;

    static SECRET_HUNGRY_SPEC: OperationSpec = OperationSpec::builder("WriteGetObjectResponse", 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
        .hand_caller_secret_to_handler()
        .build();

    impl<const OPTED_IN: bool> Operation for SecretHungry<OPTED_IN> {
        const NAME: &'static str = "WriteGetObjectResponse";
        const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);
        type Input = ();
        type Output = ();
        type DerivedResources = crate::NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::DerivedResourceError> {
            Ok(crate::NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            if OPTED_IN { &SECRET_HUNGRY_SPEC } else { &SPEC }
        }

        fn floor() -> &'static OperationFloor {
            &FLOOR
        }
    }

    /// Negative -- a standard operation may not opt in to the caller's secret (ADR-0024): the
    /// opt-in is refused as such, and without it the same operation is refused only for its name.
    #[test]
    fn a_standard_operation_that_opts_in_to_the_caller_secret_is_refused() {
        assert_eq!(
            check_operation::<SecretHungry<true>>(),
            Err(RegistryError::StandardOperationReceivesCallerSecret {
                name: "WriteGetObjectResponse"
            })
        );
        assert_eq!(
            check_operation::<SecretHungry<false>>(),
            Err(RegistryError::UnknownStandardOperation {
                name: "WriteGetObjectResponse"
            })
        );
    }

    /// Negative -- every shape of a name that is not `vendor:Name`.
    #[test]
    fn a_name_without_exactly_one_non_empty_namespace_is_refused() {
        for name in [
            "GetObject",
            ":GetObject",
            "rustfs:",
            "rustfs::GetObject",
            "rustfs: GetObject",
            "",
        ] {
            assert!(!is_namespaced(name), "{name:?} must not pass the namespace rule");
        }
    }

    /// Positive -- the shape a third party is asked for.
    #[test]
    fn a_vendor_qualified_name_is_accepted() {
        for name in ["rustfs:AdminSetConfig", "acme:DoThing"] {
            assert!(is_namespaced(name), "{name:?} is the shape the rule asks for");
        }
    }
}

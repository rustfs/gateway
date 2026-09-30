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

//! Every registration refusal of a version requirement, one requirement per index, and the one
//! registrable shape.
//!
//! Responsible for: which version requirements `super::check_operation` admits — the resource
//! shape, the missing subject, the missing nested requirement, the spelling and namespace of
//! every version action, and a standard operation's one version action — and how a requirement
//! chooses between its two forms and renders them.
//! NOT responsible for: which operations declare one (the op specs, pinned by the core
//! integration suite) or asking it (the facade's route stage).
//! Upstream: `super::check_operation`, `crate::op::AuthRequirement`. Downstream: nothing.

use rustfs_gateway_sig::{OperationFloor, SigService};

use super::{RegistryError, check_operation};
use crate::authz::{SubjectRule, WhenAbsent};
use crate::op::{AuthRequirement, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::{HandlerDeadlineClass, OperationSpec};

static READ_VERSION: AuthRequirement = AuthRequirement::new("acme:ReadVersion", ResourceShape::Object);
static BUCKET_VERSION: AuthRequirement = AuthRequirement::new("acme:ReadVersion", ResourceShape::Bucket);
static NESTED_VERSION: AuthRequirement =
    AuthRequirement::new("acme:ReadVersion", ResourceShape::Object).with_version_requirement(&READ_VERSION);
static MALFORMED_VERSION: AuthRequirement = AuthRequirement::new("acme ReadVersion", ResourceShape::Object);
static ABOUT_AN_ACCOUNT: AuthRequirement =
    AuthRequirement::new("acme:ReadVersion", ResourceShape::Object).about_subject(SubjectRule::Query {
        param: "accessKey",
        aliases: &[],
        when_absent: WhenAbsent::Refuse,
    });
static FOREIGN_VERSION: AuthRequirement = AuthRequirement::new("other:ReadVersion", ResourceShape::Object);
static TWO_VERSION_ACTIONS: AuthRequirement =
    AuthRequirement::all_of(&["acme:ReadVersion", "acme:ReadVersionMore"], ResourceShape::Object);
static GET_OBJECT_VERSION: AuthRequirement = AuthRequirement::new("s3:GetObjectVersion", ResourceShape::Object);
static GET_OBJECT_VERSIONS: AuthRequirement =
    AuthRequirement::all_of(&["s3:GetObjectVersion", "s3:GetObjectVersionAttributes"], ResourceShape::Object);

/// One requirement per index; the first is registrable, the rest are refused.
const REQUIREMENTS: [AuthRequirement; 7] = [
    AuthRequirement::new("acme:Read", ResourceShape::Object).with_version_requirement(&READ_VERSION),
    // 1: a version requirement about the bucket, for an operation about an object.
    AuthRequirement::new("acme:Read", ResourceShape::Object).with_version_requirement(&BUCKET_VERSION),
    // 2: a version requirement with a version requirement of its own.
    AuthRequirement::new("acme:Read", ResourceShape::Object).with_version_requirement(&NESTED_VERSION),
    // 3: a malformed version action.
    AuthRequirement::new("acme:Read", ResourceShape::Object).with_version_requirement(&MALFORMED_VERSION),
    // 4: a version requirement about a named account.
    AuthRequirement::new("acme:Read", ResourceShape::Object).with_version_requirement(&ABOUT_AN_ACCOUNT),
    // 5: a requirement about a named account with a version requirement.
    AuthRequirement::new("acme:Read", ResourceShape::Object)
        .about_subject(SubjectRule::Query {
            param: "accessKey",
            aliases: &[],
            when_absent: WhenAbsent::Refuse,
        })
        .with_version_requirement(&READ_VERSION),
    // 6: a version action in another vendor's namespace.
    AuthRequirement::new("acme:Read", ResourceShape::Object).with_version_requirement(&FOREIGN_VERSION),
];

const NAMES: [&str; 7] = ["acme:V0", "acme:V1", "acme:V2", "acme:V3", "acme:V4", "acme:V5", "acme:V6"];

const fn spec(index: usize) -> OperationSpec {
    OperationSpec::builder(NAMES[index], 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(REQUIREMENTS[index])
        .build()
}

static SPECS: [OperationSpec; 7] = [spec(0), spec(1), spec(2), spec(3), spec(4), spec(5), spec(6)];

static FLOORS: [OperationFloor; 7] = [
    OperationFloor::custom(NAMES[0], SigService::S3),
    OperationFloor::custom(NAMES[1], SigService::S3),
    OperationFloor::custom(NAMES[2], SigService::S3),
    OperationFloor::custom(NAMES[3], SigService::S3),
    OperationFloor::custom(NAMES[4], SigService::S3),
    OperationFloor::custom(NAMES[5], SigService::S3),
    OperationFloor::custom(NAMES[6], SigService::S3),
];

// The fixtures sit inside their own `#[cfg(test)]` item for `check_op_file_shape.sh`, which admits
// an `impl Operation` outside the ops tree only there; the whole file is test-only anyway.
#[cfg(test)]
mod fixtures {
    use super::*;

    pub(super) struct Versioned<const N: usize>;

    impl<const N: usize> Operation for Versioned<N> {
        const NAME: &'static str = NAMES[N];
        type Input = ();
        type Output = ();
        type DerivedResources = crate::NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::DerivedResourceError> {
            Ok(crate::NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &SPECS[N]
        }

        fn floor() -> &'static OperationFloor {
            &FLOORS[N]
        }
    }

    /// The rowless standard name again, with a version requirement of two actions.
    pub(super) struct StandardWithTwoVersionActions;

    static STANDARD_SPEC: OperationSpec = OperationSpec::builder("WriteGetObjectResponse", 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object).with_version_requirement(&GET_OBJECT_VERSIONS))
        .build();
    static STANDARD_FLOOR: OperationFloor = OperationFloor::builtin("WriteGetObjectResponse", SigService::S3);

    impl Operation for StandardWithTwoVersionActions {
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
            &STANDARD_SPEC
        }

        fn floor() -> &'static OperationFloor {
            &STANDARD_FLOOR
        }
    }
}

use fixtures::{StandardWithTwoVersionActions, Versioned};

fn why<const N: usize>() -> &'static str {
    match check_operation::<Versioned<N>>() {
        Err(RegistryError::InvalidAuthRule { why, .. }) => why,
        other => panic!("{} was not refused for its version requirement: {other:?}", NAMES[N]),
    }
}

/// Positive — one version action about the same resource, in the operation's own namespace, is
/// registrable, and the requirement answers with it only for a request that names a version.
#[test]
fn a_version_requirement_about_the_same_resource_is_registrable_and_chosen_by_the_version() {
    assert_eq!(check_operation::<Versioned<0>>(), Ok(()));
    let requirement = REQUIREMENTS[0];
    assert_eq!(requirement.version_requirement(), Some(&READ_VERSION));
    assert_eq!(requirement.for_version(false).action, "acme:Read");
    assert_eq!(requirement.for_version(true).action, "acme:ReadVersion");
    assert_eq!(requirement.for_version(true).version_requirement(), None);
    assert_eq!(requirement.render(), "acme:Read; versionId: acme:ReadVersion");
}

/// Negative — a requirement without a version requirement answers with itself for a request that
/// names a version: no operation silently gains a version action it never declared.
#[test]
fn n_a_requirement_without_a_version_requirement_keeps_its_own_action() {
    let plain = AuthRequirement::new("acme:Read", ResourceShape::Object);
    assert_eq!(plain.version_requirement(), None);
    assert_eq!(plain.for_version(true), plain);
    assert_eq!(plain.render(), "acme:Read");
}

/// Negative — the version requirement is about the operation's own resource shape.
#[test]
fn n_a_version_requirement_about_another_resource_shape_is_refused() {
    assert_eq!(
        why::<1>(),
        "a version requirement is about the resource shape of the requirement it replaces"
    );
}

/// Negative — a version requirement is the last word: it names none of its own.
#[test]
fn n_a_nested_version_requirement_is_refused() {
    assert_eq!(why::<2>(), "a version requirement names no version requirement of its own");
}

/// Negative — every version action is spelled `service:Action`.
#[test]
fn n_a_malformed_version_action_is_refused() {
    assert_eq!(
        check_operation::<Versioned<3>>(),
        Err(RegistryError::MalformedAuthAction {
            name: NAMES[3],
            action: "acme ReadVersion"
        })
    );
}

/// Negative — neither side of a version requirement is about an account.
#[test]
fn n_a_version_requirement_about_an_account_is_refused() {
    assert_eq!(why::<4>(), "a requirement about an account names no version requirement");
    assert_eq!(why::<5>(), "a requirement about an account names no version requirement");
}

/// Negative — a version action is held to the namespace rule every other action of a dialect
/// operation is held to.
#[test]
fn n_a_version_action_in_another_vendors_namespace_is_refused() {
    assert_eq!(
        why::<6>(),
        "a dialect operation's action is in its own vendor namespace or an IAM service's, never another vendor's"
    );
}

/// Negative — a standard operation's version requirement is one action, as its own requirement is.
#[test]
fn n_a_standard_operation_with_a_version_rule_of_two_actions_is_refused() {
    assert_eq!(
        check_operation::<StandardWithTwoVersionActions>(),
        Err(RegistryError::InvalidAuthRule {
            name: "WriteGetObjectResponse",
            why: "a standard operation is authorised by its one generated action, about no subject",
        })
    );
    // The all-of fixture is well-formed on its own: only the standard rule refuses it.
    assert_eq!(TWO_VERSION_ACTIONS.fault(), None);
    assert_eq!(GET_OBJECT_VERSION.fault(), None);
}

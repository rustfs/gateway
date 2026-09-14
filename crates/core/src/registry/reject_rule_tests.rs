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

//! Every registration refusal of an action rule or a subject rule (ADR-0025), one requirement per
//! index, and the overlay cross-check that reads the rendered rule.
//!
//! Responsible for: the any-of and all-of set rules, every action's spelling, the subject
//! parameter's spelling, the own-account rules, a standard operation's refusal, and an overlay
//! that records only the first action of a rule.
//! NOT responsible for: combining decisions or extracting a subject (`crate::authz::rule`).
//! Upstream: `super::check_operation`, `crate::dialect`. Downstream: nothing.

use rustfs_gateway_sig::{OperationFloor, SigService};

use super::{RegistryError, check_operation};
use crate::authz::{Everyone, SubjectRule, WhenAbsent};
use crate::dialect::{ClaimedRoute, ClaimedRow, Dialect, DialectError, DialectOverlay, OverlayRow};
use crate::op::{AuthRequirement, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::{HandlerDeadlineClass, OperationSpec};
use crate::route::{BucketParam, PathClaim, Predicate};

const TWO: &[&str] = &["acme:A", "acme:B"];
const USER: SubjectRule = SubjectRule::Query {
    param: "accessKey",
    when_absent: WhenAbsent::Refuse,
};

/// A set rule over `users` whose every-account flag `all` needs `action` (ADR-0026).
const fn everyone_needs(action: &'static str) -> SubjectRule {
    SubjectRule::Set {
        param: "users",
        everyone: Some(Everyone { param: "all", action }),
    }
}

/// One requirement per index; the first five are registrable, the rest are refused.
const REQUIREMENTS: [AuthRequirement; 21] = [
    AuthRequirement::any_of(TWO, ResourceShape::Service),
    AuthRequirement::all_of(TWO, ResourceShape::Bucket),
    AuthRequirement::new("acme:Own", ResourceShape::Service).about_subject(SubjectRule::Caller),
    AuthRequirement::new("admin:GetUser", ResourceShape::Service).about_subject(USER),
    AuthRequirement::any_of(TWO, ResourceShape::Service).about_subject(USER),
    // 5: one action is `new`, not a set of one.
    AuthRequirement::any_of(&["acme:A"], ResourceShape::Service),
    // 6: no action at all.
    AuthRequirement::all_of(&[], ResourceShape::Service),
    // 7: a repeated action.
    AuthRequirement::any_of(&["acme:A", "acme:A"], ResourceShape::Service),
    // 8: a malformed second action.
    AuthRequirement::all_of(&["acme:A", "acme B"], ResourceShape::Service),
    // 9: a subject parameter outside the unreserved set.
    AuthRequirement::new("admin:GetUser", ResourceShape::Service).about_subject(SubjectRule::Query {
        param: "access key",
        when_absent: WhenAbsent::Caller,
    }),
    // 10: an own-account operation with several actions.
    AuthRequirement::any_of(&["acme:A", "acme:B"], ResourceShape::Service).about_subject(SubjectRule::Caller),
    // 11: an own-account operation about a bucket.
    AuthRequirement::new("acme:Own", ResourceShape::Bucket).about_subject(SubjectRule::Caller),
    // 12: an own-account label borrowed from IAM's `admin` namespace.
    AuthRequirement::new("admin:Own", ResourceShape::Service).about_subject(SubjectRule::Caller),
    // 13: an own-account label from another vendor's namespace.
    AuthRequirement::new("other:Own", ResourceShape::Service).about_subject(SubjectRule::Caller),
    // 14: a set rule whose every-account action is broader than its own (ADR-0026).
    AuthRequirement::new("admin:ListServiceAccounts", ResourceShape::Service).about_subject(everyone_needs("admin:ListUsers")),
    // 15: an any-of set rule whose every-account action narrows it to one alternative.
    AuthRequirement::any_of(TWO, ResourceShape::Service).about_subject(everyone_needs("acme:A")),
    // 16: a malformed every-account action.
    AuthRequirement::new("admin:ListServiceAccounts", ResourceShape::Service).about_subject(everyone_needs("admin ListUsers")),
    // 17: an every-account action that is the one action every named account is already asked.
    AuthRequirement::new("acme:A", ResourceShape::Service).about_subject(everyone_needs("acme:A")),
    // 18: an every-account action an all-of rule already asks about every named account.
    AuthRequirement::all_of(TWO, ResourceShape::Service).about_subject(everyone_needs("acme:B")),
    // 19: a set parameter outside the unreserved set.
    AuthRequirement::new("admin:ListServiceAccounts", ResourceShape::Service).about_subject(SubjectRule::Set {
        param: "user s",
        everyone: None,
    }),
    // 20: a bucket operation about a named account, for the query-bucket refusals.
    AuthRequirement::new("s3:GetBucketQuota", ResourceShape::Bucket).about_subject(USER),
];

const NAMES: [&str; 21] = [
    "acme:R0", "acme:R1", "acme:R2", "acme:R3", "acme:R4", "acme:R5", "acme:R6", "acme:R7", "acme:R8", "acme:R9", "acme:R10",
    "acme:R11", "acme:R12", "acme:R13", "acme:R14", "acme:R15", "acme:R16", "acme:R17", "acme:R18", "acme:R19", "acme:R20",
];

const fn spec(index: usize) -> OperationSpec {
    OperationSpec::builder(NAMES[index], 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(REQUIREMENTS[index])
        .build()
}

static SPECS: [OperationSpec; 21] = [
    spec(0),
    spec(1),
    spec(2),
    spec(3),
    spec(4),
    spec(5),
    spec(6),
    spec(7),
    spec(8),
    spec(9),
    spec(10),
    spec(11),
    spec(12),
    spec(13),
    spec(14),
    spec(15),
    spec(16),
    spec(17),
    spec(18),
    spec(19),
    spec(20),
];

static FLOORS: [OperationFloor; 21] = [
    OperationFloor::custom(NAMES[0], SigService::S3),
    OperationFloor::custom(NAMES[1], SigService::S3),
    OperationFloor::custom(NAMES[2], SigService::S3),
    OperationFloor::custom(NAMES[3], SigService::S3),
    OperationFloor::custom(NAMES[4], SigService::S3),
    OperationFloor::custom(NAMES[5], SigService::S3),
    OperationFloor::custom(NAMES[6], SigService::S3),
    OperationFloor::custom(NAMES[7], SigService::S3),
    OperationFloor::custom(NAMES[8], SigService::S3),
    OperationFloor::custom(NAMES[9], SigService::S3),
    OperationFloor::custom(NAMES[10], SigService::S3),
    OperationFloor::custom(NAMES[11], SigService::S3),
    OperationFloor::custom(NAMES[12], SigService::S3),
    OperationFloor::custom(NAMES[13], SigService::S3),
    OperationFloor::custom(NAMES[14], SigService::S3),
    OperationFloor::custom(NAMES[15], SigService::S3),
    OperationFloor::custom(NAMES[16], SigService::S3),
    OperationFloor::custom(NAMES[17], SigService::S3),
    OperationFloor::custom(NAMES[18], SigService::S3),
    OperationFloor::custom(NAMES[19], SigService::S3),
    OperationFloor::custom(NAMES[20], SigService::S3),
];

// The fixtures sit inside their own `#[cfg(test)]` item for `check_op_file_shape.sh`, which admits
// an `impl Operation` outside the ops tree only there; the whole file is test-only anyway.
#[cfg(test)]
mod fixtures {
    use super::*;

    pub(super) struct Rule<const N: usize>;

    impl<const N: usize> Operation for Rule<N> {
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

    /// The rowless standard name again, with a rule a standard operation may not carry.
    pub(super) struct StandardWithARule;

    static STANDARD_FLOOR: OperationFloor = OperationFloor::builtin("WriteGetObjectResponse", SigService::S3);

    impl Operation for StandardWithARule {
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
            static STANDARD_SPEC: OperationSpec = spec_named("WriteGetObjectResponse", 0);
            &STANDARD_SPEC
        }

        fn floor() -> &'static OperationFloor {
            &STANDARD_FLOOR
        }
    }

    const fn spec_named(name: &'static str, index: usize) -> OperationSpec {
        let mut spec = spec(index);
        spec.name = name;
        spec
    }
}

use fixtures::{Rule, StandardWithARule};

fn why<const N: usize>() -> &'static str {
    match check_operation::<Rule<N>>() {
        Err(RegistryError::InvalidAuthRule { why, .. }) => why,
        other => panic!("{} was not refused for its rule: {other:?}", NAMES[N]),
    }
}

/// Positive — sets of two or more distinct actions, own-account labels in the vendor's namespace,
/// and a subject parameter spelled as a query key are registrable.
#[test]
fn well_formed_rules_are_registrable() {
    assert_eq!(check_operation::<Rule<0>>(), Ok(()));
    assert_eq!(check_operation::<Rule<1>>(), Ok(()));
    assert_eq!(check_operation::<Rule<2>>(), Ok(()));
    assert_eq!(check_operation::<Rule<3>>(), Ok(()));
    assert_eq!(check_operation::<Rule<4>>(), Ok(()));
}

/// Negative — a set of one, an empty set and a repeated action are refused.
#[test]
fn n_a_set_of_fewer_than_two_distinct_actions_is_refused() {
    assert!(why::<5>().contains("at least two actions"));
    assert!(why::<6>().contains("at least two actions"));
    assert!(why::<7>().contains("each action once"));
}

/// Negative — every action of a set is spelled `service:Action`, not only the first.
#[test]
fn n_a_malformed_later_action_is_refused() {
    assert_eq!(
        check_operation::<Rule<8>>(),
        Err(RegistryError::MalformedAuthAction {
            name: NAMES[8],
            action: "acme B"
        })
    );
}

/// Negative — a subject parameter that is not a plain query key is refused.
#[test]
fn n_a_subject_parameter_outside_the_unreserved_set_is_refused() {
    assert!(why::<9>().contains("unreserved"));
}

/// Negative — an own-account operation names one action, about the caller, in its own vendor's
/// namespace: never several, never a bucket, never an IAM service's or another vendor's action.
#[test]
fn n_an_own_account_rule_outside_its_bounds_is_refused() {
    assert!(why::<10>().contains("exactly one action"));
    assert!(why::<11>().contains("not a bucket"));
    assert!(why::<12>().contains("own vendor namespace"));
    assert!(why::<13>().contains("own vendor namespace"));
}

/// Negative — a standard operation is authorised by its one generated action: a rule is refused
/// before its missing route row is.
#[test]
fn n_a_standard_operation_with_a_rule_is_refused() {
    assert_eq!(
        check_operation::<StandardWithARule>(),
        Err(RegistryError::InvalidAuthRule {
            name: "WriteGetObjectResponse",
            why: "a standard operation is authorised by its one generated action, about no subject",
        })
    );
}

/// Positive — a set rule whose every-account action is broader than its own, and an any-of set
/// rule whose every-account action narrows it to one alternative, are registrable and rendered in
/// full (ADR-0026).
#[test]
fn set_rules_with_a_broader_every_account_action_are_registrable() {
    assert_eq!(check_operation::<Rule<14>>(), Ok(()));
    assert_eq!(check_operation::<Rule<15>>(), Ok(()));
    assert_eq!(
        REQUIREMENTS[14].render(),
        "admin:ListServiceAccounts about each(users, everyone=all ⇒ admin:ListUsers)"
    );
    assert_eq!(REQUIREMENTS[14].everyone_action(), Some("admin:ListUsers"));
    assert_eq!(REQUIREMENTS[3].everyone_action(), None);
}

/// Negative — every account needs an explicit, well-spelled action that no named-account question
/// already asks; and a set parameter is a plain query key.
#[test]
fn n_a_set_rule_whose_every_account_form_adds_nothing_is_refused() {
    assert!(why::<16>().contains("spelled"));
    assert!(why::<17>().contains("already requires"));
    assert!(why::<18>().contains("already requires"));
    assert!(why::<19>().contains("unreserved"));
}

// ── the overlay reads the rendered rule ──────────────────────────────────────────────────────

static GET: &[Predicate] = &[Predicate::Method(http::Method::GET)];
static ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v1/r0",
    selector: GET,
}];
const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];

static CLAIMS: &[PathClaim] = &[PathClaim {
    prefix: "/acme/admin",
    reason: "The vendor's admin surface.",
    evidence: EVIDENCE,
}];

const fn row_recording(action: &'static str) -> OverlayRow {
    OverlayRow {
        name: NAMES[0],
        precedence: 10,
        selector: "PathTemplate(\"/acme/admin/v1/r0\") ∧ Method(GET)",
        action,
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }
}

/// A record that spells the whole any-of rule.
static RECORDS_THE_RULE: DialectOverlay = DialectOverlay {
    name: "acme-rules",
    vendor: "acme",
    claims: CLAIMS,
    operations: &[row_recording("anyOf(acme:A, acme:B)")],
};

/// A record that names only the rule's first action.
static RECORDS_ONLY_THE_FIRST: DialectOverlay = DialectOverlay {
    name: "acme-rules",
    vendor: "acme",
    claims: CLAIMS,
    operations: &[row_recording("acme:A")],
};

fn declare(overlay: &'static DialectOverlay) -> Result<Dialect, Vec<DialectError>> {
    Dialect::assemble(overlay)
        .declare_claimed::<Rule<0>>(ClaimedRoute {
            precedence: 10,
            rows: ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .build()
}

/// Positive and negative — the overlay must spell the whole any-of rule; a record naming only its
/// first action is refused, so a reviewer never reads one action where two decide.
#[test]
fn n_an_overlay_that_records_only_the_first_action_is_refused() {
    assert!(declare(&RECORDS_THE_RULE).is_ok());
    let errors = declare(&RECORDS_ONLY_THE_FIRST).expect_err("the record hides an action");
    assert_eq!(
        errors,
        [DialectError::ActionMismatch {
            name: NAMES[0],
            declared: "anyOf(acme:A, acme:B)".to_owned(),
            overlay: "acme:A",
        }]
    );
}

/// Negative — a service-level claimed operation that binds a bucket parameter is refused.
#[test]
fn n_a_service_level_operation_that_binds_a_bucket_is_refused() {
    static TEMPLATED: &[ClaimedRow] = &[ClaimedRow {
        template: "/acme/admin/v1/{bucket}",
        selector: GET,
    }];
    let errors = Dialect::assemble(&RECORDS_THE_RULE)
        .declare_claimed::<Rule<0>>(ClaimedRoute {
            precedence: 10,
            rows: TEMPLATED,
            shadows: &[],
            bucket_param: Some(BucketParam::Path("bucket")),
        })
        .build()
        .expect_err("a service-level operation with a bound bucket");
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, DialectError::ClaimedBucketParam { param: "bucket", why, .. } if why.contains("only an operation authorised on a bucket"))),
        "{errors:?}"
    );
}

// ── a bucket named in the query (ADR-0026) ──────────────────────────────────────────────────

/// A record for the all-of bucket operation, bound to `bucket` in the query.
static RECORDS_A_QUERY_BUCKET: DialectOverlay = DialectOverlay {
    name: "acme-rules",
    vendor: "acme",
    claims: CLAIMS,
    operations: &[OverlayRow {
        name: NAMES[1],
        precedence: 10,
        selector: "PathTemplate(\"/acme/admin/v1/r0\") ∧ Method(GET) ⇒ BucketQuery(\"bucket\")",
        action: "allOf(acme:A, acme:B)",
        resource: ResourceShape::Bucket,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }],
};

fn declare_bucket<const N: usize>(bucket_param: Option<BucketParam>) -> Result<Dialect, Vec<DialectError>> {
    Dialect::assemble(&RECORDS_A_QUERY_BUCKET)
        .declare_claimed::<Rule<N>>(ClaimedRoute {
            precedence: 10,
            rows: ROWS,
            shadows: &[],
            bucket_param,
        })
        .build()
}

fn bucket_refusal(errors: &[DialectError], param: &str) -> Option<&'static str> {
    errors.iter().find_map(|error| match error {
        DialectError::ClaimedBucketParam { param: refused, why, .. } if *refused == param => Some(*why),
        _ => None,
    })
}

/// Positive — a bucket operation binds a query parameter, and its record says so.
#[test]
fn a_bucket_operation_binds_a_query_parameter_its_record_names() {
    assert!(declare_bucket::<1>(Some(BucketParam::Query("bucket"))).is_ok());
}

/// Negative — a query binding on a service-level operation, a parameter that is not a plain query
/// key, or one the operation's own subject rule reads, is refused before the record is read.
#[test]
fn n_a_query_binding_outside_its_bounds_is_refused() {
    let service = declare_bucket::<0>(Some(BucketParam::Query("bucket"))).expect_err("a service-level operation");
    assert!(
        bucket_refusal(&service, "bucket").is_some_and(|why| why.contains("only an operation authorised on a bucket")),
        "{service:?}"
    );
    for param in ["", "bu cket", "b&c", "b%41"] {
        let errors = declare_bucket::<1>(Some(BucketParam::Query(param))).expect_err(param);
        assert!(
            bucket_refusal(&errors, param).is_some_and(|why| why.contains("unreserved")),
            "{param:?}: {errors:?}"
        );
    }
    let shared = declare_bucket::<20>(Some(BucketParam::Query("accessKey"))).expect_err("one parameter, two meanings");
    assert!(
        bucket_refusal(&shared, "accessKey").is_some_and(|why| why.contains("different query parameters")),
        "{shared:?}"
    );
    // The control: another parameter is accepted as a binding (the operation is refused only for
    // the record this overlay does not hold).
    let other = declare_bucket::<20>(Some(BucketParam::Query("bucket"))).expect_err("no record for this operation");
    assert_eq!(bucket_refusal(&other, "bucket"), None, "{other:?}");
}

/// Negative — a template binding still needs the template's parameter; a query binding does not
/// stand in for one.
#[test]
fn n_a_path_binding_without_its_template_parameter_is_refused() {
    let errors = declare_bucket::<1>(Some(BucketParam::Path("bucket"))).expect_err("a row without {bucket}");
    assert!(
        bucket_refusal(&errors, "bucket").is_some_and(|why| why.contains("template has no parameter")),
        "{errors:?}"
    );
}

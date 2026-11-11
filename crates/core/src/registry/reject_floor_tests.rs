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

//! The registration refusal of a floor that requires SigV4 under every policy and also declares a
//! query bearer claim (rustfs/gateway#1576), with both halves as registrable controls, and how
//! refusing SigV2 under every policy composes with both (ADR-0052, rustfs/gateway#1592).
//!
//! Responsible for: `super::check_operation`'s answer for the six floors — SigV4-only with a
//! bearer claim (refused), SigV4-only alone and a bearer claim alone (both registrable), the
//! SigV2 refusal with a bearer claim (registrable, the zip download's shape), the SigV2 refusal
//! beside the SigV4 requirement (registrable: redundant, not contradictory), and all three
//! together (refused, as the SigV4 requirement with a bearer claim is).
//! NOT responsible for: what either property admits at request time (`rustfs-gateway-sig`).
//! Upstream: `super::check_operation`, `rustfs_gateway_sig::OperationFloor`. Downstream: nothing.

use rustfs_gateway_sig::{OperationFloor, QueryBearerClaim, SigService};

use super::{RegistryError, check_operation};
use crate::op::{AuthRequirement, Operation, ResourceShape};
use crate::registry::{HandlerDeadlineClass, OperationSpec};

const CLAIM: QueryBearerClaim = QueryBearerClaim::new("token", ".zip");
const NAMES: [&str; 6] = [
    "acme:SigV4OnlyWithBearer",
    "acme:SigV4Only",
    "acme:BearerOnly",
    "acme:NoSigV2WithBearer",
    "acme:NoSigV2AndSigV4Only",
    "acme:NoSigV2AndSigV4OnlyWithBearer",
];

const fn spec(index: usize) -> OperationSpec {
    OperationSpec::builder(NAMES[index], 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("acme:Read", ResourceShape::Object))
        .build()
}

static SPECS: [OperationSpec; 6] = [spec(0), spec(1), spec(2), spec(3), spec(4), spec(5)];

static FLOORS: [OperationFloor; 6] = [
    OperationFloor::builtin_presigned(NAMES[0], SigService::S3)
        .require_sigv4_under_every_policy()
        .with_query_bearer_claim(CLAIM),
    OperationFloor::builtin_presigned(NAMES[1], SigService::S3).require_sigv4_under_every_policy(),
    OperationFloor::custom(NAMES[2], SigService::S3).with_query_bearer_claim(CLAIM),
    OperationFloor::custom(NAMES[3], SigService::S3)
        .refuse_sigv2_under_every_policy()
        .with_query_bearer_claim(CLAIM),
    OperationFloor::builtin_presigned(NAMES[4], SigService::S3)
        .refuse_sigv2_under_every_policy()
        .require_sigv4_under_every_policy(),
    OperationFloor::builtin_presigned(NAMES[5], SigService::S3)
        .refuse_sigv2_under_every_policy()
        .require_sigv4_under_every_policy()
        .with_query_bearer_claim(CLAIM),
];

// The fixtures sit inside their own `#[cfg(test)]` item for `check_op_file_shape.sh`, which admits
// an `impl Operation` outside the ops tree only there; the whole file is test-only anyway.
#[cfg(test)]
mod fixtures {
    use super::*;

    pub(super) struct Floored<const N: usize>;

    impl<const N: usize> Operation for Floored<N> {
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
}

use fixtures::Floored;

/// The registry's refusal of the SigV4 requirement beside a bearer claim, for `name`.
fn assert_sigv4_bearer_refusal(result: Result<(), RegistryError>, expected: &str) {
    match result {
        Err(RegistryError::InvalidAuthRule { name, why }) => {
            assert_eq!(name, expected);
            assert!(why.contains("requires SigV4 under every policy"), "{why}");
            assert!(why.contains("query bearer claim"), "{why}");
        }
        other => panic!("expected the floor refusal, got {other:?}"),
    }
}

/// Negative — a floor requiring SigV4 under every policy that also declares a query bearer claim
/// is refused at registration, in the order the two are written.
#[test]
fn n_a_sigv4_only_floor_with_a_bearer_claim_is_refused() {
    assert_sigv4_bearer_refusal(check_operation::<Floored<0>>(), NAMES[0]);
}

/// Negative — refusing SigV2 as well does not rescue the contradiction: the SigV4 requirement
/// beside a bearer claim is refused whatever else the floor declares.
#[test]
fn n_refusing_sigv2_does_not_rescue_a_sigv4_only_floor_with_a_bearer_claim() {
    assert_sigv4_bearer_refusal(check_operation::<Floored<5>>(), NAMES[5]);
}

/// Positive — refusing SigV2 composes with a bearer claim (the zip download's floor) and with the
/// SigV4 requirement (redundant, so accepted rather than refused): neither admits what the other
/// refuses (ADR-0052).
#[test]
fn refusing_sigv2_registers_beside_a_bearer_claim_and_beside_the_sigv4_requirement() {
    assert_eq!(check_operation::<Floored<3>>(), Ok(()));
    assert_eq!(check_operation::<Floored<4>>(), Ok(()));
}

/// Positive — each half alone registers: the refusal is about the combination.
#[test]
fn a_sigv4_only_floor_and_a_bearer_floor_each_register() {
    assert_eq!(check_operation::<Floored<1>>(), Ok(()));
    assert_eq!(check_operation::<Floored<2>>(), Ok(()));
}

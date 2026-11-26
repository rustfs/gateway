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

//! `CreateSession`: minting short-lived S3 Express directory-bucket session credentials.
//!
//! Responsible for: the operation identity, privileged S3 Express signature floor, and bucket
//! authorization contract for `GET /{Bucket}?session`.
//! NOT responsible for: issuing STS tokens, validating `x-amz-s3session-token` on data-plane calls,
//! or persisting directory-bucket session state.
//! Upstream: the generated operation DTO and codec. Downstream: routing and handler registration.
//! Shares: nothing.
//!
//! # Security posture
//!
//! `CreateSession` is privileged, requires SigV4 under the `s3express` signing service, refuses
//! presigned URLs, anonymous callers, SigV2, host header tokens (ADR-0054), and S3 Express session
//! tokens themselves (`DisableS3ExpressSessionAuth`). Long-term IAM credentials and STS temporary
//! credentials remain eligible to request a directory-bucket session.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{CreateSession, CreateSessionInput, CreateSessionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires once routing selects `GET /{Bucket}?session`.
static SPEC: OperationSpec = OperationSpec::standard("CreateSession")
    .required_params(&[])
    .auth(AuthRequirement::new("s3express:CreateSession", ResourceShape::Bucket))
    .build();

/// Privileged S3 Express session minting requires header SigV4 and refuses session-token auth.
static FLOOR: OperationFloor = OperationFloor::builtin("CreateSession", SigService::S3Express)
    .mark_privileged()
    .require_sigv4_under_every_policy()
    .refuse_s3_express_session_auth();

impl Operation for CreateSession {
    const NAME: &'static str = "CreateSession";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = CreateSessionInput;
    type Output = CreateSessionOutput;
    type DerivedResources = crate::authz::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        Ok(crate::authz::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for CreateSessionInput {
    type Op = CreateSession;
}

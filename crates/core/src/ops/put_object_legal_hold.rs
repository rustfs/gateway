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

//! `PutObjectLegalHold`: the legal-hold document of one object, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutObjectLegalHold`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_object_legal_hold.rs` — the request root is the payload member's
//! `xmlName`, `LegalHold`, not the shape name (`q-lock-0005`), and the payload is promoted to
//! required so an empty body is `MalformedXML` rather than a hold silently set to a value
//! nobody sent (`q-lock-0007`); nor for the closed `Status` set, which lives once in
//! [`shared::object_lock`](super::shared::object_lock); nor for **enforcement** — what an `ON`
//! hold actually forbids is the storage side's later task. There is no bypass header here: a
//! legal hold has no governance mode to bypass, and lifting one is spelled `Status: OFF`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object_lock.
//!
//! # Why the row exists before a backend does
//!
//! The retention write's hazard, one subresource over: with no `?legal-hold` row a hold write
//! was claimed by `PutObject`, which stored the `<LegalHold>` document as the object's body —
//! destroying the object a court told somebody to keep, with a `200`. The row lands at 540,
//! ahead of `CopyObject` at 790 and `PutObject` at 800.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutObjectLegalHold, PutObjectLegalHoldInput, PutObjectLegalHoldOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The `LegalHold` document is a required *member*, refused by the decoder with `MalformedXML`
/// when the body is absent or wrongly rooted — not a required *parameter*, which is a check on
/// the request head. Nothing on the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec::builder("PutObjectLegalHold", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObjectLegalHold", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObjectLegalHold", SigService::S3);

impl Operation for PutObjectLegalHold {
    const NAME: &'static str = "PutObjectLegalHold";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectLegalHoldInput;
    type Output = PutObjectLegalHoldOutput;
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

impl HasOperation for PutObjectLegalHoldInput {
    type Op = PutObjectLegalHold;
}

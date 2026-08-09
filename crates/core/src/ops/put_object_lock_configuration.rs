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

//! `PutObjectLockConfiguration`: the whole object-lock document of one bucket, replaced — and,
//! per the pinned model's own documentation, how object lock is enabled on an existing bucket.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutObjectLockConfiguration`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_object_lock_configuration.rs` — the request root is the shape's own
//! name, `ObjectLockConfiguration`, the one document in this family whose wire root and shape
//! name agree; nor for the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay, `q-lock-0006`); nor for the document's semantic
//! rules — the one-value `ObjectLockEnabled` set, the closed `Mode` set, the `Days`/`Years`
//! mutex and its ≥1 floor — which live once in
//! [`shared::object_lock`](super::shared::object_lock) so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object_lock.
//!
//! # What the decoder refuses, and what it deliberately does not
//!
//! The decoder refuses a body that is not XML, a wrong root, and — because the overlay promotes
//! the payload to required — an absent or empty body, as `MalformedXML` (`q-lock-0007`): a
//! silently-defaulted lock configuration is a compliance answer nobody gave. It does **not**
//! refuse an element it does not know (`q-lock-0014`): a stored WORM document is re-parsed by
//! every future release, and a decoder that got stricter would downgrade the document to none,
//! silently unlocking data. The `x-amz-bucket-object-lock-token` header is decoded and carried;
//! what a governance token authorises is enforcement, and enforcement is not this family's.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutObjectLockConfiguration, PutObjectLockConfigurationInput, PutObjectLockConfigurationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The integrity header is a required *claim*, refused by the generated decoder before the body
/// is read — not a required *parameter*, which is a check on the request head alone. Nothing on
/// the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec {
    name: "PutObjectLockConfiguration",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutBucketObjectLockConfiguration", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObjectLockConfiguration", SigService::S3);

impl Operation for PutObjectLockConfiguration {
    const NAME: &'static str = "PutObjectLockConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectLockConfigurationInput;
    type Output = PutObjectLockConfigurationOutput;
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

impl HasOperation for PutObjectLockConfigurationInput {
    type Op = PutObjectLockConfiguration;
}

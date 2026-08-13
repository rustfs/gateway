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

//! `PutObjectRetention`: the retention document of one object, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutObjectRetention`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_object_retention.rs` — the request root is the payload member's
//! `xmlName`, `Retention`, not the shape name (`q-lock-0004`), the payload is promoted to
//! required so an empty body is `MalformedXML` (`q-lock-0007`), and the
//! `x-amz-bypass-governance-retention` header decodes case-insensitively with any non-boolean
//! value refused as `InvalidArgument`, never guessed true (`q-lock-0012`); nor for the
//! document's semantic rules — the closed `Mode` set and the future-only `RetainUntilDate` —
//! which live once in [`shared::object_lock`](super::shared::object_lock); nor for
//! **enforcement**: whether the bypass is honoured, whether a COMPLIANCE retention may be
//! shortened, and whether a protected object refuses deletion are the storage side's later
//! task. The decoded intent — mode, date, bypass — reaches the handler whole, which is this
//! family's entire promise.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object_lock.
//!
//! # Why the row exists before a backend does
//!
//! This is the tagging write's hazard again, on the compliance subresource. `PutObject`'s
//! selector is `Method("PUT")` and `Target("Object")` and nothing else, so with no `?retention`
//! row a retention write was claimed by `PutObject` — which **stored the `<Retention>` document
//! as the object's body**, destroying the object it meant to protect, with a `200`. The row
//! lands at 520, ahead of `CopyObject` at 790 and `PutObject` at 800; the copy edge matters
//! too, since a retention write that also carried `x-amz-copy-source` would otherwise be served
//! as a copy.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutObjectRetention, PutObjectRetentionInput, PutObjectRetentionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The `Retention` document is a required *member*, refused by the decoder with `MalformedXML`
/// when the body is absent or wrongly rooted — not a required *parameter*, which is a check on
/// the request head. Nothing on the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec::builder("PutObjectRetention", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObjectRetention", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObjectRetention", SigService::S3);

impl Operation for PutObjectRetention {
    const NAME: &'static str = "PutObjectRetention";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectRetentionInput;
    type Output = PutObjectRetentionOutput;
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

impl HasOperation for PutObjectRetentionInput {
    type Op = PutObjectRetention;
}

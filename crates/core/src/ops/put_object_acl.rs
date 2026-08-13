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

//! `PutObjectAcl`: the whole access control list of one object version, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutObjectAcl`, plus the [`HasOperation`] reverse mapping from its input type, and the
//! declaration of which target's canned-ACL set governs it.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/put_object_acl.rs`
//! from `generated/ir/PutObjectAcl.json`; nor for the integrity requirement, which the generated
//! decoder settles; nor for the two-channel rule and the grant-header grammar, which live once in
//! [`shared::acl`](super::shared::acl).
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: acl.
//!
//! # The row this family exists for
//!
//! `PUT /{Bucket}/{Key+}?acl` carries an ACL document, and with no row of its own it was claimed
//! by `PutObject`, which **stores the ACL document as the object** — the object's bytes gone,
//! replaced by the XML that was only ever meant to change who may read them. That is the
//! `PutObjectAcl -> PutObject` line of the route-coverage debt register, and it is the same
//! data-loss defect the `?tagging` and `?retention` rows retired. The row lands at 560: ahead of
//! `CopyObject` at 790, because an ACL write carrying `x-amz-copy-source` would otherwise be
//! served as a copy and overwrite the destination from the source, and ahead of `PutObject` at
//! 800.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutObjectAcl, PutObjectAclInput, PutObjectAclOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::acl::AclTarget;
use crate::registry::OperationSpec;

/// The target whose canned-ACL set governs this operation: an object's, so
/// `bucket-owner-full-control` is accepted here and `log-delivery-write` is not.
pub static ACL_TARGET: AclTarget = AclTarget::Object;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("PutObjectAcl", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObjectAcl", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObjectAcl", SigService::S3);

impl Operation for PutObjectAcl {
    const NAME: &'static str = "PutObjectAcl";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectAclInput;
    type Output = PutObjectAclOutput;
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

impl HasOperation for PutObjectAclInput {
    type Op = PutObjectAcl;
}

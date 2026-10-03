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

//! `GetObjectAcl`: the access control list of one object version, and not the object.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObjectAcl`, plus the [`HasOperation`] reverse mapping from its input type, and the
//! declaration of which target's canned-ACL set governs it.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/get_object_acl.rs`
//! from `generated/ir/GetObjectAcl.json`; nor for evaluating the list it answers with.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: acl.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}/{Key+}?acl` and `GET /{Bucket}/{Key+}` differ by one query key, and `?acl` is
//! not an exclusive predicate of `GetObject`. With no row of its own the ACL read was claimed by
//! `GetObject` and answered with the **object's bytes** — the `GetObjectAcl -> GetObject` line of
//! the route-coverage debt register, and the same disclosure the tagging and attributes reads
//! each had before their rows landed. The row sits at 550, after the retention and legal-hold
//! band and well ahead of `GetObject` at 900.
//!
//! # There is no unconfigured ACL here either
//!
//! An object always has one, so `not_configured_error` is `None` — unlike the object-level
//! retention and legal-hold reads next door, which answer `NoSuchObjectLockConfiguration` for a
//! document that was never written. `versionId` selects a version; its absence selects the
//! current one.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObjectAcl, GetObjectAclInput, GetObjectAclOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::acl::AclTarget;
use crate::registry::OperationSpec;

/// The target whose canned-ACL set governs this operation: an object's.
pub static ACL_TARGET: AclTarget = AclTarget::Object;

/// A request naming one version is asked `s3:GetObjectVersionAcl`, as AWS requires when `versionId`
/// is specified
/// (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>).
/// Legacy RustFS asks `s3:GetObjectAcl` instead (`rustfs/src/storage/access.rs:2721` on
/// rustfs/rustfs `d60dfbb826`); the RustFS profile keeps that
/// (`ServiceBuilder::authorize_versions_as_legacy_rustfs`).
static VERSION_AUTH: AuthRequirement = AuthRequirement::new("s3:GetObjectVersionAcl", ResourceShape::Object);

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::standard("GetObjectAcl")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObjectAcl", ResourceShape::Object).with_version_requirement(&VERSION_AUTH))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectAcl", SigService::S3);

impl Operation for GetObjectAcl {
    const NAME: &'static str = "GetObjectAcl";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectAclInput;
    type Output = GetObjectAclOutput;
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

impl HasOperation for GetObjectAclInput {
    type Op = GetObjectAcl;
}

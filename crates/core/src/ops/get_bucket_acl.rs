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

//! `GetBucketAcl`: the access control list of one bucket, and no judgement about what it permits.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketAcl`, plus the [`HasOperation`] reverse mapping from its input type, and the
//! declaration of which target's canned-ACL set governs this operation.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/get_bucket_acl.rs`
//! from `generated/ir/GetBucketAcl.json` — including the `xsi:type` and `xmlns:xsi` attributes of
//! `<Grantee>`, which are IR data (`q-acl-0003`) and not a branch in an encoder; nor for
//! evaluating the list it answers with, which is the deployment's `Authorizer`'s work.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: acl. The grammar of a grantee and the canned-ACL sets live in
//! [`shared::acl`](super::shared::acl); [`ACL_TARGET`] is where this file says which set applies.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?acl` and `GET /{Bucket}` differ by one query key, and `?acl` is not an
//! exclusive predicate of the listing fallback. With no row of its own the ACL read was claimed
//! by `ListObjects` and answered with a key listing — the `GetBucketAcl -> ListObjects` line of
//! the route-coverage debt register. The row lands at 250, **ahead** of the subresource band
//! rather than inside it, and the only edge that matters is that it precedes the listings: the
//! table is first-match and `ListObjects` at 700 pins no query key, so a GET row behind it would
//! hand every ACL read back to the key listing this family exists to stop.
//!
//! # There is no unconfigured ACL
//!
//! Every bucket has one from the moment it exists — at minimum its owner's `FULL_CONTROL` — so
//! this operation is the bucket-subresource read that has **no** `not_configured_error`
//! (`q-acl-0008`). A bucket nobody ever called `PutBucketAcl` on answers `200` with the owner
//! grant, never the `404` its `?cors`, `?lifecycle`, `?encryption` and `?replication` neighbours
//! answer.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketAcl, GetBucketAclInput, GetBucketAclOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::acl::AclTarget;
use crate::registry::OperationSpec;

/// The target whose canned-ACL set governs this operation: a bucket's.
///
/// Declared here rather than assumed at the call site, so the shared contract's member list and
/// the operation agree in a form a guard can check — the same declarative shape the tagging
/// operations use for their scopes.
pub static ACL_TARGET: AclTarget = AclTarget::Bucket;

/// What this operation requires of a request once routing has chosen it.
///
/// `acl` is a routing discriminator, not a required parameter: a `GET` on a bucket without it is
/// the key listing. Nothing else is required, and `not_configured_error` is deliberately `None` —
/// see the module docs.
static SPEC: OperationSpec = OperationSpec {
    name: "GetBucketAcl",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetBucketAcl", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketAcl", SigService::S3);

impl Operation for GetBucketAcl {
    const NAME: &'static str = "GetBucketAcl";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketAclInput;
    type Output = GetBucketAclOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetBucketAclInput {
    type Op = GetBucketAcl;
}

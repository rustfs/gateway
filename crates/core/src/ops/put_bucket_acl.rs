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

//! `PutBucketAcl`: the whole access control list of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketAcl`, plus the [`HasOperation`] reverse mapping from its input type, and the
//! declaration of which target's canned-ACL set governs it.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/put_bucket_acl.rs`
//! from `generated/ir/PutBucketAcl.json`; nor for the integrity requirement, which the generated
//! decoder settles (`http_checksum_required` in the overlay); nor for the two-channel rule, the
//! canned-ACL sets or the grant-header grammar, which live once in
//! [`shared::acl`](super::shared::acl) so that the body spelling and the header spelling of one
//! ACL cannot drift apart.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: acl.
//!
//! # Why the row exists, and what it stops
//!
//! `PUT /{Bucket}?acl` is disjoint from `CreateBucket` — the creation row names `acl` in its own
//! `QueryAbsent` list — so the write was not mis-routed the way the read was. It was
//! *unroutable*: with no row of its own an ACL write reached no operation at all. The row lands
//! at 260, beside the read.
//!
//! # What the decoder refuses, and what this family deliberately does not
//!
//! The decoder refuses a body that is not XML and a wrong root. It does **not** refuse an element
//! it does not know (`q-acl-0006`) or an `xmlns` attribute on the document, because an ACL
//! request body is a request XML and AWS's forward-compatibility rule applies to it. What
//! [`shared::acl`](super::shared::acl) then refuses is what the wire cannot describe: the two
//! channels used at once, neither channel used at all, a canned ACL outside a bucket's set, a
//! grant header that is not the documented grammar, a grantee whose `xsi:type` cannot be derived,
//! and a permission outside the closed set.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketAcl, PutBucketAclInput, PutBucketAclOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::acl::AclTarget;
use crate::registry::OperationSpec;

/// The target whose canned-ACL set governs this operation: a bucket's, so `log-delivery-write` is
/// accepted here and `bucket-owner-full-control` is not.
pub static ACL_TARGET: AclTarget = AclTarget::Bucket;

/// What this operation requires of a request once routing has chosen it.
///
/// The integrity header is a required *claim*, refused by the generated decoder before the body
/// is read — not a required *parameter*, which is a check on the request head alone. Nothing on
/// the head is required beyond the routing discriminator: an ACL write may legitimately carry no
/// body at all, because the header channel is the other way of saying the same thing.
static SPEC: OperationSpec = OperationSpec::standard("PutBucketAcl")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutBucketAcl", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketAcl", SigService::S3);

impl Operation for PutBucketAcl {
    const NAME: &'static str = "PutBucketAcl";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketAclInput;
    type Output = PutBucketAclOutput;
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

impl HasOperation for PutBucketAclInput {
    type Op = PutBucketAcl;
}

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

//! `GetBucketReplication`: the stored replication document of one bucket, and nothing about
//! whether an object write is ever replicated by it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketReplication`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_replication.rs` from
//! `generated/ir/GetBucketReplication.json`; nor for executing the configuration — rule
//! evaluation, cross-site transfer and the per-object `x-amz-replication-status` header (task
//! P5-01, with the object read encoders) are the replication engine's, never a route row here.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: replication, rule_filter.
//! The family validator uses `shared::rule_filter` for Filter grammar. The document's validation rules live in
//! [`shared::replication`](super::shared::replication), reached by backends through the facade;
//! this file only states the read's spec.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?replication` and `GET /{Bucket}` differ by one query key, and `?replication`
//! is not an exclusive predicate of the listing fallback. With no row of its own the
//! replication read was claimed by `ListObjects` and answered with a key listing — the
//! `GetBucketReplication -> ListObjects` line of the route-coverage debt register. The row
//! lands at 394, packed after the `?encryption` band because the tens-aligned subresource
//! slots are spoken for, so an unhandled replication read is refused with
//! `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than answered by its neighbour.
//!
//! A bucket that never had a replication document is a **404
//! `ReplicationConfigurationNotFoundError`** — one of the few AWS codes whose literal ends in
//! `Error`, and the operation-specific one: not a generic not-found, and not a `200` with an
//! empty document. That is what [`OperationSpec::not_configured_error`] carries for this
//! operation and what `q-repl-0001` records.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketReplication, GetBucketReplicationInput, GetBucketReplicationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `replication` is a routing discriminator, not a required parameter: a `GET` on a bucket
/// without it is the key listing. Nothing else is required.
static SPEC: OperationSpec = OperationSpec::standard("GetBucketReplication")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetReplicationConfiguration", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketReplication", SigService::S3);

impl Operation for GetBucketReplication {
    const NAME: &'static str = "GetBucketReplication";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketReplicationInput;
    type Output = GetBucketReplicationOutput;
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

impl HasOperation for GetBucketReplicationInput {
    type Op = GetBucketReplication;
}

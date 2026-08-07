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

//! `PutBucketReplication`: the whole replication document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketReplication`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_replication.rs` from
//! `generated/ir/PutBucketReplication.json` — the request root is the payload member's own
//! `xmlName`, wire and model in agreement; nor for the integrity requirement, which the
//! generated decoder settles (`http_checksum_required` in the overlay); nor for the document's
//! semantic rules — the V1/V2 schema couplings, the filter grammar and the `ID` bounds — which
//! live once in [`shared::replication`](super::shared::replication) so that no backend
//! re-derives them. The `x-amz-bucket-object-lock-token` header is parsed into the input and
//! passed through untouched (`q-repl-0013`); its meaning is the storage backend's question.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: replication.
//!
//! # What the decoder refuses, and what it deliberately does not
//!
//! The decoder refuses a body that is not XML, a wrong root, and a document missing `Role` or
//! carrying no `Rule` — both are required members, so clearing the configuration is spelled
//! `DeleteBucketReplication`, never an empty document. It does **not** refuse an element it
//! does not know (`q-repl-0005`), an out-of-set `Status` (`q-repl-0012`) or a duplicated
//! `Priority` (`q-repl-0009`): RustFS parses the stored replication document fail-closed — the
//! one configuration for which "stopped parsing" means "bucket unusable" rather than "feature
//! off" — so every leniency here is a stored document the next release must still read.
//! Semantic refusals — a rule mixing the V1 and V2 schemas, a filter with two direct children,
//! an `ID` over its bound — are
//! [`shared::replication::validate_replication`](super::shared::replication::validate_replication)'s
//! to make, after decoding, with the specific codes AWS answers — and with constant reasons
//! that never repeat the KMS key id or the destination account (`q-repl-0010`).

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketReplication, PutBucketReplicationInput, PutBucketReplicationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The integrity header is a required *claim*, refused by the generated decoder before the body
/// is read — not a required *parameter*, which is a check on the request head alone. Nothing on
/// the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec {
    name: "PutBucketReplication",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutReplicationConfiguration", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketReplication", SigService::S3);

impl Operation for PutBucketReplication {
    const NAME: &'static str = "PutBucketReplication";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketReplicationInput;
    type Output = PutBucketReplicationOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for PutBucketReplicationInput {
    type Op = PutBucketReplication;
}

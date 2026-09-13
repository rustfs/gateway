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

//! `PutBucketEncryption`: the whole default-encryption document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketEncryption`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_encryption.rs` from `generated/ir/PutBucketEncryption.json` —
//! the request root is the payload member's own `xmlName`, wire and model in agreement for once;
//! nor for the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules — the closed
//! `SSEAlgorithm` set and the KMS-key-id/algorithm agreement — which live once in
//! [`shared::encryption`](super::shared::encryption) so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: encryption.
//!
//! # What the decoder refuses, and what it deliberately does not
//!
//! The decoder refuses a body that is not XML, a wrong root, and a document with no `Rule` —
//! `Rules` is a required member, so clearing the configuration is spelled
//! `DeleteBucketEncryption`, never an empty document. Unknown request elements are refused
//! (`q-enc-0006`), while the rule list remains unbounded (`q-enc-0008`). Persisted configuration
//! reads use separate compatibility codecs; their leniency does not govern HTTP writes.
//! Semantic refusals — an out-of-set `SSEAlgorithm`, a `KMSMasterKeyID` beside a non-KMS
//! algorithm — are
//! [`shared::encryption::validate_encryption`](super::shared::encryption::validate_encryption)'s
//! to make, after decoding, with the specific codes AWS answers — and with constant reasons that
//! never repeat the key id (`q-enc-0009`).

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketEncryption, PutBucketEncryptionInput, PutBucketEncryptionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The integrity header is a required *claim*, refused by the generated decoder before the body
/// is read — not a required *parameter*, which is a check on the request head alone. Nothing on
/// the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec::standard("PutBucketEncryption")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutEncryptionConfiguration", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketEncryption", SigService::S3);

impl Operation for PutBucketEncryption {
    const NAME: &'static str = "PutBucketEncryption";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketEncryptionInput;
    type Output = PutBucketEncryptionOutput;
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

impl HasOperation for PutBucketEncryptionInput {
    type Op = PutBucketEncryption;
}

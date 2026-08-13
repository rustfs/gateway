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

//! `DeleteBucketEncryption`: the default-encryption document removed, the bucket left alone.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteBucketEncryption`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/delete_bucket_encryption.rs` from
//! `generated/ir/DeleteBucketEncryption.json`. It has no body in either direction — the model's
//! output is `smithy.api#Unit`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: encryption. The family's document rules live in
//! [`shared::encryption`](super::shared::encryption); this operation carries no document, and is
//! listed so a change to the family's contract knows all three members.
//!
//! # Why the row exists before a backend does
//!
//! `DELETE /{Bucket}?encryption` had no fallback row — `DeleteBucket`'s own `QueryAbsent` list
//! names `encryption`, which is what kept the request from deleting the bucket — so the absence
//! made it unroutable rather than mis-served. The row lands at 393 so the request is refused by
//! name — `crate::dispatch::NOT_REGISTERED_MESSAGE` naming `DeleteBucketEncryption` — until a
//! backend registers a handler.
//!
//! The success status is `204` and it is unconditional: removing the encryption configuration of
//! a bucket that has none is a success, not a `404` (`q-enc-0003`). A `404` here would make
//! "already gone" indistinguishable from "wrong bucket" — which is what `NoSuchBucket` is for.
//! The permission is the write's, `s3:PutEncryptionConfiguration`: AWS documents no
//! delete-specific action for this family.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteBucketEncryption, DeleteBucketEncryptionInput, DeleteBucketEncryptionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("DeleteBucketEncryption", 204, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutEncryptionConfiguration", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteBucketEncryption", SigService::S3);

impl Operation for DeleteBucketEncryption {
    const NAME: &'static str = "DeleteBucketEncryption";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteBucketEncryptionInput;
    type Output = DeleteBucketEncryptionOutput;
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

impl HasOperation for DeleteBucketEncryptionInput {
    type Op = DeleteBucketEncryption;
}

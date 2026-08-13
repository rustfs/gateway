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

//! `PutBucketAccelerateConfiguration`: the transfer-acceleration switch of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketAccelerateConfiguration`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_accelerate_configuration.rs` from
//! `generated/ir/PutBucketAccelerateConfiguration.json`; nor for
//! the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules, which
//! live once in the shared module so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # The one write in this family with no integrity requirement, beside the notification write
//!
//! The pinned model carries no `content-md5` member for this operation and no request checksum
//! requirement, so `http_checksum_required` stays false and a body with neither `Content-MD5` nor
//! an `x-amz-checksum-*` header is accepted. Six of this family's eight writes require one; this
//! and `PutBucketNotificationConfiguration` do not, and the difference is the model's, not a
//! simplification made here (`q-acc-0003`).
//!
//! # Why the row exists before a backend does
//!
//! `PUT /{Bucket}?accelerate` and `PUT /{Bucket}` differ by one query key, and `?accelerate` is not an
//! exclusive predicate of the bucket creation.
//! `CreateBucket`'s own `QueryAbsent` list names `accelerate`, which is what kept the write from
//! creating a bucket, so the absence of a row made the request unroutable rather than mis-served.
//!
//! The row lands at 201, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    PutBucketAccelerateConfiguration, PutBucketAccelerateConfigurationInput, PutBucketAccelerateConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `accelerate` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::builder("PutBucketAccelerateConfiguration", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutAccelerateConfiguration", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketAccelerateConfiguration", SigService::S3);

impl Operation for PutBucketAccelerateConfiguration {
    const NAME: &'static str = "PutBucketAccelerateConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketAccelerateConfigurationInput;
    type Output = PutBucketAccelerateConfigurationOutput;
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

impl HasOperation for PutBucketAccelerateConfigurationInput {
    type Op = PutBucketAccelerateConfiguration;
}

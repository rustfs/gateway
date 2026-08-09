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

//! `PutBucketNotificationConfiguration`: the event-notification document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketNotificationConfiguration`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_notification_configuration.rs` from
//! `generated/ir/PutBucketNotificationConfiguration.json`; nor for
//! the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules, which
//! live once in the shared module so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_notification. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_notification`](super::shared::bucket_notification); this file states what is this
//! operation's alone.
//!
//! # The second write with no integrity requirement
//!
//! The pinned model carries no `content-md5` member for the v2 notification write, so
//! `http_checksum_required` stays false — the difference from the v1 operation AWS retired, and
//! from the six writes in this family that do require one (`q-ntf-0003`). An empty
//! `<NotificationConfiguration/>` is accepted and means "deliver nothing": clearing the document is
//! this write, not a delete, because the model declares none.
//!
//! # Why the row exists before a backend does
//!
//! `PUT /{Bucket}?notification` and `PUT /{Bucket}` differ by one query key, and `?notification` is not an
//! exclusive predicate of the bucket creation.
//! `CreateBucket`'s own `QueryAbsent` list names `notification`, which is what kept the write
//! from creating a bucket, so the absence of a row made the request unroutable rather than mis-
//! served.
//!
//! The row lands at 211, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    PutBucketNotificationConfiguration, PutBucketNotificationConfigurationInput, PutBucketNotificationConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `notification` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "PutBucketNotificationConfiguration",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutBucketNotification", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketNotificationConfiguration", SigService::S3);

impl Operation for PutBucketNotificationConfiguration {
    const NAME: &'static str = "PutBucketNotificationConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketNotificationConfigurationInput;
    type Output = PutBucketNotificationConfigurationOutput;
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

impl HasOperation for PutBucketNotificationConfigurationInput {
    type Op = PutBucketNotificationConfiguration;
}

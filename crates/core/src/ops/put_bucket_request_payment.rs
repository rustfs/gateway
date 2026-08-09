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

//! `PutBucketRequestPayment`: who pays for a download from one bucket, switched.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketRequestPayment`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_request_payment.rs` from `generated/ir/PutBucketRequestPayment.json`;
//! nor for
//! the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules, which
//! live once in the shared module so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # A closed value set, refused rather than stored
//!
//! `<Payer>` is `Requester` or `BucketOwner` and nothing else. This is one of the two places in
//! the family where an out-of-set enum is a refusal rather than a stored value
//! ([`shared::bucket_config`](super::shared::bucket_config) makes it, as `InvalidArgument`), and
//! the reason is that the member is required: there is no reading of the document that omits it,
//! so an unknown value has no meaning to fall back to (`q-rqp-0002`).
//!
//! # Why the row exists before a backend does
//!
//! `PUT /{Bucket}?requestPayment` and `PUT /{Bucket}` differ by one query key, and `?requestPayment` is not
//! an
//! exclusive predicate of the bucket creation.
//! `CreateBucket`'s own `QueryAbsent` list names `requestPayment`, which is what kept the write
//! from creating a bucket, so the absence of a row made the request unroutable rather than mis-
//! served.
//!
//! The row lands at 231, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketRequestPayment, PutBucketRequestPaymentInput, PutBucketRequestPaymentOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `requestPayment` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "PutBucketRequestPayment",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutBucketRequestPayment", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketRequestPayment", SigService::S3);

impl Operation for PutBucketRequestPayment {
    const NAME: &'static str = "PutBucketRequestPayment";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketRequestPaymentInput;
    type Output = PutBucketRequestPaymentOutput;
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

impl HasOperation for PutBucketRequestPaymentInput {
    type Op = PutBucketRequestPayment;
}

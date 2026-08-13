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

//! `GetBucketRequestPayment`: who pays for a download from one bucket.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketRequestPayment`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_request_payment.rs` from `generated/ir/GetBucketRequestPayment.json`;
//! nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # The unconfigured answer is a 200 carrying the default, not an empty document
//!
//! This read is the family's third shape of unconfigured answer. A bucket that was never switched
//! to requester-pays answers `200` with `<Payer>BucketOwner</Payer>` — the *default value*, not an
//! empty `<RequestPaymentConfiguration/>` and not a `404` (`q-rqp-0001`). The payer is always one
//! of two values, so there is no such thing as a bucket with no payer.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?requestPayment` and `GET /{Bucket}` differ by one query key, and `?requestPayment` is not
//! an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketRequestPayment -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 230, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketRequestPayment, GetBucketRequestPaymentInput, GetBucketRequestPaymentOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `requestPayment` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::builder("GetBucketRequestPayment", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetBucketRequestPayment", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketRequestPayment", SigService::S3);

impl Operation for GetBucketRequestPayment {
    const NAME: &'static str = "GetBucketRequestPayment";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketRequestPaymentInput;
    type Output = GetBucketRequestPaymentOutput;
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

impl HasOperation for GetBucketRequestPaymentInput {
    type Op = GetBucketRequestPayment;
}

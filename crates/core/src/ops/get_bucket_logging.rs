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

//! `GetBucketLogging`: the access-logging destination of one bucket, and nothing that writes a log line.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketLogging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_logging.rs` from `generated/ir/GetBucketLogging.json`; nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # The unconfigured answer is a 200, not a 404
//!
//! A bucket with no logging document answers `200` with an empty `<BucketLoggingStatus/>`, so
//! [`OperationSpec::not_configured_error`] is `None`. `<LoggingEnabled>` present and absent are the
//! two states, and absent is spelled by omitting the element rather than by an error (`q-log-0001`).
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?logging` and `GET /{Bucket}` differ by one query key, and `?logging` is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketLogging -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 205, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketLogging, GetBucketLoggingInput, GetBucketLoggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `logging` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::standard("GetBucketLogging")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetBucketLogging", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketLogging", SigService::S3);

impl Operation for GetBucketLogging {
    const NAME: &'static str = "GetBucketLogging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketLoggingInput;
    type Output = GetBucketLoggingOutput;
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

impl HasOperation for GetBucketLoggingInput {
    type Op = GetBucketLogging;
}

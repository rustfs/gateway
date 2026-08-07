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

//! `GetObjectRetention`: the retention document of one object, and nothing else about it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObjectRetention`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_object_retention.rs` — where the response root is the payload
//! member's `xmlName`, `Retention`, not the shape name `ObjectLockRetention` (`q-lock-0004`).
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object_lock. The document this operation reads back is whatever a retention write
//! validated under [`shared::object_lock`](super::shared::object_lock)'s rules.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}/{Key+}?retention` and `GET /{Bucket}/{Key+}` differ by one query key, and
//! `?retention` is not an exclusive predicate of `GetObject`. With no row of its own the
//! retention read was claimed by `GetObject` and answered with the **object's bytes** — the
//! same disclosure the attributes and tagging reads had, under a compliance subresource. The
//! row lands at 510, after the `?tagging` band and ahead of the object band, so an unhandled
//! retention read is refused with `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than
//! answered by its neighbour.
//!
//! An object with no retention is a **404 `NoSuchObjectLockConfiguration`** — the object-level
//! code, deliberately distinct from the bucket read's
//! `ObjectLockConfigurationNotFoundError` (`q-lock-0002`).

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetObjectRetention, GetObjectRetentionInput, GetObjectRetentionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `retention` is a routing discriminator, not a required parameter: a `GET` on an object key
/// without it is `GetObject`. Nothing else is required — `versionId` selects a version and its
/// absence selects the current one.
static SPEC: OperationSpec = OperationSpec {
    name: "GetObjectRetention",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_OBJECT_LOCK_CONFIGURATION),
    auth: Some(AuthRequirement::new("s3:GetObjectRetention", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectRetention", SigService::S3);

impl Operation for GetObjectRetention {
    const NAME: &'static str = "GetObjectRetention";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectRetentionInput;
    type Output = GetObjectRetentionOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetObjectRetentionInput {
    type Op = GetObjectRetention;
}

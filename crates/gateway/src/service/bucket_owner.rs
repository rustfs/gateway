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

//! Expected-bucket-owner evaluation after route or input authorization allows a request.
//!
//! Responsible for: checking `x-amz-expected-bucket-owner` (header or POST form) and
//! `x-amz-source-expected-bucket-owner` against [`BucketOwnerSource`] behind the panic boundary
//! and translating [`BucketOwnerErrorKind`] into either a fail-closed authorization decision or a
//! caller-safe `NoSuchBucket` / `InternalError` [`HandlerError`].
//! NOT responsible for: authorizing S3 actions (`crate::ext::Authorizer`), deciding whether a
//! service is non-S3 (`super::isolation`), or rendering `S3Error` (`crate::render`).
//! Upstream: `super::S3Service`, `crate::ext::bucket_owner`. Downstream: `super::S3Service`.

use rustfs_gateway_core::{Decision, HandlerError, HandlerErrorContext, OwnedResource, ResourceIdentity};
use rustfs_gateway_types::BucketName;

use crate::ext::{BucketOwnerErrorKind, BucketOwnerSource};
use crate::panic_boundary::catch_boxed_future;

/// Result of enforcing an expected-bucket-owner assertion.
pub(super) struct OwnerCheckOutcome {
    pub(super) decision: Decision,
    pub(super) error: Option<HandlerError>,
}

impl OwnerCheckOutcome {
    const ALLOW: Self = Self {
        decision: Decision::Allow,
        error: None,
    };

    const DENY: Self = Self {
        decision: Decision::Deny,
        error: None,
    };

    const INDETERMINATE: Self = Self {
        decision: Decision::Indeterminate,
        error: None,
    };

    fn not_found() -> Self {
        Self {
            decision: Decision::Indeterminate,
            error: Some(HandlerError::from(HandlerErrorContext::missing_bucket())),
        }
    }

    fn backend_failure() -> Self {
        Self {
            decision: Decision::Indeterminate,
            error: Some(HandlerError::internal_error("the bucket owner lookup failed")),
        }
    }
}

/// Checks one route-stage expected-owner assertion (`x-amz-expected-bucket-owner` header or
/// `PostObject` form field).
pub(super) async fn check_route_owner(
    source: &dyn BucketOwnerSource,
    bucket: Option<&BucketName>,
    expected_owner: Option<&str>,
) -> OwnerCheckOutcome {
    match (expected_owner, bucket) {
        (Some(expected_owner), Some(bucket)) => check_bucket_owner(source, bucket, expected_owner).await,
        (None, _) | (_, None) => OwnerCheckOutcome::INDETERMINATE,
    }
}

/// Checks `x-amz-source-expected-bucket-owner` across every derived copy-source resource.
pub(super) async fn check_source_owner(
    source: &dyn BucketOwnerSource,
    resources: &[OwnedResource],
    expected_owner: Option<&str>,
) -> OwnerCheckOutcome {
    let Some(expected_owner) = expected_owner else {
        return OwnerCheckOutcome::INDETERMINATE;
    };
    if resources.is_empty() {
        return OwnerCheckOutcome::INDETERMINATE;
    }
    for resource in resources {
        let outcome = match (resource.identity(), resource.bucket()) {
            (None | Some(ResourceIdentity::Path), Some(source_bucket)) => {
                check_bucket_owner(source, source_bucket, expected_owner).await
            }
            _ => OwnerCheckOutcome::INDETERMINATE,
        };
        if outcome.decision != Decision::Allow {
            return outcome;
        }
    }
    OwnerCheckOutcome::ALLOW
}

async fn check_bucket_owner(source: &dyn BucketOwnerSource, bucket: &BucketName, expected_owner: &str) -> OwnerCheckOutcome {
    // An empty expected owner never satisfies ownership and never probes bucket existence.
    if expected_owner.is_empty() {
        return OwnerCheckOutcome::DENY;
    }
    match catch_boxed_future(|| source.owner(bucket)).await {
        Ok(Ok(actual_owner)) if actual_owner.is_empty() => OwnerCheckOutcome::INDETERMINATE,
        Ok(Ok(actual_owner)) if actual_owner.as_ref() == expected_owner => OwnerCheckOutcome::ALLOW,
        Ok(Ok(_)) => OwnerCheckOutcome::DENY,
        Ok(Err(error)) => match error.kind() {
            BucketOwnerErrorKind::Unavailable => OwnerCheckOutcome::INDETERMINATE,
            BucketOwnerErrorKind::NotFound => OwnerCheckOutcome::not_found(),
            BucketOwnerErrorKind::Backend => OwnerCheckOutcome::backend_failure(),
        },
        Err(()) => OwnerCheckOutcome::INDETERMINATE,
    }
}

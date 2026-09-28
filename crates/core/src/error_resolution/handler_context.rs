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

//! The handler-facing subset of [`ErrorContext`]: the contexts an operation handler may attach to
//! its own refusal.
//!
//! Responsible for: [`HandlerErrorContext`], one delegating constructor per handler-reachable
//! context, and the crate-internal moves made on one (unwrap, hide a missing object from a caller
//! who may not list the bucket, and restrict a marker refusal to what a copy may say of its source).
//! NOT responsible for: validating or resolving any context — every constructor delegates to
//! [`ErrorContext`] in the parent — or the verifier-only authorization-scope contexts, which are
//! deliberately absent.
//! Upstream: operation handlers and backends. Downstream: [`crate::HandlerError`], the parent's
//! resolution.

use rustfs_gateway_types::{BucketName, ETag, ObjectKey};

#[cfg(doc)]
use super::super::VersionIdLabel;
use super::{ErrorContext, InvalidErrorContext, MissingObject, ResourceVisibility};
use crate::{RedirectTarget, RegionLabel};

/// A closed context that an authenticated operation handler may return as a [`HandlerError`].
///
/// Its field is private and it deliberately has no generic constructor or conversion from
/// [`ErrorContext`]. In particular, the two authorization-scope contexts are absent: only the
/// built-in verifier may attach trusted remediation metadata to an authentication refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerErrorContext(ErrorContext);

impl HandlerErrorContext {
    /// A missing key or version, with the visibility fact that prevents existence disclosure.
    #[must_use]
    pub const fn missing_object(kind: MissingObject, visibility: ResourceVisibility) -> Self {
        Self(ErrorContext::missing_object(kind, visibility))
    }

    /// A missing key or version that retains its validated key only when visibility permits it.
    #[must_use]
    pub fn missing_object_for(key: ObjectKey, kind: MissingObject, visibility: ResourceVisibility) -> Self {
        Self(ErrorContext::missing_object_for(key, kind, visibility))
    }

    /// DeleteObject found the bucket and no current key, which is an empty `204` success.
    #[must_use]
    pub const fn delete_missing_key() -> Self {
        Self(ErrorContext::delete_missing_key())
    }

    /// The addressed bucket does not exist.
    #[must_use]
    pub const fn missing_bucket() -> Self {
        Self(ErrorContext::missing_bucket())
    }

    /// The bucket exists but belongs to another account and is therefore hidden.
    #[must_use]
    pub const fn foreign_bucket() -> Self {
        Self(ErrorContext::foreign_bucket())
    }

    /// A permanent bucket-region redirect.
    #[must_use]
    pub fn permanent_redirect(region: RegionLabel) -> Self {
        Self(ErrorContext::permanent_redirect(region))
    }

    /// A permanent redirect that retains the validated bucket name in the error document.
    #[must_use]
    pub fn permanent_redirect_for(bucket: BucketName, region: RegionLabel) -> Self {
        Self(ErrorContext::permanent_redirect_for(bucket, region))
    }

    /// A temporary endpoint redirect while bucket DNS propagates.
    #[must_use]
    pub fn temporary_redirect(region: RegionLabel, target: RedirectTarget) -> Self {
        Self(ErrorContext::temporary_redirect(region, target))
    }

    /// CreateBucket found a bucket already owned by the caller.
    #[must_use]
    pub const fn owned_bucket_recreation() -> Self {
        Self(ErrorContext::owned_bucket_recreation())
    }

    /// A version-specific read selected a delete marker.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the version id is not a [`VersionIdLabel`], or when the instant
    /// falls outside the range `Last-Modified` can express.
    pub fn versioned_delete_marker(version_id: &str, last_modified: i64) -> Result<Self, InvalidErrorContext> {
        ErrorContext::versioned_delete_marker(version_id, last_modified).map(Self)
    }

    /// A read that named no version found a delete marker, `version_id`, as the current version.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext`] when the version id is not a [`VersionIdLabel`], or when the instant
    /// falls outside the range `Last-Modified` can express.
    pub fn current_delete_marker(
        visibility: ResourceVisibility,
        key: Option<ObjectKey>,
        version_id: &str,
        last_modified: i64,
    ) -> Result<Self, InvalidErrorContext> {
        ErrorContext::current_delete_marker(visibility, key, version_id, last_modified).map(Self)
    }

    /// A read precondition matched the current entity tag.
    #[must_use]
    pub fn not_modified(etag: ETag) -> Self {
        Self(ErrorContext::not_modified(etag))
    }

    pub(crate) fn into_error_context(self) -> ErrorContext {
        self.0
    }

    pub(crate) fn copy_source_marker(self) -> Self {
        Self(self.0.copy_source_marker())
    }

    pub(crate) fn hide_missing_object(self) -> Self {
        Self(self.0.hide_missing_object())
    }
}

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

//! The actual owner used to enforce a caller's expected-bucket-owner assertion.
//!
//! Responsible for: [`BucketOwnerSource`], its fail-closed [`NoBucketOwner`] default and the
//! opaque [`BucketOwnerError`] returned when the deployment cannot supply a bucket owner.
//! NOT responsible for: authorizing an S3 action (`super::Authorizer`), decoding operation input,
//! or deciding which path segment is the bucket (`super::HostResolver`).
//! Upstream: the deployment's bucket metadata. Downstream: `crate::service` before request-body
//! ingestion and handler dispatch.
//!
//! # AWS S3 behavior
//!
//! - <https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-owner-condition.html>: AWS S3
//!   evaluates `x-amz-expected-bucket-owner` against the bucket's actual account ID, returning
//!   `403 AccessDenied` on mismatch while a missing bucket yields `404 NoSuchBucket`.
//! - <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html>: `CopyObject` accepts
//!   both `x-amz-expected-bucket-owner` for the destination bucket and
//!   `x-amz-source-expected-bucket-owner` for the source bucket, rejecting mismatches with
//!   `403 AccessDenied`.
//! - <https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html>: S3 defines `NoSuchBucket`
//!   as `404` for an absent bucket and `InternalError` as a retryable `500` server-side failure.

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_types::BucketName;
use std::sync::Arc;

/// Supplies the actual owner account id for one bucket.
///
/// The value is opaque because S3-compatible deployments need not use AWS's twelve-digit account
/// ids. It is compared byte-for-byte with `x-amz-expected-bucket-owner` (and
/// `x-amz-source-expected-bucket-owner` on copy requests) and is never written to a response or
/// log.
pub trait BucketOwnerSource: Send + Sync + 'static {
    /// Looks up the actual owner of `bucket`.
    ///
    /// Called only after authorization has allowed the request on `bucket`. An empty owner string
    /// or [`BucketOwnerError::unavailable`] fails closed as `403 AccessDenied`;
    /// [`BucketOwnerError::not_found`] answers `404 NoSuchBucket` (or bodyless `404` on `HEAD`);
    /// [`BucketOwnerError::backend_failure`] answers retryable `500 InternalError`. An error is
    /// never treated as a matching owner.
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>>;
}

impl<T: BucketOwnerSource + ?Sized> BucketOwnerSource for Arc<T> {
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        (**self).owner(bucket)
    }
}

/// Closed reason [`BucketOwnerSource::owner`] could not produce a bucket owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BucketOwnerErrorKind {
    /// No trustworthy owner source is available; fails closed as `403 AccessDenied`.
    Unavailable,
    /// The addressed bucket does not exist; maps to `404 NoSuchBucket` once authorized.
    NotFound,
    /// The bucket metadata store failed to answer; maps to retryable `500 InternalError`.
    Backend,
}

/// The bucket-owner source could not produce a trustworthy answer.
///
/// Deliberately carries no bucket name, owner id or backend message: those values must not become
/// reachable from a generic error formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketOwnerError(BucketOwnerErrorKind);

impl BucketOwnerError {
    /// The source was unavailable or had no trustworthy owner for the bucket.
    ///
    /// Fails closed as `403 AccessDenied`.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self(BucketOwnerErrorKind::Unavailable)
    }

    /// The addressed bucket does not exist.
    ///
    /// Answered `404 NoSuchBucket` (or bodyless `404` on `HEAD`) only after authorization has
    /// already allowed the request on that bucket, preventing unprivileged bucket-existence
    /// probing.
    #[must_use]
    pub const fn not_found() -> Self {
        Self(BucketOwnerErrorKind::NotFound)
    }

    /// The deployment's bucket metadata backend failed to answer.
    ///
    /// Answered retryable `500 InternalError` with a static gateway sentence so SDKs can back off
    /// and retry rather than treating a transient metadata outage as a terminal `403`.
    #[must_use]
    pub const fn backend_failure() -> Self {
        Self(BucketOwnerErrorKind::Backend)
    }

    /// The closed error kind interpreted by `crate::service::bucket_owner`.
    #[must_use]
    pub(crate) const fn kind(self) -> BucketOwnerErrorKind {
        self.0
    }
}

impl core::fmt::Display for BucketOwnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self.0 {
            BucketOwnerErrorKind::Unavailable => "bucket owner unavailable",
            BucketOwnerErrorKind::NotFound => "bucket not found",
            BucketOwnerErrorKind::Backend => "bucket owner lookup failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for BucketOwnerError {}

/// The safe default: an absent owner source never validates a presented assertion.
///
/// # Security
///
/// Default construction fails closed whenever the request presents an expected-owner assertion;
/// requests without that header do not consult this source.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoBucketOwner;

impl BucketOwnerSource for NoBucketOwner {
    fn owner<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        Box::pin(async { Err(BucketOwnerError::unavailable()) })
    }
}

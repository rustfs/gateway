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
//! opaque [`BucketOwnerError`] returned when the deployment cannot answer.
//! NOT responsible for: authorizing an S3 action (`super::Authorizer`), decoding operation input,
//! or deciding which path segment is the bucket (`super::HostResolver`).
//! Upstream: the deployment's bucket metadata. Downstream: `crate::service` before request-body
//! ingestion and handler dispatch.

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_types::BucketName;
use std::sync::Arc;

/// Supplies the actual owner account id for one bucket.
///
/// The value is opaque because S3-compatible deployments need not use AWS's twelve-digit account
/// ids. It is compared byte-for-byte with `x-amz-expected-bucket-owner` and is never written to a
/// response or log.
pub trait BucketOwnerSource: Send + Sync + 'static {
    /// Looks up the actual owner of `bucket`.
    ///
    /// An error fails closed as `403 AccessDenied`; it is never treated as a matching owner.
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>>;
}

impl<T: BucketOwnerSource + ?Sized> BucketOwnerSource for Arc<T> {
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        (**self).owner(bucket)
    }
}

/// The bucket-owner source could not produce a trustworthy answer.
///
/// Deliberately carries no bucket name, owner id or backend message: those values must not become
/// reachable from a generic error formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketOwnerError;

impl BucketOwnerError {
    /// The source was unavailable or had no trustworthy owner for the bucket.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self
    }
}

impl core::fmt::Display for BucketOwnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("bucket owner unavailable")
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

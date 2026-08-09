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

//! The one opaque policy reading shared by every authorization stage in a request.
//!
//! Responsible for: [`PolicySnapshot`], [`PolicySource`], and the safe empty default.
//! NOT responsible for: interpreting policy; deployments own that language and payload.
//! Upstream: authenticated identity. Downstream: `crate::service` and [`super::Authorizer`].

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::Identity;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Identifies one policy read. Clones retain the same identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SnapshotId(u64);

impl SnapshotId {
    /// The process-local identity of this read.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One opaque, request-scoped policy read.
#[derive(Clone)]
pub struct PolicySnapshot {
    id: SnapshotId,
    payload: Option<Arc<dyn Any + Send + Sync>>,
}

impl PolicySnapshot {
    /// Wraps a deployment-owned policy value.
    #[must_use]
    pub fn of(payload: Arc<dyn Any + Send + Sync>) -> Self {
        Self {
            id: SnapshotId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            payload: Some(payload),
        }
    }

    /// Produces an empty but uniquely identified reading.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            id: SnapshotId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            payload: None,
        }
    }

    /// Identifies this reading.
    #[must_use]
    pub const fn id(&self) -> SnapshotId {
        self.id
    }

    /// Downcasts the deployment-owned payload without panicking.
    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.payload.as_ref()?.downcast_ref::<T>()
    }
}

impl core::fmt::Debug for PolicySnapshot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PolicySnapshot")
            .field("id", &self.id)
            .field("empty", &self.payload.is_none())
            .finish()
    }
}

/// A non-secret reason a policy read failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyError(&'static str);

impl PolicyError {
    /// The source could not answer.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self("unavailable")
    }

    /// A stable operator-side label.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.0
    }
}

/// Produces exactly one policy reading for a request.
pub trait PolicySource: Send + Sync + 'static {
    /// Reads policy after authentication and before the first authorization stage.
    fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>>;
}

impl<T: PolicySource + ?Sized> PolicySource for Arc<T> {
    fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        (**self).snapshot(identity)
    }
}

/// The default source: one empty reading per request.
pub struct NoPolicy;

impl PolicySource for NoPolicy {
    fn snapshot<'a>(&'a self, _identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        Box::pin(async { Ok(PolicySnapshot::empty()) })
    }
}

/// Adapts a synchronous policy reader.
#[must_use]
pub fn policy_from<F>(read: F) -> impl PolicySource
where
    F: Fn(Option<&Identity>) -> Result<PolicySnapshot, PolicyError> + Send + Sync + 'static,
{
    struct Source<F>(F);

    impl<F> PolicySource for Source<F>
    where
        F: Fn(Option<&Identity>) -> Result<PolicySnapshot, PolicyError> + Send + Sync + 'static,
    {
        fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
            let result = (self.0)(identity);
            Box::pin(async move { result })
        }
    }

    Source(read)
}

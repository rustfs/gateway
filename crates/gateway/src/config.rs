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

//! Hot service configuration, its update handle, and one immutable request snapshot.
//!
//! Responsible for: replacing configuration atomically between requests while keeping one
//! [`ConfigSnapshot`] alive for the whole request.
//! NOT responsible for: deciding where a setting applies; the pipeline consumes the snapshot.
//! Upstream: [`crate::ServiceBuilder`]. Downstream: [`crate::S3Service`].

use std::sync::Arc;

use arc_swap::ArcSwap;

/// Settings that may be replaced without rebuilding the service.
///
/// There is deliberately no `Default`: the buffered-body ceiling is a memory-safety posture a
/// deployment should either inherit from [`crate::ServiceBuilder`] or spell explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    max_buffered_body_bytes: u64,
}

impl ServiceConfig {
    /// Creates a configuration with an explicit in-memory request-body ceiling.
    #[must_use]
    pub const fn new(max_buffered_body_bytes: u64) -> Self {
        Self { max_buffered_body_bytes }
    }

    /// The most wire-body bytes one request may retain in memory.
    #[must_use]
    pub const fn max_buffered_body_bytes(&self) -> u64 {
        self.max_buffered_body_bytes
    }
}

/// The immutable configuration one request observes.
pub type ConfigSnapshot = Arc<ServiceConfig>;

pub(crate) type ConfigStore = Arc<ArcSwap<ServiceConfig>>;

/// Replaces the configuration observed by requests that start after the update.
///
/// Clones share the same atomic store. An in-flight request retains its earlier
/// [`ConfigSnapshot`], so a replacement cannot change policy halfway through that request.
#[derive(Clone)]
pub struct ConfigHandle {
    store: ConfigStore,
}

impl ConfigHandle {
    pub(crate) fn new(store: &ConfigStore) -> Self {
        Self {
            store: Arc::clone(store),
        }
    }

    /// Atomically replaces the configuration for requests that have not started yet.
    pub fn store(&self, config: ServiceConfig) {
        self.store.store(Arc::new(config));
    }
}

impl core::fmt::Debug for ConfigHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigHandle").finish_non_exhaustive()
    }
}

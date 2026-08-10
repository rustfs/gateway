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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::request_config::RequestConfig;

    /// a-asm-0006. Every real pipeline stage consumes the same request snapshot; replacing the
    /// store after entry must not create a second `Arc` anywhere in that chain.
    #[test]
    fn all_eight_pipeline_stages_share_one_arc() {
        let store = Arc::new(ArcSwap::from_pointee(ServiceConfig::new(8)));
        let handle = ConfigHandle::new(&store);
        let entry = store.load_full();
        let mut seen = Vec::new();

        let accepted = RequestConfig::enter(Arc::clone(&entry)).accepted();
        seen.push(Arc::clone(accepted.config()));
        let routed = accepted.routed();
        seen.push(Arc::clone(routed.config()));
        let governed = routed.governed();
        seen.push(Arc::clone(governed.config()));
        handle.store(ServiceConfig::new(16));
        assert!(!Arc::ptr_eq(&entry, &store.load_full()), "the mid-request replacement did not happen");
        let authenticated = governed.authenticated();
        seen.push(Arc::clone(authenticated.config()));
        let route_authorized = authenticated.route_authorized();
        seen.push(Arc::clone(route_authorized.config()));
        let body_read = route_authorized.body_read();
        seen.push(Arc::clone(body_read.config()));
        let decoded = body_read.decoded();
        seen.push(Arc::clone(decoded.config()));
        let input_authorized = decoded.input_authorized();
        seen.push(Arc::clone(input_authorized.config()));

        assert_eq!(seen.len(), 8);
        for snapshot in seen {
            assert!(Arc::ptr_eq(&entry, &snapshot));
        }
    }
}

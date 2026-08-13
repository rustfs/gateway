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

//! Hot configuration and immutable request snapshots. Responsible for: atomic replacement and snapshot lifetime.
//! NOT responsible for: applying policy inside pipeline stages.
//! Upstream: [`crate::ServiceBuilder`]. Downstream: [`crate::S3Service`].

use std::sync::Arc;

use arc_swap::ArcSwap;

/// Replaceable request settings; no `Default` leaves the memory ceiling explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    max_buffered_body_bytes: u64,
    verbose_signature_errors: bool,
}

impl ServiceConfig {
    /// Creates configuration with an explicit in-memory request-body ceiling.
    #[must_use]
    pub const fn new(max_buffered_body_bytes: u64) -> Self {
        Self {
            max_buffered_body_bytes,
            verbose_signature_errors: false,
        }
    }

    /// The most wire-body bytes one request may retain in memory.
    #[must_use]
    pub const fn max_buffered_body_bytes(&self) -> u64 {
        self.max_buffered_body_bytes
    }
}

/// One request's immutable configuration.
pub type ConfigSnapshot = Arc<ServiceConfig>;

pub(crate) type ConfigStore = Arc<ArcSwap<ServiceConfig>>;

/// Replaces configuration between requests; in-flight requests retain their snapshot.
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

    /// Replaces configuration for requests that have not started.
    pub fn store(&self, config: ServiceConfig) {
        self.store.store(Arc::new(config));
    }
}

impl core::fmt::Debug for ConfigHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigHandle").finish_non_exhaustive()
    }
}

impl ServiceConfig {
    /// Permits redacted mismatch details. Default: off.
    #[must_use]
    pub const fn with_verbose_signature_errors(mut self, enabled: bool) -> Self {
        self.verbose_signature_errors = enabled;
        self
    }

    /// Whether mismatch responses may carry redacted details.
    #[must_use]
    pub const fn verbose_signature_errors(&self) -> bool {
        self.verbose_signature_errors
    }
}

#[cfg(test)]
fn load_entry(store: &ConfigStore) -> ConfigSnapshot {
    store.load_full()
}

#[cfg(test)]
fn load_replacement(store: &ConfigStore) -> ConfigSnapshot {
    // A distinct helper keeps both allowlisted test loads explicit.
    // Production still performs its sole load at request entry.
    // The allowlist tracks these calls as guard fixtures.
    // Keeping both calls visible makes a second load detectable.

    store.load_full()
}

// Explicit loads let the guard detect new hot loads; production loads once at entry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_config::RequestConfig;

    // a-asm-0006: stable load anchors prove replacement cannot split the entry snapshot.
    #[test]
    fn all_eight_pipeline_stages_share_one_arc() {
        let store = Arc::new(ArcSwap::from_pointee(ServiceConfig::new(8)));
        let handle = ConfigHandle::new(&store);
        let entry = load_entry(&store);
        let mut seen = Vec::new();

        let accepted = RequestConfig::enter(Arc::clone(&entry)).accepted();
        seen.push(Arc::clone(accepted.config()));
        let routed = accepted.routed();
        seen.push(Arc::clone(routed.config()));
        let governed = routed.governed();
        seen.push(Arc::clone(governed.config()));
        handle.store(ServiceConfig::new(16));
        let replacement = load_replacement(&store);
        assert!(!Arc::ptr_eq(&entry, &replacement), "the mid-request replacement did not happen");
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

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

//! Publishes validated routing and middleware replacements into the existing service store.
//!
//! Responsible for: atomic replacements and releasing middleware after the last service drops,
//! while preserving concurrent request-setting updates. NOT responsible for: validation or request capture.
//! Upstream: `ServiceBuilder` and `AssemblyUpdate`. Downstream: the live service's configuration.

use std::sync::Arc;

use crate::config::AssemblySnapshot;
use crate::routing::RuntimeAssembly;
use crate::{AssemblyError, AssemblyUpdate, ServiceBuilder};

use super::{Inner, S3Service};

impl Drop for Inner {
    fn drop(&mut self) {
        // A filter may own a ConfigHandle. Break that ownership cycle only when no service clone
        // remains; detached handles keep their settings store and old request snapshots stay owned.
        self.config.rcu(|current| {
            Arc::new(AssemblySnapshot {
                config: Arc::clone(&current.config),
                runtime: None,
            })
        });
    }
}

impl S3Service {
    /// Atomically replaces this service's routes, codecs, handlers, and operation layers.
    ///
    /// The candidate builder is consumed, and only its dialect routes, operation registrations,
    /// codecs, and operation layers participate in the replacement. The live service deliberately
    /// retains its authenticator, authorizer, filters, limits, request configuration, and all other
    /// deployment extension points. Every clone observes the same validated generation, while a
    /// request already in flight keeps the generation it loaded at entry.
    ///
    /// Candidate validation does not emit startup or security-posture logs. The atomic store is
    /// changed only after the candidate route and dispatch tables agree.
    ///
    /// # Errors
    ///
    /// Returns [`AssemblyError`] when the candidate registry is empty, has an unattached operation
    /// layer, contains conflicting routes, or cannot build a matching codec/handler dispatch table.
    /// The last-good generation remains installed on every error.
    pub fn replace_registry(&self, builder: ServiceBuilder) -> Result<(), AssemblyError> {
        let routing = Arc::new(builder.into_routing()?);
        self.inner.config.rcu(|current| {
            Arc::new(AssemblySnapshot {
                config: Arc::clone(&current.config),
                runtime: Some(Arc::new(RuntimeAssembly {
                    routing: Arc::clone(&routing),
                    ..current.runtime().as_ref().clone()
                })),
            })
        });
        Ok(())
    }

    /// Atomically replaces the validated request settings, registry, and middleware.
    ///
    /// The complete candidate includes its authorizer, policy source and timeout, audit sink,
    /// stage filters, operation layers, and observer. Validation uses the initial assembly rules;
    /// every service clone sees the new generation together, and in-flight requests keep the one
    /// they captured at entry. Existing configuration handles continue updating this same store.
    ///
    /// [`AssemblyUpdate`] exposes only replaceable fields. Authentication, security floors,
    /// admission, and other fixed host settings continue to belong to the initial service builder.
    /// Use [`Self::replace_registry`] to update only the operation registry.
    ///
    /// # Errors
    ///
    /// Returns [`AssemblyError`] for an invalid candidate, preserving the installed assembly.
    pub fn replace_assembly(&self, update: AssemblyUpdate) -> Result<(), AssemblyError> {
        let snapshot = update.into_snapshot()?;
        self.inner.config.store(Arc::new(snapshot));
        Ok(())
    }
}

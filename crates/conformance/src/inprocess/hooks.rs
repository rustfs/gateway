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

//! Every counter the in-process target's own service increments for `finish` to judge.
//!
//! Responsible for: holding those counters in one place, and [`HookCounters::all`], which
//! destructures the struct without `..` so a counter added here cannot compile without joining
//! the list that resets them and that the census perturbs.
//! NOT responsible for: incrementing (the layers and providers `super` installs) or judging
//! (`super::InProcess::finish`). Upstream: `super`; downstream: nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
pub(super) struct HookCounters {
    /// Copy-backend and ListObjectVersions dispatches.
    pub(super) authz_backend: Arc<AtomicUsize>,
    /// Credential-provider lookups.
    pub(super) credential_backend: Arc<AtomicUsize>,
    /// Exchanges of the credential-flood case.
    pub(super) credential_exchanges: Arc<AtomicUsize>,
    /// The governor's credential-lookup classifications.
    pub(super) credential_governor: Arc<AtomicUsize>,
}

impl HookCounters {
    /// Every counter, so none can be left out of a reset or a census.
    pub(super) fn all(&self) -> [&Arc<AtomicUsize>; 4] {
        let Self {
            authz_backend,
            credential_backend,
            credential_exchanges,
            credential_governor,
        } = self;
        [authz_backend, credential_backend, credential_exchanges, credential_governor]
    }

    pub(super) fn reset(&self) {
        for counter in self.all() {
            counter.store(0, Ordering::SeqCst);
        }
    }
}

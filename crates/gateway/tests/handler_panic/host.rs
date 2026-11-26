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

//! A synchronous host resolver fixture that panics once in each `HostResolver` hook.
//!
//! Responsible for: providing `PanickingResolver` in a pure synchronous module so
//! `scripts/check_resolver_pure.sh` continues to guard every file implementing `HostResolver`
//! against any `async`/`.await`.
//! NOT responsible for: real virtual-host resolution (`VirtualHostStyle`) or async assertions
//! (`tests/handler_panic.rs`).
//! Upstream: `rustfs-gateway`. Downstream: `tests/handler_panic.rs`.

#![allow(clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{HostQuery, HostRefusal, HostResolver, PathStyleOnly, ResolvedHost};

/// Panics on call 1 in `resolve`, call 2 in `signing_bucket`, call 3 in `refusal`, then recovers.
pub(super) struct PanickingResolver {
    calls: AtomicUsize,
}

impl PanickingResolver {
    /// Creates a fresh panicking resolver starting at step zero.
    pub(super) const fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl HostResolver for PanickingResolver {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("host_resolver resolve panic fixture");
        }
        PathStyleOnly.resolve(query)
    }

    fn signing_bucket(&self, _query: &HostQuery<'_>, _resolved: &ResolvedHost) -> Option<String> {
        if self.calls.load(Ordering::SeqCst) == 2 {
            panic!("host_resolver signing_bucket panic fixture");
        }
        None
    }

    fn refusal(&self, _query: &HostQuery<'_>) -> Option<HostRefusal> {
        if self.calls.load(Ordering::SeqCst) == 3 {
            panic!("host_resolver refusal panic fixture");
        }
        None
    }
}

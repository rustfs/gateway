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

//! The gateway side's host resolver: path-style, or broken on purpose.
//!
//! Responsible for: classifying a request path-style exactly as `PathStyleOnly` does, and — under
//! the misroute fault — reading every object path as a bucket path, the defect a host resolver can
//! have, so the real route table then picks another operation.
//! NOT responsible for: anything asynchronous; a resolver answers before authentication and this
//! file holds nothing that awaits (`scripts/check_resolver_pure.sh`).
//! Upstream: `rustfs-gateway`'s `PathStyleOnly`. Downstream: `gateway.rs`.

use rustfs_gateway::{HostQuery, HostResolver, PathStyleOnly, ResolvedHost};
use rustfs_gateway_core::route::TargetKind;

/// Path-style resolution, or — when misrouting — a resolver that reads every object path as a
/// bucket path, the defect a host resolver can have.
#[derive(Clone, Copy)]
pub(crate) struct Resolver {
    misroute: bool,
}

impl HostResolver for Resolver {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        let mut resolved = PathStyleOnly.resolve(query);
        if self.misroute && resolved.target == TargetKind::Object {
            resolved.target = TargetKind::Bucket;
        }
        resolved
    }
}

impl Resolver {
    pub(crate) const fn new(misroute: bool) -> Self {
        Self { misroute }
    }
}

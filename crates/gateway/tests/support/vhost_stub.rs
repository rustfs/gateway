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

//! A host resolver that answers "the host named the bucket" for every request.
//!
//! Responsible for: one fixture, so that a suite can assert the *other* value of
//! `TargetOrigin` without configuring a base domain and a bucket-shaped route.
//! NOT responsible for: resolving anything realistically. `VirtualHostStyle` is the resolver a
//! deployment installs and `tests/vhost_resolution.rs` is where its behaviour is pinned.
//! Upstream: `rustfs-gateway`. Downstream: `tests/authz_contract.rs`.
//!
//! # Why this is its own file
//!
//! `scripts/check_resolver_pure.sh` guards every file that implements [`HostResolver`], and its
//! "nothing here awaits" rule reads the whole file rather than the `impl` block — deliberately,
//! because a resolver's purity is a property of what it can reach and not only of what it writes.
//! A resolver declared inside an `async` test suite would put forty `.await`s in a guarded file
//! and force the guard to be narrowed. Keeping the fixture here keeps the guard as strict as it
//! was written to be.

use rustfs_gateway::{BucketName, HostQuery, HostResolver, ResolvedHost, TargetKind};

/// The bucket this resolver claims the host named.
pub const HOST_NAMED_BUCKET: &str = "named-by-the-host";

/// Claims every request named its bucket in the host.
///
/// The target stays [`TargetKind::Service`] so that a service-shaped fixture operation still
/// routes: the suite using this is about where a name came from, and nothing else about virtual
/// hosting.
pub struct AlwaysVirtualHosted;

impl HostResolver for AlwaysVirtualHosted {
    fn resolve(&self, _query: &HostQuery<'_>) -> ResolvedHost {
        ResolvedHost::virtual_hosted(
            TargetKind::Service,
            BucketName::new(HOST_NAMED_BUCKET).expect("a valid bucket name"),
            None,
        )
    }
}

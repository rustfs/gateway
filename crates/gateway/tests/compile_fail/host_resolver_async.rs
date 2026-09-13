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

//! Responsible for: rejecting an asynchronous host resolver at the public trait boundary.
//! NOT responsible for: host matching or runtime I/O.
//! Upstream: the gateway compile-fail suite. Downstream: the Rust compiler diagnostic.

use rustfs_gateway::{HostQuery, HostResolver, ResolvedHost, TargetKind};

struct AsyncResolver;

impl HostResolver for AsyncResolver {
    async fn resolve(&self, _query: &HostQuery<'_>) -> ResolvedHost {
        ResolvedHost::standard(TargetKind::Service)
    }
}

fn main() {}

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

//! The synchronous host-resolution marker used by the aggregate assembly-order test.
//!
//! Responsible for: recording the host stage and forwarding to the path-style resolver.
//! NOT responsible for: asserting the complete request order.
//! Upstream: `assembly_order.rs`. Downstream: `rustfs_gateway::PathStyleOnly`.

use std::sync::{Arc, Mutex};

use rustfs_gateway::{HostQuery, HostResolver, PathStyleOnly, ResolvedHost};

pub(super) struct RecordingHost {
    trail: Arc<Mutex<Vec<&'static str>>>,
}

impl RecordingHost {
    pub(super) fn new(trail: &Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            trail: Arc::clone(trail),
        }
    }
}

impl HostResolver for RecordingHost {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        self.trail.lock().expect("not poisoned").push("host");
        PathStyleOnly.resolve(query)
    }
}

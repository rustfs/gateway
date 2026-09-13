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

//! c-mw-0018: a routed filter cannot rewrite the bucket or key.
//!
//! Responsible for: pinning that the target decided by the single normalisation has no second
//! producer at the routed seam.
//! NOT responsible for: what the routed seam may read, which `tests/middleware.rs` covers.
//! Upstream: the public `RoutedView` type. Downstream: the gateway compile-fail harness.

use rustfs_gateway::{HandlerError, RoutedView, StageFilter};

struct Retarget;

impl StageFilter for Retarget {
    fn on_routed(&self, routed: &RoutedView<'_>) -> Result<(), HandlerError> {
        routed.bucket = None;
        routed.key = None;
        Ok(())
    }
}

fn main() {}

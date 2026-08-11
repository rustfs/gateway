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

//! Compile-fail boundary for resolved response fields.
//!
//! Responsible for: proving downstream code cannot mint an already resolved response shape.
//! NOT responsible for: selecting or rendering an error response.
//! Upstream: `rustfs_gateway_core::ErrorResolution`. Downstream: external response adapters.

use http::StatusCode;
use rustfs_gateway_core::{BodyPolicy, ErrorResolution};

fn main() {
    let _resolution = ErrorResolution {
        status: StatusCode::OK,
        code: None,
        body_policy: BodyPolicy::None,
        message: None,
        headers: Vec::new(),
        details: Vec::new(),
        etag: None,
        resource: None,
    };
}

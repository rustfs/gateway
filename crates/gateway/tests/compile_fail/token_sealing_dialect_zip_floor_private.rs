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

//! ADR-0056: `rustfs_gateway_dialect_rustfs_admin::admin::zip_token_floor` is crate-private.
//!
//! Responsible for: proving external crates cannot mint bearer-claimed floors via `admin::zip_token_floor`.
//! NOT responsible for: dialect routing.
//! Upstream: `rustfs_gateway_dialect_rustfs_admin::admin`. Downstream: trybuild gate.

fn main() {
    let _ = rustfs_gateway_dialect_rustfs_admin::admin::zip_token_floor("a:B");
}

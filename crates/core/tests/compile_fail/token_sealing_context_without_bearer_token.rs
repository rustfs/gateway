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

//! ADR-0056: `RequestContextView::without_bearer_token` is not a public inherent method.
//!
//! Responsible for: proving host code cannot mutate a `RequestContextView` via `without_bearer_token`.
//! NOT responsible for: runtime query stripping.
//! Upstream: `rustfs_gateway_core::RequestContextView`. Downstream: trybuild gate.

use rustfs_gateway_core::RequestContextView;
use rustfs_gateway_sig::QueryBearerClaim;

fn strip(context: RequestContextView, claim: QueryBearerClaim) -> RequestContextView {
    context.without_bearer_token(claim)
}

fn main() {}

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

//! ADR-0056: `OperationFloor::with_query_bearer_claim` is not a public inherent method.
//!
//! Responsible for: proving host code cannot attach a `QueryBearerClaim` to an arbitrary `OperationFloor`.
//! NOT responsible for: runtime floor admission.
//! Upstream: `rustfs_gateway_sig::OperationFloor`. Downstream: trybuild gate.

use rustfs_gateway_sig::{OperationFloor, QueryBearerClaim, SigService};

fn main() {
    let claim = QueryBearerClaim::new("token", ".zip");
    let _ = OperationFloor::custom("a:B", SigService::S3).with_query_bearer_claim(claim);
}

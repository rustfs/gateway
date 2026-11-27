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

//! ADR-0056: `RequestContextView::with_bearer_receipt` is not a public inherent method.
//!
//! Responsible for: proving host code cannot attach a `BearerReceipt` to a `RequestContextView`.
//! NOT responsible for: runtime context construction.
//! Upstream: `rustfs_gateway_core::RequestContextView`. Downstream: trybuild gate.

use rustfs_gateway_core::RequestContextView;
use rustfs_gateway_sig::BearerReceipt;

fn attach(context: RequestContextView, receipt: &BearerReceipt) -> RequestContextView {
    context.with_bearer_receipt(receipt)
}

fn main() {}

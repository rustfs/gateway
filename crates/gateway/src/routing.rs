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

//! One atomic routing and operation-dispatch generation.
//!
//! Responsible for: keeping the route resolver and its codec/handler dispatch table in one
//! replaceable snapshot. NOT responsible for: validating either table, request configuration, or
//! deployment extension points. Upstream: `crate::builder`. Downstream: `crate::service`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustfs_gateway_core::Router;

use crate::dispatch::DispatchTable;

/// The two tables that must describe one registry generation.
pub(crate) struct RoutingSnapshot {
    pub(crate) router: Router,
    pub(crate) dispatch: DispatchTable,
}

/// The shared atomic store held by every clone of an assembled service.
pub(crate) type RoutingStore = Arc<ArcSwap<RoutingSnapshot>>;

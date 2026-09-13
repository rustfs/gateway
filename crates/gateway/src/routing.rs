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

//! Immutable routing and middleware generations captured together at request entry.
//!
//! Responsible for: keeping the route resolver, codec/handler dispatch table, and middleware in
//! one request generation. NOT responsible for: validation, mutable storage, or request settings.
//! Upstream: `crate::builder` and `crate::config`. Downstream: `crate::service`.

use std::sync::Arc;

use rustfs_gateway_core::Router;

use crate::dispatch::DispatchTable;
use crate::ext::{Authorizer, AuthzAuditSink, Observer, PolicySource, PolicyTimeout, StageFilter};

/// The two tables that must describe one registry generation.
pub(crate) struct RoutingSnapshot {
    pub(crate) router: Router,
    pub(crate) dispatch: DispatchTable,
}

/// The replaceable extension points and operation tables used by one request.
#[derive(Clone)]
pub(crate) struct RuntimeAssembly {
    pub(crate) routing: Arc<RoutingSnapshot>,
    pub(crate) filters: Arc<[Arc<dyn StageFilter>]>,
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) policy_source: Arc<dyn PolicySource>,
    pub(crate) policy_timeout: PolicyTimeout,
    pub(crate) authz_audit: Arc<dyn AuthzAuditSink>,
    pub(crate) observer: Arc<dyn Observer>,
}

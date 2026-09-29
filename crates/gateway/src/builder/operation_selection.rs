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

//! The RustFS profile's operation selection (rustfs/gateway#1127): the one builder switch that
//! chooses the operation a request names as legacy RustFS does.
//!
//! Responsible for: [`ServiceBuilder::select_operations_as_legacy_rustfs`].
//! NOT responsible for: the order itself ([`rustfs_gateway_core::route::legacy_rustfs_selection`]),
//! or where the router applies it ([`rustfs_gateway_core::Router::dispatch`]).
//! Upstream: `super::ServiceBuilder`. Downstream: the router every request outside a dialect's
//! claim is dispatched by.

use rustfs_gateway_core::route::Selection;

use super::ServiceBuilder;

impl ServiceBuilder {
    /// Chooses the operation a request names as legacy RustFS does, for a deployment in front of
    /// RustFS.
    ///
    /// An `x-id` named exactly once is the operation, among the operations of the request's
    /// method and target, whatever else the query names; one named twice, naming no operation,
    /// or naming one of another method or target is `400 InvalidRequest`. Without it, the first
    /// present operation key in legacy RustFS's order per method and target wins. A request inside
    /// a dialect's claim is routed by the dialect, and a browser-form `POST` to a bucket is
    /// `PostObject`, as on legacy RustFS.
    ///
    /// Off by default: the route table's own precedences choose.
    #[must_use]
    pub fn select_operations_as_legacy_rustfs(mut self) -> Self {
        self.router = self.router.selecting(Selection::RustfsLegacy);
        self
    }
}

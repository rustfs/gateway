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

//! What each generated operation was generated from, and what is not migrated yet.
//!
//! Responsible for: the shapes of [`crate::ROUTES`] and [`crate::PENDING`] — the inventory facts
//! behind each declared operation, and the registration groups still served by RustFS.
//! NOT responsible for: the values (the generated `crate::table`), or checking them against the
//! inventory (`rustfs-gateway-goldens` and this crate's tests do).
//! Upstream: nothing. Downstream: `crate::table`, the tests, and a deployment that reports which
//! admin routes the gateway serves.

/// The migration issue, which every overlay row cites.
pub(crate) const ISSUE: &str = "https://github.com/rustfs/backlog/issues/1744";

/// ADR-0025, which every row whose action is a ruling cites.
pub(crate) const ADR_0025: &str = "https://github.com/rustfs/gateway/blob/main/docs/adr/0025-admin-authorization-classes.md";

/// ADR-0027, which every row with a path parameter or a shadowing declaration cites.
pub(crate) const ADR_0027: &str =
    "https://github.com/rustfs/gateway/blob/main/docs/adr/0027-service-level-admin-template-parameters.md";

/// How RustFS reads or writes one side of a route's body, as the inventory records it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyKind {
    /// No body is read.
    NotRead,
    /// The whole body is buffered before the handler runs.
    Buffered,
    /// The body is streamed.
    Streamed,
    /// The body is handed on unread to another component.
    HandedOn,
}

/// One declared operation and the inventory row it was generated from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRecord {
    /// The operation name, `rustfs:…`.
    pub operation: &'static str,
    /// The ADR-0024 registration group.
    pub group: &'static str,
    /// The group's order in ADR-0024's migration plan.
    pub order: u8,
    /// The method.
    pub method: &'static str,
    /// The canonical path, under `/rustfs/admin`.
    pub path: &'static str,
    /// The MinIO alias, under `/minio/admin`, when RustFS serves one.
    pub alias: Option<&'static str>,
    /// The query key and value that select this operation, when one route is split by its query.
    pub query: Option<(&'static str, &'static str)>,
    /// The action rule, rendered as the overlay records it.
    pub action: &'static str,
    /// The inventory's custom-auth class, when the action is ADR-0025's ruling rather than the
    /// inventory's own action.
    pub ruled: Option<&'static str>,
    /// The RustFS handler the inventory names.
    pub rustfs_handler: &'static str,
    /// How RustFS reads the request body.
    pub request_body: BodyKind,
    /// How RustFS writes the response body.
    pub response_body: BodyKind,
    /// Whether the handler is handed the caller's secret.
    pub caller_secret: bool,
}

/// A registration group whose routes RustFS still serves itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingGroup {
    /// The ADR-0024 registration group.
    pub group: &'static str,
    /// Its order in ADR-0024's migration plan.
    pub order: u8,
    /// How many inventory routes it has.
    pub routes: u16,
}

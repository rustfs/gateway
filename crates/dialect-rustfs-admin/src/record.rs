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

use rustfs_gateway_core::SubjectRule;
use rustfs_gateway_core::dialect::BucketParam;

/// The migration issue, which every overlay row cites.
pub(crate) const ISSUE: &str = "https://github.com/rustfs/backlog/issues/1744";

/// ADR-0025, which every row whose action is a ruling cites.
pub(crate) const ADR_0025: &str = "https://github.com/rustfs/gateway/blob/main/docs/adr/0025-admin-authorization-classes.md";

/// ADR-0026, which every row about a set of accounts cites.
pub(crate) const ADR_0026: &str =
    "https://github.com/rustfs/gateway/blob/main/docs/adr/0026-account-sets-query-buckets-and-anonymous-bootstrap.md";

/// ADR-0027, which every row with a path parameter or a shadowing declaration cites.
pub(crate) const ADR_0027: &str =
    "https://github.com/rustfs/gateway/blob/main/docs/adr/0027-service-level-admin-template-parameters.md";

/// ADR-0028, which every row with a subject rule cites.
pub(crate) const ADR_0028: &str = "https://github.com/rustfs/gateway/blob/main/docs/adr/0028-order-four-admin-subject-rules.md";

/// ADR-0030, which every row that binds its bucket, and the trailing-slash heal row, cite.
pub(crate) const ADR_0030: &str = "https://github.com/rustfs/gateway/blob/main/docs/adr/0030-order-five-admin-bound-buckets.md";

/// ADR-0032, which every anonymous bootstrap row and every `/profile` row cites.
pub(crate) const ADR_0032: &str =
    "https://github.com/rustfs/gateway/blob/main/docs/adr/0032-last-admin-orders-anonymous-bootstrap-and-staying-routes.md";

/// ADR-0031, which every table-catalog row cites: the surface's claims, its compat alias rows,
/// and the first-divergence shadowing rule.
pub(crate) const ADR_0031: &str = "https://github.com/rustfs/gateway/blob/main/docs/adr/0031-order-six-table-catalog-surfaces.md";

/// ADR-0036, which every row that ends in a catch-all cites.
pub(crate) const ADR_0036: &str =
    "https://github.com/rustfs/gateway/blob/main/docs/adr/0036-a-trailing-catch-all-template-parameter.md";

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
    /// The canonical path, under `/rustfs/admin` or `/_iceberg/v1`.
    pub path: &'static str,
    /// The compat row RustFS serves the same route under, when it does: the MinIO alias under
    /// `/minio/admin`, or the table catalog's `/iceberg/v1` twin (ADR-0024 (c), ADR-0031 (b)).
    pub alias: Option<&'static str>,
    /// The query key and value that select this operation, when one route is split by its query.
    pub query: Option<(&'static str, &'static str)>,
    /// The action rule, rendered as the overlay records it.
    pub action: &'static str,
    /// The inventory's custom-auth class, when the action is ADR-0025's ruling rather than the
    /// inventory's own action.
    pub ruled: Option<&'static str>,
    /// Whose account the operation acts on, when that is part of its authorisation: the caller's
    /// own, one named in the query, or a set (ADR-0025, ADR-0026, ADR-0028). The same rule the
    /// operation's `AuthRequirement` carries.
    pub subject: Option<SubjectRule>,
    /// The bucket the operation is authorised on, when it has one: the `{bucket}` template
    /// parameter every row carries (ADR-0025 (c)), or a query parameter read exactly once
    /// (ADR-0026 (e)); `None` for a service-level operation (ADR-0024 (e), ADR-0027). The same
    /// binding the operation's `ClaimedRoute` carries (ADR-0030).
    pub bucket: Option<BucketParam>,
    /// Whether the operation admits anonymous requests, which only RustFS's OIDC bootstrap routes
    /// do (ADR-0026 (f), ADR-0032). The same fact the operation's floor and overlay row carry.
    pub anonymous: bool,
    /// The RustFS handler the inventory names.
    pub rustfs_handler: &'static str,
    /// How RustFS reads the request body.
    pub request_body: BodyKind,
    /// How RustFS writes the response body.
    pub response_body: BodyKind,
    /// Whether the handler is handed the caller's secret.
    pub caller_secret: bool,
}

/// A route of a migrated group that stays with RustFS: it is declared as no operation, for the
/// recorded reason (ADR-0026 (g), (h), ADR-0032 (b)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StayingRoute {
    /// The method.
    pub method: &'static str,
    /// The path, as the inventory records it.
    pub path: &'static str,
    /// The ADR-0024 registration group.
    pub group: &'static str,
    /// Why the gateway does not serve it, with the ADR that decided so.
    pub reason: &'static str,
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

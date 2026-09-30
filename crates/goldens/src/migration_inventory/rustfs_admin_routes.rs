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

//! The RustFS admin route inventory (rustfs/backlog#1744): every route the RustFS admin router
//! registers at one pinned commit, with the facts its migration to gateway extension operations
//! needs.
//!
//! Responsible for: reading `rustfs_admin_routes.json` strictly — an unknown field, a missing
//! field or an unknown value is a refusal — and refusing a recorded inventory whose rows disagree
//! with themselves, whose rows are out of order, whose census is not what its rows add up to, or
//! whose source commit is not the pinned one. The rows are written by
//! `scripts/gen_rustfs_admin_route_inventory.py`, which reads three RustFS authorities (the route
//! policy, the registration matrix and the insert sites) and refuses to write unless they agree;
//! this file never states a count of its own.
//! NOT responsible for: generating the rows or reading RustFS (the script does, from a checkout),
//! or migrating a route (the proof slice in `rustfs_admin_proof` registers three as extension
//! operations under `cfg(test)`).
//! Upstream: the generator and the RustFS commit it read. Downstream: the proof slice, which binds
//! its operations' actions to rows here, and the ring-2 admin migration of rustfs/backlog#1744.
//!
//! # Regenerating
//!
//! ```text
//! python3 scripts/gen_rustfs_admin_route_inventory.py --rustfs <rustfs checkout> \
//!     --out crates/goldens/src/migration_inventory/rustfs_admin_routes.json
//! ```
//!
//! Then move [`RUSTFS_SOURCE_COMMIT`] to the commit the script names. `--check` instead of `--out`
//! exits non-zero when the recorded file no longer matches the checkout.

use core::fmt;
use std::collections::BTreeMap;

use serde::Deserialize;

/// The RustFS commit the recorded inventory was generated from.
pub const RUSTFS_SOURCE_COMMIT: &str = "3268c42e00b375859b4535d53fe219b02d7bfe31";

/// The only format this reader accepts. A generator that changes the row shape changes this too.
pub const INVENTORY_FORMAT: &str = "rustfs-admin-route-inventory/1";

/// The recorded inventory.
const RECORDED: &str = include_str!("rustfs_admin_routes.json");

/// The admin prefix RustFS serves, and the MinIO prefix it canonicalises onto it.
const ADMIN_PREFIX: &str = "/rustfs/admin/";

/// An HTTP method a route is registered for.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "UPPERCASE")]
pub enum RouteMethod {
    /// `DELETE`.
    Delete,
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
}

impl RouteMethod {
    /// The method as it is written on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// How a route admits its caller.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AdminAuthMode {
    /// A SigV4-signed caller, checked against one admin IAM action before the handler.
    Sigv4Admin,
    /// Nobody: a public health, STS form or OIDC bootstrap route.
    Anonymous,
    /// Signed, but authorised inside the handler (the route policy's deferred reasons).
    Custom,
}

impl AdminAuthMode {
    const fn slug(self) -> &'static str {
        match self {
            Self::Sigv4Admin => "sigv4-admin",
            Self::Anonymous => "anonymous",
            Self::Custom => "custom",
        }
    }
}

/// Whether, and in which direction, a body is sealed with the caller's secret key.
///
/// RustFS seals only on the MinIO alias (`/minio/admin/...`); the same route under
/// `/rustfs/admin/...` is plain JSON.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum BodySealing {
    /// Neither body.
    None,
    /// The request body.
    RequestOnMinioAlias,
    /// The response body.
    ResponseOnMinioAlias,
    /// Both.
    RequestAndResponseOnMinioAlias,
}

impl BodySealing {
    const fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RequestOnMinioAlias => "request-on-minio-alias",
            Self::ResponseOnMinioAlias => "response-on-minio-alias",
            Self::RequestAndResponseOnMinioAlias => "request-and-response-on-minio-alias",
        }
    }

    /// Whether the handler needs the caller's secret to read or answer the route.
    #[must_use]
    pub const fn needs_caller_secret(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// How the handler consumes the request body.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum RequestBodyUse {
    /// Read whole, under a limit, before use.
    Buffered,
    /// Drained or consumed frame by frame.
    Streamed,
    /// Handed to code outside the handler's file; not classified further.
    HandedOn,
    /// Never touched.
    NotRead,
}

impl RequestBodyUse {
    const fn slug(self) -> &'static str {
        match self {
            Self::Buffered => "buffered",
            Self::Streamed => "streamed",
            Self::HandedOn => "handed-on",
            Self::NotRead => "not-read",
        }
    }
}

/// How the handler produces the response body.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseBodyUse {
    /// A complete document.
    Buffered,
    /// A stream type the handler's file defines, or a streaming body.
    Streamed,
}

impl ResponseBodyUse {
    const fn slug(self) -> &'static str {
        match self {
            Self::Buffered => "buffered",
            Self::Streamed => "streamed",
        }
    }
}

/// Which prefix family a path belongs to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum RouteSurface {
    /// `/rustfs/admin/v3/...` and the unversioned admin debug paths.
    AdminV3,
    /// `/rustfs/admin/v4/...`.
    AdminV4,
    /// `/iceberg/v1/...`.
    TableCatalog,
    /// `/_iceberg/v1/...`.
    TableCatalogCompat,
    /// Health, profiling and the STS form post, outside every prefix.
    Root,
}

impl RouteSurface {
    const fn slug(self) -> &'static str {
        match self {
            Self::AdminV3 => "admin-v3",
            Self::AdminV4 => "admin-v4",
            Self::TableCatalog => "table-catalog",
            Self::TableCatalogCompat => "table-catalog-compat",
            Self::Root => "root",
        }
    }

    fn of(path: &str) -> Self {
        if path.starts_with("/_iceberg/v1/") {
            Self::TableCatalogCompat
        } else if path.starts_with("/iceberg/v1/") {
            Self::TableCatalog
        } else if path.starts_with("/rustfs/admin/v4/") {
            Self::AdminV4
        } else if path.starts_with(ADMIN_PREFIX) {
            Self::AdminV3
        } else {
            Self::Root
        }
    }
}

/// The route policy's risk level.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum RouteRisk {
    /// No sensitive effect.
    Normal,
    /// Discloses sensitive state.
    Sensitive,
    /// Changes security or durability state.
    High,
    /// Destroys data beyond every recovery path.
    Critical,
}

/// The public kinds a route policy may name for an anonymous route.
const PUBLIC_KINDS: [&str; 4] = ["ConsoleAsset", "Health", "OidcBootstrap", "StsFormPost"];

/// The reasons a route policy may give for deferring authorisation to the handler.
const DEFERRED_REASONS: [&str; 5] = [
    "ContextualAuthorization",
    "CredentialOnly",
    "MultipleActions",
    "NotImplemented",
    "S3Action",
];

/// One registered admin route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminRoute {
    /// The method.
    pub method: RouteMethod,
    /// The registered path pattern, `{name}` for a path parameter.
    pub path: String,
    /// The registration group (`register_admin_routes`) that inserts it.
    pub group: String,
    /// The prefix family.
    pub surface: RouteSurface,
    /// The path parameters, in order.
    pub path_params: Vec<String>,
    /// Whether RustFS also serves the route at the MinIO alias.
    pub minio_admin_alias: bool,
    /// Router-level query discriminators. Always empty for a path-table route: the RustFS router
    /// matches method and path only, and a handler's own query parsing does not route.
    pub query_discriminators: Vec<QueryDiscriminator>,
    /// How the route admits its caller.
    pub auth_mode: AdminAuthMode,
    /// The route policy's admin action, as the RustFS policy enum names it.
    pub iam_action: Option<String>,
    /// The same action in its policy wire spelling, `admin:ServerInfo`.
    pub iam_action_wire: Option<String>,
    /// The public kind of an anonymous route, or the deferred reason of a custom one.
    pub auth_detail: Option<String>,
    /// The route policy's risk level; the deferred table records none.
    pub risk: Option<RouteRisk>,
    /// Whether the admin router lets an unsigned request reach the handler.
    pub router_admits_anonymous: bool,
    /// The handler type.
    pub handler: String,
    /// The file that implements the handler.
    pub handler_file: String,
    /// Caller-secret sealing.
    pub caller_secret_body: BodySealing,
    /// Request body consumption.
    pub request_body: RequestBodyUse,
    /// Response body production.
    pub response_body: ResponseBodyUse,
}

impl AdminRoute {
    /// `METHOD path`, the key rows are ordered and looked up by.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{} {}", self.method.as_str(), self.path)
    }
}

/// One query key the admin router discriminates on before its path table.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QueryDiscriminator {
    /// The query key.
    pub key: String,
    /// `present`, or `equals:<value>`.
    pub rule: String,
}

/// One S3-shaped route the admin router claims before its path table, by query key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRoute {
    /// The RustFS route variant.
    pub name: String,
    /// The method.
    pub method: RouteMethod,
    /// `service`, `bucket` or `object`.
    pub target: String,
    /// The discriminating query key.
    pub query_discriminator: QueryDiscriminator,
    /// Always custom: a signature is required, then the handler authorises.
    pub auth_mode: AdminAuthMode,
    /// What the router requires before the handler.
    pub auth_detail: String,
    /// The action the handler authorises, as the RustFS policy enum names it.
    pub iam_action: String,
    /// The same action in its policy wire spelling.
    pub iam_action_wire: String,
}

/// Where the recorded rows came from.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventorySource {
    /// The RustFS repository.
    pub repository: String,
    /// The commit read.
    pub commit: String,
    /// The RustFS files the rows were read from.
    pub authorities: Vec<String>,
    /// The number of groups `register_admin_routes` calls.
    pub registration_groups: usize,
    /// Calls per helper in RustFS's own registration matrix.
    pub matrix_helper_calls: BTreeMap<String, usize>,
}

/// Every count the rows add up to, as the generator recorded it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryCensus {
    /// Registered routes.
    pub routes: usize,
    /// Query-discriminated routes outside the path table.
    pub extension_routes: usize,
    /// Routes per auth mode.
    pub by_auth_mode: BTreeMap<String, usize>,
    /// Routes per public kind or deferred reason (`null` for an admin-action route).
    pub by_auth_detail: BTreeMap<String, usize>,
    /// Routes per prefix family.
    pub by_surface: BTreeMap<String, usize>,
    /// Routes per registration group.
    pub by_group: BTreeMap<String, usize>,
    /// Routes per caller-secret sealing.
    pub by_caller_secret_body: BTreeMap<String, usize>,
    /// Routes per request body consumption.
    pub by_request_body: BTreeMap<String, usize>,
    /// Routes per response body production.
    pub by_response_body: BTreeMap<String, usize>,
    /// Routes with at least one path parameter.
    pub with_path_params: usize,
    /// Routes also served at the MinIO alias.
    pub with_minio_admin_alias: usize,
    /// Routes the admin router lets an unsigned request reach.
    pub router_admits_anonymous: usize,
    /// Distinct admin actions named by the route policy.
    pub distinct_iam_actions: usize,
}

/// The recorded inventory, validated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RustfsAdminRouteInventory {
    format: String,
    source: InventorySource,
    census: InventoryCensus,
    routes: Vec<AdminRoute>,
    extension_routes: Vec<ExtensionRoute>,
}

impl RustfsAdminRouteInventory {
    /// Where the rows came from.
    #[must_use]
    pub const fn source(&self) -> &InventorySource {
        &self.source
    }

    /// The census, which validation proved equal to what the rows add up to.
    #[must_use]
    pub const fn census(&self) -> &InventoryCensus {
        &self.census
    }

    /// Every registered route, ordered by [`AdminRoute::key`].
    #[must_use]
    pub fn routes(&self) -> &[AdminRoute] {
        &self.routes
    }

    /// Every query-discriminated route outside the path table.
    #[must_use]
    pub fn extension_routes(&self) -> &[ExtensionRoute] {
        &self.extension_routes
    }

    /// The route registered for `method path`, if any.
    #[must_use]
    pub fn route(&self, method: RouteMethod, path: &str) -> Option<&AdminRoute> {
        self.routes.iter().find(|route| route.method == method && route.path == path)
    }

    /// The extension route of this RustFS variant name, if any.
    #[must_use]
    pub fn extension_route(&self, name: &str) -> Option<&ExtensionRoute> {
        self.extension_routes.iter().find(|route| route.name == name)
    }

    /// One summary line, every number derived from the rows.
    #[must_use]
    pub fn render(&self) -> String {
        let join = |map: &BTreeMap<String, usize>| {
            map.iter()
                .map(|(key, count)| format!("{key}={count}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "rustfs admin routes: commit={} routes={} extension-routes={} auth=[{}] caller-secret=[{}] \
             path-params={} minio-alias={} router-anonymous={} actions={}\n",
            self.source.commit,
            self.census.routes,
            self.census.extension_routes,
            join(&self.census.by_auth_mode),
            join(&self.census.by_caller_secret_body),
            self.census.with_path_params,
            self.census.with_minio_admin_alias,
            self.census.router_admits_anonymous,
            self.census.distinct_iam_actions,
        )
    }
}

/// Why a recorded inventory was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteInventoryError {
    /// The document is not the recorded shape: an unknown or missing field, or an unknown value.
    Shape(String),
    /// The format marker names another row shape.
    Format(String),
    /// The rows name another RustFS commit than the pinned one.
    SourceCommit(String),
    /// A row is out of order, or two rows share a key.
    Order(String),
    /// A row contradicts itself.
    Row {
        /// The row's key.
        key: String,
        /// The contradiction.
        reason: &'static str,
    },
    /// A recorded count is not what the rows add up to.
    Census {
        /// The count.
        field: &'static str,
        /// What was recorded.
        recorded: String,
        /// What the rows add up to.
        derived: String,
    },
}

impl fmt::Display for RouteInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(reason) => write!(formatter, "rustfs admin route inventory is malformed: {reason}"),
            Self::Format(found) => write!(formatter, "rustfs admin route inventory format {found:?} is not {INVENTORY_FORMAT:?}"),
            Self::SourceCommit(found) => write!(
                formatter,
                "rustfs admin route inventory names commit {found}, the pinned commit is {RUSTFS_SOURCE_COMMIT}"
            ),
            Self::Order(key) => write!(formatter, "rustfs admin route {key} is out of order or repeated"),
            Self::Row { key, reason } => write!(formatter, "rustfs admin route {key}: {reason}"),
            Self::Census {
                field,
                recorded,
                derived,
            } => write!(
                formatter,
                "rustfs admin route census {field} records {recorded}, the rows add up to {derived}"
            ),
        }
    }
}

impl std::error::Error for RouteInventoryError {}

/// Reads and validates the recorded inventory.
///
/// # Errors
///
/// The first refusal [`parse_inventory`] finds.
pub fn rustfs_admin_route_inventory() -> Result<RustfsAdminRouteInventory, RouteInventoryError> {
    parse_inventory(RECORDED)
}

/// Reads and validates one inventory document.
///
/// # Errors
///
/// [`RouteInventoryError`] for a document of another shape, format or commit, a row out of order or
/// contradicting itself, or a census that is not what the rows add up to.
pub fn parse_inventory(text: &str) -> Result<RustfsAdminRouteInventory, RouteInventoryError> {
    let inventory: RustfsAdminRouteInventory =
        serde_json::from_str(text).map_err(|error| RouteInventoryError::Shape(error.to_string()))?;
    if inventory.format != INVENTORY_FORMAT {
        return Err(RouteInventoryError::Format(inventory.format));
    }
    if inventory.source.commit != RUSTFS_SOURCE_COMMIT {
        return Err(RouteInventoryError::SourceCommit(inventory.source.commit));
    }
    let mut previous: Option<(RouteMethod, &str)> = None;
    for route in &inventory.routes {
        let current = (route.method, route.path.as_str());
        if previous.is_some_and(|previous| previous >= current) {
            return Err(RouteInventoryError::Order(route.key()));
        }
        previous = Some(current);
        check_route(route)?;
    }
    for extension in &inventory.extension_routes {
        check_extension(extension)?;
    }
    check_census(&inventory)?;
    Ok(inventory)
}

fn check_route(route: &AdminRoute) -> Result<(), RouteInventoryError> {
    let refuse = |reason| {
        Err(RouteInventoryError::Row {
            key: route.key(),
            reason,
        })
    };
    if !route.path.starts_with('/') {
        return refuse("the path does not start with '/'");
    }
    let params = route
        .path
        .split('{')
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name.to_owned()))
        .collect::<Vec<_>>();
    if params != route.path_params {
        return refuse("the path parameters are not the ones the path names");
    }
    // A catch-all (`{*name}`) takes the rest of the path, so it is the last parameter and nothing
    // follows it (ADR-0036).
    if route
        .path_params
        .iter()
        .position(|param| param.starts_with('*'))
        .is_some_and(|at| at + 1 != route.path_params.len() || !route.path.ends_with('}'))
    {
        return refuse("a catch-all parameter is not the path's last segment");
    }
    if route.minio_admin_alias != route.path.starts_with(ADMIN_PREFIX) {
        return refuse("the MinIO alias flag disagrees with the path prefix");
    }
    if route.surface != RouteSurface::of(&route.path) {
        return refuse("the surface disagrees with the path prefix");
    }
    if !route.query_discriminators.is_empty() {
        return refuse("a path-table route carries a query discriminator");
    }
    let detail = route.auth_detail.as_deref();
    let consistent = match route.auth_mode {
        AdminAuthMode::Sigv4Admin => detail.is_none() && route.iam_action.is_some() && route.risk.is_some(),
        AdminAuthMode::Anonymous => {
            detail.is_some_and(|kind| PUBLIC_KINDS.contains(&kind))
                && route.iam_action.is_none()
                && route.risk.is_some()
                && route.router_admits_anonymous
        }
        AdminAuthMode::Custom => {
            detail.is_some_and(|reason| DEFERRED_REASONS.contains(&reason)) && route.iam_action.is_none() && route.risk.is_none()
        }
    };
    if !consistent {
        return refuse("the auth mode, action, detail and risk do not describe one policy row");
    }
    match (&route.iam_action, &route.iam_action_wire) {
        (None, None) => {}
        (Some(_), Some(wire))
            if wire
                .split_once(':')
                .is_some_and(|(service, action)| !service.is_empty() && !action.is_empty()) => {}
        _ => return refuse("the action has no `service:Action` wire spelling, or a spelling without an action"),
    }
    if !route.handler_file.starts_with("rustfs/src/admin/") || route.handler.is_empty() {
        return refuse("the handler is not a RustFS admin handler");
    }
    Ok(())
}

fn check_extension(route: &ExtensionRoute) -> Result<(), RouteInventoryError> {
    let refuse = |reason| {
        Err(RouteInventoryError::Row {
            key: route.name.clone(),
            reason,
        })
    };
    if !matches!(route.target.as_str(), "service" | "bucket" | "object") {
        return refuse("the target is not service, bucket or object");
    }
    let rule = route.query_discriminator.rule.as_str();
    if route.query_discriminator.key.is_empty() || !(rule == "present" || rule.starts_with("equals:")) {
        return refuse("the query discriminator is not a key with a present or equals rule");
    }
    if route.auth_mode != AdminAuthMode::Custom || !route.iam_action_wire.contains(':') || route.iam_action.is_empty() {
        return refuse("an extension route is signed then authorised against one named action");
    }
    Ok(())
}

fn tally<'a>(values: impl Iterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.to_owned()).or_insert(0) += 1;
    }
    counts
}

/// What the rows add up to.
#[must_use]
pub fn derive_census(routes: &[AdminRoute], extension_routes: &[ExtensionRoute]) -> InventoryCensus {
    InventoryCensus {
        routes: routes.len(),
        extension_routes: extension_routes.len(),
        by_auth_mode: tally(routes.iter().map(|route| route.auth_mode.slug())),
        by_auth_detail: tally(routes.iter().map(|route| route.auth_detail.as_deref().unwrap_or("null"))),
        by_surface: tally(routes.iter().map(|route| route.surface.slug())),
        by_group: tally(routes.iter().map(|route| route.group.as_str())),
        by_caller_secret_body: tally(routes.iter().map(|route| route.caller_secret_body.slug())),
        by_request_body: tally(routes.iter().map(|route| route.request_body.slug())),
        by_response_body: tally(routes.iter().map(|route| route.response_body.slug())),
        with_path_params: routes.iter().filter(|route| !route.path_params.is_empty()).count(),
        with_minio_admin_alias: routes.iter().filter(|route| route.minio_admin_alias).count(),
        router_admits_anonymous: routes.iter().filter(|route| route.router_admits_anonymous).count(),
        distinct_iam_actions: routes
            .iter()
            .filter_map(|route| route.iam_action.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
    }
}

fn check_census(inventory: &RustfsAdminRouteInventory) -> Result<(), RouteInventoryError> {
    let recorded = &inventory.census;
    let derived = derive_census(&inventory.routes, &inventory.extension_routes);
    let drift = |field, recorded: &dyn fmt::Debug, derived: &dyn fmt::Debug| {
        Err(RouteInventoryError::Census {
            field,
            recorded: format!("{recorded:?}"),
            derived: format!("{derived:?}"),
        })
    };
    macro_rules! same {
        ($($field:ident),+ $(,)?) => {
            $(if recorded.$field != derived.$field {
                return drift(stringify!($field), &recorded.$field, &derived.$field);
            })+
        };
    }
    same!(
        routes,
        extension_routes,
        by_auth_mode,
        by_auth_detail,
        by_surface,
        by_group,
        by_caller_secret_body,
        by_request_body,
        by_response_body,
        with_path_params,
        with_minio_admin_alias,
        router_admits_anonymous,
        distinct_iam_actions,
    );
    // Two numbers the rows cannot produce, cross-checked against the RustFS authorities' own.
    let matrix_rows = inventory.source.matrix_helper_calls.values().sum::<usize>();
    if matrix_rows != derived.routes {
        return drift("source.matrix_helper_calls", &matrix_rows, &derived.routes);
    }
    if inventory.source.registration_groups != derived.by_group.len() {
        return drift(
            "source.registration_groups",
            &inventory.source.registration_groups,
            &derived.by_group.len(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;

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

//! The collector's v2 inventory of separate S3 and control-plane extension tables.
//!
//! Responsible for: deserializing `rustfs_admin_routes_native.json` strictly and validating its
//! host pin, table-local precedence order, query selector registrations, and census totals.
//! NOT responsible for: collecting routes from a RustFS checkout, reading the frozen v1 inventory
//! (`super`), or choosing routing and admission rulings (`xtask`).
//! Upstream: `scripts/gen_rustfs_admin_route_inventory.py` and `rustfs_admin_routes_native.json`.
//! Downstream: `rustfs-gateway-goldens` tests and `cargo xtask rustfs-admin-dialect`.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use super::{AdminAuthMode, AdminRoute, InventoryCensus, InventorySource, QueryDiscriminator, RouteInventoryError, RouteMethod};

const FORMAT: &str = "rustfs-admin-route-inventory/2";

/// An extension as installed by one native host service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeExtension {
    /// Operation name, including its vendor namespace.
    pub name: String,
    /// HTTP request method.
    pub method: RouteMethod,
    /// Service, bucket or object.
    pub target: String,
    /// Comparison order within this service's table.
    pub precedence: u16,
    /// Primary query selector.
    pub query_discriminator: QueryDiscriminator,
    /// Additional query selectors that must also match.
    pub query_requires: Vec<QueryDiscriminator>,
    /// Policy action taken from the registered operation.
    pub iam_action_wire: String,
    /// Alternate action for a request addressing a version.
    pub version_iam_action_wire: Option<String>,
    /// Admission floor installed for this operation.
    pub floor: String,
    /// Locked gateway commit and operation module.
    pub source: String,
}

/// Ordered extension rows from each independently assembled service.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeTables {
    /// Metadata listings in the S3 service.
    pub s3: Vec<NativeExtension>,
    /// Query-discriminated operations in the control-plane service.
    pub control_plane: Vec<NativeExtension>,
}

/// A native inventory that passed the caller's source pin, registration and census checks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInventory {
    format: String,
    source: InventorySource,
    census: InventoryCensus,
    routes: Vec<AdminRoute>,
    extension_tables: NativeTables,
}

impl NativeInventory {
    /// Registered host routes, including internal query dispatch keys.
    #[must_use]
    pub fn routes(&self) -> &[AdminRoute] {
        &self.routes
    }

    /// Independent host tables, each in its own priority order.
    #[must_use]
    pub const fn tables(&self) -> &NativeTables {
        &self.extension_tables
    }

    /// Source host for the inventory.
    #[must_use]
    pub const fn source(&self) -> &InventorySource {
        &self.source
    }

    /// Verified inventory counters.
    #[must_use]
    pub const fn census(&self) -> &InventoryCensus {
        &self.census
    }
}

fn git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn policy_action(action: &str) -> bool {
    action.split_once(':').is_some_and(|(service, name)| {
        !service.is_empty()
            && service.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

impl NativeExtension {
    fn check(&self, listing: bool) -> Result<&str, RouteInventoryError> {
        let refuse = |reason| RouteInventoryError::Row {
            key: self.name.clone(),
            reason,
        };
        let kind = self
            .name
            .strip_prefix("rustfs:")
            .ok_or_else(|| refuse("missing operation namespace"))?;
        if !kind.starts_with(|c: char| c.is_ascii_uppercase()) || !kind.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(refuse("invalid operation name"));
        }
        let mut keys = BTreeSet::new();
        for query in std::iter::once(&self.query_discriminator).chain(&self.query_requires) {
            if query.key.is_empty()
                || !query.key.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
                || !(query.rule == "present" || query.rule.starts_with("equals:"))
                || !keys.insert(&query.key)
            {
                return Err(refuse("invalid or repeated query selector"));
            }
        }
        if !matches!(self.target.as_str(), "service" | "bucket" | "object")
            || !policy_action(&self.iam_action_wire)
            || self
                .version_iam_action_wire
                .as_deref()
                .is_some_and(|action| self.target != "object" || !policy_action(action))
        {
            return Err(refuse("invalid resource or policy action"));
        }
        if listing {
            if self.floor != "listing_floor"
                || self.method != RouteMethod::Get
                || self.target != "bucket"
                || !matches!(self.query_requires.as_slice(), [q] if q.key == "metadata" && q.rule == "equals:true")
            {
                return Err(refuse("invalid native metadata listing"));
            }
        } else if !matches!(self.floor.as_str(), "floor" | "presigned_floor" | "floor.with_signed_event_list()")
            || !self.query_requires.is_empty()
        {
            return Err(refuse("invalid native control-plane extension"));
        }
        let (pin, path) = self.source.split_once(':').ok_or_else(|| refuse("missing locked source"))?;
        let module = path
            .strip_prefix("crates/dialect-rustfs-admin/src/ops/")
            .and_then(|p| p.strip_suffix(".rs"));
        if !git_sha(pin)
            || !module
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
        {
            return Err(refuse("invalid locked operation source"));
        }
        Ok(pin)
    }

    fn registration_key(&self) -> String {
        let target = match self.target.as_str() {
            "service" => "",
            "bucket" => "{bucket}",
            _ => "{bucket}/{key}",
        };
        let q = &self.query_discriminator;
        let value = q
            .rule
            .strip_prefix("equals:")
            .filter(|s| !s.is_empty())
            .map(|v| format!("={v}"))
            .unwrap_or_default();
        format!("{} ?{}{value}/{target}", self.method.as_str(), q.key)
    }
}

pub(super) fn parse(text: &str, expected_host: &str) -> Result<NativeInventory, RouteInventoryError> {
    let inv: NativeInventory = serde_json::from_str(text).map_err(|e| RouteInventoryError::Shape(e.to_string()))?;
    if inv.format != FORMAT || !git_sha(expected_host) || inv.source.commit != expected_host {
        return Err(RouteInventoryError::Shape(format!(
            "expected {FORMAT} at {expected_host}, found {} at {}",
            inv.format, inv.source.commit
        )));
    }
    let mut names = BTreeSet::new();
    let mut pins = BTreeSet::new();
    let mut controls = BTreeMap::new();
    for (listing, table) in [(true, &inv.extension_tables.s3), (false, &inv.extension_tables.control_plane)] {
        if table.is_empty() {
            return Err(RouteInventoryError::Shape("empty native extension table".to_owned()));
        }
        let mut previous = None;
        for row in table {
            pins.insert(row.check(listing)?);
            if previous.is_some_and(|p| p >= row.precedence) || !names.insert(&row.name) {
                return Err(RouteInventoryError::Order(row.name.clone()));
            }
            previous = Some(row.precedence);
            if !listing && controls.insert(row.registration_key(), row).is_some() {
                return Err(RouteInventoryError::Order(row.registration_key()));
            }
        }
    }
    if pins.len() != 1 {
        return Err(RouteInventoryError::Shape("native tables name different gateway commits".to_owned()));
    }
    let mut previous = None;
    for route in &inv.routes {
        let key = (route.method, route.path.as_str());
        if previous.is_some_and(|p| p >= key) {
            return Err(RouteInventoryError::Order(route.key()));
        }
        previous = Some(key);
        let query = route.path.starts_with('?');
        if query
            && (route.group != "s3_extension"
                || route.auth_mode != AdminAuthMode::Custom
                || route.auth_detail.as_deref() != Some("S3Action")
                || controls.remove(&route.key()).is_none())
        {
            return Err(RouteInventoryError::Row {
                key: route.key(),
                reason: "query registration does not match the control-plane table",
            });
        }
        super::check_route(route, query)?;
    }
    // Object Lambda is dispatched directly, outside the admin router's registration matrix.
    for row in controls.into_values() {
        if !(row.name == "rustfs:InvokeObjectLambda"
            && row.target == "object"
            && row.method == RouteMethod::Get
            && row.query_discriminator.key == "lambdaArn"
            && row.query_discriminator.rule == "present")
        {
            return Err(RouteInventoryError::Row {
                key: row.name.clone(),
                reason: "no matching admin query registration",
            });
        }
    }
    let mut derived = super::derive_census(&inv.routes, &[]);
    derived.extension_routes = names.len();
    super::check_census(&inv.source, &inv.census, &derived)?;
    Ok(inv)
}

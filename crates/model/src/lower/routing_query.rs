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

//! The routing-query vocabulary extracted before IR emission.
//!
//! Responsible for: collecting fixed selector keys and required query members that distinguish
//! otherwise identical routes, including deferred operations.
//! NOT responsible for: assigning bits or emitting Rust; codegen owns both.
//! Upstream: Smithy operations and route overlays. Downstream: `lower` and codegen.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::json::Value;
use crate::overlay::Overlay;
use crate::smithy::{Model, has_trait, target_of, trait_of};

use super::{UNIT_SHAPE, support::Uri};

type RouteGroup = (String, String, Vec<(String, Option<String>)>, Vec<String>, Vec<String>);

pub(super) fn keys(model: &Model, overlay: &Overlay, operation_names: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut keys = BTreeSet::new();
    let mut route_groups: BTreeMap<RouteGroup, Vec<BTreeSet<String>>> = BTreeMap::new();
    for name in operation_names {
        let operation = model
            .shape_local(name)
            .ok_or_else(|| Error::Model(format!("no operation shape `{name}`")))?;
        let http_trait = trait_of(operation, "smithy.api#http")
            .ok_or_else(|| Error::ir(name, "the operation carries no smithy.api#http trait"))?;
        let uri = http_trait
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::ir(name, "smithy.api#http has no uri"))?;
        let route = Uri::parse(uri);
        keys.extend(route.query.iter().map(|(key, _)| key.clone()));
        let operation_overlay = overlay.ops.get(name);
        if let Some(operation_overlay) = operation_overlay {
            keys.extend(operation_overlay.query_present.iter().cloned());
            keys.extend(operation_overlay.query_absent.iter().cloned());
        }

        let query_fields = operation
            .get("input")
            .and_then(target_of)
            .filter(|id| *id != UNIT_SHAPE)
            .and_then(|id| model.shape(id))
            .map(|shape| {
                model
                    .members(shape)
                    .into_iter()
                    .filter(|(_, member)| has_trait(member, "smithy.api#required"))
                    .filter_map(|(_, member)| trait_of(member, "smithy.api#httpQuery").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let method = http_trait
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::ir(name, "smithy.api#http has no method"))?;
        route_groups
            .entry((
                method.to_owned(),
                route.path_shape(),
                route.query,
                operation_overlay.map(|item| item.query_present.clone()).unwrap_or_default(),
                operation_overlay.map(|item| item.query_absent.clone()).unwrap_or_default(),
            ))
            .or_default()
            .push(query_fields);
    }

    // Deferred configuration operations can share the same literal subresource URI and differ
    // by a required `id`-style query member. That required member is a selector even before the
    // operation is promoted into the emitted IR. Optional pagination/filter fields are excluded:
    // they shape one operation but never decide which operation the request selected.
    for fields in route_groups.values().filter(|fields| fields.len() > 1) {
        let mut union = BTreeSet::new();
        let mut intersection = fields.first().cloned().unwrap_or_default();
        for field_set in fields {
            union.extend(field_set.iter().cloned());
            intersection = intersection.intersection(field_set).cloned().collect();
        }
        keys.extend(union.difference(&intersection).cloned());
    }
    Ok(keys.into_iter().collect())
}

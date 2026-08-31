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

//! Route-only overlay parsing and category ownership checks.
//!
//! Responsible for: loading reasoned route-only groups and rejecting operations owned by more
//! than one generation category.
//! NOT responsible for: deriving route selectors or emitting generated artifacts.
//! Upstream: operation-family overlay documents. Downstream: [`super::Overlay::load`].

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::toml_lite::Toml;

use super::{Origins, Overlay, array_of_tables, claim};

pub(super) fn read(doc: &Toml, file: &str, operations: &mut BTreeMap<String, String>, origins: &mut Origins) -> Result<()> {
    for group in array_of_tables(doc, "route_only") {
        let reason = group
            .get("reason")
            .and_then(Toml::as_str)
            .ok_or_else(|| Error::Overlay(format!("{file}: every [[route_only]] group needs a `reason`")))?;
        let names = group
            .get("operations")
            .ok_or_else(|| Error::Overlay(format!("{file}: every [[route_only]] group needs `operations`")))?
            .string_array("route_only.operations")?;
        for name in names {
            claim(origins, &name, file, "route-only")?;
            operations.insert(name, reason.to_owned());
        }
    }
    Ok(())
}

pub(super) fn check_categories(
    overlay: &Overlay,
    include_origins: &Origins,
    route_only_origins: &Origins,
    deferred_origins: &Origins,
) -> Result<()> {
    for operation in &overlay.include {
        if overlay.route_only.contains_key(operation) {
            return collision(
                operation,
                "included",
                include_origins,
                "route-only",
                route_only_origins,
                "which surface it emits",
            );
        }
        if overlay.deferred.contains_key(operation) {
            return collision(
                operation,
                "included",
                include_origins,
                "deferred",
                deferred_origins,
                "which of the two it is",
            );
        }
    }
    for operation in overlay.route_only.keys() {
        if overlay.deferred.contains_key(operation) {
            return collision(
                operation,
                "route-only",
                route_only_origins,
                "deferred",
                deferred_origins,
                "which surface it emits",
            );
        }
    }
    Ok(())
}

fn collision(
    operation: &str,
    left_kind: &str,
    left_origins: &Origins,
    right_kind: &str,
    right_origins: &Origins,
    decision: &str,
) -> Result<()> {
    let left = left_origins.get(operation).map_or("?", String::as_str);
    let right = right_origins.get(operation).map_or("?", String::as_str);
    Err(Error::Overlay(format!(
        "`{operation}` is {left_kind} by `{left}` and {right_kind} by `{right}`; one family owns \
         an operation, and it decides {decision}"
    )))
}

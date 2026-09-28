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

//! A query parameter that is both a route discriminator and a required parameter records both roles.
//!
//! Responsible for: refusing, at lowering time, an operation that records only one of the two
//! roles of such a parameter (acceptance id c-param-1003, rustfs/backlog#1694 section 7).
//! NOT responsible for: deciding which parameters discriminate — the model's `@required` and the
//! overlay's `query_present` are the two authorities, and this only checks they agree.
//! Upstream: the lowered operations and the overlay. Downstream: `crate::lower::lower`.
//!
//! # The two roles, and what goes wrong when one is missing
//!
//! `GET /b?analytics&id=x` is `GetBucketAnalyticsConfiguration`; `GET /b?analytics` is
//! `ListBucketAnalyticsConfigurations`. `id` is the model's required member of the first *and* the
//! only thing on the wire that tells the two apart. Both roles have to be written down:
//!
//! - **required, but no selector:** the two rows share every predicate, so whichever has the lower
//!   precedence answers both requests — a listing is served as a single-configuration read that
//!   then refuses its missing `id`, or the other way round;
//! - **selector, but not required:** the decoder types the member optional although the route
//!   guarantees it, so a caller reaching the codec by any other path — a dialect, a test, a
//!   future router — gets a silent `None` instead of the operation's static `400`.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::ir::{Binding, OperationIr, Predicate};
use crate::overlay::Overlay;

/// The predicates the model's own `uri` contributes, rendered for ordering: what places two
/// operations on the same route before any overlay selector separates them.
type RouteKey = BTreeSet<String>;

/// Refuses an operation that records only one of the two roles of a discriminating parameter.
pub(super) fn check(overlay: &Overlay, operations: &[OperationIr]) -> Result<()> {
    for ir in operations {
        selector_members_are_required(ir)?;
    }
    let mut routes: BTreeMap<RouteKey, Vec<&OperationIr>> = BTreeMap::new();
    for ir in operations {
        routes.entry(route_key(overlay, ir)).or_default().push(ir);
    }
    for siblings in routes.values().filter(|siblings| siblings.len() > 1) {
        for ir in siblings {
            discriminators_are_selected(ir, siblings)?;
        }
    }
    Ok(())
}

/// Every `QueryPresent` key that is one of the operation's own query members is required.
fn selector_members_are_required(ir: &OperationIr) -> Result<()> {
    for predicate in &ir.http.predicates {
        let Predicate::QueryPresent(key) = predicate else {
            continue;
        };
        let member = ir
            .input
            .iter()
            .find(|field| field.binding == Binding::Query && field.wire_name.as_deref() == Some(key));
        if let Some(field) = member
            && !field.required
        {
            return Err(Error::ir(
                &ir.operation,
                format!(
                    "query `{key}` selects this operation but its member `{}` is not required; a route \
                     discriminator that is also a parameter must record both roles (c-param-1003)",
                    field.name
                ),
            ));
        }
    }
    Ok(())
}

/// Every required query member a sibling on the same route lacks is a `QueryPresent` selector.
fn discriminators_are_selected(ir: &OperationIr, siblings: &[&OperationIr]) -> Result<()> {
    let required = required_query(ir);
    for sibling in siblings.iter().filter(|sibling| sibling.operation != ir.operation) {
        let theirs = required_query(sibling);
        for key in required.difference(&theirs) {
            if !ir.http.predicates.contains(&Predicate::QueryPresent((*key).to_owned())) {
                return Err(Error::ir(
                    &ir.operation,
                    format!(
                        "required query `{key}` is what tells this operation from `{}` on the same route, \
                         but no `query_present` selector records it; a required parameter that is also a \
                         route discriminator must record both roles (c-param-1003)",
                        sibling.operation
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn required_query(ir: &OperationIr) -> BTreeSet<&str> {
    ir.input
        .iter()
        .filter(|field| field.required && field.binding == Binding::Query)
        .filter_map(|field| field.wire_name.as_deref())
        .collect()
}

/// Method, target and the query predicates the model's `uri` pins — everything but the overlay's
/// own selectors, which are exactly what this module checks.
fn route_key(overlay: &Overlay, ir: &OperationIr) -> RouteKey {
    let declared: BTreeSet<&str> = overlay
        .ops
        .get(&ir.operation)
        .map(|ov| ov.query_present.iter().chain(&ov.query_absent).map(String::as_str).collect())
        .unwrap_or_default();
    ir.http
        .predicates
        .iter()
        .filter(|predicate| match predicate {
            Predicate::Method(_) | Predicate::Target(_) => true,
            Predicate::QueryPresent(key) | Predicate::QueryEquals(key, _) => !declared.contains(key.as_str()),
            _ => false,
        })
        .map(|predicate| format!("{predicate:?}"))
        .collect()
}

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

//! Route-selector lowering shared by typed and route-only operations.
//!
//! Responsible for: deriving only HTTP route facts from model and overlay authority.
//! NOT responsible for: generating DTOs, codecs, operation IR, or handler registrations.
//! Upstream: Smithy HTTP traits and operation overlays. Downstream: the model lowerer.

use crate::error::{Error, Result};
use crate::ir::{ArnForm, HostClass, Http, Method, Predicate, TargetKind};
use crate::json::Value;
use crate::overlay::{OpOverlay, Overlay};
use crate::smithy::{Model, trait_of};

use super::support::Uri;

/// One protocol-known route with no generated operation representation.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteOnly {
    /// AWS official operation name.
    pub operation: String,
    /// The model- and overlay-derived selector facts needed by the router.
    pub http: Http,
}

pub(super) fn lower_http(model: &Model, overlay: &Overlay, name: &str) -> Result<Http> {
    let empty = OpOverlay::default();
    let op = model
        .shape_local(name)
        .ok_or_else(|| Error::Model(format!("no operation shape `{name}`")))?;
    let ov = overlay.ops.get(name).unwrap_or(&empty);
    let http_trait =
        trait_of(op, "smithy.api#http").ok_or_else(|| Error::ir(name, "the operation carries no smithy.api#http trait"))?;
    let method_text = http_trait
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::ir(name, "smithy.api#http has no method"))?;
    let method = Method::parse(method_text).ok_or_else(|| Error::ir(name, format!("unknown method `{method_text}`")))?;
    let uri = http_trait
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::ir(name, "smithy.api#http has no uri"))?;
    let route = Uri::parse(uri);
    let target = match &ov.target {
        Some(t) => TargetKind::parse(t).ok_or_else(|| Error::ir(name, format!("unknown target `{t}`")))?,
        None => route.target(),
    };
    let mut predicates = vec![Predicate::Method(method), Predicate::Target(target)];
    for (key, value) in &route.query {
        match value {
            Some(value) => predicates.push(Predicate::QueryEquals(key.clone(), value.clone())),
            None => predicates.push(Predicate::QueryPresent(key.clone())),
        }
    }
    for key in &ov.query_present {
        if route.query.iter().any(|(existing, _)| existing == key) {
            return Err(Error::ir(
                name,
                format!("`query_present` repeats `{key}`, which the model's uri already pins"),
            ));
        }
        predicates.push(Predicate::QueryPresent(key.clone()));
    }
    predicates.extend(ov.query_absent.iter().cloned().map(Predicate::QueryAbsent));
    predicates.extend(
        ov.header_present
            .iter()
            .cloned()
            .map(|header| Predicate::HeaderPresent { header, negated: false }),
    );
    predicates.extend(
        ov.header_absent
            .iter()
            .cloned()
            .map(|header| Predicate::HeaderPresent { header, negated: true }),
    );
    if let Some(text) = &ov.host_class {
        let class = HostClass::parse(text).ok_or_else(|| Error::ir(name, format!("unknown host_class `{text}`")))?;
        predicates.push(Predicate::HostClass(class));
    }
    if let Some(text) = &ov.arn_form {
        let form = ArnForm::parse(text).ok_or_else(|| Error::ir(name, format!("unknown arn_form `{text}`")))?;
        predicates.push(Predicate::ArnForm(form));
    }
    let success_status = ov.success_status.unwrap_or_else(|| {
        http_trait
            .get("code")
            .and_then(|code| match code {
                Value::Int(value) => u16::try_from(*value).ok(),
                _ => None,
            })
            .unwrap_or(200)
    });
    Ok(Http {
        method,
        target,
        precedence: ov
            .precedence
            .ok_or_else(|| Error::ir(name, "no route precedence; add `precedence` to the operation's overlay entry"))?,
        predicates,
        success_status,
        alt_success_statuses: ov.alt_success_statuses.clone(),
        path_shape: ov.path_shape.clone().unwrap_or_else(|| route.path_shape()),
    })
}

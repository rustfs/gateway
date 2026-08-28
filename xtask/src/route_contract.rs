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

//! Shared request acceptance and operation-route verification.
//!
//! Responsible for: building the one route witness used by operation verification.
//! NOT responsible for: rendering route diagnostics or defining route predicates.
//! Upstream: the operation catalog and route CLI.
//! Downstream: the facade acceptance and core route table.

use http::Request;
use rustfs_gateway::{Limits, WireRequest};

pub(crate) fn accepted_request(request: &str, headers: &[(String, String)]) -> Result<WireRequest<()>, String> {
    let (method, uri) = request.split_once(' ').ok_or("expected 'METHOD /path?query'")?;
    let mut builder = Request::builder().method(method).uri(uri);
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        builder = builder.header("host", "localhost");
    }
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let request = builder.body(()).map_err(|error| error.to_string())?;
    WireRequest::accept(request, &Limits::default()).map_err(|error| format!("{error:?}"))
}

pub(crate) fn verify_operation_route(name: &str) -> Result<(), String> {
    use std::collections::BTreeMap;

    use rustfs_gateway_core::route::{
        HostClass, Predicate, RouteRequestParts, RouteTable, SHADOWING, TargetKind, generated_entries,
    };

    let entries = generated_entries().map_err(|error| error.to_string())?;
    let entry = entries
        .iter()
        .find(|entry| entry.op_name == name)
        .ok_or_else(|| format!("the runtime table has no row for {name}"))?;
    let mut method = http::Method::GET;
    let mut target = TargetKind::Bucket;
    let mut host_class = HostClass::Standard;
    let mut arn_form = None;
    let mut path = None;
    let mut query = BTreeMap::new();
    let mut headers = BTreeMap::new();
    for predicate in entry.selector.predicates() {
        match predicate {
            Predicate::Method(value) => method = value.clone(),
            Predicate::Target(value) => target = *value,
            Predicate::QueryPresent(key) => {
                query.entry(*key).or_insert("");
            }
            Predicate::QueryEquals(key, value) => {
                query.insert(*key, *value);
            }
            Predicate::QueryAbsent(key) => {
                query.remove(key);
            }
            Predicate::HostClass(value) => host_class = *value,
            Predicate::PathLiteral(value) => path = Some(*value),
            Predicate::ArnForm(value) => arn_form = Some(*value),
            Predicate::HeaderPrefix(name, prefix) => {
                headers.insert(*name, format!("{prefix}x"));
            }
            Predicate::HeaderPresent { header, negated: false } => {
                headers.insert(*header, "x".to_owned());
            }
            Predicate::HeaderPresent { header, negated: true } => {
                headers.remove(header);
            }
        }
    }
    let path = path.unwrap_or(match target {
        TargetKind::Service => "/",
        TargetKind::Bucket => "/bucket",
        TargetKind::Object => "/bucket/key",
    });
    let query = query
        .into_iter()
        .map(|(key, value)| {
            if value.is_empty() {
                key.to_owned()
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let head = format!("{method} {uri}");
    let headers: Vec<_> = headers.into_iter().map(|(name, value)| (name.to_owned(), value)).collect();
    let wire = accepted_request(&head, &headers)?;
    let raw_path = wire.raw_path();
    let request = RouteRequestParts {
        method: wire.method(),
        path: raw_path.as_str(),
        target,
        host_class,
        arn_form,
        query: wire.query(),
        headers: wire.headers(),
    };
    if !entry.selector.matches(&request) {
        return Err(format!("the generated witness does not satisfy {name}: {}", entry.selector));
    }
    let table = RouteTable::build(entries, &SHADOWING).map_err(|error| error.to_string())?;
    match table.resolve(&request) {
        Some(selected) if selected.op_name == name => Ok(()),
        Some(selected) => Err(format!("the {name} witness selected {} instead", selected.op_name)),
        None => Err(format!("the {name} witness selected no operation")),
    }
}

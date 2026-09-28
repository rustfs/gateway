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

//! Responsible for: naming the S3 operation a request addresses, with the gateway's own
//! generated route table and the host's addressing rule, so that a recorded entry is filed under
//! the operation the protocol kernel would route it to.
//! Not responsible for: whether the host serves that operation. A host running a different S3
//! stack still gets the gateway's name for the request, which is the name the corpus buckets by.
//! Upstream: `layer::CorpusRecorderService::call`.
//! Downstream: `body::Head::op`.
//!
//! This is the route table the gateway itself dispatches with, not a second copy of it: a
//! hand-written classifier would be one routing rule living in two places, which is how two
//! fixes come to contradict each other.

use std::sync::OnceLock;

use http::request::Parts;
use rustfs_gateway::{HostQuery, HostResolver, Limits, WireRequest};
use rustfs_gateway_core::route::{RouteRequestParts, RouteTable, SHADOWING, generated_entries};

fn table() -> Option<&'static RouteTable> {
    static TABLE: OnceLock<Option<RouteTable>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            let entries = generated_entries().ok()?;
            RouteTable::build(entries, &SHADOWING).ok()
        })
        .as_ref()
}

/// The operation `parts` addresses, or `None` when the wire layer refuses the head or no route
/// matches it.
pub(crate) fn operation(parts: &Parts, resolver: &dyn HostResolver) -> Option<&'static str> {
    let mut head = http::Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version)
        .body(())
        .ok()?;
    *head.headers_mut() = parts.headers.clone();
    let wire = WireRequest::accept(head, &Limits::default()).ok()?;
    let resolved = resolver.resolve(&HostQuery {
        host: wire.host(),
        path: wire.raw_path().as_str(),
        method: wire.method(),
    });
    let request = RouteRequestParts {
        method: wire.method(),
        path: wire.raw_path().as_str(),
        target: resolved.target,
        host_class: resolved.host_class,
        arn_form: resolved.arn_form,
        query: wire.query(),
        headers: wire.headers(),
        host_named_bucket: resolved.bucket().is_some(),
    };
    table()?.resolve(&request).map(|entry| entry.op_name)
}

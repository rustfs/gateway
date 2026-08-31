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

//! Route-only operations own protocol selectors without inventing a handler surface.
//!
//! Responsible for: proving exact route ownership, neighbouring-request isolation, and the
//! operation-specific refusal produced when no truthful DTO and codec can be generated.
//! NOT responsible for: general route ordering or parameter validation.
//! Upstream: the generated route table and core dispatch. Downstream: the integration harness.

use crate::support::Req;

use http::StatusCode;
use rustfs_gateway_core::dispatch::{NOT_REGISTERED_MESSAGE, Router};
use rustfs_gateway_core::op::{AuthRequirement, ResourceShape};
use rustfs_gateway_core::registry::{OperationSpec, Registry};
use rustfs_gateway_core::route::{RouteTable, generated_entries};
use rustfs_gateway_types::ErrorCode;

static LIST_OBJECTS: OperationSpec = OperationSpec::builder("ListObjects", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket))
    .build();

fn table() -> RouteTable {
    let entries = generated_entries().expect("the generated rows parse");
    RouteTable::build(entries, &rustfs_gateway_core::route::SHADOWING)
        .expect("the generated table is well formed under the strict shadowing policy")
}

fn routed(table: &RouteTable, request: &Req) -> Option<&'static str> {
    table.resolve(&request.parts()).map(|entry| entry.op_name)
}

/// A route-only operation still owns its exact request shape even though codegen deliberately
/// emits no public DTO or handler registration surface for it.
#[test]
fn create_session_owns_the_bucket_session_route() {
    assert_eq!(routed(&table(), &Req::new("GET /bucket?session")), Some("CreateSession"));
}

/// Close spellings, methods and resource targets remain with their ordinary operations.
#[test]
fn create_session_does_not_claim_neighbouring_request_shapes() {
    let table = table();
    assert_eq!(routed(&table, &Req::new("GET /bucket?sessionx")), Some("ListObjects"));
    assert_eq!(routed(&table, &Req::new("GET /bucket/key?session")), Some("GetObject"));
    assert_ne!(routed(&table, &Req::new("PUT /bucket?session")), Some("CreateSession"));
    assert_ne!(routed(&table, &Req::new("HEAD /bucket?session")), Some("CreateSession"));
}

/// Route-only operations are protocol-known but intentionally cannot be registered without a
/// truthful generated DTO and codec surface.
#[test]
fn create_session_is_an_operation_specific_protocol_refusal() {
    let mut registry = Registry::new();
    registry.register(&LIST_OBJECTS).expect("the fallback listing is registrable");
    let router = Router::from_generated(registry).expect("the generated table is valid");

    let error = router
        .dispatch(&Req::new("GET /bucket?session").parts())
        .expect_err("route-only CreateSession has no handler registration surface");
    assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED);
    assert_eq!(error.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(error.message(), NOT_REGISTERED_MESSAGE);
    assert_eq!(error.operation(), Some("CreateSession"));
}

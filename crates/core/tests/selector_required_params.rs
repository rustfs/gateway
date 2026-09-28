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

//! c-param-1003 on a real operation: `id` both selects `GetBucketAnalyticsConfiguration` and is
//! its required parameter.
//!
//! Responsible for: the runtime answer each of the two roles produces — the selector sends a
//! request without `id` to the listing rather than to a route miss, and the required role makes a
//! read decoded without `id` the operation's static `400` rather than a silent `None`.
//! NOT responsible for: refusing a spec that records only one role; that is lowering's
//! `selector_params` check, exercised by the model crate's `selector_param_tests`.
//! Upstream: the generated route table and codec. Downstream: nothing.
//!
//! The intersection is real in the pinned model: rustfs/gateway#545 added the analytics pair, and
//! eleven more operation/parameter pairs share the shape (the other three `id`-selected bucket
//! configuration reads, the `uploadId`/`partNumber` multipart rows, and `GetObjectAnnotation`'s
//! `annotationName`).

use crate::support;

use http::{Request, StatusCode};
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::dispatch::Router;
use rustfs_gateway_core::op::Operation;
use rustfs_gateway_core::registry::Registry;
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto;
use support::Req;

fn router() -> Router {
    let mut registry = Registry::new();
    registry
        .register(<dto::GetBucketAnalyticsConfiguration as Operation>::spec())
        .expect("a registrable spec");
    registry
        .register(<dto::ListBucketAnalyticsConfigurations as Operation>::spec())
        .expect("a registrable spec");
    Router::from_generated(registry).expect("the generated table builds")
}

fn accepted(target: &str) -> WireRequest<()> {
    let request = Request::builder()
        .method("GET")
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// c-param-1003 — the selector role: with `id`, the single-configuration read.
#[test]
fn c_param_1003_the_discriminator_selects_the_single_configuration_read() {
    let router = router();
    let request = Req::new("GET /bucket?analytics&id=report");
    let dispatch = router.dispatch(&request.parts()).expect("routed and valid");
    assert_eq!(dispatch.entry.op_name, "GetBucketAnalyticsConfiguration");
}

/// c-param-1003 — the selector role, other direction: without `id` the request is the listing,
/// never a route miss and never the single read refusing a parameter it was not asked for.
#[test]
fn n_c_param_1003_without_the_discriminator_the_request_is_the_listing_not_a_501() {
    let router = router();
    let request = Req::new("GET /bucket?analytics");
    let dispatch = router.dispatch(&request.parts()).expect("a listing, not a refusal");
    assert_eq!(dispatch.entry.op_name, "ListBucketAnalyticsConfigurations");
}

/// c-param-1003 — the required role: the read decoded without `id` is the operation's own static
/// `400`, naming the member and echoing nothing from the request.
#[test]
fn n_c_param_1003_the_read_without_its_required_parameter_is_a_static_400() {
    let request = accepted("/bucket?analytics");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let error = dto::GetBucketAnalyticsConfiguration::decode(&view, RequestBody::None)
        .expect_err("`id` is required by the operation, not only by the route");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_ne!(error.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
    assert_eq!(error.member(), Some("Id"));
}

/// c-param-1003 — the required role, positive control: with `id` the read decodes it.
#[test]
fn c_param_1003_the_read_with_its_required_parameter_decodes_it() {
    let request = accepted("/bucket?analytics&id=report");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::GetBucketAnalyticsConfiguration::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.id, "report");
}

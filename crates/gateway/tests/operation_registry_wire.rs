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

//! Proves a registered vendor operation traverses the public wire pipeline.
//!
//! Responsible for: measuring authentication, both authorization stages, handler reachability,
//! and rendered output for one reviewed dialect codec. NOT responsible for: dialect assembly
//! refusals, registry hot updates, or standard operation behavior. Upstream: the shared signed
//! request and dialect fixtures. Downstream: P4-06's `c-reg-0004` acceptance case.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{HeaderValue, Method, StatusCode};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Decision, InputAuthzRequest, InputDecisions, RequestContext, S3Service,
};

use crate::support::{self, CountingBackend, Ping, exchange, signed, signed_with, wired_at_signed_time};

#[derive(Default)]
struct PipelineCounts {
    route: AtomicUsize,
    input: AtomicUsize,
    handler: Arc<AtomicUsize>,
}

struct MeasuredAuthorizer {
    counts: Arc<PipelineCounts>,
    route: Decision,
    input: Decision,
}

impl Authorizer for MeasuredAuthorizer {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        self.counts.route.fetch_add(1, Ordering::SeqCst);
        let decision = self.route;
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.counts.input.fetch_add(1, Ordering::SeqCst);
        let decision = self.input;
        let decisions = request.decide_all(decision, |_| decision);
        Box::pin(async move { decisions })
    }
}

fn measured_service(route: Decision, input: Decision) -> (S3Service, Arc<PipelineCounts>) {
    let counts = Arc::new(PipelineCounts::default());
    let backend = Arc::new(CountingBackend::new(&counts.handler));
    let service = wired_at_signed_time()
        .dialect(&support::ping_dialect())
        .authorizer(MeasuredAuthorizer {
            counts: Arc::clone(&counts),
            route,
            input,
        })
        .register::<Ping, _>(backend)
        .build()
        .expect("the reviewed vendor route and codec must assemble");
    (service, counts)
}

fn assert_counts(counts: &PipelineCounts, route: usize, input: usize, handler: usize) {
    assert_eq!(counts.route.load(Ordering::SeqCst), route, "unexpected route authorization count");
    assert_eq!(counts.input.load(Ordering::SeqCst), input, "unexpected input authorization count");
    assert_eq!(counts.handler.load(Ordering::SeqCst), handler, "unexpected handler count");
}

/// Positive — one signed vendor request reaches every stage and its codec renders the answer.
#[tokio::test]
async fn c_reg_0004_a_registered_vendor_codec_uses_the_whole_wire_pipeline() {
    let (service, counts) = measured_service(Decision::Allow, Decision::Allow);

    let (status, body) = exchange(&service, signed(Method::POST, "/")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<Ping>pong</Ping>");
    assert_counts(&counts, 1, 1, 1);
}

/// Negative — a tampered signed header is refused before either authorization stage or handler.
#[tokio::test]
async fn n_c_reg_0004_authentication_failure_cannot_reach_vendor_authorization() {
    let (service, counts) = measured_service(Decision::Allow, Decision::Allow);
    let mut request = signed_with(Method::POST, "/", &[("x-amz-meta-probe", "signed")]);
    request
        .headers_mut()
        .insert("x-amz-meta-probe", HeaderValue::from_static("tampered"));

    let (status, body) = exchange(&service, request).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body.contains("<Code>InvalidAccessKeyId</Code>"),
        "the default must keep a wrong signature indistinguishable from an unknown key: {body}"
    );
    assert_counts(&counts, 0, 0, 0);
}

/// Negative — route denial renders before decoded-input authorization or the handler.
#[tokio::test]
async fn n_c_reg_0004_route_denial_cannot_reach_vendor_input_or_handler() {
    let (service, counts) = measured_service(Decision::Deny, Decision::Allow);

    let (status, body) = exchange(&service, signed(Method::POST, "/")).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_counts(&counts, 1, 0, 0);
}

/// Negative — decoded-input denial renders after both decisions and before the handler.
#[tokio::test]
async fn n_c_reg_0004_input_denial_cannot_reach_the_vendor_handler() {
    let (service, counts) = measured_service(Decision::Allow, Decision::Deny);

    let (status, body) = exchange(&service, signed(Method::POST, "/")).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_counts(&counts, 1, 1, 0);
}

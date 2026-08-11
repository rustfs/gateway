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

//! The aggregate call-order oracle for an assembled request.
//!
//! Responsible for: counting every installed request-pipeline extension in one signed request and
//! comparing the observed sequence with `docs/assembly-order.md`.
//! NOT responsible for: each extension's local semantics, which its own integration suite covers.
//! Upstream: `rustfs-gateway`. Downstream: `docs/assembly-order.md`.

#[path = "assembly_order/host.rs"]
mod order_host;
use crate::support;

use std::sync::{Arc, Mutex};

use rustfs_gateway::dto::GetObjectAttributes;
use rustfs_gateway::{
    Authentication, AuthenticationOutcome, Authenticator, Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, BoxFuture,
    CorsSource, CorsSourceError, Credentials, Decision, Governor, GovernorRequest, Handler, HandlerResult, InputAuthzRequest,
    InputDecisions, Lease, Next, NoAuthzAudit, NoCors, NoObserver, NoPolicy, Observer, PolicyError, PolicySnapshot, PolicySource,
    RegionSet, Req, RequestContext, RequestEvent, SigV4Authenticator, StageFilter, StaticCredentials, Unavailable, Unlimited,
    WireHead, allow_when, op_layer,
};
use support::{Attributes, attributes_request, fixed_clock};

type Trail = Arc<Mutex<Vec<&'static str>>>;

fn note(trail: &Trail, label: &'static str) {
    trail.lock().expect("not poisoned").push(label);
}

struct Mark<T> {
    inner: T,
    label: &'static str,
    trail: Trail,
}

impl<T> Mark<T> {
    fn new(inner: T, label: &'static str, trail: &Trail) -> Self {
        Self {
            inner,
            label,
            trail: Arc::clone(trail),
        }
    }

    fn note(&self) {
        note(&self.trail, self.label);
    }
}

impl<T: Governor> Governor for Mark<T> {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        self.note();
        self.inner.try_acquire(request)
    }
}

impl<T: Authenticator> Authenticator for Mark<T> {
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        self.note();
        self.inner.authenticate(request)
    }
}

impl<T: PolicySource> PolicySource for Mark<T> {
    fn snapshot<'a>(
        &'a self,
        identity: Option<&'a rustfs_gateway::Identity>,
    ) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        self.note();
        self.inner.snapshot(identity)
    }
}

impl<T: Authorizer> Authorizer for Mark<T> {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        note(&self.trail, "authorize_route");
        self.inner.authorize_route(context, request)
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        note(&self.trail, "authorize_input");
        self.inner.authorize_input(context, request)
    }
}

impl<T: AuthzAuditSink> AuthzAuditSink for Mark<T> {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        note(
            &self.trail,
            match event.stage {
                rustfs_gateway::AuthzStage::Route => "audit_route",
                rustfs_gateway::AuthzStage::Input => "audit_input",
            },
        );
        self.inner.on_decision(event);
    }
}

impl<T: CorsSource> CorsSource for Mark<T> {
    fn load<'a>(
        &'a self,
        bucket: &'a rustfs_gateway::BucketName,
    ) -> BoxFuture<'a, Result<Option<rustfs_gateway::dto::CorsConfiguration>, CorsSourceError>> {
        self.note();
        self.inner.load(bucket)
    }
}

impl<T: Observer> Observer for Mark<T> {
    fn on_response(&self, event: &RequestEvent<'_>) {
        self.note();
        self.inner.on_response(event);
    }
}

impl<O, T> Handler<O> for Mark<T>
where
    O: rustfs_gateway::Operation,
    T: Handler<O>,
{
    fn call(&self, request: Req<O>) -> impl core::future::Future<Output = HandlerResult<O>> + Send {
        self.note();
        self.inner.call(request)
    }
}

struct Filter(Trail);

impl StageFilter for Filter {
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), rustfs_gateway::HandlerError> {
        note(&self.0, "filter_wire");
        Ok(())
    }

    fn on_routed(&self, _routed: &rustfs_gateway::RoutedView<'_>) -> Result<(), rustfs_gateway::HandlerError> {
        note(&self.0, "filter_routed");
        Ok(())
    }

    fn on_response(
        &self,
        _view: &rustfs_gateway::ResponseView<'_>,
        _response: &mut http::Response<rustfs_gateway::Body>,
    ) -> Result<(), rustfs_gateway::HandlerError> {
        note(&self.0, "filter_response");
        Ok(())
    }
}

/// a-asm-0004/a-asm-0022. One request calls every installed extension exactly as the documented
/// order says, including host/routed before governor and governor before body/authentication.
#[tokio::test]
async fn one_request_has_one_aggregate_extension_order() {
    let trail = Arc::new(Mutex::new(Vec::new()));
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let layer_trail = Arc::clone(&trail);
    let layer = op_layer(
        move |request: Req<GetObjectAttributes>,
              next: Next<'_, GetObjectAttributes>|
              -> BoxFuture<'_, HandlerResult<GetObjectAttributes>> {
            note(&layer_trail, "op_layer");
            Box::pin(async move { next.run(request).await })
        },
    );
    let service = rustfs_gateway::ServiceBuilder::new()
        .register::<GetObjectAttributes, _>(Arc::new(Mark::new(Attributes, "handler", &trail)))
        .authenticator(Mark::new(
            SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")),
            "authenticate",
            &trail,
        ))
        .authorizer(Mark::new(allow_when(|_| true), "authorizer", &trail))
        .policy_source(Mark::new(NoPolicy, "policy", &trail))
        .authz_audit(Mark::new(NoAuthzAudit, "audit", &trail))
        .host_resolver(order_host::RecordingHost::new(&trail))
        .governor(Mark::new(Unlimited, "governor", &trail))
        .cors_source(Mark::new(NoCors, "cors", &trail))
        .observer(Mark::new(NoObserver, "observer", &trail))
        .stage_filter(Filter(Arc::clone(&trail)))
        .op_layer::<GetObjectAttributes, _>(layer)
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");
    let mut request = attributes_request();
    request
        .headers_mut()
        .insert(http::header::ORIGIN, http::HeaderValue::from_static("https://example.test"));

    let response = service.call_bytes(request).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        trail.lock().expect("not poisoned").as_slice(),
        [
            "filter_wire",
            "host",
            "filter_routed",
            "governor",
            "authenticate",
            "policy",
            "authorize_route",
            "audit_route",
            "cors",
            "authorize_input",
            "audit_input",
            "op_layer",
            "handler",
            "filter_response",
            "observer",
        ]
    );
}

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

//! The public sealed static-operation entry and its fail-closed identity check.
//!
//! Responsible for: proving one generic entry preserves authorization order and rejects a wrong
//! routed operation before body, codec, or handler work.
//! NOT responsible for: facade assembly or assembly-code inspection.
//! Upstream: `rustfs-gateway-core`. Downstream: `rustfs-gateway::build_monomorphic`.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway_core::{
    AuthRequirement, CodecError, EncodedResponse, Handler, HandlerResult, MetaView, NoDerived, Operation, OperationCodec,
    OperationOrigin, OperationSpec, Req, RequestBody, ResourceShape, Resp, StaticDispatchError, StaticDispatchOutcome,
    StaticOperation, TargetKind,
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{OperationFloor, SigService};

static SPEC: OperationSpec = OperationSpec {
    name: "example:StaticProbe",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:Probe", ResourceShape::Service)),
};
static FLOOR: OperationFloor = OperationFloor::builtin("example:StaticProbe", SigService::S3);

struct StaticProbe;

impl Operation for StaticProbe {
    const NAME: &'static str = "example:StaticProbe";
    const ORIGIN: OperationOrigin = OperationOrigin::ThirdParty;
    type Input = ();
    type Output = ();
    type DerivedResources = NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl OperationCodec for StaticProbe {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<Self::Input, CodecError> {
        Ok(())
    }

    fn encode(_output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

struct Backend(Arc<Mutex<Vec<&'static str>>>);

impl Handler<StaticProbe> for Backend {
    async fn call(&self, _request: Req<StaticProbe>) -> HandlerResult<StaticProbe> {
        self.0.lock().expect("trail lock").push("handler");
        Ok(Resp::new(()))
    }
}

fn meta() -> MetaView<'static> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("valid request");
    let wire = Box::leak(Box::new(WireRequest::accept(request, &Limits::default()).expect("accepted")));
    MetaView::of(wire, TargetKind::Service).expect("service meta")
}

/// a-asm-0007. The sealed entry calls route authorization before body work, input authorization
/// after decoding, and the concrete handler last.
#[tokio::test]
async fn the_static_entry_preserves_the_authorization_order() {
    let trail = Arc::new(Mutex::new(Vec::new()));
    let route_trail = Arc::clone(&trail);
    let body_trail = Arc::clone(&trail);
    let input_trail = Arc::clone(&trail);
    let backend = Arc::new(Backend(Arc::clone(&trail)));

    let outcome = StaticOperation::<StaticProbe>::dispatch(
        StaticProbe::NAME,
        &meta(),
        backend,
        move || async move {
            route_trail.lock().expect("trail lock").push("route-authorize");
            Ok::<_, &'static str>(())
        },
        move |()| async move {
            body_trail.lock().expect("trail lock").push("body");
            Ok::<_, &'static str>(((), Bytes::new()))
        },
        move |(), resources| async move {
            input_trail.lock().expect("trail lock").push("input-authorize");
            Ok::<_, &'static str>((vec![rustfs_gateway_core::Decision::Allow; resources.len()], ()))
        },
    )
    .await
    .expect("static dispatch");

    assert!(matches!(outcome, StaticDispatchOutcome::Settled(_)));
    assert_eq!(
        *trail.lock().expect("trail lock"),
        ["route-authorize", "body", "input-authorize", "handler"]
    );
}

/// Negative — a type-list branch naming the wrong operation refuses before the route callback,
/// so it cannot read a body or reach a handler under the wrong codec.
#[tokio::test]
async fn a_routed_identity_mismatch_is_fail_closed() {
    let trail = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(Backend(Arc::clone(&trail)));
    let result = StaticOperation::<StaticProbe>::dispatch(
        "example:AnotherOperation",
        &meta(),
        backend,
        || async { Ok::<_, &'static str>(()) },
        |()| async { Ok::<_, &'static str>(((), Bytes::new())) },
        |(), _| async { Ok::<_, &'static str>((Vec::new(), ())) },
    )
    .await;

    assert!(matches!(result, Err(StaticDispatchError::OperationMismatch { .. })));
    assert!(trail.lock().expect("trail lock").is_empty());
}

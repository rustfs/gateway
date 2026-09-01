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

//! Proves registry replacement is validated, atomic, and shared by service clones.
//!
//! Responsible for: successful and refused routing-snapshot replacement through real signed wire
//! requests, plus a deterministic in-flight snapshot control. NOT responsible for: service-config
//! replacement or dialect validation itself. Upstream: the public service builder and reviewed
//! dialect fixtures. Downstream: P4-06's `c-reg-1012` acceptance case.

use std::sync::{Arc, Mutex};

use http::{Method, StatusCode};
use rustfs_gateway::{
    AuthRequirement, CodecError, EncodedResponse, Handler, HandlerContext, HandlerDeadlineClass, HandlerResult, MetaView,
    NoDerived, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, Req, RequestBody, ResourceShape, Resp,
    S3Service, ServiceBuilder, SigService, StageFilter, TargetKind, WireHead,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, OverlayRow};

use crate::support::{self, HeadPing, Ping, PingInput, PingOutput, exchange, signed, wired_at_signed_time};

struct VersionedBackend(&'static str);

impl Handler<Ping> for VersionedBackend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Ok(Resp::new(PingOutput {
            message: self.0.to_owned(),
        }))
    }

    async fn call_with_context(&self, request: Req<Ping>, _context: HandlerContext) -> HandlerResult<Ping> {
        self.call(request).await
    }
}

impl Handler<HeadPing> for VersionedBackend {
    async fn call(&self, _request: Req<HeadPing>) -> HandlerResult<HeadPing> {
        Ok(Resp::new(PingOutput {
            message: self.0.to_owned(),
        }))
    }

    async fn call_with_context(&self, request: Req<HeadPing>, _context: HandlerContext) -> HandlerResult<HeadPing> {
        self.call(request).await
    }
}

struct ShadowObject;

static SHADOW_SPEC: OperationSpec = OperationSpec::builder("example:ShadowObject", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .auth(AuthRequirement::new("example:ShadowObject", ResourceShape::Object))
    .build();
static SHADOW_FLOOR: OperationFloor = OperationFloor::builtin_presigned("example:ShadowObject", SigService::S3)
    .allow_anonymous_after_listing_in_the_posture_report();
static SHADOW_PREDICATES: &[Predicate] = &[Predicate::Method(Method::PUT), Predicate::Target(TargetKind::Object)];
static SHADOW_OVERLAY: DialectOverlay = DialectOverlay {
    name: "registry-hot-update-test",
    vendor: "example",
    operations: &[OverlayRow {
        name: "example:ShadowObject",
        precedence: 800,
        selector: "Method(PUT) ∧ Target(Object)",
        action: "example:ShadowObject",
        resource: ResourceShape::Object,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/backlog/issues/1700"],
    }],
};

impl Operation for ShadowObject {
    const NAME: &'static str = "example:ShadowObject";
    type Input = PingInput;
    type Output = PingOutput;
    type DerivedResources = NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SHADOW_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &SHADOW_FLOOR
    }
}

impl OperationCodec for ShadowObject {
    fn decode(request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {
        <Ping as OperationCodec>::decode(request, body)
    }

    fn encode(output: Self::Output, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        <Ping as OperationCodec>::encode(output, request, status)
    }
}

impl Handler<ShadowObject> for VersionedBackend {
    async fn call(&self, _request: Req<ShadowObject>) -> HandlerResult<ShadowObject> {
        Ok(Resp::new(PingOutput {
            message: self.0.to_owned(),
        }))
    }

    async fn call_with_context(&self, request: Req<ShadowObject>, _context: HandlerContext) -> HandlerResult<ShadowObject> {
        self.call(request).await
    }
}

fn live(message: &'static str) -> S3Service {
    wired_at_signed_time()
        .dialect(&support::ping_dialect())
        .register::<Ping, _>(Arc::new(VersionedBackend(message)))
        .build()
        .expect("the live service must assemble")
}

fn replacement(message: &'static str) -> ServiceBuilder {
    ServiceBuilder::new()
        .dialect(&support::ping_dialect())
        .dialect(&support::head_ping_dialect())
        .register::<Ping, _>(Arc::new(VersionedBackend(message)))
        .register::<HeadPing, _>(Arc::new(VersionedBackend(message)))
}

fn replacement_without_head(message: &'static str) -> ServiceBuilder {
    ServiceBuilder::new()
        .dialect(&support::ping_dialect())
        .register::<Ping, _>(Arc::new(VersionedBackend(message)))
}

fn shadow_dialect() -> Dialect {
    Dialect::assemble(&SHADOW_OVERLAY)
        .declare::<ShadowObject>(DialectRoute {
            precedence: 800,
            selector: SHADOW_PREDICATES,
            path_shape: "/{bucket}/{key}",
            shadows: &[],
        })
        .build()
        .expect("the test shadow declaration must agree with its overlay")
}

fn conflicting_replacement() -> ServiceBuilder {
    replacement("bad")
        .dialect(&shadow_dialect())
        .register::<ShadowObject, _>(Arc::new(VersionedBackend("bad")))
}

async fn ping(service: &S3Service) -> (StatusCode, String) {
    exchange(service, signed(Method::POST, "/")).await
}

/// Positive — a successful replacement changes the exact answer seen by every service clone.
#[tokio::test]
async fn c_reg_1012_a_successful_registry_update_reaches_every_clone() {
    let service = live("old");
    let clone = service.clone();

    service
        .replace_registry(replacement("new"))
        .expect("the replacement routing snapshot is valid");

    assert_eq!(ping(&service).await, (StatusCode::OK, "<Ping>new</Ping>".to_owned()));
    assert_eq!(ping(&clone).await, (StatusCode::OK, "<Ping>new</Ping>".to_owned()));
    assert_eq!(exchange(&clone, signed(Method::HEAD, "/")).await, (StatusCode::OK, String::new()));
}

/// Negative — a conflicting route rejects the whole update and preserves the last-good snapshot.
#[tokio::test]
async fn n_c_reg_1012_a_conflicting_update_preserves_the_last_good_wire_table() {
    let service = live("old");
    service
        .replace_registry(replacement("new"))
        .expect("the first update is valid");

    let error = service
        .replace_registry(conflicting_replacement())
        .expect_err("the standard PutObject route must not be shadowed");
    assert!(format!("{error:?}").contains("Route"), "the route conflict must be named: {error:?}");
    assert_eq!(ping(&service).await, (StatusCode::OK, "<Ping>new</Ping>".to_owned()));

    let (status, body) = exchange(&service, signed(Method::PUT, "/bucket/key")).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(
        body.contains("<Code>NotImplemented</Code>"),
        "the refused shadow route reached wire: {body}"
    );
    assert!(!body.contains("bad"), "the refused backend reached wire: {body}");
}

type DeferredUpdate = Box<dyn FnOnce() + Send>;

struct UpdatingFilter {
    update: Arc<Mutex<Option<DeferredUpdate>>>,
}

impl StageFilter for UpdatingFilter {
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), rustfs_gateway::HandlerError> {
        if let Some(update) = self.update.lock().expect("the update lock is not poisoned").take() {
            update();
        }
        Ok(())
    }
}

/// Negative — a mid-request update cannot mix the new dispatch with the old resolved route.
#[tokio::test]
async fn n_c_reg_1012_an_inflight_request_holds_one_routing_snapshot() {
    let update = Arc::new(Mutex::new(None));
    let service = wired_at_signed_time()
        .dialect(&support::ping_dialect())
        .dialect(&support::head_ping_dialect())
        .register::<Ping, _>(Arc::new(VersionedBackend("old")))
        .register::<HeadPing, _>(Arc::new(VersionedBackend("old")))
        .stage_filter(UpdatingFilter {
            update: Arc::clone(&update),
        })
        .build()
        .expect("the live service must assemble");
    let updater = service.clone();
    *update.lock().expect("the update lock is not poisoned") = Some(Box::new(move || {
        updater
            .replace_registry(replacement_without_head("new"))
            .expect("the in-flight replacement is valid");
    }));

    assert_eq!(exchange(&service, signed(Method::HEAD, "/")).await, (StatusCode::OK, String::new()));
    assert_eq!(ping(&service).await, (StatusCode::OK, "<Ping>new</Ping>".to_owned()));
}

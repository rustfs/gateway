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

//! Responsible for: fallible route errors before body reads, decoding and invocation.
//! NOT responsible for: policy evaluation or signature algorithms.
//! Upstream: the public authorizer and service; downstream: regression observations.

use super::*;
use rustfs_gateway::{
    CodecError, EncodedResponse, ErrorCode, ErrorHeader, Handler, HandlerError, HandlerResult, MetaView, NoDerived, Operation,
    OperationCodec, OperationFloor, OperationSpec, Req, RequestBody, Resp,
};
use rustfs_gateway_core::HandlerDeadlineClass;

static DECODED: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static PROBE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// Observe the Full codec independently of the handler and wire-body reader.
static PUT_SPEC: OperationSpec = OperationSpec::builder("example:BufferedPut", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .auth(rustfs_gateway::AuthRequirement::all_of(
        &["example:BufferedPut", "example:Second"],
        rustfs_gateway::ResourceShape::Service,
    ))
    .extra_permissions(&[
        rustfs_gateway_core::ExtraPermission::new(
            "example:Extra",
            &[rustfs_gateway_core::HeaderTrigger::Present("x-example-extra")],
            rustfs_gateway_core::ExtraProfile::Generic,
        ),
        rustfs_gateway_core::ExtraPermission::new(
            "example:LaterExtra",
            &[rustfs_gateway_core::HeaderTrigger::Present("x-example-extra")],
            rustfs_gateway_core::ExtraProfile::Generic,
        ),
    ])
    .build();
static PUT_FLOOR: OperationFloor = OperationFloor::custom("example:BufferedPut", rustfs_gateway::SigService::S3);
fn put_dialect() -> rustfs_gateway_core::Dialect {
    use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, OverlayRow, Predicate, ResourceShape, TargetKind};
    static SELECTOR: &[Predicate] = &[Predicate::Method(http::Method::PUT), Predicate::Target(TargetKind::Service)];
    static OVERLAY: DialectOverlay = DialectOverlay {
        name: "example-test",
        vendor: "example",
        claims: &[],
        operations: &[OverlayRow {
            name: "example:BufferedPut",
            precedence: 52,
            selector: "Method(PUT) ∧ Target(Service)",
            action: "allOf(example:BufferedPut, example:Second)",
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: &["https://github.com/rustfs/gateway/issues/37"],
        }],
    };
    Dialect::assemble(&OVERLAY)
        .declare::<BufferedPut>(DialectRoute {
            precedence: 52,
            selector: SELECTOR,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .unwrap()
}
struct BufferedPut;
impl Operation for BufferedPut {
    const NAME: &'static str = "example:BufferedPut";
    type Input = ();
    type Output = ();
    type DerivedResources = NoDerived;
    fn derive_resources(_: &()) -> Result<NoDerived, rustfs_gateway_core::DerivedResourceError> {
        Ok(NoDerived)
    }
    fn seal_derived_input(_: &mut ()) {}
    fn spec() -> &'static OperationSpec {
        &PUT_SPEC
    }
    fn floor() -> &'static OperationFloor {
        &PUT_FLOOR
    }
}
impl OperationCodec for BufferedPut {
    fn decode(_: &MetaView<'_>, _: RequestBody) -> Result<(), CodecError> {
        DECODED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn encode(_: (), _: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}
struct PutHandler;
impl Handler<BufferedPut> for PutHandler {
    async fn call(&self, _: Req<BufferedPut>) -> HandlerResult<BufferedPut> {
        HANDLED.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(()))
    }
}

struct Fallible {
    fail_extra: bool,
    allow: bool,
    asked: Mutex<Vec<String>>,
}
impl Authorizer for Fallible {
    fn authorize_route<'a>(&'a self, _: &'a RequestContext<'a>, _: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Deny })
    }
    fn authorize_route_result<'a>(
        &'a self,
        _: &'a RequestContext<'a>,
        request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Result<Decision, HandlerError>> {
        self.asked.lock().unwrap().push(request.action.to_owned());
        Box::pin(async move {
            if self.allow || (self.fail_extra && !request.action.ends_with("Extra")) {
                Ok(Decision::Allow)
            } else {
                Err(HandlerError::new(ErrorCode::SERVICE_UNAVAILABLE, "private gate failure")
                    .with_header(ErrorHeader::RetryAfter { seconds: 7 }))
            }
        })
    }
    fn authorize_input<'a>(
        &'a self,
        _: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        Box::pin(async move { request.decide_all(Decision::Allow, |_| Decision::Allow) })
    }
}

async fn roundtrip(extra: bool, allow: bool) {
    let _guard = PROBE_LOCK.lock().await;
    // An Arc passed to builder is wrapped once more: this exercises Arc's explicit forwarding.
    {
        DECODED.store(0, Ordering::SeqCst);
        HANDLED.store(0, Ordering::SeqCst);
        let authorizer = Arc::new(Fallible {
            fail_extra: extra,
            allow,
            asked: Mutex::new(Vec::new()),
        });
        let recorder = Arc::new(Recorder::default());
        let service = base()
            .register::<BufferedPut, _>(Arc::new(PutHandler))
            .dialect(&put_dialect())
            .authorizer(Arc::clone(&authorizer))
            .authz_audit(Arc::clone(&recorder))
            .build()
            .unwrap();
        let headers = if extra {
            vec![("content-length", "1"), ("x-example-extra", "true")]
        } else {
            vec![("content-length", "1")]
        };
        let request = support::signed_target_with_body_and_headers(http::Method::PUT, "/", &headers, Bytes::from_static(b"x"));
        let (parts, bytes) = request.into_parts();
        let (body, read) = CountingBody::new(bytes);
        let started = Instant::now();
        let response = service.call(http::Request::from_parts(parts, body)).await;
        let response = rustfs_gateway::collect(response).await.unwrap();
        let text = String::from_utf8(response.body().to_vec()).unwrap();
        let events = recorder.events();
        let observation = (
            response.status().as_u16(),
            support::element_text(&text, "Code"),
            support::element_text(&text, "Message"),
            response
                .headers()
                .iter()
                .find(|(name, _)| name.as_str() == "retry-after")
                .map(|(_, value)| value.to_str().unwrap()),
            (
                read.load(Ordering::SeqCst),
                DECODED.load(Ordering::SeqCst),
                HANDLED.load(Ordering::SeqCst),
            ),
            events.iter().map(|event| event.decision).collect::<Vec<_>>(),
            events.iter().any(|event| event.rendered.contains("private gate failure")),
            authorizer.asked.lock().unwrap().clone(),
            allow || started.elapsed() >= Duration::from_millis(25),
        );
        let mut asked = vec!["example:BufferedPut".to_owned()];
        if extra || allow {
            asked.push("example:Second".to_owned());
        }
        if extra {
            asked.push("example:Extra".to_owned());
        }
        if extra && allow {
            asked.push("example:LaterExtra".to_owned());
        }
        let expected = if allow {
            (
                200,
                None,
                None,
                None,
                (1, 1, 1),
                vec![Decision::Allow, Decision::Allow],
                false,
                asked,
                true,
            )
        } else {
            (
                503,
                Some("ServiceUnavailable"),
                Some("private gate failure"),
                Some("7"),
                (0, 0, 0),
                vec![Decision::Indeterminate],
                false,
                asked,
                true,
            )
        };
        assert_eq!(observation, expected, "extra={extra}, allow={allow}");
    }
}

#[tokio::test]
async fn n_route_result_default_preserves_every_legacy_decision() {
    for decision in [Decision::Allow, Decision::Deny, Decision::Indeterminate] {
        let authorizer = Arc::new(Fixed::new(decision));
        let recorder = Arc::new(Recorder::default());
        let service = base()
            .authorizer(Arc::clone(&authorizer))
            .authz_audit(Arc::clone(&recorder))
            .build()
            .unwrap();
        assert_eq!(
            exchange(&service, ping()).await.0,
            if decision == Decision::Allow {
                http::StatusCode::OK
            } else {
                http::StatusCode::FORBIDDEN
            }
        );
        assert_eq!(recorder.events()[0].decision, decision);
        assert_eq!(authorizer.calls(), if decision == Decision::Allow { 2 } else { 1 });
    }
}

#[tokio::test]
async fn n_route_result_head_errors_keep_headers_without_a_document() {
    let authorizer = Fallible {
        fail_extra: false,
        allow: false,
        asked: Mutex::new(Vec::new()),
    };
    let service = base()
        .register::<support::HeadPing, _>(Arc::new(Backend))
        .dialect(&support::head_ping_dialect())
        .authorizer(authorizer)
        .build()
        .unwrap();
    let response = exchange_wire(&service, support::signed(http::Method::HEAD, "/")).await;
    assert_eq!(
        (
            response.status().as_u16(),
            response.body().len(),
            response
                .headers()
                .iter()
                .find(|(name, _)| name.as_str() == "retry-after")
                .map(|(_, value)| value.to_str().unwrap())
        ),
        (503, 0, Some("7"))
    );
}

#[tokio::test]
async fn n_route_result_base_error_stops_before_later_questions_or_body() {
    roundtrip(false, false).await;
}
#[tokio::test]
async fn n_route_result_extra_error_stops_before_later_extras_or_body() {
    roundtrip(true, false).await;
}
#[tokio::test]
async fn p_route_result_base_allow_reads_decodes_and_invokes() {
    roundtrip(false, true).await;
}
#[tokio::test]
async fn p_route_result_extra_allow_reads_decodes_and_invokes() {
    roundtrip(true, true).await;
}

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
    AuthRequirement, CodecError, EncodedResponse, Handler, HandlerDeadlineClass, HandlerResult, HeadPart, MetaView, NoDerived,
    Operation, OperationCodec, OperationOrigin, OperationSpec, Req, RequestBody, ResourceShape, Resp, StaticDispatchError,
    StaticDispatchOutcome, StaticOperation, TargetKind,
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{CompleteMultipartUpload, CompleteMultipartUploadOutput};

use crate::support::sse_proof;

static SPEC: OperationSpec = OperationSpec::builder("example:StaticProbe", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:Probe", ResourceShape::Service))
    .build();
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
    async fn call(&self, request: Req<StaticProbe>) -> HandlerResult<StaticProbe> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    async fn call_with_context(
        &self,
        _request: Req<StaticProbe>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> HandlerResult<StaticProbe> {
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
            Ok::<_, &'static str>(((), RequestBody::Buffered(Bytes::new())))
        },
        move |(), resources| async move {
            input_trail.lock().expect("trail lock").push("input-authorize");
            Ok::<_, &'static str>((vec![rustfs_gateway_core::Decision::Allow; resources.len()], (), sse_proof()))
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
        |()| async { Ok::<_, &'static str>(((), RequestBody::Buffered(Bytes::new()))) },
        |(), _| async { Ok::<_, &'static str>((Vec::new(), (), sse_proof())) },
    )
    .await;

    assert!(matches!(result, Err(StaticDispatchError::OperationMismatch { .. })));
    assert!(trail.lock().expect("trail lock").is_empty());
}

// ── the wrapper the framework puts around a committed continuation ───────────────────────────────
//
// `Resp::map_commit_work` lives in `crates/core/src/handler.rs`, and these two tests live here
// rather than beside it because `crates/core/tests/purity_guard.rs` counts `.await` and `Box::pin`
// over that crate's whole `src` tree — test code included. A continuation is a boxed future and
// driving one needs an await, so a unit test of this would have raised the routing path's async
// count and the framework's pin count, and the honest place for it is a test target the guard does
// not scan.

/// **Negative — a wrapper for continuations is not a wrapper for everything.**
///
/// `map_commit_work` exists so the framework can put a bound around the work a backend committed
/// to. The failure mode is that it runs for the other two answer shapes as well: an event stream
/// would then be rebuilt through a closure written for a document continuation. Both non-committed
/// shapes are checked, and the closure records whether it ran rather than being trusted not to.
#[test]
fn mapping_a_commit_leaves_a_settled_answer_and_an_event_stream_alone() {
    let mut called = false;
    let settled = Resp::<StaticProbe>::with_status((), 299).map_commit_work(|work| {
        called = true;
        work
    });
    assert!(!called, "the continuation wrapper ran on a settled answer");
    assert_eq!(settled.status(), 299);
    assert!(settled.output().is_some());

    let mut called = false;
    let stream = Resp::<StaticProbe>::event_stream(rustfs_gateway_stream::ByteStream::from_bytes(Bytes::from_static(b"f")))
        .map_commit_work(|work| {
            called = true;
            work
        });
    assert!(!called, "the continuation wrapper ran on an event stream");
    assert!(stream.is_event_stream());
    assert_eq!(stream.status(), 200);
}

/// **Positive — it does run for a continuation, and the status the head went out with survives.**
///
/// The second half is the one a rebuild at the call site would lose: `Answer` has three variants and
/// only `commit_with_status` can carry an arbitrary status, so an implementation that destructured
/// and reassembled would quietly move this back to the operation's declared `200`.
#[tokio::test]
async fn mapping_a_commit_replaces_the_work_and_keeps_the_committed_status() {
    let response = Resp::<CompleteMultipartUpload>::commit_with_status(
        HeadPart::new(http::HeaderMap::new()).expect("an empty operation head"),
        Box::pin(async {
            Err::<CompleteMultipartUploadOutput, _>(rustfs_gateway_core::HandlerError::internal_error("the original"))
        }),
        206,
    )
    .map_commit_work(|_original| {
        Box::pin(async {
            Err::<CompleteMultipartUploadOutput, _>(rustfs_gateway_core::HandlerError::internal_error("the replacement"))
        })
    });
    assert_eq!(response.status(), 206);
    assert!(response.is_committed());
    let (answer, _status) = response.into_parts();
    let rustfs_gateway_core::Answer::Committed(committed) = answer else {
        panic!("a committed answer stopped being one");
    };
    let (_head, work) = committed.into_parts();
    assert_eq!(
        work.await.err().map(|error| error.message().to_owned()),
        Some("the replacement".to_owned())
    );
}

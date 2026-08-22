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

//! Public-facade parity for the sealed monomorphic operation path.
//!
//! Responsible for: comparing ordinary, refusal, committed, event-stream and panic outcomes from
//! `build` and `build_monomorphic`, plus fail-closed operation-set assembly.
//! NOT responsible for: inspecting private stage helpers; the core compile-fail suite owns that.
//! Upstream: the two public builders. Downstream: the static-dispatch assembly guard.

#![allow(clippy::panic)]

use crate::support;

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustfs_gateway::{
    AssemblyError, ClockSkewAck, Handler, HandlerCancellation, HandlerDeadlineConfig, HandlerResult, HeadPart, Next,
    OperationSetEnd, OperationSetNode, Req, RuleRef, ServiceBuilder, ServiceConfig, WireResponse, dto, op_layer,
};
use support::{Backend, ContentPing, HeadPing, Ping, PingOutput, content_ping_route, head_ping_route, ping_route, plain, wired};

type OrdinaryOperations = OperationSetNode<
    Ping,
    OperationSetNode<HeadPing, OperationSetNode<ContentPing, OperationSetNode<dto::ListBuckets, OperationSetEnd>>>,
>;
type SelectOperations = OperationSetNode<dto::SelectObjectContent, OperationSetEnd>;

fn ordinary_builder(backend: Arc<Backend>) -> ServiceBuilder {
    wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .register::<HeadPing, _>(Arc::clone(&backend))
        .register::<ContentPing, _>(Arc::clone(&backend))
        .register::<dto::ListBuckets, _>(backend)
        .route(ping_route())
        .route(head_ping_route())
        .route(content_ping_route())
}

async fn collect(response: http::Response<rustfs_gateway::Body>) -> WireResponse {
    rustfs_gateway::collect(response).await.expect("an in-memory body")
}

fn assert_wire_parity(dynamic: &WireResponse, monomorphic: &WireResponse) {
    fn header<'a>(response: &'a WireResponse, wanted: &http::HeaderName) -> Option<&'a http::HeaderValue> {
        response
            .headers()
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value)
    }
    assert_eq!(monomorphic.status(), dynamic.status());
    assert_eq!(
        header(monomorphic, &http::header::CONTENT_TYPE),
        header(dynamic, &http::header::CONTENT_TYPE)
    );
    assert_eq!(
        header(monomorphic, &http::header::CONTENT_LENGTH),
        header(dynamic, &http::header::CONTENT_LENGTH)
    );
    if dynamic.body().windows(7).any(|window| window == b"<Error>") {
        let dynamic_body = std::str::from_utf8(dynamic.body()).expect("a UTF-8 error document");
        let static_body = std::str::from_utf8(monomorphic.body()).expect("a UTF-8 error document");
        for element in ["Code", "Message", "Condition"] {
            assert_eq!(support::element_text(static_body, element), support::element_text(dynamic_body, element));
        }
        for element in ["RequestId", "HostId"] {
            assert!(support::element_text(static_body, element).is_some_and(|value| !value.is_empty()));
            assert!(support::element_text(dynamic_body, element).is_some_and(|value| !value.is_empty()));
        }
    } else {
        assert_eq!(monomorphic.body(), dynamic.body());
    }
}

enum ContextBehavior {
    Immediate,
    Cooperative(Arc<AtomicBool>),
    Uncooperative,
}

struct ContextOnly {
    behavior: ContextBehavior,
}

impl ContextOnly {
    fn immediate() -> Self {
        Self {
            behavior: ContextBehavior::Immediate,
        }
    }

    fn cooperative(rollback_completed: Arc<AtomicBool>) -> Self {
        Self {
            behavior: ContextBehavior::Cooperative(rollback_completed),
        }
    }

    fn uncooperative() -> Self {
        Self {
            behavior: ContextBehavior::Uncooperative,
        }
    }
}

impl Handler<Ping> for ContextOnly {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Err(rustfs_gateway::HandlerError::internal_error("the legacy handler entry was used"))
    }

    async fn call_with_context(&self, _request: Req<Ping>, context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        match &self.behavior {
            ContextBehavior::Immediate => {
                assert!(context.cancellation_reason().is_none());
                Ok(rustfs_gateway::Resp::new(PingOutput {
                    message: "the monomorphic path preserved its handler context".to_owned(),
                }))
            }
            ContextBehavior::Cooperative(rollback_completed) => loop {
                if matches!(context.cancellation_reason(), Some(HandlerCancellation::Deadline)) {
                    rollback_completed.store(true, Ordering::Release);
                    return Ok(rustfs_gateway::Resp::new(PingOutput {
                        message: "a late handler result must not become the response".to_owned(),
                    }));
                }
                futures_timer::Delay::new(Duration::from_millis(1)).await;
            },
            ContextBehavior::Uncooperative => core::future::pending().await,
        }
    }
}

/// Positive — the public monomorphic facade must call the context-aware handler entry rather than
/// silently falling back to the temporary one-argument migration bridge.
#[tokio::test]
async fn monomorphic_dispatch_reaches_the_context_aware_handler_entry() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let backend = Arc::new(ContextOnly::immediate());
    let monomorphic = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .build_monomorphic::<_, Operations>(backend)
        .expect("a complete static assembly");

    let response = collect(monomorphic.call_bytes(plain(http::Method::POST, "/")).await).await;
    assert_eq!(response.status(), http::StatusCode::OK);
}

fn short_handler_deadlines() -> ServiceConfig {
    let deadlines = HandlerDeadlineConfig::new(Duration::from_millis(10), Duration::from_millis(10))
        .expect("non-zero handler deadlines")
        .try_with_cleanup_grace(Duration::from_millis(20))
        .expect("a non-zero cleanup grace");
    ServiceConfig::new(1024).with_handler_deadlines(deadlines)
}

/// Negative — the monomorphic path must signal deadline cancellation, observe cooperative cleanup,
/// and discard the handler result completed after the response race was lost.
#[tokio::test]
async fn monomorphic_handler_deadline_signals_cleanup_and_discards_the_late_result() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let rollback_completed = Arc::new(AtomicBool::new(false));
    let backend = Arc::new(ContextOnly::cooperative(Arc::clone(&rollback_completed)));
    let (builder, _config) = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .config(short_handler_deadlines());
    let monomorphic = builder
        .build_monomorphic::<_, Operations>(backend)
        .expect("a complete static assembly");

    let response = collect(monomorphic.call_bytes(plain(http::Method::POST, "/")).await).await;
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(rollback_completed.load(Ordering::Acquire));
}

/// Negative — a handler that ignores cancellation must be abandoned after the bounded cleanup
/// grace instead of keeping the request future alive indefinitely.
#[tokio::test]
async fn monomorphic_handler_deadline_bounds_an_uncooperative_handler() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let backend = Arc::new(ContextOnly::uncooperative());
    let (builder, _config) = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .config(short_handler_deadlines());
    let monomorphic = builder
        .build_monomorphic::<_, Operations>(backend)
        .expect("a complete static assembly");

    let started = Instant::now();
    let response = collect(monomorphic.call_bytes(plain(http::Method::POST, "/")).await).await;
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// a-asm-0007. The public static builder preserves ordinary, refusal and committed response
/// semantics while selecting the operation codec and handler through the type-level set.
#[tokio::test]
async fn static_and_dynamic_document_shapes_are_identical() {
    let dynamic = ordinary_builder(Arc::new(Backend))
        .build()
        .expect("a complete dynamic assembly");
    let static_backend = Arc::new(Backend);
    let monomorphic = ordinary_builder(Arc::clone(&static_backend))
        .build_monomorphic::<_, OrdinaryOperations>(static_backend)
        .expect("a complete static assembly");

    for (method, uri) in [(http::Method::POST, "/"), (http::Method::PUT, "/?refuse")] {
        let dynamic_response = collect(dynamic.call_bytes(plain(method.clone(), uri)).await).await;
        let static_response = collect(monomorphic.call_bytes(plain(method, uri)).await).await;
        assert_wire_parity(&dynamic_response, &static_response);
    }
}

struct CommittedCopy(support::CopyCommit);

impl Handler<dto::CopyObject> for CommittedCopy {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        let outcome = self.0;
        Ok(rustfs_gateway::Resp::commit(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(async move {
                match outcome {
                    support::CopyCommit::Answer => Ok(dto::CopyObjectOutput::default()),
                    support::CopyCommit::Fail => Err(rustfs_gateway::HandlerError::new(
                        rustfs_gateway::ErrorCode::NO_SUCH_KEY,
                        "the source key disappeared",
                    )),
                }
            }),
        ))
    }
}

/// a-asm-0007. Both dispatch paths detach the same generated operation and render either terminal
/// document after the same frozen head.
#[tokio::test]
async fn static_and_dynamic_committed_document_shapes_are_identical() {
    type Operations = OperationSetNode<dto::CopyObject, OperationSetEnd>;
    for outcome in [support::CopyCommit::Answer, support::CopyCommit::Fail] {
        let dynamic = support::wired_at_signed_time()
            .register::<dto::CopyObject, _>(Arc::new(CommittedCopy(outcome)))
            .build()
            .expect("a complete dynamic assembly");
        let static_backend = Arc::new(CommittedCopy(outcome));
        let monomorphic = support::wired_at_signed_time()
            .register::<dto::CopyObject, _>(Arc::clone(&static_backend))
            .build_monomorphic::<_, Operations>(static_backend)
            .expect("a complete static assembly");

        let dynamic_response = collect(dynamic.call_bytes(support::copy_commit_request()).await).await;
        let static_response = collect(monomorphic.call_bytes(support::copy_commit_request()).await).await;
        assert_wire_parity(&dynamic_response, &static_response);
    }
}

/// a-asm-0007. Event streams use the same static entry and never fall through the generated empty
/// output-document encoder.
#[tokio::test]
async fn static_and_dynamic_event_streams_are_identical() {
    let body = Bytes::from_static(
        b"<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression>\
          <ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization>\
          <OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>",
    );
    let dynamic_backend = Arc::new(support::select::SelectBackend);
    let dynamic = wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::SelectObjectContent, _>(dynamic_backend)
        .build()
        .expect("a complete dynamic assembly");
    let static_backend = Arc::new(support::select::SelectBackend);
    let monomorphic = wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::SelectObjectContent, _>(Arc::clone(&static_backend))
        .build_monomorphic::<_, SelectOperations>(static_backend)
        .expect("a complete static assembly");

    let dynamic_response = collect(dynamic.call_bytes(support::select::signed_select(body.clone())).await).await;
    let static_response = collect(monomorphic.call_bytes(support::select::signed_select(body)).await).await;
    assert_wire_parity(&dynamic_response, &static_response);
    assert!(!static_response.body().is_empty());
}

struct Panics;

impl Handler<Ping> for Panics {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        panic!("handler panic fixture");
    }

    async fn call_with_context(&self, _request: Req<Ping>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        panic!("handler panic fixture");
    }
}

/// a-asm-0007. A panic in the concrete handler is still contained by the common service boundary.
#[tokio::test]
async fn static_and_dynamic_handler_panics_are_identical() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let dynamic = wired()
        .register::<Ping, _>(Arc::new(Panics))
        .route(ping_route())
        .build()
        .expect("a complete dynamic assembly");
    let static_backend = Arc::new(Panics);
    let monomorphic = wired()
        .register::<Ping, _>(Arc::clone(&static_backend))
        .route(ping_route())
        .build_monomorphic::<_, Operations>(static_backend)
        .expect("a complete static assembly");

    let dynamic_response = collect(dynamic.call_bytes(plain(http::Method::POST, "/")).await).await;
    let static_response = collect(monomorphic.call_bytes(plain(http::Method::POST, "/")).await).await;
    assert_wire_parity(&dynamic_response, &static_response);
    assert_eq!(static_response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
}

struct CommitPanics;

impl Handler<dto::CopyObject> for CommitPanics {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        Ok(rustfs_gateway::Resp::commit_with_status(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(async { panic!("committed continuation panic fixture") }),
            http::StatusCode::ACCEPTED.as_u16(),
        ))
    }

    async fn call_with_context(
        &self,
        _request: Req<dto::CopyObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<dto::CopyObject> {
        Ok(rustfs_gateway::Resp::commit_with_status(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(async { panic!("committed continuation panic fixture") }),
            http::StatusCode::ACCEPTED.as_u16(),
        ))
    }
}

/// a-asm-0007. A panic after the response head is committed becomes an in-body refusal without
/// changing the status already sent, on both dispatch paths.
#[tokio::test]
async fn static_and_dynamic_committed_panics_keep_the_committed_status() {
    type Operations = OperationSetNode<dto::CopyObject, OperationSetEnd>;
    let dynamic = support::wired_at_signed_time()
        .register::<dto::CopyObject, _>(Arc::new(CommitPanics))
        .build()
        .expect("a complete dynamic assembly");
    let static_backend = Arc::new(CommitPanics);
    let monomorphic = support::wired_at_signed_time()
        .register::<dto::CopyObject, _>(Arc::clone(&static_backend))
        .build_monomorphic::<_, Operations>(static_backend)
        .expect("a complete static assembly");

    let dynamic_response = collect(dynamic.call_bytes(support::copy_commit_request()).await).await;
    let static_response = collect(monomorphic.call_bytes(support::copy_commit_request()).await).await;
    assert_wire_parity(&dynamic_response, &static_response);
    assert_eq!(dynamic_response.status(), http::StatusCode::ACCEPTED);
    let body = std::str::from_utf8(dynamic_response.body()).expect("a UTF-8 committed error document");
    assert!(body.starts_with(rustfs_gateway::commit::PROLOGUE), "{body}");
    assert_eq!(support::element_text(body, "Code"), Some("InternalError"));
}

struct ReadyThenDropPanics;

impl Future for ReadyThenDropPanics {
    type Output = Result<dto::CopyObjectOutput, rustfs_gateway::HandlerError>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(dto::CopyObjectOutput::default()))
    }
}

impl Drop for ReadyThenDropPanics {
    fn drop(&mut self) {
        panic!("committed continuation drop panic fixture");
    }
}

struct CommitDropPanics;

impl Handler<dto::CopyObject> for CommitDropPanics {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        Ok(rustfs_gateway::Resp::commit_with_status(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(ReadyThenDropPanics),
            http::StatusCode::ACCEPTED.as_u16(),
        ))
    }

    async fn call_with_context(
        &self,
        _request: Req<dto::CopyObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<dto::CopyObject> {
        Ok(rustfs_gateway::Resp::commit_with_status(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(ReadyThenDropPanics),
            http::StatusCode::ACCEPTED.as_u16(),
        ))
    }
}

/// a-asm-0007. Destroying a completed committed continuation is still inside the committed panic
/// boundary, so a destructor panic cannot replace the status already sent.
#[tokio::test]
async fn static_and_dynamic_committed_drop_panics_keep_the_committed_status() {
    type Operations = OperationSetNode<dto::CopyObject, OperationSetEnd>;
    let dynamic = support::wired_at_signed_time()
        .register::<dto::CopyObject, _>(Arc::new(CommitDropPanics))
        .build()
        .expect("a complete dynamic assembly");
    let static_backend = Arc::new(CommitDropPanics);
    let monomorphic = support::wired_at_signed_time()
        .register::<dto::CopyObject, _>(Arc::clone(&static_backend))
        .build_monomorphic::<_, Operations>(static_backend)
        .expect("a complete static assembly");

    let dynamic_response = collect(dynamic.call_bytes(support::copy_commit_request()).await).await;
    let static_response = collect(monomorphic.call_bytes(support::copy_commit_request()).await).await;
    assert_wire_parity(&dynamic_response, &static_response);
    assert_eq!(dynamic_response.status(), http::StatusCode::ACCEPTED);
    let body = std::str::from_utf8(dynamic_response.body()).expect("a UTF-8 committed error document");
    assert_eq!(support::element_text(body, "Code"), Some("InternalError"));
}

/// a-asm-0007. Registered and type-level operation identities must agree exactly.
#[test]
fn a_static_operation_set_mismatch_is_refused() {
    let backend = Arc::new(Backend);
    let error = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .build_monomorphic::<_, OperationSetEnd>(backend)
        .expect_err("an empty type-level set must not claim a registered operation");
    assert!(error.to_string().contains("differ from declared static operations"));
}

/// a-asm-0007. Operation layers carry a dynamic typed continuation, so static assembly rejects
/// one instead of silently dropping it or claiming that its handler path is monomorphic.
#[test]
fn a_static_service_rejects_operation_layers() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let backend = Arc::new(Backend);
    let error = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .op_layer::<Ping, _>(op_layer(|request: Req<Ping>, next: Next<'_, Ping>| next.run(request)))
        .build_monomorphic::<_, Operations>(backend)
        .expect_err("a static service must not erase an operation-layer continuation");
    assert!(matches!(error, AssemblyError::MonomorphicSet { .. }), "{error}");
    assert_eq!(error.rule(), RuleRef::MONOMORPHIC_SET);
}

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

//! How a response whose head was committed before its outcome is written.
//!
//! Responsible for: the wire shape of a committed response — the prologue that goes out with the
//! head, the keep-alive bytes that hold the connection while the outcome is unknown, and the
//! trailing document, which is the operation's result or the same `<Error>` document any other
//! refusal would have produced.
//! NOT responsible for: deciding *whether* a response commits. That is the backend's, through
//! [`rustfs_gateway_core::Resp::commit`], and it is a decision only a backend can make: everything
//! that can still be refused with a status must be refused before the head goes out.
//! Upstream: `crate::render`, `rustfs-gateway-xml`. Downstream: `crate::service`.
//!
//! # Why the keep-alive contract lives here and not in a backend
//!
//! A client that has been told `200` and then reads nothing for two minutes cannot tell a slow
//! completion from a dead one, so S3 writes whitespace while it works and SDKs time out against the
//! gap between bytes. That makes the byte and the interval an **observable contract**: two backends
//! choosing two cadences are two deployments that behave differently under the same client. They are
//! constants of this module for the same reason `rustfs_gateway_core::ErrorHeader` is a closed set —
//! a backend names the fact, the framework spells the wire.
//!
//! # Why the trailing document carries no declaration of its own
//!
//! The declaration goes out with the head, in [`PROLOGUE`], because it is the one part of the body
//! that is known before the outcome is. Whatever follows — a result or an `<Error>` — is therefore a
//! continuation of a document that has already started, and a second declaration in the middle of a
//! body is not XML any parser accepts. `crate::render::document_body` and
//! [`rustfs_gateway_xml::strip_declaration`] are the two halves of that: the renderer can build the
//! error document without one, and an encoder's result body has the one it wrote removed.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{HeaderMap, Response, StatusCode};
use rustfs_gateway_core::{
    BoxFuture, CodecError, EncodedResponse, HandlerError, MetaView, ResponseBody, ResponseKind, StaticCommittedError,
    StaticCommittedResponse, TargetKind,
};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_stream::{Body, CapsInconsistency, PayloadCaps, PayloadRead, PayloadStream, TrailingHeaders};
use rustfs_gateway_types::{BucketName, NamePolicy};
use rustfs_gateway_xml::{DECLARATION, strip_declaration};
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tokio::time::Sleep;

use crate::commit_task::{CommitTaskResult, PendingCommit};
use crate::render::{S3Error, document_body};
use crate::trace::RequestTrace;

/// What goes out with a committed head, before the outcome is known.
///
/// The XML declaration and its newline: 39 bytes, which is what `c-mpu-0001` and `c-copy-0038` pin
/// as the amount already committed when the failure was discovered.
pub const PROLOGUE: &str = DECLARATION;

/// The byte written to hold the connection while a committed response has no outcome yet.
///
/// Whitespace, because it is the only thing that is legal between the declaration and the document
/// element and carries no meaning to a parser. Not a newline: it is one byte on every wire encoding.
pub const KEEPALIVE_BYTE: u8 = b' ';

/// How often [`KEEPALIVE_BYTE`] is written while the outcome is pending.
///
/// Part of the observable contract, not a tuning knob: SDKs bound the gap between bytes, so a
/// deployment that changed this would change when its clients give up. Declared here so that the
/// number has one home.
///
/// It is also the quantum of [`crate::DEFAULT_COMMIT_PROGRESS_DEADLINE`], which is
/// [`crate::KEEPALIVE_INTERVALS_WITHOUT_PROGRESS`] of these. Writing the byte and giving up on the
/// outcome are the two ends of one question — *how long may a client be told "still working"* —
/// and two independent numbers could answer it inconsistently. The body schedules its first timer
/// only after the prologue leaves, so this interval is also the earliest possible keep-alive byte.
pub const KEEPALIVE_INTERVAL_SECONDS: u64 = 5;

/// What a committed continuation reports when it stopped making progress.
///
/// A message rather than a distinct code, because the wire vocabulary is closed and no S3 code
/// means this. `InternalError` is the honest one — the operation did not report, and the gateway
/// does not know whether it happened — and the message is what tells the two `InternalError`s a
/// committed response can carry apart: a backend that reported an internal failure, and a backend
/// that reported nothing at all. Pinned by `c-mpu-0040`, which would otherwise be satisfied by the
/// first when it is written about the second.
pub const COMMIT_PROGRESS_EXPIRED: &str = "the committed continuation reported no outcome inside the progress deadline";

#[derive(Clone)]
struct PendingCommitSlot(Arc<Mutex<Option<PendingCommit>>>);

impl PendingCommitSlot {
    fn take(&self) -> Option<PendingCommit> {
        self.0.lock().ok()?.take()
    }
}

struct CommitStream {
    receiver: oneshot::Receiver<Bytes>,
    canceled: Bytes,
    timer: Option<Pin<Box<Sleep>>>,
    prologue_sent: bool,
    terminal_sent: bool,
    ended: bool,
}

impl CommitStream {
    fn new(receiver: oneshot::Receiver<Bytes>, canceled: Bytes) -> Self {
        Self {
            receiver,
            canceled,
            timer: None,
            prologue_sent: false,
            terminal_sent: false,
            ended: false,
        }
    }
}

impl PayloadStream for CommitStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<PayloadRead, rustfs_gateway_stream::StreamError>> {
        if self.ended {
            return Poll::Ready(Err(rustfs_gateway_stream::StreamError::polled_after_eof()));
        }
        if !self.prologue_sent {
            self.prologue_sent = true;
            self.timer = Some(Box::pin(tokio::time::sleep(Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS))));
            return Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from_static(PROLOGUE.as_bytes()))));
        }
        if self.terminal_sent {
            self.ended = true;
            return Poll::Ready(Ok(PayloadRead::Eof {
                trailers: TrailingHeaders::empty(),
            }));
        }

        match Pin::new(&mut self.receiver).poll(context) {
            Poll::Ready(Ok(terminal)) => {
                self.terminal_sent = true;
                if terminal.is_empty() {
                    self.ended = true;
                    Poll::Ready(Ok(PayloadRead::Eof {
                        trailers: TrailingHeaders::empty(),
                    }))
                } else {
                    Poll::Ready(Ok(PayloadRead::Chunk(terminal)))
                }
            }
            Poll::Ready(Err(_)) => {
                self.terminal_sent = true;
                Poll::Ready(Ok(PayloadRead::Chunk(self.canceled.clone())))
            }
            Poll::Pending => {
                let Some(timer) = self.timer.as_mut() else {
                    return Poll::Pending;
                };
                if timer.as_mut().poll(context).is_pending() {
                    return Poll::Pending;
                }
                self.timer = Some(Box::pin(tokio::time::sleep(Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS))));
                Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from_static(&[KEEPALIVE_BYTE]))))
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// Builds the response shell without starting its deferred work.
pub(crate) fn pending_response(
    head: HeaderMap,
    status: StatusCode,
    runtime: Handle,
    task: BoxFuture<'static, CommitTaskResult>,
    canceled: Bytes,
) -> Result<Response<Body>, CapsInconsistency> {
    let (sender, receiver) = oneshot::channel();
    let body = Body::from_stream(CommitStream::new(receiver, canceled))?;
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = head;
    let headers = response.headers_mut();
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(http::header::TRAILER);
    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    response
        .extensions_mut()
        .insert(PendingCommitSlot(Arc::new(Mutex::new(Some(PendingCommit::new(runtime, sender, task))))));
    Ok(response)
}

/// Starts deferred work after the caller has finalized every response-head mutation, counted in
/// the service's [`crate::DetachedWork`].
#[must_use]
pub(crate) fn start_counted(
    response: &mut Response<Body>,
    work: &crate::DetachedWork,
    complete: Box<dyn FnOnce(Option<rustfs_gateway_types::ErrorCode>) + Send>,
) -> bool {
    let Some(slot) = response.extensions_mut().remove::<PendingCommitSlot>() else {
        return false;
    };
    let Some(pending) = slot.take() else {
        return false;
    };
    pending.start(work, complete);
    true
}

/// [`start_counted`] with a count nobody reads, for the unit tests that predate the count.
#[cfg(test)]
#[must_use]
pub(crate) fn start_pending(
    response: &mut Response<Body>,
    complete: Box<dyn FnOnce(Option<rustfs_gateway_types::ErrorCode>) + Send>,
) -> bool {
    start_counted(response, &crate::DetachedWork::default(), complete)
}

/// The terminal bytes of a successful committed response, without a second XML declaration.
pub(crate) fn answer_document(encoded: EncodedResponse) -> Result<Bytes, CodecError> {
    match encoded.body {
        ResponseBody::Empty => Err(CodecError::internal("a committed operation produced no terminal document")),
        ResponseBody::Complete(bytes) => Ok(Bytes::copy_from_slice(strip_declaration(&bytes))),
        ResponseBody::Stream(_) => Err(CodecError::internal("a committed operation produced a streaming terminal document")),
    }
}

/// The terminal bytes of a refused committed response, after the prologue already went out.
pub(crate) fn refusal_document(error: &S3Error, trace: &RequestTrace) -> Bytes {
    Bytes::from(document_body(error, trace))
}

/// Owned request state the detached encoder needs after the service call returns.
pub(crate) struct CommitContext {
    wire: WireRequest<()>,
    target: TargetKind,
    host_bucket: Option<BucketName>,
    names: NamePolicy,
    response_kind: ResponseKind,
    trace: RequestTrace,
}

impl CommitContext {
    /// Captures the accepted request and its resolved addressing context.
    pub(crate) fn new(
        wire: WireRequest<()>,
        target: TargetKind,
        host_bucket: Option<BucketName>,
        names: NamePolicy,
        response_kind: ResponseKind,
        trace: RequestTrace,
    ) -> Self {
        Self {
            wire,
            target,
            host_bucket,
            names,
            response_kind,
            trace,
        }
    }
}

/// Rebuilds request metadata inside detached work and prepares the committed response shell.
pub(crate) fn prepare_response(
    response: StaticCommittedResponse,
    status: u16,
    context: CommitContext,
) -> Result<Response<Body>, HandlerError> {
    let CommitContext {
        wire,
        target,
        host_bucket,
        names,
        response_kind,
        trace,
    } = context;
    let runtime =
        Handle::try_current().map_err(|_| HandlerError::internal_error("a committed response requires a Tokio runtime"))?;
    let response_status = StatusCode::from_u16(status)
        .map_err(|_| HandlerError::internal_error("a committed response carries an invalid status"))?;
    let head = response.head().clone();
    let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async move {
        let meta = match MetaView::addressed_with(&wire, target, host_bucket, &names) {
            Ok(meta) => meta,
            Err(error) => {
                let error = crate::render::from_codec(error, response_kind);
                return CommitTaskResult::refusal(refusal_document(&error, &trace), error.code().cloned());
            }
        };
        match response.resolve(&meta, status).await {
            Ok(encoded) => match answer_document(encoded) {
                Ok(document) => CommitTaskResult::answer(document),
                Err(error) => {
                    let error = crate::render::from_codec(error, response_kind);
                    CommitTaskResult::refusal(refusal_document(&error, &trace), error.code().cloned())
                }
            },
            Err(StaticCommittedError::Handler(error)) => {
                let error = crate::render::from_handler(error, response_kind, crate::close::ConnectionIntent::MayKeepAlive);
                CommitTaskResult::refusal(refusal_document(&error, &trace), error.code().cloned())
            }
            Err(StaticCommittedError::Codec(error)) => {
                let error = crate::render::from_codec(error, response_kind);
                CommitTaskResult::refusal(refusal_document(&error, &trace), error.code().cloned())
            }
        }
    });
    let canceled = crate::render::from_handler(
        HandlerError::internal_error("the detached committed response task stopped"),
        response_kind,
        crate::close::ConnectionIntent::MayKeepAlive,
    );
    pending_response(head, response_status, runtime, task, refusal_document(&canceled, &trace))
        .map_err(|_| HandlerError::internal_error("the committed response body could not be constructed"))
}

/// Writes a committed response whose outcome turned out to be a refusal.
///
/// The status is the one the head went out with — *not* the refusal's own, which is the whole point:
/// by the time this refusal exists, the status line has been sent. The document is byte-for-byte the
/// one [`crate::render::render`] would have produced, minus the declaration the prologue already
/// carried and minus the head, which a refusal at this point has no way to add to.
#[cfg(test)]
fn refused(error: &S3Error, trace: &RequestTrace, status: StatusCode) -> Response<Body> {
    let mut body = String::from(PROLOGUE);
    body.push_str(&document_body(error, trace));
    let mut response = Response::new(Body::from(body.into_bytes()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    trace.apply(headers);
    response
}

/// Writes a committed response whose outcome turned out to be the answer.
///
/// The encoder's own headers survive; its framing headers do not. A length computed after the fact
/// would describe a body whose head went out before the length was knowable, and a `Trailer`
/// announcement would promise a section this response never sends — the half of `c-copy-0038` that
/// turns a reported failure into a client that waits for ever.
#[cfg(test)]
fn answered(encoded: EncodedResponse, status: StatusCode) -> Response<Body> {
    let body = match encoded.body {
        ResponseBody::Empty => Body::from(PROLOGUE.as_bytes().to_vec()),
        ResponseBody::Complete(bytes) => {
            let mut out = Vec::with_capacity(PROLOGUE.len().saturating_add(bytes.len()));
            out.extend_from_slice(PROLOGUE.as_bytes());
            out.extend_from_slice(strip_declaration(&bytes));
            Body::from(out)
        }
        // A streaming payload is handed on untouched: this function cannot read the first bytes of
        // one without buffering it, and buffering a streamed answer to remove 39 bytes would undo
        // the reason it is streamed. No operation that commits its head streams its result today.
        ResponseBody::Stream(stream) => stream.into_body(),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = encoded.headers;
    let headers = response.headers_mut();
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(http::header::TRAILER);
    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    response
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use futures_util::FutureExt as _;
    use futures_util::task::{ArcWake, waker_ref};
    use http_body_util::BodyExt as _;
    use rustfs_gateway_core::{ErrorContext, HandlerError, MissingObject, ResourceVisibility, ResponseKind, resolve};
    use rustfs_gateway_types::ErrorCode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct WakeCounter(Mutex<usize>);

    impl WakeCounter {
        fn count(&self) -> usize {
            self.0.lock().map_or(0, |count| *count)
        }
    }

    impl ArcWake for WakeCounter {
        fn wake_by_ref(counter: &Arc<Self>) {
            if let Ok(mut count) = counter.0.lock() {
                *count += 1;
            }
        }
    }

    fn trace() -> RequestTrace {
        RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0)
    }

    async fn body_of(response: Response<Body>) -> String {
        let collected = crate::wire::collect(response).await.expect("an in-memory body");
        String::from_utf8(collected.body().to_vec()).expect("utf-8")
    }

    async fn next_data(body: &mut Body) -> Option<Bytes> {
        body.frame()
            .await
            .transpose()
            .expect("the committed body reads")
            .and_then(|frame| frame.into_data().ok())
    }

    fn missing_key() -> S3Error {
        S3Error::from(resolve(
            ErrorContext::missing_object(MissingObject::Key, ResourceVisibility::Visible),
            ResponseKind::Other,
        ))
    }

    /// Negative — the status is the committed one, not the refusal's. A refusal that could still
    /// change the status line is the defect this whole seam exists to make unwritable.
    #[tokio::test]
    async fn a_committed_refusal_keeps_the_status_the_head_went_out_with() {
        let error = missing_key();
        assert_eq!(error.status(), StatusCode::NOT_FOUND);
        let response = refused(&error, &trace(), StatusCode::OK);
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Negative — the document is in the body and the prologue is in front of it, exactly once.
    /// Two declarations in one body is the failure a parser reports as a syntax error rather than as
    /// the refusal that actually happened.
    #[tokio::test]
    async fn a_committed_refusal_carries_one_declaration_and_then_the_document() {
        let error = crate::render::from_handler(
            HandlerError::new(ErrorCode::INVALID_PART, "no such part"),
            ResponseKind::Other,
            crate::ConnectionIntent::MayKeepAlive,
        );
        let body = body_of(refused(&error, &trace(), StatusCode::OK)).await;
        assert!(body.starts_with(PROLOGUE), "{body}");
        assert_eq!(body.matches("<?xml").count(), 1, "{body}");
        assert!(body.contains("<Code>InvalidPart</Code>"), "{body}");
        assert!(body.contains("<RequestId>0123456789ABCDEF</RequestId>"), "{body}");
    }

    /// Negative — a committed refusal announces no length and no trailer section. Both would be
    /// promises made after the head that carries them had already gone out.
    #[tokio::test]
    async fn a_committed_refusal_announces_neither_a_length_nor_a_trailer_section() {
        let error = missing_key();
        let response = refused(&error, &trace(), StatusCode::OK);
        assert_eq!(response.headers().get(CONTENT_LENGTH), None);
        assert_eq!(response.headers().get(http::header::TRAILER), None);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).map(http::HeaderValue::as_bytes),
            Some(&b"application/xml"[..])
        );
    }

    /// Negative — the refusal carries none of the headers a successful answer would have. An `ETag`
    /// on a response that failed is the byte a client stores and then cannot read back.
    #[tokio::test]
    async fn a_committed_refusal_carries_no_answer_headers() {
        let error = missing_key();
        let response = refused(&error, &trace(), StatusCode::OK);
        for name in ["etag", "x-amz-version-id", "x-amz-copy-source-version-id"] {
            assert!(response.headers().get(name).is_none(), "{name}");
        }
    }

    /// Negative — a success without a terminal document cannot leave only an XML declaration.
    #[test]
    fn a_committed_success_without_a_document_is_rejected() {
        assert!(answer_document(EncodedResponse::of(200)).is_err());
    }

    /// Negative — an answer's own declaration is removed rather than repeated. The encoder writes
    /// one because every other response needs it; here the prologue already sent it.
    #[tokio::test]
    async fn an_answered_commit_does_not_repeat_the_declaration() {
        let mut encoded = EncodedResponse::of(200);
        encoded.body = ResponseBody::Complete(
            format!("{DECLARATION}<CompleteMultipartUploadResult></CompleteMultipartUploadResult>").into_bytes(),
        );
        encoded.set_header("content-length", "999");
        let response = answered(encoded, StatusCode::OK);
        assert_eq!(response.headers().get(CONTENT_LENGTH), None);
        let body = body_of(response).await;
        assert_eq!(body.matches("<?xml").count(), 1, "{body}");
        assert!(body.starts_with(PROLOGUE), "{body}");
        assert!(body.contains("<CompleteMultipartUploadResult>"), "{body}");
    }

    /// Negative — no keep-alive is emitted before the complete first five-second interval.
    #[tokio::test(start_paused = true)]
    async fn the_first_keepalive_waits_a_full_interval_and_ticks_once_per_interval() {
        let (sender, receiver) = oneshot::channel();
        let mut body = Body::from_stream(CommitStream::new(receiver, Bytes::from_static(b"<Error/>")))
            .expect("the unknown-length stream has consistent capabilities");
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(PROLOGUE.as_bytes())));

        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(body.frame().now_or_never().is_none(), "a keep-alive arrived before five seconds");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(b" ")));
        assert!(body.frame().now_or_never().is_none(), "one timer tick emitted more than one byte");

        sender.send(Bytes::from_static(b"<Done/>")).expect("the body still receives");
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(b"<Done/>")));
        assert!(next_data(&mut body).await.is_none());
    }

    /// Negative — a ready result wins over a simultaneous keep-alive tick.
    #[tokio::test(start_paused = true)]
    async fn a_terminal_document_does_not_gain_a_keepalive_when_it_is_already_ready() {
        let (sender, receiver) = oneshot::channel();
        let mut body = Body::from_stream(CommitStream::new(receiver, Bytes::from_static(b"<Error/>")))
            .expect("the unknown-length stream has consistent capabilities");
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(PROLOGUE.as_bytes())));
        tokio::time::advance(Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS)).await;
        sender.send(Bytes::from_static(b"<Done/>")).expect("the body still receives");
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(b"<Done/>")));
        assert!(next_data(&mut body).await.is_none());
    }

    /// Negative — 512 pending committed responses schedule no early wake and exactly one wake per
    /// response when the first five-second interval expires. The deterministic wake count is the
    /// CPU scaling gate: doubling concurrency can at most double timer work, never square it.
    #[tokio::test(start_paused = true)]
    async fn c_enc_0065_five_hundred_twelve_commits_have_linear_timer_wakes() {
        const COMMITS: usize = 512;
        let counter = Arc::new(WakeCounter(Mutex::new(0)));
        let waker = waker_ref(&counter);
        let mut context = Context::from_waker(&waker);
        let mut senders = Vec::with_capacity(COMMITS);
        let mut streams = Vec::with_capacity(COMMITS);
        for _ in 0..COMMITS {
            let (sender, receiver) = oneshot::channel();
            senders.push(sender);
            streams.push(CommitStream::new(receiver, Bytes::from_static(b"<Error/>")));
        }

        for stream in &mut streams {
            let Poll::Ready(Ok(PayloadRead::Chunk(bytes))) = Pin::new(&mut *stream).poll_read(&mut context) else {
                panic!("a committed stream did not emit its prologue");
            };
            assert_eq!(bytes, Bytes::from_static(PROLOGUE.as_bytes()));
            assert!(Pin::new(&mut *stream).poll_read(&mut context).is_pending());
            assert!(stream.timer.is_some(), "a live stream must own exactly its one timer slot");
        }

        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert_eq!(counter.count(), 0, "a timer woke before the five-second interval");
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        let first_wakes = counter.count();
        assert_eq!(first_wakes, COMMITS, "one interval caused {first_wakes} wakes for {COMMITS} streams");
        drop(senders);
    }

    /// Negative — losing the detached sender finishes with a document rather than silent EOF.
    #[tokio::test]
    async fn a_lost_task_sender_uses_the_prebuilt_failure_document() {
        let (sender, receiver) = oneshot::channel();
        let mut body = Body::from_stream(CommitStream::new(receiver, Bytes::from_static(b"<Canceled/>")))
            .expect("the unknown-length stream has consistent capabilities");
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(PROLOGUE.as_bytes())));
        drop(sender);
        assert_eq!(next_data(&mut body).await, Some(Bytes::from_static(b"<Canceled/>")));
        assert!(next_data(&mut body).await.is_none());
    }

    /// Negative — filtering can still replace the response before the backend work is spawned.
    #[tokio::test]
    async fn pending_work_starts_only_after_the_head_is_finalized() {
        let started = Arc::new(AtomicUsize::new(0));
        let task_started = Arc::clone(&started);
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async move {
            task_started.fetch_add(1, Ordering::SeqCst);
            CommitTaskResult::answer(Bytes::from_static(b"<Done/>"))
        });
        let mut response = pending_response(
            HeaderMap::new(),
            StatusCode::OK,
            Handle::current(),
            task,
            Bytes::from_static(b"<Canceled/>"),
        )
        .expect("the pending response has consistent capabilities");
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), 0, "the work started before finalization");
        assert!(start_pending(&mut response, Box::new(|_| {})));
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    /// Negative — dropping the client-facing body does not cancel detached backend work.
    #[tokio::test]
    async fn dropping_the_response_body_does_not_cancel_started_work() {
        let (release, wait) = oneshot::channel::<()>();
        let completed = Arc::new(AtomicUsize::new(0));
        let task_completed = Arc::clone(&completed);
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async move {
            let _ = wait.await;
            task_completed.fetch_add(1, Ordering::SeqCst);
            CommitTaskResult::answer(Bytes::from_static(b"<Done/>"))
        });
        let mut response = pending_response(
            HeaderMap::new(),
            StatusCode::OK,
            Handle::current(),
            task,
            Bytes::from_static(b"<Canceled/>"),
        )
        .expect("the pending response has consistent capabilities");
        assert!(start_pending(&mut response, Box::new(|_| {})));
        drop(response);
        release.send(()).expect("the detached task still owns its receiver");
        for _ in 0..10 {
            if completed.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(completed.load(Ordering::SeqCst), 1, "body drop canceled the backend work");
    }

    /// Positive — the keep-alive contract is one byte of whitespace, which is what makes it legal
    /// between the declaration and the document element.
    #[test]
    fn the_keepalive_byte_is_whitespace_the_prologue_may_be_followed_by() {
        assert!(KEEPALIVE_BYTE.is_ascii_whitespace());
        assert_ne!(KEEPALIVE_BYTE, b'\n');
        assert_eq!(PROLOGUE, DECLARATION);
        assert_eq!(PROLOGUE.len(), 39);
    }
}

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

//! Tests external admission, byte accounting, cancellation, and publication guards.
//!
//! Responsible for: independent negative and positive boundary evidence.
//! NOT responsible for: device execution or protocol authentication.
//! Upstream: external-payload core interfaces. Downstream: the test harness.

use super::*;
use bytes::Bytes;
use rustfs_gateway_stream::{ByteStream, PayloadRead, PayloadStream};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Control {
    accepts: AtomicUsize,
    cancels: AtomicUsize,
    fail: bool,
}
impl ExternalPayloadControl for Control {
    fn accept(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        self.accepts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async move {
            if self.fail {
                Err(ExternalPayloadError::Transport)
            } else {
                Ok(())
            }
        })
    }
    fn cancel(&self) {
        self.cancels.fetch_add(1, Ordering::SeqCst);
    }
    fn protection(&self) -> PayloadProtection {
        PayloadProtection::Authenticated
    }
}
struct Logical(bool);
impl LogicalPayloadCompletion for Logical {
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async move {
            if self.0 {
                Ok(())
            } else {
                Err(ExternalPayloadError::Integrity)
            }
        })
    }
}
fn setup(length: u64, logical: bool) -> (ExternalPayloadContext, Arc<Control>) {
    let control = Arc::new(Control::default());
    let context = external_payload_context(length, control.clone(), Arc::new(Logical(logical)));
    (context, control)
}
async fn read(body: &mut ByteStream) -> Result<PayloadRead, rustfs_gateway_stream::StreamError> {
    std::future::poll_fn(|cx| Pin::new(&mut *body).poll_read(cx)).await
}

#[tokio::test]
async fn verification_before_accept_is_rejected() {
    let (context, _) = setup(0, true);
    assert!(context.verify_before_publish().await.is_err());
}
#[tokio::test]
async fn a_source_cannot_be_bound_twice() {
    let (context, _) = setup(1, true);
    assert!(context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).is_ok());
    assert!(context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).is_err());
}
#[tokio::test]
async fn a_mismatched_source_length_is_rejected() {
    let (context, _) = setup(2, true);
    assert!(context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).is_err());
}
#[tokio::test]
async fn unread_input_cannot_be_verified() {
    let (context, _) = setup(2, true);
    let _body = context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"ab"))).unwrap();
    context.accept_after_admission().await.unwrap();
    assert!(context.verify_before_publish().await.is_err());
}
#[tokio::test]
async fn a_logical_failure_prevents_publication() {
    let (context, control) = setup(1, false);
    let mut body = context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).unwrap();
    context.accept_after_admission().await.unwrap();
    assert!(matches!(read(&mut body).await.unwrap(), PayloadRead::Chunk(_)));
    let error = context.verify_before_publish().await.unwrap_err();
    assert_eq!(error.message(), ExternalPayloadError::Integrity.to_string());
    assert!(!context.is_verified());
    assert_eq!(control.cancels.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn a_transport_failure_prevents_publication() {
    let control = Arc::new(Control {
        fail: true,
        ..Control::default()
    });
    let context = external_payload_context(0, control, Arc::new(Logical(true)));
    let _body = context.bind_input(ByteStream::from_bytes(Bytes::new())).unwrap();
    context.accept_after_admission().await.unwrap();
    let error = context.verify_before_publish().await.unwrap_err();
    assert_eq!(error.message(), ExternalPayloadError::Transport.to_string());
    assert!(!context.is_verified());
}
#[tokio::test]
async fn cancellation_before_accept_never_starts_transport() {
    let (context, control) = setup(0, true);
    context.cancel();
    assert!(context.accept_after_admission().await.is_err());
    assert_eq!(control.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(control.cancels.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn cancelled_input_returns_an_error() {
    let (context, _) = setup(1, true);
    let mut body = context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).unwrap();
    context.cancel();
    assert!(read(&mut body).await.is_err());
}
#[tokio::test]
async fn clones_share_one_accept_and_one_verification() {
    let (context, control) = setup(1, true);
    let mut body = context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).unwrap();
    let other = context.clone();
    let (a, b) = futures_util::future::join(context.accept_after_admission(), other.accept_after_admission()).await;
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(control.accepts.load(Ordering::SeqCst), 1);
    assert!(matches!(read(&mut body).await.unwrap(), PayloadRead::Chunk(bytes) if bytes == b"a"[..]));
    context.verify_before_publish().await.unwrap();
    other.verify_before_publish().await.unwrap();
    assert!(context.is_verified());
}
#[tokio::test]
async fn empty_input_still_requires_admission_and_verification() {
    let (context, control) = setup(0, true);
    let _body = context.bind_input(ByteStream::from_bytes(Bytes::new())).unwrap();
    context.accept_after_admission().await.unwrap();
    context.verify_before_publish().await.unwrap();
    assert!(context.is_verified());
    assert_eq!(control.accepts.load(Ordering::SeqCst), 1);
}

#[test]
fn dormant_input_never_polls_its_source() {
    let (context, control) = setup(1, true);
    let mut body = context.bind_input(ByteStream::from_bytes(Bytes::from_static(b"a"))).unwrap();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(Pin::new(&mut body).poll_read(&mut cx).is_pending());
    assert_eq!(body.observed_length(), 0);
    assert_eq!(control.accepts.load(Ordering::SeqCst), 0);
    context.cancel();
    assert!(matches!(Pin::new(&mut body).poll_read(&mut cx), Poll::Ready(Err(_))));
}

struct PendingControl;
impl ExternalPayloadControl for PendingControl {
    fn accept(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async { Ok(()) })
    }
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(std::future::pending())
    }
    fn cancel(&self) {}
    fn protection(&self) -> PayloadProtection {
        PayloadProtection::Unknown
    }
}
#[tokio::test]
async fn logical_failure_does_not_wait_for_a_stalled_transport_observer() {
    use std::future::Future;
    let context = external_payload_context(0, Arc::new(PendingControl), Arc::new(Logical(false)));
    let _body = context.bind_input(ByteStream::from_bytes(Bytes::new())).unwrap();
    context.accept_after_admission().await.unwrap();
    let mut verify = Box::pin(context.verify_before_publish());
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let first = verify.as_mut().poll(&mut cx);
    let ready = match first {
        Poll::Ready(result) => Some(result),
        Poll::Pending => match verify.as_mut().poll(&mut cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        },
    };
    assert!(matches!(ready, Some(Err(_))));
}

use rustfs_gateway_core::{Handler, Resp, SseConfig, TargetKind, TransportSecurity};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

struct EarlySuccess(Arc<AtomicUsize>);
impl Handler<dto::PutObject> for EarlySuccess {
    async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}
impl ExternalPayloadHandler<dto::PutObject> for EarlySuccess {
    fn call_with_external_payload<'a>(
        &'a self,
        _request: Req<dto::PutObject>,
        _context: HandlerContext,
        _payload: ExternalPayloadContext,
    ) -> BoxFuture<'a, HandlerResult<dto::PutObject>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Resp::new(dto::PutObjectOutput::default())) })
    }
}
fn handler_request() -> Req<dto::PutObject> {
    let wire = WireRequest::accept(
        http::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(Bytes::new())
            .unwrap(),
        &Limits::default(),
    )
    .unwrap();
    let meta = rustfs_gateway_core::MetaView::of(&wire, TargetKind::Service).unwrap();
    let sse = rustfs_gateway_core::sse::enforce(&meta, TransportSecurity::Encrypted, &SseConfig::strict()).unwrap();
    Req::new(dto::PutObjectInput::default(), sse)
}
#[tokio::test]
async fn a_handler_cannot_return_success_without_publication_verification() {
    let (context, control) = setup(0, true);
    let (_, handler_context) = HandlerCancellationSource::pair();
    let backend = EarlySuccess(Arc::new(AtomicUsize::new(0)));
    let result = dispatch_external_payload(&backend, handler_request(), handler_context, context).await;
    assert!(result.is_err());
    assert_eq!(control.cancels.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn a_pre_cancelled_framework_request_never_invokes_the_handler() {
    let (context, control) = setup(0, true);
    let (source, handler_context) = HandlerCancellationSource::pair();
    source.cancel(HandlerCancellation::RequestAborted);
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = EarlySuccess(calls.clone());
    let result = dispatch_external_payload(&backend, handler_request(), handler_context, context).await;
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(control.cancels.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_admission_failure_keeps_its_reason_for_later_observers() {
    let (context, _) = setup(0, true);
    let first = context.verify_before_publish().await.unwrap_err();
    let second = context.verify_before_publish().await.unwrap_err();
    assert_eq!(first.message(), second.message());
}

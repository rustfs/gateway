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

//! Facade-owned admission, dormant input and publication verification for external object data.
//!
//! Responsible for: execution state, real byte accounting, shared results and explicit dispatch.
//! NOT responsible for: authenticating requests, selecting objects, native access or S3 checksum algorithms.
//! Upstream: the existing authenticated facade and integrity monitor. Downstream: explicit handlers.

use futures_util::future::{Either, FutureExt, Shared, join, select};
use futures_util::task::AtomicWaker;
use rustfs_gateway_core::external_payload::{
    ExternalPayloadContext, ExternalPayloadControl, ExternalPayloadError, ExternalPayloadExecution, ExternalPayloadHandler,
    LogicalPayloadCompletion, PayloadProtection,
};
use rustfs_gateway_core::{
    BoxFuture, HandlerCancellation, HandlerCancellationSource, HandlerContext, HandlerError, HandlerResult, Operation, Req,
};
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::{Context, Poll};

type SharedResult = Shared<BoxFuture<'static, Result<(), ExternalPayloadError>>>;

struct State {
    length: u64,
    accepted: AtomicBool,
    bound: AtomicBool,
    verified: AtomicBool,
    cancelled: AtomicBool,
    terminal_error: Mutex<Option<ExternalPayloadError>>,
    consumed: AtomicU64,
    input_waker: AtomicWaker,
    cancellation: HandlerCancellationSource,
    cancellation_context: HandlerContext,
}
impl State {
    fn cancel(&self, control: &dyn ExternalPayloadControl) {
        self.stop(ExternalPayloadError::Cancelled, control);
    }
    fn stop(&self, error: ExternalPayloadError, control: &dyn ExternalPayloadControl) {
        let first = {
            let mut reason = self.terminal_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if reason.is_some() {
                false
            } else {
                *reason = Some(error);
                true
            }
        };
        if first {
            self.cancelled.store(true, Ordering::Release);
            self.cancellation.cancel(HandlerCancellation::RequestAborted);
            control.cancel();
            self.input_waker.wake();
        }
    }
    fn terminal_error(&self) -> ExternalPayloadError {
        self.terminal_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or(ExternalPayloadError::Cancelled)
    }
    fn check_cancelled(&self) -> Result<(), ExternalPayloadError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(self.terminal_error())
        } else {
            Ok(())
        }
    }
}
struct ExecutionContext {
    state: Arc<State>,
    control: Arc<dyn ExternalPayloadControl>,
    accept: SharedResult,
    verify: SharedResult,
}
impl Drop for ExecutionContext {
    fn drop(&mut self) {
        if !self.state.verified.load(Ordering::Acquire) {
            self.state.cancel(self.control.as_ref());
        }
    }
}

impl ExecutionContext {
    /// Connects one authenticated logical length to trusted transport and S3 integrity observers.
    #[must_use]
    fn new(length: u64, control: Arc<dyn ExternalPayloadControl>, logical: Arc<dyn LogicalPayloadCompletion>) -> Arc<Self> {
        let (cancellation, cancellation_context) = HandlerCancellationSource::pair();
        let state = Arc::new(State {
            length,
            accepted: AtomicBool::new(false),
            bound: AtomicBool::new(false),
            verified: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            terminal_error: Mutex::new(None),
            consumed: AtomicU64::new(0),
            input_waker: AtomicWaker::new(),
            cancellation,
            cancellation_context,
        });
        let accept_state = Arc::clone(&state);
        let accept_control = Arc::clone(&control);
        let accept: SharedResult = (Box::pin(async move {
            accept_state.check_cancelled()?;
            let result = until_cancelled(accept_control.accept(), &accept_state).await;
            if result.is_ok() {
                accept_state.accepted.store(true, Ordering::Release);
                accept_state.input_waker.wake();
            } else if let Err(error) = result {
                accept_state.stop(error, accept_control.as_ref());
            }
            result
        }) as BoxFuture<'static, _>)
            .shared();
        let verify_state = Arc::clone(&state);
        let verify_control = Arc::clone(&control);
        let verify: SharedResult = (Box::pin(async move {
            let both = async {
                // Both observers run together. The transport owner retains reconciliation and
                // remote-access cleanup even if the request stops observing this result.
                let transport = async {
                    let result = verify_control.wait_verified().await;
                    if let Err(error) = result {
                        verify_state.stop(error, verify_control.as_ref());
                    }
                    result
                };
                let logical = async {
                    let result = logical.wait_verified().await;
                    if let Err(error) = result {
                        verify_state.stop(error, verify_control.as_ref());
                    }
                    result
                };
                let (transport, logical) = join(transport, logical).await;
                transport.and(logical)
            };
            let result = until_cancelled(Box::pin(both), &verify_state).await;
            if result.is_ok() {
                verify_state.verified.store(true, Ordering::Release);
            } else {
                verify_state.cancel(verify_control.as_ref());
            }
            result
        }) as BoxFuture<'static, _>)
            .shared();
        Arc::new(Self {
            state,
            control,
            accept,
            verify,
        })
    }

    /// The authenticated upload or part size used for admission and actual byte accounting.
    #[must_use]
    fn logical_length(&self) -> u64 {
        self.state.length
    }
    /// Protection established by the transport for this binding.
    #[must_use]
    fn protection(&self) -> PayloadProtection {
        self.control.protection()
    }
    /// Whether both logical and transport verification completed successfully.
    #[must_use]
    fn is_verified(&self) -> bool {
        self.state.verified.load(Ordering::Acquire)
    }

    /// Binds exactly one input and prevents any upstream poll before successful admission.
    ///
    /// Length is checked before ownership is consumed. This wrapper counts actual bytes delivered
    /// to the handler; successful publication cannot be inferred from a producer's claimed count.
    fn bind_input(self: &Arc<Self>, body: ByteStream) -> Result<ByteStream, ExternalPayloadError> {
        if body.remaining_length().get() != Some(self.logical_length()) || body.is_file_region() {
            return Err(ExternalPayloadError::LengthMismatch);
        }
        if self.state.bound.swap(true, Ordering::AcqRel) {
            return Err(ExternalPayloadError::AlreadyBound);
        }
        ByteStream::new(Box::pin(DormantInput {
            body,
            context: self.clone(),
            ended: false,
        }))
        .map_err(|_| ExternalPayloadError::LengthMismatch)
    }
    /// Starts the same acceptance once, after the handler's business admission checks succeed.
    async fn accept_after_admission(&self) -> Result<(), HandlerError> {
        self.state.check_cancelled().map_err(handler_error)?;
        self.accept.clone().await.map_err(handler_error)
    }
    /// Requires all actual input bytes plus logical and transport verification before publication.
    ///
    /// An early call rejects without reading or discarding any unconsumed suffix. Zero-length
    /// uploads still require a bound body, successful admission, and both terminal observers.
    async fn verify_before_publish(&self) -> Result<(), HandlerError> {
        self.state.check_cancelled().map_err(handler_error)?;
        let error = if !self.state.accepted.load(Ordering::Acquire) {
            Some(ExternalPayloadError::NotAccepted)
        } else if !self.state.bound.load(Ordering::Acquire)
            || self.state.consumed.load(Ordering::Acquire) != self.logical_length()
        {
            Some(ExternalPayloadError::UnconsumedInput)
        } else {
            None
        };
        if let Some(error) = error {
            self.state.stop(error, self.control.as_ref());
            return Err(handler_error(error));
        }
        self.verify.clone().await.map_err(handler_error)
    }
    /// Records cancellation once, wakes dormant input, and leaves cleanup with its transport owner.
    fn cancel(&self) {
        self.state.cancel(self.control.as_ref());
    }
}

async fn until_cancelled(
    future: BoxFuture<'_, Result<(), ExternalPayloadError>>,
    state: &State,
) -> Result<(), ExternalPayloadError> {
    let cancelled = Box::pin(state.cancellation_context.cancelled());
    match select(cancelled, future).await {
        Either::Left(_) => Err(state.terminal_error()),
        Either::Right((result, _)) => {
            state.check_cancelled()?;
            result
        }
    }
}
fn handler_error(error: ExternalPayloadError) -> HandlerError {
    HandlerError::internal_error(error.to_string())
}

struct DormantInput {
    body: ByteStream,
    context: Arc<ExecutionContext>,
    ended: bool,
}
impl PayloadStream for DormantInput {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        let state = &this.context.state;
        state.input_waker.register(cx.waker());
        if let Err(error) = state.check_cancelled() {
            this.ended = true;
            return Poll::Ready(Err(StreamError::upstream(Box::new(error))));
        }
        if !state.accepted.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        match Pin::new(&mut this.body).poll_read(cx) {
            Poll::Ready(Ok(PayloadRead::Chunk(bytes))) => {
                state.consumed.fetch_add(bytes.len() as u64, Ordering::AcqRel);
                Poll::Ready(Ok(PayloadRead::Chunk(bytes)))
            }
            Poll::Ready(Ok(eof @ PayloadRead::Eof { .. })) => {
                this.ended = true;
                Poll::Ready(Ok(eof))
            }
            Poll::Ready(Err(error)) => {
                this.ended = true;
                this.context.cancel();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }
    fn len_hint(&self) -> Option<u64> {
        Some(
            self.context
                .logical_length()
                .saturating_sub(self.context.state.consumed.load(Ordering::Acquire)),
        )
    }
}
impl Drop for DormantInput {
    fn drop(&mut self) {
        if self.context.state.consumed.load(Ordering::Acquire) < self.context.logical_length() {
            self.context.cancel();
        }
    }
}

/// Creates the facade execution owner for one authenticated exact-length external upload.
///
/// Callers must connect the original logical S3 integrity monitor and the transport control for
/// the same authenticated binding. This factory does not authenticate or authorize a request.
#[must_use]
pub fn external_payload_context(
    length: u64,
    control: Arc<dyn ExternalPayloadControl>,
    logical: Arc<dyn LogicalPayloadCompletion>,
) -> ExternalPayloadContext {
    ExternalPayloadContext::from_execution(ExecutionContext::new(length, control, logical))
}

impl ExternalPayloadExecution for ExecutionContext {
    fn logical_length(&self) -> u64 {
        Self::logical_length(self)
    }
    fn protection(&self) -> PayloadProtection {
        Self::protection(self)
    }
    fn is_verified(&self) -> bool {
        Self::is_verified(self)
    }
    fn bind_input(self: Arc<Self>, body: ByteStream) -> Result<ByteStream, ExternalPayloadError> {
        Self::bind_input(&self, body)
    }
    fn accept_after_admission(&self) -> BoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(Self::accept_after_admission(self))
    }
    fn verify_before_publish(&self) -> BoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(Self::verify_before_publish(self))
    }
    fn cancel(&self) {
        Self::cancel(self);
    }
}

/// Invokes an explicitly capable handler using the request already created by normal dispatch.
///
/// This adds no decoder or authorization entry. Framework callers must retain their existing
/// request and layer checks. The final success guard detects a missing publication verification;
/// it cannot reverse storage effects of a backend that violated its trait obligations.
pub async fn dispatch_external_payload<O: Operation, H: ExternalPayloadHandler<O>>(
    backend: &H,
    request: Req<O>,
    context: HandlerContext,
    payload: ExternalPayloadContext,
) -> HandlerResult<O> {
    struct CancelOnDrop(ExternalPayloadContext);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            if !self.0.is_verified() {
                self.0.cancel();
            }
        }
    }
    let guard = CancelOnDrop(payload.clone());
    if context.is_cancelled() {
        payload.cancel();
        return Err(handler_error(ExternalPayloadError::Cancelled));
    }
    let cancellation = context.clone();
    let response = match select(
        Box::pin(cancellation.cancelled()),
        backend.call_with_external_payload(request, context, payload.clone()),
    )
    .await
    {
        Either::Left((_, remaining)) => {
            payload.cancel();
            // Give the explicitly capable handler its normal rollback and outcome-reconciliation
            // path. The framework's outer deadline owner still bounds request execution.
            remaining.await
        }
        Either::Right((response, _)) => response,
    };
    if response.is_ok() && !payload.is_verified() {
        payload.cancel();
        return Err(HandlerError::internal_error(
            "external payload handler returned before publication verification",
        ));
    }
    drop(guard);
    response
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)] // Test fixtures fail immediately.
mod tests;

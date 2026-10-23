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

//! Dormant external upload sources connected to the ordinary S3 body verifier.
//!
//! Responsible for: one provider, delayed activation, checked logical EOF and cancellation.
//! NOT responsible for: signatures, request authorization, native progress or business publication.
//! Upstream: the facade's authorized dispatch. Downstream: its normal streaming body pipeline.

use super::{
    ExternalPayloadBinding, ExternalPayloadContext, ExternalPayloadControl, ExternalPayloadError, ExternalPayloadProvider,
    ExternalRequest, LogicalPayloadCompletion, PayloadProtection, external_payload_context,
};
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use http_body::{Body, Frame, SizeHint};
use rustfs_gateway_core::{BoxFuture, HandlerError, RequestBody};
use rustfs_gateway_http::TransportExtensions;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError};
use std::{
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

struct SourceState {
    provider: Option<Box<dyn ExternalPayloadProvider>>,
    source: Option<ByteStream>,
    control: Option<Arc<dyn ExternalPayloadControl>>,
    cancelled: bool,
    failure: Option<ExternalPayloadError>,
}
pub(super) struct Source {
    state: Mutex<SourceState>,
    waker: AtomicWaker,
}
impl Source {
    fn failure(&self) -> Option<ExternalPayloadError> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).failure
    }
    pub(super) fn cancel(&self) {
        let control = {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            state.cancelled = true;
            state.provider.take();
            state.source.take();
            state.control.clone()
        };
        if let Some(control) = control {
            control.cancel();
        }
        self.waker.wake();
    }
    fn control(&self) -> Result<Arc<dyn ExternalPayloadControl>, ExternalPayloadError> {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.cancelled {
            return Err(ExternalPayloadError::Cancelled);
        }
        state.control.clone().ok_or(ExternalPayloadError::NotAccepted)
    }
    pub(super) async fn prepare(&self, request: ExternalRequest) -> Result<(), ExternalPayloadError> {
        let provider = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .provider
            .take()
            .ok_or(ExternalPayloadError::AlreadyBound)?;
        let digest = *request.binding_digest();
        let length = request.logical_length();
        let payload = provider.prepare(request).await?;
        if payload.logical_length() != length {
            let (_, control, _) = payload.into_parts();
            control.cancel();
            return Err(ExternalPayloadError::LengthMismatch);
        }
        let (body, control, actual) = payload.into_parts();
        if actual != digest {
            control.cancel();
            return Err(ExternalPayloadError::Transport);
        }
        {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.cancelled {
                control.cancel();
                return Err(ExternalPayloadError::Cancelled);
            }
            state.control = Some(control);
            state.source = Some(body);
        }
        self.waker.wake();
        Ok(())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.cancel();
    }
}
struct Control(Arc<Source>);
impl ExternalPayloadControl for Control {
    fn accept(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async move { self.0.control()?.accept().await })
    }
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async move { self.0.control()?.wait_verified().await })
    }
    fn cancel(&self) {
        self.0.cancel();
    }
    fn protection(&self) -> PayloadProtection {
        self.0
            .control()
            .map_or(PayloadProtection::Unknown, |control| control.protection())
    }
}

/// Internal facade evidence for one explicitly bound upload entry.
#[derive(Clone)]
pub(crate) struct UploadEntry {
    pub(super) binding: ExternalPayloadBinding,
    pub(super) source: Arc<Source>,
    context: Arc<Mutex<Option<ExternalPayloadContext>>>,
}
impl UploadEntry {
    pub(super) fn new(binding: ExternalPayloadBinding, provider: Box<dyn ExternalPayloadProvider>) -> Self {
        Self {
            binding,
            source: Arc::new(Source {
                state: Mutex::new(SourceState {
                    provider: Some(provider),
                    source: None,
                    control: None,
                    cancelled: false,
                    failure: None,
                }),
                waker: AtomicWaker::new(),
            }),
            context: Arc::new(Mutex::new(None)),
        }
    }
    pub(super) fn context(&self) -> Result<ExternalPayloadContext, HandlerError> {
        self.context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| HandlerError::internal_error("external upload did not pass the ordinary S3 body gate"))
    }
    pub(super) fn body(&self) -> InputBody {
        InputBody {
            source: self.source.clone(),
            remaining: self.binding.length,
            ended: false,
        }
    }
}

pub(super) struct InputBody {
    source: Arc<Source>,
    remaining: u64,
    ended: bool,
}
impl Body for InputBody {
    type Data = Bytes;
    type Error = ExternalPayloadError;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        this.source.waker.register(cx.waker());
        let mut state = this.source.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.cancelled {
            this.ended = true;
            return Poll::Ready(Some(Err(ExternalPayloadError::Cancelled)));
        }
        let Some(source) = state.source.as_mut() else {
            return Poll::Pending;
        };
        match Pin::new(source).poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(PayloadRead::Chunk(bytes))) => {
                if bytes.len() as u64 > this.remaining {
                    this.ended = true;
                    return Poll::Ready(Some(Err(ExternalPayloadError::LengthMismatch)));
                }
                this.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                this.ended = true;
                if this.remaining != 0 {
                    return Poll::Ready(Some(Err(ExternalPayloadError::LengthMismatch)));
                }
                if trailers.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::trailers(trailers.into_header_map()))))
                }
            }
            Poll::Ready(Err(error)) => {
                this.ended = true;
                let reason = error
                    .producer_failure_class()
                    .map_or(ExternalPayloadError::Transport, ExternalPayloadError::from);
                state.failure.get_or_insert(reason);
                Poll::Ready(Some(Err(reason)))
            }
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
    fn is_end_stream(&self) -> bool {
        self.ended
    }
}

#[derive(Default)]
struct LogicalSignal {
    result: Mutex<Option<Result<(), ExternalPayloadError>>>,
    waker: AtomicWaker,
}
impl LogicalSignal {
    fn settle(&self, result: Result<(), ExternalPayloadError>) {
        let mut state = self.result.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_none() {
            *state = Some(result);
        }
        drop(state);
        self.waker.wake();
    }
}
impl LogicalPayloadCompletion for LogicalSignal {
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(poll_fn(|cx| {
            self.waker.register(cx.waker());
            self.result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .map_or(Poll::Pending, Poll::Ready)
        }))
    }
}
struct LogicalInput {
    body: ByteStream,
    signal: Arc<LogicalSignal>,
    source: Arc<Source>,
    ended: bool,
}
impl Drop for LogicalInput {
    fn drop(&mut self) {
        if !self.ended {
            self.signal.settle(Err(ExternalPayloadError::UnconsumedInput));
        }
    }
}
impl PayloadStream for LogicalInput {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.body).poll_read(cx);
        match result {
            Poll::Ready(Ok(eof @ PayloadRead::Eof { .. })) => {
                this.ended = true;
                this.signal.settle(Ok(()));
                Poll::Ready(Ok(eof))
            }
            Poll::Ready(Err(error)) => {
                this.ended = true;
                let reason = this.source.failure().unwrap_or(ExternalPayloadError::Integrity);
                this.signal.settle(Err(reason));
                let bytes = error.bytes_before_error();
                Poll::Ready(Err(
                    StreamError::classified_upstream(Box::new(error), reason.into()).with_bytes_before_error(bytes)
                ))
            }
            result => result,
        }
    }
    fn caps(&self) -> PayloadCaps {
        self.body.caps()
    }
    fn len_hint(&self) -> Option<u64> {
        self.body.remaining_length().get()
    }
}

pub(crate) fn bind_input(body: RequestBody, extensions: &TransportExtensions) -> Result<RequestBody, HandlerError> {
    let Some(entry) = extensions.get::<UploadEntry>() else {
        return Ok(body);
    };
    let RequestBody::Stream(body) = body else {
        return Err(HandlerError::not_implemented("external uploads require a streaming operation"));
    };
    let signal = Arc::new(LogicalSignal::default());
    let logical = ByteStream::new(Box::pin(LogicalInput {
        body,
        signal: signal.clone(),
        source: entry.source.clone(),
        ended: false,
    }))
    .map_err(|_| HandlerError::internal_error("external logical stream has inconsistent bounds"))?;
    let context = external_payload_context(entry.binding.length, Arc::new(Control(entry.source.clone())), signal);
    let body = context
        .bind_input(logical)
        .map_err(|_| HandlerError::internal_error("external logical stream could not be bound"))?;
    *entry.context.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(context);
    Ok(RequestBody::Stream(body))
}

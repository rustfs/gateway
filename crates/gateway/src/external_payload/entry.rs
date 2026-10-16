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

//! Authenticated facade entry and final response handoff for external object data.
//!
//! Responsible for: the bound logical head, unchanged S3 dispatch and one final output consumer.
//! NOT responsible for: private metadata encoding, peer establishment or storage implementation.
//! Upstream: a trusted HTTPS host. Downstream: the existing S3 pipeline and owned transport ports.

use super::{
    ExternalGetResponse, ExternalPayloadBinding, ExternalPayloadExchange, ExternalRequest, ExternalResponseResult,
    PayloadProtection, upload::UploadEntry,
};
use http::{Extensions, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body as _;
use rustfs_gateway_core::{HandlerCancellationSource, HandlerError, RequestContextView, TransportSecurity};
use rustfs_gateway_http::TransportExtensions;
use rustfs_gateway_sig::{SigFamily, SigLocation, SigService};
use rustfs_gateway_stream::{
    Body, ByteStream, NoZeroCopy, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders,
};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

#[derive(Clone)]
struct DownloadEntry(Arc<Mutex<Option<RequestContextView>>>);
struct ContextOwner(DownloadEntry);
impl Drop for ContextOwner {
    fn drop(&mut self) {
        self.0.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    }
}

/// The normal S3 result and the separately verified external output result.
///
/// A download retains its logical response headers and has no HTTP body. The private HTTPS host
/// must encode this head into its finite response envelope before writing the control response.
pub struct ExternalPayloadResponse {
    response: Response<Body>,
    output: Option<ExternalResponseResult>,
}
impl ExternalPayloadResponse {
    /// Borrows the final logical S3 response, including repeated header fields.
    #[must_use]
    pub fn response(&self) -> &Response<Body> {
        &self.response
    }
    /// Transfers the final logical response and optional verified output completion to its host.
    #[must_use]
    pub fn into_parts(self) -> (Response<Body>, Option<ExternalResponseResult>) {
        (self.response, self.output)
    }
}
impl crate::S3Service {
    /// Executes an explicitly bound upload or download through the ordinary S3 security pipeline.
    ///
    /// The actual HTTPS body must be exactly empty. The request uses UNSIGNED-PAYLOAD for an
    /// upload, with every private extension field included in its ordinary SigV4 signed headers.
    /// Logical bytes still pass through the existing S3 length, checksum, quota and deadline checks.
    /// Upload backends require explicit external registration and verification before publication.
    pub async fn call_with_external_payload_bound<B>(
        &self,
        request: Request<B>,
        binding: ExternalPayloadBinding,
        exchange: ExternalPayloadExchange,
    ) -> ExternalPayloadResponse
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();
        let upload = matches!(exchange, ExternalPayloadExchange::Upload(_));
        let encrypted = crate::service::connection_security(request.extensions()) == TransportSecurity::Encrypted;
        if request.body().size_hint().exact() != Some(0)
            || !matches!((upload, request.method()), (true, &Method::PUT) | (false, &Method::GET))
            || binding.validate_head(request.headers(), encrypted, upload).is_err()
        {
            return self.external_refusal("external request binding, signature coverage or empty control body is invalid");
        }
        let (mut parts, original) = request.into_parts();
        drop(original);
        match exchange {
            ExternalPayloadExchange::Upload(provider) => {
                let entry = UploadEntry::new(binding, provider);
                let body = entry.body();
                parts.extensions.insert(entry);
                let response = self.call(Request::from_parts(parts, body)).await;
                ExternalPayloadResponse { response, output: None }
            }
            ExternalPayloadExchange::Download(consumer) => {
                let entry = DownloadEntry(Arc::new(Mutex::new(None)));
                let owner = ContextOwner(entry.clone());
                parts.extensions.insert(entry.clone());
                let response = self.call(Request::from_parts(parts, Body::empty())).await;
                let context = entry.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
                drop(owner);
                if !matches!(response.status(), StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
                    return ExternalPayloadResponse { response, output: None };
                }
                let Some(context) = context else {
                    return self.external_refusal("external download did not reach authorized dispatch");
                };
                let Some(principal) = context.principal() else {
                    return self.external_refusal("external data requires authenticated SigV4");
                };
                let scheme = principal.scheme();
                if context.operation() != "GetObject"
                    || scheme.family() != SigFamily::V4
                    || scheme.location() != SigLocation::Header
                    || scheme.service() != SigService::S3
                {
                    return self.external_refusal("external data requires an S3 SigV4 object request");
                }
                if requires_confidentiality(&context) && consumer.protection() != PayloadProtection::ConfidentialAuthenticated {
                    return self.external_refusal("customer-key data requires a confidential authenticated external transport");
                }
                let response = crate::file_fallback::FileBodyPath::Copied(NoZeroCopy::TransportLacksSendfile).adapt(response);
                let length = response.body().len_hint();
                let Some(length) = length.filter(|length| *length <= binding.length) else {
                    return self.external_refusal("external download has no permitted exact response length");
                };
                let (parts, body) = response.into_parts();
                let progress = Arc::new(Mutex::new(ResponseProgress::default()));
                let body = match ByteStream::new(Box::pin(ResponseInput {
                    body,
                    remaining: length,
                    ended: false,
                    trailers: None,
                    progress: progress.clone(),
                })) {
                    Ok(body) => body,
                    Err(_) => return self.external_refusal("external response stream has inconsistent bounds"),
                };
                let (cancel, cancellation) = HandlerCancellationSource::pair();
                let guard = CancelOnDrop(cancel);
                let external = ExternalGetResponse {
                    request: ExternalRequest {
                        context,
                        binding_digest: binding.digest,
                        logical_length: length,
                    },
                    status: parts.status,
                    headers: parts.headers.clone(),
                    body,
                    cancellation,
                };
                let result = consume_until_cancelled(consumer.consume(external), request_cancellation).await;
                drop(guard);
                match result {
                    Ok(output)
                        if output.bytes_transferred() == length
                            && progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner).complete =>
                    {
                        ExternalPayloadResponse {
                            response: Response::from_parts(parts, Body::empty()),
                            output: Some(output),
                        }
                    }
                    _ => self.external_refusal("external download did not finish with verified bytes"),
                }
            }
        }
    }
    pub(super) fn external_refusal(&self, message: &'static str) -> ExternalPayloadResponse {
        let error = crate::render::from_handler(
            HandlerError::new(rustfs_gateway_types::ErrorCode::INVALID_REQUEST, message),
            rustfs_gateway_core::ResponseKind::Other,
            crate::close::ConnectionIntent::MayKeepAlive,
        );
        ExternalPayloadResponse {
            response: crate::render::render(&error, &self.inner.traces.mint()),
            output: None,
        }
    }
}
struct CancelOnDrop(HandlerCancellationSource);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel(rustfs_gateway_core::HandlerCancellation::RequestAborted);
    }
}
pub(crate) fn bound_entry(extensions: &Extensions) -> bool {
    extensions.get::<UploadEntry>().is_some()
        || extensions.get::<DownloadEntry>().is_some()
        || extensions.get::<super::control::ControlEntry>().is_some()
}
pub(crate) fn upload_entry(extensions: &TransportExtensions) -> bool {
    extensions.get::<UploadEntry>().is_some()
}
pub(crate) fn apply_logical_head(parts: &mut http::request::Parts) {
    if let Some(entry) = parts.extensions.get::<UploadEntry>() {
        parts
            .headers
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from(entry.binding.length));
    }
}
pub(crate) fn record_download_context(context: &RequestContextView) {
    if let Some(entry) = context.transport_extensions().get::<DownloadEntry>() {
        *entry.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(context.clone_without_caller_secret());
    }
}
pub(super) fn requires_confidentiality(context: &RequestContextView) -> bool {
    context
        .headers()
        .iter_raw()
        .any(|(name, _)| name.as_str() == "x-amz-server-side-encryption-customer-key")
}

#[derive(Default)]
struct ResponseProgress {
    complete: bool,
}
struct ResponseInput {
    body: Body,
    remaining: u64,
    ended: bool,
    trailers: Option<HeaderMap>,
    progress: Arc<Mutex<ResponseProgress>>,
}
impl PayloadStream for ResponseInput {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.ended = true;
                if this.remaining != 0 {
                    return Poll::Ready(Err(StreamError::incomplete_body()));
                }
                this.progress
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .complete = true;
                Poll::Ready(Ok(PayloadRead::Eof {
                    trailers: TrailingHeaders::from_header_map(this.trailers.take().unwrap_or_default()),
                }))
            }
            Poll::Ready(Some(Err(error))) => {
                this.ended = true;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(bytes) => {
                    if this.trailers.is_some() || bytes.len() as u64 > this.remaining {
                        this.ended = true;
                        return Poll::Ready(Err(StreamError::incomplete_body()));
                    }
                    this.remaining -= bytes.len() as u64;
                    Poll::Ready(Ok(PayloadRead::Chunk(bytes)))
                }
                Err(frame) => {
                    let Ok(trailers) = frame.into_trailers() else {
                        return Poll::Ready(Err(StreamError::incomplete_body()));
                    };
                    let bytes: usize = trailers
                        .iter()
                        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                        .sum();
                    if this.trailers.is_some() || trailers.len() > 64 || bytes > 64 * 1024 {
                        this.ended = true;
                        return Poll::Ready(Err(StreamError::incomplete_body()));
                    }
                    this.trailers = Some(trailers);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
        }
    }
    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }
    fn len_hint(&self) -> Option<u64> {
        Some(self.remaining)
    }
}

async fn consume_until_cancelled(
    future: rustfs_gateway_core::BoxFuture<'static, Result<ExternalResponseResult, super::ExternalPayloadError>>,
    cancellation: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<ExternalResponseResult, super::ExternalPayloadError> {
    use futures_util::future::{Either, select};
    use std::pin::pin;
    let Some(mut cancellation) = cancellation else {
        return future.await;
    };
    let cancelled = pin!(async move {
        loop {
            if *cancellation.borrow_and_update() {
                return;
            }
            if cancellation.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    });
    match select(cancelled, future).await {
        Either::Left(_) => Err(super::ExternalPayloadError::Cancelled),
        Either::Right((result, _)) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_control_response_accepts_bounded_bytes() {
        let response = super::super::ExternalControlResponse::new(StatusCode::OK, HeaderMap::new(), vec![1; 16]);
        assert!(response.is_ok());
    }
    #[test]
    fn finite_control_response_rejects_oversized_payload() {
        assert!(super::super::ExternalControlResponse::new(StatusCode::OK, HeaderMap::new(), vec![1; 65537]).is_err());
    }
    #[test]
    fn finite_control_response_rejects_unbounded_header_inventory() -> Result<(), http::header::InvalidHeaderName> {
        let mut headers = HeaderMap::new();
        for index in 0..65 {
            headers.insert(
                http::HeaderName::from_bytes(format!("x-test-{index}").as_bytes())?,
                HeaderValue::from_static("v"),
            );
        }
        assert!(super::super::ExternalControlResponse::new(StatusCode::OK, headers, Vec::new()).is_err());
        Ok(())
    }
    #[tokio::test]
    async fn a_closed_request_observer_does_not_cancel_successful_output() {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        drop(sender);
        let result = consume_until_cancelled(
            Box::pin(async { Ok(ExternalResponseResult::new(0, TrailingHeaders::empty())) }),
            Some(receiver),
        )
        .await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn an_explicit_request_abort_prevents_output_success() {
        let (_sender, receiver) = tokio::sync::watch::channel(true);
        let result = consume_until_cancelled(
            Box::pin(async { Ok(ExternalResponseResult::new(0, TrailingHeaders::empty())) }),
            Some(receiver),
        )
        .await;
        assert!(matches!(result, Err(super::super::ExternalPayloadError::Cancelled)));
    }
}

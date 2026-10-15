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

//! Owned external object-data ports for explicitly enabled host integrations.
//!
//! Responsible for: transport-neutral, single-use provider and consumer interfaces.
//! NOT responsible for: device access, peer control, authentication, or storage publication.
//! Upstream: the ordinary authenticated S3 pipeline. Downstream: trusted host integrations.
//!
//! These ports prepare the integration boundary. This revision rejects external wire requests:
//! the signature-bound codec, logical checksum monitor and operation registration are not yet
//! connected. Enabling the feature does not advertise successful external-data execution.

use http::{HeaderMap, Request, Response, StatusCode};
use rustfs_gateway_core::{BoxFuture, HandlerContext, RequestContextView};
use rustfs_gateway_stream::{Body, ByteStream, TrailingHeaders};

pub use crate::external_payload_execution::{dispatch_external_payload, external_payload_context};
use std::sync::Arc;

pub use rustfs_gateway_core::external_payload::{
    ExternalPayloadContext, ExternalPayloadControl, ExternalPayloadError, ExternalPayloadExecution, ExternalPayloadHandler,
    LogicalPayloadCompletion, PayloadProtection,
};

impl crate::S3Service {
    /// Receives a single-use external exchange from trusted host assembly.
    ///
    /// The signature-bound wire codec and external operation registration are not connected in
    /// this revision. Every call is therefore explicitly refused with `501 NotImplemented`, and
    /// the exchange is dropped without preparing or activating it. Ordinary S3 calls are unchanged.
    pub async fn call_with_external_payload<B>(
        &self,
        mut request: Request<B>,
        exchange: ExternalPayloadExchange,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        drop(exchange);
        request.extensions_mut().insert(crate::external_marker::ExternalEntry);
        self.call(request).await
    }
}

/// Request facts minted by the facade after its signature, binding and authorization gates.
///
/// There is no public constructor: an integration cannot authorize itself from HTTP headers.
/// The body is still dormant when a provider receives this value.
pub struct ExternalRequest {
    context: RequestContextView,
    binding_digest: [u8; 32],
    logical_length: u64,
}
impl ExternalRequest {
    /// The immutable context produced by normal S3 dispatch.
    #[must_use]
    pub fn context(&self) -> &RequestContextView {
        &self.context
    }
    /// The verified request binding for the selected external operation.
    #[must_use]
    pub fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }
    /// The authenticated exact upload length or selected download length.
    #[must_use]
    pub fn logical_length(&self) -> u64 {
        self.logical_length
    }
}

/// Single-use exchange attached by trusted host assembly to one HTTP request.
pub enum ExternalPayloadExchange {
    /// Supplies dormant input to an explicitly capable upload handler.
    Upload(Box<dyn ExternalPayloadProvider>),
    /// Consumes the final, normally encoded object response.
    Download(Box<dyn ExternalResponseConsumer>),
}

/// Creates input without granting access; the owned provider cannot prepare twice.
///
/// Dropping the provider or its future must cancel its operation without claiming remote access
/// has ended. The transport owner retains any required cleanup independently of the HTTP future.
pub trait ExternalPayloadProvider: Send {
    /// Validates the request against its prepared binding and returns a dormant source.
    fn prepare(self: Box<Self>, request: ExternalRequest) -> BoxFuture<'static, Result<ExternalPayload, ExternalPayloadError>>;
}

/// Unique body and shared control for one authenticated binding.
pub struct ExternalPayload {
    body: ByteStream,
    control: Arc<dyn ExternalPayloadControl>,
    binding_digest: [u8; 32],
    logical_length: u64,
}
impl ExternalPayload {
    /// Transfers one exactly bounded input from a trusted provider.
    ///
    /// This does not accept the operation. The facade must compare the binding and length with
    /// its authenticated request, connect its actual S3 checksum monitor, and bind the input with
    /// `ExternalPayloadContext::bind_input` before a handler receives it.
    pub fn new(
        body: ByteStream,
        control: Arc<dyn ExternalPayloadControl>,
        binding_digest: [u8; 32],
    ) -> Result<Self, ExternalPayloadError> {
        let logical_length = body.remaining_length().get().ok_or(ExternalPayloadError::LengthMismatch)?;
        if body.is_file_region() {
            return Err(ExternalPayloadError::LengthMismatch);
        }
        Ok(Self {
            body,
            control,
            binding_digest,
            logical_length,
        })
    }
    /// Checks the source facts against facade-created request evidence.
    pub fn validate_for(&self, request: &ExternalRequest) -> Result<(), ExternalPayloadError> {
        if self.binding_digest != request.binding_digest || self.logical_length != request.logical_length {
            return Err(ExternalPayloadError::LengthMismatch);
        }
        Ok(())
    }
    /// The bound logical length, without reading the source.
    #[must_use]
    pub fn logical_length(&self) -> u64 {
        self.logical_length
    }
    /// Moves the body and control once, retaining their original request binding.
    #[must_use]
    pub fn into_parts(self) -> (ByteStream, Arc<dyn ExternalPayloadControl>, [u8; 32]) {
        (self.body, self.control, self.binding_digest)
    }
}

/// The final object representation, selected and encoded by the normal S3 handler path.
///
/// HeaderMap preserves repeated fields and non-UTF-8 values. The facade converts a file region to
/// its existing bounded IO-driver path before creating this response. No consumer selects another
/// object version or re-executes a handler.
pub struct ExternalGetResponse {
    request: ExternalRequest,
    status: StatusCode,
    headers: HeaderMap,
    body: ByteStream,
    cancellation: HandlerContext,
}
impl ExternalGetResponse {
    /// Borrows the authenticated request and frozen logical response head.
    #[must_use]
    pub fn head(&self) -> (&ExternalRequest, StatusCode, &HeaderMap) {
        (&self.request, self.status, &self.headers)
    }
    /// Moves the unique input and cancellation observer to the transport consumer.
    #[must_use]
    pub fn into_parts(self) -> (ExternalRequest, StatusCode, HeaderMap, ByteStream, HandlerContext) {
        (self.request, self.status, self.headers, self.body, self.cancellation)
    }
}

/// Observed external output completion, distinct from the S3 handler's business result.
pub struct ExternalResponseResult {
    bytes_transferred: u64,
    trailers: TrailingHeaders,
}
impl ExternalResponseResult {
    /// Records real verified transport completion and trailers obtained at normal input EOF.
    #[must_use]
    pub fn new(bytes_transferred: u64, trailers: TrailingHeaders) -> Self {
        Self {
            bytes_transferred,
            trailers,
        }
    }
    /// The actual number of transferred bytes.
    #[must_use]
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred
    }
    /// The final trailers; the facade still validates their declarations and bounded size.
    #[must_use]
    pub fn trailers(&self) -> &TrailingHeaders {
        &self.trailers
    }
}

/// Consumes exactly one normally encoded object response.
///
/// Dropping the consumer or its future requests cancellation while the transport owner retains
/// progress and cleanup. A successful result must represent actual EOF and transport verification.
pub trait ExternalResponseConsumer: Send {
    /// Reports established protection before any response body or customer data is handed over.
    fn protection(&self) -> PayloadProtection;
    /// Sends the selected body with bounded backpressure, preserving final EOF trailers.
    fn consume(
        self: Box<Self>,
        response: ExternalGetResponse,
    ) -> BoxFuture<'static, Result<ExternalResponseResult, ExternalPayloadError>>;
}

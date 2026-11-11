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

//! Transport-neutral external-payload handler interfaces.
//!
//! Responsible for: control, logical-completion and execution ports and the opaque handler context.
//! NOT responsible for: polling streams, authentication, allocation or scheduling execution.
//! Upstream: the authenticated facade execution owner. Downstream: explicitly capable handlers.

use crate::{BoxFuture, Handler, HandlerContext, HandlerError, HandlerResult, Operation, Req};
use rustfs_gateway_stream::ByteStream;
use std::{fmt, sync::Arc};

/// Protection established by the trusted data transport, independently of HTTP TLS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadProtection {
    /// No verified protection evidence is available.
    Unknown,
    /// Payload integrity and peer identity are authenticated.
    Authenticated,
    /// Payload confidentiality, integrity and peer identity are authenticated.
    ConfidentialAuthenticated,
}

/// A bounded, secret-free external-data failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalPayloadError {
    /// The host has not admitted this operation.
    NotAccepted,
    /// The operation was cancelled; remote access termination is not implied.
    Cancelled,
    /// The body was already bound to its single consumer.
    AlreadyBound,
    /// An exact length is missing or disagrees with the authenticated length.
    LengthMismatch,
    /// The handler has not consumed all declared input.
    UnconsumedInput,
    /// The logical S3 checksum or trailer validation failed.
    Integrity,
    /// The transport did not produce a verified terminal result.
    Transport,
    /// The selected implementation cannot execute external payloads.
    Unavailable,
}
impl fmt::Display for ExternalPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAccepted => "external payload has not been accepted",
            Self::Cancelled => "external payload was cancelled",
            Self::AlreadyBound => "external payload already has a consumer",
            Self::LengthMismatch => "external payload length mismatch",
            Self::UnconsumedInput => "external payload input remains unconsumed",
            Self::Integrity => "external payload integrity verification failed",
            Self::Transport => "external payload transport verification failed",
            Self::Unavailable => "external payload backend is unavailable",
        })
    }
}
impl std::error::Error for ExternalPayloadError {}

impl ExternalPayloadError {
    /// Supplies an explicit producer classification while retaining this error as its source.
    #[must_use]
    pub fn into_stream_error(self) -> rustfs_gateway_stream::StreamError {
        let class = rustfs_gateway_stream::ProducerFailureClass::from(self);
        rustfs_gateway_stream::StreamError::classified_upstream(Box::new(self), class)
    }
}

impl From<ExternalPayloadError> for rustfs_gateway_stream::ProducerFailureClass {
    fn from(error: ExternalPayloadError) -> Self {
        match error {
            ExternalPayloadError::NotAccepted => Self::NotAccepted,
            ExternalPayloadError::Cancelled => Self::Cancelled,
            ExternalPayloadError::AlreadyBound => Self::AlreadyBound,
            ExternalPayloadError::LengthMismatch => Self::LengthMismatch,
            ExternalPayloadError::UnconsumedInput => Self::UnconsumedInput,
            ExternalPayloadError::Integrity => Self::Integrity,
            ExternalPayloadError::Transport => Self::Transport,
            ExternalPayloadError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<rustfs_gateway_stream::ProducerFailureClass> for ExternalPayloadError {
    fn from(class: rustfs_gateway_stream::ProducerFailureClass) -> Self {
        use rustfs_gateway_stream::ProducerFailureClass;
        match class {
            ProducerFailureClass::NotAccepted => Self::NotAccepted,
            ProducerFailureClass::Cancelled => Self::Cancelled,
            ProducerFailureClass::AlreadyBound => Self::AlreadyBound,
            ProducerFailureClass::LengthMismatch => Self::LengthMismatch,
            ProducerFailureClass::UnconsumedInput => Self::UnconsumedInput,
            ProducerFailureClass::Integrity => Self::Integrity,
            ProducerFailureClass::Transport => Self::Transport,
            ProducerFailureClass::Unavailable => Self::Unavailable,
        }
    }
}

/// Trusted transport control for one authenticated binding.
///
/// Implementations own progress and cleanup independently of observer futures. Cancellation is
/// idempotent, wakes waiters, and never claims that remote access or reclamation has completed.
/// `wait_verified` observes actual sequence, length, digest and terminal verification, including
/// after the application received the final chunk. An unavailable backend returns an error.
pub trait ExternalPayloadControl: Send + Sync + 'static {
    /// Admits the already-bound operation after host storage and quota checks.
    fn accept(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>>;
    /// Observes actual transport completion without owning application buffers.
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>>;
    /// Requests bounded, idempotent cancellation without waiting for data credits.
    fn cancel(&self);
    /// Reports established protection, never a value asserted by a request header.
    fn protection(&self) -> PayloadProtection;
}

/// Read-only result of the facade's existing logical S3 integrity monitor.
///
/// The monitor computes over actual delivered bytes, checks all required S3 checksums and
/// trailers, and can complete independently of a further body poll after the final byte. This
/// port must not substitute the empty HTTP body's digest or a transport success flag.
pub trait LogicalPayloadCompletion: Send + Sync + 'static {
    /// Waits for the operation's real logical validation result.
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>>;
}

/// Execution capability supplied by the authenticated facade for one external upload.
///
/// Implementations retain the unique-input state, count actual delivered bytes, share admission
/// and verification, and preserve the first terminal cause. This is an execution interface only:
/// it does not authenticate a request or establish authorization from caller-provided fields.
pub trait ExternalPayloadExecution: Send + Sync + 'static {
    /// The authenticated exact upload length.
    fn logical_length(&self) -> u64;
    /// Protection established by the trusted transport.
    fn protection(&self) -> PayloadProtection;
    /// Whether logical and transport verification both completed successfully.
    fn is_verified(&self) -> bool;
    /// Binds the single dormant input, counting bytes actually delivered to its consumer.
    fn bind_input(self: Arc<Self>, body: ByteStream) -> Result<ByteStream, ExternalPayloadError>;
    /// Admits the same operation once, after the handler's business checks.
    fn accept_after_admission(&self) -> BoxFuture<'_, Result<(), HandlerError>>;
    /// Requires complete input and both verification results before publication.
    fn verify_before_publish(&self) -> BoxFuture<'_, Result<(), HandlerError>>;
    /// Requests idempotent cancellation while retaining owner-managed cleanup.
    fn cancel(&self);
}

/// Read-only handler capability for a facade-owned external execution.
///
/// Cloning shares the same execution; the DTO retains unique ownership of its actual body.
/// Construction is trusted host assembly, not authentication or authorization.
#[derive(Clone)]
pub struct ExternalPayloadContext(Arc<dyn ExternalPayloadExecution>);
impl ExternalPayloadContext {
    /// Connects a trusted execution owner without granting authorization itself.
    #[must_use]
    pub fn from_execution(execution: Arc<dyn ExternalPayloadExecution>) -> Self {
        Self(execution)
    }
    /// The authenticated upload or multipart part size.
    #[must_use]
    pub fn logical_length(&self) -> u64 {
        self.0.logical_length()
    }
    /// The data protection established by this execution's transport.
    #[must_use]
    pub fn protection(&self) -> PayloadProtection {
        self.0.protection()
    }
    /// Whether the execution completed logical and transport verification.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.0.is_verified()
    }
    /// Binds one exact-length input without polling it before admission.
    pub fn bind_input(&self, body: ByteStream) -> Result<ByteStream, ExternalPayloadError> {
        self.0.clone().bind_input(body)
    }
    /// Observes shared admission after the handler's existing checks.
    pub fn accept_after_admission(&self) -> BoxFuture<'_, Result<(), HandlerError>> {
        self.0.accept_after_admission()
    }
    /// Requires complete and verified input before the handler publishes data.
    pub fn verify_before_publish(&self) -> BoxFuture<'_, Result<(), HandlerError>> {
        self.0.verify_before_publish()
    }
    /// Requests cancellation without claiming remote access has ended.
    pub fn cancel(&self) {
        self.0.cancel();
    }
}

/// Explicit backend capability for uploads whose data is supplied outside the HTTP body.
///
/// Implementations call `accept_after_admission` after their existing checks, and must call
/// `verify_before_publish` before publishing an object or part. Ordinary `Handler` implementations
/// do not acquire this capability automatically. Use one business implementation for both paths.
pub trait ExternalPayloadHandler<O: Operation>: Handler<O> {
    /// Executes an already-authorized request with its external input capability.
    fn call_with_external_payload<'a>(
        &'a self,
        request: Req<O>,
        context: HandlerContext,
        payload: ExternalPayloadContext,
    ) -> BoxFuture<'a, HandlerResult<O>>;
}

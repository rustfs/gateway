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

//! The shapes every RustFS admin operation shares.
//!
//! Responsible for: [`AdminResponse`], what every handler answers; [`spec`] and [`floor`], which
//! every operation is built from; the body decoders and the one response encoder the generated
//! codecs call; and [`AdminOperation`] with [`OperationFold`], which let a deployment walk every
//! operation without naming each one.
//! NOT responsible for: any one route (the generated [`crate::ops`]), the claims and the overlay
//! ([`crate::dialect`]), or what RustFS does in a handler.
//! Upstream: `rustfs-gateway-core`'s operation, codec and dialect types. Downstream: every
//! generated operation, [`crate::dialect`], and a deployment's handlers.
//!
//! # Why one response type
//!
//! RustFS's admin handlers answer JSON, a binary download or a live stream, and the gateway
//! interprets none of it: an admin body is opaque to the protocol. One type with a content type,
//! further headers and a complete or streamed body covers every route, and lets one generic
//! handler serve all of them.

use core::fmt;

use bytes::Bytes;
use rustfs_gateway_core::codec::{CodecError, EncodedResponse, OperationCodec, RequestBody, ResponseBody};
use rustfs_gateway_core::dialect::{BucketParam, ClaimedRow};
use rustfs_gateway_core::op::{AuthRequirement, Operation};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
use rustfs_gateway_core::route::ShadowingDecl;
use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_stream::ByteStream;

/// The content type of a JSON answer.
pub const JSON: &str = "application/json";

/// Headers an [`AdminResponse`] may not set: the server frames the message, and the content type
/// has its own field.
const RESERVED_HEADERS: &[&str] = &["connection", "content-length", "content-type", "transfer-encoding"];

/// An admin answer's body.
pub enum AdminBody {
    /// The whole body, already produced.
    Complete(Vec<u8>),
    /// A live producer, for the routes RustFS streams (`log`, `trace`, `metrics`, `inspect/archive`).
    Stream(ByteStream),
}

/// What an admin handler answers: a content type, any further headers, and the body.
///
/// The status is the operation's success status. A handler that must refuse returns a
/// `HandlerError` instead, which the facade renders like every other error.
pub struct AdminResponse {
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
    body: AdminBody,
}

impl AdminResponse {
    /// A JSON document.
    #[must_use]
    pub fn json(bytes: impl Into<Vec<u8>>) -> Self {
        Self::bytes(JSON, bytes)
    }

    /// A complete body of `content_type`.
    #[must_use]
    pub fn bytes(content_type: &'static str, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            content_type,
            headers: Vec::new(),
            body: AdminBody::Complete(bytes.into()),
        }
    }

    /// A streamed body of `content_type`.
    #[must_use]
    pub fn stream(content_type: &'static str, stream: ByteStream) -> Self {
        Self {
            content_type,
            headers: Vec::new(),
            body: AdminBody::Stream(stream),
        }
    }

    /// No body and no content type.
    #[must_use]
    pub fn empty() -> Self {
        Self::bytes("", Vec::new())
    }

    /// Adds a header, such as `content-disposition` on a download. A framing header or the
    /// content type is ignored when the response is encoded, and so is a value HTTP cannot carry.
    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// The content type, empty for none.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.content_type
    }

    /// The further headers, in the order they were added.
    #[must_use]
    pub fn headers(&self) -> &[(&'static str, String)] {
        &self.headers
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &AdminBody {
        &self.body
    }
}

impl fmt::Debug for AdminResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = match &self.body {
            AdminBody::Complete(bytes) => format!("{} bytes", bytes.len()),
            AdminBody::Stream(_) => "a stream".to_owned(),
        };
        f.debug_struct("AdminResponse")
            .field("content_type", &self.content_type)
            .field("headers", &self.headers.iter().map(|(name, _)| *name).collect::<Vec<_>>())
            .field("body", &body)
            .finish()
    }
}

/// Encodes an [`AdminResponse`] at `status`. Every generated codec's `encode` is this.
///
/// # Errors
///
/// None today; the signature is the codec's.
pub fn encode(output: AdminResponse, status: u16) -> Result<EncodedResponse, CodecError> {
    let mut encoded = EncodedResponse::of(status);
    if !output.content_type.is_empty() {
        encoded.set_header("content-type", output.content_type);
    }
    for (name, value) in output.headers {
        if !RESERVED_HEADERS.iter().any(|reserved| reserved.eq_ignore_ascii_case(name)) {
            encoded.set_header(name, &value);
        }
    }
    encoded.body = match output.body {
        AdminBody::Complete(bytes) if bytes.is_empty() => ResponseBody::Empty,
        AdminBody::Complete(bytes) => ResponseBody::Complete(bytes),
        AdminBody::Stream(stream) => ResponseBody::Stream(stream),
    };
    Ok(encoded)
}

/// The body RustFS buffers, as it arrived: an opaque JSON or binary document the handler parses.
///
/// # Errors
///
/// [`CodecError`] when the pipeline handed over something other than a buffered body.
pub fn buffered(body: RequestBody) -> Result<Bytes, CodecError> {
    body.into_buffered()
}

/// The body RustFS streams, as a live producer; an absent body is an empty stream.
///
/// # Errors
///
/// [`CodecError`] for a browser form, which no admin route accepts.
pub fn streamed(body: RequestBody) -> Result<ByteStream, CodecError> {
    match body {
        RequestBody::Stream(stream) => Ok(stream),
        RequestBody::None => Ok(ByteStream::from_bytes(Bytes::new())),
        RequestBody::Buffered(bytes) => Ok(ByteStream::from_bytes(bytes)),
        _ => Err(CodecError::internal("an admin operation was handed a browser form")),
    }
}

/// The specification every admin operation has: success `200`, no required parameter, the
/// `Standard` handler deadline, `auth`, and the caller's secret only when RustFS seals a body with
/// it (ADR-0024).
#[must_use]
pub const fn spec(name: &'static str, auth: AuthRequirement, caller_secret: bool) -> OperationSpec {
    let builder = OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(auth);
    if caller_secret {
        builder.hand_caller_secret_to_handler().build()
    } else {
        builder.build()
    }
}

/// The floor every admin operation has: privileged and header-signed only, so it is never reached
/// anonymously and never through a presigned URL (MinIO #5411 was a presigned URL edited to reach
/// an admin operation).
#[must_use]
pub const fn floor(name: &'static str) -> OperationFloor {
    OperationFloor::custom(name, SigService::S3)
}

/// The floor of an anonymous bootstrap operation (ADR-0026 (f), ADR-0032): header-signed or
/// anonymous, never presigned. The opt-in is per operation, so the start-up
/// `SECURITY_POSTURE anonymous_reachable_ops=[…]` line names it, and the authorizer is still asked.
#[must_use]
pub const fn anonymous_floor(name: &'static str) -> OperationFloor {
    OperationFloor::custom(name, SigService::S3).allow_anonymous_after_listing_in_the_posture_report()
}

/// A generated admin operation: its codec answers an [`AdminResponse`], and it knows its rows.
pub trait AdminOperation: OperationCodec + Operation<Output = AdminResponse> {
    /// Its place among the dialect's claimed rows.
    const PRECEDENCE: u16;
    /// Its ADR-0024 registration group.
    const GROUP: &'static str;
    /// The bucket it is authorised on, when it has one: its `{bucket}` template parameter or a
    /// query parameter (ADR-0025 (c), ADR-0026 (e), ADR-0030). `None` for a service-level
    /// operation, which is almost every operation.
    const BUCKET: Option<BucketParam> = None;

    /// Its canonical row, then the MinIO alias RustFS serves it under, when there is one.
    fn rows() -> &'static [ClaimedRow];

    /// The later operations it stands in front of, where a literal segment of its path meets
    /// their parameter (ADR-0027). None for almost every operation.
    fn shadows() -> &'static [ShadowingDecl] {
        &[]
    }
}

/// A step over every admin operation in turn, carrying a value from one to the next: a dialect
/// builder that declares each, or a service builder that registers a handler for each.
pub trait OperationFold {
    /// What is carried from one operation to the next.
    type Carry;

    /// Takes one operation's step.
    fn step<O: AdminOperation>(&mut self, carry: Self::Carry) -> Self::Carry;
}

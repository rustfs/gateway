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

use http::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{Response, StatusCode};
use rustfs_gateway_core::{EncodedResponse, ResponseBody};
use rustfs_gateway_stream::Body;
use rustfs_gateway_xml::{DECLARATION, strip_declaration};

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
/// and two independent numbers could answer it inconsistently. What is still missing is the
/// writing: nothing emits [`KEEPALIVE_BYTE`] on a wire yet, because doing so needs the head frozen
/// before the work runs (`P3-06` §4.2) and today the head is built from the output.
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

/// Writes a committed response whose outcome turned out to be a refusal.
///
/// The status is the one the head went out with — *not* the refusal's own, which is the whole point:
/// by the time this refusal exists, the status line has been sent. The document is byte-for-byte the
/// one [`crate::render::render`] would have produced, minus the declaration the prologue already
/// carried and minus the head, which a refusal at this point has no way to add to.
pub(crate) fn refused(error: &S3Error, trace: &RequestTrace, status: StatusCode) -> Response<Body> {
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
pub(crate) fn answered(encoded: EncodedResponse, status: StatusCode) -> Response<Body> {
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
    use rustfs_gateway_core::{ErrorContext, HandlerError, MissingObject, ResourceVisibility, ResponseKind, resolve};
    use rustfs_gateway_types::ErrorCode;

    fn trace() -> RequestTrace {
        RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0)
    }

    async fn body_of(response: Response<Body>) -> String {
        let collected = crate::wire::collect(response).await.expect("an in-memory body");
        String::from_utf8(collected.body().to_vec()).expect("utf-8")
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

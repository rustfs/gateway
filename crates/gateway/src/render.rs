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

//! The one place a refusal becomes an HTTP response.
//!
//! Responsible for: [`S3Error`] — a code, a status and a message, assembled from whichever stage
//! refused — and [`render`], which turns one into the `<Error>` document S3 clients parse.
//! NOT responsible for: deciding any code. Every code here arrives from the stage that refused:
//! `WireReject`, `PreAuthError`, `AuthError`, `Denial`, `CodecError` or `HandlerError`.
//! Upstream: `rustfs-gateway-types`, `rustfs-gateway-xml`. Downstream: `crate::service`.
//!
//! # Why every stage funnels through one renderer
//!
//! Six stages can refuse a request and each of them has its own error type. Rendering per stage
//! means six places that decide whether the body is XML, whether `Content-Type` is set, and
//! whether the response echoes anything the caller sent. The last of those is the one that
//! matters: a rejection body is the only thing an unauthenticated caller can make this service
//! produce, so "does this contain request bytes" must be answerable by reading one function.
//!
//! # What may appear in the body
//!
//! The code, a message, — for a decode failure — the *model member* name, which is a compile-time
//! constant from the IR, and the two server-minted identifiers. Nothing derived from the request
//! reaches [`S3Error::message`], because the types that carry a message before authentication
//! (`PreAuthError`, `CodecError`) hold `&'static str` and `format!` does not typecheck into them.
//! A [`rustfs_gateway_core::HandlerError`] may carry a dynamic message, and it may because by then
//! the caller has been authenticated and authorised.
//!
//! # Why the identifiers arrive as a parameter rather than being minted here
//!
//! [`render`] takes the [`RequestTrace`] the service already minted. Minting one here would be the
//! second minting site in a request, and the header the service writes and the `<RequestId>` this
//! function writes would then name two different requests — a discrepancy no test that reads only
//! one of them would ever see. So this function cannot mint: it holds no [`crate::TraceSource`],
//! and the value it renders is the value the caller receives in the header, because it writes that
//! header too.

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Response, StatusCode};
use rustfs_gateway_core::{CodecError, HandlerError, PreAuthError};
use rustfs_gateway_http::WireReject;
use rustfs_gateway_sig::AuthError;
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, ErrorContext, status_of};
use rustfs_gateway_xml::{DECLARATION, XmlWriter};

use crate::ext::Denial;
use crate::trace::RequestTrace;

/// A refusal, in the shape the renderer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Error {
    code: ErrorCode,
    status: StatusCode,
    message: std::borrow::Cow<'static, str>,
    resource: Option<String>,
}

impl S3Error {
    /// A refusal with a code, taking the status the code maps to.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        let status = status_of(&code, &ErrorContext::default());
        Self {
            code,
            status,
            message: message.into(),
            resource: None,
        }
    }

    /// A refusal whose status the stage decided rather than the code table.
    ///
    /// Needed because `WireReject` answers `413` and `431` for limits that have no distinct S3
    /// code, and folding those into the table's status would change the code's meaning everywhere
    /// else it is used.
    #[must_use]
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Names the resource the refusal is about — a bucket, or a bucket and key.
    #[must_use]
    pub fn about_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// The S3 error code.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The status this refusal goes out with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<WireReject> for S3Error {
    fn from(reject: WireReject) -> Self {
        // The status comes from the reject, not from the code table: `LimitExceeded` maps to
        // several statuses depending on which ceiling was hit, and only the reject knows which.
        Self::new(reject.error_code(), reject.as_str()).with_status(reject.to_status())
    }
}

impl From<PreAuthError> for S3Error {
    fn from(error: PreAuthError) -> Self {
        let status = error.status();
        Self::new(error.code().clone(), error.message()).with_status(status)
    }
}

impl From<AuthError> for S3Error {
    fn from(error: AuthError) -> Self {
        // The code strings are `AuthError`'s own, because SDK credential-refresh logic branches on
        // them; the status comes from the shared table so that one code has one status everywhere.
        Self::new(ErrorCode::custom(error.code()), error.message())
    }
}

impl From<Denial> for S3Error {
    fn from(denial: Denial) -> Self {
        // One sentence for every denial. A message that named the failing condition would let an
        // authenticated caller map the policy one request at a time.
        Self::new(denial.code().clone(), "the request is not allowed")
    }
}

impl From<CodecError> for S3Error {
    fn from(error: CodecError) -> Self {
        let status = error.status();
        let refusal = Self::new(error.code().clone(), error.message()).with_status(status);
        match error.member() {
            Some(member) => refusal.about_resource(member),
            None => refusal,
        }
    }
}

impl From<HandlerError> for S3Error {
    fn from(error: HandlerError) -> Self {
        let status = error.status();
        Self::new(error.code().clone(), error.message().to_owned()).with_status(status)
    }
}

/// Renders a refusal as the `<Error>` document S3 clients parse.
///
/// The body is omitted for the statuses RFC 9110 says carry none, and for `HEAD`, which the
/// service applies afterwards through `EncodedResponse::enforce_http_invariants`. Everything else
/// gets a document, because a client that receives a bare status has nothing to branch on.
///
/// `trace` is written twice — into the response head and into the document — from one value, which
/// is the whole of the request-identifier invariant. `RequestId` and `HostId` come last in the
/// element order, after `Resource` and any code-specific element, which is where S3 puts them.
#[must_use]
pub fn render(error: &S3Error, trace: &RequestTrace) -> Response<Body> {
    let mut xml = XmlWriter::document();
    xml.open("Error", None);
    xml.element("Code", error.code.as_str());
    xml.element("Message", &error.message);
    if let Some(resource) = &error.resource {
        xml.element("Resource", resource);
    }
    xml.element("RequestId", trace.request_id().as_str());
    xml.element("HostId", trace.host_id().as_str());
    xml.close();
    let body = xml.finish();

    let length = body.len();
    let mut response = Response::new(Body::from(body.into_bytes()));
    *response.status_mut() = error.status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    if let Ok(value) = http::HeaderValue::from_str(&length.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
    trace.apply(headers);
    response
}

/// The XML declaration every rendered document opens with, re-exported for a consumer that
/// compares a body byte for byte.
#[must_use]
pub const fn declaration() -> &'static str {
    DECLARATION
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The trace the tests below render with; pinned so a body can be read literally.
    fn trace() -> RequestTrace {
        RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0)
    }

    /// Negative — a rejection body carries the code and the message and nothing else. This is the
    /// assertion that stops a future edit from adding the request path "for debuggability".
    #[tokio::test]
    async fn a_rendered_refusal_echoes_nothing_from_the_request() {
        let error = S3Error::from(AuthError::SignatureDoesNotMatch);
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
        assert!(body.contains("the request was not authenticated"), "{body}");
        assert!(!body.contains("Authorization"), "{body}");
    }

    /// Negative — the two credential rejections keep distinct codes and identical messages, so the
    /// body is not an access-key oracle even though the code is faithful to S3.
    #[test]
    fn the_two_credential_rejections_differ_only_in_their_code() {
        let unknown = S3Error::from(AuthError::InvalidAccessKeyId);
        let mismatch = S3Error::from(AuthError::SignatureDoesNotMatch);
        assert_ne!(unknown.code(), mismatch.code());
        assert_eq!(unknown.message(), mismatch.message());
    }

    /// Negative — a denial says nothing about which policy condition failed.
    #[test]
    fn a_denial_renders_one_sentence() {
        assert_eq!(S3Error::from(Denial::access_denied()).message(), "the request is not allowed");
    }

    /// Negative — a wire rejection keeps the status the wire layer chose, not the one the code
    /// table would give, because several limits share one code and differ in status.
    #[test]
    fn a_wire_rejection_keeps_its_own_status() {
        let reject = WireReject::MalformedRequestTarget;
        let status = reject.to_status();
        assert_eq!(S3Error::from(reject).status(), status);
    }

    /// Positive — the document is well-formed and opens with the declaration a client expects.
    #[tokio::test]
    async fn the_document_opens_with_the_xml_declaration() {
        let error = S3Error::new(ErrorCode::ACCESS_DENIED, "the request is not allowed");
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert!(body.starts_with(declaration()), "{body}");
        assert!(body.trim_end().ends_with("</Error>"), "{body}");
    }

    /// Negative — the header and the document carry the same identifier, byte for byte. Two
    /// formatting sites that agree today are two that can drift apart tomorrow.
    #[tokio::test]
    async fn the_header_and_the_document_carry_one_identifier() {
        let error = S3Error::new(ErrorCode::ACCESS_DENIED, "the request is not allowed");
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert!(body.contains("<RequestId>0123456789ABCDEF</RequestId>"), "{body}");
        assert_eq!(collected.header("x-amz-request-id"), Some("0123456789ABCDEF"));
        assert!(body.contains("<HostId>00000000000000000000000000000000</HostId>"), "{body}");
        assert_eq!(collected.header("x-amz-id-2"), Some("00000000000000000000000000000000"));
    }

    /// Negative — the identifiers come last, after a code-specific element such as `Resource`. A
    /// client that reads the document positionally sees the order S3 emits.
    #[tokio::test]
    async fn the_identifiers_are_the_last_two_elements() {
        let error = S3Error::new(ErrorCode::ACCESS_DENIED, "the request is not allowed").about_resource("Bucket");
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert!(
            body.trim_end().ends_with(
                "<Resource>Bucket</Resource><RequestId>0123456789ABCDEF</RequestId>\
                            <HostId>00000000000000000000000000000000</HostId></Error>"
            ),
            "{body}"
        );
    }
}

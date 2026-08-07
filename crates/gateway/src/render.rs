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
//! Responsible for: [`S3Error`] — a code, a status, a message and whatever headers and extra
//! document elements the refusing stage attached — [`document`], which builds the `<Error>` XML,
//! and [`render`], which wraps it in a response head.
//! NOT responsible for: deciding any code. Every code here arrives from the stage that refused:
//! `WireReject`, `PreAuthError`, `AuthError`, `Denial`, `CodecError` or `HandlerError`. Nor for
//! deciding *which* headers a backend may attach: that closed set is
//! `rustfs_gateway_core::ErrorHeader`, and the complement is `crate::stamp::is_reserved`.
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
//!
//! # Where the 200-then-fail case will attach
//!
//! `CompleteMultipartUpload` commits `200` before it knows whether it succeeded, so it has to emit
//! an `<Error>` document into a body whose head has already gone out. That path needs the document
//! without the head, which is why [`document`] is a function of its own rather than the first half
//! of [`render`]. What it will additionally need — a `HandlerResult` that can say "committed, then
//! failed" — is not here; it is a change to the handler contract, not to this file.

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Response, StatusCode};
use rustfs_gateway_core::{CodecError, ErrorDetail, ErrorHeader, HandlerError, PreAuthError};
use rustfs_gateway_http::WireReject;
use rustfs_gateway_sig::AuthError;
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, ErrorContext, status_of};
use rustfs_gateway_xml::{DECLARATION, XmlWriter};

use crate::ext::Denial;
use crate::trace::RequestTrace;

/// What a refusal adds to itself beyond a code, a status and a message.
///
/// Behind one pointer, and absent unless something filled it in. Almost no refusal carries either
/// list — five stages out of six have no way to produce one — and an `S3Error` travels in the `Err`
/// arm of the pipeline's own `Result`s, where two inline `Vec`s are 48 bytes every refusal and every
/// success pays for. `clippy::result_large_err` is what noticed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Extras {
    headers: Vec<ErrorHeader>,
    details: Vec<ErrorDetail>,
}

/// A refusal, in the shape the renderer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Error {
    code: ErrorCode,
    status: StatusCode,
    message: std::borrow::Cow<'static, str>,
    resource: Option<String>,
    extras: Option<Box<Extras>>,
}

/// What [`S3Error::headers`] and [`S3Error::details`] answer when there are no extras.
const NO_HEADERS: &[ErrorHeader] = &[];
/// The [`NO_HEADERS`] twin.
const NO_DETAILS: &[ErrorDetail] = &[];

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
            extras: None,
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

    /// The headers the refusing stage attached, before the reserved ones are filtered out.
    ///
    /// Only a `HandlerError` populates these today: every stage that refuses before a handler runs
    /// does so from a type that has no way to carry one.
    #[must_use]
    pub fn headers(&self) -> &[ErrorHeader] {
        self.extras.as_ref().map_or(NO_HEADERS, |extras| &extras.headers)
    }

    /// The extra document elements, in the order they will be written.
    #[must_use]
    pub fn details(&self) -> &[ErrorDetail] {
        self.extras.as_ref().map_or(NO_DETAILS, |extras| &extras.details)
    }
}

impl From<WireReject> for S3Error {
    fn from(reject: WireReject) -> Self {
        // The status comes from the reject, not from the code table: `LimitExceeded` maps to
        // several statuses depending on which ceiling was hit, and only the reject knows which.
        // `message()`, never `label()`. This is the one place a refusal becomes bytes a client
        // reads, and the two strings exist precisely because they have different audiences: the
        // label is an operator's identifier and belongs in a log. There used to be a third name,
        // `as_str()`, which delegated here — it was removed because a habit-reached name that
        // happens to be right is not a guarantee, and a reviewer who sees `label()` on this line
        // can tell it is wrong, which is the property worth having.
        Self::new(reject.error_code(), reject.message()).with_status(reject.to_status())
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
        let mut refusal = Self::new(error.code().clone(), error.message().to_owned()).with_status(status);
        if !error.headers().is_empty() || !error.details().is_empty() {
            // Carried over wholesale rather than filtered here: both lists are already closed sets,
            // and the one filter that exists — the reserved header names — belongs at the write
            // site, where it is the last word.
            refusal.extras = Some(Box::new(Extras {
                headers: error.headers().to_vec(),
                details: error.details().to_vec(),
            }));
        }
        refusal
    }
}

/// The `<Error>` document on its own, with no response head around it.
///
/// Separate from [`render`] because the 200-then-fail path has no head to write — see the module
/// documentation. `RequestId` and `HostId` come last in the element order, after `Resource` and
/// after every extra element, which is where S3 puts them and where a positional reader expects
/// them; the extras themselves are already in `rustfs_gateway_core::ELEMENT_ORDER`, because the
/// type that carries them keeps them there.
#[must_use]
pub fn document(error: &S3Error, trace: &RequestTrace) -> String {
    let mut out = String::from(DECLARATION);
    out.push_str(&document_body(error, trace));
    out
}

/// The `<Error>` document with neither a response head **nor an XML declaration** around it.
///
/// For the committed path, whose declaration went out with the head: see `crate::commit`. Element
/// for element it is [`document`]'s output, and it is the same function producing both — a second
/// renderer for the committed path is a second place `<Code>` could be spelled differently.
#[must_use]
pub fn document_body(error: &S3Error, trace: &RequestTrace) -> String {
    let mut xml = XmlWriter::fragment();
    xml.open("Error", None);
    xml.element("Code", error.code.as_str());
    xml.element("Message", &error.message);
    if let Some(resource) = &error.resource {
        xml.element("Resource", resource);
    }
    for detail in error.details() {
        xml.element(detail.element(), detail.text().as_ref());
    }
    xml.element("RequestId", trace.request_id().as_str());
    xml.element("HostId", trace.host_id().as_str());
    xml.close();
    xml.finish()
}

/// Renders a refusal as the `<Error>` document S3 clients parse, with its response head.
///
/// The body is omitted for the statuses RFC 9110 says carry none, and for `HEAD`, which the
/// service applies afterwards through `EncodedResponse::enforce_http_invariants`. Everything else
/// gets a document, because a client that receives a bare status has nothing to branch on.
///
/// `trace` is written twice — into the response head and into the document — from one value, which
/// is the whole of the request-identifier invariant.
///
/// The refusing stage's own headers are written **first**, before the document's framing headers
/// and before the identifiers. That order is the point: a name in [`crate::stamp::is_reserved`] is
/// skipped outright, and even if that predicate were wrong, the framework's own writes come
/// afterwards and win. Two locks, because the first one is a list somebody has to keep correct.
#[must_use]
pub fn render(error: &S3Error, trace: &RequestTrace) -> Response<Body> {
    let body = document(error, trace);
    let length = body.len();
    let mut response = Response::new(Body::from(body.into_bytes()));
    *response.status_mut() = error.status;
    let headers = response.headers_mut();
    for header in error.headers() {
        let name = header.name();
        if crate::stamp::is_reserved(&name) {
            continue;
        }
        if let Ok(value) = http::HeaderValue::from_str(&header.value()) {
            headers.insert(name, value);
        }
    }
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

    /// Positive — the `416` a handler builds reaches the wire whole: the status, the header RFC
    /// 9110 §14.4 requires, and the two elements, in the order `c-range-0010` pins.
    #[tokio::test]
    async fn an_unsatisfiable_range_renders_its_header_and_its_two_elements() {
        let error = S3Error::from(HandlerError::unsatisfiable_range("bytes=20-30", 10));
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        assert_eq!(collected.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(collected.header("content-range"), Some("bytes */10"));
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert_eq!(
            body,
            format!(
                "{}<Error><Code>InvalidRange</Code><Message>The requested range is not satisfiable</Message>\
                 <RangeRequested>bytes=20-30</RangeRequested><ActualObjectSize>10</ActualObjectSize>\
                 <RequestId>0123456789ABCDEF</RequestId><HostId>{}</HostId></Error>",
                declaration(),
                "0".repeat(32)
            )
        );
    }

    /// Positive — the `412` document names the condition that failed, in the position `c-cond-0001`
    /// and `c-cond-0023` pin, and adds no header.
    #[tokio::test]
    async fn a_precondition_failure_renders_its_condition_element() {
        let error = S3Error::from(HandlerError::precondition_failed("If-None-Match"));
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        assert_eq!(collected.status(), StatusCode::PRECONDITION_FAILED);
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert!(
            body.contains("<Message>At least one of the pre-conditions you specified did not hold</Message><Condition>If-None-Match</Condition><RequestId>"),
            "{body}"
        );
        assert!(!body.contains("xmlns"), "{body}");
    }

    /// Negative — the identifiers stay last however many extra elements a refusal carries. A client
    /// that reads the document positionally would otherwise stop before the ones support asks for.
    #[tokio::test]
    async fn the_identifiers_stay_last_behind_every_extra_element() {
        let error = S3Error::from(
            HandlerError::internal_error("no")
                .with_detail(ErrorDetail::ActualObjectSize(10))
                .with_detail(ErrorDetail::Key(std::borrow::Cow::Borrowed("k")))
                .with_detail(ErrorDetail::BucketName(std::borrow::Cow::Borrowed("b")))
                .with_detail(ErrorDetail::Condition(std::borrow::Cow::Borrowed("If-Match")))
                .with_detail(ErrorDetail::RangeRequested(std::borrow::Cow::Borrowed("bytes=0-1"))),
        )
        .about_resource("Bucket");
        let body = document(&error, &trace());
        let order: Vec<&str> = ["Code", "Message", "Resource"]
            .into_iter()
            .chain(rustfs_gateway_core::ELEMENT_ORDER)
            .chain(["RequestId", "HostId"])
            .collect();
        let mut cursor = 0;
        for element in order {
            let at = body
                .find(&format!("<{element}>"))
                .unwrap_or_else(|| panic!("{element} in {body}"));
            assert!(at >= cursor, "{element} is out of order in {body}");
            cursor = at;
        }
    }

    /// Negative — an element's text is escaped, so a key or a range echoed back cannot close the
    /// element it sits in. This is the injection the extra elements would otherwise open: their
    /// text is the one part of the document derived from what the caller sent.
    #[tokio::test]
    async fn an_extra_element_cannot_break_out_of_its_own_element() {
        let error = S3Error::from(
            HandlerError::internal_error("no")
                .with_detail(ErrorDetail::Key(std::borrow::Cow::Borrowed("</Key><Code>AccessDenied</Code><Key>"))),
        );
        let body = document(&error, &trace());
        assert_eq!(body.matches("<Code>").count(), 1, "{body}");
        assert!(body.contains("&lt;/Key&gt;"), "{body}");
    }

    /// Negative — a refusal that carries no extras renders exactly the document it rendered before
    /// this capability existed. Adding an empty list must not add an empty element.
    #[tokio::test]
    async fn a_refusal_with_no_extras_renders_the_document_it_always_did() {
        let error = S3Error::new(ErrorCode::ACCESS_DENIED, "the request is not allowed");
        assert_eq!(
            document(&error, &trace()),
            format!(
                "{}<Error><Code>AccessDenied</Code><Message>the request is not allowed</Message>\
                 <RequestId>0123456789ABCDEF</RequestId><HostId>{}</HostId></Error>",
                declaration(),
                "0".repeat(32)
            )
        );
    }

    /// Negative — a refusal that carries a header of its own does not disturb the document's own
    /// framing, and does not disturb the identifiers. `Content-Length` still describes the bytes
    /// this function built, and the identifier is still the one the service minted, because both
    /// are written after the refusal's headers rather than before.
    #[tokio::test]
    async fn a_header_of_the_refusals_own_does_not_disturb_what_the_framework_writes() {
        let plain = render(&S3Error::from(HandlerError::internal_error("no")), &trace());
        let expected_length = plain.headers().get(CONTENT_LENGTH).cloned();

        let carrying = S3Error::from(HandlerError::internal_error("no").with_header(ErrorHeader::RetryAfter { seconds: 5 }));
        let response = render(&carrying, &trace());
        assert_eq!(response.headers().get(CONTENT_LENGTH), expected_length.as_ref());
        assert_eq!(
            response.headers().get(CONTENT_TYPE).map(http::HeaderValue::as_bytes),
            Some(&b"application/xml"[..])
        );
        assert_eq!(
            response
                .headers()
                .get(crate::trace::REQUEST_ID_HEADER)
                .map(http::HeaderValue::as_bytes),
            Some(&b"0123456789ABCDEF"[..])
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::RETRY_AFTER)
                .map(http::HeaderValue::as_bytes),
            Some(&b"5"[..])
        );
    }

    /// Negative — a header whose name the framework owns is dropped rather than written, whatever
    /// it was attached to. The closed set has no such variant today, so the filter is exercised
    /// through its predicate and through the write order: the framework writes last.
    #[tokio::test]
    async fn a_reserved_name_would_be_dropped_and_the_framework_writes_last() {
        let error = S3Error::from(HandlerError::unsatisfiable_range("bytes=20-30", 10));
        let response = render(&error, &trace());
        // Every name that survived is one a backend is allowed to have written.
        for name in response.headers().keys() {
            let written_by_the_error = error.headers().iter().any(|header| header.name() == *name);
            assert!(
                !written_by_the_error || !crate::stamp::is_reserved(name),
                "{name} was written by the refusal and is reserved"
            );
        }
        assert_eq!(response.headers().get_all(CONTENT_TYPE).iter().count(), 1);
    }

    /// Negative — every name the closed set can produce survives the filter, and every name the
    /// framework owns would not. The second half is the one that matters: it is the assertion that
    /// a widened `ErrorHeader` cannot quietly hand a backend the request identifier.
    #[test]
    fn the_filter_passes_the_closed_set_and_stops_the_framework_owned_names() {
        for header in [
            ErrorHeader::UnsatisfiedRange { complete_length: 1 },
            ErrorHeader::RetryAfter { seconds: 1 },
        ] {
            assert!(!crate::stamp::is_reserved(&header.name()), "{}", header.name());
        }
        for name in [
            "x-amz-request-id",
            "x-amz-id-2",
            "server",
            "date",
            "content-type",
            "content-length",
        ] {
            let name = http::HeaderName::from_bytes(name.as_bytes()).expect("a header name");
            assert!(crate::stamp::is_reserved(&name), "{name}");
        }
    }
}

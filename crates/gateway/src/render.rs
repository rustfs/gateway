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
//! Responsible for: [`S3Error`], `<Error>` XML in [`document`], and response heads in [`render`].
//! NOT responsible for: choosing an error code or backend header; refusing stages and
//! `rustfs_gateway_core::ErrorHeader` own those decisions.
//! Upstream: `rustfs-gateway-types`, `rustfs-gateway-xml`. Downstream: `crate::service`.
//! It keeps framing, identifiers, reserved headers, and redaction reviewable in one place.

use http::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG};
use http::{Response, StatusCode};
use rustfs_gateway_core::{
    BodyPolicy, CodecError, ErrorContext, ErrorDetail, ErrorHeader, ErrorResolution, HandlerError, PreAuthError, ResponseKind,
    resolve,
};
use rustfs_gateway_http::WireReject;
use rustfs_gateway_sig::{AuthError, SignatureMismatchDetail};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ETag, ErrorCode, EtagRender};
use rustfs_gateway_xml::{DECLARATION, XmlWriter};

use crate::{close::ConnectionIntent, ext::Denial, trace::RequestTrace};

/// Optional refusal headers, details, and redacted signature diagnostics behind one pointer.
#[derive(Clone, Default)]
struct Extras {
    headers: Vec<ErrorHeader>,
    details: Vec<ErrorDetail>,
    signature: Option<SignatureDetails>,
}

#[derive(Clone)]
struct SignatureDetails {
    canonical_request: String,
    string_to_sign: String,
}

/// A refusal, in the shape the renderer needs.
#[derive(Clone)]
pub struct S3Error {
    code: Option<ErrorCode>,
    status: StatusCode,
    body_policy: BodyPolicy,
    pub(crate) message: Option<std::borrow::Cow<'static, str>>,
    resource: Option<Box<str>>,
    etag: Option<ETag>,
    connection: ConnectionIntent,
    pub(crate) body_unfinished: Option<crate::wire_read::RequestBodyUnfinished>,
    pub(crate) answered_by_handler: bool,
    extras: Option<Box<Extras>>,
}

impl core::fmt::Debug for S3Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Error")
            .field("code", &self.code)
            .field("status", &self.status)
            .field("message", &self.message)
            .field("body_policy", &self.body_policy)
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl PartialEq for S3Error {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.status == other.status
            && self.message == other.message
            && self.resource == other.resource
            && self.etag == other.etag
            && self.body_policy == other.body_policy
            && self.connection == other.connection
            && self.body_unfinished == other.body_unfinished
            && self.headers() == other.headers()
            && self.details() == other.details()
            && signature_details_eq(self.extras.as_deref(), other.extras.as_deref())
    }
}

impl Eq for S3Error {}

fn signature_details_eq(left: Option<&Extras>, right: Option<&Extras>) -> bool {
    match (
        left.and_then(|extras| extras.signature.as_ref()),
        right.and_then(|extras| extras.signature.as_ref()),
    ) {
        (Some(left), Some(right)) => {
            left.canonical_request == right.canonical_request && left.string_to_sign == right.string_to_sign
        }
        (None, None) => true,
        _ => false,
    }
}

const NO_HEADERS: &[ErrorHeader] = &[];
const NO_DETAILS: &[ErrorDetail] = &[];

impl S3Error {
    /// What this refusal does to the connection; [`render`] carries it to the transport.
    #[must_use]
    pub const fn connection_intent(&self) -> ConnectionIntent {
        self.connection
    }

    /// Whether the connection must end after this refusal.
    #[must_use]
    pub const fn must_close_connection(&self) -> bool {
        self.connection.must_close()
    }

    /// The S3 error code.
    #[must_use]
    pub const fn code(&self) -> Option<&ErrorCode> {
        self.code.as_ref()
    }

    /// The status this refusal goes out with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The headers the refusing stage attached, before the reserved ones are filtered out.
    ///
    /// Only a `HandlerError` populates these today.
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

impl From<ErrorResolution> for S3Error {
    fn from(resolution: ErrorResolution) -> Self {
        let extras = if resolution.headers().is_empty() && resolution.details().is_empty() {
            None
        } else {
            Some(Box::new(Extras {
                headers: resolution.headers().to_vec(),
                details: resolution.details().to_vec(),
                signature: None,
            }))
        };
        Self {
            code: resolution.code().cloned(),
            status: resolution.status(),
            body_policy: resolution.body_policy(),
            message: resolution
                .message()
                .map(|message| std::borrow::Cow::Owned(message.to_owned())),
            resource: resolution.resource().map(Box::from),
            etag: resolution.etag().cloned(),
            connection: crate::close::after_refusal_code(resolution.code()),
            body_unfinished: None,
            answered_by_handler: false,
            extras,
        }
    }
}

pub(crate) fn from_wire_reject(reject: WireReject) -> S3Error {
    // The reject owns the status because one code can represent several wire failures.
    typed_refusal(
        reject.error_code(),
        reject.message(),
        reject.to_status(),
        crate::close::after_wire_reject(&reject),
    )
}

pub(crate) fn from_chunk_reject(reject: rustfs_gateway_http::ChunkReject) -> S3Error {
    // `ChunkReject` carries no client-facing sentence of its own — it is an operator's label —
    // so the message is the one this crate writes for the code, and the label stays in the log.
    let message: &'static str = match reject.error_code() {
        code if code == ErrorCode::SIGNATURE_DOES_NOT_MATCH => "the request was not authenticated",
        code if code == ErrorCode::INCOMPLETE_BODY => {
            "You did not provide the number of bytes specified by the Content-Length HTTP header."
        }
        code if code == ErrorCode::INVALID_CHUNK_SIZE => "The chunk size of the request body is not one this service accepts.",
        _ => "The chunked encoding of the request body is not one this service can read.",
    };
    typed_refusal(
        reject.error_code(),
        message,
        reject.to_status(),
        crate::close::after_chunk_reject(&reject),
    )
}

pub(crate) fn from_pre_auth(error: PreAuthError, response: ResponseKind) -> S3Error {
    from_handler(
        HandlerError::new(error.code().clone(), error.message()),
        response,
        ConnectionIntent::MayKeepAlive,
    )
}

pub(crate) fn from_auth(error: AuthError, response: ResponseKind, body_owed: bool) -> S3Error {
    // A comparison failure keeps its own code, as S3 answers it and SDKs branch on it (rd-loc-0002);
    // message, status, headers and the work done stay one for both (docs/security-model.md).
    // Authentication has its own connection policy; it is neither wire nor chunk rejection. Every
    // `AuthError::code()` spelling has a row in the error status authority —
    // `check_error_status_total.sh` reads the arms — so `known` cannot miss.
    let (code, message) = if error == AuthError::AuthorizationHeaderMalformed {
        (ErrorCode::ACCESS_DENIED, "the request was not authenticated")
    } else {
        (ErrorCode::known(error.code()).unwrap_or(ErrorCode::ACCESS_DENIED), error.message())
    };
    let connection = crate::close::after_auth_failure(&error, body_owed);
    from_handler(HandlerError::new(code, message), response, connection)
}

pub(crate) fn from_auth_with_detail(
    error: AuthError,
    detail: Option<&SignatureMismatchDetail>,
    verbose: bool,
    response: ResponseKind,
    body_owed: bool,
) -> S3Error {
    let Some((canonical_request, string_to_sign)) = detail.as_ref().and_then(|detail| detail.for_response(verbose)) else {
        return from_auth(error, response, body_owed);
    };
    if error != AuthError::SignatureDoesNotMatch {
        return from_auth(error, response, body_owed);
    }
    let mut rendered = from_handler(
        HandlerError::new(ErrorCode::SIGNATURE_DOES_NOT_MATCH, error.message()),
        response,
        crate::close::after_auth_failure(&error, body_owed),
    );
    rendered.extras = Some(Box::new(Extras {
        headers: Vec::new(),
        details: Vec::new(),
        signature: Some(SignatureDetails {
            canonical_request: redact_sensitive_canonical_values(canonical_request),
            string_to_sign: string_to_sign.to_owned(),
        }),
    }));
    rendered
}

fn redact_sensitive_canonical_values(canonical_request: &str) -> String {
    canonical_request
        .lines()
        .enumerate()
        .map(|(line_number, line)| {
            if line_number == 2 {
                return line
                    .split('&')
                    .map(|parameter| match parameter.split_once('=') {
                        Some((name, _))
                            if matches!(
                                name.to_ascii_lowercase().as_str(),
                                "x-amz-credential" | "x-amz-security-token" | "x-amz-signature"
                            ) =>
                        {
                            format!("{name}=__REDACTED__")
                        }
                        _ => parameter.to_owned(),
                    })
                    .collect::<Vec<_>>()
                    .join("&");
            }
            let Some((name, _)) = line.split_once(':') else {
                return line.to_owned();
            };
            let sensitive = name == "x-amz-security-token"
                || (name.starts_with("x-amz-server-side-encryption-")
                    && (name.contains("customer-key") || name.ends_with("aws-kms-key-id")))
                || (name.starts_with("x-amz-copy-source-server-side-encryption-") && name.contains("customer-key"));
            if sensitive {
                format!("{name}:__REDACTED__")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn from_auth_context(error: AuthError, context: ErrorContext, response: ResponseKind, body_owed: bool) -> S3Error {
    let mut rendered = from_resolution(resolve(context, response), response);
    rendered.connection = crate::close::after_auth_failure(&error, body_owed);
    rendered
}

pub(crate) fn from_denial(denial: Denial, response: ResponseKind) -> S3Error {
    // One sentence for every denial. A message that named the failing condition would let an
    // authenticated caller map the policy one request at a time.
    //
    // The connection survives: the caller is known, so none of the reasoning that closes on an
    // authentication failure applies. `c-copy-0019` asserts exactly this, and it is the case
    // that stops "every 403 closes" from being written here.
    from_handler(
        HandlerError::new(denial.code().clone(), "the request is not allowed"),
        response,
        crate::close::after_denial(),
    )
}

pub(crate) fn from_sse(rejection: rustfs_gateway_core::SseRejection, response: ResponseKind) -> S3Error {
    // `reason()` is a constant sentence per variant and `code()` is one of two codes. Nothing
    // from the request reaches either, which is the property `crates/core`'s
    // `n_no_refusal_sentence_carries_a_key_a_digest_or_a_key_id` pins: a refusal about a key
    // must not quote the key, the digest, the expected digest, or a KMS key id.
    //
    // The status comes from the shared table rather than being written here, so that
    // `InvalidRequest` means the same thing in a `400` from this stage as it does anywhere
    // else. The connection survives: the caller is authenticated by this point and the
    // request head was fully readable, so none of RFC 9112 §9.3's reasoning applies.
    let code = rejection.code();
    from_handler(HandlerError::new(code, rejection.reason()), response, ConnectionIntent::MayKeepAlive)
}

pub(crate) fn from_codec(error: CodecError, response: ResponseKind) -> S3Error {
    let context = match ErrorContext::codec(error) {
        Ok(context) => context,
        Err(_) => return internal_resolution(response),
    };
    from_resolution(resolve(context, response), response)
}

pub(crate) fn from_handler(error: HandlerError, response: ResponseKind, connection: ConnectionIntent) -> S3Error {
    let context = match ErrorContext::ordinary(error) {
        Ok(context) => context,
        Err(_) => return with_connection(internal_resolution(response), connection),
    };
    with_connection(from_resolution(resolve(context, response), response), connection)
}

pub(crate) fn from_transport_limit(error: HandlerError, status: StatusCode, connection: ConnectionIntent) -> S3Error {
    let mut refusal = from_handler(error, ResponseKind::Other, connection);
    refusal.status = status;
    refusal
}

fn typed_refusal(code: ErrorCode, message: &'static str, status: StatusCode, connection: ConnectionIntent) -> S3Error {
    let mut refusal = from_handler(HandlerError::new(code, message), ResponseKind::Other, connection);
    refusal.status = status;
    refusal
}

fn with_connection(mut refusal: S3Error, connection: ConnectionIntent) -> S3Error {
    refusal.connection = refusal.connection.and(connection);
    refusal
}

fn from_resolution(resolution: ErrorResolution, response: ResponseKind) -> S3Error {
    let mut refusal = S3Error::from(resolution);
    // Core reports that HEAD may not carry the document. The facade still has to materialize that
    // representation long enough to measure its Content-Length; the single response invariant
    // removes only the bytes immediately before the response leaves the service.
    if response == ResponseKind::Head && refusal.body_policy == BodyPolicy::None && refusal.message.is_some() {
        refusal.body_policy = BodyPolicy::ErrorDocument;
    }
    refusal
}

fn internal_resolution(response: ResponseKind) -> S3Error {
    let error = HandlerError::internal_error("the request could not be completed");
    match ErrorContext::ordinary(error) {
        Ok(context) => from_resolution(resolve(context, response), response),
        Err(_) => unreachable_internal_resolution(),
    }
}

fn unreachable_internal_resolution() -> S3Error {
    // This fallback is private and static. It is reachable only if the resolver rejects its own
    // context-free InternalError invariant, in which case returning a bounded 500 is safer than
    // panicking at the service boundary.
    S3Error {
        code: Some(ErrorCode::INTERNAL_ERROR),
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body_policy: BodyPolicy::ErrorDocument,
        message: Some(std::borrow::Cow::Borrowed("the request could not be completed")),
        resource: None,
        etag: None,
        connection: ConnectionIntent::MayKeepAlive,
        body_unfinished: None,
        answered_by_handler: false,
        extras: None,
    }
}

/// The `<Error>` document on its own, with no response head around it.
///
/// Used by the committed path, which already sent its response head.
#[must_use]
pub fn document(error: &S3Error, trace: &RequestTrace) -> String {
    let mut out = String::from(DECLARATION);
    out.push_str(&document_body(error, trace));
    out
}

/// The `<Error>` document with neither a response head **nor an XML declaration** around it.
///
/// The committed path already sent the XML declaration; see `crate::commit`.
#[must_use]
pub fn document_body(error: &S3Error, trace: &RequestTrace) -> String {
    let mut xml = XmlWriter::fragment();
    xml.open("Error", rustfs_gateway_core::error_root_namespace());
    if let Some(code) = &error.code {
        xml.element("Code", code.as_str());
    }
    if let Some(message) = &error.message {
        xml.element("Message", message);
    }
    if let Some(resource) = &error.resource {
        xml.element("Resource", resource);
    }
    for detail in error.details() {
        xml.element(detail.element(), detail.text().as_ref());
    }
    if let Some(signature) = error.extras.as_ref().and_then(|extras| extras.signature.as_ref()) {
        xml.element("CanonicalRequest", &signature.canonical_request);
        xml.element("StringToSign", &signature.string_to_sign);
    }
    xml.element("RequestId", trace.request_id().as_str());
    xml.element("HostId", trace.host_id().as_str());
    xml.close();
    xml.finish()
}

/// Renders a refusal as the `<Error>` document S3 clients parse, with its response head.
///
/// Bodyless statuses omit XML; framework-owned framing and identifiers overwrite refusal headers.
#[must_use]
pub fn render(error: &S3Error, trace: &RequestTrace) -> Response<Body> {
    let body = match error.body_policy {
        BodyPolicy::None => None,
        BodyPolicy::ErrorDocument => Some(document(error, trace)),
    };
    let mut response = Response::new(match body {
        Some(ref body) => Body::from(body.clone().into_bytes()),
        None => Body::empty(),
    });
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
    if let Some(body) = body {
        headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
        if let Ok(value) = http::HeaderValue::from_str(&body.len().to_string()) {
            headers.insert(CONTENT_LENGTH, value);
        }
    }
    if let Some(etag) = &error.etag
        && let Ok(value) = http::HeaderValue::from_str(&etag.render(EtagRender::HeaderQuoted))
    {
        headers.insert(ETAG, value);
    }
    trace.apply(headers);
    // Only the transport turns these typed extensions into socket action.
    response.extensions_mut().insert(error.connection);
    crate::close::attach_lingering_read(error.code.as_ref(), error.body_unfinished, &mut response);
    response
}

/// The connection verdict a rendered refusal is carrying, if it is carrying one.
///
/// A transport consumes this intent; it is not proof that a socket closed.
#[must_use]
pub fn connection_intent_of<B>(response: &Response<B>) -> Option<ConnectionIntent> {
    response.extensions().get::<ConnectionIntent>().copied()
}

/// The XML declaration every rendered document opens with, re-exported for a consumer that
/// compares a body byte for byte.
#[must_use]
pub const fn declaration() -> &'static str {
    DECLARATION
}

#[cfg(test)]
#[path = "render_compat_tests.rs"]
mod compatibility_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn verbose_details_redact_presigned_credentials() {
        let canonical = "GET\n/key\nX-Amz-Credential=AKID%2Fscope&X-Amz-Security-Token=session-secret&prefix=visible\nhost:example.com\n\nhost\nUNSIGNED-PAYLOAD";
        let redacted = redact_sensitive_canonical_values(canonical);
        assert!(redacted.contains("X-Amz-Credential=__REDACTED__"), "{redacted}");
        assert!(redacted.contains("X-Amz-Security-Token=__REDACTED__"), "{redacted}");
        assert!(redacted.contains("prefix=visible"), "{redacted}");
        assert!(!redacted.contains("AKID"), "{redacted}");
        assert!(!redacted.contains("session-secret"), "{redacted}");
    }

    /// The trace the tests below render with; pinned so a body can be read literally.
    fn trace() -> RequestTrace {
        RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0)
    }

    fn handler(error: HandlerError) -> S3Error {
        from_handler(error, ResponseKind::Other, ConnectionIntent::MayKeepAlive)
    }

    fn ordinary(code: ErrorCode, message: &'static str) -> S3Error {
        handler(HandlerError::new(code, message))
    }

    /// Negative — a comparison rejection carries its own code and no request data.
    #[tokio::test]
    async fn a_rendered_refusal_echoes_nothing_from_the_request() {
        let error = from_auth(AuthError::SignatureDoesNotMatch, ResponseKind::Other, true);
        let collected = crate::wire::collect(render(&error, &trace()))
            .await
            .expect("an in-memory body");
        let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
        assert!(body.contains("the request was not authenticated"), "{body}");
        assert!(!body.contains("Authorization"), "{body}");
    }

    /// Negative — a wrong signature and an unknown key differ in their S3 code alone (rd-loc-0002).
    #[test]
    fn the_two_credential_rejections_differ_only_in_their_code() {
        let unknown = from_auth(AuthError::InvalidAccessKeyId, ResponseKind::Other, true);
        let mismatch = from_auth(AuthError::SignatureDoesNotMatch, ResponseKind::Other, true);
        assert_eq!(unknown.code(), Some(&ErrorCode::INVALID_ACCESS_KEY_ID));
        assert_eq!(mismatch.code(), Some(&ErrorCode::SIGNATURE_DOES_NOT_MATCH));
        assert_eq!(unknown.message(), mismatch.message());
        assert_eq!(unknown.status(), mismatch.status());
    }

    /// Negative — malformed authentication cannot enter the contextual region response.
    #[test]
    fn a_malformed_scope_is_a_bad_request() {
        assert_eq!(
            from_auth(AuthError::AuthorizationHeaderMalformed, ResponseKind::Other, true).status(),
            http::StatusCode::FORBIDDEN
        );
    }

    /// Negative — a denial says nothing about which policy condition failed.
    #[test]
    fn a_denial_renders_one_sentence() {
        assert_eq!(
            from_denial(Denial::access_denied(), ResponseKind::Other).message(),
            Some("the request is not allowed")
        );
    }

    /// Negative — a wire rejection keeps the status the wire layer chose.
    #[test]
    fn a_wire_rejection_keeps_its_own_status() {
        let reject = WireReject::MalformedRequestTarget;
        let status = reject.to_status();
        assert_eq!(from_wire_reject(reject).status(), status);
    }

    /// Positive — the document is well-formed and opens with the declaration a client expects.
    #[tokio::test]
    async fn the_document_opens_with_the_xml_declaration() {
        let error = ordinary(ErrorCode::ACCESS_DENIED, "the request is not allowed");
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
        let error = ordinary(ErrorCode::ACCESS_DENIED, "the request is not allowed");
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
        let error = from_codec(
            CodecError::new(ErrorCode::INVALID_ARGUMENT, "invalid member").about("Bucket"),
            ResponseKind::Other,
        );
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
        let error = handler(HandlerError::unsatisfiable_range("bytes=20-30", 10));
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
        let error = handler(HandlerError::precondition_failed("If-None-Match"));
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
        let cases = [
            (
                from_codec(
                    CodecError::new(ErrorCode::INVALID_ARGUMENT, "invalid member").about("Bucket"),
                    ResponseKind::Other,
                ),
                vec!["Code", "Message", "Resource", "RequestId", "HostId"],
            ),
            (
                handler(HandlerError::unsatisfiable_range("bytes=0-1", 10)),
                vec!["Code", "Message", "RangeRequested", "ActualObjectSize", "RequestId", "HostId"],
            ),
        ];
        for (error, order) in cases {
            let body = document(&error, &trace());
            let mut cursor = 0;
            for element in order {
                let at = body
                    .find(&format!("<{element}>"))
                    .unwrap_or_else(|| panic!("{element} in {body}"));
                assert!(at >= cursor, "{element} is out of order in {body}");
                cursor = at;
            }
        }
    }

    /// Negative — escaped detail text cannot close its own element.
    #[tokio::test]
    async fn an_extra_element_cannot_break_out_of_its_own_element() {
        let error = handler(
            HandlerError::new(ErrorCode::INVALID_OBJECT_STATE, "not readable")
                .with_detail(ErrorDetail::Key(std::borrow::Cow::Borrowed("</Key><Code>AccessDenied</Code><Key>"))),
        );
        let body = document(&error, &trace());
        assert_eq!(body.matches("<Code>").count(), 1, "{body}");
        assert!(body.contains("&lt;/Key&gt;"), "{body}");
    }

    /// Negative — no extras preserves the original document exactly.
    #[tokio::test]
    async fn a_refusal_with_no_extras_renders_the_document_it_always_did() {
        let error = ordinary(ErrorCode::ACCESS_DENIED, "the request is not allowed");
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

    /// Negative — refusal headers cannot disturb framework framing or identifiers.
    #[tokio::test]
    async fn a_header_of_the_refusals_own_does_not_disturb_what_the_framework_writes() {
        let plain = render(&handler(HandlerError::new(ErrorCode::SERVICE_UNAVAILABLE, "unavailable")), &trace());
        let expected_length = plain.headers().get(CONTENT_LENGTH).cloned();

        let carrying = handler(
            HandlerError::new(ErrorCode::SERVICE_UNAVAILABLE, "unavailable").with_header(ErrorHeader::RetryAfter { seconds: 5 }),
        );
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

    /// Negative — framework-owned header names never survive refusal rendering.
    #[tokio::test]
    async fn a_reserved_name_would_be_dropped_and_the_framework_writes_last() {
        let error = handler(HandlerError::unsatisfiable_range("bytes=20-30", 10));
        let response = render(&error, &trace());
        for name in response.headers().keys() {
            let written_by_the_error = error.headers().iter().any(|header| header.name() == *name);
            assert!(
                !written_by_the_error || !crate::stamp::is_reserved(name),
                "{name} was written by the refusal and is reserved"
            );
        }
        assert_eq!(response.headers().get_all(CONTENT_TYPE).iter().count(), 1);
    }

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

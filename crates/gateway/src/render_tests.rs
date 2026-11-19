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

//! Unit tests for the gateway's response rendering and redaction.
//! The rendering implementation and compatibility tests are in the parent module.

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
        from_denial(Denial::access_denied(), ResponseKind::Other, DenialSentences::Gateway).message(),
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

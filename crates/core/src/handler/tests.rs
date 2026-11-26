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

//! Unit tests for handler wrappers (`Req`, `Resp`, `HandlerError`).
//!
//! Responsible for: response answer shapes, error header/detail ordering and deduplication, and
//! proving that [`Req`]'s `Debug` never leaks raw request-body bytes or unredacted third-party
//! inputs while preserving operation names, safe context facts, and redacted standard DTO fields.
//! NOT responsible for: wire codecs, registry erasure, or end-to-end HTTP dispatch.
//! Upstream: `super`. Downstream: none (unit tests).

use std::borrow::Cow;
use std::fmt;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{Admission, OperationFloor, RawQuery, RequestNow, SecurityFloor, SigService, Verdict, WireView};
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::dto::{
    CopyObject, CopyObjectInput, GetObject, GetObjectInput, PostObject, PostObjectFields, PostObjectInput, PutObject,
    PutObjectInput, SelectObjectContent,
};
use rustfs_gateway_types::{BucketName, CopySourceValue, ObjectKey, SseCustomerKey};

use super::*;
use crate::authz::{Decision, authorize_input, prepare_input};
use crate::codec::MetaView;
use crate::op::{AuthRequirement, ResourceShape};
use crate::registry::OperationSpec;
use crate::request_context::{Addressed, AddressingStyle, RequestContextView};
use crate::route::TargetKind;
use crate::sse::{SseConfig, SseEnforced, TransportSecurity, enforce};

fn sse_proof() -> SseEnforced {
    let request = http::Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("valid proof fixture");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted proof fixture");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("service proof fixture");
    enforce(&meta, TransportSecurity::Encrypted, &SseConfig::strict()).expect("an empty encrypted request passes SSE enforcement")
}

fn both_renderings(value: &impl fmt::Debug) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

fn pipeline_context(operation: &'static str, target: &str, headers: &[(&str, &[u8])]) -> RequestContextView {
    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri(target)
        .header("host", "sts.example.com");
    for (name, value) in headers {
        builder = builder.header(*name, http::HeaderValue::from_bytes(value).expect("fixture header value"));
    }
    let request = builder.body(Bytes::new()).expect("fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted fixture");
    let mut header_map = HeaderMap::new();
    for (name, value) in wire.headers().iter_raw() {
        header_map.append(name.clone(), value.clone());
    }
    let floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    let view = WireView::new(&header_map, RawQuery::new(wire.query().as_str()));
    let verdict = match floor.admit(
        view,
        &OperationFloor::custom(operation, SigService::Sts).allow_anonymous_after_listing_in_the_posture_report(),
        RequestNow::from_unix_seconds(0),
    ) {
        Ok(Admission::Anonymous(evidence)) => Verdict::anonymous(evidence),
        _ => panic!("the fixture presents no credentials"),
    };
    let addressed = Addressed {
        style: AddressingStyle::Path,
        bucket: None,
        key: None,
    };
    RequestContextView::from_pipeline(operation, &wire, addressed, &verdict, None).expect("an anonymous request builds a context")
}

struct StsFormLike;

static STS_FORM_SPEC: OperationSpec = OperationSpec::builder("rustfs:StsFormPost", 200, None)
    .auth(AuthRequirement::new("rustfs:AssumeRole", ResourceShape::Service))
    .build();

static STS_FORM_FLOOR: OperationFloor =
    OperationFloor::custom("rustfs:StsFormPost", SigService::Sts).allow_anonymous_after_listing_in_the_posture_report();

impl Operation for StsFormLike {
    const NAME: &'static str = "rustfs:StsFormPost";
    type Input = Bytes;
    type Output = ();
    type DerivedResources = crate::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::DerivedResourceError> {
        Ok(crate::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &STS_FORM_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &STS_FORM_FLOOR
    }
}

struct StreamInputLike;

static STREAM_INPUT_SPEC: OperationSpec = OperationSpec::builder("rustfs:PostV3AccountPassword", 200, None)
    .auth(AuthRequirement::new("rustfs:SetAccountPassword", ResourceShape::Service))
    .build();

static STREAM_INPUT_FLOOR: OperationFloor = OperationFloor::custom("rustfs:PostV3AccountPassword", SigService::S3);

impl Operation for StreamInputLike {
    const NAME: &'static str = "rustfs:PostV3AccountPassword";
    type Input = ByteStream;
    type Output = ();
    type DerivedResources = crate::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::DerivedResourceError> {
        Ok(crate::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &STREAM_INPUT_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &STREAM_INPUT_FLOOR
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Fields exist specifically to verify derived `Debug` cannot leak through `Req`.
struct CustomSecretInput {
    token: &'static str,
    raw: Bytes,
}

struct CustomSecretLike;

static CUSTOM_SECRET_SPEC: OperationSpec = OperationSpec::builder("vendor:RotateCredentials", 200, None)
    .auth(AuthRequirement::new("vendor:RotateCredentials", ResourceShape::Service))
    .build();

static CUSTOM_SECRET_FLOOR: OperationFloor = OperationFloor::custom("vendor:RotateCredentials", SigService::S3);

impl Operation for CustomSecretLike {
    const NAME: &'static str = "vendor:RotateCredentials";
    type Input = CustomSecretInput;
    type Output = ();
    type DerivedResources = crate::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::DerivedResourceError> {
        Ok(crate::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &CUSTOM_SECRET_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &CUSTOM_SECRET_FLOOR
    }
}

// ── Req::Debug redaction tests (#1602) ────────────────────────────────────────────────────────

/// Negative — formatting a `Req` for a `Bytes`-input operation never prints the body bytes in
/// either compact or alternate `Debug`, keeping web-identity tokens and MFA codes out of logs.
#[test]
fn req_debug_does_not_print_bytes_input_body_in_either_format() {
    let body = Bytes::from_static(b"Action=AssumeRoleWithWebIdentity&WebIdentityToken=JWT_SECRET_MARKER_1602&TokenCode=774411");
    let request = Req::<StsFormLike>::new(body, sse_proof());
    for rendered in both_renderings(&request) {
        assert!(!rendered.contains("JWT_SECRET_MARKER_1602"), "body token leaked: {rendered}");
        assert!(!rendered.contains("774411"), "body MFA code leaked: {rendered}");
        assert!(!rendered.contains("WebIdentityToken"), "raw form body leaked: {rendered}");
        assert!(rendered.contains("input: \"<redacted>\""), "redacted placeholder missing: {rendered}");
    }
    let compact = format!("{request:?}");
    assert!(
        compact.starts_with("Req { operation: \"rustfs:StsFormPost\", "),
        "Req operation name missing: {compact}"
    );
}

/// Negative — formatting a `Req` for a third-party `ByteStream`-input operation never prints the
/// stream bytes and still routes through `Req`'s fail-closed redaction rather than delegating to
/// the third-party input's own `Debug`.
#[test]
fn req_debug_does_not_print_third_party_stream_input_or_bypass_redaction() {
    let stream = ByteStream::from_bytes(Bytes::from_static(b"PASSWORD_STREAM_MARKER_1602"));
    let request = Req::<StreamInputLike>::new(stream, sse_proof());
    for rendered in both_renderings(&request) {
        assert!(!rendered.contains("PASSWORD_STREAM_MARKER_1602"), "stream body leaked: {rendered}");
        assert!(
            rendered.contains("input: \"<redacted>\""),
            "third-party stream input must be redacted by Req: {rendered}"
        );
        assert!(
            !rendered.contains("ByteStream"),
            "third-party stream input bypassed Req redaction: {rendered}"
        );
    }
    let compact = format!("{request:?}");
    assert!(
        compact.starts_with("Req { operation: \"rustfs:PostV3AccountPassword\", "),
        "Req operation name missing: {compact}"
    );
}

/// Negative — a third-party operation with an unredacted custom struct input never prints its
/// fields through `Req`'s `Debug`, proving redaction is fail-closed rather than a `Bytes`-only
/// denylist.
#[test]
fn req_debug_does_not_print_third_party_structured_input_fields() {
    let input = CustomSecretInput {
        token: "ROTATE_TOKEN_MARKER_1602",
        raw: Bytes::from_static(b"RAW_CREDENTIAL_BODY_1602"),
    };
    let request = Req::<CustomSecretLike>::new(input, sse_proof());
    for rendered in both_renderings(&request) {
        assert!(!rendered.contains("ROTATE_TOKEN_MARKER_1602"), "token leaked: {rendered}");
        assert!(!rendered.contains("RAW_CREDENTIAL_BODY_1602"), "raw bytes leaked: {rendered}");
        assert!(rendered.contains("input: \"<redacted>\""), "redacted placeholder missing: {rendered}");
    }
    let compact = format!("{request:?}");
    assert!(
        compact.starts_with("Req { operation: \"vendor:RotateCredentials\", "),
        "Req operation name missing: {compact}"
    );
}

/// Negative — a standard `PutObject` request carrying both a streaming body and an SSE-C key
/// never prints either secret or the body bytes, while preserving the redacted key marker, the
/// stream's declared length, and safe routing fields.
#[test]
fn req_debug_redacts_ssec_key_and_never_prints_stream_body_for_standard_put_object() {
    let body_bytes = b"PUT_OBJECT_BODY_MARKER_1602";
    let input = PutObjectInput {
        bucket: BucketName::new("debug-bucket").expect("valid bucket"),
        key: ObjectKey::new("docs/readme.txt").expect("valid key"),
        body: Some(ByteStream::from_bytes(Bytes::from_static(body_bytes))),
        sse_customer_key: Some(SseCustomerKey::new("SSEC_KEY_SECRET_MARKER_1602".to_owned())),
        ..Default::default()
    };
    let request = Req::<PutObject>::new(input, sse_proof());
    for rendered in both_renderings(&request) {
        assert!(!rendered.contains("PUT_OBJECT_BODY_MARKER_1602"), "stream bytes leaked: {rendered}");
        assert!(!rendered.contains("SSEC_KEY_SECRET_MARKER_1602"), "SSE-C key leaked: {rendered}");
        assert!(rendered.contains("debug-bucket"), "safe bucket field missing: {rendered}");
        assert!(rendered.contains("docs/readme.txt"), "safe key field missing: {rendered}");
    }
    let compact = format!("{request:?}");
    assert!(
        compact.starts_with("Req { operation: \"PutObject\", "),
        "Req operation name missing: {compact}"
    );
    assert!(
        compact.contains("sse_customer_key: Some(\"<redacted>\")"),
        "SSE-C key must remain visibly redacted: {compact}"
    );
    assert!(
        compact.contains(&format!("declared: Some({})", body_bytes.len())),
        "stream declared length must remain visible: {compact}"
    );
}

/// Negative — a standard `CopyObject` request with both destination and copy-source SSE-C keys
/// keeps both keys redacted, and a standard `PostObject` request keeps its form SSE-C key
/// redacted and its `ByteStream` body bytes absent.
#[test]
fn req_debug_redacts_copy_source_and_post_object_ssec_keys() {
    let mut copy_input = CopyObjectInput::builder(CopySourceValue::Bucket {
        bucket: "src-bucket".to_owned(),
        key: "src-key".to_owned(),
        version_id: None,
    })
    .build();
    copy_input.bucket = BucketName::new("dst-bucket").expect("valid bucket");
    copy_input.key = ObjectKey::new("dst-key").expect("valid key");
    copy_input.sse_customer_key = Some(SseCustomerKey::new("DEST_SSEC_SECRET_1602".to_owned()));
    copy_input.copy_source_sse_customer_key = Some(SseCustomerKey::new("SRC_SSEC_SECRET_1602".to_owned()));
    let decoded = prepare_input::<CopyObject>(copy_input).expect("valid copy input");
    let authorized = authorize_input(decoded, |_| Decision::Allow).expect("copy source allowed");
    let copy_request = authorized.into_request(sse_proof(), RequestContextView::detached(CopyObject::NAME));

    for rendered in both_renderings(&copy_request) {
        assert!(!rendered.contains("DEST_SSEC_SECRET_1602"), "destination SSE-C key leaked: {rendered}");
        assert!(!rendered.contains("SRC_SSEC_SECRET_1602"), "copy-source SSE-C key leaked: {rendered}");
    }
    let copy_compact = format!("{copy_request:?}");
    assert!(
        copy_compact.starts_with("Req { operation: \"CopyObject\", "),
        "Req operation name missing: {copy_compact}"
    );
    assert!(
        copy_compact.contains("sse_customer_key: Some(\"<redacted>\")"),
        "destination SSE-C key must print redacted: {copy_compact}"
    );
    assert!(
        copy_compact.contains("copy_source_sse_customer_key: Some(\"<redacted>\")"),
        "copy-source SSE-C key must print redacted: {copy_compact}"
    );

    let post_body = b"POST_OBJECT_STREAM_MARKER_1602";
    let post_input = PostObjectInput {
        bucket: BucketName::new("upload-bucket").expect("valid bucket"),
        key: ObjectKey::new("uploads/photo.bin").expect("valid key"),
        body: ByteStream::from_bytes(Bytes::from_static(post_body)),
        content_length: Some(post_body.len() as u64),
        content_type: Some("application/octet-stream".to_owned()),
        metadata: Vec::new(),
        fields: PostObjectFields {
            sse_customer_key: Some(SseCustomerKey::new("POST_SSEC_SECRET_1602".to_owned())),
            ..PostObjectFields::default()
        },
    };
    let post_request = Req::<PostObject>::new(post_input, sse_proof());
    for rendered in both_renderings(&post_request) {
        assert!(!rendered.contains("POST_OBJECT_STREAM_MARKER_1602"), "post stream leaked: {rendered}");
        assert!(!rendered.contains("POST_SSEC_SECRET_1602"), "post SSE-C key leaked: {rendered}");
    }
    let post_compact = format!("{post_request:?}");
    assert!(
        post_compact.starts_with("Req { operation: \"PostObject\", "),
        "Req operation name missing: {post_compact}"
    );
    assert!(
        post_compact.contains("sse_customer_key: Some(\"<redacted>\")"),
        "PostObject SSE-C key must print redacted: {post_compact}"
    );
    assert!(
        post_compact.contains(&format!("declared: Some({})", post_body.len())),
        "PostObject stream declared length must remain visible: {post_compact}"
    );
}

/// Negative — a `Bytes`-input request built with a real pipeline context prints safe routing
/// facts while keeping the body, query value, and header values out of `Debug`.
#[test]
fn req_debug_redacts_context_secrets_and_headers_beside_bytes_input() {
    let context = pipeline_context(
        StsFormLike::NAME,
        "/?WebIdentityToken=QUERY_SECRET_1602",
        &[("x-amz-server-side-encryption-customer-key", b"HEADER_SECRET_1602")],
    );
    let decoded = prepare_input::<StsFormLike>(Bytes::from_static(b"WebIdentityToken=BODY_SECRET_1602"))
        .expect("sts input requires no derived resources");
    let authorized = authorize_input(decoded, |_| Decision::Allow).expect("no derived resources");
    let request = authorized.into_request(sse_proof(), context);

    for rendered in both_renderings(&request) {
        assert!(!rendered.contains("BODY_SECRET_1602"), "body secret leaked: {rendered}");
        assert!(!rendered.contains("QUERY_SECRET_1602"), "query secret leaked: {rendered}");
        assert!(!rendered.contains("HEADER_SECRET_1602"), "header secret leaked: {rendered}");
        assert!(rendered.contains("input: \"<redacted>\""), "redacted input missing: {rendered}");
        assert!(rendered.contains("host: \"sts.example.com\""), "safe host missing: {rendered}");
        assert!(
            rendered.contains("x-amz-server-side-encryption-customer-key"),
            "header name missing: {rendered}"
        );
    }
    let compact = format!("{request:?}");
    assert!(
        compact.starts_with("Req { operation: \"rustfs:StsFormPost\", "),
        "Req operation name missing: {compact}"
    );
}

/// Positive — `Debug` on a `Bytes`-input request still prints the struct name, operation name,
/// redacted input placeholder, and safe context without widening the printed fields.
#[test]
fn req_debug_prints_operation_name_and_safe_context_for_bytes_input() {
    let request = Req::<StsFormLike>::new(Bytes::from_static(b"opaque-body"), sse_proof());
    let compact = format!("{request:?}");
    assert!(
        compact.starts_with("Req { operation: \"rustfs:StsFormPost\", input: \"<redacted>\", context: RequestContextView {"),
        "{compact}"
    );
    assert!(!compact.contains("resources:"), "Req::Debug must not widen to resources: {compact}");
    assert!(!compact.contains("read:"), "Req::Debug must not widen to read proof: {compact}");
    assert!(!compact.contains("sse:"), "Req::Debug must not widen to sse proof: {compact}");
}

/// Positive — `Debug` on a standard S3 operation preserves safe typed input fields and keeps an
/// absent SSE-C key distinguishable as `None`.
#[test]
fn req_debug_preserves_safe_typed_fields_for_standard_operation() {
    let input = GetObjectInput {
        bucket: BucketName::new("archive-bucket").expect("valid bucket"),
        key: ObjectKey::new("reports/2026.csv").expect("valid key"),
        part_number: Some(2),
        ..Default::default()
    };
    let request = Req::<GetObject>::new(input, sse_proof());
    let compact = format!("{request:?}");
    assert!(compact.starts_with("Req { operation: \"GetObject\", input: Input {"), "{compact}");
    assert!(compact.contains("archive-bucket"), "{compact}");
    assert!(compact.contains("reports/2026.csv"), "{compact}");
    assert!(compact.contains("part_number: Some(2)"), "{compact}");
    assert!(compact.contains("sse_customer_key: None"), "{compact}");
    assert!(compact.contains("context: RequestContextView {"), "{compact}");
}

// ── Existing Resp / HandlerError tests ────────────────────────────────────────────────────────

/// Positive — an event stream carries the operation's declared success status and no typed
/// output. Treating the stream as a settled empty output is the defect this response shape
/// exists to make impossible.
#[test]
fn an_event_stream_is_a_third_answer_shape() {
    let response = Resp::<SelectObjectContent>::event_stream(ByteStream::from_bytes(Bytes::from_static(b"frame")));
    assert_eq!(response.status(), 200);
    assert!(response.is_event_stream());
    assert!(!response.is_committed());
    assert!(response.output().is_none());
    assert!(response.into_output().is_none());
}

/// Negative — erasing an event stream must not turn it into a settled output. The facade's
/// dispatch matches this exact variant to bypass the generated document encoder.
#[test]
fn an_event_stream_survives_into_parts() {
    let response = Resp::<SelectObjectContent>::event_stream(ByteStream::from_bytes(Bytes::from_static(b"frame")));
    let (answer, status, _extra) = response.into_parts();
    assert_eq!(status, 200);
    assert!(matches!(answer, Answer::EventStream(_)));
}

/// Negative — a plain error carries no headers and no elements, so nothing this file added can
/// change the shape of a document that did not ask for it.
#[test]
fn a_plain_error_adds_nothing_to_the_document_or_the_head() {
    let error = HandlerError::internal_error("no");
    assert!(error.headers().is_empty());
    assert!(error.details().is_empty());
}

/// Negative — adding the same header twice leaves one, so a response cannot carry two
/// `Content-Range` values for an intermediary to choose between.
#[test]
fn a_repeated_header_replaces_rather_than_appends() {
    let error = HandlerError::internal_error("no")
        .with_header(ErrorHeader::UnsatisfiedRange { complete_length: 1 })
        .with_header(ErrorHeader::UnsatisfiedRange { complete_length: 2 });
    assert_eq!(error.headers(), [ErrorHeader::UnsatisfiedRange { complete_length: 2 }]);
}

/// Negative — the same for elements: a document with two `<Condition>` elements names two
/// conditions, and only one of them failed.
#[test]
fn a_repeated_element_replaces_rather_than_appends() {
    let error = HandlerError::internal_error("no")
        .with_detail(ErrorDetail::Condition(Cow::Borrowed("If-Match")))
        .with_detail(ErrorDetail::Condition(Cow::Borrowed("If-None-Match")));
    assert_eq!(error.details().len(), 1);
    assert_eq!(error.details()[0].text(), "If-None-Match");
}

/// Negative — the elements come out in the declared order whatever order they went in. This is
/// the assertion behind "a handler cannot get the document order wrong".
#[test]
fn elements_are_written_in_the_declared_order_not_the_order_they_were_added() {
    let error = HandlerError::internal_error("no")
        .with_detail(ErrorDetail::ActualObjectSize(10))
        .with_detail(ErrorDetail::Condition(Cow::Borrowed("If-Match")))
        .with_detail(ErrorDetail::RangeRequested(Cow::Borrowed("bytes=20-30")))
        .with_detail(ErrorDetail::Key(Cow::Borrowed("k")));
    let names: Vec<&str> = error.details().iter().map(ErrorDetail::element).collect();
    assert_eq!(names, ["Key", "Condition", "RangeRequested", "ActualObjectSize"]);
}

/// Negative — the two facts a `416` states about the object's length come from one argument, so
/// the header and the document cannot disagree. A client that trusted one and retried against
/// the other would loop.
#[test]
fn the_range_refusal_states_one_length_in_both_places() {
    let error = HandlerError::unsatisfiable_range("bytes=20-30", 10);
    assert_eq!(error.code().default_status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(error.headers(), [ErrorHeader::UnsatisfiedRange { complete_length: 10 }]);
    assert_eq!(error.headers()[0].value(), "bytes */10");
    let sizes: Vec<String> = error
        .details()
        .iter()
        .filter(|detail| detail.element() == "ActualObjectSize")
        .map(|detail| detail.text().into_owned())
        .collect();
    assert_eq!(sizes, ["10"]);
}

/// Negative — a zero-length object is still a length, not an absent one: `bytes */0` is what
/// tells a client that no range of it is satisfiable.
#[test]
fn a_zero_length_object_still_states_its_length() {
    let error = HandlerError::unsatisfiable_range("bytes=0-0", 0);
    assert_eq!(error.headers()[0].value(), "bytes */0");
    assert_eq!(error.details().last().expect("a size").text(), "0");
}

/// Positive — the range refusal's message and element order are the ones the wire pins.
#[test]
fn the_range_refusal_carries_the_pinned_message_and_order() {
    let error = HandlerError::unsatisfiable_range("bytes=20-30", 10);
    assert_eq!(error.message(), RANGE_NOT_SATISFIABLE_MESSAGE);
    let names: Vec<&str> = error.details().iter().map(ErrorDetail::element).collect();
    assert_eq!(names, ["RangeRequested", "ActualObjectSize"]);
}

/// Positive — the precondition refusal names the header that failed and adds no header of its
/// own; a `412` has nothing to put in its head.
#[test]
fn the_precondition_refusal_names_the_header_that_failed() {
    let error = HandlerError::precondition_failed("If-None-Match");
    assert_eq!(error.code().default_status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(error.message(), PRECONDITION_FAILED_MESSAGE);
    assert!(error.headers().is_empty());
    assert_eq!(error.details()[0].element(), "Condition");
    assert_eq!(error.details()[0].text(), "If-None-Match");
}

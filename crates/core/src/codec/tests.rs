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

//! What the generated codecs of the object family actually do to bytes.
//!
//! Responsible for: the wire-observable behaviour of `decode` and `encode` — a status, a header
//! that is present or absent, a whole body — for the five object-family operations plus the two
//! that came before them.
//! NOT responsible for: the shape of the generated source, which is allowed to change while the
//! wire is not, and for anything below the codec (acceptance, routing, signing) which has its own
//! suite.
//! Upstream: `crate::codec` and the generated `crate::codec::ops`. Downstream: nothing; this is a
//! leaf.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;
use rustfs_gateway_types::{ETag, ObjectKey, Timestamp};

use crate::codec::response::ResponseBody;
use crate::codec::{MetaView, OperationCodec, RequestBody};
use crate::route::TargetKind;

/// An accepted request, owned so a `MetaView` can borrow it.
fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn body_text(response: &ResponseBody) -> String {
    match response {
        ResponseBody::Complete(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("this response carries a stream, not a document"),
    }
}

fn header(response: &crate::codec::EncodedResponse, name: &str) -> Option<String> {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------------------------

#[test]
fn decodes_the_object_path_into_its_two_labels() {
    let request = accepted("GET", "/photos/2026/summer%2Fbeach.jpg", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("decodes");

    assert_eq!(input.bucket.as_str(), "photos");
    // The key is decoded exactly once: the escaped slash stays a character of the key and does
    // not become another path segment.
    assert_eq!(input.key.as_str(), "2026/summer/beach.jpg");
}

#[test]
fn decodes_the_conditional_and_range_headers_it_binds() {
    let request = accepted("GET", "/photos/key", &[("if-none-match", "\"abc\""), ("range", "bytes=0-99")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("decodes");

    assert_eq!(
        input.if_none_match.as_deref(),
        Some("\"abc\""),
        "the conditional header is bound as the model spells it: an opaque string"
    );
    assert!(input.range.is_some(), "one well-formed range is honoured");
}

#[test]
fn n_ignores_a_range_header_it_cannot_honour() {
    let request = accepted("GET", "/photos/key", &[("range", "items=0-1")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("an unusable range is not a refusal");

    assert!(input.range.is_none(), "RFC 9110 requires an unparseable Range to be ignored");
}

#[test]
fn n_refuses_a_put_with_no_content_length_using_the_code_the_overlay_names() {
    let request = accepted("PUT", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let error = dto::PutObject::decode(&view, RequestBody::None).expect_err("Content-Length is required");

    assert_eq!(error.code().as_str(), "MissingContentLength");
    assert_eq!(error.status(), StatusCode::LENGTH_REQUIRED, "a 411, not the generic 400");
    assert_eq!(error.member(), Some("ContentLength"));
}

#[test]
fn n_refuses_a_request_carrying_two_different_checksum_algorithms() {
    let request = accepted(
        "PUT",
        "/photos/key",
        &[
            ("content-length", "0"),
            ("x-amz-checksum-crc32", "AAAAAA=="),
            ("x-amz-checksum-sha1", "2jmj7l5rSw0yVb/vlWAYkK/YBwk="),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let error = dto::PutObject::decode(&view, RequestBody::None).expect_err("two algorithms is a contradiction");

    assert_eq!(error.code().as_str(), "InvalidRequest");
}

// ---------------------------------------------------------------------------------------------
// Bounded scalars and the required integrity check
//
// Both are protocol refusals the wire contract states and the Smithy model does not, so both are
// asserted here rather than in a handler: a value outside its range and a body with no integrity
// claim must be refused before any operation logic sees them.
// ---------------------------------------------------------------------------------------------

#[test]
fn n_refuses_a_part_number_above_the_ceiling() {
    let request = accepted("PUT", "/photos/key?partNumber=10001&uploadId=u1", &[("content-length", "0")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let error = dto::UploadPart::decode(&view, RequestBody::None).expect_err("ten thousand is the ceiling");

    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.member(), Some("PartNumber"));
}

#[test]
fn n_refuses_a_part_number_below_the_floor() {
    let request = accepted("PUT", "/photos/key?partNumber=0&uploadId=u1", &[("content-length", "0")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let error = dto::UploadPart::decode(&view, RequestBody::None).expect_err("part numbers start at one");

    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.member(), Some("PartNumber"));
}

#[test]
fn accepts_the_part_number_at_the_ceiling() {
    let request = accepted("PUT", "/photos/key?partNumber=10000&uploadId=u1", &[("content-length", "0")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::UploadPart::decode(&view, RequestBody::None).expect("the ceiling itself is inside the range");

    assert_eq!(input.part_number, 10_000);
}

#[test]
fn n_refuses_a_negative_max_keys() {
    let request = accepted("GET", "/photos?list-type=2&max-keys=-1", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let error = dto::ListObjectsV2::decode(&view, RequestBody::None).expect_err("a page cannot have fewer than no keys");

    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.member(), Some("MaxKeys"));
}

#[test]
fn n_refuses_a_max_keys_above_the_ceiling() {
    let request = accepted("GET", "/photos?list-type=2&max-keys=100000", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let error = dto::ListObjectsV2::decode(&view, RequestBody::None).expect_err("clamping would hide the client's mistake");

    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.member(), Some("MaxKeys"));
}

#[test]
fn n_refuses_a_max_keys_that_is_not_a_number() {
    let request = accepted("GET", "/photos?list-type=2&max-keys=abc", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let error = dto::ListObjectsV2::decode(&view, RequestBody::None).expect_err("a non-numeric page size is unusable");

    assert_eq!(error.code().as_str(), "InvalidArgument");
    assert_eq!(error.member(), Some("MaxKeys"));
}

#[test]
fn accepts_max_keys_at_both_ends_of_its_range() {
    for (raw, expected) in [("0", 0), ("1000", 1000)] {
        let request = accepted("GET", &format!("/photos?list-type=2&max-keys={raw}"), &[]);
        let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
        let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("both bounds are inside the range");
        assert_eq!(input.max_keys, Some(expected), "max-keys={raw}");
    }
}

#[test]
fn n_refuses_a_multi_object_delete_with_no_integrity_header() {
    let request = accepted("POST", "/photos?delete", &[("content-type", "application/xml")]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(b"<Delete><Object><Key>a</Key></Object></Delete>"));
    let error = dto::DeleteObjects::decode(&view, body).expect_err("this operation requires an integrity check");

    assert_eq!(error.code().as_str(), "InvalidRequest");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert!(
        error.message().contains("Content-MD5"),
        "the refusal names the header the caller can supply: {}",
        error.message()
    );
}

#[test]
fn n_a_checksum_algorithm_selector_alone_is_not_an_integrity_claim() {
    // `x-amz-sdk-checksum-algorithm` announces which algorithm the SDK would use; it carries no
    // digest, so it is not the integrity check the operation requires.
    let request = accepted("POST", "/photos?delete", &[("x-amz-sdk-checksum-algorithm", "CRC32")]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(b"<Delete><Object><Key>a</Key></Object></Delete>"));
    let error = dto::DeleteObjects::decode(&view, body).expect_err("an algorithm name is not a digest");

    assert_eq!(error.code().as_str(), "InvalidRequest");
}

#[test]
fn a_multi_object_delete_is_accepted_with_either_integrity_header() {
    for headers in [
        &[("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")][..],
        &[("x-amz-checksum-crc32", "AAAAAA==")][..],
    ] {
        let request = accepted("POST", "/photos?delete", headers);
        let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
        let body = RequestBody::Buffered(Bytes::from_static(b"<Delete><Object><Key>a</Key></Object></Delete>"));
        let input = dto::DeleteObjects::decode(&view, body).expect("either header satisfies the requirement");
        assert_eq!(input.delete.objects.len(), 1);
    }
}

#[test]
fn n_refuses_an_object_path_with_no_key() {
    let request = accepted("GET", "/photos", &[]);
    let error = MetaView::of(&request, TargetKind::Object).expect_err("an object route needs a key");

    assert_eq!(error.member(), Some("Key"));
    assert_eq!(error.status(), StatusCode::BAD_REQUEST, "a 400 from the chosen operation, not a 501");
}

// The four body-shape refusals below carry `content-md5` for one reason only: `DeleteObjects` is
// `httpChecksumRequired`, so the integrity check now precedes the body and a fixture without it
// would never reach the assertion it was written for. The assertions themselves are unchanged.
const DELETE_INTEGRITY: &[(&str, &str)] = &[("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")];

#[test]
fn n_refuses_a_delete_objects_body_with_the_wrong_root() {
    let request = accepted("POST", "/photos?delete", DELETE_INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(b"<Remove><Object><Key>a</Key></Object></Remove>"));
    let error = dto::DeleteObjects::decode(&view, body).expect_err("the root element is part of the contract");

    assert_eq!(error.code().as_str(), "MalformedXML");
}

#[test]
fn n_refuses_a_delete_objects_body_carrying_a_doctype() {
    let request = accepted("POST", "/photos?delete", DELETE_INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(
        b"<!DOCTYPE Delete [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><Delete><Object><Key>a</Key></Object></Delete>",
    ));
    let error = dto::DeleteObjects::decode(&view, body).expect_err("a DOCTYPE is refused, never parsed and ignored");

    assert_eq!(error.code().as_str(), "MalformedXML");
}

#[test]
fn n_refuses_a_delete_objects_body_with_no_object_at_all() {
    let request = accepted("POST", "/photos?delete", DELETE_INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(b"<Delete><Quiet>true</Quiet></Delete>"));
    let error = dto::DeleteObjects::decode(&view, body).expect_err("the key list is required");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(error.member(), Some("Objects"));
}

#[test]
fn decodes_a_delete_objects_body_under_a_namespace_prefix() {
    let request = accepted("POST", "/photos?delete", DELETE_INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(
        b"<s3:Delete xmlns:s3=\"urn:x\"><s3:Object><s3:Key>a/b</s3:Key></s3:Object></s3:Delete>",
    ));
    let input = dto::DeleteObjects::decode(&view, body).expect("a prefixed body is the same body");

    assert_eq!(input.delete.objects.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------------------------

#[test]
fn writes_the_entity_tag_quoted_in_a_header() {
    let request = accepted("PUT", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::PutObjectOutput {
        e_tag: ETag::new("d41d8cd98f00b204e9800998ecf8427e").expect("a well-formed tag"),
        ..Default::default()
    };
    let response = dto::PutObject::encode(output, &view, 200).expect("encodes");

    assert_eq!(header(&response, "etag").as_deref(), Some("\"d41d8cd98f00b204e9800998ecf8427e\""));
}

#[test]
fn n_omits_the_storage_class_header_for_the_default_class() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let standard = dto::GetObjectOutput {
        storage_class: Some(dto::StorageClass::STANDARD),
        ..Default::default()
    };
    let response = dto::GetObject::encode(standard, &view, 200).expect("encodes");
    assert!(
        header(&response, "x-amz-storage-class").is_none(),
        "the default class is suppressed in a header, and written in a listing body"
    );

    let glacier = dto::GetObjectOutput {
        storage_class: Some(dto::StorageClass::GLACIER),
        ..Default::default()
    };
    let response = dto::GetObject::encode(glacier, &view, 200).expect("encodes");
    assert_eq!(header(&response, "x-amz-storage-class").as_deref(), Some("GLACIER"));
}

#[test]
fn applies_the_response_overrides_over_the_objects_own_attributes() {
    let request = accepted("GET", "/photos/key?response-content-type=text/plain&response-cache-control=no-store", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectOutput {
        content_type: Some("image/jpeg".to_owned()),
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");

    assert_eq!(header(&response, "content-type").as_deref(), Some("text/plain"));
    assert_eq!(header(&response, "cache-control").as_deref(), Some("no-store"));
}

#[test]
fn n_writes_no_body_on_a_head_response() {
    let request = accepted("HEAD", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::HeadObjectOutput {
        e_tag: Some(ETag::new("d41d8cd98f00b204e9800998ecf8427e").expect("tag")),
        content_length: Some(11),
        ..Default::default()
    };
    let response = dto::HeadObject::encode(output, &view, 200).expect("encodes");

    assert!(response.body.is_empty(), "RFC 9110: a HEAD response never carries content");
    assert_eq!(
        header(&response, "content-length").as_deref(),
        Some("11"),
        "the length is the answer the request was asking for, so it stays"
    );
    assert!(header(&response, "etag").is_some(), "the header set is the GET's, minus the body");
}

#[test]
fn n_writes_no_body_and_no_framing_header_on_a_not_modified_response() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectOutput {
        content_length: Some(11),
        content_type: Some("text/plain".to_owned()),
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 304).expect("encodes");

    assert_eq!(response.status, StatusCode::NOT_MODIFIED);
    assert!(response.body.is_empty());
    assert!(
        header(&response, "content-length").is_none(),
        "a 304 that describes content a client will never receive is a hang waiting to happen"
    );
}

#[test]
fn n_writes_no_body_on_the_delete_object_no_content_response() {
    let request = accepted("DELETE", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::DeleteObjectOutput {
        delete_marker: Some(true),
        ..Default::default()
    };
    let response = dto::DeleteObject::encode(output, &view, 204).expect("encodes");

    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.body.is_empty());
    assert_eq!(
        header(&response, "x-amz-delete-marker").as_deref(),
        Some("true"),
        "a 204 carries no body and still carries its headers"
    );
}

#[test]
fn writes_every_delete_objects_key_into_the_result() {
    let request = accepted("POST", "/photos?delete", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::DeleteObjectsOutput {
        deleted: vec![dto::DeletedObject {
            key: Some(ObjectKey::new("gone").expect("key")),
            ..Default::default()
        }],
        errors: vec![dto::Error {
            key: Some(ObjectKey::new("kept").expect("key")),
            code: Some("AccessDenied".to_owned()),
            message: Some("Access Denied".to_owned()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let response = dto::DeleteObjects::encode(output, &view, 200).expect("encodes");

    assert_eq!(
        body_text(&response.body),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Deleted><Key>gone</Key></Deleted>\
         <Error><Key>kept</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>\
         </DeleteResult>",
        "every requested key appears exactly once, successes before failures"
    );
}

#[test]
fn writes_the_unwrapped_body_the_location_operation_declares() {
    let request = accepted("GET", "/photos?location", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    // The output has one member, so there is nothing for `..Default::default()` to fill.
    let output = dto::GetBucketLocationOutput {
        location_constraint: Some(dto::LocationConstraint::from("us-west-2")),
    };
    let response = dto::GetBucketLocation::encode(output, &view, 200).expect("encodes");

    assert_eq!(
        body_text(&response.body),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-west-2</LocationConstraint>",
        "the member is the root; a generic output wrapper here is a shipped defect"
    );
}

#[test]
fn n_escapes_a_key_that_would_otherwise_break_the_document() {
    let request = accepted("POST", "/photos?delete", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::DeleteObjectsOutput {
        deleted: vec![dto::DeletedObject {
            key: Some(ObjectKey::new("a&b<c>").expect("key")),
            ..Default::default()
        }],
        ..Default::default()
    };
    let response = dto::DeleteObjects::encode(output, &view, 200).expect("encodes");

    assert!(body_text(&response.body).contains("<Key>a&amp;b&lt;c&gt;</Key>"));
}

#[test]
fn writes_user_metadata_back_under_its_prefix() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("colour".to_owned(), "blue".to_owned());
    let output = dto::GetObjectOutput {
        metadata,
        last_modified: Some(Timestamp::from_secs(1_700_000_000)),
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");

    assert_eq!(header(&response, "x-amz-meta-colour").as_deref(), Some("blue"));
    assert_eq!(
        header(&response, "last-modified").as_deref(),
        Some("Tue, 14 Nov 2023 22:13:20 GMT"),
        "an HTTP-date header, not the ISO 8601 spelling the body elements use"
    );
}

#[test]
fn n_refuses_nothing_when_a_head_request_asks_for_a_response_override() {
    // An override still applies to a HEAD, because the header set is the GET's. What must not
    // happen is a body appearing because a query parameter was honoured.
    let request = accepted("HEAD", "/photos/key?response-content-type=text/plain", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::HeadObjectOutput::default();
    let response = dto::HeadObject::encode(output, &view, 200).expect("encodes");

    assert!(response.body.is_empty());
}

#[test]
fn n_reports_an_output_the_gateway_itself_cannot_serialise() {
    // The one error path that is not about the caller: a status the IR could not have produced.
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let error = dto::GetObject::encode(dto::GetObjectOutput::default(), &view, 99).expect_err("99 is not a status");

    assert_eq!(error.code().as_str(), "InternalError");
}

#[test]
fn n_ignores_a_metadata_value_no_header_field_can_carry() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("bad".to_owned(), "line\u{0}break".to_owned());
    let output = dto::GetObjectOutput {
        metadata,
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("a value with no field form is dropped, not fatal");

    assert!(header(&response, "x-amz-meta-bad").is_none());
}

#[test]
fn the_method_reaches_the_encoder_unchanged() {
    let request = accepted("HEAD", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    assert_eq!(view.method(), Method::HEAD);
}

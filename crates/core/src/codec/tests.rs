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
use rustfs_gateway_types::{BucketName, ETag, ObjectKey, OpaqueString, RangeOutcome, Timestamp};

use crate::codec::response::ResponseBody;
use crate::codec::{MetaView, OperationCodec, RequestBody};
use crate::route::TargetKind;

mod content_type_default;
mod header_lists;
mod metadata_and_url;
mod page_size_ceiling;
mod rustfs_listing;
mod transport_ended_empty;

/// An accepted request, owned so a `MetaView` can borrow it.
pub(super) fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
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
    let range = input.range.expect("one well-formed range is honoured");
    assert_eq!(
        range.resolve(200),
        RangeOutcome::Satisfied {
            start: 0,
            end_inclusive: 99
        }
    );
    assert_eq!(range.as_str(), "bytes=0-99", "the header survives the parse that read it");
}

#[test]
fn n_ignores_a_range_header_it_cannot_honour() {
    let request = accepted("GET", "/photos/key", &[("range", "items=0-1")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("an unusable range is not a refusal");

    // "Ignored" is now asserted where RFC 9110 §14.2 puts it — in what gets served — rather than by
    // the binding having forgotten the header. The previous form asserted `range.is_none()`, which
    // held only because an unusable range and an absent one had been collapsed into one value; that
    // collapse is what left a 416 unable to echo `<RangeRequested>` at all (issue #15).
    let range = input.range.expect("the header arrived, so it is present");
    assert_eq!(
        range.resolve(200),
        RangeOutcome::Full,
        "RFC 9110 requires an unparseable Range to be ignored and the whole representation served"
    );
    assert_eq!(
        range.as_str(),
        "items=0-1",
        "and the bytes the client sent are still the bytes we can quote back"
    );
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
fn n_refuses_a_request_whose_checksum_headers_contradict_or_cannot_be_read() {
    // The second half pins a `continue`: a value this binder cannot read must not be skipped, or
    // the caller's claim is dropped and the object is stored as though none had been made. The
    // three digest-less headers under the prefix are excepted by name, not by parse failure.
    let decode = |head: &[(&str, &str)]| {
        let mut all = vec![("content-length", "0")];
        all.extend_from_slice(head);
        let request = accepted("PUT", "/photos/key", &all);
        dto::PutObject::decode(&MetaView::of(&request, TargetKind::Object).expect("view"), RequestBody::None).map(|_| ())
    };
    let two = [
        ("x-amz-checksum-crc32", "AAAAAA=="),
        ("x-amz-checksum-sha1", "2jmj7l5rSw0yVb/vlWAYkK/YBwk="),
    ];
    assert_eq!(decode(&two).expect_err("two algorithms contradict").code().as_str(), "InvalidRequest");
    let error = decode(&[("x-amz-checksum-crc32", "nope")]).expect_err("that value is not a CRC32");
    assert_eq!((error.code().as_str(), error.member()), ("InvalidRequest", Some("ChecksumSpec")));
    decode(&[("x-amz-checksum-mode", "ON")]).expect("that header declares no digest");
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
        &[("content-md5", "aFPqFnlCon58cZ4Qt7zwvQ==")][..],
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

// The four body-shape refusals below carry an integrity header for one reason only: `DeleteObjects`
// is `httpChecksumRequired`, so the integrity check precedes the body and a fixture without it
// would never reach the assertion it was written for. The assertions themselves are unchanged.
//
// It is a checksum header rather than a `Content-MD5` because the digest is now verified against
// the body: a `Content-MD5` here would have to be recomputed every time one of these four bodies is
// edited, and the day somebody forgot, the test would go red for the digest and not for the shape
// it is about. The header this constant does send satisfies the requirement and names nothing about
// these bytes.
const DELETE_INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

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

/// One listing page with a single entry, so an encode test can name the value it is asserting.
fn one_entry_listing(key: &str, etag: &str) -> dto::ListObjectsV2Output {
    dto::ListObjectsV2Output {
        name: BucketName::new("conf-list").expect("bucket"),
        key_count: 1,
        max_keys: 1000,
        is_truncated: false,
        contents: vec![dto::Object {
            key: ObjectKey::new(key).expect("key"),
            e_tag: ETag::new(etag.to_owned()).expect("an entity tag"),
            // `LastModified` is required and its placeholder default has no rendering, so a
            // fixture that leaves it out fails on the timestamp rather than on what it asserts.
            last_modified: Timestamp::from_secs(1_767_322_745),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn writes_a_listing_entity_tag_with_its_quotes_escaped() {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = one_entry_listing("top.txt", "b28354b543375bfa94dabaeda722927f");
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    let body = body_text(&response.body);
    assert!(
        body.contains("<ETag>&quot;b28354b543375bfa94dabaeda722927f&quot;</ETag>"),
        "AWS writes the tag's own quotation marks as entities: {body}"
    );
    assert!(!body.contains("<ETag>\""), "a literal quote here is a body no golden matches: {body}");
}

#[test]
fn n_a_quote_inside_a_key_is_escaped_exactly_as_the_entity_tag_s_is() {
    // The two live in one document and S3 escapes both the same way (rustfs/gateway#13): an
    // earlier writer left the key's quote literal, and a document asserting both spellings cannot
    // match what S3 sends.
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = one_entry_listing("a&b<c>d\"e'f.txt", "b28354b543375bfa94dabaeda722927f");
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    let body = body_text(&response.body);
    assert!(body.contains("<Key>a&amp;b&lt;c&gt;d&quot;e&apos;f.txt</Key>"), "{body}");
    assert!(body.contains("&quot;b28354b543375bfa94dabaeda722927f&quot;"), "{body}");
    assert!(!body.contains("d\"e"), "{body}");
}

#[test]
fn percent_encodes_every_declared_member_when_the_request_asks_for_it() {
    let request = accepted("GET", "/conf-list?list-type=2&encoding-type=url&delimiter=%2F", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let mut output = one_entry_listing("with space.txt", "b28354b543375bfa94dabaeda722927f");
    output.delimiter = Some("/".to_owned());
    output.prefix = "a&b/".to_owned();
    output.encoding_type = Some(dto::EncodingType::URL);
    output.common_prefixes = vec![dto::CommonPrefix {
        prefix: "café/".to_owned(),
    }];
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    let body = body_text(&response.body);
    for expected in [
        "<Key>with%20space.txt</Key>",
        "<Delimiter>%2F</Delimiter>",
        "<Prefix>a%26b%2F</Prefix>",
        "<Prefix>caf%C3%A9%2F</Prefix>",
        "<EncodingType>url</EncodingType>",
    ] {
        assert!(body.contains(expected), "missing {expected} in {body}");
    }
}

#[test]
fn n_leaves_every_member_alone_when_the_request_does_not_ask() {
    let request = accepted("GET", "/conf-list?list-type=2&delimiter=%2F", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let mut output = one_entry_listing("with space.txt", "b28354b543375bfa94dabaeda722927f");
    output.delimiter = Some("/".to_owned());
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    let body = body_text(&response.body);
    assert!(body.contains("<Key>with space.txt</Key>"), "{body}");
    assert!(body.contains("<Delimiter>/</Delimiter>"), "{body}");
    assert!(!body.contains('%'), "nothing is encoded when nothing asked for it: {body}");
}

#[test]
fn n_an_unknown_encoding_type_spelling_encodes_nothing() {
    // AWS defines exactly one value. Treating anything else as "encode anyway" would produce a
    // document whose echo disagrees with its contents.
    let request = accepted("GET", "/conf-list?list-type=2&encoding-type=base64", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = one_entry_listing("with space.txt", "b28354b543375bfa94dabaeda722927f");
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    assert!(body_text(&response.body).contains("<Key>with space.txt</Key>"));
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

/// A stored value no header field can carry raw (a NUL) is written as an RFC 2047 encoded word,
/// as the s3s build RustFS runs today writes it, rather than left out of the answer with nothing
/// to say so (rustfs/gateway#996). The header is printable ASCII and decodes back to the value.
#[test]
fn n_writes_a_metadata_value_no_header_field_can_carry_raw_as_an_encoded_word() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("bad".to_owned(), "line\u{0}break".to_owned());
    let output = dto::GetObjectOutput {
        metadata,
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");

    let written = header(&response, "x-amz-meta-bad").expect("the entry is not dropped");
    assert_eq!(written, "=?UTF-8?B?bGluZQBicmVhaw==?=");
    assert_eq!(
        rustfs_gateway_http::decode_metadata_value(&written).map(|v| v.into_owned()),
        Err(rustfs_gateway_http::MetadataReject::ControlCharacterAfterDecoding),
        "the inbound rule still refuses the decoded value"
    );
}

#[test]
fn the_method_reaches_the_encoder_unchanged() {
    let request = accepted("HEAD", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    assert_eq!(view.method(), Method::HEAD);
}

// ---------------------------------------------------------------------------------------------
// Wire forms
//
// These values are opaque to the generated codec and validated by the operation that consumes
// them. The assertions here pin that ownership boundary; the linked conformance cases pin the
// end-to-end refusals.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unterminated_conditional_header_reaches_the_operation_parser_unchanged() {
    let request = accepted("GET", "/photos/key", &[("if-match", "\"5d41402abc4b2a76b9719d911017c592")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("the operation parser owns the entity-tag grammar");
    assert_eq!(input.if_match.as_deref(), Some("\"5d41402abc4b2a76b9719d911017c592"));
}

#[test]
fn accepts_every_spelling_a_conditional_header_may_legitimately_carry() {
    for spelling in ["*", "\"abc\"", "abc", "W/\"abc\""] {
        let request = accepted("GET", "/photos/key", &[("if-none-match", spelling)]);
        let view = MetaView::of(&request, TargetKind::Object).expect("view");
        let input = dto::GetObject::decode(&view, RequestBody::None).unwrap_or_else(|_| panic!("`{spelling}` is a tag"));
        assert_eq!(input.if_none_match.as_deref(), Some(spelling), "the value is checked, not rewritten");
    }
}

#[test]
fn repeated_conditional_headers_reach_the_operation_parser_as_one_value() {
    // RFC 9110 §5.3 joins the two field lines. Keeping the joined value is what lets the operation
    // parser refuse it instead of evaluating whichever field line happened to arrive first.
    let request = accepted(
        "GET",
        "/photos/key",
        &[
            ("if-match", "\"5d41402abc4b2a76b9719d911017c592\""),
            ("if-match", "\"0000000000000000000000000000dead\""),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("the operation parser owns the entity-tag grammar");
    assert_eq!(
        input.if_match.as_deref(),
        Some("\"5d41402abc4b2a76b9719d911017c592\", \"0000000000000000000000000000dead\"")
    );
}

#[test]
fn a_non_text_cursor_reaches_the_token_parser_after_query_decoding() {
    let request = accepted("GET", "/conf-list?list-type=2&continuation-token=%FF%FE%00%01", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("the token parser owns the token grammar");
    assert_eq!(
        input.continuation_token.as_ref().map(OpaqueString::as_str),
        Some("\u{fffd}\u{fffd}\0\u{1}")
    );
}

#[test]
fn a_traversal_shaped_cursor_reaches_the_token_parser_once_decoded() {
    for target in [
        "/conf-list?list-type=2&continuation-token=..%2F..%2Fetc%2Fpasswd",
        "/conf-list?list-type=2&continuation-token=%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
    ] {
        let request = accepted("GET", target, &[]);
        let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
        let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("the token parser owns the token grammar");
        assert_eq!(input.continuation_token.as_ref().map(OpaqueString::as_str), Some("../../etc/passwd"));
    }
}

#[test]
fn a_cursor_derived_from_a_key_still_decodes() {
    // The refusal is about path *syntax*, not about the slash: a cursor this service minted from
    // the last key of a page carries them, and so does a token drawn from the base64 alphabet.
    let request = accepted("GET", "/conf-list?list-type=2&continuation-token=a%2F1.txt", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("an ordinary cursor decodes");
    assert_eq!(input.continuation_token.as_ref().map(OpaqueString::as_str), Some("a/1.txt"));
}

#[test]
fn a_traversal_shaped_upload_id_marker_reaches_the_operation_parser() {
    let request = accepted(
        "GET",
        "/conf-mpu?uploads&key-marker=listed-upload&upload-id-marker=..%2F..%2F..%2Fetc%2Fpasswd",
        &[],
    );
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListMultipartUploads::decode(&view, RequestBody::None).expect("the operation parser owns marker validation");
    assert_eq!(input.upload_id_marker.as_deref(), Some("../../../etc/passwd"));
    // The key marker beside it is a key, not a token, and is left alone.
    let ordinary = accepted("GET", "/conf-mpu?uploads&key-marker=..%2Fkey", &[]);
    let view = MetaView::of(&ordinary, TargetKind::Bucket).expect("view");
    let input = dto::ListMultipartUploads::decode(&view, RequestBody::None).expect("a key marker carries a key");
    assert_eq!(input.key_marker.as_deref(), Some("../key"));
}

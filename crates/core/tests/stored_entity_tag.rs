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

//! A stored entity tag through the generated encoders: in a listing body and in a header
//! (rustfs/gateway#1611).
//!
//! Responsible for: that a tag built with `ETag::from_stored` reads back byte for byte from a
//! listing body in both document layouts, that markup in it stays text, that a character XML 1.0
//! cannot carry is substituted exactly as in every other body string, and that a value a header
//! cannot carry drops the `ETag` header — the rule `EncodedResponse::set_header` applies to every
//! header member — without failing the answer.
//! NOT responsible for: the constructor and comparison (`rustfs-gateway-types`'
//! `stored_etag_tests`), or the escaping functions themselves (`crates/xml`).
//! Upstream: the generated `ListObjectsV2` and `HeadObject` encoders. Downstream: nothing.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use http::Request;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{EncodedResponse, MetaView, OperationCodec};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{BucketName, ETag, ObjectKey, Timestamp, dto};
use rustfs_gateway_xml::UNREPRESENTABLE;

/// The four stored values the issue names.
const STORED: &[&str] = &["\"\"", "a\tb", "<x>&amp;</ETag>", "\"d41d8cd98f00b204e9800998ecf8427e\""];

fn accepted(method: &str, target: &str) -> WireRequest<()> {
    let request = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// One listing entry carrying `stored`, encoded in the model layout or legacy RustFS's.
fn listing_body(stored: &str, legacy: bool) -> String {
    let request = accepted("GET", "/conf-list?list-type=2");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let view = if legacy { view.with_rustfs_response_layout() } else { view };
    let output = dto::ListObjectsV2Output {
        name: BucketName::new("conf-list").expect("bucket"),
        key_count: 1,
        max_keys: 1000,
        contents: vec![dto::Object {
            key: ObjectKey::new("k").expect("key"),
            e_tag: Some(ETag::from_stored(stored.to_owned())),
            last_modified: Timestamp::from_secs(1_767_322_745),
            ..Default::default()
        }],
        ..Default::default()
    };
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("a stored tag always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        _ => panic!("a listing is a complete document"),
    }
}

/// The `ETag` text of the one entry, as the gateway's strict reader reads the document.
fn read_back(body: &str) -> String {
    let root = rustfs_gateway_xml::parse(body.as_bytes()).expect("the document is well-formed");
    let entry = root.child("Contents").expect("the entry is there");
    assert_eq!(entry.children_named("x").count(), 0, "markup in the tag became an element: {body}");
    entry.child_text("ETag").expect("the entity tag is there").to_owned()
}

fn head_response(stored: &str) -> EncodedResponse {
    let request = accepted("HEAD", "/photos/key");
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::HeadObjectOutput {
        e_tag: Some(ETag::from_stored(stored.to_owned())),
        content_length: Some(11),
        ..Default::default()
    };
    dto::HeadObject::encode(output, &view, 200).expect("an unrepresentable header never fails the answer")
}

#[test]
fn every_stored_tag_reads_back_from_a_listing_in_both_layouts() {
    for legacy in [false, true] {
        for stored in STORED {
            let body = listing_body(stored, legacy);
            assert_eq!(read_back(&body), format!("\"{stored}\""), "legacy layout {legacy}: {body}");
        }
    }
}

#[test]
fn n_markup_in_a_stored_tag_stays_text_in_both_layouts() {
    for legacy in [false, true] {
        let body = listing_body("</ETag><x>", legacy);
        assert!(!body.contains("</ETag><x>"), "the markup reached the document raw: {body}");
        assert_eq!(read_back(&body), "\"</ETag><x>\"");
    }
}

#[test]
fn n_a_character_xml_cannot_carry_is_substituted_as_in_every_body_string() {
    for legacy in [false, true] {
        let body = listing_body("a\u{1}b", legacy);
        assert_eq!(read_back(&body), format!("\"a{UNREPRESENTABLE}b\""), "legacy layout {legacy}");
    }
}

#[test]
fn n_a_stored_tag_no_header_can_carry_drops_only_the_header() {
    for stored in ["a\u{1}b", "a\nb", "a\r\nx-injected: 1", "a\u{7f}b", "a\u{0}"] {
        let response = head_response(stored);
        assert!(response.headers.get("etag").is_none(), "{stored:?} reached the header");
        assert!(response.headers.get("x-injected").is_none(), "{stored:?} split the header block");
        assert_eq!(
            response.headers.get("content-length").map(|v| v.as_bytes()),
            Some(&b"11"[..]),
            "the rest of the answer for {stored:?} was lost"
        );
    }
}

#[test]
fn a_stored_tag_a_header_can_carry_is_written_quoted() {
    for (stored, wire) in [("a\tb", "\"a\tb\""), ("\"\"", "\"\\\"\\\"\""), ("", "\"\"")] {
        let response = head_response(stored);
        assert_eq!(response.headers.get("etag").map(|v| v.as_bytes()), Some(wire.as_bytes()), "{stored:?}");
    }
}

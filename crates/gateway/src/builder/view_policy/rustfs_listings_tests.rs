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

//! The RustFS profile's ListMultipartUploads listing encoding, through the assembly's own table
//! ([`super::RUSTFS_LISTING_ENCODINGS`]) and the generated encoder (rustfs/gateway#1614).
//!
//! Responsible for: proving that under the profile `encoding-type=url` encodes exactly the six
//! members RustFS encodes, segment by segment, and echoes the value; that without the parameter
//! nothing is encoded or echoed; and that the default profile keeps the AWS-model encoding.
//! NOT responsible for: the per-segment escape itself (`rustfs_gateway_core::codec::rustfs_listing`)
//! or the object listings' tables (covered by the core's own tests).
//! Upstream: `super::ViewPolicy::apply`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic)] // test fixtures: a fixture that cannot be built fails the test

use super::{RUSTFS_LISTING_ENCODINGS, ViewPolicy};
use bytes::Bytes;
use http_body_util::Full;
use rustfs_gateway_core::{MetaView, OperationCodec, ResponseBody, TargetKind};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;
use rustfs_gateway_types::{BucketName, ObjectKey};

/// The raw value every encodable member carries under `tag`: a space, a `+`, a non-ASCII
/// character and two `/` that must stay literal.
fn raw(tag: &str) -> String {
    format!("{tag}/a b+\u{e9}/c")
}

/// `raw(tag)` encoded segment by segment, as RustFS encodes it.
fn per_segment(tag: &str) -> String {
    format!("{tag}/a%20b%2B%C3%A9/c")
}

/// `raw(tag)` encoded as one value, `/` included, as the AWS model encodes it.
fn whole(tag: &str) -> String {
    format!("{tag}%2Fa%20b%2B%C3%A9%2Fc")
}

/// The six members RustFS encodes, as the element and the tag of the value it carries.
const MEMBERS: [(&str, &str); 6] = [
    ("Prefix", "prefix"),
    ("Delimiter", "delimiter"),
    ("KeyMarker", "key-marker"),
    ("NextKeyMarker", "next-key-marker"),
    ("Key", "upload-key"),
    ("Prefix", "common-prefix"),
];

fn encode(policy: ViewPolicy, query: &str) -> String {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("/bucket?uploads{query}"))
        .header(http::header::HOST, "s3.example.com")
        .body(Full::new(Bytes::new()))
        .expect("a valid request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable request");
    let meta = MetaView::of(&wire, TargetKind::Bucket).expect("a view");
    let view = policy.apply::<Full<Bytes>>("ListMultipartUploads", meta, None);
    let echo = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("encoding-type="))
        .map(|value| dto::EncodingType::custom(value.to_owned()));
    let output = dto::ListMultipartUploadsOutput {
        bucket: BucketName::new("bucket").expect("bucket"),
        prefix: Some(raw("prefix")),
        delimiter: Some(raw("delimiter")),
        key_marker: Some(raw("key-marker")),
        next_key_marker: Some(raw("next-key-marker")),
        upload_id_marker: Some(raw("upload-id-marker")),
        next_upload_id_marker: Some(raw("next-upload-id-marker")),
        encoding_type: echo,
        uploads: vec![dto::MultipartUpload {
            key: Some(ObjectKey::new(raw("upload-key")).expect("key")),
            upload_id: Some(raw("upload-id")),
            ..Default::default()
        }],
        common_prefixes: vec![dto::CommonPrefix {
            prefix: raw("common-prefix"),
        }],
        ..Default::default()
    };
    let response = dto::ListMultipartUploads::encode(output, &view, 200).expect("encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        _ => panic!("a listing answers a complete document"),
    }
}

fn rustfs() -> ViewPolicy {
    ViewPolicy {
        rustfs_listings: true,
        ..ViewPolicy::default()
    }
}

/// Positive — under the profile every member RustFS encodes is encoded per segment and the value
/// is echoed.
#[test]
fn each_rustfs_member_is_encoded_per_segment_and_the_value_is_echoed() {
    let body = encode(rustfs(), "&encoding-type=url");
    for (element, tag) in MEMBERS {
        let expected = format!("<{element}>{}</{element}>", per_segment(tag));
        assert!(body.contains(&expected), "{tag}: missing {expected}: {body}");
    }
    assert!(body.contains("<EncodingType>url</EncodingType>"), "{body}");
    assert!(!body.contains("%2F"), "`/` stays literal: {body}");
}

/// Negative — the upload-id cursors are not members RustFS encodes.
#[test]
fn n_upload_id_cursors_stay_raw_under_the_profile() {
    let body = encode(rustfs(), "&encoding-type=url");
    for (element, tag) in [
        ("UploadIdMarker", "upload-id-marker"),
        ("NextUploadIdMarker", "next-upload-id-marker"),
        ("UploadId", "upload-id"),
    ] {
        let expected = format!("<{element}>{}</{element}>", raw(tag));
        assert!(body.contains(&expected), "{tag}: missing {expected}: {body}");
    }
}

/// Negative — without `encoding-type` nothing is encoded and nothing is echoed.
#[test]
fn n_without_encoding_type_nothing_is_encoded_or_echoed() {
    let body = encode(rustfs(), "");
    for (element, tag) in MEMBERS {
        let expected = format!("<{element}>{}</{element}>", raw(tag));
        assert!(body.contains(&expected), "{tag}: missing {expected}: {body}");
    }
    assert!(!body.contains("<EncodingType>"), "{body}");
    assert!(!body.contains('%'), "{body}");
}

/// Negative — a spelling other than exactly `url` encodes nothing and is echoed as sent.
#[test]
fn n_another_spelling_encodes_nothing_and_is_echoed_verbatim() {
    let body = encode(rustfs(), "&encoding-type=URL");
    for (element, tag) in MEMBERS {
        let expected = format!("<{element}>{}</{element}>", raw(tag));
        assert!(body.contains(&expected), "{tag}: missing {expected}: {body}");
    }
    assert!(body.contains("<EncodingType>URL</EncodingType>"), "{body}");
}

/// Negative — the default profile keeps the AWS-model encoding: the whole value, `/` included.
#[test]
fn n_the_default_profile_keeps_the_model_encoding() {
    let body = encode(ViewPolicy::default(), "&encoding-type=url");
    for (element, tag) in MEMBERS {
        let expected = format!("<{element}>{}</{element}>", whole(tag));
        assert!(body.contains(&expected), "{tag}: missing {expected}: {body}");
    }
    assert!(body.contains("<EncodingType>url</EncodingType>"), "{body}");
    let body = encode(ViewPolicy::default(), "");
    assert!(!body.contains('%'), "{body}");
    assert!(!body.contains("<EncodingType>"), "{body}");
}

/// Negative — ListParts has no `encoding-type`, so its entry encodes nothing and echoes nothing.
#[test]
fn n_list_parts_encodes_and_echoes_nothing() {
    let (_, parts) = RUSTFS_LISTING_ENCODINGS
        .iter()
        .find(|(operation, _)| *operation == "ListParts")
        .expect("ListParts has an entry");
    assert!(parts.members().is_empty(), "{:?}", parts.members());
    assert!(!parts.echoes());
}

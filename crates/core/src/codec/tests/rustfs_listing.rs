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

//! Legacy RustFS's `encoding-type=url` rule, seen through the generated listing encoders.
//!
//! Responsible for: a view carrying a [`RustFsListing`] encoding exactly the members it names,
//! with `/` kept literal, only for exactly `url`, and echoing `encoding-type` as legacy RustFS
//! does — while a view without one, and a value XML cannot carry, keep the AWS-model encoding.
//! NOT responsible for: which listing uses which table (`rustfs-gateway`'s RustFS profile).
//! Upstream: `crate::codec::rustfs_listing`. Downstream: nothing.

use super::*;
use crate::codec::value::RustFsListing;

/// The tables legacy RustFS applies; the assembly carries its own copy of these facts, and the
/// launcher's end-to-end suite holds the two together.
const V2: RustFsListing = RustFsListing::new(&["Object.Key", "CommonPrefix.Prefix"], true);
const V1: RustFsListing = RustFsListing::new(&["Object.Key", "CommonPrefix.Prefix", "NextMarker"], true);
const MULTIPART: RustFsListing = RustFsListing::new(&[], false);

fn v2_listing() -> dto::ListObjectsV2Output {
    let mut output = one_entry_listing("dir/with space.txt", "b28354b543375bfa94dabaeda722927f");
    output.prefix = "dir/a b/".to_owned();
    output.delimiter = Some("/".to_owned());
    output.start_after = Some("dir/a b/0".to_owned());
    output.continuation_token = Some(OpaqueString::new("ab+c/d=".to_owned()));
    output.next_continuation_token = Some(OpaqueString::new("xy+z/w=".to_owned()));
    output.common_prefixes = vec![dto::CommonPrefix {
        prefix: "dir/a b/sub dir/".to_owned(),
    }];
    output
}

fn encode_v2(query: &str, listing: Option<RustFsListing>) -> String {
    let request = accepted("GET", &format!("/conf-list?list-type=2{query}"), &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let view = match listing {
        Some(listing) => view.with_rustfs_listing_encoding(listing),
        None => view,
    };
    let mut output = v2_listing();
    output.encoding_type = request_echo(query);
    body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body)
}

/// What a backend echoes: the decoded `encoding-type`, whatever it is.
fn request_echo(query: &str) -> Option<dto::EncodingType> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("encoding-type="))
        .map(|value| dto::EncodingType::custom(value.to_owned()))
}

#[test]
fn only_the_members_legacy_encodes_are_encoded_and_slashes_stay_literal() {
    let body = encode_v2("&encoding-type=url", Some(V2));
    for expected in [
        "<Key>dir/with%20space.txt</Key>",
        "<Prefix>dir/a%20b/sub%20dir/</Prefix>",
        "<Prefix>dir/a b/</Prefix>",
        "<Delimiter>/</Delimiter>",
        "<StartAfter>dir/a b/0</StartAfter>",
        "<ContinuationToken>ab+c/d=</ContinuationToken>",
        "<NextContinuationToken>xy+z/w=</NextContinuationToken>",
        "<EncodingType>url</EncodingType>",
    ] {
        assert!(body.contains(expected), "missing {expected}: {body}");
    }
    assert!(!body.contains("%2F"), "legacy keeps `/` literal: {body}");
}

#[test]
fn n_without_the_rustfs_rule_keys_are_encoded_but_cursors_stay_opaque() {
    let body = encode_v2("&encoding-type=url", None);
    for expected in [
        "<Key>dir%2Fwith%20space.txt</Key>",
        "<Prefix>dir%2Fa%20b%2F</Prefix>",
        "<Delimiter>%2F</Delimiter>",
        "<ContinuationToken>ab+c/d=</ContinuationToken>",
        "<NextContinuationToken>xy+z/w=</NextContinuationToken>",
        "<EncodingType>url</EncodingType>",
    ] {
        assert!(body.contains(expected), "missing {expected}: {body}");
    }
}

/// Negative — encoding a listing must not encode or interpret an opaque cursor's percent signs.
#[test]
fn n_opaque_cursors_never_acquire_url_escapes() {
    let request = accepted("GET", "/conf-list?list-type=2&encoding-type=url", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    for token in ["ab+c/d=", "x%2Fy%20z", "%252F"] {
        let mut output = v2_listing();
        output.continuation_token = Some(OpaqueString::new(token.to_owned()));
        output.next_continuation_token = Some(OpaqueString::new(token.to_owned()));
        let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
        for tag in ["ContinuationToken", "NextContinuationToken"] {
            assert!(body.contains(&format!("<{tag}>{token}</{tag}>")), "{body}");
        }
        assert!(body.contains("<Key>dir%2Fwith%20space.txt</Key>"), "{body}");
    }
}

/// Negative — normal XML escaping applies to cursors; URL escapes cannot substitute for it.
#[test]
fn n_opaque_cursors_are_xml_escaped_without_url_encoding() {
    let request = accepted("GET", "/conf-list?list-type=2&encoding-type=url", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let mut output = v2_listing();
    output.continuation_token = Some(OpaqueString::new("a&b<c>d".to_owned()));
    output.next_continuation_token = Some(OpaqueString::new("a&b<c>d".to_owned()));
    let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
    for tag in ["ContinuationToken", "NextContinuationToken"] {
        assert!(body.contains(&format!("<{tag}>a&amp;b&lt;c&gt;d</{tag}>")), "{body}");
    }
}

/// The cursor read from the response, URI-quoted once by a client, becomes the next input intact.
#[test]
fn a_cursor_from_an_encoded_listing_round_trips_into_the_next_query() {
    let request = accepted("GET", "/conf-list?list-type=2&encoding-type=url", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    for token in ["ab+c/d=", "x%2Fy%20z"] {
        let mut output = v2_listing();
        output.next_continuation_token = Some(OpaqueString::new(token.to_owned()));
        let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
        let returned = body
            .split_once("<NextContinuationToken>")
            .expect("token element")
            .1
            .split_once("</NextContinuationToken>")
            .expect("token closes")
            .0;
        let quoted = rustfs_gateway_sig::percent_encode(returned.as_bytes());
        let next = accepted(
            "GET",
            &format!("/conf-list?list-type=2&encoding-type=url&continuation-token={quoted}"),
            &[],
        );
        let view = MetaView::of(&next, TargetKind::Bucket).expect("view");
        let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("next page decodes");
        assert_eq!(input.continuation_token.as_ref().map(OpaqueString::as_str), Some(token));
    }
}

/// Negative — query decoding must not interpret percent sequences inside an opaque token twice.
#[test]
fn n_a_cursor_query_is_not_percent_decoded_twice() {
    let request = accepted("GET", "/conf-list?list-type=2&continuation-token=%252e%252e%252Fabc", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("decodes once");
    assert_eq!(input.continuation_token.as_ref().map(OpaqueString::as_str), Some("%2e%2e%2Fabc"));
}

#[test]
fn n_a_spelling_other_than_exactly_url_encodes_nothing_and_is_echoed_verbatim() {
    for (query, echo) in [("&encoding-type=URL", "URL"), ("&encoding-type=foo", "foo")] {
        let body = encode_v2(query, Some(V2));
        assert!(body.contains("<Key>dir/with space.txt</Key>"), "{query}: {body}");
        assert!(body.contains("<Prefix>dir/a b/sub dir/</Prefix>"), "{query}: {body}");
        assert!(body.contains(&format!("<EncodingType>{echo}</EncodingType>")), "{query}: {body}");
    }
}

#[test]
fn n_without_encoding_type_nothing_is_encoded_or_echoed() {
    let body = encode_v2("", Some(V2));
    assert!(body.contains("<Key>dir/with space.txt</Key>"), "{body}");
    assert!(!body.contains("<EncodingType>"), "{body}");
}

#[test]
fn n_xml_whitespace_does_not_force_the_rustfs_listing_into_model_encoding() {
    for whitespace in ["\n", "\t", "\r"] {
        let request = accepted("GET", "/conf-list?list-type=2", &[]);
        let view = MetaView::of(&request, TargetKind::Bucket)
            .expect("view")
            .with_rustfs_listing_encoding(V2);
        let mut output = one_entry_listing("ordinary/key", "b28354b543375bfa94dabaeda722927f");
        output.prefix = whitespace.to_owned();
        let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
        let spelling = if whitespace == "\r" { "&#13;" } else { whitespace };
        assert!(body.contains(&format!("<Prefix>{spelling}</Prefix>")), "{whitespace:?}: {body}");
        assert!(body.contains("<Key>ordinary/key</Key>"), "{whitespace:?}: {body}");
        assert!(!body.contains("<EncodingType>"), "{whitespace:?}: {body}");
    }
}

#[test]
fn n_xml_whitespace_keeps_the_rustfs_member_selection_when_url_was_requested() {
    for whitespace in ["\n", "\t", "\r"] {
        let request = accepted("GET", "/conf-list?list-type=2&encoding-type=url", &[]);
        let view = MetaView::of(&request, TargetKind::Bucket)
            .expect("view")
            .with_rustfs_listing_encoding(V2);
        let key = format!("dir/{whitespace}key");
        let mut output = one_entry_listing(&key, "b28354b543375bfa94dabaeda722927f");
        output.prefix = whitespace.to_owned();
        let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
        let spelling = if whitespace == "\r" { "&#13;" } else { whitespace };
        assert!(body.contains(&format!("<Prefix>{spelling}</Prefix>")), "{whitespace:?}: {body}");
        let encoded = rustfs_gateway_sig::percent_encode(whitespace.as_bytes());
        assert!(body.contains(&format!("<Key>dir/{encoded}key</Key>")), "{whitespace:?}: {body}");
        assert!(body.contains("<EncodingType>url</EncodingType>"), "{whitespace:?}: {body}");
    }
}

#[test]
fn n_xml_whitespace_still_forces_model_encoding_without_the_rustfs_profile() {
    for whitespace in ["\n", "\t", "\r"] {
        let request = accepted("GET", "/conf-list?list-type=2", &[]);
        let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
        let mut output = one_entry_listing("ordinary/key", "b28354b543375bfa94dabaeda722927f");
        output.prefix = whitespace.to_owned();
        let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
        let encoded = rustfs_gateway_sig::percent_encode(whitespace.as_bytes());
        assert!(body.contains(&format!("<Prefix>{encoded}</Prefix>")), "{whitespace:?}: {body}");
        assert!(body.contains("<Key>ordinary%2Fkey</Key>"), "{whitespace:?}: {body}");
        assert!(body.contains("<EncodingType>url</EncodingType>"), "{whitespace:?}: {body}");
    }
}

#[test]
fn n_list_objects_preserves_the_xml_valid_lf_prefix_the_sdk_uses() {
    for query in ["", "&encoding-type=url"] {
        let request = accepted("GET", &format!("/conf-list?prefix=%0A{query}"), &[]);
        let view = MetaView::of(&request, TargetKind::Bucket)
            .expect("view")
            .with_rustfs_listing_encoding(V1);
        let output = dto::ListObjectsOutput {
            name: BucketName::new("conf-list").expect("bucket"),
            prefix: "\n".to_owned(),
            ..Default::default()
        };
        let body = body_text(&dto::ListObjects::encode(output, &view, 200).expect("encodes").body);
        assert!(body.contains("<Prefix>\n</Prefix>"), "{query}: {body}");
    }
}

#[test]
fn n_a_value_xml_cannot_carry_still_forces_the_model_encoding() {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_rustfs_listing_encoding(V2);
    let output = one_entry_listing("dir/ctrl\u{1}key", "b28354b543375bfa94dabaeda722927f");
    let body = body_text(&dto::ListObjectsV2::encode(output, &view, 200).expect("encodes").body);
    assert!(!body.contains('\u{1}'), "{body}");
    assert!(body.contains("<Key>dir%2Fctrl%01key</Key>"), "{body}");
    assert!(body.contains("<EncodingType>url</EncodingType>"), "{body}");
}

#[test]
fn n_a_listing_legacy_never_encodes_is_written_raw_without_an_echo() {
    let request = accepted("GET", "/conf-list?uploads&encoding-type=url", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_rustfs_listing_encoding(MULTIPART);
    let output = dto::ListMultipartUploadsOutput {
        bucket: BucketName::new("conf-list").expect("bucket"),
        prefix: Some("dir/a b/".to_owned()),
        delimiter: Some("/".to_owned()),
        encoding_type: Some(dto::EncodingType::custom("url".to_owned())),
        uploads: vec![dto::MultipartUpload {
            key: Some(ObjectKey::new("dir/with space.txt").expect("key")),
            ..Default::default()
        }],
        ..Default::default()
    };
    let body = body_text(&dto::ListMultipartUploads::encode(output, &view, 200).expect("encodes").body);
    assert!(body.contains("<Key>dir/with space.txt</Key>"), "{body}");
    assert!(body.contains("<Prefix>dir/a b/</Prefix>"), "{body}");
    assert!(body.contains("<Delimiter>/</Delimiter>"), "{body}");
    assert!(!body.contains("<EncodingType>"), "{body}");
    assert!(!body.contains('%'), "{body}");
}

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

//! Metadata RFC 2047 symmetry and response-wide forced URL encoding regressions.
//!
//! Responsible for: executable coverage of metadata decode/encode safety and listing-wide URL encoding.
//! NOT responsible for: parser internals or generated source shape.
//! Upstream: the parent codec test helpers. Downstream: nothing; this is a leaf test module.

use super::*;

#[test]
fn n_encodes_a_key_xml_cannot_carry_even_though_nothing_asked() {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let mut output = one_entry_listing("ctrl\u{1}key.txt", "b28354b543375bfa94dabaeda722927f");
    let mut sibling = output.contents.first().cloned().expect("one entry");
    sibling.key = ObjectKey::new("with space.txt").expect("key");
    output.contents.push(sibling);
    output.key_count = 2;
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    let body = body_text(&response.body);
    assert!(!body.contains('\u{1}'), "{body}");
    assert!(body.contains("<Key>ctrl%01key.txt</Key>"), "{body}");
    assert!(body.contains("<Key>with%20space.txt</Key>"), "{body}");
    assert!(body.contains("<EncodingType>url</EncodingType>"), "{body}");
    assert!(body.contains("<Name>conf-list</Name>"), "unrelated members must remain present: {body}");
}

#[test]
fn n_forces_url_encoding_for_del_even_though_xml_can_carry_it() {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = one_entry_listing("del\u{7f}key.txt", "b28354b543375bfa94dabaeda722927f");
    let response = dto::ListObjectsV2::encode(output, &view, 200).expect("encodes");

    let body = body_text(&response.body);
    assert!(!body.contains('\u{7f}'), "{body}");
    assert!(body.contains("<Key>del%7Fkey.txt</Key>"), "{body}");
    assert!(body.contains("<EncodingType>url</EncodingType>"), "{body}");
}

#[test]
fn metadata_encoded_words_are_decoded_for_storage_and_encoded_again_on_return() {
    let request = accepted(
        "PUT",
        "/photos/key",
        &[("content-length", "0"), ("x-amz-meta-caption", "=?UTF-8?B?5Lit5paH?=")],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::PutObject::decode(&view, RequestBody::Buffered(Bytes::new())).expect("decodes");
    assert_eq!(input.metadata.get("caption").map(String::as_str), Some("\u{4e2d}\u{6587}"));

    let output = dto::GetObjectOutput {
        metadata: input.metadata,
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");
    assert_eq!(header(&response, "x-amz-meta-caption").as_deref(), Some("=?UTF-8?B?5Lit5paH?="));
}

#[test]
fn adjacent_metadata_encoded_words_drop_only_the_separator() {
    let request = accepted(
        "PUT",
        "/photos/key",
        &[
            ("content-length", "0"),
            ("x-amz-meta-caption", "=?UTF-8?B?5Lit?=   =?UTF-8?B?5paH?="),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::PutObject::decode(&view, RequestBody::Buffered(Bytes::new())).expect("decodes");
    assert_eq!(input.metadata.get("caption").map(String::as_str), Some("\u{4e2d}\u{6587}"));
}

#[test]
fn nested_metadata_encoded_word_is_reencoded_before_it_reaches_a_client() {
    let request = accepted(
        "PUT",
        "/photos/key",
        &[
            ("content-length", "0"),
            ("x-amz-meta-note", "=?UTF-8?B?PT9VVEYtOD9RPz0wRD0wQUluamVjdGVkOl95ZXM/PQ==?="),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::PutObject::decode(&view, RequestBody::Buffered(Bytes::new())).expect("decodes");
    assert_eq!(input.metadata.get("note").map(String::as_str), Some("=?UTF-8?Q?=0D=0AInjected:_yes?="));

    let output = dto::GetObjectOutput {
        metadata: input.metadata,
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");
    assert_eq!(
        header(&response, "x-amz-meta-note").as_deref(),
        Some("=?UTF-8?B?PT9VVEYtOD9RPz0wRD0wQUluamVjdGVkOl95ZXM/PQ==?=")
    );
}

#[test]
fn n_does_not_encode_a_metadata_control_character_into_a_safe_looking_header() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("bad".to_owned(), "before\tafter".to_owned());
    let output = dto::GetObjectOutput {
        metadata,
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("unsafe stored metadata is omitted");
    assert!(header(&response, "x-amz-meta-bad").is_none());
}

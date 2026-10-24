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

//! Response headers, metadata RFC 2047 symmetry and forced URL encoding regressions.
//!
//! Responsible for: metadata safety, response-header carriers and listing-wide URL encoding.
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

/// A stored value with a tab is written as an encoded word, not left out (rustfs/gateway#996): the
/// encoded form carries no control byte, so the header is safe, and the client decodes the value
/// that was stored, as it does from the s3s build RustFS runs today.
#[test]
fn n_writes_a_metadata_control_character_only_inside_an_encoded_word() {
    let request = accepted("GET", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("bad".to_owned(), "before\tafter".to_owned());
    metadata.insert("crlf".to_owned(), "a\r\nInjected: yes".to_owned());
    let output = dto::GetObjectOutput {
        metadata,
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");
    assert_eq!(header(&response, "x-amz-meta-bad").as_deref(), Some("=?UTF-8?B?YmVmb3JlCWFmdGVy?="));
    assert_eq!(
        header(&response, "x-amz-meta-crlf").as_deref(),
        Some("=?UTF-8?B?YQ0KSW5qZWN0ZWQ6IHllcw==?=")
    );
    assert!(header(&response, "injected").is_none(), "no header is split off the value");
}

const HEADERS: [&str; 7] = [
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-checksum-md5",
    "x-amz-checksum-sha512",
    "x-amz-checksum-xxhash3",
    "x-amz-checksum-xxhash64",
    "x-amz-checksum-xxhash128",
];
const VALUES: [&str; 7] = [
    "AES256",
    "key-md5",
    "raw-md5",
    "raw-sha512",
    "raw-xxhash3",
    "raw-xxhash64",
    "raw-xxhash128",
];

fn output(values: [Option<&str>; 7]) -> dto::CompleteMultipartUploadOutput {
    let [algorithm, key_md5, md5, sha512, xxhash3, xxhash64, xxhash128] = values;
    dto::CompleteMultipartUploadOutput {
        sse_customer_algorithm: algorithm.map(str::to_owned),
        sse_customer_key_md5: key_md5.map(str::to_owned),
        checksum_header_md5: md5.map(str::to_owned),
        checksum_header_sha512: sha512.map(str::to_owned),
        checksum_header_xxhash3: xxhash3.map(str::to_owned),
        checksum_header_xxhash64: xxhash64.map(str::to_owned),
        checksum_header_xxhash128: xxhash128.map(str::to_owned),
        checksum_md5: Some("xml-md5".to_owned()),
        checksum_sha512: Some("xml-sha512".to_owned()),
        ..Default::default()
    }
}

#[test]
fn complete_headers_keep_present_empty_and_missing_values_without_changing_xml() {
    let request = accepted("POST", "/photos/key?uploadId=upload", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let baseline = dto::CompleteMultipartUpload::encode(output([None; 7]), &view, 200).expect("baseline");
    let body = body_text(&baseline.body);
    let mut cases = vec![VALUES.map(Some), [Some(""); 7], [None; 7]];
    for missing in 0..HEADERS.len() {
        let mut values = VALUES.map(Some);
        *values.get_mut(missing).expect("the header index has a value slot") = None;
        cases.push(values);
    }
    for values in cases {
        let response = dto::CompleteMultipartUpload::encode(output(values), &view, 200).expect("encodes");
        let observed = HEADERS.map(|name| header(&response, name));
        assert_eq!(
            (observed, body_text(&response.body)),
            (values.map(|v| v.map(str::to_owned)), body.clone())
        );
    }
}

#[test]
fn complete_headers_are_bound_before_the_body_is_committed() {
    let headers = HEADERS
        .into_iter()
        .zip(VALUES)
        .map(|(name, value)| (http::HeaderName::from_static(name), http::HeaderValue::from_static(value)))
        .collect();
    assert!(crate::HeadPart::<dto::CompleteMultipartUpload>::new(headers).is_ok());
}

#[test]
fn migration_headers_keep_get_and_head_markers_explicit() {
    let get_request = accepted("GET", "/photos/key", &[]);
    let head_request = accepted("HEAD", "/photos/key", &[]);
    let get_view = MetaView::of(&get_request, TargetKind::Object).expect("get view");
    let head_view = MetaView::of(&head_request, TargetKind::Object).expect("head view");
    for value in [Some("source"), Some(""), None] {
        let get = dto::GetObject::encode(
            dto::GetObjectOutput {
                rustfs_on_demand_migration: value.map(str::to_owned),
                ..Default::default()
            },
            &get_view,
            200,
        )
        .expect("get response");
        let head = dto::HeadObject::encode(
            dto::HeadObjectOutput {
                rustfs_on_demand_migration: value.map(str::to_owned),
                ..Default::default()
            },
            &head_view,
            200,
        )
        .expect("head response");
        assert_eq!(
            [
                header(&get, "x-rustfs-on-demand-migration"),
                header(&head, "x-rustfs-on-demand-migration")
            ],
            [value.map(str::to_owned), value.map(str::to_owned)]
        );
    }
}

#[test]
fn migration_headers_keep_the_listing_marker_outside_the_xml() {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let baseline = dto::ListObjectsV2::encode(one_entry_listing("raw key", "tag"), &view, 200).expect("baseline");
    let body = body_text(&baseline.body);
    for value in [Some("local_only"), Some(""), None] {
        let mut output = one_entry_listing("raw key", "tag");
        output.rustfs_on_demand_migration_list = value.map(str::to_owned);
        let response = dto::ListObjectsV2::encode(output, &view, 200).expect("listing response");
        assert_eq!(
            (header(&response, "x-rustfs-on-demand-migration-list"), body_text(&response.body)),
            (value.map(str::to_owned), body.clone())
        );
    }
}

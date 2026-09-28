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

//! Comma-delimited list headers, decoded from the IR's delimited `List` form.
//!
//! Responsible for: `x-amz-object-attributes` and `x-amz-optional-object-attributes` reaching a
//! handler as the list the model declares, not as one opaque string and not dropped.
//! NOT responsible for: what a handler does with an attribute name it does not recognise; the
//! element type is an open enumeration, so an unknown name survives decoding by design.
//! Upstream: the generated decoders of `GetObjectAttributes` and the three listing operations.
//! Downstream: nothing.

use super::*;

fn object_attributes(headers: &[(&str, &str)]) -> Result<Vec<String>, crate::codec::CodecError> {
    let request = accepted("GET", "/bucket/key?attributes", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    dto::GetObjectAttributes::decode(&view, RequestBody::None).map(|input| {
        input
            .object_attributes
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect()
    })
}

#[test]
fn splits_the_attribute_header_into_its_members() {
    let decoded = object_attributes(&[("x-amz-object-attributes", "ETag,Checksum,ObjectParts")]).expect("decodes");
    assert_eq!(decoded, ["ETag", "Checksum", "ObjectParts"]);
}

#[test]
fn n_optional_whitespace_around_a_member_is_not_part_of_it() {
    let decoded = object_attributes(&[("x-amz-object-attributes", " ETag ,\tObjectSize\t")]).expect("decodes");
    assert_eq!(decoded, ["ETag", "ObjectSize"]);
}

#[test]
fn n_repeated_field_lines_are_one_list() {
    let decoded = object_attributes(&[
        ("x-amz-object-attributes", "ETag"),
        ("x-amz-object-attributes", "StorageClass"),
    ])
    .expect("decodes");
    assert_eq!(decoded, ["ETag", "StorageClass"]);
}

#[test]
fn n_empty_list_elements_are_not_members() {
    let decoded = object_attributes(&[("x-amz-object-attributes", ",ETag,,ObjectSize,")]).expect("decodes");
    assert_eq!(decoded, ["ETag", "ObjectSize"], "RFC 9110 5.6.1: empty list elements do not count");
}

#[test]
fn n_an_absent_required_list_header_is_the_operation_s_refusal() {
    let error = object_attributes(&[]).expect_err("x-amz-object-attributes is required");
    assert_eq!((error.code().as_str(), error.member()), ("InvalidRequest", Some("ObjectAttributes")));
}

#[test]
fn n_a_member_the_model_does_not_name_survives_as_an_open_value() {
    let decoded = object_attributes(&[("x-amz-object-attributes", "ETag,FutureAttribute")]).expect("decodes");
    assert_eq!(decoded, ["ETag", "FutureAttribute"]);
}

#[test]
fn the_listing_operations_read_the_optional_attribute_header() {
    let request = accepted("GET", "/bucket?list-type=2", &[("x-amz-optional-object-attributes", "RestoreStatus")]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("decodes");
    let names: Vec<&str> = input.optional_object_attributes.iter().map(|value| value.as_str()).collect();
    assert_eq!(names, ["RestoreStatus"]);

    let request = accepted("GET", "/bucket", &[("x-amz-optional-object-attributes", "RestoreStatus")]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjects::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.optional_object_attributes.len(), 1);

    let request = accepted("GET", "/bucket?versions", &[("x-amz-optional-object-attributes", "RestoreStatus")]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjectVersions::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.optional_object_attributes.len(), 1);
}

#[test]
fn n_an_absent_optional_list_header_is_an_empty_list() {
    let request = accepted("GET", "/bucket?list-type=2", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let input = dto::ListObjectsV2::decode(&view, RequestBody::None).expect("decodes");
    assert!(input.optional_object_attributes.is_empty());
}

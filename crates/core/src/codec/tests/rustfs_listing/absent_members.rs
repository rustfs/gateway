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

//! A listing entry's `LastModified` or `StorageClass` the host does not hold (rustfs/gateway#1613).
//!
//! Responsible for: under the RustFS response layout, an `Object`, `ObjectVersion` or
//! `DeleteMarkerEntry` whose member still holds its placeholder is written without that element
//! and every other byte as the same entry with the member set; a set member written as today;
//! `Size` and every other required member outside the five written as before; and the default
//! layout's answer to a placeholder pinned unchanged.
//! NOT responsible for: how a host comes to hold the placeholder (the migration seam's
//! `AbsentAsPlaceholder` rule), or which assembly selects the layout (`rustfs-gateway`).
//! Upstream: the generated listing encoders. Downstream: nothing.

use rustfs_gateway_types::TimestampFormat;

use super::*;

const TIMES: [i64; 3] = [1_767_322_745, 1_767_322_746, 1_767_322_747];

fn instant(index: usize) -> Timestamp {
    Timestamp::from_secs(*TIMES.get(index).expect("a fixture index"))
}

fn spelled(index: usize) -> String {
    crate::codec::value::render_timestamp(&instant(index), TimestampFormat::Iso8601).expect("a fixture instant renders")
}

const CLASSES: [&str; 3] = ["STANDARD", "GLACIER", "STANDARD_IA"];

fn class(index: usize) -> dto::StorageClass {
    dto::StorageClass::custom((*CLASSES.get(index).expect("a fixture index")).to_owned())
}

fn view_of<'a>(request: &'a WireRequest<()>, rustfs: bool) -> MetaView<'a> {
    let view = MetaView::of(request, TargetKind::Bucket).expect("view");
    if rustfs { view.with_rustfs_response_layout() } else { view }
}

/// Which member of the middle entry the host does not hold.
#[derive(Clone, Copy)]
enum Absent {
    None,
    LastModified,
    StorageClass,
}

fn objects(absent: Absent) -> Vec<dto::Object> {
    (0..3)
        .map(|index| {
            let mut entry = dto::Object {
                key: ObjectKey::new(format!("entry-{index}")).expect("key"),
                e_tag: Some(ETag::new(format!("tag-{index}")).expect("a fixture tag")),
                last_modified: instant(index),
                size: 7,
                storage_class: class(index),
                ..Default::default()
            };
            if index == 1 {
                match absent {
                    Absent::None => {}
                    Absent::LastModified => entry.last_modified = Timestamp::default(),
                    Absent::StorageClass => entry.storage_class = dto::StorageClass::default(),
                }
            }
            entry
        })
        .collect()
}

fn encode_v2(absent: Absent, rustfs: bool) -> Result<String, crate::codec::CodecError> {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let output = dto::ListObjectsV2Output {
        name: BucketName::new("conf-list").expect("bucket"),
        key_count: 3,
        max_keys: 1000,
        contents: objects(absent),
        ..Default::default()
    };
    dto::ListObjectsV2::encode(output, &view_of(&request, rustfs), 200).map(|response| body_text(&response.body))
}

fn encode_v1(absent: Absent, rustfs: bool) -> Result<String, crate::codec::CodecError> {
    let request = accepted("GET", "/conf-list", &[]);
    let output = dto::ListObjectsOutput {
        name: BucketName::new("conf-list").expect("bucket"),
        max_keys: 1000,
        contents: objects(absent),
        ..Default::default()
    };
    dto::ListObjects::encode(output, &view_of(&request, rustfs), 200).map(|response| body_text(&response.body))
}

/// Three versions and three delete markers; `absent` empties the middle one of each.
fn encode_versions(absent: Absent, rustfs: bool) -> Result<String, crate::codec::CodecError> {
    let request = accepted("GET", "/conf-list?versions", &[]);
    let versions = (0..3)
        .map(|index| {
            let mut entry = dto::ObjectVersion {
                key: ObjectKey::new("entry").expect("key"),
                version_id: format!("version-{index}").into(),
                is_latest: index == 0,
                last_modified: instant(index),
                size: 7,
                storage_class: class(index),
                ..Default::default()
            };
            if index == 1 {
                match absent {
                    Absent::None => {}
                    Absent::LastModified => entry.last_modified = Timestamp::default(),
                    Absent::StorageClass => entry.storage_class = dto::StorageClass::default(),
                }
            }
            entry
        })
        .collect();
    let delete_markers = (0..3)
        .map(|index| dto::DeleteMarkerEntry {
            key: ObjectKey::new("marker").expect("key"),
            version_id: format!("marker-{index}").into(),
            is_latest: false,
            last_modified: if index == 1 && matches!(absent, Absent::LastModified) {
                Timestamp::default()
            } else {
                instant(index)
            },
            ..Default::default()
        })
        .collect();
    let output = dto::ListObjectVersionsOutput {
        name: BucketName::new("conf-list").expect("bucket"),
        version_id_marker: "".into(),
        max_keys: 1000,
        versions,
        delete_markers,
        ..Default::default()
    };
    dto::ListObjectVersions::encode(output, &view_of(&request, rustfs), 200).map(|response| body_text(&response.body))
}

/// The present document with the one element removed, `count` times: what an absent member must
/// produce, so every other byte is held, not only the missing element.
fn without(present: &str, element: &str, count: usize) -> String {
    assert_eq!(
        present.matches(element).count(),
        count,
        "the fixture spells {element} {count} time(s): {present}"
    );
    present.replace(element, "")
}

fn last_modified_element() -> String {
    format!("<LastModified>{}</LastModified>", spelled(1))
}

#[test]
fn n_a_listing_entry_without_last_modified_omits_only_that_element() {
    let present = encode_v2(Absent::None, true).expect("encodes");
    let absent = encode_v2(Absent::LastModified, true).expect("an absent LastModified is not a failed listing");
    assert_eq!(absent, without(&present, &last_modified_element(), 1));
}

#[test]
fn n_a_listing_entry_without_storage_class_omits_only_that_element() {
    let present = encode_v2(Absent::None, true).expect("encodes");
    let absent = encode_v2(Absent::StorageClass, true).expect("encodes");
    assert_eq!(absent, without(&present, "<StorageClass>GLACIER</StorageClass>", 1));
}

#[test]
fn n_a_first_version_listing_entry_without_last_modified_omits_only_that_element() {
    let present = encode_v1(Absent::None, true).expect("encodes");
    let absent = encode_v1(Absent::LastModified, true).expect("an absent LastModified is not a failed listing");
    assert_eq!(absent, without(&present, &last_modified_element(), 1));
}

#[test]
fn n_a_first_version_listing_entry_without_storage_class_omits_only_that_element() {
    let present = encode_v1(Absent::None, true).expect("encodes");
    let absent = encode_v1(Absent::StorageClass, true).expect("encodes");
    assert_eq!(absent, without(&present, "<StorageClass>GLACIER</StorageClass>", 1));
}

#[test]
fn n_a_version_and_a_delete_marker_without_last_modified_omit_only_that_element() {
    let present = encode_versions(Absent::None, true).expect("encodes");
    let absent = encode_versions(Absent::LastModified, true).expect("an absent LastModified is not a failed listing");
    // The middle version and the middle marker carry the same instant, and both lose it.
    assert_eq!(absent, without(&present, &last_modified_element(), 2));
}

#[test]
fn n_a_version_without_storage_class_omits_only_that_element() {
    let present = encode_versions(Absent::None, true).expect("encodes");
    let absent = encode_versions(Absent::StorageClass, true).expect("encodes");
    assert_eq!(absent, without(&present, "<StorageClass>GLACIER</StorageClass>", 1));
}

#[test]
fn present_members_render_as_today_under_the_rustfs_layout() {
    for body in [
        encode_v2(Absent::None, true),
        encode_v1(Absent::None, true),
        encode_versions(Absent::None, true),
    ] {
        let body = body.expect("encodes");
        for (index, class) in CLASSES.iter().enumerate() {
            assert!(body.contains(&format!("<LastModified>{}</LastModified>", spelled(index))), "{body}");
            assert!(body.contains(&format!("<StorageClass>{class}</StorageClass>")), "{body}");
        }
        assert!(body.contains("<Size>7</Size>"), "{body}");
    }
}

#[test]
fn n_the_default_layout_still_refuses_an_absent_last_modified() {
    for refused in [
        encode_v2(Absent::LastModified, false),
        encode_v1(Absent::LastModified, false),
        encode_versions(Absent::LastModified, false),
    ] {
        let error = refused.expect_err("the model requires LastModified, and the default layout keeps refusing");
        assert_eq!(error.status().as_u16(), 500, "{error:?}");
    }
}

#[test]
fn n_the_default_layout_still_writes_an_absent_storage_class_as_an_empty_element() {
    for body in [
        encode_v2(Absent::StorageClass, false),
        encode_v1(Absent::StorageClass, false),
        encode_versions(Absent::StorageClass, false),
    ] {
        let body = body.expect("encodes, as it did before");
        assert!(body.contains("<StorageClass></StorageClass>"), "{body}");
    }
}

#[test]
fn n_a_zero_size_is_a_value_and_is_still_written() {
    let request = accepted("GET", "/conf-list?list-type=2", &[]);
    let mut contents = objects(Absent::LastModified);
    if let Some(middle) = contents.get_mut(1) {
        middle.size = 0;
    }
    let output = dto::ListObjectsV2Output {
        name: BucketName::new("conf-list").expect("bucket"),
        key_count: 3,
        max_keys: 1000,
        contents,
        ..Default::default()
    };
    let body = body_text(
        &dto::ListObjectsV2::encode(output, &view_of(&request, true), 200)
            .expect("encodes")
            .body,
    );
    assert!(body.contains("<Size>0</Size>"), "Size stays required: {body}");
}

#[test]
fn n_a_required_timestamp_outside_the_listing_entries_is_still_refused_under_the_rustfs_layout() {
    let request = accepted("GET", "/", &[]);
    let view = MetaView::of(&request, TargetKind::Service)
        .expect("view")
        .with_rustfs_response_layout();
    let output = dto::ListBucketsOutput {
        buckets: vec![dto::Bucket {
            name: BucketName::new("conf-list").expect("bucket"),
            creation_date: Timestamp::default(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let error = dto::ListBuckets::encode(output, &view, 200).expect_err("the rule names five members, not every placeholder");
    assert_eq!(error.status().as_u16(), 500, "{error:?}");
}

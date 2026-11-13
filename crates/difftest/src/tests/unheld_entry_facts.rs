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

//! A listing entry fact a RustFS app body leaves unset, from the legacy output to the wire
//! (rustfs/gateway#1613).
//!
//! Responsible for: a legacy `Object` without `LastModified` or `StorageClass`, converted through
//! the production seam and written by the production encoder under the RustFS response layout,
//! answering the listing with that element omitted and the neighbouring entry intact; the same
//! output under the default layout still failing; a legacy value spelled as the placeholder refused
//! by the seam rather than written as unheld.
//! NOT responsible for: the seam's or the encoder's rules alone (`rustfs-gateway-types`'
//! `reverse_tests`, `rustfs-gateway-core`'s `rustfs_listing::absent_members`).
//! Upstream: `compat::s3s_0_17_0`, the generated `ListObjectsV2` codec. Downstream: none.

use rustfs_gateway::dto;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::compat::s3s_0_17_0 as seam;

use crate::s3s::dto as legacy;

fn entry(key: &str, last_modified: bool, storage_class: bool) -> legacy::Object {
    let at = seam::leaf::timestamp_to_s3s("t", rustfs_gateway_types::Timestamp::from_secs(1_700_000_000)).expect("instant");
    legacy::Object {
        key: Some(key.to_owned()),
        last_modified: last_modified.then_some(at),
        size: Some(5),
        storage_class: storage_class.then(|| legacy::ObjectStorageClass::from("STANDARD".to_owned())),
        ..Default::default()
    }
}

fn listing(contents: Vec<legacy::Object>) -> legacy::ListObjectsV2Output {
    legacy::ListObjectsV2Output {
        name: Some("bucket".to_owned()),
        prefix: Some(String::new()),
        max_keys: Some(1000),
        key_count: Some(i32::try_from(contents.len()).expect("small")),
        is_truncated: Some(false),
        contents: Some(contents),
        ..Default::default()
    }
}

/// The legacy output through the seam and the encoder, under the RustFS layout or the default.
fn answer(output: legacy::ListObjectsV2Output, rustfs: bool) -> Result<String, CodecError> {
    let request = http::Request::builder()
        .method("GET")
        .uri("http://host.invalid/bucket?list-type=2")
        .header("host", "host.invalid")
        .body(())
        .expect("request");
    let request = WireRequest::accept(request, &Limits::default()).expect("accepted");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let view = if rustfs { view.with_rustfs_response_layout() } else { view };
    let output = seam::generated::ops::list_objects_v2::output_from_s3s(output).expect("the seam takes an unheld fact");
    let response = dto::ListObjectsV2::encode(output, &view, 200)?;
    match response.body {
        ResponseBody::Complete(bytes) => Ok(String::from_utf8(bytes).expect("utf-8")),
        _ => panic!("a listing is a complete document"),
    }
}

fn entries(body: &str) -> Vec<&str> {
    body.split("<Contents>")
        .skip(1)
        .map(|tail| tail.split_once("</Contents>").expect("closed").0)
        .collect()
}

#[test]
fn n_an_unset_legacy_last_modified_is_omitted_on_the_wire() {
    let body = answer(listing(vec![entry("held", true, true), entry("unheld", false, true)]), true).expect("answers 200");
    let [held, unheld] = entries(&body)[..] else { panic!("two entries: {body}") };
    assert!(held.contains("<LastModified>2023-11-14T22:13:20.000Z</LastModified>"), "{body}");
    assert!(!unheld.contains("LastModified"), "{body}");
    assert!(
        unheld.contains("<Size>5</Size>") && unheld.contains("<StorageClass>STANDARD</StorageClass>"),
        "{body}"
    );
}

#[test]
fn n_an_unset_legacy_storage_class_is_omitted_on_the_wire() {
    let body = answer(listing(vec![entry("held", true, true), entry("unheld", true, false)]), true).expect("answers 200");
    let [held, unheld] = entries(&body)[..] else { panic!("two entries: {body}") };
    assert!(held.contains("<StorageClass>STANDARD</StorageClass>"), "{body}");
    assert!(!unheld.contains("StorageClass"), "{body}");
    assert!(unheld.contains("<LastModified>"), "{body}");
}

#[test]
fn n_the_default_layout_still_refuses_the_unset_last_modified() {
    let error = answer(listing(vec![entry("unheld", false, true)]), false).expect_err("the default layout refuses");
    assert_eq!(error.status().as_u16(), 500);
}

#[test]
fn n_a_legacy_storage_class_spelled_as_the_placeholder_is_refused_by_the_seam() {
    let mut nul = entry("k", true, true);
    nul.storage_class = Some(legacy::ObjectStorageClass::from("\u{0}".to_owned()));
    let error = seam::generated::ops::list_objects_v2::output_from_s3s(listing(vec![nul])).expect_err("refused, not omitted");
    assert_eq!(error.field, "storage_class");
}

#[test]
fn held_facts_reach_the_wire_as_before() {
    let body = answer(listing(vec![entry("held", true, true)]), true).expect("answers 200");
    assert!(body.contains("<LastModified>2023-11-14T22:13:20.000Z</LastModified>"), "{body}");
    assert!(body.contains("<StorageClass>STANDARD</StorageClass>"), "{body}");
}

/// The answer-side proof `seam_overrides` holds every `AbsentAsPlaceholder` override to: in each
/// listing output that carries the entry, an unset `"last_modified"` and an unset
/// `"storage_class"` cross as the placeholder and back as unset, and nothing else moves.
#[test]
fn every_unheld_entry_fact_crosses_as_the_placeholder_and_back_as_unset() {
    // The overrides this proves, by legacy member: "last_modified" and "storage_class".
    use rustfs_gateway_types::WirePlaceholder as _;
    use seam::generated::ops;
    let at = seam::leaf::timestamp_to_s3s("t", rustfs_gateway_types::Timestamp::from_secs(1_700_000_000)).expect("instant");

    let v2 = ops::list_objects_v2::output_from_s3s(listing(vec![entry("k", false, false)])).expect("ListObjectsV2Output");
    assert!(v2.contents[0].last_modified.is_wire_placeholder() && v2.contents[0].storage_class.is_wire_placeholder());
    let back = ops::list_objects_v2::output_to_s3s(v2).expect("back");
    let object = &back.contents.expect("entries")[0];
    assert_eq!(
        (object.last_modified.as_ref(), object.storage_class.as_ref(), object.size),
        (None, None, Some(5))
    );

    let v1 = legacy::ListObjectsOutput {
        name: Some("bucket".to_owned()),
        prefix: Some(String::new()),
        marker: Some(String::new()),
        max_keys: Some(1000),
        is_truncated: Some(false),
        contents: Some(vec![entry("k", false, false)]),
        ..Default::default()
    };
    let v1 = ops::list_objects::output_from_s3s(v1).expect("ListObjectsOutput");
    assert!(v1.contents[0].last_modified.is_wire_placeholder() && v1.contents[0].storage_class.is_wire_placeholder());
    let back = ops::list_objects::output_to_s3s(v1).expect("back");
    let object = &back.contents.expect("entries")[0];
    assert_eq!((object.last_modified.as_ref(), object.storage_class.as_ref()), (None, None));

    let versions = legacy::ListObjectVersionsOutput {
        name: Some("bucket".to_owned()),
        prefix: Some(String::new()),
        key_marker: Some(String::new()),
        version_id_marker: Some(String::new()),
        max_keys: Some(1000),
        is_truncated: Some(false),
        versions: Some(vec![legacy::ObjectVersion {
            key: Some("k".to_owned()),
            version_id: Some("v".to_owned()),
            is_latest: Some(true),
            size: Some(5),
            ..Default::default()
        }]),
        delete_markers: Some(vec![
            legacy::DeleteMarkerEntry {
                key: Some("k".to_owned()),
                version_id: Some("m".to_owned()),
                is_latest: Some(false),
                ..Default::default()
            },
            legacy::DeleteMarkerEntry {
                key: Some("k".to_owned()),
                version_id: Some("n".to_owned()),
                is_latest: Some(false),
                last_modified: Some(at),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };
    let gateway = ops::list_object_versions::output_from_s3s(versions).expect("ListObjectVersionsOutput");
    assert!(gateway.versions[0].last_modified.is_wire_placeholder() && gateway.versions[0].storage_class.is_wire_placeholder());
    assert!(gateway.delete_markers[0].last_modified.is_wire_placeholder());
    assert!(!gateway.delete_markers[1].last_modified.is_wire_placeholder());
    let back = ops::list_object_versions::output_to_s3s(gateway).expect("back");
    let version = &back.versions.expect("versions")[0];
    assert_eq!((version.last_modified.as_ref(), version.storage_class.as_ref()), (None, None));
    let markers = back.delete_markers.expect("markers");
    assert!(markers[0].last_modified.is_none() && markers[1].last_modified.is_some());
}

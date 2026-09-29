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

//! Tests for the generated member census against the pinned legacy structures.
//!
//! Responsible for: proving `differences` names exactly the member paths two values differ at —
//! nested structures member by member, lists element by element, a one-sided option or a list of
//! another length as a whole — and nothing else, that `present` names exactly the members a value
//! holds, and that every path either names is one `PATHS` lists.
//! NOT responsible for: what a difference means; the difftest seam diff decides that
//! (rustfs/gateway#1076). Upstream: `super::generated::census`. Downstream: none; test-only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::generated::census;
use super::s3s::dto as legacy;

fn identifier(key: &str, version: Option<&str>) -> legacy::ObjectIdentifier {
    legacy::ObjectIdentifier {
        key: key.to_owned(),
        version_id: version.map(str::to_owned),
        ..Default::default()
    }
}

fn delete(objects: Vec<legacy::ObjectIdentifier>) -> legacy::DeleteObjectsInput {
    legacy::DeleteObjectsInput {
        bucket: "bucket".to_owned(),
        bypass_governance_retention: None,
        checksum_algorithm: None,
        delete: legacy::Delete { objects, quiet: None },
        expected_bucket_owner: None,
        mfa: None,
        request_payer: None,
    }
}

fn differences(left: &legacy::DeleteObjectsInput, right: &legacy::DeleteObjectsInput) -> Vec<String> {
    let mut out = Vec::new();
    census::delete_objects_input::differences("", left, right, &mut out);
    out
}

/// A reported path with its list indices dropped, as `PATHS` spells it.
fn unindexed(path: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for character in path.chars() {
        match character {
            '[' => {
                skipping = true;
                out.push('[');
            }
            ']' => {
                skipping = false;
                out.push(']');
            }
            _ if skipping => {}
            other => out.push(other),
        }
    }
    out
}

#[test]
fn a_list_element_differing_in_one_member_is_named_by_index_and_member() {
    let left = delete(vec![identifier("a", None), identifier("b", Some("v1"))]);
    let right = delete(vec![identifier("a", None), identifier("b", Some("v2"))]);
    assert_eq!(differences(&left, &right), ["delete.objects[1].version_id"]);
}

#[test]
fn n_equal_values_differ_nowhere() {
    let value = delete(vec![identifier("a", Some("v1"))]);
    assert!(differences(&value, &value.clone()).is_empty());
}

#[test]
fn n_a_list_of_another_length_differs_as_a_whole_not_per_element() {
    let left = delete(vec![identifier("a", None)]);
    let right = delete(vec![identifier("a", None), identifier("b", None)]);
    assert_eq!(differences(&left, &right), ["delete.objects"]);
}

#[test]
fn n_a_one_sided_optional_structure_differs_as_a_whole() {
    let left = legacy::PutBucketLifecycleConfigurationInput {
        bucket: "bucket".to_owned(),
        ..Default::default()
    };
    let right = legacy::PutBucketLifecycleConfigurationInput {
        lifecycle_configuration: Some(legacy::BucketLifecycleConfiguration::default()),
        ..left.clone()
    };
    let mut out = Vec::new();
    census::put_bucket_lifecycle_configuration_input::differences("", &left, &right, &mut out);
    assert_eq!(out, ["lifecycle_configuration"]);
}

#[test]
fn n_a_differing_body_is_left_to_the_diff_that_drains_it() {
    let left = legacy::UploadPartInput {
        bucket: "bucket".to_owned(),
        key: "k".to_owned(),
        body: Some(legacy::StreamingBlob::from(bytes::Bytes::from_static(b"one"))),
        ..Default::default()
    };
    let right = legacy::UploadPartInput {
        body: Some(legacy::StreamingBlob::from(bytes::Bytes::from_static(b"two"))),
        bucket: "bucket".to_owned(),
        key: "k".to_owned(),
        ..Default::default()
    };
    let mut out = Vec::new();
    census::upload_part_input::differences("", &left, &right, &mut out);
    assert!(out.is_empty(), "{out:?}");
    assert!(!census::upload_part_input::PATHS.contains(&"body"));
}

#[test]
fn present_names_required_members_and_only_the_optional_ones_set() {
    let value = delete(vec![identifier("a", Some("v1")), identifier("b", None)]);
    let mut out = Vec::new();
    census::delete_objects_input::present("", &value, &mut out);
    assert_eq!(
        out,
        [
            "bucket",
            "delete.objects[].key",
            "delete.objects[].version_id",
            "delete.objects[].key",
        ]
    );
    let mut defaulted = Vec::new();
    census::delete_objects_input::present("", &delete(Vec::new()), &mut defaulted);
    assert_eq!(defaulted, ["bucket"], "an empty list and unset options name nothing");
}

#[test]
fn n_no_reported_path_is_missing_from_the_census() {
    let mut value = delete(vec![identifier("a", Some("v1"))]);
    value.bypass_governance_retention = Some(true);
    value.delete.quiet = Some(true);
    value.delete.objects[0].e_tag = Some(legacy::ETag::Strong("x".to_owned()));
    let mut present = Vec::new();
    census::delete_objects_input::present("", &value, &mut present);
    let mut differing = Vec::new();
    census::delete_objects_input::differences("", &value, &delete(vec![identifier("b", None)]), &mut differing);
    for path in present.iter().chain(&differing) {
        assert!(
            census::delete_objects_input::PATHS.contains(&unindexed(path).as_str()),
            "{path} is not in PATHS"
        );
    }
    assert!(present.contains(&"delete.objects[].e_tag".to_owned()));
}

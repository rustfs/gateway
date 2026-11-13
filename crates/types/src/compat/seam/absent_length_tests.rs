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

//! Tests for an upload's undeclared length crossing the seam from s3s (rustfs/gateway#1616),
//! compiled once per seam revision that mounts the generated tree.
//!
//! Responsible for: proving PutObject and UploadPart hand an absent `Content-Length` back in their
//! `LegacyInput` instead of refusing it, hand a declared one back as declared, still refuse a
//! negative one, and leave the gateway → s3s direction as it was. NOT responsible for: the
//! gateway's own decoder, which always has a length. Upstream: `super::put_object`,
//! `super::generated`. Downstream: none; test-only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::generated::ops;
use super::put_object;
use super::s3s::dto as oracle;
use crate::{BucketName, ObjectKey};

fn put(content_length: Option<i64>) -> oracle::PutObjectInput {
    oracle::PutObjectInput {
        bucket: "bucket".to_owned(),
        key: "k".to_owned(),
        content_length,
        ..Default::default()
    }
}

fn part(content_length: Option<i64>) -> oracle::UploadPartInput {
    oracle::UploadPartInput {
        bucket: "bucket".to_owned(),
        key: "k".to_owned(),
        part_number: 1,
        upload_id: "id-1".to_owned(),
        content_length,
        ..Default::default()
    }
}

#[test]
fn a_put_without_a_length_converts_and_reports_it_absent() {
    let (_, legacy) = put_object::input_from_s3s(put(None)).expect("an undeclared length is handed back");
    assert_eq!(legacy.content_length, None);
}

#[test]
fn a_put_with_a_length_converts_and_reports_it_declared() {
    let (gateway, legacy) = put_object::input_from_s3s(put(Some(4))).expect("converts");
    assert_eq!((gateway.content_length, legacy.content_length), (4, Some(4)));
}

#[test]
fn an_upload_part_without_a_length_converts_and_reports_it_absent() {
    let (_, legacy) = ops::upload_part::input_from_s3s(part(None)).expect("an undeclared length is handed back");
    assert_eq!(legacy.content_length, None);
}

#[test]
fn an_upload_part_with_a_length_converts_and_reports_it_declared() {
    let (gateway, legacy) = ops::upload_part::input_from_s3s(part(Some(4))).expect("converts");
    assert_eq!((gateway.content_length, legacy.content_length), (4, Some(4)));
}

#[test]
fn n_a_declared_zero_is_never_reported_absent() {
    let (gateway, legacy) = put_object::input_from_s3s(put(Some(0))).expect("converts");
    assert_eq!((gateway.content_length, legacy.content_length), (0, Some(0)));
    let (gateway, legacy) = ops::upload_part::input_from_s3s(part(Some(0))).expect("converts");
    assert_eq!((gateway.content_length, legacy.content_length), (0, Some(0)));
}

#[test]
fn n_a_negative_put_length_is_refused_by_member() {
    for length in [-1, i64::MIN] {
        let error = put_object::input_from_s3s(put(Some(length))).expect_err("negative");
        assert_eq!(error.field, "content_length");
    }
}

#[test]
fn n_a_negative_upload_part_length_is_refused_by_member() {
    for length in [-1, i64::MIN] {
        let error = ops::upload_part::input_from_s3s(part(Some(length))).expect_err("negative");
        assert_eq!(error.field, "content_length");
    }
}

#[test]
fn n_an_absent_length_does_not_hide_another_refusal() {
    let mut input = put(None);
    input.bucket = "Bad Bucket!".to_owned();
    assert_eq!(put_object::input_from_s3s(input).expect_err("bucket").field, "bucket");
    let mut input = part(None);
    input.bucket = "Bad Bucket!".to_owned();
    assert_eq!(ops::upload_part::input_from_s3s(input).expect_err("bucket").field, "bucket");
}

#[test]
fn n_the_gateway_to_s3s_direction_always_declares_its_length() {
    for length in [0, 7] {
        let input = crate::dto::PutObjectInput {
            bucket: BucketName::new("bucket").expect("bucket"),
            key: ObjectKey::new("k").expect("key"),
            content_length: length,
            ..Default::default()
        };
        assert_eq!(put_object::input_to_s3s(input).expect("converts").content_length, Some(length));
        let input = crate::ops::upload_part::Input {
            bucket: BucketName::new("bucket").expect("bucket"),
            key: ObjectKey::new("k").expect("key"),
            part_number: 1,
            upload_id: crate::UploadIdClaim::from_wire("id-1"),
            content_length: length,
            ..Default::default()
        };
        assert_eq!(ops::upload_part::input_to_s3s(input).expect("converts").content_length, Some(length));
    }
}

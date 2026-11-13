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

//! Tests for names crossing the seam from s3s (rustfs/gateway#1610), compiled once per seam
//! revision that mounts the generated tree.
//!
//! Responsible for: proving a bucket name s3s already admitted crosses under the floor alone, at
//! the leaf, through generated input and output conversions and through the hand-written ones,
//! and that a name or key below its floor is refused with its typed kind while every other refusal
//! carries none. NOT responsible for: the floor itself, which `crate::scalar::naming` tests own.
//! Upstream: `super::leaf`, `super::generated`, `super::put_object`, `super::get_bucket_location`.
//! Downstream: none; test-only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::generated::ops;
use super::s3s::dto as oracle;
use super::{get_bucket_location, leaf, put_object};
use crate::BucketName;
use crate::compat::{ConversionError, NameRefusal};

/// Names the AWS grammar reserves or refuses and the floor admits: a host stores and serves them.
const ABOVE_FLOOR: [&str; 5] = ["sthree-x", "a-s3alias", "x--ol-s3", "x--x-s3", "192.168.5.4"];

/// Bucket names below the floor, one per floor rule.
fn below_floor_buckets() -> Vec<String> {
    vec![
        String::new(),
        "ab".to_owned(),
        "a".repeat(64),
        "has space".to_owned(),
        "bkt/key".to_owned(),
        "pct%41x".to_owned(),
        "nul\0x".to_owned(),
    ]
}

/// Object keys below the key floor.
fn below_floor_keys() -> Vec<String> {
    vec![String::new(), "a\0b".to_owned(), "k".repeat(1025)]
}

fn epoch() -> oracle::Timestamp {
    oracle::Timestamp::parse(oracle::TimestampFormat::EpochSeconds, "0").expect("epoch")
}

/// A listing of one bucket, with every other member the gateway output requires.
fn listing(name: &str) -> oracle::ListBucketsOutput {
    oracle::ListBucketsOutput {
        buckets: Some(vec![oracle::Bucket {
            name: Some(name.to_owned()),
            creation_date: Some(epoch()),
            ..Default::default()
        }]),
        owner: Some(oracle::Owner::default()),
        ..Default::default()
    }
}

fn is_bucket(error: &ConversionError) -> bool {
    matches!(error.name_kind(), Some(NameRefusal::BucketName))
}

fn is_key(error: &ConversionError) -> bool {
    matches!(error.name_kind(), Some(NameRefusal::ObjectKey))
}

#[test]
fn a_name_the_aws_grammar_refuses_and_the_floor_admits_crosses_byte_for_byte() {
    for name in ABOVE_FLOOR {
        // Control: each is a name the strict constructor refuses, so the crossing is not vacuous.
        assert!(BucketName::new(name).is_err(), "{name} must be outside the AWS grammar");
        let crossed = leaf::bucket_name("bucket", name.to_owned()).expect(name);
        assert_eq!(crossed.as_str().as_bytes(), name.as_bytes());
    }
}

#[test]
fn n_a_bucket_name_below_the_floor_is_refused_with_the_bucket_kind() {
    for name in below_floor_buckets() {
        let error = leaf::bucket_name("bucket", name.clone()).expect_err(&format!("{name:?}"));
        assert_eq!(error.field, "bucket");
        assert!(is_bucket(&error), "{name:?}: {error}");
    }
}

#[test]
fn n_an_object_key_below_the_floor_is_refused_with_the_key_kind() {
    for key in below_floor_keys() {
        let error = leaf::object_key("key", key.clone()).expect_err("below the key floor");
        assert_eq!(error.field, "key");
        assert!(is_key(&error), "{} bytes: {error}", key.len());
    }
}

#[test]
fn n_a_refusal_that_is_not_a_name_reports_no_name_kind() {
    let refusals = [
        leaf::parse_i32("part_number_marker", "x1").expect_err("number"),
        leaf::etag_from_s3s("e_tag", oracle::ETag::Strong("a\u{1}b".to_owned())).expect_err("tag"),
        leaf::copy_source_to_s3s("copy_source", "").expect_err("copy source"),
        ConversionError {
            field: "bucket",
            reason: "a reason no name leaf gives",
        },
    ];
    for error in refusals {
        assert!(error.name_kind().is_none(), "{error}");
    }
}

#[test]
fn a_generated_input_and_output_carry_an_above_floor_name_both_ways() {
    for name in ABOVE_FLOOR {
        let input = oracle::HeadBucketInput {
            bucket: name.to_owned(),
            ..Default::default()
        };
        let gateway = ops::head_bucket::input_from_s3s(input).expect(name);
        assert_eq!(gateway.bucket.as_str(), name);
        assert_eq!(ops::head_bucket::input_to_s3s(gateway).expect("back").bucket, name);

        let listing = listing(name);
        let listed = ops::list_buckets::output_from_s3s(listing).expect(name);
        let buckets = listed.buckets;
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name.as_str(), name);
    }
}

#[test]
fn n_a_generated_input_or_output_naming_a_bucket_below_the_floor_is_refused_with_the_bucket_kind() {
    for name in below_floor_buckets() {
        let input = oracle::HeadBucketInput {
            bucket: name.clone(),
            ..Default::default()
        };
        let error = ops::head_bucket::input_from_s3s(input).expect_err("below the floor");
        assert_eq!(error.field, "bucket");
        assert!(is_bucket(&error), "{name:?}: {error}");

        let listing = listing(&name);
        let error = ops::list_buckets::output_from_s3s(listing).expect_err("below the floor");
        assert!(is_bucket(&error), "{name:?}: {error}");
    }
}

#[test]
fn n_a_generated_input_naming_a_key_below_the_floor_is_refused_with_the_key_kind() {
    for key in below_floor_keys() {
        let input = oracle::DeleteObjectInput {
            bucket: "sthree-x".to_owned(),
            key: key.clone(),
            ..Default::default()
        };
        let error = ops::delete_object::input_from_s3s(input).expect_err("below the key floor");
        assert_eq!(error.field, "key");
        assert!(is_key(&error), "{} bytes: {error}", key.len());
    }
}

fn put_input(bucket: &str, key: &str) -> oracle::PutObjectInput {
    oracle::PutObjectInput {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        content_length: Some(0),
        ..Default::default()
    }
}

#[test]
fn the_hand_written_inputs_carry_an_above_floor_name() {
    for name in ABOVE_FLOOR {
        let (put, _) = put_object::input_from_s3s(put_input(name, "k")).expect(name);
        assert_eq!(put.bucket.as_str(), name);
        let location = get_bucket_location::input_from_s3s(oracle::GetBucketLocationInput {
            bucket: name.to_owned(),
            expected_bucket_owner: None,
        })
        .expect(name);
        assert_eq!(location.bucket.as_str(), name);
    }
}

#[test]
fn n_the_hand_written_inputs_refuse_a_name_or_key_below_the_floor_with_its_kind() {
    for name in below_floor_buckets() {
        let error = put_object::input_from_s3s(put_input(&name, "k")).expect_err("bucket below the floor");
        assert!(is_bucket(&error), "{name:?}: {error}");
        let error = get_bucket_location::input_from_s3s(oracle::GetBucketLocationInput {
            bucket: name.clone(),
            expected_bucket_owner: None,
        })
        .expect_err("bucket below the floor");
        assert!(is_bucket(&error), "{name:?}: {error}");
    }
    for key in below_floor_keys() {
        let error = put_object::input_from_s3s(put_input("sthree-x", &key)).expect_err("key below the floor");
        assert!(is_key(&error), "{} bytes: {error}", key.len());
    }
}

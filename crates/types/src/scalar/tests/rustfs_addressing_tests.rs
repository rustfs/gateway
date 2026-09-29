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

//! Legacy RustFS's bucket naming rules and its path split (rustfs/gateway#1115).
//!
//! Responsible for: [`LegacyRustfsNameValidator`] admitting exactly the bucket names legacy
//! RustFS serves — measured on a legacy build — under the unchanged bucket floor, and
//! [`PathSplit`] being a named, off-by-default choice of the policy.
//! NOT responsible for: where the path is split (`rustfs_gateway_core::codec`), or the AWS rules
//! (`naming_tests.rs`).
//! Upstream: [`crate::scalar::naming`]. Downstream: nothing.

use std::sync::Arc;

use crate::scalar::{BucketName, LegacyRustfsNameValidator, NamePolicy, NameRejection, PathSplit};

fn legacy() -> NamePolicy {
    NamePolicy::default()
        .with_validator(Arc::new(LegacyRustfsNameValidator))
        .with_legacy_rustfs_path_split()
}

fn bucket(name: &str) -> Result<String, NameRejection> {
    BucketName::materialize(name, &legacy()).map(|bucket| bucket.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// Positive: every bucket legacy RustFS serves.
// ---------------------------------------------------------------------------

#[test]
fn a_bucket_legacy_rustfs_creates_is_admitted() {
    // Each created by `PUT /<name>` (200) and read back by `GET /<name>?location` on a legacy
    // build, and each refused by the AWS rules the default validator applies.
    for name in ["sthree-x", "abc-s3alias", "abc--x-s3", "abc--ol-s3"] {
        assert_eq!(bucket(name), Ok(name.to_owned()), "{name}");
        assert!(BucketName::materialize(name, &NamePolicy::default()).is_err(), "{name} is AWS-reserved");
    }
    for name in ["a.b", "1.2.3", "1.2.3.4.5", &"a".repeat(63), "abc", "a-b.c-d"] {
        assert_eq!(bucket(name), Ok(name.to_owned()), "{name}");
    }
}

#[test]
fn a_name_that_is_not_an_address_to_legacy_rustfs_is_admitted() {
    // Legacy RustFS reads an address with the standard library's parser, which refuses a leading
    // zero and an octet over 255: `GET /01.2.3.4?location` and `GET /256.1.1.1?location` answered
    // `404 NoSuchBucket` there, not `400 InvalidBucketName`.
    for name in ["01.2.3.4", "256.1.1.1", "1.2.3.04"] {
        assert_eq!(bucket(name), Ok(name.to_owned()), "{name}");
    }
}

// ---------------------------------------------------------------------------
// Negative: every name legacy RustFS refuses, and the floor underneath.
// ---------------------------------------------------------------------------

#[test]
fn n_a_bucket_legacy_rustfs_refuses_is_refused() {
    // Each answered `400 InvalidBucketName` by a legacy build.
    for name in [
        "1.2.3.4",
        "192.168.1.1",
        "xn--abc",
        "ab",
        &"a".repeat(64),
        "Bad_Bucket",
        "KEYB",
        "a..b",
        ".abc",
        "abc.",
        "abc-",
        "-abc",
        "abc_d",
    ] {
        assert!(bucket(name).is_err(), "{name:?} must be refused");
    }
}

#[test]
fn n_the_bucket_floor_still_runs_first() {
    for name in ["", "a/b", "a%2Fb", "a\u{0}b", "a b"] {
        assert!(bucket(name).is_err(), "{name:?} is a floor violation");
    }
}

#[test]
fn n_the_legacy_rules_say_nothing_about_keys() {
    use crate::scalar::{NameValidator, Stricter};
    assert_eq!(LegacyRustfsNameValidator.check_key("any/key\u{1}"), Stricter::NoOpinion);
}

#[test]
fn n_the_path_split_is_named_and_off_by_default() {
    assert_eq!(NamePolicy::default().path_split(), PathSplit::Literal);
    assert_eq!(legacy().path_split(), PathSplit::RustfsLegacy);
    assert_eq!(PathSplit::RustfsLegacy.as_str(), "rustfs-legacy");
    assert_eq!(PathSplit::Literal.as_str(), "literal");
    // Choosing the split changes nothing else about the policy.
    let split_only = NamePolicy::default().with_legacy_rustfs_path_split();
    assert!(BucketName::materialize("sthree-x", &split_only).is_err(), "the AWS rules still apply");
}

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

//! Security mutations for copy-source normalization and proof binding.
//!
//! Responsible for: adversarial path spellings and proof/resource mismatch cases.
//! NOT responsible for: ordinary grammar or range behavior, which remain beside the implementation.
//! Upstream: `copy_source`. Downstream: the authorization regression gate.

use super::tests::{rejected, resolved};
use super::*;
use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput};

use crate::Decision;
use crate::authz::{authorize_input, prepare_input};

#[test]
fn a_query_that_is_not_a_version_is_refused_rather_than_folded_into_the_key() {
    let err = rejected("bucket/a?b");
    assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
    assert_eq!(rejected("bucket/a?versionId=").code(), &ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn non_utf8_percent_bytes_are_refused_and_do_not_panic() {
    let err = rejected("bucket/%FF%FE");
    assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn a_traversal_in_the_copy_source_is_refused_and_never_resolved() {
    // This used to assert the spelling was ordinary key bytes. `GHSA-f4vq-9ffr-m8m3` shows why
    // that is unsafe when authorization and storage do not share one normalization.
    let err = rejected("bucket/../../etc/passwd");
    assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
    assert!(CopySource::parse("bucket/%252e%252e/x").is_err());
    assert!(CopySource::parse("bucket/%252e%252e%252fsecret").is_err());
    assert!(CopySource::parse("bucket/a%255csecret").is_err());
    assert!(CopySource::parse("bucket/%2e%2e/x").is_err());
    assert_eq!(resolved("bucket/a/./b").key().as_str(), "a/./b");
}

#[test]
fn a_denied_source_yields_no_proof_and_no_bucket() {
    let input = CopyObjectInput {
        copy_source: "bucket/key".to_owned(),
        ..Default::default()
    };
    let decoded = prepare_input::<CopyObject>(input).expect("parses");
    let err = authorize_input(decoded, |_| Decision::Deny).err().expect("denied");
    assert_eq!(err.decision(), Decision::Deny);
}

#[test]
fn a_proof_for_one_source_cannot_resolve_another_source() {
    let first = CopyObjectInput {
        copy_source: "bucket/first".to_owned(),
        ..Default::default()
    };
    let first = authorize_input(prepare_input::<CopyObject>(first).expect("first parses"), |_| Decision::Allow)
        .expect("first authorized");
    let second = CopyObjectInput {
        copy_source: "bucket/second".to_owned(),
        ..Default::default()
    };
    let second = prepare_input::<CopyObject>(second).expect("second parses");
    assert!(second.resources().source().resolve(first.read_proof()).is_none());
}

#[test]
fn a_path_proof_cannot_resolve_an_access_point_with_the_same_name_and_key() {
    let path = CopyObjectInput {
        copy_source: "my-ap/key".to_owned(),
        ..Default::default()
    };
    let path =
        authorize_input(prepare_input::<CopyObject>(path).expect("path parses"), |_| Decision::Allow).expect("path authorized");
    let access_point = CopyObjectInput {
        copy_source: "arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/key".to_owned(),
        ..Default::default()
    };
    let access_point = prepare_input::<CopyObject>(access_point).expect("access point parses");
    assert!(access_point.resources().source().resolve(path.read_proof()).is_none());
}

#[test]
fn an_access_point_proof_is_scoped_to_its_full_arn_identity() {
    let first = CopyObjectInput {
        copy_source: "arn:aws:s3:us-east-1:111111111111:accesspoint/shared/object/key".to_owned(),
        ..Default::default()
    };
    let first = authorize_input(prepare_input::<CopyObject>(first).expect("first ARN parses"), |_| Decision::Allow)
        .expect("first ARN authorized");
    let second = CopyObjectInput {
        copy_source: "arn:aws:s3:us-east-1:222222222222:accesspoint/shared/object/key".to_owned(),
        ..Default::default()
    };
    let second = prepare_input::<CopyObject>(second).expect("second ARN parses");
    assert!(second.resources().source().resolve(first.read_proof()).is_none());
}

#[test]
fn a_version_proof_cannot_resolve_another_version_of_the_same_key() {
    let first = CopyObjectInput {
        copy_source: "bucket/key?versionId=v1".to_owned(),
        ..Default::default()
    };
    let first =
        authorize_input(prepare_input::<CopyObject>(first).expect("v1 parses"), |_| Decision::Allow).expect("v1 authorized");
    let second = CopyObjectInput {
        copy_source: "bucket/key?versionId=v2".to_owned(),
        ..Default::default()
    };
    let second = prepare_input::<CopyObject>(second).expect("v2 parses");
    assert!(second.resources().source().resolve(first.read_proof()).is_none());
}

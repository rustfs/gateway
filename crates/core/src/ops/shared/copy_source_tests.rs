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

//! The copy-source contract's own tests: grammar, forms, ranges and the proof binding.
//!
//! Responsible for: the ordinary behaviour of `CopySource::parse`, `resolve_copy_range` and
//! `classify_self_copy`, plus the `rejected`/`resolved` helpers the security mutations share.
//! NOT responsible for: the adversarial spellings, which are `copy_source_security_tests`.
//! Upstream: `copy_source`. Downstream: `copy_source_security_tests`.

use super::*;
use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput};

use crate::Decision;
use crate::authz::{DerivedResourceSet, authorize_input, prepare_input};

pub(super) fn rejected(raw: &str) -> CopySourceRejection {
    match CopySource::parse(raw) {
        Err(error) => error,
        Ok(_) => panic!("copy source should be refused"),
    }
}

pub(super) fn resolved(raw: &str) -> ResolvedCopySource {
    let input = CopyObjectInput {
        copy_source: raw.to_owned(),
        ..Default::default()
    };
    let decoded = prepare_input::<CopyObject>(input).expect("parses");
    let authorized = authorize_input(decoded, |_| Decision::Allow).expect("authorized");
    authorized
        .resources()
        .source()
        .resolve(authorized.read_proof())
        .expect("the proof belongs to this source")
}

#[test]
fn the_version_suffix_is_split_before_the_key_is_decoded() {
    let source = resolved("bucket/a%3Fb?versionId=v1");
    assert_eq!(source.key().as_str(), "a?b");
    assert_eq!(source.version_id(), Some("v1"));
}

#[test]
fn a_versioned_source_requires_get_object_version() {
    let input = CopyObjectInput {
        copy_source: "bucket/key?versionId=v1".to_owned(),
        ..Default::default()
    };
    let decoded = prepare_input::<CopyObject>(input).expect("parses");
    let mut actions = Vec::new();
    decoded.resources().visit(&mut |resource| actions.push(resource.action()));
    assert_eq!(actions, ["s3:GetObjectVersion"]);
}

#[test]
fn a_leading_slash_is_accepted_and_means_the_same_thing() {
    assert_eq!(resolved("/bucket/key"), resolved("bucket/key"));
}

#[test]
fn an_encoded_key_decodes_exactly_once_and_byte_for_byte() {
    let source = resolved("bucket/na%C3%AFve%20%E2%82%AC%26%2B%2Fx");
    assert_eq!(source.key().as_str(), "naïve €&+/x");
}

#[test]
fn both_arn_forms_are_recognised() {
    let ap = resolved("arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/dir/key.txt");
    assert_eq!(ap.form(), CopySourceForm::AccessPointArn);
    assert_eq!(ap.key().as_str(), "dir/key.txt");

    let op = CopySource::parse("arn:aws:s3-outposts:us-east-1:1:outpost/op-1/bucket/src-bucket/object/k").expect("parses");
    assert_eq!(op.form(), CopySourceForm::OutpostsArn);
    assert_eq!(op.resource.container(), Some("op-1"));
    assert_eq!(op.resource.bucket().as_str(), "src-bucket");
}

#[test]
fn an_unrecognised_arn_is_refused_rather_than_read_as_a_bucket() {
    let err = rejected("arn:aws:iam::123456789012:user/bob");
    assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn an_empty_or_keyless_value_is_refused() {
    for raw in ["", "bucket", "bucket/", "/bucket"] {
        let err = rejected(raw);
        assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT, "{raw}");
    }
}

#[test]
fn the_handler_resolves_the_same_normalized_resource_authorization_saw() {
    let resolved = resolved("bucket/a%2Fb?versionId=v1");
    assert_eq!(resolved.bucket().as_str(), "bucket");
    assert_eq!(resolved.key().as_str(), "a/b");
    assert_eq!(resolved.version_id(), Some("v1"));
}

#[test]
fn a_self_copy_is_recognised_and_a_versioned_one_is_not() {
    let bucket = BucketName::new("bucket").expect("bucket");
    let key = ObjectKey::new("key").expect("key");
    assert!(resolved("bucket/key").is_self_copy(&bucket, &key));
    assert!(!resolved("bucket/key?versionId=v1").is_self_copy(&bucket, &key));
    assert!(!resolved("bucket/other").is_self_copy(&bucket, &key));
}

#[test]
fn a_self_copy_that_changes_nothing_is_refused_and_one_that_rewrites_metadata_is_not() {
    let bucket = BucketName::new("bucket").expect("bucket");
    let key = ObjectKey::new("key").expect("key");
    let source = resolved("bucket/key");
    assert_eq!(classify_self_copy(&source, &bucket, &key, false), SelfCopy::Illegal);
    assert_eq!(
        classify_self_copy(&source, &bucket, &key, false)
            .rejection()
            .map(|r| r.code().clone()),
        Some(ErrorCode::INVALID_REQUEST)
    );
    assert_eq!(classify_self_copy(&source, &bucket, &key, true), SelfCopy::RewriteMetadata);
    assert!(classify_self_copy(&source, &bucket, &key, true).rejection().is_none());
}

#[test]
fn a_copied_span_is_end_minus_start_plus_one() {
    let span = resolve_copy_range(Some("bytes=0-9"), 100).expect("resolves").expect("a span");
    assert_eq!(span.len(), 10);
    assert!(!span.is_empty());
}

#[test]
fn the_suffix_and_open_ended_forms_parse_as_they_do_for_a_read() {
    let last_five = resolve_copy_range(Some("bytes=-5"), 100).expect("resolves").expect("a span");
    assert_eq!((last_five.start, last_five.end_inclusive), (95, 99));
    let from_three = resolve_copy_range(Some("bytes=3-"), 100).expect("resolves").expect("a span");
    assert_eq!((from_three.start, from_three.end_inclusive), (3, 99));
}

#[test]
fn a_zero_byte_source_copies_without_a_span_and_without_faulting() {
    assert_eq!(resolve_copy_range(None, 0), Ok(None));
    assert_eq!(
        resolve_copy_range(Some("bytes=0-0"), 0).expect_err("refused").code(),
        &ErrorCode::INVALID_ARGUMENT
    );
}

/// The rule this function's own doc comment states and a read range does not: a span the source
/// cannot satisfy in full is refused, never trimmed. `ByteRange::resolve` answers `bytes=0-100`
/// over ten bytes with `0-9` and `bytes=-100` with all ten — each a part ninety-odd bytes short
/// of the length the client committed the upload to, with a `200` to go with it.
#[test]
fn a_span_the_source_cannot_satisfy_in_full_is_refused_rather_than_clamped() {
    for header in ["bytes=100-200", "bytes=0-100", "bytes=9-10", "bytes=0-10", "bytes=-100"] {
        let err = resolve_copy_range(Some(header), 10).expect_err("refused");
        assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT, "{header}");
    }
    // The boundaries themselves are not refusals: the last byte of a ten-byte source is nine,
    // and a suffix exactly as long as the source is the whole source rather than an overrun.
    let whole = Ok(Some(CopyRange {
        start: 0,
        end_inclusive: 9,
    }));
    assert_eq!(resolve_copy_range(Some("bytes=0-9"), 10), whole);
    assert_eq!(resolve_copy_range(Some("bytes=-10"), 10), whole);
}

/// A read ignores a `Range` it cannot parse and serves the whole representation. Doing that on
/// a copy would write the entire source under a header that asked for part of it.
#[test]
fn a_value_that_is_not_a_byte_range_is_refused_rather_than_ignored() {
    for header in ["items=0-1", "bytes=", "bytes=abc", "bytes=5-1", "nonsense"] {
        let err = resolve_copy_range(Some(header), 10).expect_err("refused");
        assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT, "{header}");
    }
}

#[test]
fn more_than_one_span_is_refused() {
    let err = resolve_copy_range(Some("bytes=0-1,5-6"), 100).expect_err("refused");
    assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
}

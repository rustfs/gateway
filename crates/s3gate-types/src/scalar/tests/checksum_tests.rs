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

//! Checksum cases: the published CRC check values, header selection, and every rejection path.
//!
//! Responsible for: pinning each algorithm against its published check value, the packed size
//! budget, and the distinct error codes the three integrity failures carry.
//! NOT responsible for: where in the pipeline verification happens.
//! Upstream: [`crate::scalar::checksum`]. Downstream: nothing.

use md5::{Digest as _, Md5};
use proptest::prelude::*;

use crate::scalar::{
    ChecksumAlgorithm, ChecksumError, ChecksumSpec, ChecksumType, ContentMd5, ErrorCode, parse_request_checksum,
};

/// The string every CRC specification publishes its check value for.
const CHECK_INPUT: &[u8] = b"123456789";

fn digest_of(algo: ChecksumAlgorithm, input: &[u8]) -> Vec<u8> {
    let mut hasher = algo.checksummer();
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[test]
fn c_cks_0001_crc32_matches_the_published_check_value() {
    assert_eq!(digest_of(ChecksumAlgorithm::Crc32, CHECK_INPUT), 0xcbf4_3926u32.to_be_bytes());
}

#[test]
fn c_cks_0002_crc32c_matches_the_published_check_value() {
    assert_eq!(digest_of(ChecksumAlgorithm::Crc32c, CHECK_INPUT), 0xe306_9283u32.to_be_bytes());
}

#[test]
fn c_cks_0003_crc64nvme_matches_the_published_check_value() {
    assert_eq!(
        digest_of(ChecksumAlgorithm::Crc64Nvme, CHECK_INPUT),
        0xae8b_1486_0a79_9888u64.to_be_bytes()
    );
}

#[test]
fn sha_algorithms_match_their_published_vectors() {
    assert_eq!(
        hex::encode(digest_of(ChecksumAlgorithm::Sha1, b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex::encode(digest_of(ChecksumAlgorithm::Sha256, b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn every_algorithm_reports_its_own_width() {
    for algo in ChecksumAlgorithm::ALL {
        assert_eq!(digest_of(*algo, b"x").len(), algo.digest_len());
        assert_eq!(algo.checksummer().size(), algo.digest_len() as u64);
    }
}

#[test]
fn c_cks_0004_part_crcs_combine_into_the_whole() {
    let head = ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &digest_of(ChecksumAlgorithm::Crc32, b"1234"))
        .expect("a four byte digest is valid");
    let tail = ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &digest_of(ChecksumAlgorithm::Crc32, b"56789"))
        .expect("a four byte digest is valid");
    let whole = ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &digest_of(ChecksumAlgorithm::Crc32, CHECK_INPUT))
        .expect("a four byte digest is valid");

    let combined = ChecksumSpec::combine_full_object(&[(head, 4), (tail, 5)]).expect("CRCs combine");
    assert_eq!(combined.render_base64(), whole.render_base64());
    assert_eq!(combined.checksum_type(), ChecksumType::FullObject);
}

#[test]
fn sha_checksums_cannot_be_combined() {
    let part = ChecksumSpec::from_digest(ChecksumAlgorithm::Sha256, &digest_of(ChecksumAlgorithm::Sha256, b"x")).expect("valid");
    assert_eq!(ChecksumSpec::combine_full_object(&[(part, 1)]), Err(ChecksumError::NotCombinable));
    assert_eq!(ChecksumSpec::combine_full_object(&[]), Err(ChecksumError::NotCombinable));
}

#[test]
fn a_composite_checksum_carries_its_part_count() {
    let part = ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &digest_of(ChecksumAlgorithm::Crc32, b"a")).expect("valid");
    let composite = ChecksumSpec::composite_of(&[part, part, part]).expect("three parts compose");
    assert_eq!(composite.checksum_type(), ChecksumType::Composite);
    assert_eq!(composite.part_count(), Some(3));
    assert!(composite.render_base64().ends_with("-3"));

    let reparsed = ChecksumSpec::parse_header("x-amz-checksum-crc32", composite.render_base64()).expect("it re-parses");
    assert_eq!(reparsed, composite);
}

#[test]
fn c_cks_n001_two_different_checksum_headers_are_rejected() {
    let headers = [
        ("x-amz-checksum-crc32", "mnG7TA=="),
        ("x-amz-checksum-sha256", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="),
    ];
    let error = parse_request_checksum(&headers).expect_err("only one checksum header is allowed");
    assert_eq!(error, ChecksumError::MultipleChecksumHeaders);
    assert_eq!(error.error_code(), ErrorCode::INVALID_REQUEST);
    assert!(error.message().contains("single"));
}

#[test]
fn a_repeated_identical_header_is_one_header() {
    let headers = [("x-amz-checksum-crc32", "mnG7TA=="), ("X-Amz-Checksum-CRC32", "mnG7TA==")];
    let spec = parse_request_checksum(&headers).expect("the same value twice is not a conflict");
    assert!(spec.is_some());
}

#[test]
fn c_cks_n002_a_declared_algorithm_without_a_value_is_rejected() {
    let headers = [("x-amz-sdk-checksum-algorithm", "CRC32")];
    assert_eq!(parse_request_checksum(&headers), Err(ChecksumError::AlgorithmDeclaredWithoutValue));

    let mismatched = [
        ("x-amz-sdk-checksum-algorithm", "CRC32"),
        ("x-amz-checksum-sha256", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="),
    ];
    assert_eq!(parse_request_checksum(&mismatched), Err(ChecksumError::AlgorithmDeclaredWithoutValue));
}

#[test]
fn no_checksum_headers_at_all_is_not_an_error() {
    assert_eq!(parse_request_checksum(&[("content-type", "text/plain")]), Ok(None));
}

#[test]
fn c_cks_n003_a_malformed_content_md5_is_invalid_digest() {
    let error = ContentMd5::parse("not base64!").expect_err("that is not base64");
    assert_eq!(error, ChecksumError::InvalidDigest);
    assert_eq!(error.error_code(), ErrorCode::INVALID_DIGEST);
    // Valid base64 of the wrong width is equally invalid.
    assert_eq!(ContentMd5::parse("Zm9v"), Err(ChecksumError::InvalidDigest));
}

#[test]
fn c_cks_n004_a_content_md5_mismatch_is_bad_digest() {
    let body = b"hello";
    let digest: [u8; 16] = Md5::digest(body).into();
    let expected = ContentMd5::parse(&crate::scalar::base64::encode(&digest)).expect("valid");
    assert_eq!(expected.verify(&digest), Ok(()));

    let other: [u8; 16] = Md5::digest(b"goodbye").into();
    let error = expected.verify(&other).expect_err("a different body must not verify");
    assert_eq!(error, ChecksumError::BadDigest);
    assert_eq!(error.error_code(), ErrorCode::BAD_DIGEST);
}

#[test]
fn c_cks_n005_a_checksum_mismatch_has_its_own_code() {
    // The three integrity failures must stay distinguishable: SDKs branch on which one they get.
    assert_eq!(ChecksumError::ChecksumMismatch.error_code(), ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH);
    assert_ne!(ChecksumError::ChecksumMismatch.error_code(), ChecksumError::BadDigest.error_code());
}

#[test]
fn c_cks_n006_a_value_of_the_wrong_width_is_rejected() {
    // A SHA-256 value under a CRC32 header name.
    let error = ChecksumSpec::parse_header("x-amz-checksum-crc32", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")
        .expect_err("the width does not match the algorithm");
    assert_eq!(error, ChecksumError::InvalidChecksumValue);
    assert!(ChecksumSpec::parse_header("x-amz-checksum-crc32", "AAAA").is_err());
    assert!(ChecksumSpec::parse_header("x-amz-checksum-crc32", "not base64").is_err());
}

#[test]
fn c_cks_n007_an_out_of_range_part_count_is_rejected() {
    assert!(ChecksumSpec::parse_header("x-amz-checksum-crc32", "mnG7TA==-99999").is_err());
    assert!(ChecksumSpec::parse_header("x-amz-checksum-crc32", "mnG7TA==-0").is_err());
    assert!(ChecksumSpec::parse_header("x-amz-checksum-crc32", "mnG7TA==-").is_err());
    assert!(ChecksumSpec::parse_header("x-amz-checksum-crc32", "mnG7TA==-10000").is_ok());
}

#[test]
fn c_cks_n008_an_unknown_checksum_type_is_rejected() {
    assert!(ChecksumType::parse("BOGUS").is_err());
    assert!(ChecksumType::parse("composite").is_err(), "the wire spelling is uppercase");
    let headers = [("x-amz-checksum-crc32", "mnG7TA=="), ("x-amz-checksum-type", "BOGUS")];
    assert_eq!(parse_request_checksum(&headers), Err(ChecksumError::InvalidChecksumValue));
}

#[test]
fn a_checksum_type_that_contradicts_the_value_is_rejected() {
    let headers = [("x-amz-checksum-crc32", "mnG7TA=="), ("x-amz-checksum-type", "COMPOSITE")];
    assert!(parse_request_checksum(&headers).is_err(), "a value without a -N suffix is not composite");
}

#[test]
fn an_unknown_checksum_header_is_rejected_rather_than_ignored() {
    let headers = [("x-amz-checksum-blake3", "mnG7TA==")];
    assert_eq!(parse_request_checksum(&headers), Err(ChecksumError::UnknownAlgorithm));
}

#[test]
fn c_cks_n010_the_packed_spec_stays_within_its_budget() {
    // The compile-time assertion in the module is the real gate; this states the number.
    assert!(size_of::<ChecksumSpec>() <= 96, "ChecksumSpec must stay small enough for Req<O>");
}

#[test]
fn header_and_wire_names_round_trip() {
    for algo in ChecksumAlgorithm::ALL {
        assert_eq!(ChecksumAlgorithm::from_header_name(algo.header_name()), Some(*algo));
        assert_eq!(ChecksumAlgorithm::from_wire_name(algo.wire_name()), Some(*algo));
        assert_eq!(
            ChecksumAlgorithm::from_header_name(&algo.header_name().to_uppercase()),
            Some(*algo),
            "header names are case-insensitive"
        );
    }
    assert_eq!(ChecksumAlgorithm::from_wire_name("BLAKE3"), None);
}

proptest! {
    /// A digest survives the base64 wire form unchanged, for every algorithm.
    #[test]
    fn digest_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..512)) {
        for algo in ChecksumAlgorithm::ALL {
            let digest = digest_of(*algo, &payload);
            let spec = ChecksumSpec::from_digest(*algo, &digest).expect("a computed digest is the right width");
            let parsed = ChecksumSpec::parse_header(algo.header_name(), spec.render_base64())
                .expect("what we rendered, we parse");
            let decoded = parsed.digest().expect("valid");
            prop_assert_eq!(decoded.as_bytes(), digest.as_slice());
            prop_assert_eq!(parsed.algorithm(), *algo);
        }
    }
}

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

//! The integrity matrix: which claims a head may carry, and what each one costs at end-of-body.
//!
//! Responsible for: every ambiguity [`BodyIntegrity::resolve`] refuses, every comparison
//! [`BodyDigests::verify`] performs, and the two properties that make the result worth anything —
//! that both claims are checked when both are present, and that the digests see the body once.
//! NOT responsible for: the algorithms themselves (`rustfs-gateway-types` pins them against their
//! published check values) or the response rendering (the facade owns that).
//! Upstream: `rustfs-gateway-http`. Downstream: nothing.
//!
//! 19 negative / 6 positive.

use http::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::{BodyIntegrity, ChecksumReject, ChecksumSubject, HeaderView};
use rustfs_gateway_stream::TrailingHeaders;
use rustfs_gateway_types::{ChecksumAlgorithm, ErrorCode};

/// The body every case in this file digests, and the true digests of it.
const BODY: &[u8] = b"hello world";
/// base64(CRC32(BODY)).
const CRC32: &str = "DUoRhQ==";
/// base64(SHA-1(BODY)).
const SHA1: &str = "Kq5sNclPz7QV2+lfQIuc6R7oRu0=";
/// base64(MD5(BODY)).
const MD5: &str = "XrY7u+Ae7tCTyyK7j1rNww==";

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a test header name");
        let value = HeaderValue::from_str(value).expect("a test header value");
        map.append(name, value);
    }
    map
}

fn resolve(pairs: &[(&str, &str)]) -> Result<BodyIntegrity, ChecksumReject> {
    resolve_for(pairs, ChecksumSubject::RequestBody)
}

fn resolve_for(pairs: &[(&str, &str)], subject: ChecksumSubject) -> Result<BodyIntegrity, ChecksumReject> {
    let map = headers(pairs);
    let view = HeaderView::new(&map);
    BodyIntegrity::resolve(&view, subject)
}

/// Resolves, digests the whole body in one call, and closes.
fn round_trip(pairs: &[(&str, &str)], body: &[u8]) -> Result<u64, ChecksumReject> {
    let mut digests = resolve(pairs)?.begin();
    digests.update(body);
    let verified = digests.verify()?;
    Ok(verified.verified_bytes())
}

fn trailers(pairs: &[(&str, &str)]) -> TrailingHeaders {
    TrailingHeaders::from_header_map(headers(pairs))
}

#[test]
fn c_ck_0002_a_matching_unsigned_trailer_checksum_verifies_only_at_eof() {
    let integrity = resolve(&[
        ("x-amz-trailer", "x-amz-checksum-crc32"),
        ("x-amz-sdk-checksum-algorithm", "CRC32"),
    ])
    .expect("one declared trailer checksum is not an ambiguity");
    let mut missing = integrity.begin();
    missing.update(BODY);
    assert_eq!(missing.verify(), Err(ChecksumReject::TrailerChecksumMissing));

    let mut digests = integrity.begin();
    digests.update(BODY);
    let verified = digests
        .verify_with_trailers(&trailers(&[("x-amz-checksum-crc32", CRC32)]))
        .expect("the EOF value is the CRC32 of the body");
    assert_eq!(verified.verified_bytes(), BODY.len() as u64);
    assert_eq!(verified.checksum().map(|checksum| checksum.render_base64()), Some(CRC32));
}

#[test]
fn c_ck_0035_a_header_checksum_and_a_trailer_checksum_are_refused_together() {
    assert_eq!(
        resolve(&[("x-amz-checksum-crc32", CRC32), ("x-amz-trailer", "x-amz-checksum-crc32")]),
        Err(ChecksumReject::HeaderAndTrailerBothPresent)
    );
}

#[test]
fn c_ck_0036_the_sdk_algorithm_must_match_a_trailer_checksum_too() {
    assert_eq!(
        resolve(&[
            ("x-amz-trailer", "x-amz-checksum-crc32"),
            ("x-amz-sdk-checksum-algorithm", "SHA256"),
        ]),
        Err(ChecksumReject::SdkAlgorithmMismatch)
    );
}

#[test]
fn c_ck_0039_a_trailer_checksum_that_disagrees_with_the_body_is_refused() {
    let mut digests = resolve(&[("x-amz-trailer", "x-amz-checksum-crc32")])
        .expect("one declared trailer checksum")
        .begin();
    digests.update(BODY);
    assert_eq!(
        digests.verify_with_trailers(&trailers(&[("x-amz-checksum-crc32", "AAAAAA==")])),
        Err(ChecksumReject::ChecksumMismatch)
    );
}

#[test]
fn c_ck_0001_a_matching_checksum_header_verifies_and_reports_what_it_verified() {
    let mut digests = resolve(&[("x-amz-checksum-crc32", CRC32)])
        .expect("one well-formed checksum header is not an ambiguity")
        .begin();
    digests.update(BODY);
    let verified = digests.verify().expect("the value is the CRC32 of the body");
    assert_eq!(verified.verified_bytes(), BODY.len() as u64);
    let checksum = verified.checksum().expect("the request claimed one");
    assert_eq!(checksum.algorithm(), ChecksumAlgorithm::Crc32);
    assert_eq!(checksum.render_base64(), CRC32, "the verified value is the one that was compared");
}

#[test]
fn c_ck_0006_a_matching_content_md5_verifies_on_its_own() {
    assert_eq!(round_trip(&[("content-md5", MD5)], BODY), Ok(BODY.len() as u64));
}

#[test]
fn c_ck_0007_a_request_carrying_both_claims_has_both_of_them_checked() {
    // Positive control for the two negatives below: with both values correct the request passes,
    // so a failure there is the comparison and not the pairing.
    assert_eq!(
        round_trip(&[("content-md5", MD5), ("x-amz-checksum-sha1", SHA1)], BODY),
        Ok(BODY.len() as u64)
    );
}

#[test]
fn a_request_claiming_nothing_owes_nothing_and_opens_no_digest() {
    let integrity = resolve(&[("content-type", "text/plain")]).expect("no claim is not an ambiguity");
    assert!(integrity.is_empty());
    assert!(integrity.declared_checksum().is_none());
    assert!(!integrity.declares_content_md5());
    let verified = integrity.begin().verify().expect("nothing to compare cannot disagree");
    assert!(
        verified.checksum().is_none(),
        "a request that claimed no checksum must not come back holding one"
    );
}

#[test]
fn c_ck_0034_two_different_checksum_headers_are_refused_before_any_body_byte() {
    let error =
        resolve(&[("x-amz-checksum-crc32", CRC32), ("x-amz-checksum-sha1", SHA1)]).expect_err("two claims are two claims");
    assert_eq!(error, ChecksumReject::MultipleChecksumHeaders);
    assert_eq!(error.error_code(), ErrorCode::INVALID_REQUEST);
}

#[test]
fn c_ck_0036_a_declared_algorithm_that_no_value_header_carries_is_refused() {
    assert_eq!(
        resolve(&[("x-amz-sdk-checksum-algorithm", "SHA256")]),
        Err(ChecksumReject::SdkAlgorithmMismatch)
    );
    assert_eq!(
        resolve(&[("x-amz-sdk-checksum-algorithm", "SHA256"), ("x-amz-checksum-crc32", CRC32)]),
        Err(ChecksumReject::SdkAlgorithmMismatch),
        "naming one algorithm and sending another is the same contradiction"
    );
}

#[test]
fn c_ck_0037_a_checksum_value_that_is_not_strict_base64_is_refused_and_not_skipped() {
    // The failure this pins is a `continue`. An arbitration that drops a header it cannot parse
    // answers "this request claimed no checksum" for a request that claimed one, and the body is
    // then committed with nothing compared — which is the silent form of the very failure the
    // header exists to catch.
    for value in ["DUoRhQ", "DU oRhQ==", "DUoRh*==", "DUoRhQ==DUoRhQ==", ""] {
        assert_eq!(
            resolve(&[("x-amz-checksum-crc32", value)]),
            Err(ChecksumReject::InvalidChecksumValue),
            "`{value}` is not a CRC32 digest"
        );
    }
}

#[test]
fn an_algorithm_this_build_does_not_implement_is_refused_rather_than_ignored() {
    assert_eq!(resolve(&[("x-amz-checksum-blake3", CRC32)]), Err(ChecksumReject::UnknownAlgorithm));
}

#[test]
fn a_malformed_content_md5_is_invalid_digest_and_not_bad_digest() {
    // The codes are different rules: InvalidDigest says the header could not be read at all,
    // BadDigest says it was read and disagreed. A client that cannot tell them apart cannot tell a
    // broken signer from a corrupted body.
    let error = resolve(&[("content-md5", "not base64!")]).expect_err("that is not base64");
    assert_eq!(error, ChecksumReject::InvalidDigest);
    assert_eq!(error.error_code(), ErrorCode::INVALID_DIGEST);
    assert_eq!(
        resolve(&[("content-md5", "DUoRhQ==")]),
        Err(ChecksumReject::InvalidDigest),
        "base64 of the wrong width is not an MD5"
    );
}

#[test]
fn c_ck_0039_a_checksum_that_disagrees_with_the_body_is_a_checksum_mismatch() {
    let error = round_trip(&[("x-amz-checksum-crc32", CRC32)], b"goodbye world").expect_err("that is a different body");
    assert_eq!(error, ChecksumReject::ChecksumMismatch);
    assert_eq!(error.error_code(), ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH);
}

#[test]
fn c_ck_0038_a_content_md5_that_disagrees_with_the_body_is_a_bad_digest() {
    let error = round_trip(&[("content-md5", MD5)], b"goodbye world").expect_err("that is a different body");
    assert_eq!(error, ChecksumReject::BadDigest);
    assert_eq!(error.error_code(), ErrorCode::BAD_DIGEST);
}

#[test]
fn c_ck_0040_a_correct_content_md5_does_not_excuse_a_wrong_checksum() {
    // The asymmetric pair this and the next test form is the whole point of K-4: whichever claim a
    // caller can satisfy must not become the one that is checked.
    let error = round_trip(&[("content-md5", MD5), ("x-amz-checksum-crc32", "AAAAAA==")], BODY)
        .expect_err("the CRC32 is not the CRC32 of this body");
    assert_eq!(error, ChecksumReject::ChecksumMismatch);
}

#[test]
fn a_correct_checksum_does_not_excuse_a_wrong_content_md5() {
    let error = round_trip(&[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA=="), ("x-amz-checksum-crc32", CRC32)], BODY)
        .expect_err("the MD5 is not the MD5 of this body");
    assert_eq!(error, ChecksumReject::BadDigest);
}

#[test]
fn an_empty_body_still_has_a_digest_and_a_claim_about_a_longer_one_fails() {
    // The state this refuses is "there was nothing to compare, so nothing disagreed". A zero-length
    // body has a digest like any other, and a request claiming the digest of eleven bytes while
    // sending none must not pass for want of input.
    assert_eq!(round_trip(&[("x-amz-checksum-crc32", CRC32)], b""), Err(ChecksumReject::ChecksumMismatch));
    // base64(CRC32("")) — the empty body's own digest verifies.
    assert_eq!(round_trip(&[("x-amz-checksum-crc32", "AAAAAA==")], b""), Ok(0));
}

#[test]
fn c_ck_0042_the_read_side_checksum_mode_header_is_not_a_claim() {
    // `x-amz-checksum-mode: ENABLED` asks a read to return a checksum and declares none. It shares
    // the `x-amz-checksum-` prefix with the algorithm headers, and an arbitration that treats the
    // prefix as a closed set of algorithms refuses every ranged read that asks for its object's
    // checksum back — which is c-range-0016.
    let integrity = resolve(&[("x-amz-checksum-mode", "ENABLED"), ("range", "bytes=0-4")])
        .expect("asking for a checksum back is not claiming one");
    assert!(integrity.is_empty());
}

#[test]
fn the_response_side_algorithm_and_type_headers_are_not_claims_either() {
    let integrity = resolve(&[("x-amz-checksum-algorithm", "CRC32"), ("x-amz-checksum-type", "FULL_OBJECT")])
        .expect("naming an algorithm for a multipart upload declares no digest");
    assert!(integrity.is_empty());
}

#[test]
fn a_split_feed_digests_what_one_feed_digests_and_is_counted_once() {
    // The unit half of the single-pass witness: the count is the body's length however many runs it
    // arrived in. The half that measures the *production* wiring is in the assembly, where the
    // decoded body is eleven bytes and the wire body is twenty-one — see
    // `chunked::tests::the_digests_see_the_decoded_body_once_and_never_the_framing`, which is what
    // a double feed or a feed of the framing would actually break.
    let mut digests = resolve(&[("content-md5", MD5), ("x-amz-checksum-crc32", CRC32)])
        .expect("two different features, not two claims of one")
        .begin();
    for run in BODY.chunks(4) {
        digests.update(run);
    }
    assert_eq!(digests.observed_bytes(), BODY.len() as u64);
    let verified = digests.verify().expect("a split feed digests what one feed digests");
    assert_eq!(verified.verified_bytes(), BODY.len() as u64);
}

#[test]
fn no_two_refusals_share_a_label_or_a_sentence() {
    // Only the two mappings that branch are asserted. `to_status` and `may_commit` returned a
    // constant with no branch, so a test comparing them against that constant compares a literal to
    // itself — AGENTS.md's defect #7, and the reason `may_commit` no longer exists.
    let all = [
        ChecksumReject::MultipleChecksumHeaders,
        ChecksumReject::SdkAlgorithmMismatch,
        ChecksumReject::UnknownAlgorithm,
        ChecksumReject::InvalidChecksumValue,
        ChecksumReject::InvalidDigest,
        ChecksumReject::BadDigest,
        ChecksumReject::ChecksumMismatch,
        ChecksumReject::HeaderAndTrailerBothPresent,
        ChecksumReject::TrailerChecksumMissing,
        ChecksumReject::TrailerNotAllowed,
    ];
    let mut labels: Vec<&str> = all.iter().map(|reject| reject.as_str()).collect();
    let mut sentences: Vec<&str> = all.iter().map(|reject| reject.message()).collect();
    for set in [&mut labels, &mut sentences] {
        let count = set.len();
        set.sort_unstable();
        set.dedup();
        assert_eq!(set.len(), count, "two refusals that read the same are one refusal in every log");
    }
}

#[test]
fn a_named_resource_checksum_is_arbitrated_but_never_compared_against_this_body() {
    // `CompleteMultipartUpload` carries the digest of the assembled object, usually composite, while
    // its body is the completion XML. Comparing them is a check that can only fail — it would answer
    // 400 to every SDK multipart completion that carries a checksum.
    let composite = &[("x-amz-checksum-crc32", "AAAAAA==")];
    let integrity = resolve_for(composite, ChecksumSubject::NamedResource).expect("that is a well-formed claim");
    assert!(integrity.declared_checksum().is_none(), "it is not this body's digest");
    let mut digests = integrity.begin();
    digests.update(BODY);
    assert!(digests.verify().is_ok(), "a claim about another resource cannot disagree with this body");

    // Arbitration still runs: a contradiction is a contradiction on every operation.
    assert_eq!(
        resolve_for(
            &[("x-amz-checksum-crc32", CRC32), ("x-amz-checksum-sha1", SHA1)],
            ChecksumSubject::NamedResource
        ),
        Err(ChecksumReject::MultipleChecksumHeaders)
    );
    // `Content-MD5` is the message body's digest on every operation, this one included.
    let mut digests = resolve_for(&[("content-md5", MD5)], ChecksumSubject::NamedResource)
        .expect("a well-formed MD5")
        .begin();
    digests.update(b"goodbye world");
    assert_eq!(digests.verify(), Err(ChecksumReject::BadDigest));
}

#[test]
fn a_request_with_no_body_to_describe_owes_nothing_and_still_refuses_a_contradiction() {
    // S3 ignores a `Content-MD5` on a read rather than refusing it, and a digest of bytes that were
    // never sent describes nothing this service received.
    let integrity = resolve_for(&[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")], ChecksumSubject::None)
        .expect("a read carries no claim about a body");
    assert!(integrity.is_empty());
    assert!(integrity.begin().verify().is_ok());
    assert_eq!(
        resolve_for(&[("x-amz-checksum-crc32", CRC32), ("x-amz-checksum-sha1", SHA1)], ChecksumSubject::None),
        Err(ChecksumReject::MultipleChecksumHeaders),
        "a request that contradicts itself does so on every method"
    );
}

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

//! Cases `c-wire-0008` and `c-wire-0020`..`0032`: rules W-1 to W-6, the framing ambiguities that
//! application-layer request smuggling is built from.
//!
//! Responsible for: proving each framing rule fires, that a rejection never permits the body to
//! be read, and that a broken chunk line is a `400` rather than a `500`.
//! NOT responsible for: `aws-chunked`, which is a payload framing selected by the signature and
//! decoded in P3-03.
//! Upstream: `support`. Downstream: nothing.

mod support;

use http::{Request, StatusCode, Version, header::CONTENT_LENGTH, header::HOST, header::TRANSFER_ENCODING};
use s3gate_http::{BodyLength, LimitKind, Limits, MAX_CHUNK_SIZE_LINE_BYTES, WireReject, validate_chunk_size_line};
use support::accept;

fn with_headers(pairs: &[(&'static str, &str)], version: Version) -> Request<&'static str> {
    let mut builder = Request::builder().method("PUT").uri("/bucket/key").version(version);
    builder = builder.header(HOST, "b.example.com");
    for (name, value) in pairs {
        builder = builder.header(*name, *value);
    }
    builder.body("").expect("valid fixture request")
}

fn reject_of(pairs: &[(&'static str, &str)]) -> WireReject {
    accept(with_headers(pairs, Version::HTTP_11)).expect_err("expected a framing rejection")
}

// ── positive ────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_wire_0008_transfer_encoding_chunked_without_content_length_is_accepted() {
    let accepted = accept(with_headers(&[("transfer-encoding", "chunked")], Version::HTTP_11))
        .expect("chunked alone is the well-formed streaming shape");
    assert_eq!(accepted.framing().length(), BodyLength::Chunked);
    assert!(accepted.framing().is_transfer_chunked());
    // A chunked request has no announced length, and saying "zero" would be a different lie from
    // saying "unknown".
    assert_eq!(accepted.framing().declared_length(), None);
}

#[test]
fn c_wire_0008b_content_length_alone_is_accepted_and_announced() {
    let accepted = accept(with_headers(&[("content-length", "42")], Version::HTTP_11)).expect("a plain length");
    assert_eq!(accepted.framing().length(), BodyLength::Exact(42));
    assert_eq!(accepted.framing().declared_length(), Some(42));
    assert!(!accepted.framing().is_transfer_chunked());
}

#[test]
fn c_wire_0008c_no_framing_header_means_no_body() {
    let accepted = accept(with_headers(&[], Version::HTTP_11)).expect("a body-less request");
    assert_eq!(accepted.framing().length(), BodyLength::Empty);
    assert!(!accepted.framing().has_body());
}

#[test]
fn c_wire_0008d_valid_chunk_size_lines_parse() {
    assert_eq!(validate_chunk_size_line(b"5\r\n"), Ok(5));
    assert_eq!(validate_chunk_size_line(b"0\r\n"), Ok(0));
    assert_eq!(validate_chunk_size_line(b"1a2B\r\n"), Ok(0x1a2b));
    assert_eq!(validate_chunk_size_line(b"10;chunk-signature=abc\r\n"), Ok(16));
}

// ── negative ────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_wire_0020_content_length_with_transfer_encoding_is_rejected_without_reading_the_body() {
    let reject = reject_of(&[("content-length", "5"), ("transfer-encoding", "chunked")]);
    assert_eq!(reject, WireReject::ContentLengthTransferEncodingConflict);
    assert_eq!(reject.to_status(), StatusCode::BAD_REQUEST);
    // RFC 9112 §6.1: answer 400 and close. Draining first would mean reading a body whose extent
    // this layer has just declared undecidable.
    assert!(reject.must_close_connection());
    assert!(!reject.may_read_body());
}

#[test]
fn c_wire_0020b_the_conflict_is_reported_before_either_header_is_parsed() {
    // The `Content-Length` here is also malformed. The conflict must still be the verdict, so the
    // reason a request was refused does not depend on which of two defects is examined first.
    let reject = reject_of(&[("content-length", "not-a-number"), ("transfer-encoding", "chunked")]);
    assert_eq!(reject, WireReject::ContentLengthTransferEncodingConflict);
}

#[test]
fn c_wire_0021_repeated_transfer_encoding_is_rejected() {
    let reject = reject_of(&[("transfer-encoding", "chunked"), ("transfer-encoding", "chunked")]);
    assert_eq!(reject, WireReject::TransferEncodingMalformed);
}

#[test]
fn c_wire_0022_chunked_not_last_is_rejected() {
    assert_eq!(
        reject_of(&[("transfer-encoding", "chunked, gzip")]),
        WireReject::TransferEncodingMalformed
    );
}

#[test]
fn c_wire_0022b_a_coding_before_chunked_is_rejected_too() {
    assert_eq!(
        reject_of(&[("transfer-encoding", "gzip, chunked")]),
        WireReject::TransferEncodingMalformed
    );
}

#[test]
fn c_wire_0023_transfer_encoding_identity_is_rejected() {
    assert_eq!(reject_of(&[("transfer-encoding", "identity")]), WireReject::TransferEncodingMalformed);
}

#[test]
fn c_wire_0024_transfer_encoding_on_http2_is_rejected() {
    let request = with_headers(&[("transfer-encoding", "chunked")], Version::HTTP_2);
    assert_eq!(accept(request).err(), Some(WireReject::TransferEncodingOnHttp2));
}

#[test]
fn c_wire_0025_two_different_content_lengths_are_rejected() {
    assert_eq!(
        reject_of(&[("content-length", "5"), ("content-length", "10")]),
        WireReject::DuplicateContentLength
    );
}

#[test]
fn c_wire_0026_two_identical_content_lengths_are_rejected() {
    // Refused precisely because it is unambiguous to *us*: it is the probe that tells an attacker
    // which end of the chain drops the duplicate.
    assert_eq!(
        reject_of(&[("content-length", "5"), ("content-length", "5")]),
        WireReject::DuplicateContentLength
    );
}

#[test]
fn c_wire_0027_to_0030_malformed_content_lengths_are_rejected() {
    for spelling in ["+5", " 5", "5 ", "0x5", "5,5", "", "1e3", "٥"] {
        let request = Request::builder()
            .method("PUT")
            .uri("/bucket/key")
            .header(HOST, "b.example.com")
            .header(CONTENT_LENGTH, spelling)
            .body("")
            .expect("valid fixture request");
        assert_eq!(accept(request).err(), Some(WireReject::MalformedContentLength), "spelling {spelling:?}");
    }
}

#[test]
fn c_wire_0028_a_negative_content_length_never_becomes_a_huge_positive_one() {
    // No cast is involved anywhere on this path: the parse admits digits only, so "-1" cannot
    // wrap into `u64::MAX` the way an `as` conversion would.
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/key")
        .header(HOST, "b.example.com")
        .header(CONTENT_LENGTH, "-1")
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).err(), Some(WireReject::MalformedContentLength));
}

#[test]
fn c_wire_0028b_an_overflowing_content_length_is_rejected_not_wrapped() {
    let request = Request::builder()
        .method("PUT")
        .uri("/bucket/key")
        .header(HOST, "b.example.com")
        .header(CONTENT_LENGTH, "99999999999999999999")
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).err(), Some(WireReject::MalformedContentLength));
}

#[test]
fn c_wire_0031_a_bare_line_feed_does_not_terminate_a_chunk_size_line() {
    assert_eq!(validate_chunk_size_line(b"5;\n"), Err(WireReject::MalformedChunkFraming));
    assert_eq!(validate_chunk_size_line(b"5\n"), Err(WireReject::MalformedChunkFraming));
    // Nor does an extra CRLF inside the line.
    assert_eq!(validate_chunk_size_line(b"5\r\n\r\n"), Err(WireReject::MalformedChunkFraming));
}

#[test]
fn c_wire_0032_an_over_long_chunk_size_line_is_refused_by_the_limit() {
    let mut line = vec![b'0'; MAX_CHUNK_SIZE_LINE_BYTES];
    line.extend_from_slice(b"5\r\n");
    assert_eq!(validate_chunk_size_line(&line), Err(WireReject::LimitExceeded(LimitKind::ChunkSizeLine)));
}

#[test]
fn c_wire_0032b_more_than_sixteen_size_digits_is_malformed() {
    assert_eq!(validate_chunk_size_line(b"00000000000000005\r\n"), Err(WireReject::MalformedChunkFraming));
}

#[test]
fn c_wire_0032c_a_non_hex_chunk_size_is_malformed_and_never_a_server_error() {
    for line in [
        &b"0x5\r\n"[..],
        b"-1\r\n",
        b" 5\r\n",
        b"5 \r\n",
        b"\r\n",
        b";ext\r\n",
        b"+5\r\n",
    ] {
        let reject = validate_chunk_size_line(line).expect_err("malformed chunk line");
        assert_eq!(reject, WireReject::MalformedChunkFraming, "line {line:?}");
        // A framing defect the peer caused is a 400. A 500 here would tell an operator their own
        // server broke, and would retry-storm a request that will never succeed.
        assert_eq!(reject.to_status(), StatusCode::BAD_REQUEST);
    }
}

#[test]
fn c_wire_0063_an_over_large_declared_body_is_400_entity_too_large_and_never_drained() {
    let limits = Limits {
        max_body_bytes: 1024,
        ..Limits::default()
    };
    let request = with_headers(&[("content-length", "4096")], Version::HTTP_11);
    let reject = support::accept_with(request, &limits).expect_err("over the body ceiling");
    assert_eq!(reject, WireReject::LimitExceeded(LimitKind::BodyBytes));
    // S3 answers 400 EntityTooLarge and never 413; clients branch on the code in the XML body,
    // not on the status. Following the RFC here would emit a shape no S3 client has seen.
    assert_eq!(reject.to_status(), StatusCode::BAD_REQUEST);
    assert_eq!(reject.error_code(), s3gate_types::ErrorCode::ENTITY_TOO_LARGE);
    // Draining the body of a request refused *for its size* is paying the attacker's bandwidth.
    assert!(!reject.may_read_body());
    assert!(reject.must_close_connection());
}

#[test]
fn a_transfer_encoding_rejection_names_the_header_it_is_about() {
    let reject = reject_of(&[("transfer-encoding", "chunked, gzip")]);
    assert_eq!(reject.as_str(), "transfer-encoding-malformed");
}

#[test]
fn transfer_encoding_case_is_not_a_way_around_the_rule() {
    let accepted = accept(with_headers(&[(TRANSFER_ENCODING.as_str(), "ChUnKeD")], Version::HTTP_11))
        .expect("a transfer coding is case-insensitive");
    assert_eq!(accepted.framing().length(), BodyLength::Chunked);
}

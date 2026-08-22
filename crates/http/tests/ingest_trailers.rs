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

//! Trailer-section contracts at the decoded-body EOF boundary.
//!
//! Responsible for: proving that a real `aws-chunked` trailer is parsed only after the terminal
//! chunk, matches its declaration, and arrives with EOF without minting commit authority.
//! NOT responsible for: checksum comparison or the signed-trailer HMAC chain.
//! Upstream: `rustfs-gateway-http` ingest and `rustfs-gateway-stream` pull events. Downstream: the
//! gateway body reader that consumes EOF trailers.

mod support;

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use http::{HeaderName, HeaderValue};
use rustfs_gateway_http::{ChunkFraming, ChunkLimits, ChunkReject, IngestPipeline, IngestPolicy, TrailerDeclaration};
use rustfs_gateway_stream::{AsyncPayloadRead, ReadProgress, StreamError, TrailingHeaders};
use support::ingest::{FramingFixture, ScriptReader, declared_length, no_observers};

/// Positive: an unsigned trailer is visible only on EOF, while checksum comparison remains an
/// explicit later obligation.
#[test]
fn an_unsigned_trailer_reaches_eof_without_minting_commit_authority() {
    let body = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 3, 5, "x-amz-checksum-crc32c");
    let (output, trailers) = drive(&mut pipeline).expect("valid trailer");

    assert_eq!(output, b"hello");
    assert_eq!(
        trailers
            .get(&HeaderName::from_static("x-amz-checksum-crc32c"))
            .expect("the declared trailer reaches EOF"),
        &HeaderValue::from_static("NhCmhg==")
    );
    assert!(pipeline.trailer_section_complete(), "EOF proves the exact section arrived");
    assert!(!pipeline.commit_allowed(), "parsing is not checksum comparison");
}

/// Negative: a trailer can never override authorization metadata from the authenticated head.
#[test]
fn c_ck_0022_authorization_is_not_an_allowed_trailer() {
    let body = b"1\r\nx\r\n0\r\nauthorization:attacker\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 64, 1, "x-amz-checksum-crc32c");

    assert!(drive(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerNotAllowed));
    assert!(!pipeline.commit_allowed());
}

/// Negative: sharing the checksum prefix does not make an unknown algorithm a checksum.
#[test]
fn an_unknown_checksum_algorithm_is_not_an_allowed_trailer() {
    let result = TrailerDeclaration::parse(&HeaderValue::from_static("x-amz-checksum-unknown"), false);

    assert!(matches!(result, Err(ChunkReject::TrailerNotAllowed)));
}

/// Negative: the two-field ceiling is enforced on what arrived, not only on the declaration.
#[test]
fn c_ck_0026_three_actual_trailers_are_refused() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:a\r\nx-amz-checksum-sha256:b\r\nx-amz-checksum-crc32:c\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 9, 1, "x-amz-checksum-crc32c,x-amz-checksum-sha256");

    assert!(drive(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerCountExceeded));
}

/// Negative: an unfinished field cannot grow past the one-kibibyte trailer budget.
#[test]
fn c_ck_0027_a_trailer_section_over_one_kibibyte_is_refused() {
    let mut body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:".to_vec();
    body.extend(core::iter::repeat_n(b'a', 1024));
    body.extend_from_slice(b"\r\n\r\n");
    let mut pipeline = unsigned_trailer(body, 73, 1, "x-amz-checksum-crc32c");

    assert!(drive(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerSizeExceeded));
}

/// Negative: changing the declared checksum name is a set mismatch, even when both names are
/// individually allowed.
#[test]
fn c_ck_0028_the_actual_trailer_name_must_equal_the_declaration() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-sha256:a\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 5, 1, "x-amz-checksum-crc32c");

    assert!(drive(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::DeclaredTrailerMismatch));
}

/// Negative: declaring two fields and sending one cannot be mistaken for a complete section.
#[test]
fn c_ck_0029_every_declared_trailer_must_arrive() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:a\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 7, 1, "x-amz-checksum-crc32c,x-amz-checksum-sha256");

    assert!(drive(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::DeclaredTrailerMismatch));
}

/// Negative: transport EOF before the empty line that closes the trailer never becomes body EOF.
#[test]
fn c_ck_0043_truncation_before_the_trailer_terminator_is_an_error() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:a\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 4, 1, "x-amz-checksum-crc32c");

    assert!(drive(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TruncatedBeforeTrailer));
    assert!(!pipeline.commit_allowed());
}

fn unsigned_trailer(body: Vec<u8>, slice: usize, declared: u64, names: &'static str) -> IngestPipeline<ScriptReader> {
    let framing =
        ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("the fixture is internally consistent");
    let declaration =
        TrailerDeclaration::parse(&HeaderValue::from_static(names), false).expect("the checksum declaration is allowed");
    IngestPipeline::new(
        ScriptReader::new(body, slice),
        framing,
        declared_length(declared),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    )
    .and_then(|pipeline| pipeline.with_trailer_declaration(declaration))
    .expect("the declaration matches the framing mode")
}

fn drive(pipeline: &mut IngestPipeline<ScriptReader>) -> Result<(Vec<u8>, TrailingHeaders), StreamError> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut output = Vec::new();
    let mut buffer = [0_u8; 2];
    loop {
        match Pin::new(&mut *pipeline).poll_fill(&mut cx, &mut buffer) {
            Poll::Pending => continue,
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Ready(Ok(ReadProgress::Filled(written))) => {
                output.extend_from_slice(&buffer[..written]);
            }
            Poll::Ready(Ok(ReadProgress::Eof { trailers })) => {
                return Ok((output, trailers));
            }
        }
    }
}

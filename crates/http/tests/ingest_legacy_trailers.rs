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

//! The trailer-section readings the RustFS profile opts into, through the whole pipeline.
//!
//! Responsible for: proving that [`ChunkLimits::with_empty_line_before_trailers`] accepts exactly
//! one CRLF between the terminal chunk line and the first trailer field, in both trailer modes,
//! and that everything around it — a second empty line, bytes after the terminator, a bare LF —
//! stays refused; that [`ChunkLimits::with_trailer_bounds`] and
//! [`ChunkLimits::with_undeclared_trailer_fields_discarded`] read legacy RustFS's 16 KiB, hundred-field
//! sections, sign-cover an undeclared field and drop it, refusing one byte or one field more; and
//! that the default limits keep the core's rules.
//! NOT responsible for: the trailer grammar's default rules (`ingest_verify.rs`) or the codes a
//! refusal is answered with (`rustfs-gateway`).
//! Upstream: `rustfs-gateway-http`'s ingest pipeline. Downstream: none.

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use http::HeaderValue;
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, IngestPipeline, IngestPolicy,
    TrailerDeclaration,
};
use rustfs_gateway_stream::{AsyncPayloadRead, ReadProgress, StreamError, TrailingHeaders};

use crate::support::ingest::{
    FramingFixture, ScriptReader, SignedChunker, TEST_AMZ_DATE, TEST_SCOPE_LINE, declared_length, no_observers,
};

const KEY: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];
const CHECKSUM: (&str, &str) = ("x-amz-checksum-crc32c", "NhCmhg==");

fn empty_line_limits() -> ChunkLimits {
    ChunkLimits::default().with_empty_line_before_trailers()
}

fn signed_body(fields: &[(&str, &str)], empty_line: bool) -> Vec<u8> {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"hello");
    chunker.finish_with_trailers(fields, empty_line)
}

fn pipeline(body: Vec<u8>, signed: bool, limits: ChunkLimits, names: &'static str) -> IngestPipeline<ScriptReader> {
    let fixture = if signed {
        FramingFixture::streaming_signed_trailer()
    } else {
        FramingFixture::streaming_unsigned_trailer()
    };
    let framing = ChunkFraming::derive(&fixture).expect("the fixture is internally consistent");
    let signer = signed.then(|| {
        let scope = ChunkScope::new(TEST_SCOPE_LINE, TEST_AMZ_DATE).expect("valid scope");
        ChunkSigner::new(ChunkSigningKey::from_derived(KEY), scope, ChunkSeed::from_request_signature(SEED))
    });
    let declaration = TrailerDeclaration::parse(&HeaderValue::from_static(names), signed).expect("an allowed declaration");
    IngestPipeline::new(
        ScriptReader::new(body, 7),
        framing,
        declared_length(5),
        signer,
        no_observers(),
        limits,
        IngestPolicy::default(),
    )
    .and_then(|pipeline| pipeline.with_trailer_declaration(declaration))
    .expect("the declaration matches the framing mode")
}

pub(crate) fn drive(pipeline: &mut IngestPipeline<ScriptReader>) -> Result<(Vec<u8>, TrailingHeaders), StreamError> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut output = Vec::new();
    let mut buffer = [0_u8; 64];
    loop {
        match Pin::new(&mut *pipeline).poll_fill(&mut cx, &mut buffer) {
            Poll::Pending => continue,
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Ready(Ok(ReadProgress::Filled(written))) => output.extend_from_slice(&buffer[..written]),
            Poll::Ready(Ok(ReadProgress::Eof { trailers })) => return Ok((output, trailers)),
        }
    }
}

fn refusal(body: Vec<u8>, signed: bool, limits: ChunkLimits) -> Option<ChunkReject> {
    let mut pipeline = pipeline(body, signed, limits, CHECKSUM.0);
    assert!(drive(&mut pipeline).is_err(), "the body was accepted");
    assert!(!pipeline.commit_allowed());
    pipeline.reject()
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive — the layout legacy RustFS accepts: one CRLF after the signed terminal chunk, then the
/// fields, the trailer signature still verified.
#[test]
fn one_empty_line_before_signed_trailers_is_read_under_the_option() {
    let mut pipeline = pipeline(signed_body(&[CHECKSUM], true), true, empty_line_limits(), CHECKSUM.0);
    let (body, trailers) = drive(&mut pipeline).expect("the empty line is tolerated");
    assert_eq!(body, b"hello");
    assert_eq!(
        trailers.as_header_map().get(CHECKSUM.0).map(HeaderValue::as_bytes),
        Some(CHECKSUM.1.as_bytes())
    );
    assert!(pipeline.trailer_signature_satisfied());
}

/// Positive — the unsigned trailer mode, which legacy RustFS reads the same way.
#[test]
fn one_empty_line_before_unsigned_trailers_is_read_under_the_option() {
    let body = b"5\r\nhello\r\n0\r\n\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n".to_vec();
    let mut pipeline = pipeline(body, false, empty_line_limits(), CHECKSUM.0);
    let (_, trailers) = drive(&mut pipeline).expect("the empty line is tolerated");
    assert_eq!(
        trailers.as_header_map().get(CHECKSUM.0).map(HeaderValue::as_bytes),
        Some(CHECKSUM.1.as_bytes())
    );
}

/// Positive — the option does not make the empty line mandatory.
#[test]
fn the_standard_layout_is_still_read_under_the_option() {
    let mut pipeline = pipeline(signed_body(&[CHECKSUM], false), true, empty_line_limits(), CHECKSUM.0);
    assert!(drive(&mut pipeline).is_ok());
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative — the default limits read the empty line as an empty trailer section, as before.
#[test]
fn n_the_default_limits_refuse_the_empty_line() {
    assert_eq!(
        refusal(signed_body(&[CHECKSUM], true), true, ChunkLimits::default()),
        Some(ChunkReject::TrailerSignatureMissing)
    );
    let unsigned = b"5\r\nhello\r\n0\r\n\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n".to_vec();
    assert_eq!(
        refusal(unsigned, false, ChunkLimits::default()),
        Some(ChunkReject::DeclaredTrailerMismatch)
    );
}

/// Negative — exactly one: a second empty line ends an empty section, and the fields after it are
/// never read as trailers.
#[test]
fn n_two_empty_lines_are_refused_under_the_option() {
    let mut body = signed_body(&[CHECKSUM], true);
    let at = body
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the empty line")
        + 2;
    body.splice(at..at, *b"\r\n");
    assert_eq!(refusal(body, true, empty_line_limits()), Some(ChunkReject::TrailerSignatureMissing));
    let unsigned = b"5\r\nhello\r\n0\r\n\r\n\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n".to_vec();
    assert_eq!(refusal(unsigned, false, empty_line_limits()), Some(ChunkReject::DeclaredTrailerMismatch));
}

/// Negative — a lone CRLF followed by the end of the body is still the empty section, refused for
/// lacking the declared checksum as without the option, not a truncated one.
#[test]
fn n_a_lone_empty_line_at_the_end_is_the_empty_section_under_the_option() {
    let unsigned = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
    for limits in [empty_line_limits(), ChunkLimits::default()] {
        assert_eq!(refusal(unsigned.clone(), false, limits), Some(ChunkReject::DeclaredTrailerMismatch));
    }
}

/// Negative — bytes after the section's terminator are refused, as without the option.
#[test]
fn n_bytes_after_the_trailer_terminator_are_refused_under_the_option() {
    let mut body = signed_body(&[CHECKSUM], true);
    body.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n\r\n");
    assert_eq!(refusal(body, true, empty_line_limits()), Some(ChunkReject::DataAfterTrailer));
    let unsigned = b"5\r\nhello\r\n0\r\n\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n\r\n".to_vec();
    assert_eq!(refusal(unsigned, false, empty_line_limits()), Some(ChunkReject::DataAfterTrailer));
}

/// Negative — only a CRLF is an empty line: a bare LF, a lone CR or whitespace are not.
#[test]
fn n_an_empty_line_spelt_otherwise_is_refused_under_the_option() {
    for (spelling, reject) in [
        (&b"\n"[..], ChunkReject::BadLineTerminator),
        (b"\rx", ChunkReject::BadLineTerminator),
        (b" \r\n", ChunkReject::MalformedTrailer),
    ] {
        let mut body = b"5\r\nhello\r\n0\r\n".to_vec();
        body.extend_from_slice(spelling);
        body.extend_from_slice(b"x-amz-checksum-crc32c:NhCmhg==\r\n\r\n");
        assert_eq!(refusal(body, false, empty_line_limits()), Some(reject), "{spelling:?}");
    }
}

/// Negative — the empty line is part of the trailer section, so it is signed over nothing and a
/// tampered field after it still fails the trailer signature.
#[test]
fn n_a_tampered_field_after_the_empty_line_fails_the_trailer_signature() {
    let body = signed_body(&[CHECKSUM], true);
    let text = String::from_utf8(body).expect("ascii fixture");
    let tampered = text.replace(CHECKSUM.1, "AAAAAA==").into_bytes();
    assert_eq!(refusal(tampered, true, empty_line_limits()), Some(ChunkReject::TrailerSignatureMismatch));
}

// ── legacy RustFS's trailer bounds ─────────────────────────────────────────────────────

fn legacy_bounds() -> ChunkLimits {
    ChunkLimits::default()
        .with_trailer_bounds(ChunkLimits::HARD_MAX_TRAILER_SECTION_BYTES, ChunkLimits::HARD_MAX_TRAILER_FIELDS)
        .with_undeclared_trailer_fields_discarded()
}

/// An unsigned body whose trailer section is `fields` followed by the empty line that ends it.
fn unsigned_trailer_body(fields: &str) -> Vec<u8> {
    let mut body = b"5\r\nhello\r\n0\r\n".to_vec();
    body.extend_from_slice(fields.as_bytes());
    body.extend_from_slice(b"\r\n");
    body
}

const CHECKSUM_LINE: &str = "x-amz-checksum-crc32c:NhCmhg==\r\n";

/// A padding field that makes the whole section, final CRLF included, exactly `section` bytes.
fn padded_to(section: usize) -> String {
    let padding = "v".repeat(section - CHECKSUM_LINE.len() - "x-padding:\r\n".len() - 2);
    format!("{CHECKSUM_LINE}x-padding:{padding}\r\n")
}

fn only_the_checksum(trailers: &TrailingHeaders) {
    let names: Vec<&str> = trailers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, [CHECKSUM.0], "an undeclared field was handed on");
}

/// Positive — a 16 KiB section, its final CRLF included, is read, and the padding is dropped.
#[test]
fn a_section_of_exactly_sixteen_kibibytes_is_read_under_legacy_bounds() {
    let mut pipeline = pipeline(unsigned_trailer_body(&padded_to(16 * 1024)), false, legacy_bounds(), CHECKSUM.0);
    let (body, trailers) = drive(&mut pipeline).expect("the section is at the bound");
    assert_eq!(body, b"hello");
    only_the_checksum(&trailers);
}

/// Positive — a hundred fields, ninety-nine of them the same undeclared one, are read, and only
/// the declared checksum is handed on.
#[test]
fn a_hundred_fields_are_read_under_legacy_bounds() {
    let fields = format!("{}{CHECKSUM_LINE}", "x-padding:v\r\n".repeat(99));
    let mut pipeline = pipeline(unsigned_trailer_body(&fields), false, legacy_bounds(), CHECKSUM.0);
    let (_, trailers) = drive(&mut pipeline).expect("the count is at the bound");
    only_the_checksum(&trailers);
}

/// Positive — in signed framing an undeclared field is covered by the trailer signature, as legacy
/// RustFS covers it, and still dropped once the signature verified.
#[test]
fn a_signed_undeclared_field_is_verified_then_dropped_under_legacy_bounds() {
    let body = signed_body(&[("x-padding", "v"), CHECKSUM], false);
    let mut pipeline = pipeline(body, true, legacy_bounds(), CHECKSUM.0);
    let (_, trailers) = drive(&mut pipeline).expect("the signature covers both fields");
    assert!(pipeline.trailer_signature_satisfied());
    let names: Vec<&str> = trailers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, [CHECKSUM.0, "x-amz-trailer-signature"]);
}

/// Negative — the default limits refuse an undeclared field and anything past one KiB.
#[test]
fn n_the_default_limits_keep_the_core_trailer_bounds() {
    let fields = format!("x-padding:v\r\n{CHECKSUM_LINE}");
    assert_eq!(
        refusal(unsigned_trailer_body(&fields), false, ChunkLimits::default()),
        Some(ChunkReject::TrailerNotAllowed)
    );
    assert_eq!(ChunkLimits::default().max_trailer_section_bytes(), 1024);
    assert_eq!(ChunkLimits::default().max_trailer_fields(), 2);
    assert!(!ChunkLimits::default().discards_undeclared_trailer_fields());
}

/// Negative — one byte past 16 KiB is refused.
#[test]
fn n_a_section_one_byte_past_sixteen_kibibytes_is_refused() {
    assert_eq!(
        refusal(unsigned_trailer_body(&padded_to(16 * 1024 + 1)), false, legacy_bounds()),
        Some(ChunkReject::TrailerSizeExceeded)
    );
}

/// Negative — a hundred and one fields are refused, even when none is the checksum.
#[test]
fn n_a_hundred_and_one_fields_are_refused() {
    let fields = format!("{}{CHECKSUM_LINE}", "x-padding:v\r\n".repeat(100));
    assert_eq!(
        refusal(unsigned_trailer_body(&fields), false, legacy_bounds()),
        Some(ChunkReject::TrailerCountExceeded)
    );
    let undeclared_only = "x-private:v\r\n".repeat(101);
    assert_eq!(
        refusal(unsigned_trailer_body(&undeclared_only), false, legacy_bounds()),
        Some(ChunkReject::TrailerCountExceeded)
    );
}

/// Negative — the bounds cannot be raised past legacy RustFS's.
#[test]
fn n_the_trailer_bounds_stop_at_their_hard_ceilings() {
    let limits = ChunkLimits::default().with_trailer_bounds(u16::MAX, u8::MAX);
    assert_eq!(limits.max_trailer_section_bytes(), 16 * 1024);
    assert_eq!(limits.max_trailer_fields(), 100);
    let floor = ChunkLimits::default().with_trailer_bounds(0, 0);
    assert_eq!(floor.max_trailer_section_bytes(), ChunkLimits::default().max_trailer_section_bytes());
    assert_eq!(floor.max_trailer_fields(), ChunkLimits::default().max_trailer_fields());
}

/// Negative — an undeclared field the signature does not cover, or one altered after signing,
/// fails the trailer signature.
#[test]
fn n_an_undeclared_field_outside_the_signature_is_refused() {
    let signed = String::from_utf8(signed_body(&[CHECKSUM], false)).expect("ascii fixture");
    let added = signed.replacen("x-amz-trailer-signature", "x-padding:v\r\nx-amz-trailer-signature", 1);
    assert_eq!(
        refusal(added.into_bytes(), true, legacy_bounds()),
        Some(ChunkReject::TrailerSignatureMismatch)
    );
    let tampered = String::from_utf8(signed_body(&[("x-padding", "v"), CHECKSUM], false))
        .expect("ascii fixture")
        .replacen("x-padding:v", "x-padding:w", 1);
    assert_eq!(
        refusal(tampered.into_bytes(), true, legacy_bounds()),
        Some(ChunkReject::TrailerSignatureMismatch)
    );
}

/// Negative — the declared checksum must still arrive exactly once, and an unsigned section still
/// may not carry a trailer signature.
#[test]
fn n_the_declared_fields_are_still_exact_under_legacy_bounds() {
    for fields in [
        "x-padding:v\r\n".to_owned(),
        format!("{CHECKSUM_LINE}{CHECKSUM_LINE}"),
        format!("{CHECKSUM_LINE}x-amz-trailer-signature:{}\r\n", "0".repeat(64)),
    ] {
        assert_eq!(
            refusal(unsigned_trailer_body(&fields), false, legacy_bounds()),
            Some(ChunkReject::DeclaredTrailerMismatch),
            "{fields}"
        );
    }
}

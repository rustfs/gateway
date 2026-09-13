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

//! Whether the chunk parser runs at all, and whether the two declared lengths agree.
//!
//! Responsible for: the derivation of [`ChunkFraming`], the four mode/length cross-checks, and
//! the interaction between HTTP's own framing decision and the payload framing layered inside it.
//! NOT responsible for: chunk syntax (`ingest_chunk_rules`) or the signature chain
//! (`ingest_verify`).
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.
//!
//! 8 positive / 19 negative.

use crate::support::ingest::{
    FramingFixture, ScriptReader, declared_length, drain_pipeline, no_body_ceiling, no_observers, unsigned_body,
    wire_framing_with_length,
};
use http::{HeaderMap, HeaderValue, Version, header::CONTENT_LENGTH, header::TRANSFER_ENCODING};
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, Framing, IngestPipeline, IngestPolicy, Limits, ModeConfusion, WireReject,
    validate_decoded_length,
};

fn decoded_of(framing: &ChunkFraming, header: Option<&str>, wire_length: u64) -> Result<Option<u64>, ChunkReject> {
    let wire = wire_framing_with_length(wire_length);
    validate_decoded_length(framing, header, &wire).map(|decoded| decoded.map(rustfs_gateway_http::DecodedLength::get))
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive: a signed streaming source derives framed, signed, no trailer.
#[test]
fn signed_streaming_derives_a_signed_framing() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    assert!(framing.is_framed());
    assert!(framing.has_chunk_signatures());
    assert!(!framing.declares_trailers());
}

/// Positive: unsigned streaming with a trailer is framed but unsigned.
#[test]
fn c_ing_0002_unsigned_streaming_with_a_trailer_is_framed_but_unsigned() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("a consistent source");
    assert!(framing.is_framed());
    assert!(!framing.has_chunk_signatures());
    assert!(framing.declares_trailers());
}

/// Positive: a non-streaming source is not framed, and needs no decoded length.
#[test]
fn a_non_streaming_source_is_not_framed() {
    let framing = ChunkFraming::derive(&FramingFixture::unsigned_payload()).expect("a consistent source");
    assert!(!framing.is_framed());
    assert_eq!(decoded_of(&framing, None, 1024), Ok(None));
}

/// Positive: a decoded length that fits inside the wire length with room for framing is accepted.
#[test]
fn c_ing_0006_a_decoded_length_that_fits_inside_the_wire_length_is_accepted() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    assert_eq!(decoded_of(&framing, Some("1024"), 4096), Ok(Some(1024)));
}

/// Positive: a zero-length framed body is representable — the terminal chunk alone still fits.
#[test]
fn an_empty_framed_body_is_accepted() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    assert_eq!(decoded_of(&framing, Some("0"), 512), Ok(Some(0)));
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative: the header is forbidden, not ignored, outside a framed mode. Two answers to "how
/// long is this body" is what a smuggler needs; ignoring one of them leaves both on the wire.
#[test]
fn c_ing_0040_a_decoded_length_on_a_non_framed_body_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::unsigned_payload()).expect("a consistent source");
    assert_eq!(
        decoded_of(&framing, Some("1024"), 4096),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed))
    );
}

/// Negative: the other half of the same rule — a framed body without the header.
#[test]
fn c_ing_0041_a_framed_body_without_a_decoded_length_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    assert_eq!(
        decoded_of(&framing, None, 4096),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMissing))
    );
}

/// Negative: every spelling of the decoded length that some parser accepts and others do not.
#[test]
fn a_decoded_length_that_is_not_a_bare_run_of_digits_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    for spelling in ["+1024", "-1024", "0x400", " 1024", "1024 ", "1_024", "", "1024\t"] {
        assert_eq!(
            decoded_of(&framing, Some(spelling), 1 << 20),
            Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMalformed)),
            "spelling {spelling:?} must be refused"
        );
    }
}

/// Negative: a decoded length that cannot be represented at all.
#[test]
fn a_decoded_length_that_overflows_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    assert_eq!(
        decoded_of(&framing, Some("99999999999999999999"), u64::MAX),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMalformed))
    );
}

/// Negative: more decoded bytes than the wire can carry.
#[test]
fn c_ing_0042_a_decoded_length_larger_than_the_wire_length_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    assert_eq!(
        decoded_of(&framing, Some("4096"), 1024),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength {
            decoded: 4096,
            wire: 1024,
        }))
    );
}

/// Negative: exactly equal is still refused — framing occupies bytes, so a body cannot be all
/// payload. This is the boundary an off-by-one would open.
#[test]
fn a_decoded_length_equal_to_the_wire_length_leaves_no_room_for_framing() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    let err = decoded_of(&framing, Some("1024"), 1024).expect_err("framing must fit too");
    assert!(matches!(
        err,
        ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength { .. })
    ));
}

/// Negative: unsigned framing is cheaper per chunk, but not free — the boundary moves, it does
/// not disappear.
#[test]
fn unsigned_framing_still_requires_room_for_its_own_overhead() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("a consistent source");
    assert!(decoded_of(&framing, Some("1024"), 1033).is_err(), "10 bytes is the exact minimum");
    assert_eq!(decoded_of(&framing, Some("1024"), 1034), Ok(Some(1024)));
}

/// Negative: `Transfer-Encoding: chunked` does not excuse the decoded length. With no
/// `Content-Length` it is the only number the body is held to, so its absence is refused exactly
/// as it is under a declared wire length (rustfs/gateway#750).
#[test]
fn c_ing_0041_a_framed_body_under_transfer_encoding_chunked_without_a_decoded_length_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("a consistent source");
    assert_eq!(
        validate_decoded_length(&framing, None, &transfer_chunked()),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMissing))
    );
}

/// Negative: the spelling rules do not relax when the transport ends the body. A decoded length
/// that is the only ceiling has to be the one every parser reads the same way.
#[test]
fn a_malformed_decoded_length_under_transfer_encoding_chunked_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    for spelling in ["+1024", "0x400", " 1024", "", "99999999999999999999"] {
        assert_eq!(
            validate_decoded_length(&framing, Some(spelling), &transfer_chunked()),
            Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMalformed)),
            "spelling {spelling:?} must be refused"
        );
    }
}

/// Negative: an HTTP/1.1 framed body with neither `Content-Length` nor `Transfer-Encoding` has a
/// zero-length body (RFC 9112 §6.3), and a decoded length cannot fit in zero wire bytes. Only a
/// transport that delimits the body itself replaces the wire length with the decoded one.
#[test]
fn a_framed_http11_body_with_neither_length_header_is_still_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    let wire = Framing::classify(Version::HTTP_11, &HeaderMap::new(), &Limits::default()).expect("no body is well formed");
    assert_eq!(
        validate_decoded_length(&framing, Some("1024"), &wire),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength {
            decoded: 1024,
            wire: 0,
        }))
    );
}

/// Negative: an HTTP/2 request that does declare `Content-Length` is still held to rule C-7. The
/// transport-delimited acceptance is for the absent header, not a way around a present one.
#[test]
fn an_http2_framed_body_that_declares_a_content_length_is_still_bound_by_it() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1024"));
    let wire = Framing::classify(Version::HTTP_2, &headers, &Limits::default()).expect("a declared length");
    assert_eq!(
        validate_decoded_length(&framing, Some("4096"), &wire),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength {
            decoded: 4096,
            wire: 1024,
        }))
    );
}

/// Negative: HTTP's own framing conflict is refused before the payload framing is ever consulted.
/// The two layers are separate decisions and the outer one fails first.
#[test]
fn a_content_length_transfer_encoding_conflict_never_reaches_the_payload_framing() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1024"));
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    assert_eq!(
        Framing::classify(Version::HTTP_11, &headers, &Limits::default()),
        Err(WireReject::ContentLengthTransferEncodingConflict)
    );
}

/// Negative: a source that says "framed" and "no decoded length required" contradicts itself, and
/// a pipeline built on it would apply its ceilings to a body shape it is not reading.
#[test]
fn a_source_that_contradicts_itself_is_refused() {
    let mut fixture = FramingFixture::streaming_signed();
    fixture.decoded_length_required = false;
    assert_eq!(
        ChunkFraming::derive(&fixture),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMissing))
    );

    let mut fixture = FramingFixture::unsigned_payload();
    fixture.decoded_length_required = true;
    assert_eq!(
        ChunkFraming::derive(&fixture),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed))
    );
}

/// Negative: chunk signatures without framing, and a declared trailer without framing, are both
/// states a real payload mode cannot reach — and are refused here rather than half-honoured.
#[test]
fn signatures_or_trailers_without_framing_are_refused() {
    let mut fixture = FramingFixture::unsigned_payload();
    fixture.signed = true;
    assert!(ChunkFraming::derive(&fixture).is_err());

    let mut fixture = FramingFixture::unsigned_payload();
    fixture.trailers = true;
    assert!(ChunkFraming::derive(&fixture).is_err());
}

/// Negative, and the rule the whole module is arranged around: the chunk parser cannot be
/// constructed for a body the signature did not declare framed. `Content-Encoding: aws-chunked`
/// has no route into this decision — there is no method on the source that could carry it.
#[test]
fn c_ing_0020_a_pipeline_cannot_be_built_for_a_body_the_signature_did_not_frame() {
    let framing = ChunkFraming::derive(&FramingFixture::unsigned_payload()).expect("a consistent source");
    let built = IngestPipeline::new(
        ScriptReader::new(b"anything".to_vec(), 8),
        framing,
        declared_length(8),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    );
    assert!(matches!(
        built.err(),
        Some(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed))
    ));
}

/// Negative: the body ceiling still applies to the wire length of a framed upload; the payload
/// framing does not exempt a request from the limits the head is subject to.
#[test]
fn the_wire_body_ceiling_still_applies_to_a_framed_upload() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("99999999999"));
    let limits = Limits {
        max_body_bytes: 1024,
        ..no_body_ceiling()
    };
    assert!(Framing::classify(Version::HTTP_11, &headers, &limits).is_err());
}

// ── a body the transport ends (rustfs/gateway#750) ──────────────────────────────────────────────

/// `Transfer-Encoding: chunked` and no `Content-Length`: the shape botocore sends for a trailer
/// upload over TLS.
fn transfer_chunked() -> Framing {
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    Framing::classify(Version::HTTP_11, &headers, &Limits::default()).expect("chunked is well formed")
}

/// An HTTP/2 head with no `Content-Length`: the stream's `END_STREAM` ends the body (RFC 9113
/// §8.1), so there is no wire length to hold a decoded length against either.
fn http2_without_a_length() -> Framing {
    Framing::classify(Version::HTTP_2, &HeaderMap::new(), &Limits::default()).expect("an HTTP/2 head")
}

/// Positive: `aws-chunked` inside `Transfer-Encoding: chunked` is accepted with the declared
/// decoded length, which AWS makes mandatory for every streaming upload precisely because the
/// encoded length may be absent. That number becomes the ceiling the decoder holds the body to.
#[test]
fn c_ing_0006_a_framed_body_under_transfer_encoding_chunked_takes_its_decoded_length() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("a consistent source");
    let decoded = validate_decoded_length(&framing, Some("1024"), &transfer_chunked());
    assert_eq!(decoded.map(|length| length.map(rustfs_gateway_http::DecodedLength::get)), Ok(Some(1024)));
}

/// Positive: the same over HTTP/2 without `Content-Length`, signed or not, empty or not.
#[test]
fn a_framed_body_on_http2_without_a_content_length_takes_its_decoded_length() {
    for fixture in [FramingFixture::streaming_signed(), FramingFixture::streaming_unsigned()] {
        let framing = ChunkFraming::derive(&fixture).expect("a consistent source");
        for (header, expected) in [("1024", 1024), ("0", 0)] {
            let decoded = validate_decoded_length(&framing, Some(header), &http2_without_a_length());
            assert_eq!(
                decoded.map(|length| length.map(rustfs_gateway_http::DecodedLength::get)),
                Ok(Some(expected))
            );
        }
    }
}

/// A pipeline over unsigned framing whose decoded length was validated against a
/// `Transfer-Encoding: chunked` head — so no wire length stands behind it.
fn transport_delimited_pipeline(body: Vec<u8>, declared: u64, limits: ChunkLimits) -> IngestPipeline<ScriptReader> {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_unsigned()).expect("a consistent source");
    let declared = validate_decoded_length(&framing, Some(&declared.to_string()), &transfer_chunked())
        .expect("head-level checks pass without a wire length")
        .expect("a framed body always yields a decoded length");
    IngestPipeline::new(
        ScriptReader::new(body, 4096),
        framing,
        declared,
        None,
        no_observers(),
        limits,
        IngestPolicy::default(),
    )
    .expect("an unsigned pipeline without a signer is well formed")
}

/// Positive: a transport-delimited body of exactly its decoded length arrives whole and may be
/// committed.
#[test]
fn a_transport_delimited_body_of_exactly_its_decoded_length_is_delivered() {
    let payload = vec![b'p'; 512];
    let mut pipeline = transport_delimited_pipeline(unsigned_body(&[&payload, &payload]), 1024, ChunkLimits::default());
    let delivered = drain_pipeline(&mut pipeline, 4096).map(|bytes| bytes.len());
    assert_eq!(delivered.ok(), Some(1024));
    assert_eq!(pipeline.decoded_bytes(), 1024);
    assert!(pipeline.commit_allowed());
}

/// Negative: with no wire length the decoded length is the ceiling, so the first byte past it is
/// refused and the counter never passes the declaration.
#[test]
fn a_transport_delimited_body_longer_than_its_decoded_length_is_refused() {
    let payload = vec![b'p'; 512];
    let body = unsigned_body(&[&payload, &payload, &payload]);
    let mut pipeline = transport_delimited_pipeline(body, 1024, ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("the third chunk is over the declaration");
    assert_eq!(pipeline.reject(), Some(ChunkReject::DecodedLengthOverflow { declared: 1024 }));
    assert_eq!(pipeline.decoded_bytes(), 1024);
    assert!(!pipeline.commit_allowed());
}

/// Negative: and a short body is refused at the terminal chunk rather than committed short.
#[test]
fn a_transport_delimited_body_shorter_than_its_decoded_length_is_refused() {
    let payload = vec![b'p'; 1023];
    let mut pipeline = transport_delimited_pipeline(unsigned_body(&[&payload]), 1024, ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("one byte short");
    assert_eq!(
        pipeline.reject(),
        Some(ChunkReject::DecodedLengthUnderflow {
            declared: 1024,
            actual: 1023
        })
    );
    assert!(!pipeline.commit_allowed());
}

/// Negative: the chunk-count ceiling is derived from the decoded length, so it still bounds a
/// micro-chunk flood when there is no wire length to bound it.
#[test]
fn the_chunk_count_ceiling_still_bounds_a_transport_delimited_body() {
    let mut body = Vec::new();
    for _ in 0..4096 {
        body.extend_from_slice(b"1\r\nx\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    let mut pipeline = transport_delimited_pipeline(body, 4096, ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("a flood of one-byte chunks");
    assert!(
        matches!(pipeline.reject(), Some(ChunkReject::TooManyChunks { .. })),
        "got {:?}",
        pipeline.reject()
    );
}

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
//!
//! 5 positive / 13 negative.

mod support;

use http::{HeaderMap, HeaderValue, Version, header::CONTENT_LENGTH, header::TRANSFER_ENCODING};
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, Framing, IngestPipeline, IngestPolicy, Limits, ModeConfusion, WireReject,
    validate_decoded_length,
};
use support::ingest::{FramingFixture, ScriptReader, declared_length, no_body_ceiling, no_observers, wire_framing_with_length};

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
fn unsigned_streaming_with_a_trailer_is_framed_but_unsigned() {
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
fn a_decoded_length_that_fits_inside_the_wire_length_is_accepted() {
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
fn a_decoded_length_on_a_non_framed_body_is_refused() {
    let framing = ChunkFraming::derive(&FramingFixture::unsigned_payload()).expect("a consistent source");
    assert_eq!(
        decoded_of(&framing, Some("1024"), 4096),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed))
    );
}

/// Negative: the other half of the same rule — a framed body without the header.
#[test]
fn a_framed_body_without_a_decoded_length_is_refused() {
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
fn a_decoded_length_larger_than_the_wire_length_is_refused() {
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

/// Negative: `aws-chunked` layered inside `Transfer-Encoding: chunked` gives two independently
/// declared ends, so rule C-7 has nothing to check the inner one against.
#[test]
fn a_framed_body_under_transfer_encoding_chunked_has_no_wire_length_to_check() {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("a consistent source");
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    let wire = Framing::classify(Version::HTTP_11, &headers, &Limits::default()).expect("chunked is well formed");
    assert_eq!(
        validate_decoded_length(&framing, Some("1024"), &wire),
        Err(ChunkReject::ModeConfusion(ModeConfusion::WireLengthMissing))
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
fn a_pipeline_cannot_be_built_for_a_body_the_signature_did_not_frame() {
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

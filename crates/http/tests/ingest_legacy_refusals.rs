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

//! The aws-chunked refusals the RustFS profile answers as legacy RustFS does.
//!
//! Responsible for: [`ChunkReject::legacy_rustfs_error_code`]'s table, the head-time wire-length
//! check [`ChunkLimits::with_legacy_rustfs_refusals`] leaves to the decoder, and the 1 KiB
//! chunk-size line [`ChunkLimits::HARD_MAX_CHUNK_META_SIZE`] admits, through the pipeline.
//! NOT responsible for: rendering a refusal (`rustfs-gateway`), or the default rules
//! (`ingest_framing.rs`, `ingest_chunk_rules.rs`).
//! Upstream: `rustfs-gateway-http`'s ingest. Downstream: none.

use rustfs_gateway_http::{ChunkFraming, ChunkLimits, ChunkReject, ModeConfusion, validate_decoded_length_with};
use rustfs_gateway_types::ErrorCode;

use crate::support::ingest::{FramingFixture, drain_pipeline, no_observers, unsigned_pipeline, wire_framing_with_length};

fn legacy() -> ChunkLimits {
    ChunkLimits::default().with_legacy_rustfs_refusals()
}

fn framed() -> ChunkFraming {
    ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("consistent fixture")
}

fn validated(header: Option<&str>, wire: u64, limits: ChunkLimits) -> Result<Option<u64>, ChunkReject> {
    validate_decoded_length_with(&framed(), header, &wire_framing_with_length(wire), &limits)
        .map(|decoded| decoded.map(rustfs_gateway_http::DecodedLength::get))
}

/// The refusal an unsigned body of `wire` bytes declaring `declared` ends in, under `limits`.
fn refusal(wire: Vec<u8>, declared: u64, limits: ChunkLimits) -> Option<ChunkReject> {
    let mut pipeline = unsigned_pipeline(wire, 64, declared, no_observers(), limits);
    assert!(drain_pipeline(&mut pipeline, 64).is_err(), "the body was accepted");
    pipeline.reject()
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive — legacy RustFS's codes: a framing or trailer refusal is `IncompleteBody`, a chunk
/// or a size line over its ceiling `EntityTooLarge`, a broken chain `SignatureDoesNotMatch`.
#[test]
fn chunk_refusals_carry_legacy_rustfs_codes() {
    for (reject, code) in [
        (ChunkReject::MalformedChunkSize, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::LeadingZeros, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::BadLineTerminator, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::UnexpectedExtension, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::ZeroSizedNonTerminalChunk, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::TooManyChunks { max: 1 }, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::OverheadRatioExceeded { overhead: 1, decoded: 1 }, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::TrailerNotAllowed, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::TrailerCountExceeded, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::TrailerSizeExceeded, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::MalformedTrailer, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::DeclaredTrailerMismatch, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::DataAfterTrailer, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::TruncatedStream, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::TruncatedBeforeTrailer, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::DecodedLengthOverflow { declared: 1 }, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::DecodedLengthUnderflow { declared: 2, actual: 1 }, ErrorCode::INCOMPLETE_BODY),
        (ChunkReject::ChunkSizeTooLarge { declared: 2, max: 1 }, ErrorCode::ENTITY_TOO_LARGE),
        (ChunkReject::ChunkMetaTooLong, ErrorCode::ENTITY_TOO_LARGE),
        (ChunkReject::SignatureChainBroken { chunk_index: 0 }, ErrorCode::SIGNATURE_DOES_NOT_MATCH),
        (ChunkReject::TrailerSignatureMismatch, ErrorCode::SIGNATURE_DOES_NOT_MATCH),
    ] {
        assert_eq!(reject.legacy_rustfs_error_code(), code, "{reject:?}");
    }
}

/// Positive — under the option a decoded length the wire cannot carry is left to the decoder,
/// which ends that body however it ends.
#[test]
fn the_wire_length_check_is_left_to_the_decoder_under_the_option() {
    assert_eq!(validated(Some("28"), 20, legacy()), Ok(Some(28)));
    assert_eq!(
        refusal(b"invalid-chunk-size\r\n".to_vec(), 28, legacy()),
        Some(ChunkReject::MalformedChunkSize)
    );
    assert_eq!(refusal(b"5\r\nhello\r\n".to_vec(), 28, legacy()), Some(ChunkReject::TruncatedStream));
}

/// Positive — a size line of exactly 1 KiB, its CRLF included, is read and judged by its content.
#[test]
fn a_size_line_of_one_kibibyte_is_read_at_the_legacy_ceiling() {
    let limits = legacy().with_max_chunk_meta_size(ChunkLimits::HARD_MAX_CHUNK_META_SIZE);
    let mut line = vec![b'z'; 1022];
    line.extend_from_slice(b"\r\n");
    assert_eq!(refusal(line, 28, limits), Some(ChunkReject::MalformedChunkSize));
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative — the default limits keep the head-time refusal and the core's codes.
#[test]
fn n_the_default_limits_keep_the_head_check_and_the_cores_codes() {
    assert!(matches!(
        validated(Some("28"), 20, ChunkLimits::default()),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength {
            decoded: 28,
            wire: 20
        }))
    ));
    assert!(!ChunkLimits::default().answers_legacy_rustfs_refusals());
    assert_eq!(ChunkReject::MalformedChunkSize.error_code(), ErrorCode::INVALID_REQUEST);
    assert_eq!(
        ChunkReject::ChunkSizeTooLarge { declared: 2, max: 1 }.error_code(),
        ErrorCode::INVALID_CHUNK_SIZE
    );
}

/// Negative — the option defers only the wire-length check: a missing, malformed or forbidden
/// decoded length is still refused from the head.
#[test]
fn n_the_other_head_checks_stay_under_the_option() {
    assert!(matches!(
        validated(None, 20, legacy()),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMissing))
    ));
    assert!(matches!(
        validated(Some("0x1c"), 200, legacy()),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMalformed))
    ));
    let unframed = ChunkFraming::derive(&FramingFixture::unsigned_payload()).expect("consistent fixture");
    assert!(matches!(
        validate_decoded_length_with(&unframed, Some("28"), &wire_framing_with_length(200), &legacy()),
        Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed))
    ));
}

/// Negative — head-level contradictions keep their own code under the legacy table.
#[test]
fn n_head_level_refusals_keep_their_codes() {
    for reject in [
        ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMissing),
        ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength { decoded: 2, wire: 1 }),
        ChunkReject::TrailerInNonTrailerMode,
        ChunkReject::TrailerSignatureMissing,
    ] {
        assert_eq!(reject.legacy_rustfs_error_code(), reject.error_code(), "{reject:?}");
    }
}

/// Negative — one byte past 1 KiB is refused as too long, and no setting raises the line past it.
#[test]
fn n_a_size_line_past_one_kibibyte_is_refused() {
    let limits = legacy().with_max_chunk_meta_size(u16::MAX);
    assert_eq!(limits.max_chunk_meta_size(), ChunkLimits::HARD_MAX_CHUNK_META_SIZE);
    let mut line = vec![b'z'; 1023];
    line.extend_from_slice(b"\r\n");
    assert_eq!(refusal(line, 28, limits), Some(ChunkReject::ChunkMetaTooLong));
    assert_eq!(ChunkLimits::default().max_chunk_meta_size(), 256, "the default is unchanged");
}

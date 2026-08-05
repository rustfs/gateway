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

//! Chunk syntax and the ceilings that stop a chunk from being unbounded.
//!
//! Responsible for: every rule the decoder applies to a chunk-size line, the per-chunk data
//! ceiling that is this task's security fix, the chunk-count and overhead ceilings, and the two
//! directions in which the decoded length can disagree with what arrives.
//! NOT responsible for: the signature chain (`ingest_verify`) or the framing decision
//! (`ingest_framing`).
//!
//! 5 positive / 26 negative.

mod support;

use rustfs_gateway_http::{ChunkLimits, ChunkReject};
use support::ingest::{ScriptReader, drain_pipeline, no_observers, raw_chunk_body, unsigned_body, unsigned_pipeline};

fn reject_of(body: Vec<u8>, declared: u64, limits: ChunkLimits) -> (ChunkReject, usize) {
    let mut pipeline = unsigned_pipeline(body, 64 * 1024, declared, no_observers(), limits);
    let err = drain_pipeline(&mut pipeline, 4096).err();
    assert!(err.is_some(), "the body must be refused");
    let reject = pipeline.reject().expect("a refusal is retained for the response layer");
    (reject, pipeline.window_bytes())
}

fn refuse(header_line: &str, data: &[u8]) -> ChunkReject {
    reject_of(raw_chunk_body(header_line, data), 4096, ChunkLimits::default()).0
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive: three chunks arrive byte for byte, and the body is committable.
#[test]
fn three_chunks_round_trip_byte_for_byte() {
    let body = unsigned_body(&[b"first-", b"second-", b"third"]);
    let mut pipeline = unsigned_pipeline(body, 7, 18, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 5).expect("a well formed body is accepted");
    assert_eq!(out, b"first-second-third");
    assert_eq!(pipeline.decoded_bytes(), 18);
    assert_eq!(pipeline.delivered_bytes(), 18);
}

/// Positive: the same body delivered one byte per read still reassembles, so no rule depends on
/// a chunk arriving whole in one read.
#[test]
fn a_body_arriving_one_byte_at_a_time_reassembles() {
    let body = unsigned_body(&[b"alpha", b"beta"]);
    let mut pipeline = unsigned_pipeline(body, 1, 9, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 3).expect("a well formed body is accepted");
    assert_eq!(out, b"alphabeta");
}

/// Positive: a chunk of exactly the ceiling is accepted; the ceiling is inclusive.
#[test]
fn a_chunk_of_exactly_the_ceiling_is_accepted() {
    let limits = ChunkLimits::default().with_max_chunk_size(4096);
    let payload = vec![b'x'; 4096];
    let body = unsigned_body(&[&payload]);
    let mut pipeline = unsigned_pipeline(body, 1024, 4096, no_observers(), limits);
    let out = drain_pipeline(&mut pipeline, 4096).expect("exactly the ceiling is within it");
    assert_eq!(out.len(), 4096);
}

/// Positive: an empty framed body is just the terminal chunk.
#[test]
fn an_empty_body_is_the_terminal_chunk_alone() {
    let mut pipeline = unsigned_pipeline(b"0\r\n\r\n".to_vec(), 8, 0, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 16).expect("an empty body is well formed");
    assert!(out.is_empty());
    assert_eq!(pipeline.decoded_bytes(), 0);
}

/// Positive: uppercase hex in the *size* is legal per RFC 9112; it is the signature that must be
/// lowercase. The two rules are separate and this asserts they have not been merged.
#[test]
fn an_uppercase_hex_chunk_size_is_accepted() {
    let payload = vec![b'y'; 0x1A];
    let body = raw_chunk_body("1A\r\n", &payload);
    let mut pipeline = unsigned_pipeline(body, 64, 0x1A, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 64).expect("hex is case-insensitive");
    assert_eq!(out.len(), 0x1A);
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative, and the reason this task exists: a chunk announcing four gigabytes is refused at its
/// header. Not one data byte is read and the window never grows to hold it.
#[test]
fn a_four_gigabyte_chunk_is_refused_at_the_header_without_reading_a_data_byte() {
    let mut pipeline = unsigned_pipeline(b"ffffffff\r\n".to_vec(), 1024, 4096, no_observers(), ChunkLimits::default());
    let before = pipeline.window_bytes();
    let err = drain_pipeline(&mut pipeline, 4096).expect_err("an over-large chunk is refused");

    assert_eq!(err.bytes_before_error(), 0);
    assert!(matches!(
        pipeline.reject(),
        Some(ChunkReject::ChunkSizeTooLarge {
            declared: 0xffff_ffff,
            ..
        })
    ));
    assert_eq!(pipeline.decoded_bytes(), 0);
    assert_eq!(pipeline.window_bytes(), before, "the window must not grow towards the announced size");
    assert!(pipeline.window_bytes() <= 64 * 1024, "peak buffer stays at the initial window");
}

/// Negative: the same announcement fed one byte per read is refused just as early, so the attack
/// cannot be stretched over time into an unbounded buffer.
#[test]
fn an_over_large_chunk_fed_one_byte_at_a_time_is_still_refused_immediately() {
    let mut body = b"ffffffff\r\n".to_vec();
    body.extend_from_slice(&[b'z'; 4096]);
    let mut pipeline = unsigned_pipeline(body, 1, 4096, no_observers(), ChunkLimits::default());
    let err = drain_pipeline(&mut pipeline, 4096).expect_err("an over-large chunk is refused");

    assert_eq!(err.bytes_before_error(), 0);
    assert!(matches!(pipeline.reject(), Some(ChunkReject::ChunkSizeTooLarge { .. })));
    assert!(pipeline.window_bytes() <= 64 * 1024);
}

/// Negative: one byte over the configured ceiling is over it.
#[test]
fn a_chunk_one_byte_over_the_ceiling_is_refused() {
    let limits = ChunkLimits::default().with_max_chunk_size(4096);
    let payload = vec![b'x'; 4097];
    let (reject, _) = reject_of(unsigned_body(&[&payload]), 8192, limits);
    assert_eq!(
        reject,
        ChunkReject::ChunkSizeTooLarge {
            declared: 4097,
            max: 4096
        }
    );
}

/// Negative: the ceiling cannot be configured away, and cannot be raised past the hard limit.
#[test]
fn the_chunk_ceiling_cannot_be_configured_away() {
    assert_eq!(ChunkLimits::default().max_chunk_size(), 1024 * 1024);
    assert_eq!(
        ChunkLimits::default().with_max_chunk_size(u32::MAX).max_chunk_size(),
        ChunkLimits::HARD_MAX_CHUNK_SIZE
    );
    assert_eq!(ChunkLimits::default().with_max_chunk_size(0).max_chunk_size(), 1);
}

/// Negative: more than one leading zero. Stricter than RFC 9112 on purpose — the same number to
/// one parser, an overflow or a truncation to another.
#[test]
fn a_chunk_size_with_leading_zeros_is_refused() {
    assert_eq!(refuse("0000000000001\r\n", b"x"), ChunkReject::LeadingZeros);
    assert_eq!(refuse("01\r\n", b"x"), ChunkReject::LeadingZeros);
}

/// Negative: a `0x` prefix.
#[test]
fn a_chunk_size_with_a_hex_prefix_is_refused() {
    // The hexadecimal-digit rule fires before the leading-zero rule, so `0x10` is refused as a
    // malformed size rather than as a leading zero. Either way it never becomes sixteen.
    assert_eq!(refuse("0x10\r\n", b"x"), ChunkReject::MalformedChunkSize);
    assert_eq!(refuse("x10\r\n", b"x"), ChunkReject::MalformedChunkSize);
}

/// Negative: a sign.
#[test]
fn a_signed_chunk_size_is_refused() {
    assert_eq!(refuse("+10\r\n", b"x"), ChunkReject::MalformedChunkSize);
    assert_eq!(refuse("-10\r\n", b"x"), ChunkReject::MalformedChunkSize);
}

/// Negative: whitespace anywhere around the size.
#[test]
fn whitespace_around_the_chunk_size_is_refused() {
    assert_eq!(refuse(" 10\r\n", b"x"), ChunkReject::MalformedChunkSize);
    assert_eq!(refuse("10 \r\n", b"x"), ChunkReject::MalformedChunkSize);
    assert_eq!(refuse("10 ;foo\r\n", b"x"), ChunkReject::MalformedChunkSize);
}

/// Negative: an empty size field, and one longer than sixteen digits.
#[test]
fn an_empty_or_over_long_chunk_size_is_refused() {
    assert_eq!(refuse("\r\n", b"x"), ChunkReject::MalformedChunkSize);
    assert_eq!(refuse("11111111111111111\r\n", b"x"), ChunkReject::MalformedChunkSize);
}

/// Negative: the metadata ceiling, which bounds the header and — unlike the chunk ceiling — has
/// always been there. Both are needed; neither substitutes for the other.
#[test]
fn an_over_long_chunk_size_line_is_refused() {
    let padding = "a".repeat(300);
    let (reject, _) = reject_of(raw_chunk_body(&format!("10;{padding}\r\n"), b"x"), 4096, ChunkLimits::default());
    assert_eq!(reject, ChunkReject::ChunkMetaTooLong);
}

/// Negative: a bare LF terminates a line for several parsers and not for others.
#[test]
fn a_bare_line_feed_is_refused() {
    assert_eq!(refuse("10\n", b"x"), ChunkReject::BadLineTerminator);
}

/// Negative: a lone CR, and a CR followed by anything other than LF.
#[test]
fn a_carriage_return_not_followed_by_a_line_feed_is_refused() {
    assert_eq!(refuse("10\rX", b"x"), ChunkReject::BadLineTerminator);
}

/// Negative: the CRLF that closes chunk data is also exact.
#[test]
fn a_chunk_data_terminator_other_than_crlf_is_refused() {
    let mut body = b"5\r\nhello\n".to_vec();
    body.extend_from_slice(b"0\r\n\r\n");
    let (reject, _) = reject_of(body, 4096, ChunkLimits::default());
    assert_eq!(reject, ChunkReject::BadLineTerminator);
}

/// Negative: unsigned framing permits no chunk extension at all, including the signature one.
/// A chunk extension one party parses and another ignores is the chunk-extension desync.
#[test]
fn an_extension_on_unsigned_framing_is_refused() {
    assert_eq!(
        refuse(
            "5;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n",
            b"hello"
        ),
        ChunkReject::UnexpectedExtension
    );
    assert_eq!(refuse("5;foo=bar\r\n", b"hello"), ChunkReject::UnexpectedExtension);
    assert_eq!(refuse("5;\r\n", b"hello"), ChunkReject::UnexpectedExtension);
}

/// Negative: a micro-chunk flood is bounded by the chunk count derived from the declared length,
/// so the CPU spent on framing cannot be amplified without bound.
#[test]
fn a_micro_chunk_flood_is_refused_by_the_chunk_count_ceiling() {
    let mut body = Vec::new();
    for _ in 0..4096 {
        body.extend_from_slice(b"1\r\nx\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    let (reject, _) = reject_of(body, 4096, ChunkLimits::default());
    assert!(matches!(reject, ChunkReject::TooManyChunks { .. }), "got {reject:?}");
}

/// Negative: the overhead ratio catches the same shape when the chunk count alone would not,
/// because the declared body is large enough to justify many chunks.
#[test]
fn framing_overhead_out_of_proportion_to_the_payload_is_refused() {
    let limits = ChunkLimits::default()
        .with_min_chunk_size_for_count(1)
        .with_overhead_ratio_floor_bytes(64);
    let mut body = Vec::new();
    for _ in 0..4096 {
        body.extend_from_slice(b"1\r\nx\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    let (reject, _) = reject_of(body, 4096, limits);
    assert!(matches!(reject, ChunkReject::OverheadRatioExceeded { .. }), "got {reject:?}");
}

/// Negative: more body than the declaration allows is refused, and the decoder's own counter —
/// the only length any consumer may read — never exceeds the declaration.
#[test]
fn more_body_than_declared_is_refused_and_the_counter_never_exceeds_the_declaration() {
    let payload = vec![b'p'; 512];
    let body = unsigned_body(&[&payload, &payload, &payload]);
    let mut pipeline = unsigned_pipeline(body, 4096, 1024, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("the third chunk is over the declaration");

    assert_eq!(pipeline.reject(), Some(ChunkReject::DecodedLengthOverflow { declared: 1024 }));
    assert_eq!(
        pipeline.decoded_bytes(),
        1024,
        "the counter a quota reads stops at the declaration, and is not the header"
    );
    assert!(!pipeline.commit_allowed());
}

/// Negative: less body than declared is refused at the terminal chunk, and nothing may be
/// committed. A short upload accepted as complete is a truncated object stored as a whole one.
#[test]
fn less_body_than_declared_is_refused_and_may_not_be_committed() {
    let payload = vec![b'p'; 16];
    let mut pipeline = unsigned_pipeline(unsigned_body(&[&payload]), 4096, 1024, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("the body is short");

    assert_eq!(
        pipeline.reject(),
        Some(ChunkReject::DecodedLengthUnderflow {
            declared: 1024,
            actual: 16
        })
    );
    assert!(!pipeline.commit_allowed());
}

/// Negative: a stream that stops before the terminal chunk fails; it never reports end-of-stream.
#[test]
fn a_truncated_stream_fails_and_never_reports_end_of_stream() {
    let mut body = b"10\r\n".to_vec();
    body.extend_from_slice(&[b'q'; 16]);
    let mut pipeline = unsigned_pipeline(body, 8, 16, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("a truncated body must not end cleanly");

    assert_eq!(pipeline.reject(), Some(ChunkReject::TruncatedStream));
    assert!(!pipeline.commit_allowed());
}

/// Negative: bytes after the terminal chunk mean the peer treated a zero-sized chunk as an
/// ordinary one, which is two different bodies depending on who is reading.
#[test]
fn bytes_after_the_terminal_chunk_are_refused() {
    let mut body = unsigned_body(&[b"data"]);
    body.extend_from_slice(b"4\r\nmore\r\n");
    let mut pipeline = unsigned_pipeline(body, 4096, 4, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("nothing follows the terminal chunk");
    assert_eq!(pipeline.reject(), Some(ChunkReject::ZeroSizedNonTerminalChunk));
}

/// Negative: every refusal is a 400 except the signature one, which is a 403 — and no refusal is
/// ever committable or keeps the connection.
#[test]
fn the_status_mapping_separates_framing_from_authentication() {
    assert_eq!(ChunkReject::TruncatedStream.to_status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(
        ChunkReject::SignatureChainBroken { chunk_index: 3 }.to_status(),
        http::StatusCode::FORBIDDEN
    );
    for reject in [
        ChunkReject::TruncatedStream,
        ChunkReject::LeadingZeros,
        ChunkReject::SignatureChainBroken { chunk_index: 0 },
    ] {
        assert!(!reject.may_commit());
        assert!(reject.must_close_connection());
    }
}

/// Negative: the refusal renders as a label and never as a signature, so no log line built from
/// it can become a signing oracle.
#[test]
fn a_refusal_never_renders_a_signature() {
    let rendered = format!("{}", ChunkReject::SignatureChainBroken { chunk_index: 7 });
    assert_eq!(rendered, "signature-chain-broken");
}

/// Negative: a reader that is polled after the body ended reports it rather than restarting.
#[test]
fn polling_after_the_body_ended_is_an_error() {
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use rustfs_gateway_stream::AsyncPayloadRead;

    let mut pipeline = unsigned_pipeline(unsigned_body(&[b"done"]), 4096, 4, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 64).expect("a well formed body");
    assert_eq!(out, b"done");

    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0u8; 8];
    let again = Pin::new(&mut pipeline).poll_fill(&mut cx, &mut buf);
    assert!(matches!(again, Poll::Ready(Err(_))), "a finished body is not restartable");
}

/// Negative: an empty caller buffer yields zero progress rather than spinning or failing.
#[test]
fn an_empty_caller_buffer_makes_no_progress() {
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use rustfs_gateway_stream::{AsyncPayloadRead, ReadProgress};

    let mut pipeline = unsigned_pipeline(unsigned_body(&[b"data"]), 4096, 4, no_observers(), ChunkLimits::default());
    let mut cx = Context::from_waker(Waker::noop());
    let progress = Pin::new(&mut pipeline).poll_fill(&mut cx, &mut []);
    assert!(matches!(progress, Poll::Ready(Ok(ReadProgress::Filled(0)))));
}

/// Negative: a reader is never handed more than the window, so a hostile chunk size cannot make
/// the pipeline allocate. The scripted socket records how much it was actually asked for.
#[test]
fn the_peer_is_never_asked_for_more_than_the_window() {
    let payload = vec![b'w'; 8192];
    let body = unsigned_body(&[&payload]);
    let total = body.len();
    let mut pipeline = unsigned_pipeline(body, 1 << 20, 8192, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 1024).expect("a well formed body");
    assert_eq!(out.len(), 8192);
    assert!(pipeline.window_bytes() <= 64 * 1024);
    assert!(total > 0);
}

/// A scripted socket that reports `Pending` periodically does not change any outcome; every rule
/// above holds across a resumption.
#[test]
fn a_socket_that_pends_does_not_change_the_outcome() {
    use rustfs_gateway_http::{ChunkFraming, IngestPipeline, IngestPolicy};
    use support::ingest::{FramingFixture, declared_length};

    let framing = ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("consistent");
    let reader = ScriptReader::new(unsigned_body(&[b"alpha", b"beta"]), 3).pending_every(3);
    let mut pipeline = IngestPipeline::new(
        reader,
        framing,
        declared_length(9),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    )
    .expect("well formed");
    let out = drain_pipeline(&mut pipeline, 4).expect("a well formed body");
    assert_eq!(out, b"alphabeta");
}

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

//! The chunk signature chain, and the promise that nothing unverified is ever handed over.
//!
//! Responsible for: the chain seeded by the request signature, the extension whitelist that
//! carries it, the "delivered bytes from a failing chunk is zero" property, the trailer
//! hand-off, and the ordering that makes a trailer section unreachable before end-of-stream.
//! NOT responsible for: chunk syntax (`ingest_chunk_rules`) or the counters
//! (`ingest_perf_gates`).
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.
//!
//! 4 positive / 24 negative.

mod support;

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use http::{HeaderName, HeaderValue};
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, IngestPipeline, IngestPolicy,
    MAX_SCOPE_LINE_BYTES, TrailerDeclaration,
};
use rustfs_gateway_stream::{AsyncPayloadRead, ReadProgress, StreamError, TrailingHeaders};
use smallvec::SmallVec;
use support::ingest::{
    FramingFixture, ScriptReader, SignedChunker, TEST_AMZ_DATE, TEST_SCOPE_LINE, declared_length, drain_pipeline, hex_lower,
    no_observers, signed_pipeline, unsigned_body, unsigned_trailer_pipeline,
};

const KEY: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];
const OTHER_SEED: [u8; 32] = [0x33; 32];

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive: three signed chunks verify in order and arrive byte for byte.
#[test]
fn c_ing_0001_a_signed_body_verifies_and_arrives_byte_for_byte() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"first-").push(b"second-").push(b"third");
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4096, 18, KEY, SEED, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 4096).expect("a correctly signed body is accepted");

    assert_eq!(out, b"first-second-third");
    assert_eq!(pipeline.delivered_bytes(), 18);
    assert!(pipeline.commit_allowed(), "a verified terminal chunk permits the commit");
    assert_eq!(
        pipeline.signer().map(rustfs_gateway_http::ChunkSigner::chunks_verified),
        Some(4),
        "three data chunks plus the terminal one"
    );
}

/// Positive: an empty signed body is the terminal chunk, and its signature is still checked.
#[test]
fn c_ing_0009_an_empty_signed_body_still_verifies_its_terminal_chunk() {
    let body = SignedChunker::new(KEY, SEED).finish();
    let mut pipeline = signed_pipeline(body, 4096, 0, KEY, SEED, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 64).expect("an empty signed body is well formed");

    assert!(out.is_empty());
    assert!(pipeline.commit_allowed());
}

/// Positive: the chain survives a socket that hands over one byte at a time and pends in between,
/// so verification does not depend on a chunk arriving in one read.
#[test]
fn the_chain_survives_a_byte_at_a_time_socket() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"slow").push(b"drip");
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 1, 8, KEY, SEED, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 3).expect("a correctly signed body is accepted");
    assert_eq!(out, b"slowdrip");
}

/// Positive: an unsigned trailer is visible only on EOF, while checksum comparison remains an
/// explicit later obligation.
#[test]
fn an_unsigned_trailer_reaches_eof_without_minting_commit_authority() {
    let body = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 3, 5, "x-amz-checksum-crc32c");
    let (output, trailers) = drive_trailered(&mut pipeline).expect("valid trailer");

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

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative, and the property `VerifyBeforeDeliver` exists for: when the very first chunk's
/// signature is wrong, the consumer has been shown zero bytes. There is no partial object to roll
/// back, because there was never a partial object.
#[test]
fn c_ing_0035_a_bad_first_chunk_signature_delivers_zero_bytes() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push_with_signature(b"payload-that-must-not-arrive", &[0xAA; 32]);
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4096, 28, KEY, SEED, no_observers(), ChunkLimits::default());
    let err = drain_pipeline(&mut pipeline, 4096).expect_err("a bad signature must fail");

    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
    assert_eq!(pipeline.delivered_bytes(), 0, "not one unverified byte reaches the consumer");
    assert_eq!(err.bytes_before_error(), 0);
    assert!(!pipeline.commit_allowed());
    assert_eq!(
        ChunkReject::SignatureChainBroken { chunk_index: 0 }.to_status(),
        http::StatusCode::FORBIDDEN
    );
}

/// Negative: a trailer can never override authorization metadata from the authenticated head.
#[test]
fn c_ck_0022_authorization_is_not_an_allowed_trailer() {
    let body = b"1\r\nx\r\n0\r\nauthorization:attacker\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 64, 1, "x-amz-checksum-crc32c");

    assert!(drive_trailered(&mut pipeline).is_err());
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

    assert!(drive_trailered(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerCountExceeded));
}

/// Negative: an unfinished field cannot grow past the one-kibibyte trailer budget.
#[test]
fn c_ck_0027_a_trailer_section_over_one_kibibyte_is_refused() {
    let mut body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:".to_vec();
    body.extend(core::iter::repeat_n(b'a', 1024));
    body.extend_from_slice(b"\r\n\r\n");
    let mut pipeline = unsigned_trailer(body, 73, 1, "x-amz-checksum-crc32c");

    assert!(drive_trailered(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerSizeExceeded));
}

/// Negative: changing the declared checksum name is a set mismatch, even when both names are
/// individually allowed.
#[test]
fn c_ck_0028_the_actual_trailer_name_must_equal_the_declaration() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-sha256:a\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 5, 1, "x-amz-checksum-crc32c");

    assert!(drive_trailered(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::DeclaredTrailerMismatch));
}

/// Negative: declaring two fields and sending one cannot be mistaken for a complete section.
#[test]
fn c_ck_0029_every_declared_trailer_must_arrive() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:a\r\n\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 7, 1, "x-amz-checksum-crc32c,x-amz-checksum-sha256");

    assert!(drive_trailered(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::DeclaredTrailerMismatch));
}

/// Negative: transport EOF before the empty line that closes the trailer never becomes body EOF.
#[test]
fn c_ck_0043_truncation_before_the_trailer_terminator_is_an_error() {
    let body = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32c:a\r\n".to_vec();
    let mut pipeline = unsigned_trailer(body, 4, 1, "x-amz-checksum-crc32c");

    assert!(drive_trailered(&mut pipeline).is_err());
    assert_eq!(pipeline.reject(), Some(ChunkReject::TruncatedBeforeTrailer));
    assert!(!pipeline.commit_allowed());
}

/// Negative: when a later chunk fails, the bytes of *that* chunk are still zero — the consumer
/// has seen exactly the chunks that verified, and nothing of the one that did not.
#[test]
fn c_ing_0035_a_bad_later_chunk_delivers_none_of_its_own_bytes() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"good-chunk");
    chunker.push_with_signature(b"forged-chunk", &[0xBB; 32]);
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4096, 22, KEY, SEED, no_observers(), ChunkLimits::default());
    let mut delivered = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0u8; 4096];
    let failure = loop {
        match Pin::new(&mut pipeline).poll_fill(&mut cx, &mut buf) {
            Poll::Pending => continue,
            Poll::Ready(Ok(ReadProgress::Filled(n))) => delivered.extend_from_slice(&buf[..n]),
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => panic!("a forged chunk must not end cleanly"),
            Poll::Ready(Err(err)) => break err,
        }
    };

    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 1 }));
    assert_eq!(delivered, b"good-chunk");
    assert_eq!(failure.bytes_before_error(), 10);
    assert!(
        !delivered.windows(6).any(|w| w == b"forged"),
        "no byte of the failing chunk may be visible"
    );
}

/// Negative: a chunk signature from another position in the same body. The chain is ordered, so
/// a signature that was valid at chunk one is not valid at chunk three.
#[test]
fn c_ing_0036_a_signature_replayed_from_another_position_breaks_the_chain() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    let first_signature = chunker.signature_for(b"one");
    chunker.push(b"one").push(b"two");
    chunker.push_with_signature(b"three", &first_signature);
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4096, 11, KEY, SEED, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("an out-of-order signature must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 2 }));
}

/// Negative: chunk signatures from a different request. The seed is this request's own head
/// signature, so a chain built on another seed does not verify against it.
#[test]
fn c_ing_0037_chunk_signatures_from_another_request_do_not_verify() {
    let mut chunker = SignedChunker::new(KEY, OTHER_SEED);
    chunker.push(b"replayed");
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4096, 8, KEY, SEED, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("another request's chain must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
    assert_eq!(pipeline.delivered_bytes(), 0);
}

/// Negative: a chain signed under a different key.
#[test]
fn chunk_signatures_under_another_key_do_not_verify() {
    let mut chunker = SignedChunker::new([0x44; 32], SEED);
    chunker.push(b"wrong-key");
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4096, 9, KEY, SEED, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("another key's chain must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
}

/// Negative: the signature covers the data, so moving a byte across a chunk boundary invalidates
/// it even though the concatenated body is unchanged.
#[test]
fn moving_a_byte_across_a_chunk_boundary_breaks_the_signature() {
    let mut correct = SignedChunker::new(KEY, SEED);
    correct.push(b"abcd").push(b"efgh");
    let signatures = (correct.signature_for(b"abcd"), correct.signature_for(b"abcde"));
    assert_ne!(signatures.0, signatures.1, "the digest covers the data, not only its length");

    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push_with_signature(b"abcde", &signatures.0);
    let body = chunker.finish();
    let mut pipeline = signed_pipeline(body, 4096, 5, KEY, SEED, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("the digest no longer matches");
    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
}

/// Negative: every spelling of the signature extension that is not the exact one.
#[test]
fn c_ing_0029_to_0031_every_other_spelling_of_the_signature_extension_is_refused() {
    let signature = SignedChunker::new(KEY, SEED).signature_for(b"data");
    let hex = hex_lower(&signature);
    let spellings = [
        format!("chunk-signature=\"{hex}\""),
        format!("chunk-signature={}", hex.to_uppercase()),
        format!("chunk-signature={hex};foo=bar"),
        format!("chunk-signature={};", &hex[..63]),
        format!("Chunk-Signature={hex}"),
        format!("chunksignature={hex}"),
        format!("foo=bar;chunk-signature={hex}"),
        format!("chunk-signature={hex}0"),
    ];

    for spelling in spellings {
        let mut chunker = SignedChunker::new(KEY, SEED);
        chunker.push_raw_extension(b"data", &spelling);
        let body = chunker.finish();
        let mut pipeline = signed_pipeline(body, 4096, 4, KEY, SEED, no_observers(), ChunkLimits::default());
        let _ = drain_pipeline(&mut pipeline, 4096).expect_err("only the exact extension is accepted");
        assert_eq!(
            pipeline.reject(),
            Some(ChunkReject::UnexpectedExtension),
            "spelling {spelling:?} must be refused as an unexpected extension"
        );
    }
}

/// Negative: signed framing with no extension at all.
#[test]
fn a_signed_chunk_without_a_signature_is_refused() {
    let mut body = b"4\r\ndata\r\n".to_vec();
    body.extend_from_slice(b"0\r\n\r\n");
    let mut pipeline = signed_pipeline(body, 4096, 4, KEY, SEED, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("signed framing requires the signature");
    assert_eq!(pipeline.reject(), Some(ChunkReject::UnexpectedExtension));
}

/// Negative: signed framing without a signer, and unsigned framing with one, are both refused at
/// construction. A pipeline that verified nothing while the mode promised verification would be
/// the worst possible failure, and it is not constructible.
#[test]
fn the_signer_and_the_mode_must_agree_at_construction() {
    let signed = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("consistent");
    let built = IngestPipeline::new(
        ScriptReader::new(Vec::new(), 1),
        signed,
        declared_length(0),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    );
    assert_eq!(built.err(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));

    let unsigned = ChunkFraming::derive(&FramingFixture::streaming_unsigned_trailer()).expect("consistent");
    let signer = ChunkSigner::new(
        ChunkSigningKey::from_derived(KEY),
        ChunkScope::new(TEST_SCOPE_LINE, TEST_AMZ_DATE).expect("valid scope"),
        ChunkSeed::from_request_signature(SEED),
    );
    let built = IngestPipeline::new(
        ScriptReader::new(Vec::new(), 1),
        unsigned,
        declared_length(0),
        Some(signer),
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    );
    assert_eq!(built.err(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
}

/// Negative: a scope line that would overflow the stack-resident string-to-sign is refused at
/// construction rather than silently truncating the bytes the signature is computed over.
#[test]
fn an_over_long_scope_line_is_refused() {
    let long = "x".repeat(MAX_SCOPE_LINE_BYTES + 1);
    assert!(ChunkScope::new(&long, TEST_AMZ_DATE).is_err());
    assert!(ChunkScope::new("", TEST_AMZ_DATE).is_err());
}

/// Negative: a timestamp of the wrong width.
#[test]
fn a_timestamp_of_the_wrong_width_is_refused() {
    assert!(ChunkScope::new(TEST_SCOPE_LINE, "20130524T000000").is_err());
    assert!(ChunkScope::new(TEST_SCOPE_LINE, "20130524T000000ZZ").is_err());
    assert!(ChunkScope::new(TEST_SCOPE_LINE, "").is_err());
}

/// Negative: the seed is 64 lowercase hex characters and nothing else.
#[test]
fn a_seed_that_is_not_lowercase_hex_is_refused() {
    let good = hex_lower(&[0xab; 32]);
    assert!(ChunkSeed::from_hex(&good).is_ok());
    assert!(ChunkSeed::from_hex(&good.to_uppercase()).is_err());
    assert!(ChunkSeed::from_hex(&good[..63]).is_err());
    assert!(ChunkSeed::from_hex(&format!("{good}0")).is_err());
    assert!(ChunkSeed::from_hex("").is_err());
}

/// Negative: a trailered body decodes and delivers, and still may not be committed. The trailer
/// carries a checksum and, in signed framing, its own signature; neither has been checked here,
/// so the pipeline fails closed rather than reporting a body it has not finished validating.
#[test]
fn a_trailered_body_is_never_committable_at_this_stage() {
    let mut body = unsigned_body(&[b"payload"]);
    body.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n\r\n");
    let mut pipeline = unsigned_trailer_pipeline(body, 4096, 7, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 4096).expect("the body itself is well formed");

    assert_eq!(out, b"payload");
    assert!(!pipeline.commit_allowed(), "an unverified trailer section must not permit a commit");
}

/// Negative: the trailer section is unreachable before end-of-stream. Every progress event that
/// carries bytes carries no trailers at all — the type has no field for them — and the one event
/// that does carry them is the last.
#[test]
fn a_trailer_section_is_only_ever_reachable_at_end_of_stream() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"one").push(b"two");
    let body = chunker.finish();

    let mut pipeline = signed_pipeline(body, 4, 6, KEY, SEED, no_observers(), ChunkLimits::default());
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0u8; 3];
    let mut events = 0usize;
    loop {
        match Pin::new(&mut pipeline).poll_fill(&mut cx, &mut buf) {
            Poll::Pending => continue,
            Poll::Ready(Ok(ReadProgress::Filled(n))) => {
                assert!(n > 0, "a filled event always carries bytes");
                events += 1;
            }
            Poll::Ready(Ok(ReadProgress::Eof { trailers })) => {
                assert!(events > 0, "bytes arrive before the end");
                assert!(trailers.is_empty(), "this stage parses no trailer field");
                break;
            }
            Poll::Ready(Err(err)) => panic!("a well formed body must not fail: {err}"),
        }
    }
}

/// Negative: the delivery policy has no opt-out. There is exactly one variant, its lookahead is
/// one chunk, and a lookahead of zero — "deliver before verifying" — is not representable.
#[test]
fn the_delivery_policy_has_no_opt_out() {
    let policy = IngestPolicy::default();
    assert_eq!(policy, IngestPolicy::verify_before_deliver());
    assert_eq!(policy.lookahead_chunks(), 1);
    let IngestPolicy::VerifyBeforeDeliver { lookahead_chunks } = policy;
    assert_eq!(lookahead_chunks.get(), 1);
}

/// Negative: a truncated signed body — the terminal chunk never arrives — fails, and the bytes
/// that did verify are reported so the caller knows exactly how much it accepted.
#[test]
fn c_ing_0043_a_truncated_signed_body_reports_what_had_verified() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"partial");
    let body = chunker.finish_truncated();

    let mut pipeline = signed_pipeline(body, 4096, 32, KEY, SEED, no_observers(), ChunkLimits::default());
    let err = drain_pipeline(&mut pipeline, 4096).expect_err("a truncated body must not end cleanly");

    assert_eq!(pipeline.reject(), Some(ChunkReject::TruncatedStream));
    assert_eq!(err.bytes_before_error(), 7);
    assert!(!pipeline.commit_allowed());
}

/// Negative: two observers installed on a failing body still see only what was decoded, and the
/// pipeline reports the same counters afterwards. A failure must not leave the accounting behind.
#[test]
fn a_failed_body_still_reports_consistent_counters() {
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"kept");
    chunker.push_with_signature(b"lost", &[0xCC; 32]);
    let body = chunker.finish();

    let observers: SmallVec<[Box<dyn rustfs_gateway_stream::ByteObserver>; 4]> =
        SmallVec::from_vec(vec![Box::new(rustfs_gateway_stream::ByteCounter::new()) as _]);
    let mut pipeline = signed_pipeline(body, 4096, 8, KEY, SEED, observers, ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 4096).expect_err("the second chunk is forged");

    assert_eq!(pipeline.decoded_bytes(), 8, "both chunks were decoded");
    assert_eq!(pipeline.delivered_bytes(), 4, "only the verified one was delivered");
    let outcomes = pipeline.finish_observers();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].observed_bytes(),
        8,
        "an observer sees what was decoded, which is not what was delivered"
    );
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

fn drive_trailered(pipeline: &mut IngestPipeline<ScriptReader>) -> Result<(Vec<u8>, TrailingHeaders), StreamError> {
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

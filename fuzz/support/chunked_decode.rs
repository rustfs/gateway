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

//! The `chunked_decode` property: arbitrary bytes through the bounded `aws-chunked` ingest pipeline.
//!
//! Responsible for: decoding one fuzz input into a framing mode, a read size, a chunk ceiling, a
//! declared decoded length and a wire body; assembling `IngestPipeline` with the arguments
//! `rustfs-gateway`'s `ChunkIngest::into_pipeline` passes; driving it to its end; and asserting
//! what the pipeline promises about every body, accepted or refused.
//! NOT responsible for: choosing a libFuzzer entry point, or deciding whether a refusal's status
//! and wording are right (`crates/http/tests/reject_wording.rs` owns that).
//! Upstream: libFuzzer bytes, or a committed seed under `fuzz/seeds/chunked_decode/`.
//! Downstream: `fuzz/fuzz_targets/chunked_decode.rs` and the fixed-seed replay in
//! `crates/http/tests/chunked_decode_replay.rs`, which run this same file.
//!
//! # Input layout
//!
//! | Offset | Meaning |
//! | --- | --- |
//! | 0 | bit 0 set: `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, signed with [`SIGNING_KEY`]; clear: unsigned framing with no trailer section |
//! | 1 | bytes handed out per wire read, minus one (`0` = one byte per read) |
//! | 2 | chunk ceiling: index into [`MAX_CHUNK_SIZES`], modulo its length |
//! | 3..7 | `x-amz-decoded-content-length`, big-endian `u32` |
//! | 7.. | the wire body |
//!
//! The unsigned mode is not one a real `x-amz-content-sha256` value selects — the unsigned
//! streaming form always declares a trailer — but it is the same decoder on its strictest terminal
//! path, and it lets the fuzzer reach accepted bodies without forging an HMAC.
//!
//! # What is asserted, beyond "it did not panic"
//!
//! 1. **The ceiling is enforced at the size line.** An independent reading of the body's first line
//!    decides whether it announces a chunk above the configured ceiling. When it does, the refusal
//!    must be exactly `ChunkSizeTooLarge` for that size, no byte may have been delivered, the window
//!    must not have grown, and at one byte per read the wire must not have been asked for a single
//!    byte past that line.
//! 2. **Residency is bounded.** The window never exceeds one chunk plus two metadata lines.
//! 3. **An accepted body is whole.** Delivered bytes equal the declaration and the decoder's own
//!    count, and the body is committable.
//! 4. **A refusal is named and final.** Every refusal of an in-memory wire carries a `ChunkReject`,
//!    leaves the body uncommittable, and every later poll is an error rather than bytes or EOF.
//! 5. **No truncation of an accepted body is accepted.** Every strict prefix of an accepted body of
//!    at most [`SWEEP_LIMIT`] bytes is refused as `TruncatedStream`.

#![allow(dead_code)] // The fuzz binary calls `check` only; the replay also reads the constants.

use core::cell::Cell;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::rc::Rc;

use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, DecodedLength, Framing,
    IngestPipeline, IngestPolicy, Limits, MIN_CHUNK_META_BYTES, PayloadFramingSource, validate_decoded_length,
};
use rustfs_gateway_stream::{AsyncPayloadRead, PayloadCaps, ReadProgress, StreamError, TrailingHeaders};

/// The derived SigV4 key every signed input is verified under. It authenticates nothing anywhere.
pub(crate) const SIGNING_KEY: [u8; 32] = [0x4b; 32];
/// The request-head signature the chunk chain is seeded from.
pub(crate) const REQUEST_SIGNATURE: [u8; 32] = [0x5e; 32];
/// The credential scope of every signed input.
pub(crate) const SCOPE_LINE: &str = "20130524/us-east-1/s3/aws4_request";
/// The timestamp of every signed input.
pub(crate) const AMZ_DATE: &str = "20130524T000000Z";
/// How many leading input bytes select the case rather than form the body.
pub(crate) const HEADER_BYTES: usize = 7;
/// The chunk ceilings an input can select: two small enough for a fuzzer to cross, and production's.
pub(crate) const MAX_CHUNK_SIZES: [u32; 3] = [16, 4096, ChunkLimits::DEFAULT_MAX_CHUNK_SIZE];
/// The longest accepted body whose every truncation is replayed.
pub(crate) const SWEEP_LIMIT: usize = 512;

/// What one input selected.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Case<'a> {
    pub(crate) signed: bool,
    pub(crate) slice: usize,
    pub(crate) limits: ChunkLimits,
    pub(crate) declared: u64,
    pub(crate) body: &'a [u8],
}

impl<'a> Case<'a> {
    /// Splits an input into its selectors and its body, or `None` when it is too short to select.
    pub(crate) fn parse(input: &'a [u8]) -> Option<Self> {
        let (header, body) = input.split_first_chunk::<HEADER_BYTES>()?;
        let [flags, slice, ceiling, d0, d1, d2, d3] = *header;
        let ceiling = MAX_CHUNK_SIZES[usize::from(ceiling) % MAX_CHUNK_SIZES.len()];
        Some(Self {
            signed: flags & 1 == 1,
            slice: usize::from(slice) + 1,
            limits: ChunkLimits::default().with_max_chunk_size(ceiling),
            declared: u64::from(u32::from_be_bytes([d0, d1, d2, d3])),
            body,
        })
    }
}

/// What the pipeline did with one input.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// The delivered body on EOF, or the named refusal.
    pub(crate) verdict: Result<Vec<u8>, ChunkReject>,
    /// `IngestPipeline::delivered_bytes` at the end.
    pub(crate) delivered_bytes: u64,
    /// The window when the pipeline was built.
    pub(crate) initial_window: usize,
    /// The window at the end.
    pub(crate) window_bytes: usize,
    /// How many wire bytes the pipeline pulled.
    pub(crate) bytes_read: usize,
    /// How many chunk signatures verified, for a signed case.
    pub(crate) chunks_verified: Option<u32>,
}

/// Runs one input through the pipeline and asserts every property in the module docs.
///
/// Returns `None` for an input shorter than [`HEADER_BYTES`].
pub(crate) fn check(input: &[u8]) -> Option<Outcome> {
    let case = Case::parse(input)?;
    let outcome = run(&case, case.body);

    if let Some((size, line_bytes)) = oversized_first_line(&case) {
        let max = case.limits.max_chunk_size();
        assert_eq!(
            outcome.verdict.as_ref().err(),
            Some(&ChunkReject::ChunkSizeTooLarge { declared: size, max }),
            "a size line announcing {size} bytes against a {max}-byte ceiling must be refused at that line",
        );
        assert_eq!(outcome.delivered_bytes, 0, "an over-large first chunk delivered bytes");
        assert_eq!(
            outcome.window_bytes, outcome.initial_window,
            "the window grew towards an over-large chunk"
        );
        if case.slice == 1 {
            assert_eq!(outcome.bytes_read, line_bytes, "the wire was read past an over-large chunk's size line");
        }
    }

    if outcome.verdict.is_ok() && case.body.len() <= SWEEP_LIMIT {
        for cut in 0..case.body.len() {
            let truncated = run(&case, &case.body[..cut]);
            assert_eq!(
                truncated.verdict.as_ref().err(),
                Some(&ChunkReject::TruncatedStream),
                "the first {cut} bytes of an accepted {}-byte body were not refused as truncated",
                case.body.len(),
            );
        }
    }
    Some(outcome)
}

/// Builds the pipeline for `case` over `body`, drives it to its end, and asserts the invariants
/// that hold for every body.
fn run(case: &Case<'_>, body: &[u8]) -> Outcome {
    let framing = ChunkFraming::derive(&Mode { signed: case.signed })
        .expect("Mode answers framed and decoded-length-required together, so it is consistent");
    let signer = case.signed.then(|| {
        let scope = ChunkScope::new(SCOPE_LINE, AMZ_DATE).expect("SCOPE_LINE and AMZ_DATE are a valid constant scope");
        ChunkSigner::new(
            ChunkSigningKey::from_derived(SIGNING_KEY),
            scope,
            ChunkSeed::from_request_signature(REQUEST_SIGNATURE),
        )
    });
    let bytes_read = Rc::new(Cell::new(0usize));
    let wire = Wire {
        data: body,
        slice: case.slice,
        read: Rc::clone(&bytes_read),
        eof_emitted: false,
    };
    let mut pipeline = IngestPipeline::new(
        wire,
        framing,
        declared_length(&framing, case.declared),
        signer,
        Default::default(),
        case.limits,
        IngestPolicy::verify_before_deliver(),
    )
    .expect("the framing is framed and the signer is present exactly when it signs");
    let initial_window = pipeline.window_bytes();

    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0u8; 1024];
    let mut delivered = Vec::new();
    let verdict = loop {
        match Pin::new(&mut pipeline).poll_fill(&mut cx, &mut buf) {
            Poll::Pending => panic!("an in-memory wire never pends, so the pipeline must not either"),
            Poll::Ready(Ok(ReadProgress::Filled(n))) => {
                assert!(n > 0 && n <= buf.len(), "a non-empty read filled {n} bytes");
                delivered.extend_from_slice(&buf[..n]);
            }
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => break Ok(delivered),
            Poll::Ready(Err(error)) => {
                assert_eq!(error.bytes_before_error(), pipeline.delivered_bytes());
                break Err(pipeline
                    .reject()
                    .expect("every refusal of an in-memory wire is a named ChunkReject"));
            }
        }
    };

    let ceiling = usize::try_from(case.limits.max_chunk_size()).unwrap_or(usize::MAX)
        + 2 * usize::from(case.limits.max_chunk_meta_size())
        + MIN_CHUNK_META_BYTES;
    assert!(
        pipeline.window_bytes() <= ceiling,
        "the window grew to {} bytes past its {ceiling}-byte ceiling",
        pipeline.window_bytes(),
    );
    match &verdict {
        Ok(body) => {
            assert_eq!(body.len() as u64, case.declared, "an accepted body differs from its declared length");
            assert_eq!(pipeline.decoded_bytes(), case.declared);
            assert_eq!(pipeline.delivered_bytes(), case.declared);
            assert!(pipeline.commit_allowed(), "an accepted body is not committable");
        }
        Err(_) => {
            assert!(!pipeline.commit_allowed(), "a refused body is committable");
            assert!(pipeline.delivered_bytes() <= pipeline.decoded_bytes());
        }
    }
    let after = Pin::new(&mut pipeline).poll_fill(&mut cx, &mut buf);
    assert!(
        matches!(after, Poll::Ready(Err(_))),
        "a pipeline that ended answered a later poll with {after:?}",
    );

    Outcome {
        verdict,
        delivered_bytes: pipeline.delivered_bytes(),
        initial_window,
        window_bytes: pipeline.window_bytes(),
        bytes_read: bytes_read.get(),
        chunks_verified: pipeline.signer().map(ChunkSigner::chunks_verified),
    }
}

/// Reads the body's first line independently of the decoder and answers whether it is a
/// well-formed size line announcing a chunk above the ceiling: `(size, line bytes with CRLF)`.
///
/// Only a line every other rule would accept counts, so that the decoder refusing it for some
/// other reason first — a bad extension, a leading zero — is not mistaken for a missed ceiling.
fn oversized_first_line(case: &Case<'_>) -> Option<(u64, usize)> {
    let end = case.body.iter().position(|byte| matches!(byte, b'\r' | b'\n'))?;
    if case.body.get(end..end + 2)? != b"\r\n" {
        return None;
    }
    let line_bytes = end + 2;
    if line_bytes > usize::from(case.limits.max_chunk_meta_size()) {
        return None;
    }
    let line = &case.body[..end];
    let (digits, extension) = match line.iter().position(|byte| *byte == b';') {
        Some(at) => (&line[..at], Some(&line[at + 1..])),
        None => (line, None),
    };
    if digits.is_empty() || digits.len() > 16 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    if digits.len() > 1 && digits[0] == b'0' {
        return None;
    }
    let well_formed_extension = match extension {
        None => !case.signed,
        Some(extension) => {
            case.signed
                && extension
                    .strip_prefix(b"chunk-signature=")
                    .is_some_and(|hex| hex.len() == 64 && hex.iter().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
        }
    };
    if !well_formed_extension {
        return None;
    }
    let text = core::str::from_utf8(digits).ok()?;
    let size = u64::from_str_radix(text, 16).ok()?;
    (size > u64::from(case.limits.max_chunk_size())).then_some((size, line_bytes))
}

/// The head-level cross-check, satisfied by construction: `Content-Length` leaves room for any
/// framing, so every input reaches the body. `crates/http/tests/ingest_framing.rs` owns the check.
fn declared_length(framing: &ChunkFraming, declared: u64) -> DecodedLength {
    let wire_length = declared.saturating_add(1 << 32);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_length));
    let limits = Limits {
        max_body_bytes: u64::MAX,
        ..Limits::default()
    };
    let wire = Framing::classify(http::Version::HTTP_11, &headers, &limits)
        .expect("a lone decimal Content-Length under an unlimited body ceiling is well formed");
    validate_decoded_length(framing, Some(&declared.to_string()), &wire)
        .expect("Content-Length exceeds the declaration by more than any framing overhead")
        .expect("a framed body always yields a decoded length")
}

/// The signature-derived framing answers for the two modes an input can select.
struct Mode {
    signed: bool,
}

impl PayloadFramingSource for Mode {
    fn is_framed(&self) -> bool {
        true
    }

    fn has_chunk_signatures(&self) -> bool {
        self.signed
    }

    fn requires_decoded_length(&self) -> bool {
        true
    }

    fn declares_trailers(&self) -> bool {
        false
    }
}

/// An in-memory wire handing out at most `slice` bytes per read and counting what it handed out.
struct Wire<'a> {
    data: &'a [u8],
    slice: usize,
    read: Rc<Cell<usize>>,
    eof_emitted: bool,
}

impl AsyncPayloadRead for Wire<'_> {
    fn poll_fill(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        let at = this.read.get();
        let rest = this.data.get(at..).unwrap_or_default();
        if rest.is_empty() {
            if this.eof_emitted {
                return Poll::Ready(Err(StreamError::polled_after_eof()));
            }
            this.eof_emitted = true;
            return Poll::Ready(Ok(ReadProgress::Eof {
                trailers: TrailingHeaders::empty(),
            }));
        }
        let take = rest.len().min(this.slice).min(buf.len());
        buf[..take].copy_from_slice(&rest[..take]);
        this.read.set(at + take);
        Poll::Ready(Ok(ReadProgress::Filled(take)))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

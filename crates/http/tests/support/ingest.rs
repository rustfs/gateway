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

//! Wire-shaped fixtures for the ingest suites: raw `aws-chunked` bytes, a scripted socket, and
//! an independently written chunk signer.
//!
//! Responsible for: producing the exact bytes a peer would send — including the malformed ones a
//! client library refuses to emit — and driving a pipeline without an async runtime.
//! NOT responsible for: any assertion. Every one lives in the suite that owns the rule.
//! Upstream: `rustfs-gateway-stream`, `hmac`, `sha2`. Downstream: the four ingest suites.
//!
//! The signer here is written from the AWS streaming specification rather than shared with the
//! implementation. That is deliberate: a test that called the implementation's own string-to-sign
//! would assert that the code does what it does. It is not a published known-answer vector either
//! — both sides were written from the same reading of the same specification, so a shared
//! misreading would still pass. `tests/ingest_known_answer.rs` closes that gap with AWS's own
//! published chunked-upload example (gateway#5); this fixture remains useful for every case that
//! needs an arbitrary, not-AWS's-own, signed body.

// Each test binary compiles this module separately and uses a subset of it.
#![allow(dead_code, unreachable_pub)]

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use hmac::{Hmac, KeyInit, Mac};
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, DecodedLength, IngestPipeline, IngestPolicy,
    PayloadFramingSource,
};
use rustfs_gateway_stream::{AsyncPayloadRead, ByteObserver, PayloadCaps, ReadProgress, StreamError};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

type HmacSha256 = Hmac<Sha256>;

/// The published AWS example scope. It authenticates nothing anywhere.
pub const TEST_SCOPE_LINE: &str = "20130524/us-east-1/s3/aws4_request";
/// The matching timestamp.
pub const TEST_AMZ_DATE: &str = "20130524T000000Z";

/// A signature-derived framing fixture, standing in for `PayloadMode` one layer above.
///
/// The four answers are set independently so a suite can build the contradictory sources a real
/// `PayloadMode` cannot produce, and check that the derivation refuses them.
#[derive(Clone, Copy, Debug)]
pub struct FramingFixture {
    pub framed: bool,
    pub signed: bool,
    pub decoded_length_required: bool,
    pub trailers: bool,
}

impl FramingFixture {
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`.
    pub fn streaming_signed() -> Self {
        Self {
            framed: true,
            signed: true,
            decoded_length_required: true,
            trailers: false,
        }
    }

    /// Framed, unsigned, with no trailer section.
    ///
    /// No `x-amz-content-sha256` value selects exactly this today — the unsigned streaming form
    /// always declares a trailer — so it cannot arrive from a real `PayloadMode`. It is the
    /// fixture the decoder suites use, because it exercises the strict terminal path: with no
    /// trailer section declared, nothing at all may follow the terminal chunk.
    pub fn streaming_unsigned() -> Self {
        Self {
            framed: true,
            signed: false,
            decoded_length_required: true,
            trailers: false,
        }
    }

    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`.
    pub fn streaming_unsigned_trailer() -> Self {
        Self {
            framed: true,
            signed: false,
            decoded_length_required: true,
            trailers: true,
        }
    }

    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`.
    pub fn streaming_signed_trailer() -> Self {
        Self {
            framed: true,
            signed: true,
            decoded_length_required: true,
            trailers: true,
        }
    }

    /// `UNSIGNED-PAYLOAD`, or any non-streaming value: not framed, whatever `Content-Encoding`
    /// happens to say.
    pub fn unsigned_payload() -> Self {
        Self {
            framed: false,
            signed: false,
            decoded_length_required: false,
            trailers: false,
        }
    }
}

impl PayloadFramingSource for FramingFixture {
    fn is_framed(&self) -> bool {
        self.framed
    }

    fn has_chunk_signatures(&self) -> bool {
        self.signed
    }

    fn requires_decoded_length(&self) -> bool {
        self.decoded_length_required
    }

    fn declares_trailers(&self) -> bool {
        self.trailers
    }
}

/// A socket that hands out a scripted byte string in slices of a chosen size.
///
/// `pending_every` makes the reader report "not ready" periodically, so a suite exercises the
/// resumption path rather than only the happy single-poll case.
pub struct ScriptReader {
    data: Vec<u8>,
    at: usize,
    slice: usize,
    pending_every: usize,
    polls: usize,
    reads: usize,
    eof_emitted: bool,
}

impl ScriptReader {
    /// A reader over `data`, handing out at most `slice` bytes per read.
    pub fn new(data: Vec<u8>, slice: usize) -> Self {
        Self {
            data,
            at: 0,
            slice: slice.max(1),
            pending_every: 0,
            polls: 0,
            reads: 0,
            eof_emitted: false,
        }
    }

    /// Reports `Pending` once every `every` polls.
    pub fn pending_every(mut self, every: usize) -> Self {
        self.pending_every = every;
        self
    }

    /// How many bytes the peer has actually been asked for.
    ///
    /// A ceiling that is enforced "at the chunk header, before one data byte is read" is only
    /// enforced there if this number stops growing, which is what the DoS regression asserts.
    pub fn bytes_read(&self) -> usize {
        self.at
    }

    /// How many fill calls have been served.
    pub fn reads(&self) -> usize {
        self.reads
    }
}

impl AsyncPayloadRead for ScriptReader {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        this.polls = this.polls.saturating_add(1);
        if this.pending_every > 0 && this.polls.is_multiple_of(this.pending_every) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if this.at >= this.data.len() {
            if this.eof_emitted {
                return Poll::Ready(Err(StreamError::polled_after_eof()));
            }
            this.eof_emitted = true;
            return Poll::Ready(Ok(ReadProgress::Eof {
                trailers: rustfs_gateway_stream::TrailingHeaders::empty(),
            }));
        }
        let take = (this.data.len() - this.at).min(this.slice).min(buf.len());
        if take == 0 {
            return Poll::Ready(Ok(ReadProgress::Filled(0)));
        }
        buf[..take].copy_from_slice(&this.data[this.at..this.at + take]);
        this.at += take;
        this.reads = this.reads.saturating_add(1);
        Poll::Ready(Ok(ReadProgress::Filled(take)))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// Drives a pipeline to its end without a runtime, returning the delivered bytes.
pub fn drain_pipeline<R: AsyncPayloadRead + Unpin>(
    pipeline: &mut IngestPipeline<R>,
    buf_size: usize,
) -> Result<Vec<u8>, StreamError> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut out = Vec::new();
    let mut buf = vec![0u8; buf_size.max(1)];
    loop {
        match Pin::new(&mut *pipeline).poll_fill(&mut cx, &mut buf) {
            Poll::Pending => continue,
            Poll::Ready(Err(err)) => return Err(err),
            Poll::Ready(Ok(ReadProgress::Filled(n))) => out.extend_from_slice(&buf[..n]),
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => return Ok(out),
        }
    }
}

/// Builds an unsigned `aws-chunked` body out of the given data chunks.
pub fn unsigned_body(chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// Builds a body whose single chunk header is written out verbatim, malformed spellings included.
pub fn raw_chunk_body(header_line: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(header_line.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

/// An independently written signed-chunk producer.
pub struct SignedChunker {
    key: [u8; 32],
    scope_line: String,
    amz_date: String,
    previous: [u8; 32],
    out: Vec<u8>,
}

impl SignedChunker {
    /// A producer chained from `seed`, which stands in for the request-head signature.
    pub fn new(key: [u8; 32], seed: [u8; 32]) -> Self {
        Self {
            key,
            scope_line: TEST_SCOPE_LINE.to_owned(),
            amz_date: TEST_AMZ_DATE.to_owned(),
            previous: seed,
            out: Vec::new(),
        }
    }

    /// The signature this chunk should carry, without emitting it.
    pub fn signature_for(&self, data: &[u8]) -> [u8; 32] {
        let mut sts = String::new();
        sts.push_str("AWS4-HMAC-SHA256-PAYLOAD\n");
        sts.push_str(&self.amz_date);
        sts.push('\n');
        sts.push_str(&self.scope_line);
        sts.push('\n');
        sts.push_str(&hex_lower(&self.previous));
        sts.push('\n');
        sts.push_str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
        sts.push_str(&hex_lower(&Sha256::digest(data).into()));
        hmac_sha256(&self.key, sts.as_bytes())
    }

    /// Appends a correctly signed chunk.
    pub fn push(&mut self, data: &[u8]) -> &mut Self {
        let signature = self.signature_for(data);
        self.emit(data, &signature);
        self.previous = signature;
        self
    }

    /// Appends a chunk carrying a signature of the caller's choosing, and chains from the
    /// *correct* one, so a suite can corrupt exactly one link.
    pub fn push_with_signature(&mut self, data: &[u8], signature: &[u8; 32]) -> &mut Self {
        let correct = self.signature_for(data);
        self.emit(data, signature);
        self.previous = correct;
        self
    }

    /// Appends a chunk whose extension is written out verbatim.
    pub fn push_raw_extension(&mut self, data: &[u8], extension: &str) -> &mut Self {
        let correct = self.signature_for(data);
        self.out
            .extend_from_slice(format!("{:x};{extension}\r\n", data.len()).as_bytes());
        self.out.extend_from_slice(data);
        self.out.extend_from_slice(b"\r\n");
        self.previous = correct;
        self
    }

    /// Appends the terminal chunk and returns the whole body.
    pub fn finish(mut self) -> Vec<u8> {
        let signature = self.signature_for(&[]);
        self.out
            .extend_from_slice(format!("0;chunk-signature={}\r\n\r\n", hex_lower(&signature)).as_bytes());
        self.out
    }

    /// Ends the body without a terminal chunk, which is the truncation attack.
    pub fn finish_truncated(self) -> Vec<u8> {
        self.out
    }

    fn emit(&mut self, data: &[u8], signature: &[u8; 32]) {
        self.out
            .extend_from_slice(format!("{:x};chunk-signature={}\r\n", data.len(), hex_lower(signature)).as_bytes());
        self.out.extend_from_slice(data);
        self.out.extend_from_slice(b"\r\n");
    }
}

/// Assembles a signed pipeline over `body`.
pub fn signed_pipeline(
    body: Vec<u8>,
    slice: usize,
    declared: u64,
    key: [u8; 32],
    seed: [u8; 32],
    observers: SmallVec<[Box<dyn ByteObserver>; 4]>,
    limits: ChunkLimits,
) -> IngestPipeline<ScriptReader> {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("consistent fixture");
    let scope = ChunkScope::new(TEST_SCOPE_LINE, TEST_AMZ_DATE).expect("valid scope");
    let signer = ChunkSigner::new(ChunkSigningKey::from_derived(key), scope, ChunkSeed::from_request_signature(seed));
    IngestPipeline::new(
        ScriptReader::new(body, slice),
        framing,
        declared_length(declared),
        Some(signer),
        observers,
        limits,
        IngestPolicy::default(),
    )
    .expect("a signed pipeline with a signer is well formed")
}

/// Assembles an unsigned pipeline with no trailer section over `body`.
pub fn unsigned_pipeline(
    body: Vec<u8>,
    slice: usize,
    declared: u64,
    observers: SmallVec<[Box<dyn ByteObserver>; 4]>,
    limits: ChunkLimits,
) -> IngestPipeline<ScriptReader> {
    unsigned_pipeline_with(FramingFixture::streaming_unsigned(), body, slice, declared, observers, limits)
}

/// Assembles an unsigned pipeline that declares a trailer section.
pub fn unsigned_trailer_pipeline(
    body: Vec<u8>,
    slice: usize,
    declared: u64,
    observers: SmallVec<[Box<dyn ByteObserver>; 4]>,
    limits: ChunkLimits,
) -> IngestPipeline<ScriptReader> {
    unsigned_pipeline_with(FramingFixture::streaming_unsigned_trailer(), body, slice, declared, observers, limits)
}

fn unsigned_pipeline_with(
    fixture: FramingFixture,
    body: Vec<u8>,
    slice: usize,
    declared: u64,
    observers: SmallVec<[Box<dyn ByteObserver>; 4]>,
    limits: ChunkLimits,
) -> IngestPipeline<ScriptReader> {
    let framing = ChunkFraming::derive(&fixture).expect("consistent fixture");
    IngestPipeline::new(
        ScriptReader::new(body, slice),
        framing,
        declared_length(declared),
        None,
        observers,
        limits,
        IngestPolicy::default(),
    )
    .expect("an unsigned pipeline without a signer is well formed")
}

/// Builds a [`DecodedLength`] the way the head validation would.
pub fn declared_length(bytes: u64) -> DecodedLength {
    let framing = ChunkFraming::derive(&FramingFixture::streaming_signed()).expect("consistent fixture");
    let wire = wire_framing_with_length(bytes.saturating_add(1_000_000));
    rustfs_gateway_http::validate_decoded_length(&framing, Some(&bytes.to_string()), &wire)
        .expect("the fixture wire length is generous enough")
        .expect("a framed body always yields a decoded length")
}

/// A `Framing` carrying an exact `Content-Length`.
pub fn wire_framing_with_length(bytes: u64) -> rustfs_gateway_http::Framing {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&bytes.to_string()).expect("a decimal length is a valid header value"),
    );
    rustfs_gateway_http::Framing::classify(http::Version::HTTP_11, &headers, &no_body_ceiling())
        .expect("a lone Content-Length is well formed")
}

/// Default limits with the body ceiling raised out of the way of the fixtures.
pub fn no_body_ceiling() -> rustfs_gateway_http::Limits {
    rustfs_gateway_http::Limits {
        max_body_bytes: u64::MAX,
        ..rustfs_gateway_http::Limits::default()
    }
}

/// No observers.
pub fn no_observers() -> SmallVec<[Box<dyn ByteObserver>; 4]> {
    SmallVec::new()
}

/// Lowercase hex of a 32-byte value.
pub fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// One HMAC-SHA256 step, written out here rather than shared with the implementation.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

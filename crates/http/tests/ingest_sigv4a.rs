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

//! Streaming SigV4a (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]`) chunk and trailer
//! verification tests for `rustfs-gateway-http::ingest`.
//!
//! Responsible for: verifying multi-chunk ECDSA P-256 chains (both unpadded and AWS CRT 144-char
//! `'*'`-padded), signed trailing headers, verify-before-deliver on tampered chunks/trailers,
//! padding grammar strictness, and cross-mode (HMAC vs ECDSA) rejection.
//! NOT responsible for: SigV4a KDF or request-head verification (`rustfs-gateway-sig`).
//! Upstream: `rustfs-gateway-http::ingest`, `p256`, `sha2`. Downstream: none (test module).
//!
//! 4 positive / 10 negative.

use crate::support::ingest::{ScriptReader, TEST_AMZ_DATE, declared_length, drain_pipeline, no_observers};
use http::HeaderValue;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use rustfs_gateway_http::{
    ChunkFraming, ChunkLimits, ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, ChunkVerifyingKey,
    EcdsaChunkSeed, IngestPipeline, IngestPolicy, ModeConfusion, PayloadFramingSource, TrailerDeclaration,
};
use sha2::{Digest, Sha256};

const SCOPE_LINE_V4A: &str = "20130524/s3/aws4_request";
const EMPTY_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct EcdsaFramingFixture {
    framed: bool,
    signed: bool,
    ecdsa: bool,
    decoded_len: bool,
    trailers: bool,
}

impl EcdsaFramingFixture {
    fn signed_ecdsa(trailers: bool) -> Self {
        Self {
            framed: true,
            signed: true,
            ecdsa: true,
            decoded_len: true,
            trailers,
        }
    }
}

impl PayloadFramingSource for EcdsaFramingFixture {
    fn is_framed(&self) -> bool {
        self.framed
    }
    fn has_chunk_signatures(&self) -> bool {
        self.signed
    }
    fn requires_decoded_length(&self) -> bool {
        self.decoded_len
    }
    fn declares_trailers(&self) -> bool {
        self.trailers
    }
    fn has_ecdsa_chunk_signatures(&self) -> bool {
        self.ecdsa
    }
}

fn test_signing_key(seed_byte: u8) -> SigningKey {
    let mut bytes = [seed_byte; 32];
    bytes[0] = 0x11;
    SigningKey::from_bytes((&bytes).into()).expect("valid non-zero P-256 scalar")
}

fn verifying_key_of(sk: &SigningKey) -> ChunkVerifyingKey {
    let point = sk.verifying_key().to_sec1_point(true);
    let mut sec1 = [0u8; 33];
    sec1.copy_from_slice(point.as_bytes());
    ChunkVerifyingKey::from_sec1_compressed(sec1).expect("valid compressed SEC1 point")
}

fn hex_lower_slice(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn sign_der_hex(sk: &SigningKey, msg: &[u8]) -> String {
    let sig: p256::ecdsa::Signature = sk.sign(msg);
    hex_lower_slice(sig.to_der().as_bytes())
}

fn pad_144(unpadded: &str) -> String {
    let mut out = unpadded.to_owned();
    while out.len() < 144 {
        out.push('*');
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    let d: [u8; 32] = Sha256::digest(data).into();
    hex_lower_slice(&d)
}

struct EcdsaChunker {
    sk: SigningKey,
    previous: String,
    padded: bool,
    out: Vec<u8>,
}

impl EcdsaChunker {
    fn new(sk: SigningKey, seed_hex: &str, padded: bool) -> Self {
        Self {
            sk,
            previous: seed_hex.to_owned(),
            padded,
            out: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8]) -> &mut Self {
        let sts = format!(
            "AWS4-ECDSA-P256-SHA256-PAYLOAD\n{TEST_AMZ_DATE}\n{SCOPE_LINE_V4A}\n{}\n{EMPTY_SHA256_HEX}\n{}",
            self.previous,
            sha256_hex(data)
        );
        let unpadded = sign_der_hex(&self.sk, sts.as_bytes());
        let wire_sig = if self.padded { pad_144(&unpadded) } else { unpadded.clone() };
        self.previous = unpadded;
        self.out
            .extend_from_slice(format!("{:x};chunk-signature={wire_sig}\r\n", data.len()).as_bytes());
        self.out.extend_from_slice(data);
        self.out.extend_from_slice(b"\r\n");
        self
    }

    fn finish(mut self) -> Vec<u8> {
        let sts = format!(
            "AWS4-ECDSA-P256-SHA256-PAYLOAD\n{TEST_AMZ_DATE}\n{SCOPE_LINE_V4A}\n{}\n{EMPTY_SHA256_HEX}\n{EMPTY_SHA256_HEX}",
            self.previous
        );
        let unpadded = sign_der_hex(&self.sk, sts.as_bytes());
        let wire_sig = if self.padded { pad_144(&unpadded) } else { unpadded };
        self.out
            .extend_from_slice(format!("0;chunk-signature={wire_sig}\r\n\r\n").as_bytes());
        self.out
    }

    fn finish_with_trailer(mut self, name: &str, value: &str) -> Vec<u8> {
        let term_sts = format!(
            "AWS4-ECDSA-P256-SHA256-PAYLOAD\n{TEST_AMZ_DATE}\n{SCOPE_LINE_V4A}\n{}\n{EMPTY_SHA256_HEX}\n{EMPTY_SHA256_HEX}",
            self.previous
        );
        let term_unpadded = sign_der_hex(&self.sk, term_sts.as_bytes());
        let term_wire = if self.padded {
            pad_144(&term_unpadded)
        } else {
            term_unpadded.clone()
        };
        self.previous = term_unpadded;
        self.out
            .extend_from_slice(format!("0;chunk-signature={term_wire}\r\n").as_bytes());

        let canonical_trailer = format!("{name}:{value}\n");
        let trailer_sts = format!(
            "AWS4-ECDSA-P256-SHA256-TRAILER\n{TEST_AMZ_DATE}\n{SCOPE_LINE_V4A}\n{}\n{}",
            self.previous,
            sha256_hex(canonical_trailer.as_bytes())
        );
        let trailer_unpadded = sign_der_hex(&self.sk, trailer_sts.as_bytes());
        let trailer_wire = if self.padded {
            pad_144(&trailer_unpadded)
        } else {
            trailer_unpadded
        };
        self.out.extend_from_slice(format!("{name}:{value}\r\n").as_bytes());
        self.out
            .extend_from_slice(format!("x-amz-trailer-signature:{trailer_wire}\r\n\r\n").as_bytes());
        self.out
    }
}

fn ecdsa_pipeline(
    wire: Vec<u8>,
    step_bytes: usize,
    declared: u64,
    sk: &SigningKey,
    seed_hex: &str,
    trailers: bool,
) -> IngestPipeline<ScriptReader> {
    let framing = ChunkFraming::derive(&EcdsaFramingFixture::signed_ecdsa(trailers)).expect("valid framing");
    let length = declared_length(declared);
    let signer = ChunkSigner::new_ecdsa(
        verifying_key_of(sk),
        ChunkScope::new(SCOPE_LINE_V4A, TEST_AMZ_DATE).expect("valid scope"),
        EcdsaChunkSeed::from_hex(seed_hex).expect("valid ecdsa seed"),
    );
    let reader = ScriptReader::new(wire, step_bytes);
    let pipeline = IngestPipeline::new(
        reader,
        framing,
        length,
        Some(signer),
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::verify_before_deliver(),
    )
    .expect("valid pipeline");
    if trailers {
        let decl = TrailerDeclaration::parse(&HeaderValue::from_static("x-amz-checksum-crc32"), true).expect("valid");
        pipeline.with_trailer_declaration(decl).expect("valid declaration")
    } else {
        pipeline
    }
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive: multi-chunk unpadded ECDSA DER SigV4a upload verifies and delivers exact bytes.
#[test]
fn sigv4a_unpadded_chunks_verify_and_deliver() {
    let sk = test_signing_key(0x21);
    let seed = sign_der_hex(&sk, b"request-head-sts");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, false);
    chunker.push(b"alpha-").push(b"beta-").push(b"gamma");
    let wire = chunker.finish();

    let mut pipeline = ecdsa_pipeline(wire, 17, 16, &sk, &seed, false);
    let out = drain_pipeline(&mut pipeline, 64).expect("verifies");
    assert_eq!(out, b"alpha-beta-gamma");
    assert_eq!(pipeline.delivered_bytes(), 16);
    assert!(pipeline.commit_allowed());
    assert_eq!(pipeline.signer().map(ChunkSigner::chunks_verified), Some(4));
}

/// Positive: AWS CRT 144-char right-`'*'`-padded ECDSA chunks strip padding when chaining `previous`.
#[test]
fn sigv4a_crt_padded_chunks_verify_and_chain_unpadded() {
    let sk = test_signing_key(0x22);
    let seed = sign_der_hex(&sk, b"padded-head-sts");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, true);
    chunker.push(b"chunk-one-").push(b"chunk-two");
    let wire = chunker.finish();

    let mut pipeline = ecdsa_pipeline(wire, 23, 19, &sk, &seed, false);
    let out = drain_pipeline(&mut pipeline, 64).expect("verifies padded chunks");
    assert_eq!(out, b"chunk-one-chunk-two");
    assert!(pipeline.commit_allowed());
    assert_eq!(pipeline.signer().map(ChunkSigner::chunks_verified), Some(3));
}

/// Positive: signed ECDSA trailer verifies with unpadded DER signatures.
#[test]
fn sigv4a_signed_trailer_unpadded_verifies() {
    let sk = test_signing_key(0x23);
    let seed = sign_der_hex(&sk, b"trailer-head-sts");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, false);
    chunker.push(b"hello world");
    let wire = chunker.finish_with_trailer("x-amz-checksum-crc32", "DUoRhQ==");

    let mut pipeline = ecdsa_pipeline(wire, 64, 11, &sk, &seed, true);
    let out = drain_pipeline(&mut pipeline, 64).expect("verifies signed trailer");
    assert_eq!(out, b"hello world");
    assert!(pipeline.trailer_section_complete());
    assert!(pipeline.trailer_signature_satisfied());
}

/// Positive: signed ECDSA trailer verifies with AWS CRT 144-char `'*'`-padded signatures.
#[test]
fn sigv4a_signed_trailer_crt_padded_verifies() {
    let sk = test_signing_key(0x24);
    let seed = sign_der_hex(&sk, b"padded-trailer-head-sts");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, true);
    chunker.push(b"hello world");
    let wire = chunker.finish_with_trailer("x-amz-checksum-crc32", "DUoRhQ==");

    let mut pipeline = ecdsa_pipeline(wire, 19, 11, &sk, &seed, true);
    let out = drain_pipeline(&mut pipeline, 64).expect("verifies padded signed trailer");
    assert_eq!(out, b"hello world");
    assert!(pipeline.trailer_section_complete());
    assert!(pipeline.trailer_signature_satisfied());
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative: a tampered byte inside chunk 0 fails verification and delivers zero bytes.
#[test]
fn n_sigv4a_tampered_chunk_byte_delivers_zero_bytes() {
    let sk = test_signing_key(0x31);
    let seed = sign_der_hex(&sk, b"head");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, false);
    chunker.push(b"secret-payload");
    let mut wire = chunker.finish();
    let pos = wire.windows(6).position(|w| w == b"secret").expect("payload present");
    wire[pos] ^= 0x01;

    let mut pipeline = ecdsa_pipeline(wire, 64, 14, &sk, &seed, false);
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("tampered chunk must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
    assert_eq!(pipeline.delivered_bytes(), 0);
    assert!(!pipeline.commit_allowed());
}

/// Negative: a chunk signed by a different P-256 key is refused at chunk 0.
#[test]
fn n_sigv4a_wrong_verifying_key_fails() {
    let sk_client = test_signing_key(0x32);
    let sk_server = test_signing_key(0x33);
    let seed = sign_der_hex(&sk_client, b"head");
    let mut chunker = EcdsaChunker::new(sk_client, &seed, false);
    chunker.push(b"hello");
    let wire = chunker.finish();

    let mut pipeline = ecdsa_pipeline(wire, 64, 5, &sk_server, &seed, false);
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("wrong key must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
}

/// Negative: tampering with the trailing checksum value invalidates the ECDSA trailer signature.
#[test]
fn n_sigv4a_tampered_trailer_value_fails_signature() {
    let sk = test_signing_key(0x34);
    let seed = sign_der_hex(&sk, b"head");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, false);
    chunker.push(b"hello world");
    let wire = chunker.finish_with_trailer("x-amz-checksum-crc32", "DUoRhQ==");
    let tampered = String::from_utf8(wire)
        .expect("utf8")
        .replace("DUoRhQ==", "AAAAAA==")
        .into_bytes();

    let mut pipeline = ecdsa_pipeline(tampered, 64, 11, &sk, &seed, true);
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("tampered trailer must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerSignatureMismatch));
    assert!(!pipeline.trailer_signature_satisfied());
}

/// Negative: omitting `x-amz-trailer-signature` in ECDSA trailer mode returns `TrailerSignatureMissing`.
#[test]
fn n_sigv4a_missing_trailer_signature_is_refused() {
    let sk = test_signing_key(0x35);
    let seed = sign_der_hex(&sk, b"head");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, false);
    chunker.push(b"hello");
    let mut wire = chunker.finish_with_trailer("x-amz-checksum-crc32", "AAAAAA==");
    let sig_pos = wire
        .windows("x-amz-trailer-signature:".len())
        .position(|w| w == b"x-amz-trailer-signature:")
        .expect("sig header");
    wire.truncate(sig_pos);
    wire.extend_from_slice(b"\r\n");

    let mut pipeline = ecdsa_pipeline(wire, 64, 5, &sk, &seed, true);
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("missing trailer sig must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::TrailerSignatureMissing));
}

/// Negative: malformed `'*'` padding on a chunk signature (wrong total length, leading `'*'`,
/// embedded `'*'`) is rejected as `UnexpectedExtension`.
#[test]
fn n_sigv4a_malformed_star_padding_is_rejected() {
    let sk = test_signing_key(0x36);
    let seed = sign_der_hex(&sk, b"head");
    let valid_chunk_sig = sign_der_hex(&sk, b"dummy");
    let bad_short_pad = format!("{valid_chunk_sig}*");
    let bad_leading_pad = format!("*{valid_chunk_sig}");
    let mut bad_embedded = pad_144(&valid_chunk_sig);
    bad_embedded.pop();
    bad_embedded.push('a');

    for bad_sig in [bad_short_pad, bad_leading_pad, bad_embedded] {
        let wire = format!("5;chunk-signature={bad_sig}\r\nhello\r\n0;chunk-signature={valid_chunk_sig}\r\n\r\n").into_bytes();
        let mut pipeline = ecdsa_pipeline(wire, 256, 5, &sk, &seed, false);
        let _ = drain_pipeline(&mut pipeline, 64).expect_err("bad padding must fail");
        assert_eq!(pipeline.reject(), Some(ChunkReject::UnexpectedExtension));
    }
}

/// Negative: `'*'` padding is forbidden on the request-head `EcdsaChunkSeed`.
#[test]
fn n_sigv4a_star_padding_forbidden_on_request_seed() {
    let sk = test_signing_key(0x37);
    let padded = pad_144(&sign_der_hex(&sk, b"head"));
    assert_eq!(
        EcdsaChunkSeed::from_hex(&padded).err(),
        Some(ChunkReject::SignatureChainBroken { chunk_index: 0 })
    );
}

/// Negative: an HMAC 64-hex signature or raw 64-byte non-DER signature is rejected in ECDSA chunk mode.
#[test]
fn n_sigv4a_hmac_or_raw_chunk_signature_rejected_in_ecdsa_mode() {
    let sk = test_signing_key(0x38);
    let seed = sign_der_hex(&sk, b"head");
    for bad in ["a".repeat(64), "b".repeat(128)] {
        let wire = format!("5;chunk-signature={bad}\r\nhello\r\n0;chunk-signature={bad}\r\n\r\n").into_bytes();
        let mut pipeline = ecdsa_pipeline(wire, 256, 5, &sk, &seed, false);
        let _ = drain_pipeline(&mut pipeline, 64).expect_err("non-DER must fail");
        assert_eq!(pipeline.reject(), Some(ChunkReject::UnexpectedExtension));
    }
}

/// Negative: pairing an ECDSA `ChunkFraming` with an HMAC `ChunkSigner` (and vice versa) fails
/// closed at `IngestPipeline::new`.
#[test]
fn n_sigv4a_cross_mode_framing_and_signer_rejected() {
    let sk = test_signing_key(0x39);
    let seed = sign_der_hex(&sk, b"head");
    let ecdsa_framing = ChunkFraming::derive(&EcdsaFramingFixture::signed_ecdsa(false)).expect("valid");
    let hmac_signer = ChunkSigner::new(
        ChunkSigningKey::from_derived([0x5a; 32]),
        ChunkScope::new("20130524/us-east-1/s3/aws4_request", TEST_AMZ_DATE).expect("ok"),
        ChunkSeed::from_request_signature([0xaa; 32]),
    );
    let err = IngestPipeline::new(
        ScriptReader::new(Vec::new(), 64),
        ecdsa_framing,
        declared_length(0),
        Some(hmac_signer),
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::verify_before_deliver(),
    )
    .err()
    .expect("cross-mode must fail");
    assert_eq!(err, ChunkReject::SignatureChainBroken { chunk_index: 0 });

    let hmac_framing = ChunkFraming::derive(&EcdsaFramingFixture {
        framed: true,
        signed: true,
        ecdsa: false,
        decoded_len: true,
        trailers: false,
    })
    .expect("valid");
    let ecdsa_signer = ChunkSigner::new_ecdsa(
        verifying_key_of(&sk),
        ChunkScope::new(SCOPE_LINE_V4A, TEST_AMZ_DATE).expect("ok"),
        EcdsaChunkSeed::from_hex(&seed).expect("ok"),
    );
    let err2 = IngestPipeline::new(
        ScriptReader::new(Vec::new(), 64),
        hmac_framing,
        declared_length(0),
        Some(ecdsa_signer),
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::verify_before_deliver(),
    )
    .err()
    .expect("reverse cross-mode must fail");
    assert_eq!(err2, ChunkReject::SignatureChainBroken { chunk_index: 0 });
}

/// Negative: contradictory `PayloadFramingSource` claiming ECDSA signatures without signed framing
/// is rejected as `ModeConfusion`.
#[test]
fn n_sigv4a_contradictory_ecdsa_framing_source_rejected() {
    for bad in [
        EcdsaFramingFixture {
            framed: true,
            signed: false,
            ecdsa: true,
            decoded_len: true,
            trailers: false,
        },
        EcdsaFramingFixture {
            framed: false,
            signed: false,
            ecdsa: true,
            decoded_len: false,
            trailers: false,
        },
    ] {
        assert_eq!(
            ChunkFraming::derive(&bad),
            Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed))
        );
    }
}

/// Negative: a truncated ECDSA streaming body without a terminal zero-sized chunk returns
/// `TruncatedStream`.
#[test]
fn n_sigv4a_truncated_stream_without_terminal_chunk_fails() {
    let sk = test_signing_key(0x3a);
    let seed = sign_der_hex(&sk, b"head");
    let mut chunker = EcdsaChunker::new(sk.clone(), &seed, false);
    chunker.push(b"hello");
    let truncated = chunker.out; // no terminal 0;chunk-signature=...

    let mut pipeline = ecdsa_pipeline(truncated, 64, 5, &sk, &seed, false);
    let _ = drain_pipeline(&mut pipeline, 64).expect_err("truncated stream must fail");
    assert_eq!(pipeline.reject(), Some(ChunkReject::TruncatedStream));
}

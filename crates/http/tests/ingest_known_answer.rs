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

//! [`ChunkSigner`] verified against a published known-answer vector, not our own builder.
//!
//! Responsible for: reproducing AWS's own worked chunked-upload example byte for byte and
//! confirming [`ChunkSigner::verify_chunk`] agrees with every signature AWS published for it, in
//! both directions — the exact chain accepted, and the chain broken in isolation at the seed, the
//! key, a chunk's data, and a chunk's position all refused.
//! NOT responsible for: chunk syntax, framing selection, or trailer parsing — `ingest_verify.rs`
//! and its siblings own those, and every one of their fixtures is `support::ingest::SignedChunker`,
//! a second implementation written independently from the same specification. That catches a
//! typo; it cannot catch a shared misreading of the specification, which is exactly the gap this
//! file closes. See gateway#5.
//! Upstream: AWS's own published example. Downstream: none — this is a leaf regression file.
//!
//! # Source of the vector
//!
//! <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html>, "Example:
//! PUT Object" — the worked chunked-upload example AWS publishes as "a test suite to verify your
//! code". Every constant below (the credentials, the timestamp, the canonical request, the seed
//! signature, both chunk sizes, both chunk payload hashes, and all three chunk signatures) is
//! copied verbatim from that page. The four-step key derivation is the one AWS states in the same
//! page and is not itself secret or disputed; it was independently re-derived and checked against
//! the page's own seed signature before being pinned here as [`SIGNING_KEY`], so a wrong key
//! could not have produced the numbers below by accident.
//!
//! 1 positive / 4 negative.

use rustfs_gateway_http::{ChunkReject, ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey};

/// `20130524/us-east-1/s3/aws4_request` — the credential scope AWS's worked example signs under.
const SCOPE_LINE: &str = "20130524/us-east-1/s3/aws4_request";
/// The matching request timestamp.
const AMZ_DATE: &str = "20130524T000000Z";

/// The SigV4 signing key AWS's example derives from `AWSSecretAccessKey =
/// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` over the scope above: `HMAC(HMAC(HMAC(HMAC("AWS4" +
/// secret, "20130524"), "us-east-1"), "s3"), "aws4_request")`. AWS does not publish this
/// intermediate value directly — only the formula and the seed signature it produces — so it was
/// computed independently and accepted only after `HMAC(SIGNING_KEY, seed_string_to_sign)` was
/// checked byte for byte against [`SEED_SIGNATURE_HEX`] below, which AWS does publish.
const SIGNING_KEY: [u8; 32] = [
    0xdb, 0xb8, 0x93, 0xac, 0xc0, 0x10, 0x96, 0x49, 0x18, 0xf1, 0xfd, 0x43, 0x3a, 0xdd, 0x87, 0xc7, 0x0e, 0x8b, 0x0d, 0xb6, 0xbe,
    0x30, 0xc1, 0xfb, 0xea, 0xfe, 0xfa, 0x5e, 0xc6, 0xba, 0x83, 0x78,
];

/// The seed signature AWS's example computes over the request head (the `Authorization` header
/// signature), which starts the chunk chain.
const SEED_SIGNATURE_HEX: &str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

/// Chunk 1's published signature: 65536 bytes, every one the ASCII letter `a`.
const CHUNK1_LEN: usize = 65536;
const CHUNK1_SIGNATURE_HEX: &str = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";

/// Chunk 2's published signature: 1024 bytes, every one the ASCII letter `a`.
const CHUNK2_LEN: usize = 1024;
const CHUNK2_SIGNATURE_HEX: &str = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";

/// The terminal, zero-length chunk's published signature.
const CHUNK3_SIGNATURE_HEX: &str = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9";

/// Decodes exactly 64 lowercase hex characters into 32 bytes; panics on anything else, because
/// every literal above is a fixed constant this file owns.
fn hex32(input: &str) -> [u8; 32] {
    let bytes = input.as_bytes();
    assert_eq!(bytes.len(), 64, "vector constant {input:?} is not 64 hex characters");
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[index * 2] as char).to_digit(16).expect("lowercase hex");
        let lo = (bytes[index * 2 + 1] as char).to_digit(16).expect("lowercase hex");
        *slot = ((hi << 4) | lo) as u8;
    }
    out
}

fn signer_at(previous: &str) -> ChunkSigner {
    ChunkSigner::new(
        ChunkSigningKey::from_derived(SIGNING_KEY),
        ChunkScope::new(SCOPE_LINE, AMZ_DATE).expect("the published scope line is well formed"),
        ChunkSeed::from_hex(previous).expect("the vector's seed is 64 lowercase hex characters"),
    )
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive: AWS's own three-chunk chain — 64 KiB, 1 KiB, and the terminal zero-length chunk —
/// verifies exactly as published, with no signature built by this codebase anywhere in the chain.
#[test]
fn c_ing_kav_0001_the_published_three_chunk_chain_verifies() {
    let mut signer = signer_at(SEED_SIGNATURE_HEX);

    signer.update(&[b'a'; CHUNK1_LEN]);
    signer
        .verify_chunk(&hex32(CHUNK1_SIGNATURE_HEX))
        .expect("chunk 1 matches AWS's published signature");

    signer.update(&[b'a'; CHUNK2_LEN]);
    signer
        .verify_chunk(&hex32(CHUNK2_SIGNATURE_HEX))
        .expect("chunk 2 matches AWS's published signature");

    // The terminal chunk carries no data; `update` is not called for it.
    signer
        .verify_chunk(&hex32(CHUNK3_SIGNATURE_HEX))
        .expect("the terminal chunk matches AWS's published signature");

    assert_eq!(signer.chunks_verified(), 3);
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative: one byte of chunk 1's payload changed from the published `65536 * 'a'` breaks the
/// digest, so the published chunk 1 signature no longer matches.
#[test]
fn a_single_byte_changed_in_the_published_chunk_breaks_its_signature() {
    let mut signer = signer_at(SEED_SIGNATURE_HEX);
    let mut data = vec![b'a'; CHUNK1_LEN];
    data[CHUNK1_LEN - 1] = b'b';
    signer.update(&data);

    assert_eq!(
        signer.verify_chunk(&hex32(CHUNK1_SIGNATURE_HEX)),
        Err(ChunkReject::SignatureChainBroken { chunk_index: 0 })
    );
}

/// Negative: chunk 2's published signature presented in chunk 1's position. The chain is
/// positional — chunk 2's signature was computed with chunk 1's signature as its own "previous"
/// line, so it cannot double as chunk 1's answer even though both are real, AWS-published values.
#[test]
fn the_published_chunk_2_signature_does_not_verify_as_chunk_1() {
    let mut signer = signer_at(SEED_SIGNATURE_HEX);
    signer.update(&[b'a'; CHUNK1_LEN]);

    assert_eq!(
        signer.verify_chunk(&hex32(CHUNK2_SIGNATURE_HEX)),
        Err(ChunkReject::SignatureChainBroken { chunk_index: 0 })
    );
}

/// Negative: starting the chain from a seed one bit away from AWS's published seed signature.
/// The chunk data and the presented signature are both exactly what AWS published; only the seed
/// is wrong, and that alone is enough to break the chain at chunk 0.
#[test]
fn a_seed_one_bit_off_the_published_value_breaks_the_chain() {
    let mut seed = hex32(SEED_SIGNATURE_HEX);
    seed[0] ^= 0x01;
    let mut signer = ChunkSigner::new(
        ChunkSigningKey::from_derived(SIGNING_KEY),
        ChunkScope::new(SCOPE_LINE, AMZ_DATE).expect("valid scope"),
        ChunkSeed::from_request_signature(seed),
    );
    signer.update(&[b'a'; CHUNK1_LEN]);

    assert_eq!(
        signer.verify_chunk(&hex32(CHUNK1_SIGNATURE_HEX)),
        Err(ChunkReject::SignatureChainBroken { chunk_index: 0 })
    );
}

/// Negative: a signing key one byte away from the one that produces AWS's published seed
/// signature. The data and every presented signature stay exactly as published; only the key
/// this deployment holds is wrong, which is the shape a stale or mistyped secret takes in
/// production.
#[test]
fn a_signing_key_one_byte_off_the_published_key_breaks_the_chain() {
    let mut key = SIGNING_KEY;
    key[0] ^= 0x01;
    let mut signer = ChunkSigner::new(
        ChunkSigningKey::from_derived(key),
        ChunkScope::new(SCOPE_LINE, AMZ_DATE).expect("valid scope"),
        ChunkSeed::from_hex(SEED_SIGNATURE_HEX).expect("valid seed"),
    );
    signer.update(&[b'a'; CHUNK1_LEN]);

    assert_eq!(
        signer.verify_chunk(&hex32(CHUNK1_SIGNATURE_HEX)),
        Err(ChunkReject::SignatureChainBroken { chunk_index: 0 })
    );
}

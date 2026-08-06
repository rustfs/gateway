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

//! The aws-chunked signature chain: one link per chunk, seeded by the request signature.
//!
//! Responsible for: [`ChunkSigner`], the two algorithm lines a chunk and a trailer are signed
//! under, and the frame a signed chunk is written as.
//! NOT responsible for: deriving the key (that is [`crate::signing_key`], and the chain is handed
//! the result), deciding that the body is framed at all (that is [`crate::PayloadMode`]), or
//! decoding a frame — the decoder lives in `rustfs-gateway-http`.
//! Upstream: [`super::SigV4Signer`], which is the only thing that can build one, because the seed
//! is a request signature. Downstream: `src/signer_tests.rs`.
//!
//! # Why the last HMAC is spelled here rather than reused
//!
//! [`crate::calculate_signature`] takes a [`crate::StringToSign`], which is the *canonical-request*
//! grammar — algorithm, timestamp, scope, digest-of-canonical-request. A chunk's string-to-sign is
//! a different grammar with a previous-signature line in it, and [`crate::StringToSign`] has no
//! constructor outside its own module. The derivation chain is shared; only the final HMAC is
//! written twice, and the alternative is a public constructor for a type whose whole value is that
//! only one function produces it.

use sha2::{Digest, Sha256};

use super::{AmzDate, SigningKey, encode_hex_lower};

/// The algorithm line of a chunk's string-to-sign.
pub const CHUNK_ALGORITHM: &str = "AWS4-HMAC-SHA256-PAYLOAD";
/// The algorithm line of the trailing-header block's string-to-sign.
pub const TRAILER_ALGORITHM: &str = "AWS4-HMAC-SHA256-TRAILER";
/// The chunk-extension a signed aws-chunked frame carries.
pub const CHUNK_SIGNATURE_EXTENSION: &str = ";chunk-signature=";

/// The aws-chunked signature chain: the seed is the request signature, each chunk seeds the next.
///
/// It holds the derived key, so it has no `Debug` and no way to hand the key back:
///
/// ```compile_fail,E0599
/// use rustfs_gateway_sig::ChunkSigner;
/// fn leak(signer: &ChunkSigner) {
///     let _ = signer.expose_key(); // there is no such method, on purpose
/// }
/// ```
pub struct ChunkSigner {
    material: SigningKey,
    timestamp: AmzDate,
    scope_line: String,
    previous: String,
}

impl ChunkSigner {
    /// The signature of the previous link: the seed before any chunk, then each chunk's own.
    #[must_use]
    pub fn previous_signature_hex(&self) -> &str {
        &self.previous
    }

    /// Signs one chunk's data and advances the chain.
    ///
    /// The final chunk of an aws-chunked body carries no data; pass an empty slice for it.
    pub fn sign_chunk(&mut self, data: &[u8]) -> &str {
        let mut text = String::with_capacity(160);
        text.push_str(CHUNK_ALGORITHM);
        text.push('\n');
        text.push_str(self.timestamp.as_str());
        text.push('\n');
        text.push_str(&self.scope_line);
        text.push('\n');
        text.push_str(&self.previous);
        text.push('\n');
        text.push_str(&sha256_hex(b""));
        text.push('\n');
        text.push_str(&sha256_hex(data));
        self.advance(&text)
    }

    /// Signs the trailing-header block and advances the chain.
    ///
    /// `trailer_block` is the canonicalised trailing headers exactly as they are sent, each line
    /// `name:value\n`.
    pub fn sign_trailer(&mut self, trailer_block: &str) -> &str {
        let mut text = String::with_capacity(160);
        text.push_str(TRAILER_ALGORITHM);
        text.push('\n');
        text.push_str(self.timestamp.as_str());
        text.push('\n');
        text.push_str(&self.scope_line);
        text.push('\n');
        text.push_str(&self.previous);
        text.push('\n');
        text.push_str(&sha256_hex(trailer_block.as_bytes()));
        self.advance(&text)
    }

    /// One complete signed aws-chunked frame: size line, chunk signature, data, CRLF.
    pub fn encode_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        let size = data.len();
        let signature = self.sign_chunk(data).to_owned();
        let mut out = format!("{size:x}{CHUNK_SIGNATURE_EXTENSION}{signature}\r\n").into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn advance(&mut self, text: &str) -> &str {
        // `StringToSign` is the canonical-request form; a chunk string-to-sign is a different
        // grammar, so the HMAC is taken directly with the same key the request was signed under.
        let next = hmac_hex(&self.material, text.as_bytes());
        self.previous = next;
        &self.previous
    }
}

impl ChunkSigner {
    /// Builds a chain. `pub(super)` because the seed must be a request signature, and
    /// [`super::SigV4Signer::chunk_signer`] is the only thing that holds one together with the key.
    pub(super) fn seeded(material: SigningKey, timestamp: AmzDate, scope_line: String, previous: String) -> Self {
        Self {
            material,
            timestamp,
            scope_line,
            previous,
        }
    }
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    encode_hex_lower(&digest)
}

/// One HMAC-SHA256 under the derived key, rendered as the hex a chunk extension carries.
pub(super) fn hmac_hex(material: &SigningKey, data: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    // `Hmac` accepts a key of any length, so `new_from_slice` cannot fail here.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(material.expose()).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    encode_hex_lower(&bytes)
}

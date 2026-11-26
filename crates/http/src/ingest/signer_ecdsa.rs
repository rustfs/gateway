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

//! ECDSA P-256 (SigV4a) chunk and trailer verification primitives for `aws-chunked` ingest.
//!
//! Responsible for: [`ChunkVerifyingKey`] (the 33-byte SEC1 compressed public point adopted from
//! `rustfs-gateway-sig`), [`EcdsaChunkSeed`] (the unpadded lowercase-hex DER request-head seed),
//! strict wire parsing of unpadded or 144-char right-`'*'`-padded DER chunk/trailer signatures,
//! and high-S-tolerant P-256 verification.
//! NOT responsible for: P-256 keypair derivation from secrets (that stays in
//! `rustfs-gateway-sig`), framing state transitions (`decoder.rs`), or HMAC-SHA256 chunk chains
//! (`signer.rs`).
//! Upstream: `p256`, [`crate::ingest::reject::ChunkReject`]. Downstream: `decoder.rs`, `signer.rs`.

use core::fmt;

use p256::ecdsa::signature::Verifier;

use crate::ingest::reject::ChunkReject;

/// The fixed prefix of a SigV4a streaming chunk string-to-sign.
pub(crate) const ECDSA_CHUNK_STRING_TO_SIGN_PREFIX: &[u8] = b"AWS4-ECDSA-P256-SHA256-PAYLOAD\n";

/// The fixed prefix of a SigV4a streaming trailer string-to-sign.
pub(crate) const ECDSA_TRAILER_STRING_TO_SIGN_PREFIX: &[u8] = b"AWS4-ECDSA-P256-SHA256-TRAILER\n";

/// Minimum byte length of a canonical ASN.1 DER ECDSA P-256 signature.
pub(crate) const MIN_ECDSA_DER_BYTES: usize = 8;

/// Maximum byte length of a canonical ASN.1 DER ECDSA P-256 signature.
pub(crate) const MAX_ECDSA_DER_BYTES: usize = 72;

/// Maximum lowercase-hex length of an ASN.1 DER ECDSA P-256 signature (and AWS CRT padded width).
pub(crate) const MAX_ECDSA_DER_HEX_BYTES: usize = 144;

/// Stack buffer capacity for a SigV4a chunk or trailer string-to-sign (max 403 bytes).
pub(crate) const ECDSA_STRING_TO_SIGN_CAPACITY: usize = 512;

/// AWS CRT right-padding byte for streaming SigV4a chunk and trailer signatures.
const SIGV4A_PADDING_BYTE: u8 = b'*';

/// The public P-256 verifying key used to check per-chunk and trailer SigV4a signatures.
///
/// Holds only the public curve point — never the derived private scalar — so zero secret material
/// crosses the boundary into `rustfs-gateway-http`.
#[derive(Clone, Copy)]
pub struct ChunkVerifyingKey {
    inner: p256::ecdsa::VerifyingKey,
}

impl ChunkVerifyingKey {
    /// Adopts a 33-byte SEC1 compressed P-256 public key produced by `rustfs-gateway-sig`.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::SignatureChainBroken`] for chunk zero if the bytes are not a valid P-256
    /// point.
    pub fn from_sec1_compressed(bytes: [u8; 33]) -> Result<Self, ChunkReject> {
        let inner = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| ChunkReject::SignatureChainBroken { chunk_index: 0 })?;
        Ok(Self { inner })
    }

    /// Verifies `der_bytes` over `message`, accepting compliant high-S (`s > n/2`) ECDSA values.
    pub(crate) fn verify_der(&self, message: &[u8], der_bytes: &[u8]) -> bool {
        let Ok(parsed) = p256::ecdsa::Signature::from_der(der_bytes) else {
            return false;
        };
        let normalized = parsed.normalize_s();
        self.inner.verify(message, &normalized).is_ok()
    }
}

impl fmt::Debug for ChunkVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkVerifyingKey(<p256-public>)")
    }
}

/// The verified SigV4a request-head DER signature that seeds an ECDSA chunk chain.
///
/// Stack-resident and unpadded: head `Authorization` signatures never carry `'*'` padding.
/// No `Debug` and no `PartialEq`.
pub struct EcdsaChunkSeed {
    hex: [u8; MAX_ECDSA_DER_HEX_BYTES],
    len: u8,
}

impl EcdsaChunkSeed {
    /// Parses the unpadded lowercase-hex ASN.1 DER request-head signature.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::SignatureChainBroken`] for chunk zero if the value is not valid unpadded
    /// lowercase-hex canonical DER.
    pub fn from_hex(hex: &str) -> Result<Self, ChunkReject> {
        let frame =
            EcdsaDerFrame::parse_unpadded_hex(hex.as_bytes()).ok_or(ChunkReject::SignatureChainBroken { chunk_index: 0 })?;
        Self::from_frame(&frame)
    }

    /// Adopts validated raw ASN.1 DER request-head signature bytes directly (e.g. published by the
    /// authenticator after request-head verification).
    ///
    /// # Errors
    ///
    /// [`ChunkReject::SignatureChainBroken`] for chunk zero if the bytes are not a strict canonical
    /// ASN.1 DER ECDSA P-256 signature.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, ChunkReject> {
        let frame = EcdsaDerFrame::from_der_bytes(der_bytes).ok_or(ChunkReject::SignatureChainBroken { chunk_index: 0 })?;
        Self::from_frame(&frame)
    }

    fn from_frame(frame: &EcdsaDerFrame) -> Result<Self, ChunkReject> {
        let mut out = [0u8; MAX_ECDSA_DER_HEX_BYTES];
        let hex_len = frame
            .write_hex_lower(&mut out)
            .ok_or(ChunkReject::SignatureChainBroken { chunk_index: 0 })?;
        let len = u8::try_from(hex_len).map_err(|_| ChunkReject::SignatureChainBroken { chunk_index: 0 })?;
        Ok(Self { hex: out, len })
    }

    pub(crate) const fn into_parts(self) -> ([u8; MAX_ECDSA_DER_HEX_BYTES], u8) {
        (self.hex, self.len)
    }
}

/// One parsed ASN.1 DER ECDSA P-256 signature read from a chunk extension or trailer line.
///
/// Stack-resident with no `Debug` and no `PartialEq`.
#[derive(Clone, Copy)]
pub(crate) struct EcdsaDerFrame {
    der: [u8; MAX_ECDSA_DER_BYTES],
    len: u8,
}

impl EcdsaDerFrame {
    /// Parses a wire chunk or trailer signature: either unpadded lowercase-hex DER (`16..=144`
    /// even bytes) or AWS CRT 144-byte right-`'*'`-padded lowercase-hex DER.
    pub(crate) fn parse_wire_hex(input: &[u8]) -> Option<Self> {
        if input.contains(&SIGV4A_PADDING_BYTE) {
            if input.len() != MAX_ECDSA_DER_HEX_BYTES {
                return None;
            }
            let first_pad = input.iter().position(|byte| *byte == SIGV4A_PADDING_BYTE)?;
            let hex_part = input.get(..first_pad)?;
            let pad_part = input.get(first_pad..)?;
            if !pad_part.iter().all(|byte| *byte == SIGV4A_PADDING_BYTE) {
                return None;
            }
            Self::parse_unpadded_hex(hex_part)
        } else {
            Self::parse_unpadded_hex(input)
        }
    }

    /// Parses strictly unpadded lowercase-hex canonical ASN.1 DER bytes.
    pub(crate) fn parse_unpadded_hex(input: &[u8]) -> Option<Self> {
        let min_hex = MIN_ECDSA_DER_BYTES.checked_mul(2)?;
        if input.len() < min_hex || input.len() > MAX_ECDSA_DER_HEX_BYTES || !input.len().is_multiple_of(2) {
            return None;
        }
        let byte_len = input.len().checked_div(2)?;
        let mut der = [0u8; MAX_ECDSA_DER_BYTES];
        let target = der.get_mut(..byte_len)?;
        for (index, slot) in target.iter_mut().enumerate() {
            let at = index.checked_mul(2)?;
            let high = hex_value_lower(*input.get(at)?)?;
            let low = hex_value_lower(*input.get(at.checked_add(1)?)?)?;
            *slot = (high << 4) | low;
        }
        let slice = der.get(..byte_len)?;
        Self::from_der_bytes(slice)
    }

    /// Validates raw canonical ASN.1 DER ECDSA P-256 bytes.
    pub(crate) fn from_der_bytes(slice: &[u8]) -> Option<Self> {
        if slice.len() < MIN_ECDSA_DER_BYTES || slice.len() > MAX_ECDSA_DER_BYTES {
            return None;
        }
        let parsed = p256::ecdsa::Signature::from_der(slice).ok()?;
        if parsed.to_der().as_bytes().len() != slice.len() {
            return None;
        }
        let mut der = [0u8; MAX_ECDSA_DER_BYTES];
        der.get_mut(..slice.len())?.copy_from_slice(slice);
        let len = u8::try_from(slice.len()).ok()?;
        Some(Self { der, len })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        let len = usize::from(self.len);
        self.der.get(..len).unwrap_or(&[])
    }

    pub(crate) fn write_hex_lower(&self, out: &mut [u8; MAX_ECDSA_DER_HEX_BYTES]) -> Option<usize> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let bytes = self.as_bytes();
        let hex_len = bytes.len().checked_mul(2)?;
        for (index, byte) in bytes.iter().enumerate() {
            let at = index.checked_mul(2)?;
            let high = *DIGITS.get(usize::from(byte >> 4))?;
            let low = *DIGITS.get(usize::from(byte & 0x0f))?;
            *out.get_mut(at)? = high;
            *out.get_mut(at.checked_add(1)?)? = low;
        }
        Some(hex_len)
    }
}

fn hex_value_lower(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Writes one SigV4a ECDSA chunk string-to-sign into `out` entirely on the stack.
pub(crate) fn write_ecdsa_chunk_sts(
    amz_date: &str,
    scope_line: &str,
    previous_hex: &[u8],
    chunk_digest: &[u8; 32],
    out: &mut [u8; ECDSA_STRING_TO_SIGN_CAPACITY],
) -> Option<usize> {
    let mut at = 0usize;
    let mut put = |src: &[u8], at: &mut usize| -> Option<()> {
        let end = at.checked_add(src.len())?;
        out.get_mut(*at..end)?.copy_from_slice(src);
        *at = end;
        Some(())
    };

    put(ECDSA_CHUNK_STRING_TO_SIGN_PREFIX, &mut at)?;
    put(amz_date.as_bytes(), &mut at)?;
    put(b"\n", &mut at)?;
    put(scope_line.as_bytes(), &mut at)?;
    put(b"\n", &mut at)?;
    put(previous_hex, &mut at)?;
    put(b"\n", &mut at)?;
    put(crate::ingest::signer::EMPTY_SHA256_HEX, &mut at)?;
    put(b"\n", &mut at)?;

    let mut hex = [0u8; 64];
    crate::ingest::signer::write_hex_lower(chunk_digest, &mut hex);
    put(&hex, &mut at)?;

    Some(at)
}

/// Writes one SigV4a ECDSA trailer string-to-sign into `out` entirely on the stack.
pub(crate) fn write_ecdsa_trailer_sts(
    amz_date: &str,
    scope_line: &str,
    previous_hex: &[u8],
    trailer_digest: &[u8; 32],
    out: &mut [u8; ECDSA_STRING_TO_SIGN_CAPACITY],
) -> Option<usize> {
    let mut at = 0usize;
    let mut put = |src: &[u8], at: &mut usize| -> Option<()> {
        let end = at.checked_add(src.len())?;
        out.get_mut(*at..end)?.copy_from_slice(src);
        *at = end;
        Some(())
    };

    put(ECDSA_TRAILER_STRING_TO_SIGN_PREFIX, &mut at)?;
    put(amz_date.as_bytes(), &mut at)?;
    put(b"\n", &mut at)?;
    put(scope_line.as_bytes(), &mut at)?;
    put(b"\n", &mut at)?;
    put(previous_hex, &mut at)?;
    put(b"\n", &mut at)?;

    let mut hex = [0u8; 64];
    crate::ingest::signer::write_hex_lower(trailer_digest, &mut hex);
    put(&hex, &mut at)?;

    Some(at)
}

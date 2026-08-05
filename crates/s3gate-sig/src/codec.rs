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

//! Strict, length-exact hex and base64 codecs for digests and signatures.
//!
//! Responsible for: decoding into a fixed-size array or failing — never truncating, never
//! zero-padding, never accepting two spellings of one value; and the matching encoders used to
//! rebuild the client's original signed token.
//! NOT responsible for: deciding what a decoded digest means (that is [`crate::PayloadMode`]),
//! constant-time comparison (that is [`crate::Signature`]), or general-purpose base64 — these
//! functions only handle the exact lengths the signature protocol uses.
//! Upstream: [`crate::SigParseError`]. Downstream: `mode.rs`, `signature.rs`, and P2-03's
//! `Authorization` parser.

use crate::SigParseError;

/// Length of the base64 encoding of a 32-byte digest, padding included.
const BASE64_SHA256_LEN: usize = 44;

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decodes exactly `N * 2` lowercase hex characters into `N` bytes.
///
/// Any other length fails. This is the anti-truncation rule: a 63- or 65-character digest is a
/// malformed request, and silently truncating or zero-padding it would let a client control the
/// bytes a later comparison runs over.
///
/// # Errors
///
/// [`SigParseError::MalformedHex`] if the length is wrong or any byte is outside `[0-9a-f]`.
/// Uppercase is rejected on purpose — AWS signs lowercase, and accepting both spellings creates
/// two strings with one meaning.
///
/// # Examples
///
/// ```
/// # use s3gate_sig::codec::decode_hex_lower;
/// let digest = decode_hex_lower::<32>(&"ab".repeat(32)).expect("valid");
/// assert_eq!(digest[0], 0xab);
/// assert!(decode_hex_lower::<32>(&"AB".repeat(32)).is_err());
/// ```
pub fn decode_hex_lower<const N: usize>(input: &str) -> Result<[u8; N], SigParseError> {
    let bytes = input.as_bytes();
    if bytes.len() != N * 2 {
        return Err(SigParseError::MalformedHex);
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        // `chunks_exact(2)` yields slices of length two, so both indexes are in range.
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, SigParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SigParseError::MalformedHex),
    }
}

/// Encodes `N` bytes as lowercase hex.
#[must_use]
pub fn encode_hex_lower<const N: usize>(bytes: &[u8; N]) -> String {
    let mut out = String::with_capacity(N * 2);
    for byte in bytes {
        out.push(char::from(nibble_to_hex(byte >> 4)));
        out.push(char::from(nibble_to_hex(byte & 0x0f)));
    }
    out
}

fn nibble_to_hex(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble & 0x0f) - 10,
    }
}

/// Decodes canonical standard base64 of a 32-byte SHA-256 digest.
///
/// Generic REST SigV4 signers put the payload checksum into `x-amz-content-sha256` in base64
/// rather than hex (observed in s3s#631), so this form has to be accepted — but only in its one
/// canonical spelling.
///
/// Rejected, each for a concrete reason:
///
/// * any length other than 44 characters — the digest is fixed at 32 bytes;
/// * the URL-safe alphabet (`-`/`_`) and any whitespace — same bytes, different string;
/// * missing, extra, or interior padding;
/// * a final character carrying non-zero unused bits. 44 characters encode 33 bytes' worth of
///   slots; the last character contributes only 4 of its 6 bits. A lenient decoder accepts 64
///   different spellings of every digest, and "two strings, one digest" is exactly the shape of
///   a comparison bypass.
///
/// # Errors
///
/// [`SigParseError::MalformedBase64`] on any of the above.
pub fn decode_base64_sha256(input: &str) -> Result<[u8; 32], SigParseError> {
    let bytes = input.as_bytes();
    if bytes.len() != BASE64_SHA256_LEN {
        return Err(SigParseError::MalformedBase64);
    }
    // Exactly one padding character, and it is last: 32 bytes is 10 full groups plus 2 bytes.
    if bytes[BASE64_SHA256_LEN - 1] != b'=' {
        return Err(SigParseError::MalformedBase64);
    }

    let mut out = [0u8; 32];
    let mut written = 0usize;
    let mut accumulator = 0u32;
    let mut bits = 0u32;

    for &byte in &bytes[..BASE64_SHA256_LEN - 1] {
        let value = base64_value(byte)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let full = u8::try_from((accumulator >> bits) & 0xff).map_err(|_| SigParseError::MalformedBase64)?;
            let slot = out.get_mut(written).ok_or(SigParseError::MalformedBase64)?;
            *slot = full;
            written += 1;
        }
    }

    if written != 32 {
        return Err(SigParseError::MalformedBase64);
    }
    // Canonicality: the leftover bits of the last character must be zero.
    if bits != 0 && (accumulator & ((1 << bits) - 1)) != 0 {
        return Err(SigParseError::MalformedBase64);
    }
    Ok(out)
}

fn base64_value(byte: u8) -> Result<u8, SigParseError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(SigParseError::MalformedBase64),
    }
}

/// Encodes a 32-byte digest as canonical standard base64, padding included.
#[must_use]
pub fn encode_base64_sha256(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(BASE64_SHA256_LEN);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &byte in digest {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let index = usize::try_from((accumulator >> bits) & 0x3f).unwrap_or(0);
            out.push(char::from(BASE64_ALPHABET[index & 0x3f]));
        }
    }
    if bits > 0 {
        let index = usize::try_from((accumulator << (6 - bits)) & 0x3f).unwrap_or(0);
        out.push(char::from(BASE64_ALPHABET[index & 0x3f]));
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    #[test]
    fn hex_round_trip_is_lowercase() {
        let encoded = encode_hex_lower(&DIGEST);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_hex_lower::<32>(&encoded).expect("round trip"), DIGEST);
    }

    #[test]
    fn base64_round_trip_matches_hex_digest() {
        let encoded = encode_base64_sha256(&DIGEST);
        assert_eq!(encoded.len(), BASE64_SHA256_LEN);
        assert_eq!(decode_base64_sha256(&encoded).expect("round trip"), DIGEST);
    }

    #[test]
    fn hex_rejects_wrong_length_without_truncating() {
        assert_eq!(decode_hex_lower::<32>(&"a".repeat(63)), Err(SigParseError::MalformedHex));
        assert_eq!(decode_hex_lower::<32>(&"a".repeat(65)), Err(SigParseError::MalformedHex));
        assert_eq!(decode_hex_lower::<32>(""), Err(SigParseError::MalformedHex));
    }

    #[test]
    fn hex_rejects_uppercase_and_non_hex_bytes() {
        assert_eq!(decode_hex_lower::<32>(&"AB".repeat(32)), Err(SigParseError::MalformedHex));
        assert_eq!(decode_hex_lower::<32>(&"zz".repeat(32)), Err(SigParseError::MalformedHex));
        // A hex string padded with spaces is a different string, not a lenient spelling.
        let padded = format!(" {}", "ab".repeat(32));
        assert_eq!(decode_hex_lower::<32>(&padded[..64]), Err(SigParseError::MalformedHex));
    }

    #[test]
    fn base64_rejects_non_canonical_trailing_bits() {
        let mut encoded = encode_base64_sha256(&DIGEST).into_bytes();
        // Bump the last data character to a value with non-zero unused low bits.
        let last = encoded.len() - 2;
        let value = base64_value(encoded[last]).expect("alphabet");
        encoded[last] = BASE64_ALPHABET[usize::from(value | 0b11)];
        let mutated = String::from_utf8(encoded).expect("ascii");
        assert_eq!(decode_base64_sha256(&mutated), Err(SigParseError::MalformedBase64));
    }

    #[test]
    fn base64_rejects_padding_and_alphabet_deviations() {
        let encoded = encode_base64_sha256(&DIGEST);
        let unpadded = encoded.trim_end_matches('=').to_owned();
        assert_eq!(decode_base64_sha256(&unpadded), Err(SigParseError::MalformedBase64));
        assert_eq!(decode_base64_sha256(&format!("{encoded}=")), Err(SigParseError::MalformedBase64));
        let url_safe = encoded.replace('+', "-").replace('/', "_");
        if url_safe != encoded {
            assert_eq!(decode_base64_sha256(&url_safe), Err(SigParseError::MalformedBase64));
        }
        let with_newline = format!("{}\n", &encoded[..BASE64_SHA256_LEN - 1]);
        assert_eq!(decode_base64_sha256(&with_newline), Err(SigParseError::MalformedBase64));
    }
}

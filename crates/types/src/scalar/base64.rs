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

//! Standard base64 (RFC 4648 §4) for the short, fixed-size values S3 puts in headers.
//!
//! Responsible for: encoding and decoding checksum digests and `Content-MD5`, strictly — the
//! standard alphabet only, mandatory padding, no whitespace, and no non-canonical trailing bits.
//! Strictness matters because a checksum header is a security-adjacent input: two spellings that
//! decode to the same digest would let a client pick which one a downstream cache sees.
//! NOT responsible for: URL-safe base64, streaming, or anything large. Digests are at most 32
//! bytes, so a table-driven scalar implementation is the right size of hammer and keeps a
//! dependency out of the tree.
//! Upstream: none. Downstream: [`super::checksum`].

use super::parse_error::{ParseError, rules};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The number of base64 characters (including padding) that `n` bytes encode to.
pub(super) const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encodes `input` with the standard alphabet and padding.
pub(super) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(input.len()));
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
        let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
        let bits = (b0 << 16) | (b1 << 8) | b2;

        out.push(char::from(ALPHABET[(bits >> 18) as usize & 0x3f]));
        out.push(char::from(ALPHABET[(bits >> 12) as usize & 0x3f]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(bits >> 6) as usize & 0x3f])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[bits as usize & 0x3f])
        } else {
            '='
        });
    }
    out
}

/// Decodes strict standard base64 into `out`, returning the number of bytes written.
///
/// # Errors
///
/// Returns a [`ParseError`] with `subject` for input that is not a multiple of four characters,
/// uses a character outside the alphabet, pads in the middle, sets non-canonical trailing bits, or
/// decodes to more than `out.len()` bytes.
pub(super) fn decode_into(subject: &'static str, input: &str, out: &mut [u8]) -> Result<usize, ParseError> {
    let bytes = input.as_bytes();
    let err = |reason: &'static str| ParseError::new(subject, rules::RFC4648_BASE64, reason);

    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(err("base64 value is empty or not a multiple of four characters"));
    }

    let mut written = 0usize;
    let quads = bytes.len() / 4;
    for (index, quad) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == quads;
        let mut bits = 0u32;
        let mut pad = 0usize;
        for (position, &byte) in quad.iter().enumerate() {
            if byte == b'=' {
                if !last || position < 2 {
                    return Err(err("base64 padding appears before the end of the value"));
                }
                pad += 1;
                bits <<= 6;
                continue;
            }
            if pad != 0 {
                return Err(err("base64 padding is followed by data"));
            }
            let Some(value) = decode_symbol(byte) else {
                return Err(err("base64 value contains a character outside the standard alphabet"));
            };
            bits = (bits << 6) | u32::from(value);
        }

        let produced = 3 - pad;
        // Non-canonical encodings (trailing bits that the padding says are absent) are rejected so
        // that one digest has exactly one spelling.
        let discarded_bits = bits & ((1u32 << (pad * 8)) - 1);
        if discarded_bits != 0 {
            return Err(err("base64 value sets bits that its padding declares absent"));
        }
        if written + produced > out.len() {
            return Err(err("base64 value decodes to more bytes than the field can hold"));
        }
        let full = bits.to_be_bytes();
        out[written..written + produced].copy_from_slice(&full[1..1 + produced]);
        written += produced;
    }
    Ok(written)
}

const fn decode_symbol(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

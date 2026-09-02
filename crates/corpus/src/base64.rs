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

//! Responsible for: standard-alphabet, padded base64 with strict decoding, used for the
//! `bytes_b64` and `body_b64` fields.
//! Not responsible for: any URL-safe or unpadded variant, and for choosing what gets
//! encoded — that is `schema`'s and `store`'s business.
//! Upstream: `schema` on load and store, `case` on conversion.
//! Downstream: nothing; this module depends on `core` only.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard, padded base64.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        let b0 = u32::from(group[0]);
        let b1 = group.get(1).copied().map_or(0, u32::from);
        let b2 = group.get(2).copied().map_or(0, u32::from);
        let packed = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((packed >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((packed >> 12) & 0x3f) as usize]));
        out.push(if group.len() > 1 {
            char::from(ALPHABET[((packed >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            char::from(ALPHABET[(packed & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

fn value_of(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard, padded base64.
///
/// Strict by construction: a wrong length, a character outside the alphabet, or padding
/// anywhere but the tail is an error rather than a silently shorter output. A decoder
/// that repairs its input cannot be used to prove anything about the bytes it was given.
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(format!("base64 length {} is not a multiple of 4", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, group) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let pad = group.iter().filter(|byte| **byte == b'=').count();
        if pad > 0 && !last {
            return Err("base64 padding appears before the final group".to_owned());
        }
        if pad > 2 || (pad > 0 && group[3] != b'=') || (pad == 2 && group[2] != b'=') {
            return Err("base64 padding is misplaced".to_owned());
        }
        let mut packed = 0u32;
        for (offset, byte) in group.iter().enumerate() {
            if *byte == b'=' {
                continue;
            }
            let value = value_of(*byte).ok_or_else(|| format!("byte {byte:#04x} is outside the base64 alphabet"))?;
            packed |= value << (18 - 6 * offset);
        }
        out.push(((packed >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((packed >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((packed & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Encode bytes as lowercase hexadecimal, the conformance case schema's `hex` spelling.
pub fn to_hex(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decode lowercase or uppercase hexadecimal.
pub fn from_hex(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("hex length {} is odd", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let mut value = 0u8;
        for byte in pair {
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(format!("byte {byte:#04x} is not a hex digit")),
            };
            value = (value << 4) | nibble;
        }
        out.push(value);
    }
    Ok(out)
}

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

//! User-metadata header rules, including the one that survives decoding.
//!
//! Responsible for: validating `x-amz-meta-*` names as HTTP tokens, and validating values both as
//! they arrive and — when they carry an RFC 2047 encoded-word — as they will look once decoded.
//! NOT responsible for: storing metadata, decoding it for storage, size accounting across the
//! whole metadata set, or writing metadata back out. Outbound injection defence is P3-06's.
//! Upstream: this crate's `text`. Downstream: `header_view`, `wire`.
//!
//! # The rule worth stating twice
//!
//! A value is checked for control characters, then decoded, then checked **again**. An encoded
//! word such as `=?utf-8?B?...?=` is inert bytes on the way in and becomes something else
//! entirely on the way out; validating only the encoded form means a `\r\n` that no inbound check
//! ever saw is present in the decoded value, ready to be written into a response header, a log
//! line or a metadata file. The second check is the whole point of this module — the first one is
//! what the `http` crate already does.

use crate::text::{contains_crlf, contains_forbidden_control, is_token};

/// The prefix every user-metadata header carries.
pub const METADATA_PREFIX: &str = "x-amz-meta-";

/// Why a metadata name or value was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataReject {
    /// The name is not `x-amz-meta-` followed by a non-empty HTTP token.
    ///
    /// A name containing `:`, a space or a CRLF is the header-injection primitive: written back
    /// out unchanged it terminates the field early and starts one the peer chose.
    MalformedKey,
    /// The value carried a control character as received.
    ControlCharacterInValue,
    /// The value carried an RFC 2047 encoded-word this layer cannot parse.
    MalformedEncodedWord,
    /// The value decoded to bytes containing CR, LF or another control character.
    ControlCharacterAfterDecoding,
}

impl MetadataReject {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedKey => "malformed-key",
            Self::ControlCharacterInValue => "control-character-in-value",
            Self::MalformedEncodedWord => "malformed-encoded-word",
            Self::ControlCharacterAfterDecoding => "control-character-after-decoding",
        }
    }
}

/// Validates a user-metadata header name.
///
/// The full name — prefix included — must be a non-empty HTTP token, and the part after the
/// prefix must be non-empty.
///
/// # Errors
///
/// [`MetadataReject::MalformedKey`].
pub fn validate_metadata_key(name: &str) -> Result<(), MetadataReject> {
    let bytes = name.as_bytes();
    if !is_token(bytes) {
        return Err(MetadataReject::MalformedKey);
    }
    let Some(suffix) = name.strip_prefix(METADATA_PREFIX) else {
        return Err(MetadataReject::MalformedKey);
    };
    if suffix.is_empty() {
        return Err(MetadataReject::MalformedKey);
    }
    Ok(())
}

/// Validates a user-metadata header value, before and after RFC 2047 decoding.
///
/// The value must be free of control characters as received; then every RFC 2047 encoded-word it
/// contains is decoded and the decoded bytes are checked again. Nothing is returned: this
/// function answers "may this value exist", not "what does it decode to". Decoding for storage
/// happens exactly once, later, and belongs to whoever stores it.
///
/// # Errors
///
/// * [`MetadataReject::ControlCharacterInValue`] — a control character in the value as received.
/// * [`MetadataReject::MalformedEncodedWord`] — an encoded-word whose charset, encoding or
///   payload does not parse. It is refused rather than treated as literal text, because a
///   downstream decoder that is more forgiving would produce bytes this one never inspected.
/// * [`MetadataReject::ControlCharacterAfterDecoding`] — the decoded bytes contain CR, LF or
///   another control character.
pub fn validate_metadata_value(value: &[u8]) -> Result<(), MetadataReject> {
    if contains_forbidden_control(value) {
        return Err(MetadataReject::ControlCharacterInValue);
    }
    let mut cursor = 0usize;
    while let Some(rest) = value.get(cursor..) {
        let Some(start) = find(rest, b"=?") else { break };
        let absolute = cursor.saturating_add(start);
        let after = decode_encoded_word(value.get(absolute..).unwrap_or(&[]))?;
        cursor = absolute.saturating_add(after);
    }
    Ok(())
}

/// Decodes one encoded-word starting at `input[0..2] == "=?"`, validating every decoded byte.
///
/// Returns how many bytes of `input` the encoded-word occupied.
fn decode_encoded_word(input: &[u8]) -> Result<usize, MetadataReject> {
    // `=?charset?E?text?=`; the charset is not interpreted, only skipped, because this function
    // decides whether the decoded bytes are safe, not what they mean.
    let after_prefix = 2usize;
    let rest = input.get(after_prefix..).ok_or(MetadataReject::MalformedEncodedWord)?;
    let charset_len = find(rest, b"?").ok_or(MetadataReject::MalformedEncodedWord)?;
    if charset_len == 0 {
        return Err(MetadataReject::MalformedEncodedWord);
    }
    let after_charset = after_prefix.saturating_add(charset_len).saturating_add(1);

    let encoding = input
        .get(after_charset)
        .copied()
        .ok_or(MetadataReject::MalformedEncodedWord)?;
    if input.get(after_charset.saturating_add(1)) != Some(&b'?') {
        return Err(MetadataReject::MalformedEncodedWord);
    }
    let text_start = after_charset.saturating_add(2);
    let text_all = input.get(text_start..).ok_or(MetadataReject::MalformedEncodedWord)?;
    let text_len = find(text_all, b"?=").ok_or(MetadataReject::MalformedEncodedWord)?;
    let text = text_all.get(..text_len).ok_or(MetadataReject::MalformedEncodedWord)?;

    match encoding {
        b'b' | b'B' => decode_base64(text)?,
        b'q' | b'Q' => decode_quoted(text)?,
        _ => return Err(MetadataReject::MalformedEncodedWord),
    }

    Ok(text_start.saturating_add(text_len).saturating_add(2))
}

/// Decodes base64 encoded text, rejecting any decoded byte that is a control character.
///
/// Decoding runs through a three-byte window and is never collected: the decoded value is not
/// wanted here, only the verdict on it.
fn decode_base64(text: &[u8]) -> Result<(), MetadataReject> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text {
        if *byte == b'=' {
            break;
        }
        let value = base64_value(*byte).ok_or(MetadataReject::MalformedEncodedWord)?;
        accumulator = accumulator.checked_shl(6).ok_or(MetadataReject::MalformedEncodedWord)? | u32::from(value);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            let shifted = accumulator.checked_shr(bits).ok_or(MetadataReject::MalformedEncodedWord)?;
            let decoded = u8::try_from(shifted & 0xFF).map_err(|_| MetadataReject::MalformedEncodedWord)?;
            reject_decoded(decoded)?;
            accumulator &= (1u32.checked_shl(bits).unwrap_or(0)).wrapping_sub(1);
        }
    }
    Ok(())
}

/// The 6-bit value of one standard base64 alphabet character.
fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(byte.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes RFC 2047 "Q" encoded text, rejecting any decoded byte that is a control character.
fn decode_quoted(text: &[u8]) -> Result<(), MetadataReject> {
    let mut index = 0usize;
    while let Some(byte) = text.get(index).copied() {
        match byte {
            b'_' => {
                index = index.saturating_add(1);
            }
            b'=' => {
                let high = text
                    .get(index.saturating_add(1))
                    .copied()
                    .ok_or(MetadataReject::MalformedEncodedWord)?;
                let low = text
                    .get(index.saturating_add(2))
                    .copied()
                    .ok_or(MetadataReject::MalformedEncodedWord)?;
                let high = hex_nibble(high).ok_or(MetadataReject::MalformedEncodedWord)?;
                let low = hex_nibble(low).ok_or(MetadataReject::MalformedEncodedWord)?;
                let decoded = high.checked_shl(4).unwrap_or(0) | low;
                reject_decoded(decoded)?;
                index = index.saturating_add(3);
            }
            other => {
                reject_decoded(other)?;
                index = index.saturating_add(1);
            }
        }
    }
    Ok(())
}

/// The numeric value of one hexadecimal digit.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Refuses one decoded byte if it is a control character.
fn reject_decoded(byte: u8) -> Result<(), MetadataReject> {
    let single = [byte];
    if contains_crlf(&single) || contains_forbidden_control(&single) {
        return Err(MetadataReject::ControlCharacterAfterDecoding);
    }
    Ok(())
}

/// The offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

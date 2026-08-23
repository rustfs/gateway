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
//! Responsible for: validating `x-amz-meta-*` names as HTTP tokens, decoding RFC 2047 values for
//! storage, and encoding stored Unicode values for a response.
//! NOT responsible for: storing metadata or size accounting across the whole metadata set.
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

use std::borrow::Cow;

use crate::text::is_token;

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
    if contains_metadata_control(value) {
        return Err(MetadataReject::ControlCharacterInValue);
    }
    let value = core::str::from_utf8(value).map_err(|_| MetadataReject::MalformedEncodedWord)?;
    let _ = decode_metadata_value(value)?;
    Ok(())
}

/// Decodes every RFC 2047 encoded-word in one accepted user-metadata value.
///
/// Linear whitespace between adjacent encoded-words is not part of the decoded value. Ordinary
/// ASCII text around encoded-words is retained. A value without an encoded-word is borrowed.
///
/// # Errors
///
/// [`MetadataReject`] when an encoded-word is malformed, uses an unsupported charset, is not
/// valid text in its declared charset, or the value contains a control character before or after
/// decoding.
pub fn decode_metadata_value(value: &str) -> Result<Cow<'_, str>, MetadataReject> {
    if value.chars().any(char::is_control) {
        return Err(MetadataReject::ControlCharacterInValue);
    }

    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    let mut output: Option<String> = None;
    while let Some(rest) = bytes.get(cursor..) {
        let Some(relative) = find(rest, b"=?") else { break };
        let start = cursor.saturating_add(relative);
        let (consumed, decoded) = decode_encoded_word(bytes.get(start..).ok_or(MetadataReject::MalformedEncodedWord)?)?;
        let target = output.get_or_insert_with(|| String::with_capacity(value.len()));
        target.push_str(value.get(cursor..start).ok_or(MetadataReject::MalformedEncodedWord)?);
        target.push_str(&decoded);
        cursor = start.saturating_add(consumed);

        let whitespace_end = bytes
            .get(cursor..)
            .map(|tail| {
                tail.iter()
                    .take_while(|byte| matches!(byte, b' ' | b'\t'))
                    .count()
                    .saturating_add(cursor)
            })
            .unwrap_or(cursor);
        if whitespace_end > cursor && bytes.get(whitespace_end..).is_some_and(|tail| tail.starts_with(b"=?")) {
            cursor = whitespace_end;
        }
    }

    let Some(mut output) = output else {
        return Ok(Cow::Borrowed(value));
    };
    output.push_str(value.get(cursor..).ok_or(MetadataReject::MalformedEncodedWord)?);
    if output.chars().any(char::is_control) {
        return Err(MetadataReject::ControlCharacterAfterDecoding);
    }
    Ok(Cow::Owned(output))
}

/// Encodes a non-ASCII user-metadata value into RFC 2047 UTF-8 base64 encoded-words.
///
/// Each word is at most 75 bytes and contains an integral number of UTF-8 characters. ASCII-only
/// values are returned unchanged unless they contain encoded-word syntax that a client could
/// decode a second time.
///
/// # Errors
///
/// [`MetadataReject::ControlCharacterInValue`] when the pre-encode value contains any control
/// character.
pub fn encode_metadata_value(value: &str) -> Result<Cow<'_, str>, MetadataReject> {
    if value.chars().any(char::is_control) {
        return Err(MetadataReject::ControlCharacterInValue);
    }
    if value.is_ascii() && find(value.as_bytes(), b"=?").is_none() {
        return Ok(Cow::Borrowed(value));
    }

    const MAX_INPUT_BYTES_PER_WORD: usize = 45;
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    let mut start = 0usize;
    while start < value.len() {
        let mut end = start.saturating_add(MAX_INPUT_BYTES_PER_WORD).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        if end == start {
            return Err(MetadataReject::MalformedEncodedWord);
        }
        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str("=?UTF-8?B?");
        encode_base64(value.get(start..end).ok_or(MetadataReject::MalformedEncodedWord)?.as_bytes(), &mut output);
        output.push_str("?=");
        start = end;
    }
    Ok(Cow::Owned(output))
}

/// Decodes one encoded-word starting at `input[0..2] == "=?"`.
///
/// Returns the occupied byte count and decoded Unicode text.
fn decode_encoded_word(input: &[u8]) -> Result<(usize, String), MetadataReject> {
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
    let consumed = text_start.saturating_add(text_len).saturating_add(2);
    if consumed > 75 || text.is_empty() {
        return Err(MetadataReject::MalformedEncodedWord);
    }

    let decoded = match encoding {
        b'b' | b'B' => decode_base64(text)?,
        b'q' | b'Q' => decode_quoted(text)?,
        _ => return Err(MetadataReject::MalformedEncodedWord),
    };
    let charset = input
        .get(after_prefix..after_prefix.saturating_add(charset_len))
        .ok_or(MetadataReject::MalformedEncodedWord)?;
    let decoded = decode_charset(charset, &decoded)?;
    if decoded.chars().any(char::is_control) {
        return Err(MetadataReject::ControlCharacterAfterDecoding);
    }

    Ok((consumed, decoded))
}

/// Decodes strict standard base64.
fn decode_base64(text: &[u8]) -> Result<Vec<u8>, MetadataReject> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return Err(MetadataReject::MalformedEncodedWord);
    }
    let mut output = Vec::with_capacity(text.len().saturating_div(4).saturating_mul(3));
    let chunk_count = text.len().saturating_div(4);
    for (index, chunk) in text.chunks_exact(4).enumerate() {
        let [first, second, third, fourth] = chunk else {
            return Err(MetadataReject::MalformedEncodedWord);
        };
        let a = base64_value(*first).ok_or(MetadataReject::MalformedEncodedWord)?;
        let b = base64_value(*second).ok_or(MetadataReject::MalformedEncodedWord)?;
        let is_last = index.saturating_add(1) == chunk_count;
        output.push((a << 2) | (b >> 4));
        match (*third, *fourth) {
            (b'=', b'=') if is_last && b & 0x0F == 0 => {}
            (third, b'=') if is_last => {
                let c = base64_value(third).ok_or(MetadataReject::MalformedEncodedWord)?;
                if c & 0x03 != 0 {
                    return Err(MetadataReject::MalformedEncodedWord);
                }
                output.push((b << 4) | (c >> 2));
            }
            (b'=', _) | (_, b'=') => return Err(MetadataReject::MalformedEncodedWord),
            (third, fourth) => {
                let c = base64_value(third).ok_or(MetadataReject::MalformedEncodedWord)?;
                let d = base64_value(fourth).ok_or(MetadataReject::MalformedEncodedWord)?;
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
        }
    }
    Ok(output)
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

/// Decodes RFC 2047 "Q" encoded text.
fn decode_quoted(text: &[u8]) -> Result<Vec<u8>, MetadataReject> {
    if text.is_empty() {
        return Err(MetadataReject::MalformedEncodedWord);
    }
    let mut output = Vec::with_capacity(text.len());
    let mut index = 0usize;
    while let Some(byte) = text.get(index).copied() {
        match byte {
            b'_' => {
                output.push(b' ');
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
                output.push(decoded);
                index = index.saturating_add(3);
            }
            other if other.is_ascii_graphic() && other != b'?' => {
                output.push(other);
                index = index.saturating_add(1);
            }
            _ => return Err(MetadataReject::MalformedEncodedWord),
        }
    }
    Ok(output)
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

/// Converts the charsets S3 metadata clients use into Unicode.
fn decode_charset(charset: &[u8], bytes: &[u8]) -> Result<String, MetadataReject> {
    if charset.eq_ignore_ascii_case(b"utf-8") {
        return core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| MetadataReject::MalformedEncodedWord);
    }
    if charset.eq_ignore_ascii_case(b"us-ascii") {
        if !bytes.is_ascii() {
            return Err(MetadataReject::MalformedEncodedWord);
        }
        return core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| MetadataReject::MalformedEncodedWord);
    }
    if charset.eq_ignore_ascii_case(b"iso-8859-1") {
        return Ok(bytes.iter().map(|byte| char::from(*byte)).collect());
    }
    Err(MetadataReject::MalformedEncodedWord)
}

/// Appends standard padded base64.
fn encode_base64(bytes: &[u8], output: &mut String) {
    for chunk in bytes.chunks(3) {
        let Some(a) = chunk.first().copied() else {
            continue;
        };
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(base64_char(a >> 2));
        output.push(base64_char(((a & 0x03) << 4) | (b >> 4)));
        if chunk.len() > 1 {
            output.push(base64_char(((b & 0x0F) << 2) | (c >> 6)));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(base64_char(c & 0x3F));
        } else {
            output.push('=');
        }
    }
}

/// Resolves a six-bit base64 digit without a potentially panicking index operation.
fn base64_char(value: u8) -> char {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ALPHABET.get(usize::from(value)).copied().map(char::from).unwrap_or('=')
}

/// Metadata values must be printable before they are stored or encoded.
fn contains_metadata_control(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| matches!(byte, 0x00..=0x1F | 0x7F))
}

/// The offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

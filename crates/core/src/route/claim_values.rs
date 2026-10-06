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

//! Decoding of strict and opaque claimed-path values.
//!
//! Responsible for: decoding once, strict-segment refusals and the opaque UTF-8 boundary.
//! NOT responsible for: matching paths, claim containment or authorization.
//! Upstream: `claim::PathTemplate`. Downstream: its extracted `PathParams`.

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Decodes one parameter value, once, and refuses what no handler may be handed.
pub(super) fn decode_parameter(raw: &str) -> Result<String, &'static str> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut rest = raw.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%' {
            let [high, low, after @ ..] = tail else {
                return Err("a percent escape is cut short");
            };
            let (Some(high), Some(low)) = (hex(*high), hex(*low)) else {
                return Err("a percent escape is not two hexadecimal digits");
            };
            bytes.push((high << 4) | low);
            rest = after;
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    let value = String::from_utf8(bytes).map_err(|_| "the decoded value is not UTF-8")?;
    if value.is_empty() {
        return Err("the value is empty");
    }
    if value.contains(['/', '\\']) {
        return Err("the decoded value contains a path separator");
    }
    if value == "." || value == ".." {
        return Err("the decoded value is a dot segment");
    }
    if value.chars().any(char::is_control) {
        return Err("the decoded value contains a control character");
    }
    Ok(value)
}

/// Decodes an opaque segment or catch-all once, with the gateway's one name decoder, which is also how RustFS's
/// heal handler decodes the rest it captures: every `%` followed by two hexadecimal digits is that
/// byte, any other `%` stays as it is, and the result must be UTF-8. Nothing else is refused:
/// separators, empty and dot segments and control characters are part of the value, which its
/// handler validates (ADR-0036, ADR-0040).
pub(super) fn decode_opaque(raw: &str) -> Result<String, &'static str> {
    rustfs_gateway_types::decode_once(raw).map_err(|_| "the decoded value is not UTF-8")
}

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

//! Client-authored HTTP/2 control frames: RST_STREAM, GOAWAY, PRIORITY and literal `raw` frames.
//! Responsible for: turning one declared control frame into the exact envelope the writer sends —
//! an error-code name into its RFC 9113 section 7 number, a GOAWAY error code into its eight-octet
//! payload, and a `raw` frame's octets into the envelope they already spell — and refusing, by
//! name, every declaration that would leave a field unsent or make the writer's stream and credit
//! accounting guess.
//! NOT responsible for: writing frames, reading the peer's reaction, or deciding what a peer ought
//! to do; `super::duplex` writes, `super::Receiver` observes, and the case asserts.
//! Upstream: `super::envelope`. Downstream: `super::Envelope`.

use super::{
    CONTINUATION, DATA, Envelope, FRAME_HEADER_LEN, GOAWAY, H2Frame, HEADERS, PRIORITY, RST_STREAM, SETTINGS, SutError,
    WINDOW_UPDATE, declared_stream, refused, within_frame_length,
};

/// The RFC 9113 section 7 error-code registry, by the names the RFC gives them.
const ERROR_CODES: &[(&str, u32)] = &[
    ("NO_ERROR", 0x0),
    ("PROTOCOL_ERROR", 0x1),
    ("INTERNAL_ERROR", 0x2),
    ("FLOW_CONTROL_ERROR", 0x3),
    ("SETTINGS_TIMEOUT", 0x4),
    ("STREAM_CLOSED", 0x5),
    ("FRAME_SIZE_ERROR", 0x6),
    ("REFUSED_STREAM", 0x7),
    ("CANCEL", 0x8),
    ("COMPRESSION_ERROR", 0x9),
    ("CONNECT_ERROR", 0xa),
    ("ENHANCE_YOUR_CALM", 0xb),
    ("INADEQUATE_SECURITY", 0xc),
    ("HTTP_1_1_REQUIRED", 0xd),
];

/// Frame types with a typed form whose stream and credit accounting the writer relies on; a `raw`
/// spelling of one would bypass that accounting, so it is refused rather than guessed at.
const TYPED_ONLY: &[u8] = &[DATA, HEADERS, SETTINGS, WINDOW_UPDATE, CONTINUATION];

/// Whether this module owns the declared frame type.
pub(super) fn owns(kind: &str) -> bool {
    matches!(kind, "rst_stream" | "goaway" | "priority" | "raw")
}

/// The error-code number an authored `error_code` names: a registered name, or `0x` followed by
/// one to eight hexadecimal digits for a code the registry does not name.
fn error_code(index: usize, spelling: &str) -> Result<u32, SutError> {
    if let Some((_, code)) = ERROR_CODES.iter().find(|(name, _)| *name == spelling) {
        return Ok(*code);
    }
    spelling
        .strip_prefix("0x")
        .filter(|digits| (1..=8).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|digits| u32::from_str_radix(digits, 16).ok())
        .ok_or_else(|| {
            refused(format!(
                "`h2_frames[{index}].error_code = \"{spelling}\"` is neither an RFC 9113 section 7 error-code \
                 name such as CANCEL nor a `0x`-prefixed hexadecimal code"
            ))
        })
}

/// Compiles one owned control frame into its envelope.
pub(super) fn envelope(index: usize, frame: &H2Frame) -> Result<Envelope, SutError> {
    let kind = frame.kind.as_str();
    if !frame.flags.is_empty() {
        return Err(refused(format!(
            "`h2_frames[{index}].flags` is declared on a {kind} frame, which defines no flags this writer sets; \
             spell unusual flag bits with a `raw` frame"
        )));
    }
    if frame.increment.is_some() {
        return Err(refused(format!("`h2_frames[{index}].increment` belongs to window_update, not to {kind}")));
    }
    if kind == "raw" {
        return raw(index, frame);
    }
    let frame_type = match kind {
        "rst_stream" => RST_STREAM,
        "goaway" => GOAWAY,
        _ => PRIORITY,
    };
    let stream_id = declared_stream(index, frame, frame_type == GOAWAY)?;
    within_frame_length(index, frame)?;
    let payload = match (frame_type, frame.error_code.as_deref(), frame.payload_declared) {
        (PRIORITY, Some(_), _) => {
            return Err(refused(format!(
                "`h2_frames[{index}].error_code` belongs to rst_stream and goaway, not to priority"
            )));
        }
        (PRIORITY, None, false) => {
            return Err(refused(format!(
                "`h2_frames[{index}]` is a priority frame with no payload_hex; its five octets carry the dependency \
                 and weight the case must spell"
            )));
        }
        (_, Some(_), true) => {
            return Err(refused(format!("`h2_frames[{index}]` declares both error_code and payload_hex")));
        }
        (_, None, true) => frame.payload.clone(),
        (RST_STREAM, Some(code), false) => error_code(index, code)?.to_be_bytes().to_vec(),
        // A client has accepted no server-initiated stream, so the last-stream identifier is zero.
        (_, Some(code), false) => [0_u32.to_be_bytes(), error_code(index, code)?.to_be_bytes()].concat(),
        (_, None, false) => {
            return Err(refused(format!(
                "`h2_frames[{index}]` is a {kind} frame with neither error_code nor payload_hex"
            )));
        }
    };
    Ok(Envelope {
        frame_type,
        flags: 0,
        stream_id,
        payload,
        delay_ms: frame.delay_ms,
    })
}

/// A `raw` frame is one complete frame, header included, written octet for octet.
fn raw(index: usize, frame: &H2Frame) -> Result<Envelope, SutError> {
    if frame.stream_id.is_some() || frame.error_code.is_some() {
        return Err(refused(format!(
            "`h2_frames[{index}]` is a raw frame: its payload_hex is the whole frame, header included, so \
             stream_id and error_code would be ignored rather than sent"
        )));
    }
    if !frame.payload_declared {
        return Err(refused(format!("`h2_frames[{index}]` is a raw frame with no payload_hex")));
    }
    let bytes = frame.payload.as_slice();
    let (header, payload) = bytes.split_at_checked(FRAME_HEADER_LEN).ok_or_else(|| {
        refused(format!(
            "`h2_frames[{index}].payload_hex` is {} octets, shorter than the nine-octet frame header a raw frame spells",
            bytes.len()
        ))
    })?;
    let [l0, l1, l2, frame_type, flags, s0, s1, s2, s3] =
        <[u8; FRAME_HEADER_LEN]>::try_from(header).map_err(|_| refused("a raw frame header is nine octets".to_owned()))?;
    let length = u32::from_be_bytes([0, l0, l1, l2]);
    if usize::try_from(length).ok() != Some(payload.len()) {
        return Err(refused(format!(
            "`h2_frames[{index}]` is a raw frame whose header declares {length} payload octets but carries {}; \
             one raw entry is exactly one frame, so where the peer's frame boundary falls stays authored",
            payload.len()
        )));
    }
    if TYPED_ONLY.contains(&frame_type) {
        return Err(refused(format!(
            "`h2_frames[{index}]` is a raw frame of type 0x{frame_type:02x}, which has a typed form; the writer's \
             stream and flow-control accounting reads the typed form, so declare it that way"
        )));
    }
    Ok(Envelope {
        frame_type,
        flags,
        // The reserved bit is kept: the whole identifier field is authored.
        stream_id: u32::from_be_bytes([s0, s1, s2, s3]),
        payload: payload.to_vec(),
        delay_ms: frame.delay_ms,
    })
}

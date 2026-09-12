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

//! Authored HTTP/2 frame declarations, read in the order the case wrote them.
//! Responsible for: reading every `request.h2_frames` entry into one typed value — its type, stream
//! id, flags, payload octets, error code, increment, and not-before delay — so that no field a case
//! wrote is reduced to "some frames were declared".
//! NOT responsible for: deciding whether a transport can send a frame, encoding one on the wire, or
//! HPACK; `crate::conn::h2` owns all three and refuses what it cannot carry out by name.
//! Upstream: `super::InProcess::read_wire`. Downstream: `crate::conn::h2`.

use crate::sut::SutError;
use crate::value::Value;

/// One `request.h2_frames` entry, exactly as declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct H2Frame {
    /// The `h2Frame.type` spelling, e.g. `headers`.
    pub(crate) kind: String,
    /// The declared stream id, when there is one. Range checks belong to the encoder.
    pub(crate) stream_id: Option<i64>,
    /// The declared flag names, in the order written.
    pub(crate) flags: Vec<String>,
    /// The frame payload octets; empty when `payload_hex` is absent or empty.
    pub(crate) payload: Vec<u8>,
    /// The RST_STREAM or GOAWAY error code spelling.
    pub(crate) error_code: Option<String>,
    /// The WINDOW_UPDATE increment.
    pub(crate) increment: Option<i64>,
    /// How long to wait before writing this frame.
    pub(crate) delay_ms: u64,
}

/// Reads the `request.h2_frames` array; absent is an empty script.
pub(super) fn read(frames: Option<&Value>) -> Result<Vec<H2Frame>, SutError> {
    let Some(frames) = frames else { return Ok(Vec::new()) };
    let frames = frames
        .as_array()
        .ok_or_else(|| SutError::Environment("`request.h2_frames` is not an array of frames".to_owned()))?;
    frames
        .iter()
        .enumerate()
        .map(|(index, frame)| read_one(index, frame))
        .collect()
}

fn read_one(index: usize, frame: &Value) -> Result<H2Frame, SutError> {
    // One read per line: `crate::keys` allows one source location to claim one schema key.
    let kind = frame.read("h2Frame.type").and_then(Value::as_str);
    let stream_id = frame.read("h2Frame.stream_id").and_then(Value::as_integer);
    let flags = frame.read_strings("h2Frame.flags");
    let payload_hex = frame.read("h2Frame.payload_hex").and_then(Value::as_str);
    let error_code = frame.read("h2Frame.error_code").and_then(Value::as_str);
    let increment = frame.read("h2Frame.increment").and_then(Value::as_integer);
    let delay_ms = frame.read("h2Frame.delay_ms").and_then(Value::as_integer);

    let kind = kind.ok_or_else(|| SutError::Environment(format!("`h2_frames[{index}]` declares no `type`")))?;
    let flags = flags.ok_or_else(|| SutError::Environment(format!("`h2_frames[{index}].flags` is not a list of names")))?;
    let payload = match payload_hex {
        None | Some("") => Vec::new(),
        Some(text) => super::decode_hex(text)
            .ok_or_else(|| SutError::Environment(format!("`h2_frames[{index}].payload_hex` is not valid hex")))?,
    };
    Ok(H2Frame {
        kind: kind.to_owned(),
        stream_id,
        flags: flags.into_iter().map(ToOwned::to_owned).collect(),
        payload,
        error_code: error_code.map(ToOwned::to_owned),
        increment,
        delay_ms: delay_ms.unwrap_or(0).unsigned_abs(),
    })
}

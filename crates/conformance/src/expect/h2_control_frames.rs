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

//! Responsible for: exact ordered comparison of supported HTTP/2 control-frame observations, with
//! connection-level WINDOW_UPDATE grants matched by presence and value outside that order.
//! NOT responsible for: reading sockets, classifying stream outcomes, or application event frames.
//! Upstream: `super::judge` and transport observations. Downstream: expectation diagnostics.

use crate::diagnostic::Diagnostic;
use crate::observation::{Observation, ObservedH2ControlFrame};
use crate::value::Value;

pub(super) fn check_h2_control_frames(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(expected) = expect.read("expect.h2_control_frames") else { return };
    let failure = match (expected.as_array(), observed.h2_control_frames.as_ref()) {
        (None, _) => Some("expected control frames must be an array"),
        (_, None) => Some("this transport did not measure HTTP/2 control frames"),
        (Some(expected), Some(actual)) => {
            let expected: Option<Vec<_>> = expected.iter().map(read_frame).collect();
            match expected {
                None => Some("expected HTTP/2 control frame has an unsupported type or invalid fields"),
                Some(expected) => compare(&expected, actual),
            }
        }
    };
    if let Some(message) = failure {
        out.push(Diagnostic::deny(
            "expect/h2_control_frames",
            &format!("{pointer}/h2_control_frames"),
            message,
        ));
    }
}

pub(super) fn check_socket_read_after(expect: &Value, observed: &Observation, pointer: &str, out: &mut Vec<Diagnostic>) {
    let Some(expected) = expect.read("expect.socket_read_after") else { return };
    let expected = expected.as_str();
    let actual = observed.socket_read_after.map(|state| state.as_str());
    if expected.is_none() || actual.is_none() || expected != actual {
        out.push(Diagnostic::deny(
            "expect/socket_read_after",
            &format!("{pointer}/socket_read_after"),
            "receive-side termination differs or was not measured within the observation window",
        ));
    }
}

/// Connection-level WINDOW_UPDATE grants are matched by presence and value, apart from the others:
/// RFC 9113 section 5.2.1 leaves when a receiver sends WINDOW_UPDATE, and what it grants, to the
/// implementation, so a grant's position among other frames, or an unasserted grant, is not a
/// protocol fact. Every other control frame keeps its exact count, order and fields.
fn compare(expected: &[ExpectedFrame], actual: &[ObservedH2ControlFrame]) -> Option<&'static str> {
    let (expected_grants, expected_ordered): (Vec<_>, Vec<_>) =
        expected.iter().partition(|frame| frame.connection_grant().is_some());
    let (actual_grants, actual_ordered): (Vec<_>, Vec<_>) = actual.iter().partition(|frame| grant_of(frame).is_some());
    if expected_ordered.len() != actual_ordered.len()
        || !expected_ordered
            .iter()
            .zip(&actual_ordered)
            .all(|(expected, actual)| expected.matches(actual))
    {
        return Some("received HTTP/2 control frames differ in count, order, or fields");
    }
    let mut unclaimed: Vec<u32> = actual_grants.into_iter().filter_map(grant_of).collect();
    for increment in expected_grants.iter().filter_map(|frame| frame.connection_grant()) {
        let Some(position) = unclaimed.iter().position(|received| *received == increment) else {
            return Some("an asserted connection-level WINDOW_UPDATE grant was not received");
        };
        unclaimed.swap_remove(position);
    }
    None
}

fn grant_of(frame: &ObservedH2ControlFrame) -> Option<u32> {
    match frame {
        ObservedH2ControlFrame::WindowUpdate { stream_id: 0, increment } => Some(*increment),
        _ => None,
    }
}

enum ExpectedFrame {
    Exact(ObservedH2ControlFrame),
    GoAwayCodes { last_stream_id: u32, codes: Vec<u32> },
}

impl ExpectedFrame {
    fn connection_grant(&self) -> Option<u32> {
        match self {
            Self::Exact(frame) => grant_of(frame),
            Self::GoAwayCodes { .. } => None,
        }
    }

    fn matches(&self, actual: &ObservedH2ControlFrame) -> bool {
        match (self, actual) {
            (Self::Exact(expected), actual) => expected == actual,
            (
                Self::GoAwayCodes { last_stream_id, codes },
                ObservedH2ControlFrame::GoAway {
                    last_stream_id: actual_id,
                    error_code,
                },
            ) => last_stream_id == actual_id && codes.contains(error_code),
            _ => false,
        }
    }
}

fn read_frame(frame: &Value) -> Option<ExpectedFrame> {
    let kind = frame.read("h2ControlFrame.type").and_then(Value::as_str);
    let stream_id = frame.read("h2ControlFrame.stream_id");
    let last_stream_id = frame.read("h2ControlFrame.last_stream_id");
    let exact_code = frame.read("h2ControlFrame.error_code");
    let error_code = exact_code.and_then(Value::as_integer);
    let alternatives = frame.read("h2ControlFrame.error_code_any_of");
    let increment = frame.read("h2ControlFrame.increment");
    let payload_hex = frame.read("h2ControlFrame.payload_hex");
    if payload_hex.is_some() && kind != Some("ping") {
        return None;
    }
    match kind? {
        "rst_stream" if last_stream_id.is_none() && increment.is_none() && alternatives.is_none() => {
            let error_code = u32::try_from(error_code?).ok()?;
            let stream_id = u32::try_from(stream_id?.as_integer()?)
                .ok()
                .filter(|id| (1..=0x7fff_ffff).contains(id))?;
            Some(ExpectedFrame::Exact(ObservedH2ControlFrame::ResetStream { stream_id, error_code }))
        }
        "goaway" if stream_id.is_none() && increment.is_none() => {
            let last_stream_id = u32::try_from(last_stream_id?.as_integer()?)
                .ok()
                .filter(|id| *id <= 0x7fff_ffff)?;
            if let Some(alternatives) = alternatives {
                if exact_code.is_some() {
                    return None;
                }
                let values = alternatives.as_array()?;
                if values.is_empty() {
                    return None;
                }
                let mut codes = Vec::with_capacity(values.len());
                for value in values {
                    let code = u32::try_from(value.as_integer()?).ok()?;
                    if codes.contains(&code) {
                        return None;
                    }
                    codes.push(code);
                }
                Some(ExpectedFrame::GoAwayCodes { last_stream_id, codes })
            } else {
                let error_code = u32::try_from(error_code?).ok()?;
                Some(ExpectedFrame::Exact(ObservedH2ControlFrame::GoAway {
                    last_stream_id,
                    error_code,
                }))
            }
        }
        "window_update" if last_stream_id.is_none() && exact_code.is_none() && alternatives.is_none() => {
            let stream_id = u32::try_from(stream_id?.as_integer()?).ok().filter(|id| *id <= 0x7fff_ffff)?;
            let increment = u32::try_from(increment?.as_integer()?)
                .ok()
                .filter(|value| (1..=0x7fff_ffff).contains(value))?;
            Some(ExpectedFrame::Exact(ObservedH2ControlFrame::WindowUpdate { stream_id, increment }))
        }
        "ping"
            if stream_id.is_none()
                && last_stream_id.is_none()
                && exact_code.is_none()
                && alternatives.is_none()
                && increment.is_none() =>
        {
            let opaque_data = <[u8; 8]>::try_from(super::decode_hex(payload_hex?.as_str()?)?).ok()?;
            Some(ExpectedFrame::Exact(ObservedH2ControlFrame::PingAck { opaque_data }))
        }
        _ => None,
    }
}

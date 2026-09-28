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

//! Automatic `Records` framing by `EventSequence::records`.
//!
//! Responsible for: a payload past the one-message ceiling becoming consecutive frames whose
//! payloads concatenate to the input, instead of a refusal; the phase check still refusing it
//! after the accounting, without output; and an empty call still writing one empty frame.
//! NOT responsible for: frame byte layout, which `event_stream_frame_replay` and the unit tests
//! pin; or the lazy `frame_records` adapter and its memory bound, which the facade tests own.
//! Upstream: `rustfs_gateway_core::ops::shared::event_stream`. Downstream: Cargo's harness.
//!
//! 1 positive / 2 negative.

use rustfs_gateway_core::ops::shared::event_stream::{EventSequence, EventStreamError, MAX_PAYLOAD_BYTES, stats_document};

use crate::event_stream_frame_replay::property;

type Frame = (Vec<(String, String)>, Vec<u8>);

fn header<'a>(frame: &'a Frame, name: &str) -> Option<&'a str> {
    frame.0.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

fn event_type(frame: &Frame) -> String {
    match header(frame, ":message-type") {
        Some("error") => format!("error:{}", header(frame, ":error-code").unwrap_or_default()),
        _ => header(frame, ":event-type").unwrap_or_default().to_owned(),
    }
}

/// Splits concatenated messages with the independent reader.
fn frames(mut stream: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    while !stream.is_empty() {
        let total = u32::from_be_bytes(stream[..4].try_into().expect("a prelude")) as usize;
        out.push(property::reference_frame(&stream[..total]).expect("a well-formed message"));
        stream = &stream[total..];
    }
    out
}

#[test]
fn records_past_the_ceiling_become_consecutive_frames() {
    let payload: Vec<u8> = (0..=MAX_PAYLOAD_BYTES).map(|at| (at % 251) as u8).collect();
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    let framed = sequence.records(&payload, &mut out);
    if framed.is_err() {
        // Terminate before asserting, so a refusal fails this test instead of aborting the harness.
        sequence.exception("InternalError", "refused", &mut out).expect("terminates");
    }
    assert_eq!(framed, Ok(()), "an oversized payload is framed, not refused");
    sequence.stats(&stats_document(0, 0, 0), &mut out).expect("accounting");
    sequence.end(&mut out).expect("terminator");
    let frames = frames(&out);
    let kinds: Vec<_> = frames.iter().map(event_type).collect();
    assert_eq!(kinds, ["Records", "Records", "Stats", "End"]);
    assert_eq!(frames[0].1.len(), MAX_PAYLOAD_BYTES);
    assert_eq!(frames[1].1.len(), 1);
    assert_eq!([frames[0].1.as_slice(), frames[1].1.as_slice()].concat(), payload);
}

#[test]
fn n_an_oversized_payload_after_the_accounting_is_refused_without_output() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    sequence.stats(&stats_document(0, 0, 0), &mut out).expect("accounting");
    let before = out.clone();
    let late = sequence.records(&vec![0_u8; MAX_PAYLOAD_BYTES + 1], &mut out);
    sequence.end(&mut out).expect("terminator");
    assert_eq!(late, Err(EventStreamError::OutOfOrder));
    assert_eq!(out[..before.len()], before[..]);
    assert_eq!(frames(&out[before.len()..]).iter().map(event_type).collect::<Vec<_>>(), ["End"]);
}

#[test]
fn n_an_empty_records_call_still_writes_one_empty_frame() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    sequence.records(&[], &mut out).expect("an empty chunk");
    sequence.stats(&stats_document(0, 0, 0), &mut out).expect("accounting");
    sequence.end(&mut out).expect("terminator");
    let frames = frames(&out);
    assert_eq!(frames.iter().map(event_type).collect::<Vec<_>>(), ["Records", "Stats", "End"]);
    assert!(frames[0].1.is_empty());
}

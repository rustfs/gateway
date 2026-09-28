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

//! Event-stream framing fuzz property shared by libFuzzer and the stable replay.
//!
//! Responsible for: decoding arbitrary bytes into a bounded script of framing calls, running it
//! against the production `event_stream` encoder and `EventSequence`, and holding every call to
//! an independent model: its own CRC-32, its own frame reader, its own header-limit arithmetic and
//! its own sequence state machine. Each call must append exactly the one frame the model predicts
//! (lengths, both CRC ranges, ordered string headers, byte-identical payload) after unchanged
//! earlier output, and each refusal must leave the output and the sequence state untouched.
//! NOT responsible for: HTTP delivery, or decoding a stream in production (S3 has no inbound one).
//! Upstream: libFuzzer bytes and `fuzz/seeds/event_stream_frame/`. Downstream:
//! `rustfs_gateway_core::ops::shared::event_stream`.
//!
//! Evidence: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTSelectObjectAppendix.html
//! A message is a prelude with total and header lengths, a CRC over those eight bytes, string
//! headers, the payload and a CRC over everything before it; an error message carries its code
//! and message as headers, no payload, and ends the stream.
//! https://smithy.io/2.0/aws/amazon-eventstream.html#message-format bounds a string value at
//! 65,535 bytes and the whole header block at 128 KiB.

use rustfs_gateway_core::ops::shared::event_stream::{
    EventKind, EventSequence, EventStreamError, encode_event, encode_exception,
};

/// One framing call.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Records(Vec<u8>),
    Progress(String),
    Cont,
    Stats(String),
    End,
    Exception(String, String),
    /// `encode_event` outside any sequence.
    RawEvent(EventKind, Vec<u8>),
    /// `encode_exception` outside any sequence.
    RawException(String, String),
}

/// What a script did, for the replay to pin.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    /// Frames appended by accepted calls, excluding the closing frame the property adds.
    pub frames: usize,
    /// Every refusal, in call order.
    pub refusals: Vec<EventStreamError>,
    /// Whether the script itself terminated the sequence.
    pub terminated: bool,
}

/// Runs arbitrary fuzz bytes.
pub(super) fn check(input: &[u8]) -> Summary {
    run(&decode(input))
}

/// The most calls one input may make, so a long input cannot turn into an unbounded run.
const MAX_OPS: usize = 64;

/// Characters a fill argument repeats: one, two, three and four UTF-8 bytes wide, so a limit
/// counted in characters instead of bytes is reachable.
const FILL: [char; 4] = ['a', '\u{e9}', '\u{20ac}', '\u{1f600}'];

/// The payload ceiling written down independently: 16 MiB less one KiB of header room.
const PAYLOAD_CEILING: usize = 16 * 1024 * 1024 - 1024;
/// A string header value's length field is a `u16`.
const VALUE_CEILING: usize = 65_535;
/// The complete encoded header block may not exceed 128 KiB.
const BLOCK_CEILING: usize = 128 * 1024;

/// Decodes the script.
///
/// Each call is one byte, `b % 8`: Records, Progress, Cont, Stats, End, Exception, a raw
/// `encode_event` (followed by a kind byte, `% 5`) and a raw `encode_exception`. An argument is a
/// length byte `m`: below `0x80` it is followed by `m` literal bytes (strings are read lossily, so
/// invalid UTF-8 becomes three-byte replacement characters); from `0x80` it repeats
/// `FILL[m & 3]` a big-endian `u16` number of times, plus 65,536 when `m & 4` is set.
pub(super) fn decode(input: &[u8]) -> Vec<Op> {
    let mut reader = Reader { input };
    let mut ops = Vec::new();
    while ops.len() < MAX_OPS {
        let Some(op) = reader.byte() else { break };
        ops.push(match op % 8 {
            0 => Op::Records(reader.bytes()),
            1 => Op::Progress(reader.string()),
            2 => Op::Cont,
            3 => Op::Stats(reader.string()),
            4 => Op::End,
            5 => Op::Exception(reader.string(), reader.string()),
            6 => {
                let kind = match reader.byte().unwrap_or(0) % 5 {
                    0 => EventKind::Records,
                    1 => EventKind::Stats,
                    2 => EventKind::Progress,
                    3 => EventKind::Cont,
                    _ => EventKind::End,
                };
                Op::RawEvent(kind, reader.bytes())
            }
            _ => Op::RawException(reader.string(), reader.string()),
        });
    }
    ops
}

struct Reader<'a> {
    input: &'a [u8],
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.input.split_first()?;
        self.input = rest;
        Some(first)
    }

    fn string(&mut self) -> String {
        match self.argument() {
            Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
            Err(filled) => filled,
        }
    }

    fn bytes(&mut self) -> Vec<u8> {
        match self.argument() {
            Ok(raw) => raw,
            Err(filled) => filled.into_bytes(),
        }
    }

    /// `Ok` for literal bytes, `Err` for a repeated character.
    fn argument(&mut self) -> Result<Vec<u8>, String> {
        let Some(mark) = self.byte() else { return Ok(Vec::new()) };
        if mark < 0x80 {
            let take = usize::from(mark).min(self.input.len());
            let (raw, rest) = self.input.split_at(take);
            self.input = rest;
            return Ok(raw.to_vec());
        }
        let high = usize::from(self.byte().unwrap_or(0));
        let low = usize::from(self.byte().unwrap_or(0));
        let count = (high << 8 | low) + if mark & 4 == 0 { 0 } else { 65_536 };
        Err(std::iter::repeat_n(FILL[usize::from(mark & 3)], count).collect())
    }
}

/// Where the model's sequence is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Scanning,
    Counted,
    Terminated,
}

/// The one frame a call must append: its string headers in order and its payload.
type Frame = (Vec<(String, String)>, Vec<u8>);

fn event_frame(kind: EventKind, payload: &[u8]) -> Result<Frame, EventStreamError> {
    if payload.len() > PAYLOAD_CEILING {
        return Err(EventStreamError::PayloadTooLarge);
    }
    let (name, content_type) = match kind {
        EventKind::Records => ("Records", Some("application/octet-stream")),
        EventKind::Stats => ("Stats", Some("text/xml")),
        EventKind::Progress => ("Progress", Some("text/xml")),
        EventKind::Cont => ("Cont", None),
        EventKind::End => ("End", None),
    };
    let mut headers = vec![pair(":message-type", "event"), pair(":event-type", name)];
    headers.extend(content_type.map(|value| pair(":content-type", value)));
    Ok((headers, payload.to_vec()))
}

fn error_frame(code: &str, message: &str) -> Result<Frame, EventStreamError> {
    let headers = vec![
        pair(":message-type", "error"),
        pair(":error-code", code),
        pair(":error-message", message),
    ];
    let block: usize = headers.iter().map(|(name, value)| 1 + name.len() + 1 + 2 + value.len()).sum();
    if headers.iter().any(|(_, value)| value.len() > VALUE_CEILING) || block > BLOCK_CEILING {
        return Err(EventStreamError::HeaderTooLarge);
    }
    Ok((headers, Vec::new()))
}

fn pair(name: &str, value: &str) -> (String, String) {
    (name.to_owned(), value.to_owned())
}

/// What the model says a call does: the refusal, or the frame and the phase after it.
fn predict(phase: Phase, op: &Op) -> Result<(Frame, Phase), EventStreamError> {
    let order = |allowed: bool| if allowed { Ok(()) } else { Err(EventStreamError::OutOfOrder) };
    match op {
        Op::Records(payload) => {
            order(phase == Phase::Scanning)?;
            Ok((event_frame(EventKind::Records, payload)?, phase))
        }
        Op::Progress(document) => {
            order(phase == Phase::Scanning)?;
            Ok((event_frame(EventKind::Progress, document.as_bytes())?, phase))
        }
        Op::Cont => {
            order(phase == Phase::Scanning)?;
            Ok((event_frame(EventKind::Cont, &[])?, phase))
        }
        Op::Stats(document) => {
            order(phase == Phase::Scanning)?;
            Ok((event_frame(EventKind::Stats, document.as_bytes())?, Phase::Counted))
        }
        Op::End => {
            order(phase == Phase::Counted)?;
            Ok((event_frame(EventKind::End, &[])?, Phase::Terminated))
        }
        Op::Exception(code, message) => {
            order(phase != Phase::Terminated)?;
            Ok((error_frame(code, message)?, Phase::Terminated))
        }
        Op::RawEvent(kind, payload) => Ok((event_frame(*kind, payload)?, phase)),
        Op::RawException(code, message) => Ok((error_frame(code, message)?, phase)),
    }
}

fn apply(sequence: &mut EventSequence, op: &Op, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
    match op {
        Op::Records(payload) => sequence.records(payload, out),
        Op::Progress(document) => sequence.progress(document, out),
        Op::Cont => sequence.cont(out),
        Op::Stats(document) => sequence.stats(document, out),
        Op::End => sequence.end(out),
        Op::Exception(code, message) => sequence.exception(code, message, out),
        Op::RawEvent(kind, payload) => encode_event(*kind, payload, out),
        Op::RawException(code, message) => encode_exception(code, message, out),
    }
}

/// Runs one call against production and the model, asserting that they agree byte for byte.
fn step(sequence: &mut EventSequence, phase: &mut Phase, op: &Op, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
    let before = out.clone();
    let actual = apply(sequence, op, out);
    match predict(*phase, op) {
        Err(expected) => {
            assert_eq!(actual, Err(expected), "production and model disagree on {op:?}");
            assert_eq!(*out, before, "a refused call changed the output");
        }
        Ok((frame, next)) => {
            assert_eq!(actual, Ok(()), "production refused what the model accepts: {op:?}");
            assert_eq!(out.get(..before.len()), Some(before.as_slice()), "earlier output was rewritten");
            let appended = out.get(before.len()..).unwrap_or_default();
            assert_eq!(reference_frame(appended), Ok(frame), "the appended frame is not the predicted one");
            *phase = next;
        }
    }
    assert_eq!(sequence.is_terminated(), *phase == Phase::Terminated, "sequence state diverged");
    actual
}

/// Runs a script, then closes a still-live sequence with a checked error frame so dropping it is
/// legal.
pub(super) fn run(ops: &[Op]) -> Summary {
    // Held without drop glue so a failed assertion unwinds as one panic rather than aborting on
    // the sequence's own unterminated-drop assertion; it is dropped explicitly once closed.
    let mut sequence = std::mem::ManuallyDrop::new(EventSequence::new());
    let mut phase = Phase::Scanning;
    let mut out = Vec::new();
    let mut summary = Summary::default();
    for op in ops {
        match step(&mut sequence, &mut phase, op, &mut out) {
            Ok(()) => summary.frames += 1,
            Err(refusal) => summary.refusals.push(refusal),
        }
    }
    summary.terminated = sequence.is_terminated();
    if !summary.terminated {
        let close = Op::Exception("InternalError".into(), "script ended".into());
        assert_eq!(step(&mut sequence, &mut phase, &close, &mut out), Ok(()));
    }
    drop(std::mem::ManuallyDrop::into_inner(sequence));
    summary
}

/// Independent bitwise CRC-32/ISO-HDLC (reflected polynomial `0xEDB88320`).
pub(super) fn reference_crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn be32(bytes: &[u8], at: usize) -> Result<usize, &'static str> {
    let word: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or("truncated")?
        .try_into()
        .map_err(|_| "truncated")?;
    Ok(u32::from_be_bytes(word) as usize)
}

/// Independent reader for exactly one message: lengths, both CRC ranges, string headers, payload.
pub(super) fn reference_frame(frame: &[u8]) -> Result<Frame, &'static str> {
    let total = be32(frame, 0)?;
    let headers_len = be32(frame, 4)?;
    if total != frame.len() {
        return Err("total length does not describe the frame");
    }
    let payload_start = 12 + headers_len;
    if payload_start + 4 > total {
        return Err("header length exceeds the frame");
    }
    if be32(frame, 8)? as u32 != reference_crc32(&frame[..8]) {
        return Err("prelude CRC does not cover the first eight bytes");
    }
    if be32(frame, total - 4)? as u32 != reference_crc32(&frame[..total - 4]) {
        return Err("message CRC does not cover everything before it");
    }
    let mut block = &frame[12..payload_start];
    let mut headers = Vec::new();
    while let Some((&name_len, rest)) = block.split_first() {
        let name_len = usize::from(name_len);
        let name = rest.get(..name_len).ok_or("header name overruns the block")?;
        let rest = rest.get(name_len..).ok_or("header name overruns the block")?;
        let (&kind, rest) = rest.split_first().ok_or("missing header type")?;
        if kind != 7 {
            return Err("header is not a string");
        }
        let value_len = usize::from(u16::from_be_bytes(
            rest.get(..2)
                .ok_or("missing value length")?
                .try_into()
                .map_err(|_| "missing value length")?,
        ));
        let value = rest.get(2..2 + value_len).ok_or("header value overruns the block")?;
        headers.push((
            String::from_utf8(name.to_vec()).map_err(|_| "header name is not UTF-8")?,
            String::from_utf8(value.to_vec()).map_err(|_| "header value is not UTF-8")?,
        ));
        block = &rest[2 + value_len..];
    }
    Ok((headers, frame[payload_start..total - 4].to_vec()))
}

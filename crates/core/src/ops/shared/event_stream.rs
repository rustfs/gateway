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

//! The `application/vnd.amazon.event-stream` framing, and the order the frames must arrive in.
//!
//! Responsible for: encoding one message — prelude, prelude CRC-32, header block, payload,
//! message CRC-32 — byte for byte; the header block's own `name / type / value` encoding; the
//! two documents a `Stats` and a `Progress` frame carry; and [`EventSequence`], which refuses an
//! order the protocol does not allow and refuses to be dropped without a terminator.
//! NOT responsible for: deciding *what* to send — no query is evaluated here and no record is
//! produced here; nor for putting the bytes on a socket, which the facade does for a
//! [`crate::Resp::event_stream`]; nor for **decoding** a stream, because S3 has no inbound one
//! and a parser with no traffic is an attack surface with no user.
//! Upstream: nothing but `rustfs-gateway-types`' CRC-32. Downstream: whichever assembly
//! eventually writes a select response, and the conformance suite, which reads frames back with
//! an implementation of its own.
//!
//! Shares: event_stream.
//! Members: SelectObjectContent
//!
//! # How framing reaches the response model
//!
//! An event stream is the third [`crate::Answer`] shape beside settled and committed output.
//! A backend frames messages here, wraps their [`rustfs_gateway_stream::ByteStream`] with
//! [`crate::Resp::event_stream`], and the facade writes the documented content type without
//! invoking an output-document encoder. The conformance target then reads the bytes back with its
//! own parser and CRC implementation.
//!
//! # Why the CRCs are the whole point
//!
//! Every message carries two CRC-32s over two *different* ranges. The prelude CRC covers the
//! first eight bytes and nothing else; the message CRC covers every byte of the message except
//! itself. A message whose lengths are right and whose CRC covers one byte too many is
//! structurally plausible, encodes and decodes perfectly against its own author's arithmetic,
//! and is rejected by every real SDK. That failure is invisible to any test that reads the frame
//! back with the encoder's own primitive, which is why the tests below assert **literal**
//! expected bytes, and why `crates/conformance` reads frames back with a CRC-32 of its own.
//!
//! The digest is CRC-32/ISO-HDLC — the one whose published check value over `123456789` is
//! `0xCBF43926` — reached through [`ChecksumAlgorithm::Crc32`], so this module has no arithmetic
//! of its own to get wrong.

use rustfs_gateway_types::ChecksumAlgorithm;

use crate::contracts::{
    EVENT_CRC_ALGORITHM, EVENT_MESSAGE_CRC_COVERAGE, EVENT_PRELUDE_CRC_COVERAGE, EventCrcAlgorithmPolicy,
    EventMessageCrcCoveragePolicy, EventPreludeCrcCoveragePolicy, SELECT_EVENT_MEDIA_TYPE, SELECT_EVENT_TERMINATION,
    SelectEventMediaTypePolicy, SelectEventTerminationPolicy,
};

/// The response content type a select answer is framed in.
pub const EVENT_STREAM_CONTENT_TYPE: &str = match SELECT_EVENT_MEDIA_TYPE {
    SelectEventMediaTypePolicy::ApplicationVndAmazonEventStream => "application/vnd.amazon.event-stream",
    SelectEventMediaTypePolicy::OctetStream => "application/octet-stream",
};

/// The largest payload one message may carry, in bytes.
///
/// AWS caps a whole message at 16 MiB. The headers of the payload-bearing event frames this
/// module writes are well under a kilobyte, so a kilobyte is subtracted rather than computed:
/// a producer that wants the exact remaining room should ask, and one that wants a chunk size should use a round
/// number far below the ceiling. A payload past this is refused rather than truncated — a
/// truncated record is a wrong answer, and a refused one is a bug report.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024 - 1024;

/// The fixed cost of a message: the eight prelude bytes, the prelude CRC, the message CRC.
const FRAME_OVERHEAD: usize = 4 + 4 + 4 + 4;

/// What went wrong while framing a message.
///
/// These are producer mistakes. Messages are constants and never repeat bytes from a header
/// or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventStreamError {
    /// A payload larger than [`MAX_PAYLOAD_BYTES`].
    ///
    /// The producer has to split the records itself: this module frames what it is given and
    /// never decides where a record boundary is, because only the producer knows.
    PayloadTooLarge,
    /// A header name exceeds 255 bytes, a string value exceeds 65,535 bytes, or all encoded
    /// headers exceed 128 KiB.
    HeaderTooLarge,
    /// An event that the sequence contract does not allow at this point.
    OutOfOrder,
}

impl EventStreamError {
    /// A constant sentence, never built from the message being framed.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "an event-stream payload exceeded the maximum message size",
            Self::HeaderTooLarge => "an event-stream header exceeded its wire length limit",
            Self::OutOfOrder => "an event-stream message was produced out of sequence",
        }
    }
}

impl core::fmt::Display for EventStreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for EventStreamError {}

/// The five event types a select response is made of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A chunk of result bytes, in the requested output serialization.
    Records,
    /// The final accounting, sent exactly once before the terminator.
    Stats,
    /// An interim accounting, sent only when the request asked for progress.
    Progress,
    /// A keep-alive carrying no payload, so a long scan does not look like a stalled connection.
    Cont,
    /// The terminator. Exactly one, and the stream is not complete without it.
    End,
}

impl EventKind {
    /// The `:event-type` header value.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Records => "Records",
            Self::Stats => "Stats",
            Self::Progress => "Progress",
            Self::Cont => "Cont",
            Self::End => "End",
        }
    }

    /// The `:content-type` header value, when the event carries one.
    ///
    /// `Records` carries opaque bytes in whatever serialization the request asked for, so it is
    /// `application/octet-stream`; `Stats` and `Progress` carry a small XML document. `Cont` and
    /// `End` carry no payload and therefore no content type — writing one would describe a body
    /// that is not there.
    #[must_use]
    pub const fn content_type(self) -> Option<&'static str> {
        match self {
            Self::Records => Some("application/octet-stream"),
            Self::Stats | Self::Progress => Some("text/xml"),
            Self::Cont | Self::End => None,
        }
    }
}

/// Appends one event message to `out`.
///
/// # Errors
///
/// [`EventStreamError::PayloadTooLarge`] when `payload` is longer than [`MAX_PAYLOAD_BYTES`].
/// The producer splits; this function never truncates.
pub fn encode_event(kind: EventKind, payload: &[u8], out: &mut Vec<u8>) -> Result<(), EventStreamError> {
    let mut headers = Vec::new();
    push_string_header(&mut headers, ":message-type", "event")?;
    push_string_header(&mut headers, ":event-type", kind.event_type())?;
    if let Some(content_type) = kind.content_type() {
        push_string_header(&mut headers, ":content-type", content_type)?;
    }
    encode_message(&headers, payload, out)
}

/// Appends one S3 Select request-level error message to `out`.
///
/// This is the shape an error takes once the status line has already gone out as `200`: the
/// failure is a frame, not a status. A stream that simply stops instead hangs the client — the
/// failure upstream shipped twice — so a producer that gives up owes this message and then an
/// [`EventKind::End`] is *not* sent, because the error is itself terminal.
/// The code and message occupy `:error-code` and `:error-message` string headers; the frame
/// carries no payload.
/// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTSelectObjectAppendix.html
///
/// # Errors
///
/// [`EventStreamError::HeaderTooLarge`] when either string exceeds 65,535 UTF-8 bytes or the
/// complete encoded header block exceeds 128 KiB.
/// A refused frame leaves `out` unchanged.
pub fn encode_exception(code: &str, message: &str, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
    let mut headers = Vec::new();
    push_string_header(&mut headers, ":message-type", "error")?;
    push_string_header(&mut headers, ":error-code", code)?;
    push_string_header(&mut headers, ":error-message", message)?;
    encode_message(&headers, &[], out)
}

/// The `<Stats>` document a [`EventKind::Stats`] frame carries.
#[must_use]
pub fn stats_document(bytes_scanned: u64, bytes_processed: u64, bytes_returned: u64) -> String {
    accounting_document("Stats", bytes_scanned, bytes_processed, bytes_returned)
}

/// The `<Progress>` document a [`EventKind::Progress`] frame carries.
#[must_use]
pub fn progress_document(bytes_scanned: u64, bytes_processed: u64, bytes_returned: u64) -> String {
    accounting_document("Progress", bytes_scanned, bytes_processed, bytes_returned)
}

/// The one renderer behind both accounting documents, which have the same three counters.
fn accounting_document(root: &str, scanned: u64, processed: u64, returned: u64) -> String {
    format!(
        "<{root}><Details><BytesScanned>{scanned}</BytesScanned>\
         <BytesProcessed>{processed}</BytesProcessed>\
         <BytesReturned>{returned}</BytesReturned></Details></{root}>"
    )
}

/// Writes `name: value` as one header of the block, in the `7` (string) value type.
///
/// Every header this protocol needs is a string, so the other fifteen value types have no
/// encoder here: an encoder with no caller is a branch nothing checks.
fn push_string_header(headers: &mut Vec<u8>, name: &str, value: &str) -> Result<(), EventStreamError> {
    let name_len = u8::try_from(name.len()).map_err(|_| EventStreamError::HeaderTooLarge)?;
    let value_len = u16::try_from(value.len()).map_err(|_| EventStreamError::HeaderTooLarge)?;
    headers.push(name_len);
    headers.extend_from_slice(name.as_bytes());
    headers.push(7);
    headers.extend_from_slice(&value_len.to_be_bytes());
    headers.extend_from_slice(value.as_bytes());
    Ok(())
}

/// The one place a message is assembled, so the two CRC ranges are written down once.
fn encode_message(headers: &[u8], payload: &[u8], out: &mut Vec<u8>) -> Result<(), EventStreamError> {
    // Services must limit the complete encoded header block as well as each string value.
    // https://smithy.io/2.0/aws/amazon-eventstream.html#message-format
    if headers.len() > 128 * 1024 {
        return Err(EventStreamError::HeaderTooLarge);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(EventStreamError::PayloadTooLarge);
    }
    let total = FRAME_OVERHEAD
        .checked_add(headers.len())
        .and_then(|sum| sum.checked_add(payload.len()))
        .and_then(|sum| u32::try_from(sum).ok())
        .ok_or(EventStreamError::PayloadTooLarge)?;
    let headers_len = u32::try_from(headers.len()).map_err(|_| EventStreamError::PayloadTooLarge)?;

    let start = out.len();
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&headers_len.to_be_bytes());
    // The prelude CRC covers the eight bytes just written and nothing else. Widening it by one
    // byte produces a stream that this module would happily read back and no SDK accepts.
    let prelude_crc = match EVENT_PRELUDE_CRC_COVERAGE {
        EventPreludeCrcCoveragePolicy::First8 => crc32(out.get(start..).unwrap_or_default()),
        EventPreludeCrcCoveragePolicy::First12 => {
            let mut wrong = out.get(start..).unwrap_or_default().to_vec();
            wrong.extend_from_slice(&[0; 4]);
            crc32(&wrong)
        }
    };
    out.extend_from_slice(&prelude_crc.to_be_bytes());
    out.extend_from_slice(headers);
    out.extend_from_slice(payload);
    // The message CRC covers everything from the first prelude byte up to but excluding itself,
    // which includes the prelude CRC.
    let message_crc = match EVENT_MESSAGE_CRC_COVERAGE {
        EventMessageCrcCoveragePolicy::FrameWithoutCrc => crc32(out.get(start..).unwrap_or_default()),
        EventMessageCrcCoveragePolicy::PayloadOnly => crc32(payload),
    };
    out.extend_from_slice(&message_crc.to_be_bytes());
    Ok(())
}

/// CRC-32/ISO-HDLC of `data`, as a number.
///
/// Reached through the types crate's checksum surface rather than reimplemented, so there is one
/// implementation of this polynomial in the workspace and it is the one with the published check
/// vector behind it.
fn crc32(data: &[u8]) -> u32 {
    let algorithm = match EVENT_CRC_ALGORITHM {
        EventCrcAlgorithmPolicy::Crc32IsoHdlc => ChecksumAlgorithm::Crc32,
        EventCrcAlgorithmPolicy::Crc32c => ChecksumAlgorithm::Crc32c,
    };
    let mut digest = algorithm.checksummer();
    digest.update(data);
    let bytes = digest.finalize();
    let mut wide = [0_u8; 4];
    // A CRC-32 digest is four bytes by construction; a shorter one would leave leading zeros,
    // which is a wrong answer rather than a panic.
    let take = bytes.len().min(4);
    wide.get_mut(4 - take..)
        .unwrap_or_default()
        .copy_from_slice(bytes.get(..take).unwrap_or_default());
    u32::from_be_bytes(wide)
}

/// Where a stream is in the order the protocol fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Records, progress and keep-alives are all still allowed.
    Scanning,
    /// The accounting has been sent; only the terminator is left.
    Counted,
    /// The stream is complete, by an `End` or by an exception.
    Terminated,
}

/// The order a select response's frames must be written in, made unrepresentable to get wrong.
///
/// `Records*`, with `Progress` and `Cont` interleaved freely, then exactly one `Stats`, then
/// exactly one `End` — or, at any point, one exception, which terminates instead. Every method
/// refuses a message the phase does not allow, so a producer cannot send two terminators, send
/// records after the accounting, or finish without one.
///
/// Dropping one that has not terminated is a producer bug and a debug assertion catches it. It
/// is deliberately not a release-mode panic: a half-written stream already hangs the client, and
/// aborting the process is not an improvement for the other connections.
#[derive(Debug)]
#[must_use = "a sequence that is never terminated is a stream that hangs its client"]
pub struct EventSequence {
    phase: Phase,
}

impl Default for EventSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSequence {
    /// Opens a sequence at the scanning phase.
    pub const fn new() -> Self {
        Self { phase: Phase::Scanning }
    }

    /// Whether the stream has been terminated, by an `End` or by an exception.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        matches!(self.phase, Phase::Terminated)
    }

    /// Appends a `Records` frame.
    ///
    /// # Errors
    ///
    /// [`EventStreamError::OutOfOrder`] once the accounting has been sent, and
    /// [`EventStreamError::PayloadTooLarge`] for a chunk past [`MAX_PAYLOAD_BYTES`].
    pub fn records(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        self.scanning_event(EventKind::Records, payload, out)
    }

    /// Appends a `Progress` frame.
    ///
    /// # Errors
    ///
    /// As [`EventSequence::records`].
    pub fn progress(&mut self, document: &str, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        self.scanning_event(EventKind::Progress, document.as_bytes(), out)
    }

    /// Appends a `Cont` keep-alive.
    ///
    /// # Errors
    ///
    /// As [`EventSequence::records`].
    pub fn cont(&mut self, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        self.scanning_event(EventKind::Cont, &[], out)
    }

    /// Appends the single `Stats` frame.
    ///
    /// # Errors
    ///
    /// [`EventStreamError::OutOfOrder`] for a second accounting or one after the terminator.
    pub fn stats(&mut self, document: &str, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        if self.phase != Phase::Scanning {
            return Err(EventStreamError::OutOfOrder);
        }
        encode_event(EventKind::Stats, document.as_bytes(), out)?;
        self.phase = Phase::Counted;
        Ok(())
    }

    /// Appends the terminator.
    ///
    /// The accounting has to have gone first: a stream that ends without one leaves the client
    /// no total, which is the difference between "no rows matched" and "the scan stopped early".
    ///
    /// # Errors
    ///
    /// [`EventStreamError::OutOfOrder`] before the accounting, or after the stream has already
    /// ended.
    pub fn end(&mut self, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        if self.phase != Phase::Counted {
            return Err(EventStreamError::OutOfOrder);
        }
        if matches!(SELECT_EVENT_TERMINATION, SelectEventTerminationPolicy::RecordsStatsEnd) {
            encode_event(EventKind::End, &[], out)?;
        }
        self.phase = Phase::Terminated;
        Ok(())
    }

    /// Appends an in-band S3 Select error and terminates.
    ///
    /// Allowed from either live phase, because a failure can happen after the accounting and
    /// before the terminator, and the client still has to be told rather than left waiting.
    ///
    /// # Errors
    ///
    /// [`EventStreamError::OutOfOrder`] once the stream has already ended, or
    /// [`EventStreamError::HeaderTooLarge`] when either string exceeds 65,535 UTF-8 bytes or the
    /// complete encoded header block exceeds 128 KiB.
    /// A refused error frame leaves the sequence live and its output unchanged.
    pub fn exception(&mut self, code: &str, message: &str, out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        if self.phase == Phase::Terminated {
            return Err(EventStreamError::OutOfOrder);
        }
        encode_exception(code, message, out)?;
        self.phase = Phase::Terminated;
        Ok(())
    }

    /// The three events that are only legal while the scan is still running.
    fn scanning_event(&mut self, kind: EventKind, payload: &[u8], out: &mut Vec<u8>) -> Result<(), EventStreamError> {
        if self.phase != Phase::Scanning {
            return Err(EventStreamError::OutOfOrder);
        }
        encode_event(kind, payload, out)
    }
}

impl Drop for EventSequence {
    fn drop(&mut self) {
        debug_assert!(
            self.is_terminated(),
            "an event sequence was dropped without an End or an exception, which hangs the client"
        );
    }
}

#[cfg(test)]
// Test code is exempt from the no-expect and no-indexing rules; the allowance mirrors
// `encryption`'s test module. Indexing is deliberate here: a frame literal that is the wrong
// length must panic loudly in a test rather than silently compare a shorter slice.
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests;

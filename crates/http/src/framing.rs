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

//! Where the body ends, decided once, from HTTP's own framing headers.
//!
//! Responsible for: rules W-1 to W-6 — refusing `Content-Length` together with
//! `Transfer-Encoding`, refusing a malformed or repeated `Transfer-Encoding`, refusing any
//! transfer coding on HTTP/2, refusing a repeated or malformed `Content-Length`, and validating a
//! chunk-size line.
//! NOT responsible for: `aws-chunked`, the application-layer framing S3 layers *inside* the body.
//! That is selected by `PayloadMode` in `rustfs-gateway-sig` and decoded in P3-03; `Content-Encoding` is
//! never read here, and no function in this module takes it.
//! Upstream: `http`, and this crate's `limits` and `reject`. Downstream: `wire`, and the ingest
//! pipeline that reads the body.
//!
//! # Why every ambiguity is fatal
//!
//! Application-layer request smuggling is one disagreement: the front end decides the body ends
//! in one place, the back end decides it ends in another, and the bytes in between become a
//! second request that nobody authenticated. RFC 9112 §6.1 requires a server receiving both
//! `Transfer-Encoding` and `Content-Length` to answer `400` and close the connection; RFC 9110
//! §8.6 calls a message with inconsistent `Content-Length` values malformed. This module goes one
//! step further and refuses two *identical* `Content-Length` headers as well, because the
//! tolerant case is what an attacker uses to discover which end of the chain wins.

use http::{HeaderMap, Version, header::CONTENT_LENGTH, header::TRANSFER_ENCODING};

use crate::limits::{LimitKind, Limits};
use crate::reject::WireReject;

/// The longest chunk-size line accepted, including its terminating CRLF.
///
/// A chunk size needs sixteen hex digits at the very most. The remaining budget covers chunk
/// extensions; anything beyond it is a parser-differential probe — a thousand leading zeros is
/// the same number to one implementation and an overflow or a truncation to another.
pub const MAX_CHUNK_SIZE_LINE_BYTES: usize = 256;

/// The largest number of hex digits a chunk size may carry.
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

/// Where the body ends, according to HTTP.
///
/// Not `Option<u64>`: "no body" and "a body whose end is signalled by a terminal chunk" are
/// different facts, and a reader that cannot tell them apart either waits for bytes that will
/// never come or stops before the ones that will.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyLength {
    /// No framing header, so no body.
    Empty,
    /// `Content-Length` announced exactly this many bytes.
    Exact(u64),
    /// `Transfer-Encoding: chunked`; the length is known only once the terminal chunk arrives.
    Chunked,
}

/// The framing decision for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framing {
    length: BodyLength,
}

impl Framing {
    /// Where the body ends.
    #[must_use]
    pub fn length(&self) -> BodyLength {
        self.length
    }

    /// The announced body length, when `Content-Length` gave one.
    ///
    /// `None` under chunked framing is a fact, not a missing value: asking a chunked request how
    /// long it is has no answer until it has finished arriving.
    #[must_use]
    pub fn declared_length(&self) -> Option<u64> {
        match self.length {
            BodyLength::Empty => Some(0),
            BodyLength::Exact(length) => Some(length),
            BodyLength::Chunked => None,
        }
    }

    /// Whether HTTP itself frames this body in chunks.
    ///
    /// This is about `Transfer-Encoding` only. Whether the *payload* is `aws-chunked` framed is a
    /// different question with a different answer, asked of `PayloadMode::is_framed` in
    /// `rustfs-gateway-sig`; the two are deliberately not the same predicate, and a request can be either
    /// one without being the other.
    #[must_use]
    pub fn is_transfer_chunked(&self) -> bool {
        matches!(self.length, BodyLength::Chunked)
    }

    /// Whether a body is expected at all.
    #[must_use]
    pub fn has_body(&self) -> bool {
        !matches!(self.length, BodyLength::Empty | BodyLength::Exact(0))
    }

    /// Applies rules W-1 to W-5 and returns the framing decision.
    ///
    /// # Errors
    ///
    /// * [`WireReject::ContentLengthTransferEncodingConflict`] — both framing headers present
    ///   (W-1).
    /// * [`WireReject::TransferEncodingMalformed`] — repeated, or any coding other than a single
    ///   `chunked` (W-2). `identity` is included: it is not a transfer coding a request may use,
    ///   and implementations disagree about whether it means "chunked" or "nothing".
    /// * [`WireReject::TransferEncodingOnHttp2`] — any transfer coding on HTTP/2 or later, which
    ///   RFC 9113 §8.2.2 forbids (W-3).
    /// * [`WireReject::DuplicateContentLength`] — the header appeared twice, equal values
    ///   included (W-4).
    /// * [`WireReject::MalformedContentLength`] — not a bare run of ASCII digits (W-5).
    /// * [`WireReject::LimitExceeded`] — the declared length exceeds [`Limits::max_body_bytes`].
    ///   The caller must close without reading the body.
    pub fn classify(version: Version, headers: &HeaderMap, limits: &Limits) -> Result<Self, WireReject> {
        classify(version, headers, limits)
    }
}

/// The body of [`Framing::classify`], kept free-standing so the crate can call it internally.
fn classify(version: Version, headers: &HeaderMap, limits: &Limits) -> Result<Framing, WireReject> {
    let mut transfer_encodings = headers.get_all(TRANSFER_ENCODING).iter();
    let first_te = transfer_encodings.next();
    let repeated_te = transfer_encodings.next().is_some();

    let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
    let first_cl = content_lengths.next();
    let repeated_cl = content_lengths.next().is_some();

    // W-1 first, and before any parsing: the conflicting pair is the smuggling primitive, and the
    // reason for the rejection should not depend on which of the two happens to also be malformed.
    if first_te.is_some() && first_cl.is_some() {
        return Err(WireReject::ContentLengthTransferEncodingConflict);
    }

    if let Some(value) = first_te {
        // W-3. HTTP/2 and HTTP/3 have their own framing; a transfer coding riding along with it
        // is a message meant for an HTTP/1.1 parser somewhere behind us.
        if version != Version::HTTP_10 && version != Version::HTTP_11 && version != Version::HTTP_09 {
            return Err(WireReject::TransferEncodingOnHttp2);
        }
        if repeated_te {
            return Err(WireReject::TransferEncodingMalformed);
        }
        // W-2. Exactly one coding, and it must be `chunked`. A list such as `chunked, gzip` puts
        // chunked somewhere other than last, and `gzip, chunked` asks this gateway to apply a
        // content coding it does not implement — accepting either would mean guessing where the
        // body ends.
        if !value.as_bytes().eq_ignore_ascii_case(b"chunked") {
            return Err(WireReject::TransferEncodingMalformed);
        }
        return Ok(Framing {
            length: BodyLength::Chunked,
        });
    }

    if let Some(value) = first_cl {
        // W-4.
        if repeated_cl {
            return Err(WireReject::DuplicateContentLength);
        }
        let length = parse_content_length(value.as_bytes())?;
        if length > limits.max_body_bytes {
            return Err(WireReject::LimitExceeded(LimitKind::BodyBytes));
        }
        return Ok(Framing {
            length: BodyLength::Exact(length),
        });
    }

    Ok(Framing {
        length: BodyLength::Empty,
    })
}

/// Parses a `Content-Length` value under W-5.
///
/// Only a non-empty run of ASCII digits is accepted. A leading `+`, a leading `-`, surrounding
/// whitespace, a `0x` prefix and an embedded comma are all refused: every one of them is accepted
/// by *some* HTTP implementation and refused by others, which is the definition of a framing
/// ambiguity. No cast is involved — an overflow is a rejection, not a wrap.
fn parse_content_length(bytes: &[u8]) -> Result<u64, WireReject> {
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(WireReject::MalformedContentLength);
    }
    let mut length: u64 = 0;
    for byte in bytes {
        let digit = u64::from(byte.wrapping_sub(b'0'));
        length = length
            .checked_mul(10)
            .and_then(|acc| acc.checked_add(digit))
            .ok_or(WireReject::MalformedContentLength)?;
    }
    Ok(length)
}

/// Validates one chunk-size line and returns the size it announces (rule W-6).
///
/// The input is the line *including* its terminating CRLF, exactly as it sits in the read buffer.
/// The rules: the line ends with CRLF and contains no other CR or LF, so a bare `\n` cannot end a
/// line here even though several parsers accept one; the size is one to sixteen hexadecimal
/// digits with no sign, no whitespace and no `0x`; a chunk extension may follow a `;` and must be
/// visible ASCII; and the whole line fits in [`MAX_CHUNK_SIZE_LINE_BYTES`].
///
/// This layer does not itself dechunk an HTTP/1.1 body — the transport does. The function exists
/// so that the rule has one implementation: the transport's framing error maps onto
/// [`WireReject::MalformedChunkFraming`], which is a `400` and never a `500`, and P3-03's
/// `aws-chunked` decoder validates its own size lines against the same predicate rather than a
/// second, slightly different one.
///
/// # Errors
///
/// * [`WireReject::LimitExceeded`] with [`LimitKind::ChunkSizeLine`] — the line is too long.
/// * [`WireReject::MalformedChunkFraming`] — anything else above.
pub fn validate_chunk_size_line(line: &[u8]) -> Result<u64, WireReject> {
    if line.len() > MAX_CHUNK_SIZE_LINE_BYTES {
        return Err(WireReject::LimitExceeded(LimitKind::ChunkSizeLine));
    }
    let body = match line {
        [rest @ .., b'\r', b'\n'] => rest,
        _ => return Err(WireReject::MalformedChunkFraming),
    };
    if body.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(WireReject::MalformedChunkFraming);
    }

    let (digits, extension) = match body.iter().position(|byte| *byte == b';') {
        Some(at) => {
            let digits = body.get(..at).ok_or(WireReject::MalformedChunkFraming)?;
            let extension = body.get(at.saturating_add(1)..).ok_or(WireReject::MalformedChunkFraming)?;
            (digits, Some(extension))
        }
        None => (body, None),
    };

    if digits.is_empty() || digits.len() > MAX_CHUNK_SIZE_DIGITS || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(WireReject::MalformedChunkFraming);
    }
    if let Some(extension) = extension
        && !extension.iter().all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return Err(WireReject::MalformedChunkFraming);
    }

    let mut size: u64 = 0;
    for byte in digits {
        let digit = hex_value(*byte).ok_or(WireReject::MalformedChunkFraming)?;
        size = size
            .checked_mul(16)
            .and_then(|acc| acc.checked_add(u64::from(digit)))
            .ok_or(WireReject::MalformedChunkFraming)?;
    }
    Ok(size)
}

/// The numeric value of one hexadecimal digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

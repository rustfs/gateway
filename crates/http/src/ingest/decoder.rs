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

//! The `aws-chunked` state machine, working in place on the buffer the socket wrote into.
//!
//! Responsible for: chunk-size lines, the single permitted chunk extension, the CRLF rules, every
//! ceiling that is decidable from a chunk header, and the running decoded-byte count that is the
//! only length any consumer is allowed to believe.
//! NOT responsible for: reading from a socket, owning a buffer, verifying a signature, hashing,
//! or a trailer section. It is handed a slice and a cursor and it returns events; the pipeline
//! owns the buffer and the i/o.
//! Upstream: this crate's `limits` and the ingest `reject`. Downstream: `pipeline`.
//!
//! # Why the decoder never copies the body
//!
//! Every event this module produces is a `(start, len)` pair into the caller's buffer. Chunk
//! headers are skipped by moving the cursor, not by moving the bytes, so the number of bytes this
//! module memmoves for a 64 KiB chunk is zero; the pipeline's only move is the compaction of the
//! partial header left at the end of a buffer, which is at most one metadata line.
//!
//! # Every rule here is a rule two parsers could otherwise disagree about
//!
//! A leading `+`, a `0x` prefix, a thousand leading zeros, a bare `\n`, a second chunk extension,
//! a quoted extension value, whitespace around the size: each is accepted by some HTTP
//! implementation and refused by others. A gateway that is tolerant where its neighbour is strict
//! is a gateway whose body boundary can be made to differ from its neighbour's, and the bytes
//! between the two boundaries are a request nobody authenticated.

use crate::ingest::reject::ChunkReject;
use crate::ingest::signer::parse_chunk_signature;
use crate::limits::ChunkLimits;

/// The shortest a chunk-size line can be: one hex digit and a CRLF.
pub const MIN_CHUNK_META_BYTES: usize = 3;

/// The largest number of hexadecimal digits a chunk size may carry.
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

/// The one chunk extension signed framing permits.
const CHUNK_SIGNATURE_PREFIX: &[u8] = b"chunk-signature=";

/// What the decoder wants next, or what it has just produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeEvent {
    /// The buffer holds no complete unit; the caller must read more bytes.
    NeedMore,
    /// A run of body bytes at `start`, `len` long, inside the buffer the caller passed.
    ///
    /// The bytes have been decoded but *not* verified: under
    /// [`IngestPolicy::VerifyBeforeDeliver`] the pipeline holds them until the chunk's signature
    /// verifies.
    ///
    /// [`IngestPolicy::VerifyBeforeDeliver`]: crate::IngestPolicy::VerifyBeforeDeliver
    Data {
        /// Offset into the caller's buffer.
        start: usize,
        /// Length of the run.
        len: usize,
    },
    /// A chunk has ended; its signature, when the mode has one, is ready to be verified.
    ChunkEnd {
        /// The signature announced in this chunk's extension, for signed framing.
        signature: Option<[u8; 32]>,
        /// Whether this was the terminal, zero-sized chunk.
        terminal: bool,
    },
    /// The terminal chunk and its closing CRLF have both been consumed.
    Done,
}

/// Where in an `aws-chunked` body the decoder currently is.
#[derive(Debug)]
enum State {
    /// Reading a chunk-size line.
    Meta,
    /// Reading chunk data.
    Data { remaining: u64, signature: Option<[u8; 32]> },
    /// Reading the CRLF that closes a chunk's data.
    DataCrlf { signature: Option<[u8; 32]>, terminal: bool },
    /// The terminal chunk has been consumed.
    Done,
}

/// The `aws-chunked` framing state machine.
#[derive(Debug)]
pub(crate) struct ChunkDecoder {
    state: State,
    cursor: usize,
    signed: bool,
    declared: u64,
    decoded_bytes: u64,
    overhead_bytes: u64,
    chunk_count: u64,
    max_chunk_count: u64,
    limits: ChunkLimits,
}

impl ChunkDecoder {
    /// Builds a decoder for a body that declared `declared` decoded bytes.
    pub(crate) fn new(signed: bool, declared: u64, limits: ChunkLimits) -> Self {
        Self {
            state: State::Meta,
            cursor: 0,
            signed,
            declared,
            decoded_bytes: 0,
            overhead_bytes: 0,
            chunk_count: 0,
            max_chunk_count: limits.max_chunk_count(declared),
            limits,
        }
    }

    /// How many body bytes have been decoded.
    pub(crate) fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }

    /// How many bytes of framing overhead have been consumed.
    pub(crate) fn overhead_bytes(&self) -> u64 {
        self.overhead_bytes
    }

    /// The parse position inside the caller's buffer.
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    /// Moves the parse position back by `shift`, after the caller has compacted its buffer.
    pub(crate) fn rebase(&mut self, shift: usize) {
        self.cursor = self.cursor.saturating_sub(shift);
    }

    /// Advances the state machine over `input`, which starts at buffer offset zero.
    ///
    /// # Errors
    ///
    /// Any [`ChunkReject`] the framing rules produce. Every one of them is fatal: the caller must
    /// not resume the decoder afterwards.
    pub(crate) fn step(&mut self, input: &[u8]) -> Result<DecodeEvent, ChunkReject> {
        match self.state {
            State::Done => Ok(DecodeEvent::Done),
            State::Meta => self.step_meta(input),
            State::Data { remaining, signature } => Ok(self.step_data(input, remaining, signature)),
            State::DataCrlf { signature, terminal } => self.step_data_crlf(input, signature, terminal),
        }
    }

    /// Reads and validates one chunk-size line.
    fn step_meta(&mut self, input: &[u8]) -> Result<DecodeEvent, ChunkReject> {
        let rest = input.get(self.cursor..).unwrap_or(&[]);
        let ceiling = usize::from(self.limits.max_chunk_meta_size());
        let Some((line_len, consumed)) = find_line(rest, ceiling)? else {
            return Ok(DecodeEvent::NeedMore);
        };
        let line = rest.get(..line_len).ok_or(ChunkReject::MalformedChunkSize)?;

        let (size, signature) = self.parse_meta_line(line)?;

        self.chunk_count = self.chunk_count.saturating_add(1);
        if self.chunk_count > self.max_chunk_count {
            return Err(ChunkReject::TooManyChunks {
                max: self.max_chunk_count,
            });
        }
        self.overhead_bytes = self.overhead_bytes.saturating_add(consumed as u64);
        self.check_overhead_ratio()?;

        self.cursor = self.cursor.saturating_add(consumed);

        if size == 0 {
            // The terminal chunk is the only place a zero size is legal, and it is only the
            // terminal chunk if the declared body has actually arrived. Checking the length here
            // rather than at end-of-stream is what stops a short upload being committed whole.
            if self.decoded_bytes < self.declared {
                return Err(ChunkReject::DecodedLengthUnderflow {
                    declared: self.declared,
                    actual: self.decoded_bytes,
                });
            }
            self.state = State::DataCrlf {
                signature,
                terminal: true,
            };
            return self.step(input);
        }

        // Refused at the header: not one byte of an over-large chunk is read, and the buffer
        // never grows to hold it. This is the ceiling whose absence is a remote memory-exhaustion
        // primitive, because the chunk's signature only arrives after its data.
        if size > u64::from(self.limits.max_chunk_size()) {
            return Err(ChunkReject::ChunkSizeTooLarge {
                declared: size,
                max: self.limits.max_chunk_size(),
            });
        }
        if self.decoded_bytes.saturating_add(size) > self.declared {
            return Err(ChunkReject::DecodedLengthOverflow { declared: self.declared });
        }

        self.state = State::Data {
            remaining: size,
            signature,
        };
        self.step(input)
    }

    /// Splits a chunk-size line into its size and its single permitted extension.
    fn parse_meta_line(&self, line: &[u8]) -> Result<(u64, Option<[u8; 32]>), ChunkReject> {
        let (digits, extension) = match line.iter().position(|byte| *byte == b';') {
            Some(at) => {
                let digits = line.get(..at).ok_or(ChunkReject::MalformedChunkSize)?;
                let extension = line.get(at.saturating_add(1)..).ok_or(ChunkReject::UnexpectedExtension)?;
                (digits, Some(extension))
            }
            None => (line, None),
        };

        let size = parse_chunk_size(digits)?;
        let signature = self.parse_extension(extension)?;
        Ok((size, signature))
    }

    /// Applies the extension whitelist for the framing mode.
    fn parse_extension(&self, extension: Option<&[u8]>) -> Result<Option<[u8; 32]>, ChunkReject> {
        match (self.signed, extension) {
            // Signed framing: exactly one extension, exactly this name, exactly 64 lowercase hex.
            // A second extension, a quoted value or uppercase hex is refused rather than
            // tolerated: a chunk extension one party parses and another ignores is the desync
            // primitive behind chunk-extension request smuggling.
            (true, Some(extension)) => {
                if extension.contains(&b';') {
                    return Err(ChunkReject::UnexpectedExtension);
                }
                let value = extension
                    .strip_prefix(CHUNK_SIGNATURE_PREFIX)
                    .ok_or(ChunkReject::UnexpectedExtension)?;
                parse_chunk_signature(value).map(Some).ok_or(ChunkReject::UnexpectedExtension)
            }
            (true, None) => Err(ChunkReject::UnexpectedExtension),
            (false, None) => Ok(None),
            // Unsigned framing has no signature to carry, so it has no legal extension at all.
            (false, Some(_)) => Err(ChunkReject::UnexpectedExtension),
        }
    }

    /// Hands out as much chunk data as the buffer currently holds.
    fn step_data(&mut self, input: &[u8], remaining: u64, signature: Option<[u8; 32]>) -> DecodeEvent {
        let available = input.len().saturating_sub(self.cursor);
        if available == 0 {
            return DecodeEvent::NeedMore;
        }
        let wanted = usize::try_from(remaining).unwrap_or(usize::MAX);
        let len = available.min(wanted);
        let start = self.cursor;

        self.cursor = self.cursor.saturating_add(len);
        self.decoded_bytes = self.decoded_bytes.saturating_add(len as u64);
        let left = remaining.saturating_sub(len as u64);
        self.state = if left == 0 {
            State::DataCrlf {
                signature,
                terminal: false,
            }
        } else {
            State::Data {
                remaining: left,
                signature,
            }
        };
        DecodeEvent::Data { start, len }
    }

    /// Consumes the CRLF that closes a chunk and reports the chunk as ended.
    fn step_data_crlf(&mut self, input: &[u8], signature: Option<[u8; 32]>, terminal: bool) -> Result<DecodeEvent, ChunkReject> {
        let rest = input.get(self.cursor..).unwrap_or(&[]);
        match rest {
            [b'\r', b'\n', ..] => {
                self.cursor = self.cursor.saturating_add(2);
                self.overhead_bytes = self.overhead_bytes.saturating_add(2);
                self.state = if terminal { State::Done } else { State::Meta };
                Ok(DecodeEvent::ChunkEnd { signature, terminal })
            }
            // Exactly CRLF. A bare `\n`, a lone `\r` or a doubled CRLF are each accepted by some
            // parser somewhere, which is the whole problem.
            [b'\r'] | [] => Ok(DecodeEvent::NeedMore),
            _ => Err(ChunkReject::BadLineTerminator),
        }
    }

    /// Refuses a body whose framing has outgrown its share of the payload.
    fn check_overhead_ratio(&self) -> Result<(), ChunkReject> {
        if self.overhead_bytes <= self.limits.overhead_ratio_floor_bytes() {
            return Ok(());
        }
        let permitted = u128::from(self.decoded_bytes).saturating_mul(u128::from(self.limits.max_overhead_permille()));
        let actual = u128::from(self.overhead_bytes).saturating_mul(1000);
        if actual > permitted {
            return Err(ChunkReject::OverheadRatioExceeded {
                overhead: self.overhead_bytes,
                decoded: self.decoded_bytes,
            });
        }
        Ok(())
    }
}

/// Finds the end of a CRLF-terminated line, refusing every other terminator.
///
/// Returns the line length (without the CRLF) and the number of bytes the line occupies
/// (including it), or `None` when more input is needed.
fn find_line(rest: &[u8], ceiling: usize) -> Result<Option<(usize, usize)>, ChunkReject> {
    let searchable = rest.get(..rest.len().min(ceiling)).unwrap_or(rest);
    match searchable.iter().position(|byte| matches!(byte, b'\r' | b'\n')) {
        // A bare LF terminates a line for several parsers and does not for others.
        Some(at) if searchable.get(at) == Some(&b'\n') => Err(ChunkReject::BadLineTerminator),
        Some(at) => match rest.get(at.saturating_add(1)) {
            Some(b'\n') => {
                let consumed = at.checked_add(2).ok_or(ChunkReject::ChunkMetaTooLong)?;
                if consumed > ceiling {
                    return Err(ChunkReject::ChunkMetaTooLong);
                }
                Ok(Some((at, consumed)))
            }
            Some(_) => Err(ChunkReject::BadLineTerminator),
            None if rest.len() >= ceiling => Err(ChunkReject::ChunkMetaTooLong),
            None => Ok(None),
        },
        None if rest.len() >= ceiling => Err(ChunkReject::ChunkMetaTooLong),
        None => Ok(None),
    }
}

/// Parses a chunk size under the strict spelling.
///
/// One to sixteen hexadecimal digits, at most one leading zero, no sign, no `0x`, no whitespace.
/// Every one of those is refused rather than normalised, because a size that two parsers read
/// differently is a body boundary that two parsers place differently.
fn parse_chunk_size(digits: &[u8]) -> Result<u64, ChunkReject> {
    if digits.is_empty() || digits.len() > MAX_CHUNK_SIZE_DIGITS {
        return Err(ChunkReject::MalformedChunkSize);
    }
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(ChunkReject::MalformedChunkSize);
    }
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return Err(ChunkReject::LeadingZeros);
    }
    let mut size: u64 = 0;
    for byte in digits {
        let digit = hex_value(*byte).ok_or(ChunkReject::MalformedChunkSize)?;
        size = size
            .checked_mul(16)
            .and_then(|acc| acc.checked_add(u64::from(digit)))
            .ok_or(ChunkReject::MalformedChunkSize)?;
    }
    Ok(size)
}

/// The numeric value of one hexadecimal digit, either case.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

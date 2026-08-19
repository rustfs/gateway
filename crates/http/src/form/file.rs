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

//! The file part, read under a ceiling that was named before it started.
//!
//! Responsible for: emitting file content to a sink, stopping at the byte that crosses the
//! ceiling, finding the closing delimiter, and refusing a part that arrives after the file.
//! NOT responsible for: choosing the ceiling — that is the caller's, at
//! [`super::FormReader::into_file`]; storing the bytes; or hashing them.
//! Upstream: `super::reader`, which is the only thing that can construct this type. Downstream:
//! whatever the caller's sink writes to.

use super::{FormReject, find};

/// What one [`FileReader::push`] achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStep {
    /// Everything offered was consumed and the file part has not ended.
    NeedMore,
    /// The file part and the closing delimiter have both been read.
    Complete {
        /// How many bytes the file part carried.
        file_bytes: u64,
    },
}

/// Where file bytes go as they are read.
///
/// A sink rather than a returned buffer: the reader hands over subslices of the caller's own
/// memory and never accumulates, which is what makes its resident cost independent of the upload.
pub trait FileSink {
    /// Accepts one run of file content.
    fn accept(&mut self, bytes: &[u8]);
}

impl<F: FnMut(&[u8])> FileSink for F {
    fn accept(&mut self, bytes: &[u8]) {
        self(bytes);
    }
}

/// What the reader is looking for after the content ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tail {
    /// File content, up to `\r\n--boundary`.
    Content,
    /// The two bytes that say whether the form ends here or another part follows.
    Marker,
    /// Both have been read.
    Done,
}

/// Reads the file part, under a ceiling that was named before it existed.
///
/// The only way to obtain one is [`super::FormReader::into_file`]. There is no `new`, no
/// `Default`, and no way to raise the ceiling once reading has begun.
#[derive(Debug)]
pub struct FileReader {
    ceiling: u64,
    max_whole_stream_bytes: u64,
    /// `\r\n--boundary`, the sequence that ends the file part.
    closing: Vec<u8>,
    /// Bytes already read from the transport that belong to the file part or the delimiter.
    ///
    /// Bounded by the part-header budget on entry and by `closing.len() - 1` thereafter, so it is
    /// a function of the boundary length and never of the upload.
    carry: Vec<u8>,
    /// Reused across pushes so that resolving the carry costs no allocation per frame.
    scratch: Vec<u8>,
    file_bytes: u64,
    bytes_seen: u64,
    tail: Tail,
}

impl FileReader {
    /// Builds the reader. Crate-private: the ceiling has to come from `into_file`.
    pub(super) fn new(ceiling: u64, max_whole_stream_bytes: u64, delimiter: &[u8], carry: Vec<u8>, bytes_seen: u64) -> Self {
        let mut closing = Vec::with_capacity(delimiter.len().saturating_add(2));
        closing.extend_from_slice(b"\r\n");
        closing.extend_from_slice(delimiter);
        let scratch = Vec::with_capacity(carry.len().saturating_add(closing.len()).saturating_add(closing.len()));
        Self {
            ceiling,
            max_whole_stream_bytes,
            closing,
            carry,
            scratch,
            file_bytes: 0,
            bytes_seen,
            tail: Tail::Content,
        }
    }

    /// The effective ceiling, already the smaller of the policy's and the deployment's.
    #[must_use]
    pub const fn ceiling(&self) -> u64 {
        self.ceiling
    }

    /// How many file bytes have been handed to the sink.
    #[must_use]
    pub const fn file_bytes(&self) -> u64 {
        self.file_bytes
    }

    /// How many form bytes have been read in total, the text fields included.
    #[must_use]
    pub const fn bytes_seen(&self) -> u64 {
        self.bytes_seen
    }

    /// Offers more of the body.
    ///
    /// # Errors
    ///
    /// * [`FormReject::FileTooLarge`] the moment the content passes the ceiling — the byte that
    ///   passes it never reaches the sink.
    /// * [`FormReject::FieldAfterFile`] when another part follows the file.
    /// * [`FormReject::WholeStreamTooLarge`], and [`FormReject::MalformedPart`] for a close that
    ///   is neither `--` nor `\r\n`.
    pub fn push(&mut self, input: &[u8], sink: &mut impl FileSink) -> Result<FileStep, FormReject> {
        self.bytes_seen = self.bytes_seen.saturating_add(input.len() as u64);
        if self.bytes_seen > self.max_whole_stream_bytes {
            return Err(FormReject::WholeStreamTooLarge);
        }
        let mut offset = 0usize;
        loop {
            match self.tail {
                Tail::Done => {
                    return Ok(FileStep::Complete {
                        file_bytes: self.file_bytes,
                    });
                }
                Tail::Marker => {
                    while self.carry.len() < 2 {
                        let Some(&byte) = input.get(offset) else { break };
                        self.carry.push(byte);
                        offset = offset.saturating_add(1);
                    }
                    if self.carry.len() < 2 {
                        return Ok(FileStep::NeedMore);
                    }
                    return match self.carry.get(..2) {
                        Some(b"--") => {
                            self.tail = Tail::Done;
                            Ok(FileStep::Complete {
                                file_bytes: self.file_bytes,
                            })
                        }
                        Some(b"\r\n") => Err(FormReject::FieldAfterFile),
                        _ => Err(FormReject::MalformedPart),
                    };
                }
                Tail::Content => {
                    let rest = input.get(offset..).unwrap_or_default();
                    let consumed = self.scan_content(rest, sink)?;
                    offset = offset.saturating_add(consumed);
                    if self.tail == Tail::Content && consumed == 0 {
                        return Ok(FileStep::NeedMore);
                    }
                }
            }
        }
    }

    /// Ends the file part.
    ///
    /// # Errors
    ///
    /// [`FormReject::IncompleteStream`] when the body stopped before the closing delimiter. This
    /// is the answer a truncated upload gets, and it must never be the answer a complete upload
    /// gets because the transport happened to split it somewhere awkward — which is exactly what
    /// `c-lim-0007` measures.
    pub const fn finish(&self) -> Result<u64, FormReject> {
        match self.tail {
            Tail::Done => Ok(self.file_bytes),
            _ => Err(FormReject::IncompleteStream),
        }
    }

    /// Emits as much of `input` as is certainly content, returning how much of it was consumed.
    ///
    /// The contract this upholds, and which [`FileReader::push`] relies on to terminate: when the
    /// tail is still `Content` on return, every byte of `input` was consumed.
    fn scan_content(&mut self, input: &[u8], sink: &mut impl FileSink) -> Result<usize, FormReject> {
        let closing = self.closing.len();
        let hold = closing.saturating_sub(1);

        if !self.carry.is_empty() {
            if input.len() < hold {
                // Too little lookahead to decide where the carry ends. Absorb what there is, emit
                // the prefix no delimiter can reach back into, and wait. The carry cannot grow
                // past `hold` this way, so a peer sending one byte per frame does not accumulate.
                self.carry.extend_from_slice(input);
                let mut carry = core::mem::take(&mut self.carry);
                let outcome = find(&carry, &self.closing);
                let split = match outcome {
                    Some(at) => at,
                    None => carry.len().saturating_sub(hold.min(carry.len())),
                };
                let emitted = self.emit_from(&carry, split, sink);
                let drop_to = match outcome {
                    Some(at) => at.saturating_add(closing).min(carry.len()),
                    None => split,
                };
                carry.drain(..drop_to);
                self.carry = carry;
                if outcome.is_some() {
                    self.tail = Tail::Marker;
                }
                emitted?;
                return Ok(input.len());
            }

            // Enough lookahead to decide every position inside the carry: a delimiter beginning at
            // carry index `p` needs at most `closing - 1` bytes beyond the carry to be recognised.
            let carried = self.carry.len();
            let mut scratch = core::mem::take(&mut self.scratch);
            scratch.clear();
            scratch.extend_from_slice(&self.carry);
            scratch.extend_from_slice(input.get(..hold).unwrap_or_default());
            if let Some(at) = find(&scratch, &self.closing).filter(|at| *at < carried) {
                let emitted = self.emit_from(&scratch, at, sink);
                self.tail = Tail::Marker;
                self.carry.clear();
                self.carry
                    .extend_from_slice(scratch.get(at.saturating_add(closing)..).unwrap_or_default());
                self.scratch = scratch;
                emitted?;
                return Ok(hold);
            }
            self.scratch = scratch;
            // No delimiter begins inside the carry, so all of it is content. The borrowed bytes
            // were lookahead only: they stay in `input` and are scanned below.
            let carry = core::mem::take(&mut self.carry);
            let emitted = self.emit_from(&carry, carry.len(), sink);
            self.carry = carry;
            self.carry.clear();
            emitted?;
        }

        match find(input, &self.closing) {
            Some(at) => {
                self.emit_from(input, at, sink)?;
                self.tail = Tail::Marker;
                Ok(at.saturating_add(closing))
            }
            None => {
                let keep = hold.min(input.len());
                let split = input.len().saturating_sub(keep);
                let emitted = self.emit_from(input, split, sink);
                self.carry.extend_from_slice(input.get(split..).unwrap_or_default());
                emitted?;
                Ok(input.len())
            }
        }
    }

    /// Emits `bytes[..end]`.
    fn emit_from(&mut self, bytes: &[u8], end: usize, sink: &mut impl FileSink) -> Result<(), FormReject> {
        self.emit(bytes.get(..end).unwrap_or_default(), sink)
    }

    /// Hands content to the sink, refusing the byte that would cross the ceiling.
    fn emit(&mut self, bytes: &[u8], sink: &mut impl FileSink) -> Result<(), FormReject> {
        if bytes.is_empty() {
            return Ok(());
        }
        let next = self.file_bytes.saturating_add(bytes.len() as u64);
        if next > self.ceiling {
            // Everything up to the ceiling is content the policy admitted; the byte after it is
            // the violation. Nothing past the ceiling reaches the sink.
            let room = usize::try_from(self.ceiling.saturating_sub(self.file_bytes))
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            if room > 0 {
                sink.accept(bytes.get(..room).unwrap_or_default());
                self.file_bytes = self.file_bytes.saturating_add(room as u64);
            }
            return Err(FormReject::FileTooLarge);
        }
        sink.accept(bytes);
        self.file_bytes = next;
        Ok(())
    }
}

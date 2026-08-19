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

//! The half of the form that comes before the file, and the door to the half that comes after.
//!
//! Responsible for: the boundary delimiters, each part's header block, the bounded text fields,
//! and stopping at the `file` part header with no file byte consumed.
//! NOT responsible for: file content — that is `super::file`, reachable only through
//! [`FormReader::into_file`] and only with a ceiling; and policy semantics, which are
//! `rustfs-gateway-sig`'s.
//! Upstream: `super` for the limits, the rejections and the shared parsers. Downstream:
//! `super::file`.

use super::{
    FORM_FILE_FIELD, FORM_POLICY_FIELD, FileReader, FormField, FormLimits, FormReject, find, parse_boundary, parse_disposition,
};

/// What one [`FormReader::push`] achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormStep {
    /// Everything offered was consumed and the `file` part has not started.
    NeedMore,
    /// The `file` part's header block has been read and **no file byte has been consumed**.
    ///
    /// `consumed` counts the bytes of this push the reader took. Everything after it is file
    /// content and belongs to the [`FileReader`] that [`FormReader::into_file`] produces.
    FileReached {
        /// How many bytes of the offered slice the reader consumed.
        consumed: usize,
    },
}

/// What the reader is looking for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The opening `--boundary` delimiter, or the one that follows a field.
    Delimiter,
    /// A part's header block, up to `\r\n\r\n`.
    PartHeaders,
    /// A text field's value, up to `\r\n--boundary`.
    FieldValue,
    /// The `file` part header has been read; this reader is finished.
    FileReached,
    /// The closing `--boundary--` was read, and no `file` part was in the form.
    Ended,
}

/// Reads a POST Object form's text fields and stops at the file.
///
/// See the module documentation of [`super`] for why stopping is the point.
#[derive(Debug)]
pub struct FormReader {
    limits: FormLimits,
    /// `--boundary`, materialised once.
    delimiter: Vec<u8>,
    buffer: Vec<u8>,
    fields: Vec<FormField>,
    state: State,
    current_field: Option<String>,
    filename: Option<String>,
    bytes_seen: u64,
    /// How far into `buffer` the current state has already searched without a hit.
    ///
    /// Without it, a peer that sends a 20 KiB `policy` one byte per frame makes the reader
    /// re-scan the whole pending value on every frame: twenty thousand frames times twenty
    /// thousand bytes, for one field whose ceiling is deliberately small. The cursor makes the
    /// search linear in the field, which is what the ceiling was supposed to bound.
    scanned: usize,
}

impl FormReader {
    /// Builds a reader from a request `Content-Type`.
    ///
    /// # Errors
    ///
    /// [`FormReject::MalformedContentType`] when the media type is not `multipart/form-data`, when
    /// no `boundary` parameter is present or two are, or when the boundary is empty, non-graphic,
    /// or longer than the 70 bytes RFC 2046 permits.
    pub fn new(content_type: &str, limits: FormLimits) -> Result<Self, FormReject> {
        let boundary = parse_boundary(content_type)?;
        let mut delimiter = Vec::with_capacity(boundary.len().saturating_add(2));
        delimiter.extend_from_slice(b"--");
        delimiter.extend_from_slice(boundary.as_bytes());
        Ok(Self {
            limits,
            delimiter,
            buffer: Vec::new(),
            fields: Vec::new(),
            state: State::Delimiter,
            current_field: None,
            filename: None,
            bytes_seen: 0,
            scanned: 0,
        })
    }

    /// Every text field read so far, in arrival order.
    #[must_use]
    pub fn fields(&self) -> &[FormField] {
        &self.fields
    }

    /// One field's value by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|field| field.name() == name).map(FormField::value)
    }

    /// The `filename` parameter of the `file` part, once that part's header has been read.
    ///
    /// Multipart metadata, deliberately kept out of [`FormReader::fields`]: a policy condition
    /// naming `filename` must not be satisfiable by a form field a peer invented.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// The part being read when the last rejection happened, when it had a name.
    ///
    /// For an operator's log line. It is not reflected to the client, for the reason
    /// [`crate::LimitKind`] gives: naming the ceiling that fired is a probe for the ceiling.
    #[must_use]
    pub fn current_field(&self) -> Option<&str> {
        self.current_field.as_deref()
    }

    /// How many bytes of form this reader has consumed, for the whole-stream budget.
    #[must_use]
    pub const fn bytes_seen(&self) -> u64 {
        self.bytes_seen
    }

    /// Offers more of the body.
    ///
    /// # Errors
    ///
    /// Any [`FormReject`] the framing, the ceilings, or the field ordering produce.
    pub fn push(&mut self, input: &[u8]) -> Result<FormStep, FormReject> {
        let mut offset = 0usize;
        loop {
            match self.state {
                State::FileReached => return Ok(FormStep::FileReached { consumed: offset }),
                State::Ended => return Err(FormReject::MissingFile),
                _ => {}
            }

            let room = self.state_budget().saturating_sub(self.buffer.len());
            let take = room.min(input.len().saturating_sub(offset));
            if take > 0 {
                let Some(slice) = input.get(offset..offset.saturating_add(take)) else {
                    return Err(FormReject::MalformedPart);
                };
                self.bytes_seen = self.bytes_seen.saturating_add(take as u64);
                if self.bytes_seen > self.limits.max_whole_stream_bytes() {
                    return Err(FormReject::WholeStreamTooLarge);
                }
                self.buffer.extend_from_slice(slice);
                offset = offset.saturating_add(take);
            }

            // `step` either decides something or reports that the buffer is short. It never
            // reports "short" while the buffer is at its budget — every state answers a full
            // buffer with a decision or a rejection — so this loop cannot spin.
            if !self.step()? && take == 0 {
                return Ok(FormStep::NeedMore);
            }
        }
    }

    /// Reports how a form that simply stopped should be refused.
    #[must_use]
    pub fn finish(&self) -> FormReject {
        match self.state {
            State::Ended => FormReject::MissingFile,
            _ => FormReject::IncompleteStream,
        }
    }

    /// Starts reading the file part under `ceiling` bytes.
    ///
    /// **This is the only constructor of [`FileReader`] there is**, and the ceiling is an argument
    /// rather than a field someone may forget to set. The effective bound is
    /// `min(ceiling, FormLimits::max_file_bytes)`: a policy's `content-length-range` tightens the
    /// deployment maximum and can never loosen it.
    ///
    /// # Errors
    ///
    /// [`FormReject::MalformedPart`] when the `file` part has not been reached. Reading a file
    /// that has not been announced is not a state this type will represent.
    pub fn into_file(self, ceiling: u64) -> Result<FileReader, FormReject> {
        if self.state != State::FileReached {
            return Err(FormReject::MalformedPart);
        }
        Ok(FileReader::new(
            ceiling.min(self.limits.max_file_bytes()),
            self.limits.max_whole_stream_bytes(),
            &self.delimiter,
            self.buffer,
            self.bytes_seen,
        ))
    }

    /// How large the pending buffer may grow in the current state.
    fn state_budget(&self) -> usize {
        match self.state {
            // `--boundary` plus the two bytes that say whether another part follows.
            State::Delimiter => self.delimiter.len().saturating_add(2),
            State::PartHeaders => self.limits.max_part_header_bytes(),
            // Room for the value at its ceiling, plus the terminator that ends it, so a value
            // exactly at the ceiling is still recognised as complete rather than as too large.
            State::FieldValue => self.field_ceiling().saturating_add(self.terminator_len()),
            State::FileReached | State::Ended => 0,
        }
    }

    /// `\r\n--boundary`, the sequence that ends a field value.
    fn terminator_len(&self) -> usize {
        self.delimiter.len().saturating_add(2)
    }

    /// The byte ceiling of the field currently being read.
    fn field_ceiling(&self) -> usize {
        match self.current_field.as_deref() {
            Some(FORM_POLICY_FIELD) => self.limits.max_policy_bytes(),
            _ => self.limits.max_field_bytes(),
        }
    }

    /// Searches `buffer` for `needle`, resuming where the last unsuccessful search stopped.
    ///
    /// A needle that straddles the resume point is still found: the search restarts
    /// `needle.len() - 1` bytes back, which is every position a match could still begin at.
    fn find_resumable(&mut self, needle: &[u8]) -> Option<usize> {
        let from = self.scanned.saturating_sub(needle.len().saturating_sub(1));
        let hit = find(self.buffer.get(from..).unwrap_or_default(), needle).map(|at| from.saturating_add(at));
        self.scanned = if hit.is_some() { 0 } else { self.buffer.len() };
        hit
    }

    /// Resets the search cursor when the buffer's meaning changes.
    fn rewind(&mut self) {
        self.scanned = 0;
    }

    /// Decides as much as the buffer allows. Returns whether it decided anything.
    fn step(&mut self) -> Result<bool, FormReject> {
        match self.state {
            State::Delimiter => self.step_delimiter(),
            State::PartHeaders => self.step_headers(),
            State::FieldValue => self.step_value(),
            State::FileReached | State::Ended => Ok(false),
        }
    }

    fn step_delimiter(&mut self) -> Result<bool, FormReject> {
        let want = self.delimiter.len().saturating_add(2);
        if self.buffer.len() < want {
            return Ok(false);
        }
        if self.buffer.get(..self.delimiter.len()) != Some(self.delimiter.as_slice()) {
            return Err(FormReject::MalformedPart);
        }
        let Some(marker) = self.buffer.get(self.delimiter.len()..want) else {
            return Err(FormReject::MalformedPart);
        };
        let ended = match marker {
            b"\r\n" => false,
            b"--" => true,
            _ => return Err(FormReject::MalformedPart),
        };
        self.buffer.drain(..want);
        self.rewind();
        self.state = if ended { State::Ended } else { State::PartHeaders };
        Ok(true)
    }

    fn step_headers(&mut self) -> Result<bool, FormReject> {
        let Some(end) = self.find_resumable(b"\r\n\r\n") else {
            if self.buffer.len() >= self.limits.max_part_header_bytes() {
                return Err(FormReject::PartHeaderTooLarge);
            }
            return Ok(false);
        };
        let Some(block) = self.buffer.get(..end) else {
            return Err(FormReject::MalformedPart);
        };
        let (name, filename) = parse_disposition(block)?;
        self.buffer.drain(..end.saturating_add(4));
        self.rewind();
        let duplicate = self.fields.iter().any(|field| field.name() == name);
        let full = self.fields.len() >= self.limits.max_field_count();
        self.current_field = Some(name.clone());
        if name == FORM_FILE_FIELD {
            self.filename = filename;
            self.state = State::FileReached;
            return Ok(true);
        }
        if duplicate {
            return Err(FormReject::DuplicateField);
        }
        if full {
            return Err(FormReject::TooManyFields);
        }
        self.state = State::FieldValue;
        Ok(true)
    }

    fn step_value(&mut self) -> Result<bool, FormReject> {
        let mut terminator = Vec::with_capacity(self.terminator_len());
        terminator.extend_from_slice(b"\r\n");
        terminator.extend_from_slice(&self.delimiter);
        let ceiling = self.field_ceiling();
        let Some(end) = self.find_resumable(&terminator) else {
            // The trailing `terminator.len() - 1` bytes may still turn out to be the terminator,
            // so only what lies before them is certainly value. The field is too large the moment
            // *that* passes the ceiling — not a byte earlier, or a value exactly at the ceiling
            // would be refused whenever its terminator arrived in a later frame.
            let certain = self.buffer.len().saturating_sub(terminator.len().saturating_sub(1));
            if certain > ceiling {
                return Err(self.too_large());
            }
            return Ok(false);
        };
        if end > ceiling {
            return Err(self.too_large());
        }
        let Some(raw) = self.buffer.get(..end) else {
            return Err(FormReject::MalformedPart);
        };
        if crate::text::contains_forbidden_control(raw) {
            return Err(FormReject::MalformedFieldValue);
        }
        let Ok(value) = core::str::from_utf8(raw) else {
            return Err(FormReject::MalformedFieldValue);
        };
        let Some(name) = self.current_field.clone() else {
            return Err(FormReject::MalformedPart);
        };
        self.fields.push(FormField::new(name, value.to_owned()));
        // Leave the `\r\n` behind and hand the delimiter itself back to `step_delimiter`.
        self.buffer.drain(..end.saturating_add(2));
        self.rewind();
        self.state = State::Delimiter;
        Ok(true)
    }

    fn too_large(&self) -> FormReject {
        match self.current_field.as_deref() {
            Some(FORM_POLICY_FIELD) => FormReject::PolicyTooLarge,
            _ => FormReject::FieldTooLarge,
        }
    }
}

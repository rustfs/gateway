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
//! and stopping at the `file` part header with no file byte consumed — under either
//! [`FormGrammar`]: the gateway's own, or the legacy RustFS one, which adds a preamble before the
//! first boundary and transport padding after a boundary line.
//! NOT responsible for: file content — that is `super::file`, reachable only through
//! [`FormReader::into_file`] and only with a ceiling; what a legacy header block says
//! (`super::legacy`); and policy semantics, which are `rustfs-gateway-sig`'s.
//! Upstream: `super` for the limits, the rejections and the shared parsers. Downstream:
//! `super::file`, `super::legacy`.

use super::{
    FORM_FILE_FIELD, FORM_POLICY_FIELD, FileReader, FormField, FormGrammar, FormLimits, FormReject, find, legacy, parse_boundary,
    parse_disposition,
};

/// How much of a preamble is held at once while the first boundary is searched for.
///
/// The preamble is discarded as it is searched: between searches only the bytes that could still
/// begin a boundary are kept, so a preamble of any length costs this much memory, and its bytes
/// are charged to the whole-stream budget like every other byte of the form.
const PREAMBLE_WINDOW: usize = 1024;

/// How much transport padding after a boundary is held at once; it is discarded as it is read.
const PADDING_WINDOW: usize = 64;

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
    ///
    /// The gateway grammar only; the legacy grammar reads the same bytes as [`State::Preamble`]
    /// and [`State::AfterBoundary`].
    Delimiter,
    /// Legacy grammar: before the first boundary. Everything up to its first occurrence is a
    /// preamble and is discarded.
    Preamble,
    /// Legacy grammar: just after a boundary. `--` closes the form, a space or a tab is transport
    /// padding, and CRLF opens a part.
    AfterBoundary,
    /// Legacy grammar: transport padding after a boundary, up to the CRLF that ends its line.
    Padding,
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
/// See the `form` module documentation for why stopping is the point.
#[derive(Debug)]
pub struct FormReader {
    limits: FormLimits,
    grammar: FormGrammar,
    /// `--boundary`, materialised once.
    delimiter: Vec<u8>,
    /// `\r\n--boundary`, materialised once for all text-field pushes.
    terminator: Vec<u8>,
    buffer: Vec<u8>,
    fields: Vec<FormField>,
    state: State,
    current_field: Option<String>,
    filename: Option<String>,
    /// Legacy grammar: the `file` part's name exactly as sent, once that part's header is read.
    file_part_name: Option<String>,
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
    /// Builds a reader from a request `Content-Type`, under the gateway's own grammar.
    ///
    /// # Errors
    ///
    /// [`FormReject::MalformedContentType`] when the media type is not `multipart/form-data`, when
    /// no `boundary` parameter is present or two are, or when the boundary is empty, non-graphic,
    /// or longer than the 70 bytes RFC 2046 permits.
    pub fn new(content_type: &str, limits: FormLimits) -> Result<Self, FormReject> {
        Self::with_grammar(content_type, limits, FormGrammar::Gateway)
    }

    /// Builds a reader from a request `Content-Type`, under `grammar`.
    ///
    /// # Errors
    ///
    /// [`FormReject::MalformedContentType`] as [`FormReader::new`] describes for
    /// [`FormGrammar::Gateway`]; for [`FormGrammar::LegacyRustfs`], when the header does not read
    /// as `multipart/form-data` with a `boundary` under the legacy header grammar, or the boundary
    /// is not one to seventy RFC 2046 `bchars` that do not end in a space.
    pub fn with_grammar(content_type: &str, limits: FormLimits, grammar: FormGrammar) -> Result<Self, FormReject> {
        let boundary = match grammar {
            FormGrammar::Gateway => parse_boundary(content_type)?,
            FormGrammar::LegacyRustfs { .. } => legacy::boundary(content_type)?.to_owned(),
        };
        let mut delimiter = Vec::with_capacity(boundary.len().saturating_add(2));
        delimiter.extend_from_slice(b"--");
        delimiter.extend_from_slice(boundary.as_bytes());
        let mut terminator = Vec::with_capacity(delimiter.len().saturating_add(2));
        terminator.extend_from_slice(b"\r\n");
        terminator.extend_from_slice(&delimiter);
        Ok(Self {
            limits,
            grammar,
            delimiter,
            terminator,
            buffer: Vec::new(),
            fields: Vec::new(),
            state: match grammar {
                FormGrammar::Gateway => State::Delimiter,
                FormGrammar::LegacyRustfs { .. } => State::Preamble,
            },
            current_field: None,
            filename: None,
            file_part_name: None,
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

    /// The grammar this reader reads with.
    #[must_use]
    pub const fn grammar(&self) -> FormGrammar {
        self.grammar
    }

    /// The name `${filename}` in a `key` stands for, once the `file` part's header has been read.
    ///
    /// Under [`FormGrammar::Gateway`] this is [`FormReader::filename`]. Under
    /// [`FormGrammar::LegacyRustfs`] a file part without a `filename` is named after the part
    /// itself, as sent, as the legacy stack names it.
    ///
    /// Legacy-compat (rustfs/backlog#2684): the legacy stack stores `uploads/${filename}` from a
    /// file part without a `filename` as `uploads/file` (or `uploads/File`, as the part was
    /// spelled): the form field's name stands in for a file name the client never sent. The
    /// intended future behaviour is to refuse a `${filename}` key when the file has no name.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        match self.grammar {
            FormGrammar::Gateway => self.filename.as_deref(),
            FormGrammar::LegacyRustfs { .. } => self.filename.as_deref().or(self.file_part_name.as_deref()),
        }
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
            let decided = self.step()?;
            // A preamble and transport padding belong to no ceiling, so under the legacy grammar
            // everything decided before the file is held to the most a form at every ceiling can
            // carry there: what is read before authorization stays bounded. Counted in decided
            // bytes, not buffered ones, so the refusal falls at the same byte however the body
            // was framed; the buffer on top of it is bounded by the state budgets.
            if matches!(self.grammar, FormGrammar::LegacyRustfs { .. })
                && self.bytes_seen.saturating_sub(self.buffer.len() as u64) > self.limits.max_prelude_bytes()
            {
                return Err(FormReject::PreludeTooLarge);
            }
            if !decided && take == 0 {
                return Ok(FormStep::NeedMore);
            }
        }
    }

    /// Reports how a form that simply stopped should be refused.
    ///
    /// Under the legacy grammar a body that ended before its first boundary never was a form, so it
    /// is malformed rather than truncated, as the legacy stack answers it.
    #[must_use]
    pub fn finish(&self) -> FormReject {
        match self.state {
            State::Ended => FormReject::MissingFile,
            State::Preamble => FormReject::MalformedPart,
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
            self.grammar,
        ))
    }

    /// How large the pending buffer may grow in the current state.
    fn state_budget(&self) -> usize {
        match self.state {
            // `--boundary` plus the two bytes that say whether another part follows.
            State::Delimiter => self.delimiter.len().saturating_add(2),
            // Enough to hold one whole `--boundary` beside the bytes already searched.
            State::Preamble => self.delimiter.len().saturating_mul(2).max(PREAMBLE_WINDOW),
            // `--`, CRLF, or the first byte of padding.
            State::AfterBoundary => 2,
            State::Padding => PADDING_WINDOW,
            State::PartHeaders => self.limits.max_part_header_bytes(),
            // Room for the value at its ceiling, plus the terminator that ends it, so a value
            // exactly at the ceiling is still recognised as complete rather than as too large.
            State::FieldValue => self.field_ceiling().saturating_add(self.terminator_len()),
            State::FileReached | State::Ended => 0,
        }
    }

    /// `\r\n--boundary`, the sequence that ends a field value.
    fn terminator_len(&self) -> usize {
        self.terminator.len()
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
    fn find_resumable(buffer: &[u8], scanned: &mut usize, needle: &[u8]) -> Option<usize> {
        let from = scanned.saturating_sub(needle.len().saturating_sub(1));
        let hit = find(buffer.get(from..).unwrap_or_default(), needle).map(|at| from.saturating_add(at));
        *scanned = if hit.is_some() { 0 } else { buffer.len() };
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
            State::Preamble => Ok(self.step_preamble()),
            State::AfterBoundary => self.step_after_boundary(),
            State::Padding => self.step_padding(),
            State::PartHeaders => match self.grammar {
                FormGrammar::Gateway => self.step_headers(),
                FormGrammar::LegacyRustfs { .. } => self.step_legacy_headers(),
            },
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
        let Some(end) = self.header_block_end()? else {
            return Ok(false);
        };
        let Some(block) = self.buffer.get(..end.saturating_sub(4)) else {
            return Err(FormReject::MalformedPart);
        };
        let (name, filename) = parse_disposition(block)?;
        self.buffer.drain(..end);
        self.rewind();
        self.enter_part(name, filename, None)
    }

    /// Where the part header block in the buffer ends, its CRLF CRLF included, or `None` while it
    /// has not ended within the ceiling yet.
    fn header_block_end(&mut self) -> Result<Option<usize>, FormReject> {
        let ceiling = self.limits.max_part_header_bytes();
        let Some(at) = Self::find_resumable(&self.buffer, &mut self.scanned, b"\r\n\r\n") else {
            if self.buffer.len() >= ceiling {
                return Err(FormReject::PartHeaderTooLarge);
            }
            return Ok(None);
        };
        // The buffer may already hold more than the header ceiling — after a field it carries the
        // bytes that followed the value, up to that field's own budget — so the block found in it
        // is measured, not only the buffer. Otherwise the ceiling would hold for a body sent a byte
        // at a time and not for the same body sent in one frame.
        let end = at.saturating_add(4);
        if end > ceiling {
            return Err(FormReject::PartHeaderTooLarge);
        }
        Ok(Some(end))
    }

    /// Enters the part a header block named: the file part, where this reader stops, or a text
    /// field, which must be new and within the field count. `name` is already lowercased.
    fn enter_part(&mut self, name: String, filename: Option<String>, file_part_name: Option<String>) -> Result<bool, FormReject> {
        let duplicate = self.fields.iter().any(|field| field.name() == name);
        let full = self.fields.len() >= self.limits.max_field_count();
        self.current_field = Some(name.clone());
        if name == FORM_FILE_FIELD {
            self.filename = filename;
            self.file_part_name = file_part_name;
            self.state = State::FileReached;
            return Ok(true);
        }
        // Under both grammars. Legacy RustFS keeps both values of a repeated field and reads the
        // last; the RustFS profile still fails closed here, because the policy check and the POST
        // bridge would have to read the same one and neither does yet (an open item on
        // rustfs/backlog#1677, like the control-byte refusal in `step_value`).
        if duplicate {
            return Err(FormReject::DuplicateField);
        }
        if full {
            return Err(FormReject::TooManyFields);
        }
        self.state = State::FieldValue;
        Ok(true)
    }

    /// Legacy grammar: discards the preamble up to and including the first `--boundary`.
    ///
    /// Legacy-compat (rustfs/backlog#2684): the first occurrence of `--boundary` ends the preamble
    /// wherever it falls, mid-line included, and there is no second search: what follows it must be
    /// a boundary line or the form is refused. RFC 2046 only recognises a delimiter at the start of
    /// a line; the intended future behaviour is to search for one there.
    fn step_preamble(&mut self) -> bool {
        if let Some(at) = find(&self.buffer, &self.delimiter) {
            self.buffer.drain(..at.saturating_add(self.delimiter.len()));
            self.rewind();
            self.state = State::AfterBoundary;
            return true;
        }
        // Keep only the tail that could still be the start of a boundary.
        let keep = self.delimiter.len().saturating_sub(1).min(self.buffer.len());
        let discard = self.buffer.len().saturating_sub(keep);
        self.buffer.drain(..discard);
        discard > 0
    }

    /// Legacy grammar: reads what follows a boundary — `--` closes the form, a space or a tab
    /// starts transport padding, CRLF starts a part's header block.
    fn step_after_boundary(&mut self) -> Result<bool, FormReject> {
        let Some(&first) = self.buffer.first() else {
            return Ok(false);
        };
        let next = match first {
            b' ' | b'\t' => {
                self.state = State::Padding;
                return Ok(true);
            }
            b'-' | b'\r' => match self.buffer.get(..2) {
                None => return Ok(false),
                Some(b"--") => State::Ended,
                Some(b"\r\n") => State::PartHeaders,
                Some(_) => return Err(FormReject::MalformedPart),
            },
            _ => return Err(FormReject::MalformedPart),
        };
        self.buffer.drain(..2);
        self.rewind();
        self.state = next;
        Ok(true)
    }

    /// Legacy grammar: discards spaces and tabs after a boundary; the line must then end in CRLF.
    fn step_padding(&mut self) -> Result<bool, FormReject> {
        let padding = self.buffer.iter().take_while(|byte| matches!(byte, b' ' | b'\t')).count();
        if padding > 0 {
            self.buffer.drain(..padding);
            return Ok(true);
        }
        match (self.buffer.first(), self.buffer.get(..2)) {
            (None, _) | (Some(b'\r'), None) => Ok(false),
            (_, Some(b"\r\n")) => {
                self.buffer.drain(..2);
                self.rewind();
                self.state = State::PartHeaders;
                Ok(true)
            }
            _ => Err(FormReject::MalformedPart),
        }
    }

    /// Legacy grammar: locates a part's header block and reads it with `super::legacy`.
    fn step_legacy_headers(&mut self) -> Result<bool, FormReject> {
        match self.buffer.get(..2) {
            None => return Ok(false),
            // An empty header block: the part has no `Content-Disposition`, so no name.
            Some(b"\r\n") => return Err(FormReject::MalformedPart),
            Some(_) => {}
        }
        let Some(end) = self.header_block_end()? else {
            return Ok(false);
        };
        let Some(block) = self.buffer.get(..end) else {
            return Err(FormReject::MalformedPart);
        };
        let head = legacy::part_head(block)?;
        // Legacy-compat (rustfs/backlog#2684): a part named by an empty `name` is a field like any
        // other. RFC 7578 gives every part a name; the intended future behaviour is to refuse an
        // empty one, as the gateway grammar does.
        let name = head.name.to_ascii_lowercase();
        if crate::text::contains_forbidden_control(name.as_bytes()) {
            return Err(FormReject::MalformedPart);
        }
        self.buffer.drain(..head.content_start);
        self.rewind();
        self.enter_part(name, head.filename, Some(head.name))
    }

    fn step_value(&mut self) -> Result<bool, FormReject> {
        let ceiling = self.field_ceiling();
        let Some(end) = Self::find_resumable(&self.buffer, &mut self.scanned, &self.terminator) else {
            // The trailing `terminator.len() - 1` bytes may still turn out to be the terminator,
            // so only what lies before them is certainly value. The field is too large the moment
            // *that* passes the ceiling — not a byte earlier, or a value exactly at the ceiling
            // would be refused whenever its terminator arrived in a later frame.
            let certain = self.buffer.len().saturating_sub(self.terminator.len().saturating_sub(1));
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
        // Under both grammars. Legacy RustFS stores a value holding CR, LF or another control
        // byte as sent; the RustFS profile fails closed rather than store a header-injection
        // primitive (an open item on rustfs/backlog#1677).
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
        match self.grammar {
            FormGrammar::Gateway => {
                // Leave the `\r\n` behind and hand the delimiter itself back to `step_delimiter`.
                self.buffer.drain(..end.saturating_add(2));
                self.state = State::Delimiter;
            }
            FormGrammar::LegacyRustfs { .. } => {
                self.buffer.drain(..end.saturating_add(self.terminator.len()));
                self.state = State::AfterBoundary;
            }
        }
        self.rewind();
        Ok(true)
    }

    fn too_large(&self) -> FormReject {
        match self.current_field.as_deref() {
            Some(FORM_POLICY_FIELD) => FormReject::PolicyTooLarge,
            _ => FormReject::FieldTooLarge,
        }
    }
}

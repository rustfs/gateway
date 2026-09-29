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

//! POST Object form builders and readers shared by the legacy-grammar suites.
//!
//! Responsible for: building `multipart/form-data` bodies part by part, and reading one through
//! `FormReader` and `FileReader` under a grammar, in several framings that must agree.
//! NOT responsible for: assertions, which stay in `form_grammar.rs` and `form_legacy_edges.rs`.
//! Upstream: `rustfs-gateway-http`'s form reader. Downstream: those two suites.

use rustfs_gateway_http::{FileReader, FormGrammar, FormLimits, FormReader, FormReject, FormStep};

/// The grammar under test, for a request that declared its length, as every browser does.
pub const LEGACY: FormGrammar = FormGrammar::LegacyRustfs { declared_length: true };

/// A legacy-grammar reader under `limits`.
pub fn legacy_reader(content_type: &str, limits: FormLimits) -> Result<FormReader, FormReject> {
    FormReader::with_grammar(content_type, limits, LEGACY)
}

pub const BOUNDARY: &str = "----GatewayFormBoundary7MA4YWxkTrZu0gW";

pub fn content_type() -> String {
    format!("multipart/form-data; boundary={BOUNDARY}")
}

/// What a complete read of a form produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub fields: Vec<(String, String)>,
    pub filename: Option<String>,
    pub file: Vec<u8>,
}

/// Reads `body` in frames of `frame` bytes.
pub fn read_framed(content_type: &str, body: &[u8], frame: usize) -> Result<Parsed, FormReject> {
    read_framed_under(content_type, body, frame, LEGACY)
}

/// Reads `body` in frames of `frame` bytes under `grammar`.
pub fn read_framed_under(content_type: &str, body: &[u8], frame: usize, grammar: FormGrammar) -> Result<Parsed, FormReject> {
    let mut head = Some(FormReader::with_grammar(content_type, FormLimits::default(), grammar)?);
    let mut file: Option<FileReader> = None;
    let mut parsed = Parsed {
        fields: Vec::new(),
        filename: None,
        file: Vec::new(),
    };
    for piece in body.chunks(frame.max(1)) {
        let mut piece = piece;
        if let Some(mut reader) = head.take() {
            match reader.push(piece)? {
                FormStep::NeedMore => {
                    head = Some(reader);
                    continue;
                }
                FormStep::FileReached { consumed } => {
                    parsed.fields = reader
                        .fields()
                        .iter()
                        .map(|field| (field.name().to_owned(), field.value().to_owned()))
                        .collect();
                    parsed.filename = reader.filename().map(str::to_owned);
                    file = Some(reader.into_file(u64::MAX)?);
                    piece = &piece[consumed..];
                }
            }
        }
        let Some(reading) = file.as_mut() else {
            unreachable!("the head is either still reading or has handed over the file");
        };
        let mut sink = |bytes: &[u8]| parsed.file.extend_from_slice(bytes);
        reading.push(piece, &mut sink)?;
    }
    match (head, file) {
        (Some(reader), _) => Err(reader.finish()),
        (None, Some(reading)) => reading.finish().map(|_| parsed),
        (None, None) => Err(FormReject::IncompleteStream),
    }
}

/// Reads `body` whole and in four other framings, and requires every framing to agree.
///
/// A grammar rule that only holds when the bytes arrive together is not a rule, so every case in
/// this file is decided five times.
pub fn read(content_type: &str, body: &[u8]) -> Result<Parsed, FormReject> {
    let whole = read_framed(content_type, body, body.len());
    for frame in [1, 2, 5, 13] {
        assert_eq!(
            read_framed(content_type, body, frame),
            whole,
            "{frame}-byte frames disagree with one frame"
        );
    }
    whole
}

/// One part: its raw header block (without the blank line) and its content.
pub fn part(headers: &str, content: &str) -> Vec<u8> {
    format!("--{BOUNDARY}\r\n{headers}\r\n\r\n{content}\r\n").into_bytes()
}

/// A form of the given parts, closed by the canonical closing delimiter.
pub fn form(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut body: Vec<u8> = parts.concat();
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// A text field part with the ordinary quoted spelling.
pub fn field(name: &str, value: &str) -> Vec<u8> {
    part(&format!("Content-Disposition: form-data; name=\"{name}\""), value)
}

/// The canonical `file` part.
pub fn file(filename: &str, content: &str) -> Vec<u8> {
    part(
        &format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: text/plain"),
        content,
    )
}

/// A form whose first part carries `disposition` as its whole header block, then a canonical file.
pub fn with_first_part(headers: &str) -> Vec<u8> {
    form(&[part(headers, "value"), file("a.txt", "content")])
}

/// A form whose file part carries `disposition` as its `Content-Disposition` value.
pub fn with_file_disposition(disposition: &str) -> Vec<u8> {
    form(&[
        field("key", "uploads/${filename}"),
        part(&format!("Content-Disposition: {disposition}"), "content"),
    ])
}

pub fn field_names(parsed: &Parsed) -> Vec<&str> {
    parsed.fields.iter().map(|(name, _)| name.as_str()).collect()
}

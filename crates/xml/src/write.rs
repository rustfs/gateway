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

//! The writer every generated encoder writes an S3 response body through.
//!
//! Responsible for: the declaration, elements, attributes, escaping, and the two decisions that
//! are not free — whether an empty member is written as a paired element or not written at all,
//! and whether a text node's double quotes are escaped.
//! NOT responsible for: knowing which members exist, in what order, or under what names. Every
//! one of those is IR data the generated encoder supplies.
//! Upstream: nothing. Downstream: `rustfs-gateway-core`'s generated codecs.
//!
//! # Why there is no pretty-printing and no self-closing form
//!
//! S3 writes one line with no whitespace between elements, and writes an empty element as
//! `<X></X>` rather than `<X/>`. Both are observable: a conformance case that pins a body byte for
//! byte fails on either. So neither is an option this writer offers — an option is a thing a
//! caller can get wrong.
//!
//! # Why escaping the double quote *is* an option
//!
//! A `"` is legal, unescaped, in XML character data, so escaping it is a choice — and S3 makes it
//! differently in two elements of the same body. An entity tag comes back as
//! `<ETag>&quot;d41d…&quot;</ETag>` while an object key carrying a quote comes back with the
//! literal byte (`c-list-0001` and `c-list-0036` pin the two against each other). That is a
//! property of the member being written, not of the writer, so it arrives as a separate method
//! whose call sites are chosen from the IR rather than as a flag on `escape_text`.

use core::fmt::Write as _;

use crate::chars::{UNREPRESENTABLE, is_xml_char};

/// The XML declaration S3 puts at the head of every response body.
pub const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// The S3 namespace written on a response root.
pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Builds one XML document.
///
/// Element nesting is tracked so that `close` cannot close the wrong element by accident: it
/// closes whatever `open` last opened, and the name is remembered rather than repeated.
#[derive(Debug, Default)]
pub struct XmlWriter {
    out: String,
    open: Vec<String>,
}

impl XmlWriter {
    /// A writer with the XML declaration already written.
    #[must_use]
    pub fn document() -> Self {
        Self {
            out: String::from(DECLARATION),
            open: Vec::new(),
        }
    }

    /// A writer with no declaration, for a fragment.
    #[must_use]
    pub fn fragment() -> Self {
        Self::default()
    }

    /// Opens an element, optionally carrying the S3 namespace.
    pub fn open(&mut self, name: &str, xmlns: Option<&str>) {
        self.out.push('<');
        self.out.push_str(name);
        if let Some(namespace) = xmlns {
            self.out.push_str(" xmlns=\"");
            escape_attribute(namespace, &mut self.out);
            self.out.push('"');
        }
        self.out.push('>');
        self.open.push(name.to_owned());
    }

    /// Opens an element with attributes.
    pub fn open_with(&mut self, name: &str, attributes: &[(&str, &str)]) {
        self.out.push('<');
        self.out.push_str(name);
        for (attribute, value) in attributes {
            self.out.push(' ');
            self.out.push_str(attribute);
            self.out.push_str("=\"");
            escape_attribute(value, &mut self.out);
            self.out.push('"');
        }
        self.out.push('>');
        self.open.push(name.to_owned());
    }

    /// Closes the most recently opened element. A close with nothing open writes nothing.
    pub fn close(&mut self) {
        let Some(name) = self.open.pop() else {
            return;
        };
        self.out.push_str("</");
        self.out.push_str(&name);
        self.out.push('>');
    }

    /// Writes a complete element with text content, escaped.
    pub fn element(&mut self, name: &str, text: &str) {
        self.out.push('<');
        self.out.push_str(name);
        self.out.push('>');
        escape_text(text, &mut self.out);
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }

    /// Writes a complete element whose text is escaped *including its double quotes*.
    ///
    /// The difference from [`Self::element`] is one character class and it is byte-observable:
    /// this writes `&quot;` where that writes `"`. Only a value whose own wire form carries
    /// quotation marks asks for it — in this surface, an entity tag — and which members those are
    /// is IR data, not something this writer knows.
    pub fn element_quoting(&mut self, name: &str, text: &str) {
        self.out.push('<');
        self.out.push_str(name);
        self.out.push('>');
        escape_text_and_quotes(text, &mut self.out);
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }

    /// The [`Self::element_if_present`] twin of [`Self::element_quoting`].
    pub fn element_quoting_if_present(&mut self, name: &str, text: &str) {
        if !text.is_empty() {
            self.element_quoting(name, text);
        }
    }

    /// Writes escaped text into the element that is currently open.
    ///
    /// The unwrapped-output form needs it: there the single body member *is* the root, so its text
    /// is written between an `open` and a `close` rather than by [`Self::element`].
    pub fn text(&mut self, text: &str) {
        escape_text(text, &mut self.out);
    }

    /// Writes an element only when the text is non-empty.
    ///
    /// The other half of the IR's `empty_value_policy`; the `emit` half is [`Self::element`] with
    /// an empty string, which writes `<X></X>`.
    pub fn element_if_present(&mut self, name: &str, text: &str) {
        if !text.is_empty() {
            self.element(name, text);
        }
    }

    /// Writes an element holding a decimal integer.
    pub fn element_i64(&mut self, name: &str, value: i64) {
        let mut buffer = String::new();
        let _ = write!(buffer, "{value}");
        self.element(name, &buffer);
    }

    /// Writes an element holding `true` or `false`.
    pub fn element_bool(&mut self, name: &str, value: bool) {
        self.element(name, if value { "true" } else { "false" });
    }

    /// How many bytes have been written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Finishes the document, closing anything still open.
    ///
    /// Closing rather than refusing: an encoder that returns early on an error path would
    /// otherwise produce a truncated document, and a truncated document is the one failure a
    /// client cannot distinguish from a dropped connection.
    #[must_use]
    pub fn finish(mut self) -> String {
        while !self.open.is_empty() {
            self.close();
        }
        self.out
    }
}

/// Removes the leading [`DECLARATION`], if the bytes open with exactly it.
///
/// For the response whose head is committed before its outcome is known: the declaration goes out
/// with the head, so the document that follows must not carry a second one — and a second `<?xml …?>`
/// in the middle of a body is not something a parser recovers from, it is a syntax error reported
/// instead of the outcome the body was carrying.
///
/// Exact-prefix only, and deliberately not a "skip any prolog" scanner: this crate wrote the bytes
/// it is asked to trim, so the one form it emits is the one form worth recognising. Anything else is
/// left alone rather than guessed at, because trimming the wrong prefix truncates a document.
#[must_use]
pub fn strip_declaration(document: &[u8]) -> &[u8] {
    match document.strip_prefix(DECLARATION.as_bytes()) {
        Some(rest) => rest,
        None => document,
    }
}

/// Escapes element text.
///
/// The three that change meaning, plus a carriage return. `\r` is escaped because an XML parser
/// normalises a literal one to `\n` on the way in, so a value containing one would not survive a
/// round trip — and object keys and user metadata do contain them.
///
/// A `"` is deliberately **not** escaped: it changes nothing inside character data, and the one
/// member whose wire form carries quotation marks reaches
/// [`XmlWriter::element_quoting`]/[`escape_text_and_quotes`] instead.
pub fn escape_text(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            other => out.push(representable(other)),
        }
    }
}

/// Everything [`escape_text`] escapes, plus the double quote as `&quot;`.
///
/// Not a stricter-is-safer variant to reach for by default: the two produce different bytes for
/// the same value, both spellings are pinned by conformance cases, and picking this one for a
/// member S3 spells with a literal `"` is as much a wire defect as the other way round.
pub fn escape_text_and_quotes(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            other => out.push(representable(other)),
        }
    }
}

/// Escapes an attribute value: everything [`escape_text`] escapes, plus the quotes and the
/// whitespace an attribute-value normalisation would otherwise collapse.
pub fn escape_attribute(value: &str, out: &mut String) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            other => out.push(representable(other)),
        }
    }
}

/// The character itself, unless XML 1.0 cannot represent it at all.
///
/// The three escaping passes above answer "how is this character spelled"; this answers the prior
/// question of whether it has a spelling. A character that does not is replaced by
/// [`UNREPRESENTABLE`] rather than written raw, because writing it raw produces a document that is
/// not well-formed — and a client's parser rejects the whole document, so one such character in
/// one member hides every other value in the response behind a syntax error.
///
/// This is the writer half of one predicate. [`crate::read`] refuses a *request* carrying such a
/// character, so no caller-supplied value reaches this function; what does reach it is a value a
/// backend already holds, which the gateway did not choose and cannot refuse without hiding the
/// siblings. The listing path never reaches it either: a stored key that fails the predicate is
/// percent-encoded before it is escaped (`ObjectKey::needs_url_encoding`, `c-list-0035`).
fn representable(character: char) -> char {
    if is_xml_char(character) { character } else { UNREPRESENTABLE }
}

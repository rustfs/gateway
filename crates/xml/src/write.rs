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
//! # Why every text node escapes both quotes
//!
//! A `"` and a `'` are legal unescaped in XML character data, so escaping them is a choice, and
//! S3's choice is observable: its serializer writes `&quot;` and `&apos;` in every text node, not
//! only in an entity tag. An anonymous ListObjectsV2 against a public AWS Open Data bucket
//! (<https://unidata-nexrad-level2.s3.amazonaws.com/?list-type=2&max-keys=1&prefix=a%22b%27c%3Cd%3Ee%26f>,
//! recorded on rustfs/gateway#13) echoes the prefix `a"b'c<d>e&f` as
//! `<Prefix>a&quot;b&apos;c&lt;d&gt;e&amp;f</Prefix>`, and a listing of the same bucket carries
//! `<ETag>&quot;…&quot;</ETag>` and `<Delimiter>&quot;</Delimiter>`. One escaping for every text
//! node is also what a client can rely on: every XML parser reads both spellings as the same
//! character, so matching S3's bytes costs no client anything. The one exception is the legacy
//! RustFS layout ([`XmlWriter::legacy_layout`]): legacy RustFS writes an entity tag's quotes as
//! they are, so [`XmlWriter::entity_tag_element`] does too there, and every other text node keeps
//! both quotes escaped, as legacy RustFS escapes them.

use core::fmt::Write as _;

use crate::chars::{UNREPRESENTABLE, is_xml_char};

/// The XML declaration S3 puts at the head of every response body.
pub const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// [`DECLARATION`] without its line end: the declaration legacy RustFS writes, the root element
/// straight after it ([`XmlWriter::legacy_layout`]).
pub const COMPACT_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

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
    /// Whether this document is written in legacy RustFS's layout ([`XmlWriter::legacy_layout`]).
    legacy: bool,
    /// The open elements whose children are written in a declared order, innermost last.
    orders: Vec<ChildOrder>,
}

/// One open element whose children are rearranged into a declared order when it closes.
#[derive(Debug)]
struct ChildOrder {
    /// How many elements were open, this one included, when the order was declared.
    depth: usize,
    /// The child element names, in the order they are written.
    names: &'static [&'static str],
    /// Where each child written so far starts, and its rank in `names`.
    children: Vec<(usize, usize)>,
}

impl XmlWriter {
    /// A writer with the XML declaration already written.
    #[must_use]
    pub fn document() -> Self {
        Self {
            out: String::from(DECLARATION),
            ..Self::default()
        }
    }

    /// Writes this document in the layout legacy RustFS writes its answers in, or not: the XML
    /// declaration with no line end after it, and each element's children in the order
    /// [`Self::order_children`] declares for it. Off by default, where the declaration ends with a
    /// line end, as AWS writes it, and children keep the order they are written in.
    ///
    /// Decided before the root is opened; once anything follows the declaration the layout is
    /// fixed, and a later call changes nothing.
    pub fn legacy_layout(&mut self, on: bool) {
        if !self.open.is_empty() || self.out.len() > DECLARATION.len() {
            return;
        }
        self.legacy = on;
        if self.out == DECLARATION || self.out == COMPACT_DECLARATION {
            self.out.clear();
            self.out.push_str(if on { COMPACT_DECLARATION } else { DECLARATION });
        }
    }

    /// Declares the order the children of the element open now are written in, by name: when it
    /// closes they are rearranged so that every child named earlier in `names` comes before every
    /// child named later, keeping the order they were written in among children of one name, and
    /// every child `names` does not list after all of them. Honoured only under
    /// [`Self::legacy_layout`]; otherwise, and with no element open, it changes nothing.
    pub fn order_children(&mut self, names: &'static [&'static str]) {
        if !self.legacy || self.open.is_empty() {
            return;
        }
        let depth = self.open.len();
        if self.orders.last().is_some_and(|order| order.depth == depth) {
            self.orders.pop();
        }
        self.orders.push(ChildOrder {
            depth,
            names,
            children: Vec::new(),
        });
    }

    /// Records that a child named `name` starts here, when the element open now orders its children.
    fn child_starts(&mut self, name: &str) {
        let depth = self.open.len();
        let start = self.out.len();
        if let Some(order) = self.orders.last_mut()
            && order.depth == depth
        {
            let rank = order
                .names
                .iter()
                .position(|listed| *listed == name)
                .unwrap_or(order.names.len());
            order.children.push((start, rank));
        }
    }

    /// Rearranges the children of the element about to close, when it orders them.
    fn arrange_children(&mut self) {
        let depth = self.open.len();
        if !self.orders.last().is_some_and(|order| order.depth == depth) {
            return;
        }
        let Some(order) = self.orders.pop() else {
            return;
        };
        let Some(&(first, _)) = order.children.first() else {
            return;
        };
        let end = self.out.len();
        let mut segments: Vec<(usize, usize, usize)> = order
            .children
            .iter()
            .enumerate()
            .map(|(index, &(start, rank))| {
                let stop = order.children.get(index + 1).map_or(end, |&(next, _)| next);
                (rank, start, stop)
            })
            .collect();
        segments.sort_by_key(|&(rank, _, _)| rank);
        let mut arranged = String::with_capacity(end - first);
        for (_, start, stop) in segments {
            arranged.push_str(self.out.get(start..stop).unwrap_or_default());
        }
        self.out.truncate(first);
        self.out.push_str(&arranged);
    }

    /// Writes an entity-tag element. Under [`Self::legacy_layout`] the tag's double quotes are
    /// written as they are, as legacy RustFS writes an entity tag, and everything else is escaped
    /// as element text; otherwise it is [`Self::element`], quotes escaped as in every other text
    /// node.
    pub fn entity_tag_element(&mut self, name: &str, text: &str) {
        if !self.legacy {
            self.element(name, text);
            return;
        }
        self.child_starts(name);
        self.out.push('<');
        self.out.push_str(name);
        self.out.push('>');
        for (index, part) in text.split('"').enumerate() {
            if index > 0 {
                self.out.push('"');
            }
            escape_text(part, &mut self.out);
        }
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }

    /// [`Self::entity_tag_element`], only when the text is non-empty.
    pub fn entity_tag_element_if_present(&mut self, name: &str, text: &str) {
        if !text.is_empty() {
            self.entity_tag_element(name, text);
        }
    }

    /// A writer with no declaration, for a fragment.
    #[must_use]
    pub fn fragment() -> Self {
        Self::default()
    }

    /// Opens an element, optionally carrying the S3 namespace.
    pub fn open(&mut self, name: &str, xmlns: Option<&str>) {
        self.child_starts(name);
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
        self.child_starts(name);
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
        self.arrange_children();
        let Some(name) = self.open.pop() else {
            return;
        };
        self.out.push_str("</");
        self.out.push_str(&name);
        self.out.push('>');
    }

    /// Writes a complete element with text content, escaped.
    pub fn element(&mut self, name: &str, text: &str) {
        self.child_starts(name);
        self.out.push('<');
        self.out.push_str(name);
        self.out.push('>');
        escape_text(text, &mut self.out);
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
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

    /// Appends one independently validated element fragment.
    ///
    /// Runtime extension vtables encode into a scratch writer first. Parsing the finished fragment
    /// here prevents a faulty extension from injecting an unbalanced close into its static parent.
    ///
    /// # Errors
    ///
    /// [`crate::XmlError`] when `fragment` is not one bounded, well-formed XML element.
    pub fn append_fragment(&mut self, fragment: &str) -> Result<(), crate::XmlError> {
        crate::parse(fragment.as_bytes())?;
        // A fragment's element is a child like any other; its name is not read back, so it ranks
        // after every child an order names.
        self.child_starts("");
        self.out.push_str(fragment);
        Ok(())
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

/// Removes the leading [`COMPACT_DECLARATION`] a [`XmlWriter::legacy_layout`] document opens with,
/// if the bytes open with exactly it; [`strip_declaration`] for the other layout.
///
/// A separate function rather than a second form [`strip_declaration`] accepts: a caller names the
/// layout it wrote, and the default layout's trimming stays exactly the one form it always was. The
/// default declaration opens with the same bytes and then a line end; it is not this form, and is
/// left alone.
#[must_use]
pub fn strip_compact_declaration(document: &[u8]) -> &[u8] {
    match document.strip_prefix(COMPACT_DECLARATION.as_bytes()) {
        Some(rest) if !rest.starts_with(b"\n") => rest,
        _ => document,
    }
}

/// Escapes element text.
///
/// The five characters XML predefines an entity for, plus a carriage return. `\r` is escaped
/// because an XML parser normalises a literal one to `\n` on the way in, so a value containing one
/// would not survive a round trip — and object keys and user metadata do contain them. Both quotes
/// are escaped because S3 escapes them in every text node; see the module documentation.
pub fn escape_text(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#13;"),
            other => out.push(representable(other)),
        }
    }
}

/// Escapes an attribute value: everything [`escape_text`] escapes, plus the line feed and tab an
/// attribute-value normalisation would otherwise collapse into spaces.
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
/// The two escaping passes above answer "how is this character spelled"; this answers the prior
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

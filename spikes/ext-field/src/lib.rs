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

//! Single-field evidence for an XML extension vtable.
//!
//! This crate measures whether one static parent codec can round-trip one dialect field without
//! naming its Rust type. It is not a production codec and has no downstream runtime consumer;
//! ADR-0007 consumes its test and measurement results.

mod del_marker_expiration;
mod lifecycle_rule;
mod policy;

use std::fmt;

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

pub use del_marker_expiration::DelMarkerExpiration;
pub use lifecycle_rule::LifecycleRule;
pub use policy::{CodecPolicy, ExtField, ExtVTable, Extensions, UnknownPolicy, XmlLimits};

/// The quick-xml writer used by extension vtables.
pub type XmlWriter = quick_xml::Writer<Vec<u8>>;

/// The resource limit that rejected a document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// The request body exceeded the configured byte cap.
    Bytes,
    /// Element nesting exceeded the configured maximum depth.
    Depth,
    /// The number of start or empty elements exceeded the configured maximum.
    Elements,
}

/// A fail-closed error from the spike XML codec or extension registry.
#[derive(Debug)]
pub enum XmlError {
    /// Reading the bounded request body failed.
    Io(String),
    /// quick-xml or UTF-8 rejected the document.
    Xml(String),
    /// The document carried a DOCTYPE declaration.
    Doctype,
    /// A configured byte, depth, or element-count limit was exceeded.
    LimitExceeded(LimitKind),
    /// The active unknown policy rejected an element.
    UnknownElement(String),
    /// Two extension types claimed the same parent and local element name.
    DuplicateRegistration {
        /// The parent shape claimed by both registrations.
        parent: &'static str,
        /// The local element name claimed by both registrations.
        local_name: &'static str,
    },
    /// A vtable's TypeId did not match the value stored in Extensions.
    TypeMismatch,
    /// A required known member was absent.
    MissingRequired(&'static str),
    /// An extension codec failed.
    Extension(String),
}

impl fmt::Display for XmlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "failed to read XML body: {message}"),
            Self::Xml(message) => write!(formatter, "invalid XML: {message}"),
            Self::Doctype => formatter.write_str("DOCTYPE is forbidden"),
            Self::LimitExceeded(kind) => write!(formatter, "XML {kind:?} limit exceeded"),
            Self::UnknownElement(name) => write!(formatter, "unknown XML element {name}"),
            Self::DuplicateRegistration { parent, local_name } => {
                write!(formatter, "duplicate extension registration for {parent}.{local_name}")
            }
            Self::TypeMismatch => formatter.write_str("extension TypeId did not match its stored value"),
            Self::MissingRequired(name) => write!(formatter, "missing required XML member {name}"),
            Self::Extension(message) => write!(formatter, "extension codec failed: {message}"),
        }
    }
}

impl std::error::Error for XmlError {}

/// One allocation-owned event returned by [`XmlReader`].
#[derive(Debug, Eq, PartialEq)]
pub enum XmlEvent {
    /// A start tag with its local name.
    Start(String),
    /// A self-closing tag with its local name.
    Empty(String),
    /// An end tag with its local name.
    End(String),
    /// Text or CDATA decoded as UTF-8.
    Text(String),
    /// End of input.
    Eof,
}

/// A quick-xml pull reader that enforces byte, depth, element-count, and DOCTYPE limits.
pub struct XmlReader<'input> {
    inner: quick_xml::Reader<&'input [u8]>,
    limits: XmlLimits,
    depth: u16,
    elements: u32,
}

impl<'input> XmlReader<'input> {
    pub(crate) fn new(input: &'input [u8], limits: XmlLimits) -> Result<Self, XmlError> {
        if input.len() > limits.max_bytes {
            return Err(XmlError::LimitExceeded(LimitKind::Bytes));
        }
        Ok(Self {
            inner: quick_xml::Reader::from_reader(input),
            limits,
            depth: 0,
            elements: 0,
        })
    }

    /// Reads the next material event while enforcing all configured limits.
    pub fn next_event(&mut self) -> Result<XmlEvent, XmlError> {
        loop {
            let event = self.inner.read_event().map_err(|error| XmlError::Xml(error.to_string()))?;
            match event {
                Event::Start(start) => {
                    self.note_element(true)?;
                    return Ok(XmlEvent::Start(decode_name(start.name().as_ref())?));
                }
                Event::Empty(empty) => {
                    self.note_element(false)?;
                    return Ok(XmlEvent::Empty(decode_name(empty.name().as_ref())?));
                }
                Event::End(end) => {
                    if self.depth == 0 {
                        return Err(XmlError::Xml("end tag without an open element".to_owned()));
                    }
                    self.depth -= 1;
                    return Ok(XmlEvent::End(decode_name(end.name().as_ref())?));
                }
                Event::Text(text) => {
                    return text
                        .decode()
                        .map(|value| XmlEvent::Text(value.into_owned()))
                        .map_err(|error| XmlError::Xml(error.to_string()));
                }
                Event::CData(text) => {
                    return text
                        .decode()
                        .map(|value| XmlEvent::Text(value.into_owned()))
                        .map_err(|error| XmlError::Xml(error.to_string()));
                }
                Event::DocType(_) => return Err(XmlError::Doctype),
                Event::Eof => return Ok(XmlEvent::Eof),
                Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::GeneralRef(_) => {}
            }
        }
    }

    fn note_element(&mut self, remains_open: bool) -> Result<(), XmlError> {
        self.elements = self
            .elements
            .checked_add(1)
            .ok_or(XmlError::LimitExceeded(LimitKind::Elements))?;
        if self.elements > self.limits.max_elements {
            return Err(XmlError::LimitExceeded(LimitKind::Elements));
        }
        let next_depth = self.depth.checked_add(1).ok_or(XmlError::LimitExceeded(LimitKind::Depth))?;
        if next_depth > self.limits.max_depth {
            return Err(XmlError::LimitExceeded(LimitKind::Depth));
        }
        if remains_open {
            self.depth = next_depth;
        }
        Ok(())
    }
}

fn decode_name(bytes: &[u8]) -> Result<String, XmlError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| XmlError::Xml(error.to_string()))
}

pub(crate) fn skip_element_content(reader: &mut XmlReader<'_>) -> Result<(), XmlError> {
    let mut nested = 0_u16;
    loop {
        match reader.next_event()? {
            XmlEvent::Start(_) => {
                nested = nested.checked_add(1).ok_or(XmlError::LimitExceeded(LimitKind::Depth))?;
            }
            XmlEvent::End(_) if nested == 0 => return Ok(()),
            XmlEvent::End(_) => nested -= 1,
            XmlEvent::Eof => return Err(XmlError::Xml("unexpected EOF in unknown element".to_owned())),
            XmlEvent::Empty(_) | XmlEvent::Text(_) => {}
        }
    }
}

pub(crate) fn read_text_content(reader: &mut XmlReader<'_>, end_name: &str) -> Result<String, XmlError> {
    let mut value = String::new();
    loop {
        match reader.next_event()? {
            XmlEvent::Text(text) => value.push_str(&text),
            XmlEvent::End(name) if name == end_name => return Ok(value),
            XmlEvent::End(name) => return Err(XmlError::Xml(format!("expected </{end_name}>, found </{name}>"))),
            XmlEvent::Start(name) | XmlEvent::Empty(name) => return Err(XmlError::UnknownElement(name)),
            XmlEvent::Eof => return Err(XmlError::Xml(format!("unexpected EOF in <{end_name}>"))),
        }
    }
}

/// Writes one start/text/end element without exposing a partially finished result.
pub fn write_text_element(writer: &mut XmlWriter, name: &str, value: &str) -> Result<(), XmlError> {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .map_err(|error| XmlError::Xml(error.to_string()))?;
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .map_err(|error| XmlError::Xml(error.to_string()))?;
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|error| XmlError::Xml(error.to_string()))
}

pub(crate) fn write_start(writer: &mut XmlWriter, name: &str) -> Result<(), XmlError> {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .map_err(|error| XmlError::Xml(error.to_string()))
}

pub(crate) fn write_end(writer: &mut XmlWriter, name: &str) -> Result<(), XmlError> {
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|error| XmlError::Xml(error.to_string()))
}

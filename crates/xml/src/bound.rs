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

//! Schema-bound reading: a request document read against the shape its operation declares, the
//! way legacy RustFS reads one (rustfs/gateway#1078).
//!
//! Responsible for: [`read`], which walks the document's events against a caller-supplied
//! [`Document`] and either refuses it or returns the tree the generated decoders read — holding
//! exactly the members the shape declares, each scalar in the spelling the caller's scalar reading
//! returned — and the shape vocabulary ([`Document`], [`Shape`], [`Member`], [`Scalar`]).
//! NOT responsible for: any element name or member (the caller's schema supplies every one), the
//! grammar of a scalar (the caller's `scalar` reading), or mapping a refusal onto an S3 error code.
//! Upstream: `quick-xml`. Downstream: `rustfs-gateway-core`'s codec, which selects this reading
//! for a deployment that answers request documents as legacy RustFS does.
//!
//! # What "the way legacy RustFS reads one" means
//!
//! [`crate::parse`] reads any well-formed document into a tree and leaves every question about its
//! members to the decoder, which skips an element it does not know and keeps the first of a
//! repeated one. Legacy RustFS reads a request document member by member instead, and differs in
//! ways a client can observe and storage can record:
//!
//! * an element outside a shape's members is skipped only where the shape is an operation's whole
//!   document (the payload root) and inside a wrapped list; everywhere else it refuses the document;
//! * a member that is not a repeated list may appear once, and a second occurrence refuses the
//!   document;
//! * an element name is compared as the document spells it, prefix included, and never checked
//!   against the `Name` production — `<s3:Rule>` is not `Rule`, and an unknown name is unknown
//!   whatever its spelling;
//! * a scalar member holds text only — a child element inside it refuses the document — and its
//!   text is the character data exactly as written (no line-end normalisation), with entity and
//!   character references resolved and CDATA sections, comments and processing instructions left
//!   out entirely;
//! * attributes are read on one element only, a structure's declared type attribute (`xsi:type` on
//!   `Grantee`), matched by its literal spelling rather than by namespace;
//! * text between the members of a structure, and after the root, is ignored.
//!
//! Every refusal is the legacy stack's `MalformedXML`; the caller decides the code.
//!
//! # What this reader keeps from [`crate::parse`], deliberately
//!
//! The limits (body bytes, depth, element count) and three refusals legacy RustFS does not make:
//! a `DOCTYPE` (the entity-expansion entry point, refused rather than trusted to a dependency), a
//! character XML 1.0 cannot represent (stored, it makes every later read of the document
//! unparseable), and a document that is not UTF-8. They are registered divergences, not parity.

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::chars::{is_xml_char, is_xml_representable};
use crate::error::XmlError;
use crate::read::{XmlAttribute, XmlLimits, XmlNode};

/// One request document's shape: its root names and every structure it can reach.
#[derive(Debug)]
pub struct Document {
    /// The root element names the document accepts, the canonical one first.
    pub roots: &'static [&'static str],
    /// Every structure the document reaches; index 0 is the root's.
    pub shapes: &'static [Shape],
    /// What an empty body is.
    pub empty: EmptyBody,
}

/// What an empty body is to a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyBody {
    /// A missing body: [`BoundRefusal::Missing`].
    Missing,
    /// A document the reading refuses, like any other that ends before its root.
    Refused,
    /// No document: legacy RustFS reads the document as optional and hands its handler none, and
    /// the handler refuses the request itself: [`BoundRefusal::Absent`].
    Absent,
}

/// One structure.
#[derive(Debug)]
pub struct Shape {
    /// The structure's name, for diagnostics only.
    pub name: &'static str,
    /// Whether the members are a set of optional and required members or a choice of one.
    pub content: Content,
    /// The one attribute this structure's element carries a member in, when it has one.
    pub attribute: Option<Attribute>,
}

/// What a structure's element holds.
#[derive(Debug)]
pub enum Content {
    /// Members, and what an element outside them is.
    Members {
        /// The members, each once.
        members: &'static [Member],
        /// What an element outside `members` is.
        unknown: Unknown,
    },
    /// Exactly one of these members: a structural union.
    Choice(&'static [Member]),
}

/// What an element outside a structure's members is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// Skipped with everything inside it: the structure is an operation's whole document.
    Skip,
    /// The document is refused.
    Refuse,
}

/// One member of a structure.
#[derive(Debug)]
pub struct Member {
    /// The element name, exactly as the document must spell it.
    pub element: &'static str,
    /// How many elements the member is carried by.
    pub arity: Arity,
    /// What one element of the member holds.
    pub value: Value,
    /// Whether the document is refused without it.
    pub required: bool,
    /// Whether the member reaches the returned tree. A member the legacy stack reads and no decoder
    /// of this gateway does is validated and then left out.
    pub kept: bool,
}

/// How many elements a member is carried by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arity {
    /// One element; a second refuses the document.
    One,
    /// The element repeats directly under the structure (a flattened list).
    Repeated,
    /// One wrapper element; each entry is an element of this name inside it, and any other element
    /// inside it is skipped.
    Wrapped(&'static str),
}

/// What one element of a member holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// Text, read through the caller's scalar reading for this kind.
    Text(Scalar),
    /// The structure at this index of [`Document::shapes`].
    Shape(u16),
}

/// The kind of text a scalar member holds. The grammar of each is the caller's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    /// Any text.
    Text,
    /// A 32-bit integer.
    Integer,
    /// A 64-bit integer.
    Long,
    /// A boolean.
    Boolean,
    /// An RFC 3339 date-time.
    DateTime,
    /// An HTTP date.
    HttpDate,
    /// An entity tag.
    EntityTag,
}

/// The attribute a structure's element carries one member in.
#[derive(Debug)]
pub struct Attribute {
    /// The attribute's spelling on the wire, prefix included, compared literally.
    pub key: &'static str,
    /// The local name the returned tree carries it under.
    pub name: &'static str,
    /// The namespace the returned tree carries it in.
    pub namespace: &'static str,
    /// Whether the document is refused without it.
    pub required: bool,
}

/// Why a scalar reading refused a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarRefusal {
    /// The value is not one the member's grammar reads.
    Unreadable,
    /// The value reads, but it is one the caller cannot carry exactly.
    Uncarriable,
}

/// Why [`read`] refused a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundRefusal {
    /// The reading refuses the document; legacy RustFS answers it `MalformedXML`.
    Document(Reason),
    /// A lexical refusal or a limit shared with [`crate::parse`].
    Xml(XmlError),
    /// The body is empty and the document calls that a missing body ([`EmptyBody::Missing`]).
    Missing,
    /// The body is empty and the document calls that no document at all ([`EmptyBody::Absent`]):
    /// the caller answers what legacy RustFS's handler answers a request without one.
    Absent,
    /// The document reads, but it holds a value the caller cannot carry exactly: a scalar the
    /// scalar reading called uncarriable. Reported only for a document the reading otherwise
    /// accepts, so a document legacy RustFS refuses is refused as that first. (An optional wrapped
    /// list's empty wrapper is carried: the caller holds such a list's presence apart from its
    /// entries, rustfs/gateway#1078.)
    Uncarriable,
}

/// What made the reading refuse a document. Diagnostics only: every one is `MalformedXML`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The root element is not one the document accepts.
    Root,
    /// An element outside a structure's members, where the structure refuses one.
    UnknownElement,
    /// A second element of a member that may appear once.
    Repeated,
    /// A required member or attribute is absent.
    Missing,
    /// An element inside a scalar member, or a second member of a choice.
    UnexpectedElement,
    /// A choice with no member.
    EmptyChoice,
    /// The document ended inside an element, or before one.
    Truncated,
    /// Content after the root element.
    Trailing,
    /// A scalar value its grammar does not read.
    Unreadable,
    /// An attribute that does not parse.
    Attribute,
    /// A reference that names neither a predefined entity nor a character.
    Reference,
}

impl From<XmlError> for BoundRefusal {
    fn from(error: XmlError) -> Self {
        Self::Xml(error)
    }
}

/// The scalar reading a caller supplies: a raw value in, the spelling the returned tree carries out.
pub type ScalarReading<'a> = &'a dyn Fn(Scalar, &str) -> Result<String, ScalarRefusal>;

/// Reads `body` against `document`, as legacy RustFS reads a request document.
///
/// # Errors
///
/// [`BoundRefusal`]: the reading refused the document, a limit was crossed, or the scalar reading
/// found a value it cannot carry.
pub fn read(body: &[u8], document: &Document, limits: XmlLimits, scalar: ScalarReading<'_>) -> Result<XmlNode, BoundRefusal> {
    if body.len() > limits.max_body_bytes() {
        return Err(XmlError::BodyTooLarge.into());
    }
    if body.is_empty() {
        return match document.empty {
            EmptyBody::Missing => Err(BoundRefusal::Missing),
            EmptyBody::Refused => refuse(Reason::Truncated),
            EmptyBody::Absent => Err(BoundRefusal::Absent),
        };
    }
    let text = core::str::from_utf8(body).map_err(|_| XmlError::NotUtf8)?;
    let mut walker = Walker {
        reader: Reader::from_str(text),
        peeked: None,
        pending_end: false,
        depth: 0,
        elements: 0,
        uncarriable: false,
        limits,
        document,
        scalar,
    };
    walker.reader.config_mut().trim_text(false);
    walker.reader.config_mut().check_end_names = true;
    let tree = walker.document_root()?;
    if walker.uncarriable {
        return Err(BoundRefusal::Uncarriable);
    }
    Ok(tree)
}

/// One event of the document, as the reading sees it.
enum Token<'a> {
    Start(BytesStart<'a>),
    End,
    Text(String),
    Eof,
}

struct Walker<'a, 'f> {
    reader: Reader<&'a [u8]>,
    peeked: Option<Token<'a>>,
    /// An empty element was handed out as a start; its end is the next token.
    pending_end: bool,
    depth: usize,
    elements: usize,
    /// A value the caller cannot carry was read; reported once the whole document has read.
    uncarriable: bool,
    limits: XmlLimits,
    document: &'f Document,
    scalar: ScalarReading<'f>,
}

fn refuse<T>(reason: Reason) -> Result<T, BoundRefusal> {
    Err(BoundRefusal::Document(reason))
}

/// The element name as the document spelled it. Every delimiter `quick-xml` cuts a name at is
/// ASCII, so a name sliced out of UTF-8 input is UTF-8.
fn name_of<'n>(start: &'n BytesStart<'_>) -> Result<&'n str, BoundRefusal> {
    core::str::from_utf8(start.name().into_inner()).map_err(|_| BoundRefusal::Xml(XmlError::NotUtf8))
}

impl<'a> Walker<'a, '_> {
    /// The next token, with comments, processing instructions, declarations and CDATA sections
    /// left out and every reference resolved into text.
    fn fetch(&mut self) -> Result<Token<'a>, BoundRefusal> {
        if self.pending_end {
            self.pending_end = false;
            return Ok(Token::End);
        }
        loop {
            match self.reader.read_event() {
                Err(_) => return Err(XmlError::Malformed.into()),
                Ok(Event::Start(start)) => return Ok(Token::Start(start)),
                Ok(Event::Empty(start)) => {
                    self.pending_end = true;
                    return Ok(Token::Start(start));
                }
                Ok(Event::End(_)) => return Ok(Token::End),
                Ok(Event::Text(text)) => {
                    let raw = text.decode().map_err(|_| XmlError::NotUtf8)?;
                    if !is_xml_representable(&raw) {
                        return Err(XmlError::ForbiddenCharacter.into());
                    }
                    return Ok(Token::Text(raw.into_owned()));
                }
                Ok(Event::GeneralRef(reference)) => {
                    let name = reference.decode().map_err(|_| XmlError::NotUtf8)?;
                    return Ok(Token::Text(resolve(&name)?.to_string()));
                }
                Ok(Event::DocType(_)) => return Err(XmlError::DocTypeDeclaration.into()),
                Ok(Event::Eof) => return Ok(Token::Eof),
                Ok(_) => {}
            }
        }
    }

    fn peek(&mut self) -> Result<&Token<'a>, BoundRefusal> {
        if self.peeked.is_none() {
            self.peeked = Some(self.fetch()?);
        }
        Ok(self.peeked.get_or_insert(Token::Eof))
    }

    fn next(&mut self) -> Result<Token<'a>, BoundRefusal> {
        match self.peeked.take() {
            Some(token) => Ok(token),
            None => self.fetch(),
        }
    }

    /// Counts an element that was just opened against the depth and element ceilings.
    fn enter(&mut self) -> Result<(), BoundRefusal> {
        self.elements = self.elements.saturating_add(1);
        if self.elements > self.limits.max_elements() {
            return Err(XmlError::TooManyElements.into());
        }
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.limits.max_depth() {
            return Err(XmlError::TooDeep.into());
        }
        Ok(())
    }

    /// The end of the element just read: text before it is ignored, an element or the end of the
    /// document refuses it.
    fn close(&mut self) -> Result<(), BoundRefusal> {
        loop {
            match self.next()? {
                Token::Text(_) => {}
                Token::End => {
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(());
                }
                Token::Start(_) => return refuse(Reason::UnexpectedElement),
                Token::Eof => return refuse(Reason::Truncated),
            }
        }
    }

    fn document_root(&mut self) -> Result<XmlNode, BoundRefusal> {
        let start = loop {
            match self.next()? {
                Token::Text(_) => {}
                Token::Start(start) => break start,
                Token::End => return refuse(Reason::Root),
                Token::Eof => return refuse(Reason::Truncated),
            }
        };
        let name = name_of(&start)?;
        let Some(root) = self.document.roots.iter().find(|root| **root == name) else {
            return refuse(Reason::Root);
        };
        self.enter()?;
        let node = self.structure(root, 0, &start)?;
        self.close()?;
        loop {
            match self.next()? {
                Token::Text(_) => {}
                Token::Eof => return Ok(node),
                Token::Start(_) | Token::End => return refuse(Reason::Trailing),
            }
        }
    }

    /// One structure's element, already opened: its attribute and its content, not its end.
    fn structure(&mut self, name: &str, index: u16, start: &BytesStart<'_>) -> Result<XmlNode, BoundRefusal> {
        let shape = self
            .document
            .shapes
            .get(usize::from(index))
            .ok_or(BoundRefusal::Document(Reason::UnknownElement))?;
        let mut node = XmlNode {
            name: name.to_owned(),
            ..XmlNode::default()
        };
        let mut attribute_value = None;
        if let Some(attribute) = &shape.attribute {
            attribute_value = self.typed_attribute(start, attribute)?;
        }
        match &shape.content {
            Content::Members { members, unknown } => self.members(members, *unknown, &mut node)?,
            Content::Choice(members) => self.choice(members, &mut node)?,
        }
        if let Some(attribute) = &shape.attribute {
            match attribute_value {
                Some(value) => node.attributes.push(XmlAttribute {
                    name: attribute.name.to_owned(),
                    namespace: Some(attribute.namespace.into()),
                    value,
                }),
                None if attribute.required => return refuse(Reason::Missing),
                None => {}
            }
        }
        Ok(node)
    }

    /// The declared attribute of a structure's element, matched by its literal spelling. Every
    /// attribute of that element is parsed, and one that does not parse refuses the document.
    fn typed_attribute(&self, start: &BytesStart<'_>, attribute: &Attribute) -> Result<Option<String>, BoundRefusal> {
        let mut found = None;
        let mut count = 0usize;
        for parsed in start.attributes() {
            let parsed = parsed.map_err(|_| BoundRefusal::Document(Reason::Attribute))?;
            count = count.saturating_add(1);
            if count > self.limits.max_attributes_per_element() {
                return Err(XmlError::TooManyAttributes.into());
            }
            if parsed.value.as_ref().len() > self.limits.max_attribute_bytes() {
                return Err(XmlError::AttributeTooLong.into());
            }
            if parsed.key.as_ref() == attribute.key.as_bytes() {
                let value = parsed
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map_err(|_| BoundRefusal::Document(Reason::Attribute))?;
                if !is_xml_representable(&value) {
                    return Err(XmlError::ForbiddenCharacter.into());
                }
                found = Some(value.into_owned());
            }
        }
        Ok(found)
    }

    /// A structure's members, up to (not including) its end.
    fn members(&mut self, members: &[Member], unknown: Unknown, node: &mut XmlNode) -> Result<(), BoundRefusal> {
        let mut seen = vec![false; members.len()];
        loop {
            let start = match self.peek()? {
                Token::Start(_) => match self.next()? {
                    Token::Start(start) => start,
                    _ => return refuse(Reason::Truncated),
                },
                Token::Text(_) => {
                    self.next()?;
                    continue;
                }
                Token::End | Token::Eof => break,
            };
            self.enter()?;
            let name = name_of(&start)?;
            match members.iter().position(|member| member.element == name) {
                Some(index) => {
                    let member = &members[index];
                    if member.arity != Arity::Repeated && seen[index] {
                        return refuse(Reason::Repeated);
                    }
                    seen[index] = true;
                    let child = match member.arity {
                        Arity::One | Arity::Repeated => self.value(member.element, member.value, &start)?,
                        Arity::Wrapped(entry) => self.wrapped(member.element, entry, member.value)?,
                    };
                    if member.kept {
                        node.children.push(child);
                    }
                }
                None => match unknown {
                    Unknown::Skip => self.skip()?,
                    Unknown::Refuse => return refuse(Reason::UnknownElement),
                },
            }
            self.close()?;
        }
        if members.iter().zip(&seen).any(|(member, seen)| member.required && !seen) {
            return refuse(Reason::Missing);
        }
        Ok(())
    }

    /// A structural union's one member, up to (not including) its end.
    fn choice(&mut self, members: &[Member], node: &mut XmlNode) -> Result<(), BoundRefusal> {
        loop {
            match self.next()? {
                Token::Text(_) => {}
                Token::Start(start) => {
                    self.enter()?;
                    let name = name_of(&start)?;
                    let Some(member) = members.iter().find(|member| member.element == name) else {
                        return refuse(Reason::UnknownElement);
                    };
                    let child = self.value(member.element, member.value, &start)?;
                    node.children.push(child);
                    return self.close();
                }
                Token::End | Token::Eof => return refuse(Reason::EmptyChoice),
            }
        }
    }

    /// One element of a member, already opened, up to (not including) its end.
    fn value(&mut self, element: &str, value: Value, start: &BytesStart<'_>) -> Result<XmlNode, BoundRefusal> {
        match value {
            Value::Shape(index) => self.structure(element, index, start),
            Value::Text(kind) => {
                let raw = self.text()?;
                let text = match (self.scalar)(kind, &raw) {
                    Ok(text) => text,
                    Err(ScalarRefusal::Unreadable) => return refuse(Reason::Unreadable),
                    Err(ScalarRefusal::Uncarriable) => {
                        self.uncarriable = true;
                        raw
                    }
                };
                Ok(XmlNode {
                    name: element.to_owned(),
                    text,
                    ..XmlNode::default()
                })
            }
        }
    }

    /// A wrapped list's entries, up to (not including) the wrapper's end.
    fn wrapped(&mut self, element: &str, entry: &str, value: Value) -> Result<XmlNode, BoundRefusal> {
        let mut wrapper = XmlNode {
            name: element.to_owned(),
            ..XmlNode::default()
        };
        loop {
            let start = match self.peek()? {
                Token::Start(_) => match self.next()? {
                    Token::Start(start) => start,
                    _ => return refuse(Reason::Truncated),
                },
                Token::Text(_) => {
                    self.next()?;
                    continue;
                }
                Token::End | Token::Eof => return Ok(wrapper),
            };
            self.enter()?;
            if name_of(&start)? == entry {
                let item = self.value(entry, value, &start)?;
                wrapper.children.push(item);
            } else {
                self.skip()?;
            }
            self.close()?;
        }
    }

    /// A scalar's text, up to (not including) its end. An element inside it refuses the document.
    fn text(&mut self) -> Result<String, BoundRefusal> {
        let mut text: Option<String> = None;
        loop {
            match self.peek()? {
                Token::Text(_) => {
                    if let Token::Text(chunk) = self.next()? {
                        text.get_or_insert_with(String::new).push_str(&chunk);
                    }
                }
                Token::End => return Ok(text.unwrap_or_default()),
                Token::Start(_) => return refuse(Reason::UnexpectedElement),
                Token::Eof => return refuse(Reason::Truncated),
            }
        }
    }

    /// Everything inside an element being skipped, up to (not including) its end.
    fn skip(&mut self) -> Result<(), BoundRefusal> {
        let mut depth = 0usize;
        loop {
            match self.peek()? {
                Token::Start(_) => {
                    self.next()?;
                    self.enter()?;
                    depth = depth.saturating_add(1);
                }
                Token::End => {
                    if depth == 0 {
                        return Ok(());
                    }
                    self.next()?;
                    self.depth = self.depth.saturating_sub(1);
                    depth -= 1;
                }
                Token::Text(_) => {
                    self.next()?;
                }
                Token::Eof => return refuse(Reason::Truncated),
            }
        }
    }
}

/// A reference, resolved as legacy RustFS resolves one: the five predefined entities by name, and
/// a character reference in decimal or in hexadecimal after a lower-case `x`, to a character XML
/// 1.0 admits. Anything else refuses the document.
fn resolve(name: &str) -> Result<char, BoundRefusal> {
    let predefined = match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    };
    if let Some(character) = predefined {
        return Ok(character);
    }
    let number = name.strip_prefix('#').filter(|number| !number.is_empty());
    let code = number.and_then(|number| match number.strip_prefix('x') {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => number.parse::<u32>().ok(),
    });
    match code.and_then(char::from_u32) {
        Some(character) if is_xml_char(character) => Ok(character),
        _ => refuse(Reason::Reference),
    }
}

#[cfg(test)]
#[path = "bound_tests.rs"]
mod tests;

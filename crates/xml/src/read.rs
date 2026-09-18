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

//! The reader every generated decoder reads an S3 request body through.
//!
//! Responsible for: turning a buffered body into a bounded tree of [`XmlNode`], applying XML 1.0
//! line-end normalisation, and refusing every construct an S3 request body has no use for.
//! NOT responsible for: knowing which elements an operation expects, or what any of them mean.
//! Upstream: `quick-xml`. Downstream: `rustfs-gateway-core`'s generated codecs.
//!
//! # Why a tree and not a pull parser
//!
//! S3 request bodies are small, bounded by a per-operation cap the IR already carries, and their
//! members are order-independent on the way in. A pull parser would push that ordering question
//! into every generated decoder; a tree answers it once, here.
//!
//! # What is refused, and why refusing beats ignoring
//!
//! A `DOCTYPE` is refused rather than skipped. `quick-xml` does not expand entities, so skipping
//! it would be safe *today* — which is exactly the kind of safety that disappears in a dependency
//! bump nobody reviews as a protocol change. Depth and element count are bounded for the same
//! reason: the cap on body bytes does not bound the tree a body can describe.
//!
//! # Why attributes carry a namespace and not a prefix
//!
//! Exactly one member of the supported S3 surface is written as an XML attribute — the
//! `<Grantee>` discriminator, which AWS sends as `xsi:type` beside an `xmlns:xsi` declaration on
//! that same element. A reader that stored the literal string `xsi:type` would be answering a
//! question about a document-local alias: another client may bind the same namespace to `xs`, and
//! a document that writes `xsi:type` while binding `xsi` to nothing has not written that
//! attribute at all. So declarations are resolved as the document is walked, each attribute keeps
//! the namespace its prefix resolved to, and the declarations themselves are not attributes of
//! the element they appear on.

use std::sync::Arc;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::chars::{is_xml_char, is_xml_name, is_xml_representable};
use crate::error::XmlError;

/// How many buffered bytes one XML request body may hold.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// How deep a request body may nest.
///
/// The deepest supported shapes use only a small fraction of this budget; the separate ceiling
/// prevents a compact body from manufacturing an arbitrarily deep tree.
pub const MAX_DEPTH: usize = 32;

/// How many elements a request body may hold.
///
/// A `DeleteObjects` request is the largest legitimate one, and AWS caps it at a thousand keys of
/// up to five members each. The ceiling is that, with room to answer over it with a protocol error
/// rather than a parse error.
pub const MAX_ELEMENTS: usize = 100_000;

/// How many attributes one element may carry.
pub const MAX_ATTRIBUTES_PER_ELEMENT: usize = 32;

/// How many bytes one attribute value may carry.
pub const MAX_ATTRIBUTE_BYTES: usize = 4 * 1024;

/// Independent allocation ceilings applied while an XML request body is parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmlLimits {
    max_body_bytes: usize,
    max_depth: usize,
    max_elements: usize,
    max_attributes_per_element: usize,
    max_attribute_bytes: usize,
}

impl XmlLimits {
    /// The bounded S3 request-body posture.
    pub const S3: Self = Self {
        max_body_bytes: MAX_BODY_BYTES,
        max_depth: MAX_DEPTH,
        max_elements: MAX_ELEMENTS,
        max_attributes_per_element: MAX_ATTRIBUTES_PER_ELEMENT,
        max_attribute_bytes: MAX_ATTRIBUTE_BYTES,
    };

    /// Builds a limit set, rejecting zero rather than treating it as unlimited.
    #[must_use]
    pub const fn new(
        max_body_bytes: usize,
        max_depth: usize,
        max_elements: usize,
        max_attributes_per_element: usize,
        max_attribute_bytes: usize,
    ) -> Option<Self> {
        if max_body_bytes == 0
            || max_depth == 0
            || max_elements == 0
            || max_attributes_per_element == 0
            || max_attribute_bytes == 0
        {
            None
        } else {
            Some(Self {
                max_body_bytes,
                max_depth,
                max_elements,
                max_attributes_per_element,
                max_attribute_bytes,
            })
        }
    }

    /// Maximum buffered document size in bytes.
    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        self.max_body_bytes
    }

    /// Maximum nesting depth.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Maximum element count.
    #[must_use]
    pub const fn max_elements(self) -> usize {
        self.max_elements
    }

    /// Maximum attributes on one element.
    #[must_use]
    pub const fn max_attributes_per_element(self) -> usize {
        self.max_attributes_per_element
    }

    /// Maximum bytes in one attribute value.
    #[must_use]
    pub const fn max_attribute_bytes(self) -> usize {
        self.max_attribute_bytes
    }
}

/// One attribute of a parsed element.
///
/// The prefix is not kept. A prefix is a document-local alias for a namespace and two documents
/// that mean the same thing routinely spell it differently — `xsi:type` and `xs:type` are the same
/// attribute when the two prefixes are bound to the same URI, and `xsi:type` in two documents is
/// *not* the same attribute if only one of them declared `xsi`. So what is kept is what the
/// document actually said: the local name and the namespace the prefix resolved to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XmlAttribute {
    /// Local attribute name, namespace prefix stripped.
    pub name: String,
    /// The namespace the prefix resolved to. `None` only for an unprefixed attribute, which is
    /// in no namespace at all.
    ///
    /// An attribute whose prefix no enclosing element bound is not stored — see [`XmlNode`].
    ///
    /// Shared rather than copied, and that is a bound and not a micro-optimisation: a declaration
    /// is written once and may be referenced by every attribute under it, so a per-attribute
    /// `String` would let a one-megabyte body naming a four-kilobyte namespace once and using it
    /// a hundred thousand times allocate four hundred megabytes. The document bounds the bytes it
    /// contains; it must not bound the bytes it can make this side hold.
    pub namespace: Option<Arc<str>>,
    /// Attribute value, entity references already resolved.
    pub value: String,
}

/// One element of a parsed body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XmlNode {
    /// Local element name, namespace prefix stripped.
    pub name: String,
    /// Concatenated text content, entity references already resolved.
    pub text: String,
    /// Attributes, in document order, with namespace declarations already applied and removed.
    ///
    /// A prefixed attribute whose prefix no enclosing element bound is **absent** rather than
    /// present in no namespace. The two are not the same thing and collapsing them is what would
    /// let `<Grantee xsi:type="Group">` with no `xmlns:xsi` be read as the attribute AWS sends;
    /// an undeclared prefix is a namespace-well-formedness error, and this reader's answer to it
    /// is that the document did not write that attribute.
    pub attributes: Vec<XmlAttribute>,
    /// Child elements, in document order.
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    /// The value of the unprefixed attribute with this name.
    ///
    /// Deliberately does not match a prefixed attribute of the same local name: an unprefixed
    /// attribute is in no namespace at all, and answering `xsi:type` to a caller that asked for
    /// `type` is the confusion this crate keeps the namespace for.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.namespace.is_none() && attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }

    /// The value of the attribute in this namespace with this local name.
    #[must_use]
    pub fn attribute_ns(&self, namespace: &str, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.namespace.as_deref() == Some(namespace) && attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }

    /// The first child with this local name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.name == name)
    }

    /// The text of the first child with this local name.
    #[must_use]
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.as_str())
    }

    /// Every child with this local name, in document order.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |child| child.name == name)
    }
}

/// Parses a buffered body into its root element.
///
/// # Errors
///
/// [`XmlError`], one variant per refusal. No variant carries a fragment of the input.
pub fn parse(body: &[u8]) -> Result<XmlNode, XmlError> {
    parse_with_limits(body, XmlLimits::S3)
}

/// Parses a buffered body under an explicit, non-zero limit set.
///
/// # Errors
///
/// [`XmlError`], one variant per refusal. No variant carries a fragment of the input.
pub fn parse_with_limits(body: &[u8], limits: XmlLimits) -> Result<XmlNode, XmlError> {
    if body.len() > limits.max_body_bytes {
        return Err(XmlError::BodyTooLarge);
    }
    let text = core::str::from_utf8(body).map_err(|_| XmlError::NotUtf8)?;
    let mut reader = Reader::from_str(text);
    let config = reader.config_mut();
    config.trim_text(false);
    config.check_end_names = true;

    let mut stack: Vec<XmlNode> = Vec::new();
    // One frame per *open* element, holding the `xmlns` bindings that element declared. An
    // element's own declarations are in scope for its own attributes — AWS declares `xmlns:xsi`
    // on the same `<Grantee>` that carries `xsi:type` — so a frame is pushed before that
    // element's attributes are resolved, and popped when the element closes.
    let mut scopes: Vec<Vec<(String, Arc<str>)>> = Vec::new();
    let mut root: Option<XmlNode> = None;
    let mut elements = 0usize;

    loop {
        match reader.read_event() {
            Err(_) => return Err(XmlError::Malformed),
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => return Err(XmlError::DocTypeDeclaration),
            Ok(Event::Start(start)) => {
                elements = elements.saturating_add(1);
                if elements > limits.max_elements {
                    return Err(XmlError::TooManyElements);
                }
                if stack.len() >= limits.max_depth {
                    return Err(XmlError::TooDeep);
                }
                scopes.push(declarations(&start, limits)?);
                let attributes = read_attributes(&start, limits, &scopes)?;
                stack.push(XmlNode {
                    name: local_name(start.name().as_ref())?,
                    attributes,
                    ..XmlNode::default()
                });
            }
            Ok(Event::Empty(empty)) => {
                elements = elements.saturating_add(1);
                if elements > limits.max_elements {
                    return Err(XmlError::TooManyElements);
                }
                // `<X/>` is the same element as `<X></X>` and sits at the same depth. Checking only
                // the paired spelling let every tree nest one level past the ceiling through a
                // self-closed leaf (rustfs/backlog#1766, found by the `xml_parse` property).
                if stack.len() >= limits.max_depth {
                    return Err(XmlError::TooDeep);
                }
                // An empty element declares and closes in one event, so its frame lives exactly as
                // long as the resolution of its own attributes.
                scopes.push(declarations(&empty, limits)?);
                let attributes = read_attributes(&empty, limits, &scopes)?;
                scopes.pop();
                let node = XmlNode {
                    name: local_name(empty.name().as_ref())?,
                    attributes,
                    ..XmlNode::default()
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => {
                        if root.is_some() {
                            return Err(XmlError::Malformed);
                        }
                        root = Some(node);
                    }
                }
            }
            Ok(Event::End(_)) => {
                scopes.pop();
                let Some(node) = stack.pop() else {
                    return Err(XmlError::Malformed);
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => {
                        if root.is_some() {
                            return Err(XmlError::Malformed);
                        }
                        root = Some(node);
                    }
                }
            }
            Ok(Event::Text(chunk)) => {
                let Some(node) = stack.last_mut() else {
                    continue;
                };
                // XML 1.0 §2.11 applies before parsing: a literal CR and CRLF each become one LF.
                // `xml10_content` performs that byte-level normalisation without touching a CR
                // introduced later by a numeric character reference.
                let decoded = chunk.xml10_content().map_err(|_| XmlError::UnsupportedEntity)?;
                node.text.push_str(representable(decoded.as_ref())?);
            }
            Ok(Event::CData(chunk)) => {
                let Some(node) = stack.last_mut() else {
                    continue;
                };
                // CDATA is part of the same parsed entity and follows the same §2.11 line-end
                // rule; only entity expansion differs from ordinary text.
                let decoded = chunk.xml10_content().map_err(|_| XmlError::NotUtf8)?;
                node.text.push_str(representable(decoded.as_ref())?);
            }
            // `quick-xml` hands every `&…;` back verbatim instead of expanding it. That is the
            // property this crate relies on: the five XML predefines and numeric character
            // references are resolved here, by name, and every other reference is refused. A
            // parser that expanded them would decide what `&xxe;` means before this code runs.
            Ok(Event::GeneralRef(reference)) => {
                let Some(node) = stack.last_mut() else {
                    continue;
                };
                let resolved = match reference.resolve_char_ref() {
                    Ok(Some(character)) => character,
                    Ok(None) => {
                        let name = reference.decode().map_err(|_| XmlError::NotUtf8)?;
                        predefined_entity(name.as_ref()).ok_or(XmlError::UnsupportedEntity)?
                    }
                    Err(_) => return Err(XmlError::UnsupportedEntity),
                };
                if !is_xml_char(resolved) {
                    return Err(XmlError::ForbiddenCharacter);
                }
                node.text.push(resolved);
            }
            Ok(_) => {}
        }
    }

    if !stack.is_empty() {
        return Err(XmlError::Malformed);
    }
    root.ok_or(XmlError::Empty)
}

/// The `xmlns` bindings one element declares, and the ceilings every attribute is held to.
///
/// The limits are applied here rather than in [`read_attributes`] so that they are applied once
/// per attribute and to *every* attribute — a declaration is an attribute on the wire, and a
/// ceiling that skipped them would let a document carry an unbounded number of `xmlns:` pairs.
fn declarations(start: &BytesStart<'_>, limits: XmlLimits) -> Result<Vec<(String, Arc<str>)>, XmlError> {
    let mut declared = Vec::new();
    let mut count = 0usize;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| XmlError::Malformed)?;
        count = count.saturating_add(1);
        if count > limits.max_attributes_per_element {
            return Err(XmlError::TooManyAttributes);
        }
        if attribute.value.as_ref().len() > limits.max_attribute_bytes {
            return Err(XmlError::AttributeTooLong);
        }
        let (prefix, local) = split_name(attribute.key.as_ref())?;
        // `xmlns:p="…"` binds `p`; a bare `xmlns="…"` binds the *default* element namespace, and
        // an unprefixed attribute is in no namespace whatever the default is. Only the first
        // form is a binding this crate can be asked about.
        if prefix.as_deref() == Some("xmlns") {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| XmlError::UnsupportedEntity)?;
            declared.push((local, Arc::from(representable(value.as_ref())?)));
        }
    }
    Ok(declared)
}

/// One element's attributes, with prefixes resolved against the scopes in force and the namespace
/// declarations themselves removed.
fn read_attributes(
    start: &BytesStart<'_>,
    limits: XmlLimits,
    scopes: &[Vec<(String, Arc<str>)>],
) -> Result<Vec<XmlAttribute>, XmlError> {
    let mut out = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| XmlError::Malformed)?;
        if attribute.value.as_ref().len() > limits.max_attribute_bytes {
            return Err(XmlError::AttributeTooLong);
        }
        let (prefix, name) = split_name(attribute.key.as_ref())?;
        if prefix.as_deref() == Some("xmlns") || (prefix.is_none() && name == "xmlns") {
            continue;
        }
        let namespace = match prefix {
            // An undeclared prefix names a namespace the document never bound. Storing it with
            // no namespace would make it indistinguishable from the unprefixed attribute of the
            // same local name, so it is dropped instead.
            Some(prefix) => match resolve(scopes, &prefix) {
                Some(namespace) => Some(namespace),
                None => continue,
            },
            None => None,
        };
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| XmlError::UnsupportedEntity)?;
        representable(value.as_ref())?;
        out.push(XmlAttribute {
            name,
            namespace,
            value: value.into_owned(),
        });
    }
    Ok(out)
}

/// The namespace a prefix is bound to by the innermost element that binds it.
fn resolve(scopes: &[Vec<(String, Arc<str>)>], prefix: &str) -> Option<Arc<str>> {
    scopes.iter().rev().find_map(|frame| {
        frame
            .iter()
            .find(|(bound, _)| bound == prefix)
            .map(|(_, namespace)| namespace.clone())
    })
}

/// An attribute name split into its prefix, when it has one, and its local part.
fn split_name(raw: &[u8]) -> Result<(Option<String>, String), XmlError> {
    let name = qualified_name(raw)?;
    match name.split_once(':') {
        Some((prefix, local)) => Ok((Some(prefix.to_owned()), local.to_owned())),
        None => Ok((None, name.to_owned())),
    }
}

/// A tag or attribute name as the wire spelled it, refused unless it is an XML `Name` whose
/// colons, if any, each have a non-empty part on both sides.
///
/// `quick-xml` hands over whatever stood between `<` and the first whitespace, so this is the one
/// place the `Name` production is checked for every element and attribute (rustfs/gateway#743).
/// The production admits a colon anywhere, but `:a`, `a:` and `a::b` would leave [`local_name`]
/// or [`split_name`] with an empty prefix or local part — a nameless element the writer would
/// spell `<>` — so those are refused with it. `a:b:c` stays accepted as it always was, with `c` as
/// its local name: this crate is not a namespace processor for element names.
fn qualified_name(raw: &[u8]) -> Result<&str, XmlError> {
    let name = representable(core::str::from_utf8(raw).map_err(|_| XmlError::NotUtf8)?)?;
    if !is_xml_name(name) || name.split(':').any(str::is_empty) {
        return Err(XmlError::InvalidName);
    }
    Ok(name)
}

/// The five entities XML defines without a DTD. There is no sixth, by design.
fn predefined_entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

/// The local part of an element name, with any namespace prefix dropped.
///
/// S3 clients send both the prefixed and the unprefixed spelling of the same body, and a decoder
/// that matched on the full name would accept one and refuse the other.
fn local_name(raw: &[u8]) -> Result<String, XmlError> {
    let name = qualified_name(raw)?;
    Ok(name.rsplit(':').next().unwrap_or(name).to_owned())
}

/// The text, unless it carries a character XML 1.0 cannot represent.
///
/// The reader is the ingress for this rule, and it is the ingress for a reason: `quick-xml` does
/// not validate the `Char` production, so a raw `U+0001` inside an element is parsed happily,
/// reaches a decoder as an ordinary string member, and is stored. Whatever writes it back out then
/// produces a document that is not well-formed, and a conforming client rejects the whole
/// response — one such value hides every other value in the same document.
///
/// Refusing here rather than per member is what makes the rule uniform: every generated decoder of
/// an XML body already funnels through [`parse_with_limits`], so an operation that gains a string
/// member gains the refusal with it, and there is no per-operation call an author can forget. The
/// same predicate is what [`crate::write`] cannot emit, so the refused set and the un-writable set
/// are the same set by construction.
///
/// Borrowing rather than rewriting: the value is either usable as it stands or refused. A reader
/// that silently repaired the document would accept a request whose echo does not match what was
/// sent.
fn representable(text: &str) -> Result<&str, XmlError> {
    if is_xml_representable(text) {
        Ok(text)
    } else {
        Err(XmlError::ForbiddenCharacter)
    }
}

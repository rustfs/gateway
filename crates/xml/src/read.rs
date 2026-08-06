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
//! Responsible for: turning a buffered body into a bounded tree of [`XmlNode`], and refusing
//! every construct an S3 request body has no use for.
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

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::XmlError;

/// How deep a request body may nest.
///
/// The deepest shape in the supported surface is a list of structures inside the root, which is
/// three. Sixteen leaves room for a family that has not landed yet without leaving room for a
/// body whose only purpose is its depth.
pub const MAX_DEPTH: usize = 16;

/// How many elements a request body may hold.
///
/// A `DeleteObjects` request is the largest legitimate one, and AWS caps it at a thousand keys of
/// up to five members each. The ceiling is that, with room to answer over it with a protocol error
/// rather than a parse error.
pub const MAX_ELEMENTS: usize = 32_768;

/// One element of a parsed body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XmlNode {
    /// Local element name, namespace prefix stripped.
    pub name: String,
    /// Concatenated text content, entity references already resolved.
    pub text: String,
    /// Child elements, in document order.
    pub children: Vec<XmlNode>,
}

impl XmlNode {
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
    let text = core::str::from_utf8(body).map_err(|_| XmlError::NotUtf8)?;
    let mut reader = Reader::from_str(text);
    let config = reader.config_mut();
    config.trim_text(false);
    config.check_end_names = true;

    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root: Option<XmlNode> = None;
    let mut elements = 0usize;

    loop {
        match reader.read_event() {
            Err(_) => return Err(XmlError::Malformed),
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => return Err(XmlError::DocTypeDeclaration),
            Ok(Event::Start(start)) => {
                elements = elements.saturating_add(1);
                if elements > MAX_ELEMENTS {
                    return Err(XmlError::TooManyElements);
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlError::TooDeep);
                }
                stack.push(XmlNode {
                    name: local_name(start.name().as_ref())?,
                    ..XmlNode::default()
                });
            }
            Ok(Event::Empty(empty)) => {
                elements = elements.saturating_add(1);
                if elements > MAX_ELEMENTS {
                    return Err(XmlError::TooManyElements);
                }
                let node = XmlNode {
                    name: local_name(empty.name().as_ref())?,
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
                let decoded = chunk.decode().map_err(|_| XmlError::UnsupportedEntity)?;
                node.text.push_str(decoded.as_ref());
            }
            Ok(Event::CData(chunk)) => {
                let Some(node) = stack.last_mut() else {
                    continue;
                };
                let decoded = core::str::from_utf8(chunk.as_ref()).map_err(|_| XmlError::NotUtf8)?;
                node.text.push_str(decoded);
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
    let name = core::str::from_utf8(raw).map_err(|_| XmlError::NotUtf8)?;
    Ok(name.rsplit(':').next().unwrap_or(name).to_owned())
}

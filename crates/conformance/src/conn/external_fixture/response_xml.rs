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

//! The one reader of fixture-control response documents.
//!
//! Responsible for: strictly reading a small S3 response document and returning, for every element
//! at a named path, its direct children's names and text. It refuses rather than guesses: a body
//! that is not well-formed, has another root, a DOCTYPE, an undeclared entity, a malformed
//! attribute or comment, or text beside elements is `None`.
//! NOT responsible for: what a caller requires of those children (`multipart`, `versioned`,
//! `writes`), or judging a case's response body (`crate::xml`).
//! Upstream: fixture controls; downstream: `quick_xml`.

/// The direct children of one element: local name and text, `None` for a child with element content.
pub(super) type Children = Vec<(Vec<u8>, Option<String>)>;

struct Open {
    name: Vec<u8>,
    text: String,
    has_elements: bool,
}

/// The children of every element whose local-name path from the root is `path`, in document order.
pub(super) fn element_texts(body: &[u8], path: &[&[u8]]) -> Option<Vec<Children>> {
    use quick_xml::{Reader, escape::resolve_predefined_entity, events::Event};
    let mut reader = Reader::from_reader(body);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut stack: Vec<Open> = Vec::new();
    let mut items: Vec<Children> = Vec::new();
    let mut root_seen = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(element) => {
                for attribute in element.attributes() {
                    attribute.ok()?;
                }
                let name = element.local_name().as_ref().to_vec();
                match stack.last_mut() {
                    None if root_seen || path.first() != Some(&name.as_slice()) => return None,
                    None => root_seen = true,
                    Some(parent) => parent.has_elements = true,
                }
                stack.push(Open {
                    name,
                    text: String::new(),
                    has_elements: false,
                });
                if stack.len() == path.len() && stack.iter().zip(path).all(|(open, step)| open.name == *step) {
                    items.push(Vec::new());
                }
            }
            Event::End(_) => {
                let open = stack.pop()?;
                if open.has_elements && !open.text.trim().is_empty() {
                    return None;
                }
                let at_item = stack.len() == path.len() && stack.iter().zip(path).all(|(open, step)| open.name == *step);
                if at_item {
                    let text = (!open.has_elements).then_some(open.text);
                    items.last_mut()?.push((open.name, text));
                }
            }
            Event::Text(text) => {
                let text = text.xml10_content().ok()?;
                match stack.last_mut() {
                    Some(open) => open.text.push_str(&text),
                    None if text.trim().is_empty() => {}
                    None => return None,
                }
            }
            Event::CData(text) => stack.last_mut()?.text.push_str(&text.xml10_content().ok()?),
            Event::GeneralRef(reference) => {
                let open = stack.last_mut()?;
                match reference.resolve_char_ref().ok()? {
                    Some(character) => open.text.push(character),
                    None => open.text.push_str(resolve_predefined_entity(&reference.decode().ok()?)?),
                }
            }
            Event::Decl(_) if root_seen => return None,
            Event::DocType(_) => return None,
            Event::Eof => return (root_seen && stack.is_empty()).then_some(items),
            _ => {}
        }
    }
}

/// The texts of every child named `name` across `children`.
pub(super) fn texts<'a>(children: &'a Children, name: &'a [u8]) -> impl Iterator<Item = Option<&'a str>> + 'a {
    children
        .iter()
        .filter(move |(child, _)| child == name)
        .map(|(_, text)| text.as_deref())
}

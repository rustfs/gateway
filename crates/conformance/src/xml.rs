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

//! The response-body scanner the expectation engine needs.
//!
//! Responsible for: reading enough structure out of an S3 XML body to support `expect.body.xml`,
//! `expect.body.redact`, `expect.capture.xml_text` and `expect.error.code` — the root element and
//! its namespace, the order of the root's children, how empty elements were rendered, and the text
//! of a named element. It is a scanner over the bytes as they arrived, deliberately not a
//! document model: the assertions here are about the wire form, and a parse-then-compare would
//! erase the very differences the corpus exists to catch.
//! NOT responsible for: entity expansion, DTDs, namespaces beyond the literal `xmlns` attribute,
//! or producing XML.
//! Upstream: nothing. Downstream: `crate::expect`.

/// The placeholder that replaces a redacted element's text on both sides of a comparison.
pub const REDACTED: &str = "__REDACTED__";

/// How an empty element was written on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyElementStyle {
    /// `<Prefix/>`
    SelfClosing,
    /// `<Prefix></Prefix>`
    Paired,
}

/// A start tag as it appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartTag {
    /// Element name, including any prefix.
    pub name: String,
    /// The raw attribute text between the name and the closing bracket.
    pub attributes: String,
    /// Whether the tag closed itself.
    pub self_closing: bool,
}

impl StartTag {
    /// Returns the value of an attribute, if present. Values may be single- or double-quoted.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<String> {
        let mut rest = self.attributes.as_str();
        while let Some(position) = rest.find(name) {
            let after = &rest[position + name.len()..];
            let trimmed = after.trim_start();
            if let Some(value) = trimmed.strip_prefix('=') {
                let value = value.trim_start();
                let quote = value.chars().next()?;
                if quote == '"' || quote == '\'' {
                    let value = &value[1..];
                    let end = value.find(quote)?;
                    return Some(value[..end].to_owned());
                }
            }
            rest = &rest[position + name.len()..];
        }
        None
    }
}

/// Whether the body opens with an XML declaration.
#[must_use]
pub fn has_declaration(body: &str) -> bool {
    body.trim_start().starts_with("<?xml")
}

/// The root element's start tag.
#[must_use]
pub fn root_tag(body: &str) -> Option<StartTag> {
    scan(body).into_iter().find_map(|event| match event {
        Event::Start(tag) => Some(StartTag::from(tag)),
        Event::End(_) => None,
    })
}

/// The names of the root element's direct children, in the order they appeared.
///
/// Repeated siblings appear once each time; callers that assert a relative order compare against
/// first occurrences.
#[must_use]
pub fn root_child_names(body: &str) -> Vec<String> {
    let mut depth = 0_usize;
    let mut names = Vec::new();
    for event in scan(body) {
        match event {
            Event::Start(tag) => {
                if depth == 1 {
                    names.push(tag.name.clone());
                }
                if !tag.self_closing {
                    depth += 1;
                }
            }
            Event::End(_) => depth = depth.saturating_sub(1),
        }
    }
    names
}

/// Every empty element in the body, paired with how it was written.
#[must_use]
pub fn empty_element_styles(body: &str) -> Vec<(String, EmptyElementStyle)> {
    let events = scan(body);
    let mut out = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let Event::Start(tag) = event else { continue };
        if tag.self_closing {
            out.push((tag.name.clone(), EmptyElementStyle::SelfClosing));
            continue;
        }
        // `<X></X>` with nothing between the two tags: the scanner records positions, so an
        // element whose close tag follows immediately had no children, and the raw slice between
        // them tells us whether it had text.
        if let Some(Event::End(name)) = events.get(index + 1)
            && name == &tag.name
            && tag.text_after.trim().is_empty()
        {
            out.push((tag.name.clone(), EmptyElementStyle::Paired));
        }
    }
    out
}

/// The text of the first element with this name, with entities left exactly as they arrived.
#[must_use]
pub fn first_element_text(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_owned())
}

/// Replaces the text of every named element with [`REDACTED`].
///
/// The element's presence and position survive, so a byte comparison still asserts them. Applied
/// to both sides of a comparison, which makes it idempotent on an expectation that already holds
/// the placeholder.
#[must_use]
pub fn redact(body: &str, names: &[&str]) -> String {
    let mut out = body.to_owned();
    for name in names {
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        let mut cursor = 0;
        let mut next = String::new();
        while let Some(offset) = out[cursor..].find(&open) {
            let start = cursor + offset + open.len();
            let Some(end_offset) = out[start..].find(&close) else { break };
            let end = start + end_offset;
            next.push_str(&out[cursor..start]);
            next.push_str(REDACTED);
            cursor = end;
        }
        next.push_str(&out[cursor..]);
        out = next;
    }
    out
}

#[derive(Debug, Clone)]
struct ScannedStart {
    name: String,
    attributes: String,
    self_closing: bool,
    /// The character data that immediately follows this tag, used to tell `<X></X>` from `<X>y</X>`.
    text_after: String,
}

#[derive(Debug, Clone)]
enum Event {
    Start(ScannedStart),
    End(String),
}

impl From<ScannedStart> for StartTag {
    fn from(value: ScannedStart) -> StartTag {
        StartTag {
            name: value.name,
            attributes: value.attributes,
            self_closing: value.self_closing,
        }
    }
}

fn scan(body: &str) -> Vec<Event> {
    let bytes: Vec<char> = body.chars().collect();
    let mut events = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != '<' {
            index += 1;
            continue;
        }
        // Declarations, comments and processing instructions carry no structure we assert on.
        if bytes[index..].starts_with(&['<', '?']) || bytes[index..].starts_with(&['<', '!']) {
            match find_char(&bytes, index, '>') {
                Some(end) => index = end + 1,
                None => break,
            }
            continue;
        }
        let Some(end) = find_char(&bytes, index, '>') else { break };
        let inner: String = bytes[index + 1..end].iter().collect();
        index = end + 1;
        let text_after: String = bytes[index..].iter().take_while(|ch| **ch != '<').collect();
        if let Some(name) = inner.strip_prefix('/') {
            events.push(Event::End(name.trim().to_owned()));
            continue;
        }
        let self_closing = inner.ends_with('/');
        let inner = inner.strip_suffix('/').unwrap_or(&inner).trim();
        let (name, attributes) = match inner.find(char::is_whitespace) {
            Some(split) => (inner[..split].to_owned(), inner[split..].trim().to_owned()),
            None => (inner.to_owned(), String::new()),
        };
        events.push(Event::Start(ScannedStart {
            name,
            attributes,
            self_closing,
            text_after,
        }));
    }
    events
}

fn find_char(chars: &[char], from: usize, needle: char) -> Option<usize> {
    chars[from..].iter().position(|ch| *ch == needle).map(|offset| from + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        "<IsTruncated>true</IsTruncated><Name>conf-list</Name><Prefix></Prefix>",
        "<CommonPrefixes><Prefix>a/</Prefix></CommonPrefixes>",
        "<NextContinuationToken>opaque</NextContinuationToken></ListBucketResult>",
    );

    #[test]
    fn the_root_tag_and_its_namespace_are_read_from_the_wire() {
        let root = root_tag(LIST).expect("a root element");
        assert_eq!(root.name, "ListBucketResult");
        assert_eq!(root.attribute("xmlns").as_deref(), Some("http://s3.amazonaws.com/doc/2006-03-01/"));
    }

    #[test]
    fn a_declaration_is_detected() {
        assert!(has_declaration(LIST));
        assert!(!has_declaration("<Error><Code>x</Code></Error>"));
    }

    #[test]
    fn only_direct_children_of_the_root_are_listed() {
        let names = root_child_names(LIST);
        assert_eq!(names, vec!["IsTruncated", "Name", "Prefix", "CommonPrefixes", "NextContinuationToken"]);
    }

    #[test]
    fn a_paired_empty_element_is_distinguished_from_a_self_closing_one() {
        let paired = empty_element_styles("<a><Prefix></Prefix></a>");
        assert_eq!(paired, vec![("Prefix".to_owned(), EmptyElementStyle::Paired)]);
        let closed = empty_element_styles("<a><Prefix/></a>");
        assert_eq!(closed, vec![("Prefix".to_owned(), EmptyElementStyle::SelfClosing)]);
    }

    #[test]
    fn an_element_with_text_is_not_empty() {
        assert!(empty_element_styles("<a><Prefix>x</Prefix></a>").is_empty());
    }

    #[test]
    fn the_first_matching_element_text_wins() {
        assert_eq!(first_element_text(LIST, "Prefix").as_deref(), Some(""));
        assert_eq!(first_element_text(LIST, "Name").as_deref(), Some("conf-list"));
        assert_eq!(first_element_text(LIST, "Absent"), None);
    }

    #[test]
    fn redaction_keeps_the_element_and_replaces_only_the_text() {
        let redacted = redact(LIST, &["NextContinuationToken"]);
        assert!(redacted.contains("<NextContinuationToken>__REDACTED__</NextContinuationToken>"));
        assert!(!redacted.contains("opaque"));
    }

    #[test]
    fn redaction_is_idempotent_so_it_can_run_on_both_sides() {
        let once = redact(LIST, &["NextContinuationToken"]);
        assert_eq!(redact(&once, &["NextContinuationToken"]), once);
    }

    #[test]
    fn redaction_replaces_every_occurrence() {
        let body = "<a><Id>one</Id><Id>two</Id></a>";
        assert_eq!(redact(body, &["Id"]), "<a><Id>__REDACTED__</Id><Id>__REDACTED__</Id></a>");
    }
}

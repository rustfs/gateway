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

//! A structural comparison of two S3 XML documents, so one difference is named by its element
//! path instead of hiding every difference after the first differing byte.
//!
//! Responsible for: reading the small XML subset S3 answers use (elements, attributes, text; no
//! DTD, no comments, no CDATA) into a tree that keeps what a byte comparison would see — raw
//! attribute text, raw (still escaped) text, and whether an empty element was written `<X/>` or
//! `<X></X>` — and listing, per element path, the differences in attributes, spelling, child
//! order, child presence and text.
//! NOT responsible for: the byte comparison, which `encode.rs` still runs; a document this reader
//! refuses is compared as bytes only.
//! Upstream: `encode.rs`. Downstream: `encode.rs`.

/// One element as written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Element {
    name: String,
    /// Attributes in the order written, values raw.
    attributes: Vec<(String, String)>,
    /// Written `<X/>`.
    self_closing: bool,
    children: Vec<Element>,
    /// The text directly inside, raw — for an element with children, whatever sits between them.
    text: String,
}

/// One structural difference, at a path such as `ListBucketResult/Contents[1]/ETag`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum XmlDifference {
    /// The same children in another order: both orders, comma-joined.
    Order { path: String, gateway: String, s3s: String },
    /// Anything else at `path`: attributes, spelling, presence or text, rendered.
    Element { path: String, gateway: String, s3s: String },
}

struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn skip_whitespace(&mut self) {
        let skipped = self.rest().len() - self.rest().trim_start().len();
        self.at += skipped;
    }

    fn element(&mut self) -> Option<Element> {
        self.skip_whitespace();
        let rest = self.rest();
        if !rest.starts_with('<') || rest.starts_with("</") || rest.starts_with("<!") || rest.starts_with("<?") {
            return None;
        }
        let end = rest.find('>')?;
        let tag = &rest[1..end];
        let (tag, self_closing) = match tag.strip_suffix('/') {
            Some(tag) => (tag.trim_end(), true),
            None => (tag, false),
        };
        let (name, mut attribute_text) = tag.split_once(char::is_whitespace).unwrap_or((tag, ""));
        let mut attributes = Vec::new();
        loop {
            attribute_text = attribute_text.trim_start();
            if attribute_text.is_empty() {
                break;
            }
            let (key, value_part) = attribute_text.split_once('=')?;
            let value_part = value_part.strip_prefix('"')?;
            let close = value_part.find('"')?;
            attributes.push((key.trim().to_owned(), value_part[..close].to_owned()));
            attribute_text = &value_part[close + 1..];
        }
        self.at += end + 1;
        let mut element = Element {
            name: name.to_owned(),
            attributes,
            self_closing,
            children: Vec::new(),
            text: String::new(),
        };
        if self_closing {
            return Some(element);
        }
        let close = format!("</{name}>");
        loop {
            let rest = self.rest();
            if rest.starts_with(&close) {
                self.at += close.len();
                return Some(element);
            }
            if rest.starts_with('<') && !rest.starts_with("</") {
                element.children.push(self.element()?);
                continue;
            }
            let next = rest.find('<')?;
            element.text.push_str(&rest[..next]);
            self.at += next;
            if !self.rest().starts_with('<') {
                return None;
            }
            if self.rest().starts_with("</") && !self.rest().starts_with(&close) {
                return None;
            }
        }
    }
}

/// Reads one document's root element, or `None` when the text is not the subset this reads.
pub(crate) fn parse(text: &str) -> Option<Element> {
    let mut reader = Reader { text, at: 0 };
    let root = reader.element()?;
    reader.skip_whitespace();
    reader.rest().is_empty().then_some(root)
}

/// The names in `names` that `other` also has, in order, repeated neighbours collapsed.
fn common<'a>(names: &[&'a str], other: &[&str]) -> Vec<&'a str> {
    let mut kept: Vec<&'a str> = Vec::new();
    for name in names.iter().filter(|name| other.contains(name)) {
        if kept.last() != Some(name) {
            kept.push(name);
        }
    }
    kept
}

fn names(children: &[Element]) -> Vec<&str> {
    children.iter().map(|child| child.name.as_str()).collect()
}

fn spelled(element: &Element) -> String {
    let attributes: String = element
        .attributes
        .iter()
        .map(|(key, value)| format!(" {key}=\"{value}\""))
        .collect();
    if element.self_closing {
        format!("<{}{attributes}/>", element.name)
    } else {
        format!("<{}{attributes}>", element.name)
    }
}

/// Every difference between two elements at `path`, in document order.
pub(crate) fn differences(path: &str, gateway: &Element, s3s: &Element, out: &mut Vec<XmlDifference>) {
    if gateway.name != s3s.name {
        out.push(XmlDifference::Element {
            path: path.to_owned(),
            gateway: spelled(gateway),
            s3s: spelled(s3s),
        });
        return;
    }
    if gateway.attributes != s3s.attributes || gateway.self_closing != s3s.self_closing {
        out.push(XmlDifference::Element {
            path: path.to_owned(),
            gateway: spelled(gateway),
            s3s: spelled(s3s),
        });
    }
    if gateway.text != s3s.text {
        out.push(XmlDifference::Element {
            path: path.to_owned(),
            gateway: format!("{:?}", gateway.text),
            s3s: format!("{:?}", s3s.text),
        });
    }
    if gateway.children.is_empty() && s3s.children.is_empty() {
        return;
    }
    let (left, right) = (names(&gateway.children), names(&s3s.children));
    // The order of the children both sides wrote, repeated neighbours collapsed: a child only one
    // side has is a presence difference below, and must not hide a reorder of the rest.
    if common(&left, &right) != common(&right, &left) {
        out.push(XmlDifference::Order {
            path: path.to_owned(),
            gateway: left.join(","),
            s3s: right.join(","),
        });
    }
    // Pair children by name and occurrence, so an order difference does not also read as every
    // child being different.
    let mut seen: Vec<&str> = Vec::new();
    for name in left.iter().chain(&right) {
        if seen.contains(name) {
            continue;
        }
        seen.push(name);
        let ours: Vec<&Element> = gateway.children.iter().filter(|child| child.name == *name).collect();
        let theirs: Vec<&Element> = s3s.children.iter().filter(|child| child.name == *name).collect();
        let repeated = ours.len().max(theirs.len()) > 1;
        for index in 0..ours.len().max(theirs.len()) {
            let child_path = if repeated {
                format!("{path}/{name}[{index}]")
            } else {
                format!("{path}/{name}")
            };
            match (ours.get(index), theirs.get(index)) {
                (Some(left), Some(right)) => differences(&child_path, left, right, out),
                (left, right) => out.push(XmlDifference::Element {
                    path: child_path,
                    gateway: left.map_or_else(|| "<absent>".to_owned(), |element| spelled(element)),
                    s3s: right.map_or_else(|| "<absent>".to_owned(), |element| spelled(element)),
                }),
            }
        }
    }
}

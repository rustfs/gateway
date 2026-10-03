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

//! Every perturbation of a request document the parity proof sends both stacks: per element an
//! unknown child, a repetition, a removal and a prefixed name; per scalar the value spellings
//! legacy RustFS reads differently from a tree reader; and per document the prolog and root forms.
//!
//! Responsible for: [`perturbations`], which writes each variant back as bytes.
//! NOT responsible for: what either stack answers (`parity`).
//! Upstream: `rustfs_gateway_xml::parse` for the baseline's tree. Downstream: `parity`.

use rustfs_gateway_xml::XmlNode;

const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// One element of a baseline, with what a variant may replace its text by.
#[derive(Clone, Debug)]
struct Node {
    name: String,
    attributes: Vec<(String, String)>,
    /// Escaped on write.
    text: String,
    /// Written verbatim instead of `text`, when a variant needs markup inside a value.
    raw: Option<String>,
    children: Vec<Node>,
}

impl Node {
    fn of(tree: &XmlNode) -> Self {
        let mut attributes = Vec::new();
        for attribute in &tree.attributes {
            match attribute.namespace.as_deref() {
                Some(XSI) => {
                    attributes.push(("xmlns:xsi".to_owned(), XSI.to_owned()));
                    attributes.push((format!("xsi:{}", attribute.name), attribute.value.clone()));
                }
                _ => attributes.push((attribute.name.clone(), attribute.value.clone())),
            }
        }
        Self {
            name: tree.name.clone(),
            attributes,
            text: if tree.children.is_empty() {
                tree.text.clone()
            } else {
                String::new()
            },
            raw: None,
            children: tree.children.iter().map(Self::of).collect(),
        }
    }

    fn write(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (name, value) in &self.attributes {
            out.push(' ');
            out.push_str(name);
            out.push_str("=\"");
            escape(value, out);
            out.push('"');
        }
        out.push('>');
        match &self.raw {
            Some(raw) => out.push_str(raw),
            None => escape(&self.text, out),
        }
        for child in &self.children {
            child.write(out);
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }

    fn at(&mut self, path: &[usize]) -> &mut Node {
        match path.split_first() {
            None => self,
            Some((first, rest)) => self.children[*first].at(rest),
        }
    }

    fn paths(&self, prefix: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        out.push(prefix.clone());
        for (index, child) in self.children.iter().enumerate() {
            prefix.push(index);
            child.paths(prefix, out);
            prefix.pop();
        }
    }

    fn label(&self, path: &[usize]) -> String {
        let mut names = vec![self.name.clone()];
        let mut node = self;
        for index in path {
            node = &node.children[*index];
            names.push(format!("{}[{index}]", node.name));
        }
        names.join("/")
    }
}

fn escape(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
}

fn written(root: &Node) -> String {
    let mut out = String::new();
    root.write(&mut out);
    out
}

/// The text spellings of one scalar that legacy RustFS and a tree reader read differently, or that
/// sit at the edge of a scalar grammar: `(label, text, raw markup)`.
fn value_variants(text: &str) -> Vec<(&'static str, Option<String>, Option<String>)> {
    let first = text.chars().next().map_or(0x41, u32::from);
    vec![
        ("empty", Some(String::new()), None),
        ("leading-space", Some(format!(" {text}")), None),
        ("trailing-space", Some(format!("{text} ")), None),
        ("newline-around", Some(format!("\n{text}\n")), None),
        ("capitalised-true", Some("True".to_owned()), None),
        ("upper-true", Some("TRUE".to_owned()), None),
        ("upper-false", Some("FALSE".to_owned()), None),
        ("digits-then-text", Some("12abc".to_owned()), None),
        ("decimal", Some("30.5".to_owned()), None),
        ("lone-plus", Some("+".to_owned()), None),
        ("negative", Some("-1".to_owned()), None),
        ("zero", Some("0".to_owned()), None),
        ("overflow", Some("99999999999999999999".to_owned()), None),
        ("space-separated-date", Some("2026-01-02 03:04:05Z".to_owned()), None),
        ("offset-date", Some("2026-01-02T03:04:05+08:00".to_owned()), None),
        ("zero-offset-date", Some("2026-01-02T03:04:05-00:00".to_owned()), None),
        ("compact-offset-date", Some("2026-01-02T03:04:05+0800".to_owned()), None),
        ("leap-second", Some("2026-06-30T23:59:60Z".to_owned()), None),
        ("http-date", Some("Fri, 02 Jan 2026 03:04:05 GMT".to_owned()), None),
        ("obsolete-http-date", Some("Friday, 02-Jan-26 03:04:05 GMT".to_owned()), None),
        ("weak-tag", Some("W/\"abc\"".to_owned()), None),
        ("tag-with-quote", Some("a\"b".to_owned()), None),
        ("cdata", None, Some(format!("<![CDATA[{text}]]>"))),
        ("cdata-suffix", None, Some(format!("{text}<![CDATA[-x]]>"))),
        ("comment-inside", None, Some(format!("<!-- c -->{text}"))),
        ("carriage-return", Some(format!("{text}\r\n{text}")), None),
        (
            "character-reference",
            None,
            Some(format!("&#{first};{}", text.chars().skip(1).collect::<String>())),
        ),
        ("element-inside", None, Some(format!("{text}<b/>"))),
    ]
}

/// Every variant of `document`, labelled. The baseline itself is the first, labelled `baseline`.
///
/// # Panics
///
/// When the baseline does not parse as a tree: a baseline is a fixture this module wrote.
pub(super) fn perturbations(document: &str) -> Vec<(String, String)> {
    let tree = rustfs_gateway_xml::parse(document.as_bytes()).expect("a baseline parses");
    let root = Node::of(&tree);
    let mut paths = Vec::new();
    root.paths(&mut Vec::new(), &mut paths);
    let mut out = vec![("baseline".to_owned(), written(&root))];

    for path in &paths {
        let label = root.label(path);
        let mut unknown = root.clone();
        unknown.at(path).children.insert(
            0,
            Node {
                name: "FutureKnob".to_owned(),
                attributes: Vec::new(),
                text: "on".to_owned(),
                raw: None,
                children: Vec::new(),
            },
        );
        out.push((format!("unknown-child {label}"), written(&unknown)));

        let mut prefixed = root.clone();
        prefixed.attributes.push(("xmlns:s3".to_owned(), "urn:s3".to_owned()));
        let node = prefixed.at(path);
        node.name = format!("s3:{}", node.name);
        out.push((format!("prefixed {label}"), written(&prefixed)));

        if let Some((last, parent)) = path.split_last() {
            let mut repeated = root.clone();
            let copy = repeated.at(parent).children[*last].clone();
            repeated.at(parent).children.insert(last + 1, copy);
            out.push((format!("repeated {label}"), written(&repeated)));

            let mut removed = root.clone();
            removed.at(parent).children.remove(*last);
            out.push((format!("removed {label}"), written(&removed)));
        }

        if !root.clone().at(path).children.is_empty() {
            let mut emptied = root.clone();
            emptied.at(path).children.clear();
            out.push((format!("emptied {label}"), written(&emptied)));
        }

        if !root.clone().at(path).attributes.is_empty() {
            for (kind, attributes) in [
                ("no-attributes", Vec::new()),
                (
                    "other-prefix",
                    vec![
                        ("xmlns:x".to_owned(), XSI.to_owned()),
                        ("x:type".to_owned(), "Group".to_owned()),
                    ],
                ),
                ("undeclared-prefix", vec![("xsi:type".to_owned(), "Group".to_owned())]),
                (
                    "duplicate",
                    vec![
                        ("xsi:type".to_owned(), "Group".to_owned()),
                        ("xsi:type".to_owned(), "Group".to_owned()),
                    ],
                ),
                (
                    "empty-type",
                    vec![
                        ("xmlns:xsi".to_owned(), XSI.to_owned()),
                        ("xsi:type".to_owned(), String::new()),
                    ],
                ),
                (
                    "entity-in-type",
                    vec![
                        ("xmlns:xsi".to_owned(), XSI.to_owned()),
                        ("xsi:type".to_owned(), "Gr&amp;oup".to_owned()),
                    ],
                ),
            ] {
                let mut variant = root.clone();
                variant.at(path).attributes = attributes;
                out.push((format!("attributes {kind} {label}"), written(&variant)));
            }
        }

        if root.clone().at(path).children.is_empty() {
            let original = root.clone().at(path).text.clone();
            for (kind, text, raw) in value_variants(&original) {
                let mut variant = root.clone();
                let node = variant.at(path);
                if let Some(text) = text {
                    node.text = text;
                }
                node.raw = raw;
                out.push((format!("value {kind} {label}"), written(&variant)));
            }
        }
    }

    let body = written(&root);
    let name = &root.name;
    let inner = body
        .strip_prefix(&format!("<{name}"))
        .and_then(|rest| rest.strip_suffix(&format!("</{name}>")))
        .unwrap_or_default();
    for (label, document) in [
        ("declaration", format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}")),
        ("prolog-comment-and-pi", format!("<!-- c --><?pi x?>{body}")),
        ("byte-order-mark", format!("\u{feff}{body}")),
        ("leading-text", format!("text{body}")),
        ("trailing-text", format!("{body}text")),
        ("trailing-element", format!("{body}<Extra/>")),
        ("doctype", format!("<!DOCTYPE {name}>{body}")),
        ("prefixed-root", format!("<s3:{name} xmlns:s3=\"urn:s3\"{inner}</s3:{name}>")),
        (
            "default-namespace",
            format!("<{name} xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"{inner}</{name}>"),
        ),
        ("wrong-root", format!("<Wrong{inner}</Wrong>")),
        ("pretty-printed", body.replace("><", ">\n  <")),
        ("control-character", body.replacen("</", "\u{1}</", 1)),
        ("unclosed", body.trim_end_matches('>').to_owned()),
        ("empty-body", String::new()),
        ("whitespace-body", "  \n ".to_owned()),
        ("not-xml", "Enabled".to_owned()),
    ] {
        out.push((format!("document {label}"), document));
    }
    out
}

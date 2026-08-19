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
//!
//! Entity expansion is the one exception, and it is offered as a separate step ([`unescape`])
//! rather than folded into the scanner. The distinction is between a value the case *asserts* and
//! a value the case *spends*: an assertion is about the bytes that arrived, so `&quot;` must stay
//! `&quot;` or the corpus stops being able to tell the two spellings apart; a captured value is
//! about to be written back into a later request, where `&quot;` is six characters no server will
//! match. Only [`crate::expect`]'s capture site expands.
//!
//! NOT responsible for: DTDs, entity *declarations* and the general entities they would define,
//! namespaces beyond the literal `xmlns` attribute, or producing XML.
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
///
/// "Opens with" is meant literally: the declaration has to be the first byte of the body, because
/// that is the only position XML gives it. `prolog ::= XMLDecl? Misc*` puts nothing before the
/// declaration, so a `<?xml ...?>` that follows so much as a space is not a declaration at all —
/// it is a processing instruction in a document that has none, and no parser accepts it.
///
/// The distinction is the whole subject of `c-mpu-0038`. A completion that has to flush its head
/// before it knows the outcome writes the declaration first and its keep-alive whitespace *after*
/// it, which is legal prolog whitespace; the same server writing the whitespace first produces
/// bytes nothing can parse. Trimming here would report both as `true` and leave the case unable to
/// tell them apart.
#[must_use]
pub fn has_declaration(body: &str) -> bool {
    body.starts_with("<?xml")
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

/// Expands the five predefined XML entities and numeric character references in `text`.
///
/// This is what turns an element's wire form into the value it encodes, so that a captured
/// `<ETag>&quot;abc-1&quot;</ETag>` can be spent as an `If-Match` header rather than sent as six
/// literal characters no server will match.
///
/// # What it deliberately does not do
///
/// A reference this function does not recognise is left exactly as it arrived. XML 1.0 defines
/// only five predefined entities; anything else has to be *declared*, and a declaration is
/// something [`crate::expect`] refuses to accept in a body rather than something it resolves.
/// Rewriting an unknown reference into anything at all would be inventing a value the server never
/// sent, which is the failure this module exists to avoid. The expansion is also a single
/// left-to-right pass over the input, so `&amp;quot;` yields `&quot;` and never `"`: an expansion
/// that ran twice would let a body that escaped its ampersand correctly masquerade as one that did
/// not.
///
/// # Why not the production reader
///
/// `rustfs-gateway-xml` has a real parser that resolves entities. It is deliberately not used
/// here, for the reason this whole module exists: it is the *implementation's* reader, and a
/// harness that judged an implementation's output by running it back through that implementation's
/// own parser would agree with it by construction. It also refuses an entity it does not know,
/// which is right for a request the gateway must reject and wrong for a harness whose job is to
/// record what a possibly-misbehaving target actually sent.
#[must_use]
pub fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        let after = &rest[position..];
        // A reference is `&name;`. Without a terminating `;` — or with one so far away it cannot
        // be a reference — the ampersand is just an ampersand.
        let Some(end) = after.find(';').filter(|end| *end <= MAX_REFERENCE_LEN) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        match expand(&after[1..end]) {
            Some(character) => out.push(character),
            None => out.push_str(&after[..=end]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The longest reference worth considering, counted from the `&` to the `;`. `&#x10FFFF;` is nine
/// characters; a `;` further away than this belongs to something else in the text.
const MAX_REFERENCE_LEN: usize = 10;

/// The character one reference names, or `None` when nothing in XML 1.0 defines it.
fn expand(name: &str) -> Option<char> {
    match name {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        _ => {}
    }
    let digits = name.strip_prefix('#')?;
    let code = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    char::from_u32(code)
}

/// Replaces the text of every named element with [`REDACTED`].
///
/// The element's presence and position survive, so a byte comparison still asserts them. Applied
/// to both sides of a comparison, which makes it idempotent on an expectation that already holds
/// the placeholder.
///
/// # An element with no text is left with no text
///
/// `<X></X>` stays `<X></X>`. It is text that is replaced, and an empty element has none — writing
/// the placeholder into one would *manufacture* a value the server never sent, and the whole point
/// of redacting is to stop a server-minted value from being compared, not to invent one.
///
/// The distinction is load-bearing rather than pedantic. "Present and not empty" is the only useful
/// assertion about an opaque value: a cursor element that is there and blank is the same failure as
/// no cursor at all, wearing a valid document. A case says it by asking for
/// `<X>__REDACTED__</X>` and refusing `<X></X>`, and it can only say it if filling the empty form
/// is not something this function does. `c-list-0042` is that case.
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
            if end_offset > 0 {
                next.push_str(REDACTED);
            }
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
    fn the_five_predefined_entities_are_expanded() {
        assert_eq!(unescape("&quot;abc-1&quot;"), "\"abc-1\"");
        assert_eq!(unescape("a &amp; b"), "a & b");
        assert_eq!(unescape("&lt;Key&gt;"), "<Key>");
        assert_eq!(unescape("it&apos;s"), "it's");
    }

    #[test]
    fn numeric_character_references_are_expanded_in_both_spellings() {
        assert_eq!(unescape("&#34;x&#x22;"), "\"x\"");
        assert_eq!(unescape("&#x1F600;"), "\u{1F600}");
    }

    #[test]
    fn text_with_nothing_to_expand_is_returned_unchanged() {
        assert_eq!(unescape("6304d8b66864869a34b0f9efd0631414-1"), "6304d8b66864869a34b0f9efd0631414-1");
    }

    /// The control on the whole function: an expansion that guessed would manufacture a value the
    /// server never sent, which is worse than leaving the reference where it was.
    #[test]
    fn a_reference_xml_does_not_define_is_left_exactly_as_it_arrived() {
        assert_eq!(unescape("&copy;"), "&copy;");
        assert_eq!(unescape("&#xZZ;"), "&#xZZ;");
        assert_eq!(unescape("&#x110000;"), "&#x110000;");
        assert_eq!(unescape("a & b; c"), "a & b; c");
        assert_eq!(unescape("&quot"), "&quot");
    }

    /// One pass, not a fixpoint. A body that escaped its ampersand correctly must not come out
    /// looking like one that did not.
    #[test]
    fn expansion_does_not_run_twice_over_its_own_output() {
        assert_eq!(unescape("&amp;quot;"), "&quot;");
    }

    #[test]
    fn a_declaration_is_detected() {
        assert!(has_declaration(LIST));
        assert!(!has_declaration("<Error><Code>x</Code></Error>"));
    }

    /// Whitespace *after* the declaration is legal prolog whitespace and the declaration is still
    /// there; whitespace *before* it means there is no declaration, only a processing instruction
    /// in a document that never had one.
    #[test]
    fn a_declaration_only_counts_where_xml_allows_one() {
        assert!(has_declaration("<?xml version=\"1.0\"?>\n   \n<R/>"));
        assert!(!has_declaration("   <?xml version=\"1.0\"?>\n<R/>"));
        assert!(!has_declaration("\n<?xml version=\"1.0\"?><R/>"));
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

    /// Negative — an element with nothing in it is left with nothing in it. Filling it would let a
    /// server that wrote a blank opaque value satisfy a case asserting that the value is there, and
    /// a blank cursor is the same dead end as no cursor at all.
    #[test]
    fn redaction_does_not_manufacture_text_for_an_empty_element() {
        assert_eq!(redact("<a><Id></Id></a>", &["Id"]), "<a><Id></Id></a>");
        assert_eq!(
            redact("<a><Id></Id><Id>two</Id></a>", &["Id"]),
            "<a><Id></Id><Id>__REDACTED__</Id></a>",
            "the empty one is untouched and the one with a value is still redacted"
        );
    }

    /// Negative — a self-closing element has no text either, and no closing tag for the scan to
    /// find, so it comes back exactly as it arrived rather than being rewritten into the paired
    /// form. The wire form is what `expect.body.xml.empty_elements` asserts.
    #[test]
    fn redaction_leaves_a_self_closing_element_alone() {
        assert_eq!(redact("<a><Id/></a>", &["Id"]), "<a><Id/></a>");
    }
}

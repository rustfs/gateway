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

//! The `xml_parse` property: arbitrary bytes through the bounded XML request-body reader.
//!
//! Responsible for: decoding one fuzz input into an `XmlLimits` and a document; running the one
//! bounded entry point every generated decoder reads a body through, `parse_with_limits`; and
//! asserting what that reader promises about every document, accepted or refused.
//! NOT responsible for: choosing a libFuzzer entry point, generating samples (the stable replay in
//! `crates/core/tests/xml_parse_replay.rs` does that), or mapping a refusal onto an S3 error code,
//! which is each operation's.
//! Upstream: libFuzzer bytes, a committed seed under `fuzz/seeds/xml_parse/`, or the replay's
//! fixed-seed sampler. Downstream: `fuzz/fuzz_targets/xml_parse.rs` and the replay, which run this
//! same file.
//!
//! # Input layout
//!
//! | Offset | Meaning |
//! | --- | --- |
//! | 0 | body-byte ceiling: index into [`BODY_CEILINGS`], modulo its length |
//! | 1 | depth ceiling: index into [`DEPTH_CEILINGS`] |
//! | 2 | element ceiling: index into [`ELEMENT_CEILINGS`] |
//! | 3 | attributes-per-element ceiling: index into [`ATTRIBUTE_CEILINGS`] |
//! | 4 | attribute-value byte ceiling: index into [`ATTRIBUTE_BYTE_CEILINGS`] |
//! | 5.. | the document |
//!
//! Every table ends in the production `XmlLimits::S3` value, and holds small ceilings a fuzzer can
//! cross in a few bytes.
//!
//! # What is asserted, beyond "it did not panic"
//!
//! 1. **The body ceiling is exact.** A document over it is refused as `BodyTooLarge` whatever it
//!    holds. For every document, the verdict under a ceiling of exactly its length equals the
//!    verdict under the case's own limits (when those admit it), and a ceiling one byte shorter
//!    is `BodyTooLarge`.
//! 2. **The tree ceilings are exact.** An accepted tree's depth and element count, measured on the
//!    tree, are within the ceilings; the same document is accepted into the same tree at a ceiling
//!    of exactly that depth or count, and refused as `TooDeep` or `TooManyElements` one below it.
//!    Where the document's raw attributes can be counted from the tree — no `:` and no `xmlns`
//!    anywhere, so nothing was a declaration or an unresolved prefix — attribute count and, with no
//!    `&` or CR either, attribute bytes are held to the same exactness as `TooManyAttributes` and
//!    `AttributeTooLong`.
//! 3. **An accepted tree round-trips.** Written back through the production `XmlWriter` — paired
//!    empty elements, one fresh prefix per namespaced attribute — it reads back into the same tree
//!    under the same depth and element ceilings. A ceiling that counted one spelling of an element
//!    and not another cannot pass this. Checks 3 to 5 run only on a tree whose names the writer can
//!    spell: `quick-xml` does not check the Name production, so the reader accepts
//!    `<xmlns:p="u"/>` as an element whose local name is `p"`, which no writer can emit
//!    (`fuzz/seeds/xml_parse/element-name-not-an-xml-name`, rustfs/backlog#1766).
//! 4. **A `DOCTYPE` is always refused.** The accepted document, with a `DOCTYPE` declaring an
//!    entity placed after its XML declaration, is `DocTypeDeclaration` — never parsed and ignored.
//! 5. **No entity is expanded.** A reference to an undeclared entity placed inside the root is
//!    `UnsupportedEntity`; the predefined `&lt;` and the character reference `&#x41;` in the same
//!    place are resolved, by name, to exactly `<A` in front of the root's text.

#![allow(dead_code)] // The fuzz binary calls `check` only; the replay also reads the tables.

use rustfs_gateway_xml::{
    DECLARATION, MAX_ATTRIBUTE_BYTES, MAX_ATTRIBUTES_PER_ELEMENT, MAX_BODY_BYTES, MAX_DEPTH, MAX_ELEMENTS, XmlError, XmlLimits,
    XmlNode, XmlWriter, parse_with_limits,
};

/// How many leading input bytes select the limits rather than form the document.
pub(crate) const HEADER_BYTES: usize = 5;
/// The body-byte ceilings an input can select.
pub(crate) const BODY_CEILINGS: [usize; 4] = [16, 64, 512, MAX_BODY_BYTES];
/// The depth ceilings an input can select.
pub(crate) const DEPTH_CEILINGS: [usize; 4] = [1, 2, 4, MAX_DEPTH];
/// The element ceilings an input can select.
pub(crate) const ELEMENT_CEILINGS: [usize; 4] = [1, 3, 8, MAX_ELEMENTS];
/// The attributes-per-element ceilings an input can select.
pub(crate) const ATTRIBUTE_CEILINGS: [usize; 3] = [1, 3, MAX_ATTRIBUTES_PER_ELEMENT];
/// The attribute-value byte ceilings an input can select.
pub(crate) const ATTRIBUTE_BYTE_CEILINGS: [usize; 3] = [1, 8, MAX_ATTRIBUTE_BYTES];

/// The `DOCTYPE` placed into an accepted document: an internal subset declaring an entity, which
/// is the XXE shape a parser that honoured it would expand.
pub(crate) const DOCTYPE_PROBE: &str = "<!DOCTYPE r [<!ENTITY xxe \"expanded\">]>";
/// The undeclared entity reference placed inside an accepted document's root.
pub(crate) const ENTITY_PROBE: &str = "&xxe;";
/// The two references this reader does resolve, and what they resolve to.
pub(crate) const PREDEFINED_PROBE: (&str, &str) = ("&lt;&#x41;", "<A");

/// What one input selected.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Case<'a> {
    pub(crate) limits: XmlLimits,
    pub(crate) document: &'a [u8],
}

impl<'a> Case<'a> {
    /// Splits an input into its limits and its document, or `None` when it is too short to select.
    pub(crate) fn parse(input: &'a [u8]) -> Option<Self> {
        let (header, document) = input.split_first_chunk::<HEADER_BYTES>()?;
        let [body, depth, elements, attributes, attribute_bytes] = header.map(usize::from);
        let limits = XmlLimits::new(
            BODY_CEILINGS[body % BODY_CEILINGS.len()],
            DEPTH_CEILINGS[depth % DEPTH_CEILINGS.len()],
            ELEMENT_CEILINGS[elements % ELEMENT_CEILINGS.len()],
            ATTRIBUTE_CEILINGS[attributes % ATTRIBUTE_CEILINGS.len()],
            ATTRIBUTE_BYTE_CEILINGS[attribute_bytes % ATTRIBUTE_BYTE_CEILINGS.len()],
        )
        .expect("every table entry is non-zero");
        Some(Self { limits, document })
    }
}

/// Encodes a case the way [`Case::parse`] reads it; the replay's sampler and seeds are built with it.
pub(crate) fn encode(selectors: [u8; HEADER_BYTES], document: &[u8]) -> Vec<u8> {
    let mut input = selectors.to_vec();
    input.extend_from_slice(document);
    input
}

/// The measurements of an accepted tree the ceilings are compared against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Shape {
    /// Nesting depth, the root being depth one.
    pub(crate) depth: usize,
    /// Elements, the root included.
    pub(crate) elements: usize,
    /// The most attributes any one element kept.
    pub(crate) widest: usize,
    /// The longest attribute value or attribute namespace, in bytes.
    pub(crate) longest: usize,
}

impl Shape {
    fn of(node: &XmlNode) -> Self {
        let own = node
            .attributes
            .iter()
            .map(|attribute| attribute.value.len().max(attribute.namespace.as_deref().map_or(0, str::len)))
            .max()
            .unwrap_or(0);
        let mut shape = Self {
            depth: 1,
            elements: 1,
            widest: node.attributes.len(),
            longest: own,
        };
        for child in &node.children {
            let inner = Self::of(child);
            shape.depth = shape.depth.max(inner.depth + 1);
            shape.elements += inner.elements;
            shape.widest = shape.widest.max(inner.widest);
            shape.longest = shape.longest.max(inner.longest);
        }
        shape
    }
}

/// What the reader did with one input.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// The tree, or the named refusal.
    pub(crate) verdict: Result<XmlNode, XmlError>,
    /// The accepted tree's measurements.
    pub(crate) shape: Option<Shape>,
    /// The accepted tree written back through `XmlWriter`.
    pub(crate) canonical: Option<String>,
}

/// Runs one input through the reader and asserts every property in the module docs.
///
/// Returns `None` for an input shorter than [`HEADER_BYTES`].
pub(crate) fn check(input: &[u8]) -> Option<Outcome> {
    let case = Case::parse(input)?;
    let limits = case.limits;
    let document = case.document;
    let verdict = parse_with_limits(document, limits);

    // 1. The body ceiling, exactly.
    if document.len() > limits.max_body_bytes() {
        assert_eq!(verdict, Err(XmlError::BodyTooLarge), "a document over the body ceiling was read");
        return Some(Outcome {
            verdict,
            shape: None,
            canonical: None,
        });
    }
    if !document.is_empty() {
        assert_eq!(
            parse_with_limits(document, with(limits, Ceiling::Body, document.len())),
            verdict,
            "a body ceiling of exactly the document's length changed the verdict",
        );
    }
    if document.len() >= 2 {
        assert_eq!(
            parse_with_limits(document, with(limits, Ceiling::Body, document.len() - 1)),
            Err(XmlError::BodyTooLarge),
            "a body ceiling one byte short of the document did not refuse it",
        );
    }

    let Ok(tree) = &verdict else {
        return Some(Outcome {
            verdict,
            shape: None,
            canonical: None,
        });
    };
    let shape = Shape::of(tree);

    // 2. The tree ceilings, exactly.
    assert!(
        shape.depth <= limits.max_depth(),
        "a {}-deep tree passed a depth ceiling of {}",
        shape.depth,
        limits.max_depth()
    );
    assert!(
        shape.elements <= limits.max_elements(),
        "a {}-element tree passed an element ceiling of {}",
        shape.elements,
        limits.max_elements(),
    );
    assert!(
        shape.widest <= limits.max_attributes_per_element(),
        "an element kept {} attributes under a ceiling of {}",
        shape.widest,
        limits.max_attributes_per_element(),
    );
    assert!(
        shape.longest <= limits.max_attribute_bytes(),
        "an attribute kept {} bytes under a ceiling of {}",
        shape.longest,
        limits.max_attribute_bytes(),
    );
    exact(document, limits, Ceiling::Depth, shape.depth, tree, XmlError::TooDeep);
    exact(document, limits, Ceiling::Elements, shape.elements, tree, XmlError::TooManyElements);
    let countable = !contains(document, b":") && !contains(document, b"xmlns");
    if countable {
        exact(document, limits, Ceiling::Attributes, shape.widest, tree, XmlError::TooManyAttributes);
        if !document.iter().any(|byte| matches!(byte, b'&' | b'\r')) {
            exact(document, limits, Ceiling::AttributeBytes, shape.longest, tree, XmlError::AttributeTooLong);
        }
    }

    // 3–5 need the tree written back, and a name outside the Name production has no spelling.
    if !writable(tree) {
        return Some(Outcome {
            verdict,
            shape: Some(shape),
            canonical: None,
        });
    }

    // 3. The round trip, under the same depth and element ceilings.
    let canonical = canonical(tree);
    let relaxed = |extra: usize| {
        XmlLimits::new(
            canonical.len() + extra,
            limits.max_depth(),
            limits.max_elements(),
            // One declaration per namespaced attribute, and escaping grows a value at most sixfold.
            limits.max_attributes_per_element() * 2,
            limits.max_attribute_bytes().saturating_mul(6),
        )
        .expect("every ceiling is non-zero")
    };
    assert_eq!(
        parse_with_limits(canonical.as_bytes(), relaxed(0)).as_ref(),
        Ok(tree),
        "the accepted tree did not read back from its own canonical form {canonical:?}",
    );

    // 4. A DOCTYPE, placed where a prolog may hold one.
    let body = &canonical[DECLARATION.len()..];
    let with_doctype = format!("{DECLARATION}{DOCTYPE_PROBE}{body}");
    assert_eq!(
        parse_with_limits(with_doctype.as_bytes(), relaxed(DOCTYPE_PROBE.len())),
        Err(XmlError::DocTypeDeclaration),
        "a DOCTYPE in the prolog of an accepted document was not refused",
    );

    // 5. Entity references, placed first inside the root.
    let start_tag = start_tag_len(tree);
    let (head, rest) = canonical.split_at(DECLARATION.len() + start_tag);
    let with_entity = format!("{head}{ENTITY_PROBE}{rest}");
    assert_eq!(
        parse_with_limits(with_entity.as_bytes(), relaxed(ENTITY_PROBE.len())),
        Err(XmlError::UnsupportedEntity),
        "an undeclared entity reference was not refused",
    );
    let (probe, resolved) = PREDEFINED_PROBE;
    let with_predefined = format!("{head}{probe}{rest}");
    let mut expected = tree.clone();
    expected.text.insert_str(0, resolved);
    assert_eq!(
        parse_with_limits(with_predefined.as_bytes(), relaxed(probe.len())),
        Ok(expected),
        "the predefined and character references did not resolve to exactly {resolved:?}",
    );

    Some(Outcome {
        verdict,
        shape: Some(shape),
        canonical: Some(canonical),
    })
}

/// One of the five ceilings.
#[derive(Clone, Copy, Debug)]
enum Ceiling {
    Body,
    Depth,
    Elements,
    Attributes,
    AttributeBytes,
}

/// `limits` with one ceiling replaced.
fn with(limits: XmlLimits, ceiling: Ceiling, value: usize) -> XmlLimits {
    let mut values = [
        limits.max_body_bytes(),
        limits.max_depth(),
        limits.max_elements(),
        limits.max_attributes_per_element(),
        limits.max_attribute_bytes(),
    ];
    values[ceiling as usize] = value;
    let [body, depth, elements, attributes, attribute_bytes] = values;
    XmlLimits::new(body, depth, elements, attributes, attribute_bytes).expect("a replaced ceiling is non-zero")
}

/// The accepted document reads into the same tree at a ceiling of exactly `measured`, and is
/// refused as `error` one below it.
fn exact(document: &[u8], limits: XmlLimits, ceiling: Ceiling, measured: usize, tree: &XmlNode, error: XmlError) {
    assert_eq!(
        parse_with_limits(document, with(limits, ceiling, measured.max(1))).as_ref(),
        Ok(tree),
        "{ceiling:?}: a ceiling of exactly the measured {measured} refused the document",
    );
    if measured >= 2 {
        assert_eq!(
            parse_with_limits(document, with(limits, ceiling, measured - 1)),
            Err(error),
            "{ceiling:?}: a ceiling one below the measured {measured} was not refused by name",
        );
    }
}

/// The tree written back through the production writer, with a fresh prefix per namespaced
/// attribute so that two attributes sharing a local name never collide.
pub(crate) fn canonical(tree: &XmlNode) -> String {
    let mut writer = XmlWriter::document();
    write_node(&mut writer, tree);
    writer.finish()
}

fn write_node(writer: &mut XmlWriter, node: &XmlNode) {
    let mut attributes: Vec<(String, String)> = Vec::with_capacity(node.attributes.len() * 2);
    for (index, attribute) in node.attributes.iter().enumerate() {
        match &attribute.namespace {
            Some(namespace) => {
                attributes.push((format!("xmlns:p{index}"), namespace.to_string()));
                attributes.push((format!("p{index}:{}", attribute.name), attribute.value.clone()));
            }
            None => attributes.push((attribute.name.clone(), attribute.value.clone())),
        }
    }
    let borrowed: Vec<(&str, &str)> = attributes
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    writer.open_with(&node.name, &borrowed);
    writer.text(&node.text);
    for child in &node.children {
        write_node(writer, child);
    }
    writer.close();
}

/// The length of the root's start tag in [`canonical`], read off a childless, textless copy.
fn start_tag_len(tree: &XmlNode) -> usize {
    let bare = XmlNode {
        name: tree.name.clone(),
        attributes: tree.attributes.clone(),
        ..XmlNode::default()
    };
    let mut writer = XmlWriter::fragment();
    write_node(&mut writer, &bare);
    writer.finish().len() - "</>".len() - tree.name.len()
}

/// Whether every element and attribute name in the tree is one the writer can spell: a letter or
/// `_`, then letters, digits, `-`, `_` or `.`. Deliberately narrower than XML's Name production.
fn writable(node: &XmlNode) -> bool {
    fn plain(name: &str) -> bool {
        let mut characters = name.chars();
        characters.next().is_some_and(|first| first.is_alphabetic() || first == '_')
            && characters.all(|character| character.is_alphanumeric() || matches!(character, '-' | '_' | '.'))
    }
    plain(&node.name) && node.attributes.iter().all(|attribute| plain(&attribute.name)) && node.children.iter().all(writable)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

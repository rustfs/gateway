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

//! Fixed-seed replay of the `xml_parse` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/xml_parse/` through the same
//! property file the fuzz target runs, pinning the exact outcome of the seventeen hand-written
//! seeds — each ceiling at and one past its boundary, `DOCTYPE`, entity and character refusals,
//! and a namespaced positive control — and of the one minimised finding (an element name outside
//! the `Name` production), and driving forty thousand deterministic samples through
//! that property on stable, with coverage floors stated as counts.
//! NOT responsible for: fuzzing — `ci.yml` defers libFuzzer runs to a schedule — or the reader's
//! hand-picked matrix in `crates/xml/src/tests.rs`, or turning a finding into a conformance case,
//! which needs a protocol oracle a crash does not carry.
//! Upstream: `fuzz/support/xml_parse.rs` and the committed seeds. Downstream: Cargo's harness.

use std::path::{Path, PathBuf};

use rustfs_gateway_xml::XmlError;

#[path = "../../../fuzz/support/xml_parse.rs"]
mod xml_parse;

use xml_parse::{Outcome, Shape, check, encode};

/// The seeds the property's two directions rest on. Each must exist; none may be skipped.
const REQUIRED_SEEDS: [&str; 17] = [
    "valid-namespaced",
    "doctype-xxe",
    "doctype-lowercase-after-declaration",
    "undeclared-entity",
    "depth-at-ceiling",
    "depth-over-ceiling",
    "empty-leaf-over-depth",
    "elements-at-ceiling",
    "elements-over-ceiling",
    "attributes-at-ceiling",
    "attributes-over-ceiling",
    "declaration-counts-as-attribute",
    "attribute-bytes-at-ceiling",
    "attribute-bytes-over-ceiling",
    "body-at-ceiling",
    "body-over-ceiling",
    "forbidden-character-reference",
];

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/xml_parse")
}

fn replay(name: &str) -> Outcome {
    let path = seed_dir().join(name);
    let input = std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()));
    check(&input).unwrap_or_else(|| panic!("seed {name} is shorter than the case header"))
}

fn refusal(name: &str) -> XmlError {
    match replay(name).verdict {
        Ok(tree) => panic!("seed {name} was accepted as {tree:?}"),
        Err(error) => error,
    }
}

fn accepted_shape(name: &str) -> Shape {
    let outcome = replay(name);
    assert!(outcome.verdict.is_ok(), "seed {name} was refused: {:?}", outcome.verdict);
    outcome.shape.expect("an accepted seed is measured")
}

// ---------------------------------------------------------------------------------------------
// Positive control.
// ---------------------------------------------------------------------------------------------

/// Without it, a reader that refused every document would satisfy every refusal below. Prefixes
/// are dropped from element names and resolved on attributes; the predefined and character
/// references resolve by name; and the canonical form the round trip wrote is what was read back.
#[test]
fn the_namespaced_seed_is_read_resolved_and_round_trips() {
    let outcome = replay("valid-namespaced");
    let tree = outcome.verdict.expect("the positive control is accepted");
    assert_eq!(tree.name, "Delete");
    assert_eq!(tree.child("Object").and_then(|object| object.child_text("Key")), Some("a&bA"));
    let grantee = tree.child("Grantee").expect("the self-closed Grantee is a child");
    assert_eq!(grantee.attribute_ns("http://www.w3.org/2001/XMLSchema-instance", "type"), Some("Group"));
    assert!(grantee.attribute("type").is_none(), "a prefixed attribute is not the unprefixed one");
    assert_eq!(
        outcome.shape,
        Some(Shape {
            depth: 3,
            elements: 4,
            widest: 1,
            longest: 41
        })
    );
    assert_eq!(
        outcome.canonical.as_deref(),
        Some(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<Delete><Object><Key>a&amp;bA</Key></Object>",
            "<Grantee xmlns:p0=\"http://www.w3.org/2001/XMLSchema-instance\" p0:type=\"Group\"></Grantee></Delete>",
        )),
    );
}

// ---------------------------------------------------------------------------------------------
// DOCTYPE, entities and characters.
// ---------------------------------------------------------------------------------------------

/// The XXE shape: an external entity declared in the internal subset and referenced in a key. It
/// is refused at the declaration, not read with the reference left unexpanded.
#[test]
fn the_external_entity_doctype_is_refused_as_a_doctype() {
    assert_eq!(refusal("doctype-xxe"), XmlError::DocTypeDeclaration);
}

/// A lowercase `doctype` after an XML declaration and a newline is still a document type
/// declaration, and still refused as one.
#[test]
fn a_lowercase_doctype_after_the_declaration_is_refused_as_a_doctype() {
    assert_eq!(refusal("doctype-lowercase-after-declaration"), XmlError::DocTypeDeclaration);
}

/// With no `DOCTYPE` to declare it, `&xxe;` names nothing, and a reference to nothing is refused
/// rather than left in the text verbatim or dropped.
#[test]
fn an_undeclared_entity_reference_is_refused() {
    assert_eq!(refusal("undeclared-entity"), XmlError::UnsupportedEntity);
}

/// A character reference to a character XML 1.0 excludes is refused like the raw byte would be.
#[test]
fn a_reference_to_a_forbidden_character_is_refused() {
    assert_eq!(refusal("forbidden-character-reference"), XmlError::ForbiddenCharacter);
}

/// The first libFuzzer finding (rustfs/gateway#743): `<xmlns:p="urn:p" …/>`, which `quick-xml`
/// tokenises as an element whose name is `xmlns:p="urn:p"`. Refused as a name rather than read
/// as an element the writer cannot spell.
#[test]
fn an_element_name_outside_the_name_production_is_refused() {
    assert_eq!(refusal("element-name-not-an-xml-name"), XmlError::InvalidName);
}

/// The fuzz findings of rustfs/gateway#1077: a prefixed element name whose local part starts with a
/// digit — `<a:2 …/>` from the first nightly, and `<…66.66:66666666666666389 …>` from the post-merge
/// dispatch. Each part of a qualified name is a `Name` on its own, so both are refused as names
/// rather than read as an element whose canonical spelling (`<2 …>`) this reader then refuses.
#[test]
fn a_prefixed_element_name_whose_local_part_is_not_a_name_is_refused() {
    assert_eq!(refusal("qualified-name-digit-local-part"), XmlError::InvalidName);
    assert_eq!(refusal("qualified-name-long-digit-local-part"), XmlError::InvalidName);
}

// ---------------------------------------------------------------------------------------------
// Each ceiling, at its boundary and one past it.
// ---------------------------------------------------------------------------------------------

/// Depth ceiling two: a two-deep tree is accepted.
#[test]
fn a_tree_exactly_as_deep_as_the_ceiling_is_accepted() {
    assert_eq!(accepted_shape("depth-at-ceiling").depth, 2);
}

/// Depth ceiling two: a three-deep tree of paired elements is refused by name.
#[test]
fn a_tree_one_deeper_than_the_ceiling_is_refused_as_too_deep() {
    assert_eq!(refusal("depth-over-ceiling"), XmlError::TooDeep);
}

/// Depth ceiling two: the same three-deep tree with its leaf self-closed. `<c/>` and `<c></c>`
/// are one element, so a ceiling that counted only the paired spelling would let every tree grow
/// one level past it.
#[test]
fn a_self_closed_leaf_one_deeper_than_the_ceiling_is_refused_as_too_deep() {
    assert_eq!(refusal("empty-leaf-over-depth"), XmlError::TooDeep);
}

/// Element ceiling three: three elements are accepted.
#[test]
fn a_tree_with_exactly_the_ceiling_of_elements_is_accepted() {
    assert_eq!(accepted_shape("elements-at-ceiling").elements, 3);
}

/// Element ceiling three: a fourth element is refused by name.
#[test]
fn one_element_past_the_ceiling_is_refused_as_too_many_elements() {
    assert_eq!(refusal("elements-over-ceiling"), XmlError::TooManyElements);
}

/// Attribute ceiling three: three attributes are accepted.
#[test]
fn an_element_with_exactly_the_ceiling_of_attributes_is_accepted() {
    assert_eq!(accepted_shape("attributes-at-ceiling").widest, 3);
}

/// Attribute ceiling three: a fourth attribute is refused by name.
#[test]
fn one_attribute_past_the_ceiling_is_refused_as_too_many_attributes() {
    assert_eq!(refusal("attributes-over-ceiling"), XmlError::TooManyAttributes);
}

/// Attribute ceiling three: three kept attributes plus the `xmlns:` declaration one of them needs.
/// A declaration is an attribute on the wire, so a ceiling that skipped them would let one element
/// carry any number of bindings.
#[test]
fn a_namespace_declaration_counts_against_the_attribute_ceiling() {
    assert_eq!(refusal("declaration-counts-as-attribute"), XmlError::TooManyAttributes);
}

/// Attribute-value ceiling eight: an eight-byte value is accepted.
#[test]
fn an_attribute_value_exactly_at_the_byte_ceiling_is_accepted() {
    assert_eq!(accepted_shape("attribute-bytes-at-ceiling").longest, 8);
}

/// Attribute-value ceiling eight: a nine-byte value is refused by name.
#[test]
fn an_attribute_value_one_byte_past_the_ceiling_is_refused() {
    assert_eq!(refusal("attribute-bytes-over-ceiling"), XmlError::AttributeTooLong);
}

/// Body ceiling sixteen: a sixteen-byte document is accepted.
#[test]
fn a_document_exactly_at_the_body_ceiling_is_accepted() {
    let outcome = replay("body-at-ceiling");
    assert_eq!(outcome.verdict.map(|tree| tree.text), Ok("012345678".to_owned()));
}

/// Body ceiling sixteen: a seventeen-byte document is refused before it is read.
#[test]
fn a_document_one_byte_past_the_body_ceiling_is_refused() {
    assert_eq!(refusal("body-over-ceiling"), XmlError::BodyTooLarge);
}

/// Every committed seed — the seventeen above and any minimised regression added later — replays
/// under the property's own assertions. A missing directory or required seed fails, not skips.
#[test]
fn every_committed_seed_replays_under_the_fuzz_property() {
    let dir = seed_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("seed directory {} is missing: {error}", dir.display()))
        .map(|entry| {
            entry
                .expect("a readable directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    for required in REQUIRED_SEEDS {
        assert!(names.iter().any(|name| name == required), "required seed {required} is missing");
    }
    for name in &names {
        replay(name);
    }
}

// ---------------------------------------------------------------------------------------------
// Forty thousand deterministic samples.
// ---------------------------------------------------------------------------------------------

const ELEMENT_NAMES: [&str; 6] = ["a", "Key", "s3:Object", "Delete", "x:y:z", "Grantee"];
const ATTRIBUTE_NAMES: [&str; 8] = ["k", "v", "xsi:type", "xmlns:xsi", "xmlns:s3", "q:x", "xmlns", "w"];
const ATTRIBUTE_VALUES: [&str; 9] = ["1", "Group", "urn:x", "a&amp;b", "&lt;", "a\tb", "12345678", "&#x41;", ""];
const TEXTS: [&str; 10] = [
    "",
    "t",
    "a&amp;b",
    "&#13;",
    "\r\n",
    "<![CDATA[c<d]]>",
    "<!-- c -->",
    "&#x10FFFF;",
    "é",
    "0123456789",
];
/// What a pick draws one time in [`HAZARD_ODDS`] instead: each is a refusal of its own.
const HAZARDS: [&str; 4] = ["&xxe;", "&#1;", "123456789", "&bogus"];
const HAZARD_ODDS: usize = 16;

/// A xorshift sequence: a failed sample is reproducible from its index alone.
struct Sampler(u64);

impl Sampler {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("a small bound")).expect("below a usize bound")
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    /// A pick from `items`, or one time in [`HAZARD_ODDS`] a hazard.
    fn pick_or_hazard<'a>(&mut self, items: &[&'a str]) -> &'a str {
        if self.below(HAZARD_ODDS) == 0 {
            self.pick(&HAZARDS)
        } else {
            self.pick(items)
        }
    }

    /// A selector byte that picks the production ceiling two times in three, so that most samples
    /// cross at most one small ceiling. Production is the last entry of every table, and the tables
    /// hold three or four entries: 251 is the byte that is 2 modulo 3 and 3 modulo 4.
    fn selector(&mut self) -> u8 {
        if self.below(3) == 0 {
            self.next().to_le_bytes()[0]
        } else {
            251
        }
    }

    fn element(&mut self, out: &mut String, depth: usize) {
        let name = self.pick(&ELEMENT_NAMES);
        out.push('<');
        out.push_str(name);
        if name.starts_with("s3:") {
            out.push_str(" xmlns:s3=\"urn:s3\"");
        }
        // Consecutive names, so an element never repeats one: a duplicate is `Malformed`, and the
        // flipped byte below reaches that often enough.
        let first = self.below(ATTRIBUTE_NAMES.len());
        for offset in 0..self.below(5) {
            let attribute = ATTRIBUTE_NAMES[(first + offset) % ATTRIBUTE_NAMES.len()];
            let value = self.pick_or_hazard(&ATTRIBUTE_VALUES);
            out.push_str(&format!(" {attribute}=\"{value}\""));
        }
        let children = if depth >= 6 { 0 } else { self.below(4) };
        let text = self.pick_or_hazard(&TEXTS);
        if children == 0 && text.is_empty() && self.below(2) == 0 {
            out.push_str("/>");
            return;
        }
        out.push('>');
        out.push_str(text);
        for _ in 0..children {
            self.element(out, depth + 1);
        }
        out.push_str("</");
        out.push_str(name);
        out.push('>');
    }

    /// One input: five limit selectors, then a generated document with a random prolog, sometimes
    /// damaged by one flipped byte or a truncation.
    fn sample(&mut self) -> Vec<u8> {
        let selectors = [
            self.selector(),
            self.selector(),
            self.selector(),
            self.selector(),
            self.selector(),
        ];
        let mut document = String::new();
        match self.below(10) {
            0 => document.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
            1 => document.push_str("<!DOCTYPE a [<!ENTITY xxe \"x\">]>"),
            2 => document.push_str("<!-- lead --> "),
            _ => {}
        }
        self.element(&mut document, 1);
        let mut bytes = document.into_bytes();
        match self.below(12) {
            0 if !bytes.is_empty() => {
                let at = self.below(bytes.len());
                bytes[at] = self.next().to_le_bytes()[0];
            }
            1 if !bytes.is_empty() => {
                let keep = self.below(bytes.len());
                bytes.truncate(keep);
            }
            _ => {}
        }
        encode(selectors, &bytes)
    }
}

/// Samples per shard. Four shards run on separate test threads.
const SHARD_SAMPLES: u32 = 10_000;

/// The reader's property over one shard. The counts are the other half: a sampler that drifted
/// into producing only malformed documents would pass every assertion while exercising nothing,
/// so every refusal the reader can name, and acceptance itself, must be reached a stated number of
/// times.
fn hold_the_xml_property_over_a_shard(seed: u64) {
    let mut sampler = Sampler(seed);
    let (mut accepted, mut nested, mut countable, mut round_tripped) = (0u32, 0u32, 0u32, 0u32);
    let mut refused = std::collections::BTreeMap::<String, u32>::new();
    for _ in 0..SHARD_SAMPLES {
        let input = sampler.sample();
        let outcome = check(&input).expect("every sample carries the case header");
        match outcome.verdict {
            Ok(_) => {
                accepted += 1;
                if outcome.shape.is_some_and(|shape| shape.depth >= 3) {
                    nested += 1;
                }
                // The round trip, DOCTYPE and entity probes ran: the tree's names were writable.
                if outcome.canonical.is_some() {
                    round_tripped += 1;
                }
                // The property's attribute exactness runs only on these; see its module docs.
                let document = &input[xml_parse::HEADER_BYTES..];
                if !document.contains(&b':') && !document.windows(5).any(|window| window == b"xmlns") {
                    countable += 1;
                }
            }
            Err(error) => *refused.entry(format!("{error:?}")).or_default() += 1,
        }
    }
    let count = |name: &str| refused.get(name).copied().unwrap_or(0);
    assert!(accepted >= 1_000, "seed {seed:#x}: only {accepted} samples were accepted");
    assert!(nested >= 100, "seed {seed:#x}: only {nested} accepted samples nested three deep");
    assert!(
        round_tripped >= 1_000,
        "seed {seed:#x}: only {round_tripped} accepted samples were written back and probed"
    );
    assert!(
        countable >= 100,
        "seed {seed:#x}: only {countable} accepted samples had countable attributes"
    );
    for (name, floor) in [
        ("BodyTooLarge", 1_200),
        ("Malformed", 700),
        ("NotUtf8", 150),
        ("DocTypeDeclaration", 450),
        ("UnsupportedEntity", 500),
        ("TooDeep", 300),
        ("TooManyElements", 250),
        ("TooManyAttributes", 450),
        ("AttributeTooLong", 400),
        ("ForbiddenCharacter", 300),
        // Reached only through a flipped byte landing in a tag name, so the floor is low; it is
        // still a floor, so a sampler that stopped reaching the refusal at all is caught.
        ("InvalidName", 5),
    ] {
        assert!(
            count(name) >= floor,
            "seed {seed:#x}: only {} samples were refused as {name}; all refusals: {refused:?}",
            count(name),
        );
    }
}

/// Forty thousand fixed-seed samples, the first of four shards.
#[test]
fn fixed_seed_samples_hold_the_xml_property_shard_1_of_4() {
    hold_the_xml_property_over_a_shard(0x786d_6c2d_7061_7273);
}

/// Forty thousand fixed-seed samples, the second of four shards.
#[test]
fn fixed_seed_samples_hold_the_xml_property_shard_2_of_4() {
    hold_the_xml_property_over_a_shard(0x626f_756e_6465_6421);
}

/// Forty thousand fixed-seed samples, the third of four shards.
#[test]
fn fixed_seed_samples_hold_the_xml_property_shard_3_of_4() {
    hold_the_xml_property_over_a_shard(0x646f_6374_7970_6521);
}

/// Forty thousand fixed-seed samples, the fourth of four shards.
#[test]
fn fixed_seed_samples_hold_the_xml_property_shard_4_of_4() {
    hold_the_xml_property_over_a_shard(0x656e_7469_7479_2121);
}

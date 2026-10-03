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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! Reader refusals and writer byte shapes.
//!
//! Every writer test compares whole bytes, because the properties this crate promises — no
//! whitespace, paired empty elements, escaping — are only observable that way.

use crate::error::XmlError;
use crate::read::{
    MAX_ATTRIBUTE_BYTES, MAX_ATTRIBUTES_PER_ELEMENT, MAX_BODY_BYTES, MAX_DEPTH, MAX_ELEMENTS, XmlLimits, parse, parse_with_limits,
};
use crate::write::{DECLARATION, S3_XMLNS, XmlWriter, strip_declaration};

// ---------------------------------------------------------------------------------------------
// Declaration removal, for the response whose head is committed before its outcome
// ---------------------------------------------------------------------------------------------

/// Positive — the declaration this crate writes is the declaration it removes, and the rest of the
/// document survives byte for byte.
#[test]
fn removes_the_declaration_this_crate_writes() {
    let document = format!("{DECLARATION}<Result><Key>a</Key></Result>");
    assert_eq!(strip_declaration(document.as_bytes()), b"<Result><Key>a</Key></Result>");
}

/// Negative — a body with no declaration is returned untouched. A function that trimmed a fixed
/// number of bytes would decapitate the document element instead.
#[test]
fn n_leaves_a_body_without_a_declaration_alone() {
    assert_eq!(strip_declaration(b"<Result></Result>"), b"<Result></Result>");
    assert_eq!(strip_declaration(b""), b"");
}

/// Negative — only the exact form is removed. A declaration spelled differently — single quotes, no
/// trailing newline, a `standalone` attribute, leading whitespace — is another writer's, and this
/// function does not guess where it ends.
#[test]
fn n_removes_only_the_exact_declaration_and_never_guesses() {
    for other in [
        "<?xml version='1.0' encoding='UTF-8'?>\n<A></A>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><A></A>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<A></A>",
        " <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<A></A>",
    ] {
        assert_eq!(strip_declaration(other.as_bytes()), other.as_bytes(), "{other}");
    }
}

/// Negative — a second declaration further in is not removed. Only the leading one is the prologue's;
/// removing another would hide a defect in whatever produced the body rather than reporting one.
#[test]
fn n_removes_at_most_one_declaration_and_only_at_the_front() {
    let document = format!("{DECLARATION}<A>{DECLARATION}</A>");
    let trimmed = strip_declaration(document.as_bytes());
    assert_eq!(std::str::from_utf8(trimmed).expect("utf-8"), format!("<A>{DECLARATION}</A>"));
}

// ---------------------------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------------------------

#[test]
fn writes_a_document_with_no_whitespace_between_elements() {
    let mut writer = XmlWriter::document();
    writer.open("DeleteResult", Some(S3_XMLNS));
    writer.open("Deleted", None);
    writer.element("Key", "a/b");
    writer.close();
    writer.close();

    assert_eq!(
        writer.finish(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Deleted><Key>a/b</Key></Deleted></DeleteResult>"
    );
}

#[test]
fn writes_an_empty_member_in_its_paired_form() {
    let mut writer = XmlWriter::fragment();
    writer.element("Prefix", "");
    assert_eq!(writer.finish(), "<Prefix></Prefix>", "a self-closing form is a different body");
}

#[test]
fn omits_a_member_the_policy_drops() {
    let mut writer = XmlWriter::fragment();
    writer.element_if_present("Delimiter", "");
    writer.element_if_present("Prefix", "p");
    assert_eq!(writer.finish(), "<Prefix>p</Prefix>");
}

#[test]
fn escapes_the_characters_that_change_meaning() {
    let mut writer = XmlWriter::fragment();
    writer.element("Key", "a&b<c>d\re");
    assert_eq!(writer.finish(), "<Key>a&amp;b&lt;c&gt;d&#13;e</Key>");
}

/// The bytes S3 wrote for the prefix `a"b'c<d>e&f` (recorded on rustfs/gateway#13).
#[test]
fn escapes_both_quotes_in_every_text_node_as_s3_does() {
    let mut writer = XmlWriter::fragment();
    writer.element("Prefix", "a\"b'c<d>e&f");
    assert_eq!(writer.finish(), "<Prefix>a&quot;b&apos;c&lt;d&gt;e&amp;f</Prefix>");
}

#[test]
fn n_an_entity_tag_and_an_object_key_are_escaped_alike() {
    // The corpus once pinned `&quot;` inside `<ETag>` and a literal `"` inside `<Key>`
    // (rustfs/gateway#13). S3 writes one escaping for both, so there is one writer method.
    let mut writer = XmlWriter::fragment();
    writer.element("ETag", "\"d41d8cd98f00b204e9800998ecf8427e\"");
    writer.element("Key", "a&b<c>d\"e.txt");
    assert_eq!(
        writer.finish(),
        "<ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag><Key>a&amp;b&lt;c&gt;d&quot;e.txt</Key>"
    );
}

#[test]
fn n_a_quote_is_escaped_in_the_unwrapped_text_form_too() {
    let mut writer = XmlWriter::fragment();
    writer.open("LocationConstraint", None);
    writer.text("it's \"here\"");
    writer.close();
    assert_eq!(writer.finish(), "<LocationConstraint>it&apos;s &quot;here&quot;</LocationConstraint>");
}

#[test]
fn n_the_omit_policy_drops_an_empty_entity_tag() {
    let mut writer = XmlWriter::fragment();
    writer.element_if_present("ETag", "");
    writer.element_if_present("ETag", "\"abc\"");
    assert_eq!(writer.finish(), "<ETag>&quot;abc&quot;</ETag>");
}

#[test]
fn escapes_quotes_and_whitespace_inside_an_attribute() {
    let mut writer = XmlWriter::fragment();
    writer.open_with("Node", &[("id", "a\"b\nc")]);
    writer.close();
    assert_eq!(writer.finish(), "<Node id=\"a&quot;b&#10;c\"></Node>");
}

#[test]
fn closes_everything_still_open_on_finish() {
    let mut writer = XmlWriter::fragment();
    writer.open("A", None);
    writer.open("B", None);
    assert_eq!(
        writer.finish(),
        "<A><B></B></A>",
        "a truncated body is indistinguishable from a dropped connection"
    );
}

// ---------------------------------------------------------------------------------------------
// Reader — every case below is a refusal except the first
// ---------------------------------------------------------------------------------------------

#[test]
fn reads_a_nested_body_into_a_tree() {
    let root = parse(b"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object><Quiet>true</Quiet></Delete>")
        .expect("a well-formed body parses");

    assert_eq!(root.name, "Delete");
    assert_eq!(root.child_text("Quiet"), Some("true"));
    let keys: Vec<&str> = root
        .children_named("Object")
        .filter_map(|object| object.child_text("Key"))
        .collect();
    assert_eq!(keys, vec!["a", "b"]);
}

#[test]
fn c_lim_0003_reads_a_body_at_depth_thirty() {
    let mut body = String::new();
    for _ in 0..30 {
        body.push_str("<A>");
    }
    for _ in 0..30 {
        body.push_str("</A>");
    }

    assert!(parse(body.as_bytes()).is_ok());
}

#[test]
fn reads_a_prefixed_element_under_its_local_name() {
    let root = parse(b"<s3:Delete xmlns:s3=\"urn:x\"><s3:Quiet>true</s3:Quiet></s3:Delete>").expect("parses");
    assert_eq!(root.name, "Delete");
    assert_eq!(root.child_text("Quiet"), Some("true"));
}

#[test]
fn n_refuses_a_doctype_declaration() {
    let body = b"<!DOCTYPE Delete [<!ENTITY x \"y\">]><Delete></Delete>";
    assert_eq!(parse(body), Err(XmlError::DocTypeDeclaration));
}

#[test]
fn c_lim_0025_refuses_an_external_entity_reference() {
    let body = b"<Delete><Quiet>&xxe;</Quiet></Delete>";
    assert!(matches!(parse(body), Err(XmlError::UnsupportedEntity) | Err(XmlError::Malformed)));
}

#[test]
fn n_refuses_a_body_that_is_not_utf8() {
    assert_eq!(parse(&[0xff, 0xfe, 0x00]), Err(XmlError::NotUtf8));
}

#[test]
fn n_refuses_an_unclosed_element() {
    assert_eq!(parse(b"<Delete><Object></Delete>"), Err(XmlError::Malformed));
}

#[test]
fn n_refuses_an_empty_body() {
    assert_eq!(parse(b""), Err(XmlError::Empty));
}

#[test]
fn c_lim_0023_refuses_a_body_that_nests_past_the_depth_ceiling() {
    let mut body = String::new();
    for _ in 0..=MAX_DEPTH {
        body.push_str("<A>");
    }
    for _ in 0..=MAX_DEPTH {
        body.push_str("</A>");
    }
    assert_eq!(parse(body.as_bytes()), Err(XmlError::TooDeep));
}

/// Negative — the same tree with its deepest element self-closed. `<A/>` and `<A></A>` are one
/// element at one depth; counting only the paired spelling let a tree nest one level past the
/// ceiling (rustfs/backlog#1766). The positive half — exactly `MAX_DEPTH` levels ending in `<A/>` —
/// is still accepted.
#[test]
fn n_refuses_a_self_closed_leaf_past_the_depth_ceiling() {
    let nest = |levels: usize| format!("{}<A/>{}", "<A>".repeat(levels), "</A>".repeat(levels));
    assert_eq!(parse(nest(MAX_DEPTH).as_bytes()), Err(XmlError::TooDeep));
    assert!(parse(nest(MAX_DEPTH - 1).as_bytes()).is_ok());
}

#[test]
fn c_lim_0024_refuses_a_body_with_more_elements_than_the_ceiling() {
    let mut body = String::from("<Delete>");
    for _ in 0..MAX_ELEMENTS {
        body.push_str("<Object/>");
    }
    body.push_str("</Delete>");
    assert_eq!(parse(body.as_bytes()), Err(XmlError::TooManyElements));
}

#[test]
fn n_refuses_a_body_larger_than_the_configured_ceiling() {
    let limits = XmlLimits::new(8, MAX_DEPTH, MAX_ELEMENTS, MAX_ATTRIBUTES_PER_ELEMENT, MAX_ATTRIBUTE_BYTES)
        .expect("all limits are non-zero");
    assert_eq!(parse_with_limits(b"<Root></Root>", limits), Err(XmlError::BodyTooLarge));
}

#[test]
fn n_refuses_more_attributes_than_one_element_may_hold() {
    let mut body = String::from("<Root");
    for index in 0..=MAX_ATTRIBUTES_PER_ELEMENT {
        body.push_str(&format!(" a{index}=\"x\""));
    }
    body.push_str("></Root>");

    assert_eq!(parse(body.as_bytes()), Err(XmlError::TooManyAttributes));
}

#[test]
fn c_lim_0026_refuses_an_attribute_value_larger_than_the_ceiling() {
    let value = "x".repeat(MAX_ATTRIBUTE_BYTES + 1);
    let body = format!("<Root value=\"{value}\"></Root>");
    assert_eq!(parse(body.as_bytes()), Err(XmlError::AttributeTooLong));
}

#[test]
fn n_zero_xml_limits_are_not_constructible() {
    assert!(XmlLimits::new(0, MAX_DEPTH, MAX_ELEMENTS, MAX_ATTRIBUTES_PER_ELEMENT, MAX_ATTRIBUTE_BYTES).is_none());
    assert!(XmlLimits::new(1, 0, MAX_ELEMENTS, MAX_ATTRIBUTES_PER_ELEMENT, MAX_ATTRIBUTE_BYTES).is_none());
    assert!(XmlLimits::new(1, MAX_DEPTH, 0, MAX_ATTRIBUTES_PER_ELEMENT, MAX_ATTRIBUTE_BYTES).is_none());
    assert!(XmlLimits::new(1, MAX_DEPTH, MAX_ELEMENTS, 0, MAX_ATTRIBUTE_BYTES).is_none());
    assert!(XmlLimits::new(1, MAX_DEPTH, MAX_ELEMENTS, MAX_ATTRIBUTES_PER_ELEMENT, 0).is_none());
}

#[test]
fn n_refuses_two_root_elements() {
    assert_eq!(parse(b"<A></A><B></B>"), Err(XmlError::Malformed));
}

#[test]
fn resolves_only_the_five_predefined_entities() {
    let root = parse(b"<Key>&amp;&lt;&gt;&quot;&apos;</Key>").expect("the predefines resolve");
    assert_eq!(root.text, "&<>\"'");
}

// ---------------------------------------------------------------------------------------------
// Attribute reading, for the one member of the S3 surface that is written as an attribute
// ---------------------------------------------------------------------------------------------

/// The XML Schema instance namespace, which is the only namespace an S3 request body binds.
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// The `<Grantee>` element as AWS writes it, with the declaration on the element that uses it.
const GRANTEE: &[u8] =
    br#"<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>g</URI></Grantee>"#;

/// Positive — the attribute AWS discriminates a grantee with reaches the caller, resolved to the
/// namespace its prefix was bound to on that same element.
#[test]
fn reads_the_grantee_discriminator_from_the_element_that_declares_its_prefix() {
    let root = parse(GRANTEE).expect("the grantee parses");
    assert_eq!(root.attribute_ns(XSI, "type"), Some("Group"));
    assert_eq!(root.child_text("URI"), Some("g"));
}

/// Positive — a prefix is a document-local alias, so the same namespace spelled with a different
/// prefix is the same attribute. A reader keyed on the literal `xsi:type` would answer `None`.
#[test]
fn reads_the_same_attribute_under_a_different_prefix() {
    let body = br#"<Grantee xmlns:q="http://www.w3.org/2001/XMLSchema-instance" q:type="CanonicalUser"><ID>i</ID></Grantee>"#;
    let root = parse(body).expect("the grantee parses");
    assert_eq!(root.attribute_ns(XSI, "type"), Some("CanonicalUser"));
}

/// Positive — a prefix bound by an ancestor is in scope for a descendant, and the innermost
/// binding of a prefix wins over an outer one.
#[test]
fn resolves_a_prefix_bound_by_an_ancestor_and_prefers_the_innermost_binding() {
    let body = br#"<A xmlns:p="urn:outer"><B p:k="outer"/><C xmlns:p="urn:inner"><D p:k="inner"/></C></A>"#;
    let root = parse(body).expect("the document parses");
    let b = root.child("B").expect("B is present");
    assert_eq!(b.attribute_ns("urn:outer", "k"), Some("outer"));
    let d = root.child("C").and_then(|c| c.child("D")).expect("D is present");
    assert_eq!(d.attribute_ns("urn:inner", "k"), Some("inner"));
    assert_eq!(d.attribute_ns("urn:outer", "k"), None);
}

/// Negative — a prefix goes out of scope when the element that bound it closes. Without the pop,
/// the second `<B>` would resolve against a binding no longer in force.
#[test]
fn n_a_binding_does_not_outlive_the_element_that_declared_it() {
    let body = br#"<A><C xmlns:p="urn:inner"><B p:k="in"/></C><B p:k="out"/></A>"#;
    let root = parse(body).expect("the document parses");
    let inner = root.child("C").and_then(|c| c.child("B")).expect("the inner B");
    assert_eq!(inner.attribute_ns("urn:inner", "k"), Some("in"));
    let outer = root.children_named("B").next().expect("the outer B");
    assert_eq!(outer.attribute_ns("urn:inner", "k"), None);
    assert_eq!(outer.attribute("k"), None);
}

/// Negative — a prefix nothing ever bound resolves to no namespace, so the namespaced lookup does
/// not answer it. `xsi:type` without `xmlns:xsi` is not the attribute AWS sends.
#[test]
fn n_an_unbound_prefix_is_not_the_namespaced_attribute() {
    let root = parse(br#"<Grantee xsi:type="Group"><URI>g</URI></Grantee>"#).expect("the grantee parses");
    assert_eq!(root.attribute_ns(XSI, "type"), None);
    assert_eq!(root.attribute("type"), None);
}

/// Negative — an unprefixed attribute is in no namespace, and a namespaced one is not answered to
/// a caller that asked for the bare name. The two lookups do not leak into each other.
#[test]
fn n_the_bare_and_the_namespaced_lookups_do_not_answer_each_other() {
    let bare = parse(br#"<Grantee type="Group"></Grantee>"#).expect("parses");
    assert_eq!(bare.attribute("type"), Some("Group"));
    assert_eq!(bare.attribute_ns(XSI, "type"), None);

    let namespaced = parse(GRANTEE).expect("parses");
    assert_eq!(namespaced.attribute("type"), None);
}

/// Negative — a namespace declaration is a declaration, not data. It must not surface as an
/// attribute of the element it appears on, or a decoder that reflects attributes back would write
/// `xmlns:xsi` twice.
#[test]
fn n_a_namespace_declaration_is_not_an_attribute() {
    let root = parse(GRANTEE).expect("parses");
    assert_eq!(root.attributes.len(), 1);
    assert_eq!(root.attributes[0].name, "type");
    let defaulted = parse(br#"<A xmlns="urn:d" k="v"></A>"#).expect("parses");
    assert_eq!(defaulted.attributes.len(), 1);
    assert_eq!(defaulted.attribute("k"), Some("v"));
}

/// Positive — an attribute value is unescaped, and the five predefines are the whole set.
#[test]
fn unescapes_an_attribute_value_and_refuses_a_sixth_entity() {
    let root = parse(br#"<A k="&amp;&lt;&gt;&quot;&apos;"></A>"#).expect("the predefines resolve");
    assert_eq!(root.attribute("k"), Some("&<>\"'"));
    assert_eq!(parse(br#"<A k="&xxe;"></A>"#), Err(XmlError::UnsupportedEntity));
}

/// Positive — an empty element carries its attributes too, and its own declaration is in scope for
/// them. `<Grantee …/>` is the shape a grantee with no members takes.
#[test]
fn an_empty_element_carries_its_attributes() {
    let body = br#"<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"/>"#;
    let root = parse(body).expect("parses");
    assert_eq!(root.attribute_ns(XSI, "type"), Some("Group"));
}

/// Negative — the ceilings still bite once attributes are kept, and a declaration counts toward
/// them: a document cannot buy extra attribute budget by spelling them `xmlns:`.
#[test]
fn n_declarations_count_against_the_attribute_ceiling() {
    let mut body = String::from("<Root");
    for index in 0..=MAX_ATTRIBUTES_PER_ELEMENT {
        body.push_str(&format!(" xmlns:p{index}=\"urn:{index}\""));
    }
    body.push_str("></Root>");
    assert_eq!(parse(body.as_bytes()), Err(XmlError::TooManyAttributes));

    let value = "x".repeat(MAX_ATTRIBUTE_BYTES + 1);
    let long = format!("<Root xmlns:p=\"{value}\"></Root>");
    assert_eq!(parse(long.as_bytes()), Err(XmlError::AttributeTooLong));
}

/// Negative — the same attribute twice on one element is refused rather than resolved to whichever
/// copy the parser happened to keep. Two spellings of one discriminator is a document whose meaning
/// depends on the reader.
#[test]
fn n_refuses_an_element_carrying_the_same_attribute_twice() {
    assert_eq!(parse(br#"<Grantee a="1" a="2"></Grantee>"#), Err(XmlError::Malformed));
    let repeated =
        br#"<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group" xsi:type="CanonicalUser"/>"#;
    assert_eq!(parse(repeated), Err(XmlError::Malformed));
}

/// Positive — a namespace is shared by every attribute that resolves through one declaration, so a
/// document that declares once and refers many times does not make this side hold one copy per
/// reference. The pointer equality is the assertion: a `String` per attribute would pass every
/// other test in this file and allocate four hundred megabytes from a one-megabyte body.
#[test]
fn shares_one_namespace_across_every_attribute_that_resolves_through_it() {
    let long = "urn:".to_owned() + &"n".repeat(2048);
    let body = format!(r#"<A xmlns:p="{long}"><B p:k="1"/><B p:k="2"/></A>"#);
    let root = parse(body.as_bytes()).expect("the document parses");
    let mut children = root.children_named("B");
    let first = children.next().expect("the first B");
    let second = children.next().expect("the second B");
    let one = first.attributes.first().expect("an attribute").namespace.clone();
    let two = second.attributes.first().expect("an attribute").namespace.clone();
    assert_eq!(one.as_deref(), Some(long.as_str()));
    let (Some(one), Some(two)) = (one, two) else {
        unreachable!("both attributes resolved");
    };
    assert!(std::sync::Arc::ptr_eq(&one, &two), "the namespace is shared, not copied per attribute");
}

// ---------------------------------------------------------------------------------------------
// The XML 1.0 character range, in both directions (rustfs/gateway#256)
// ---------------------------------------------------------------------------------------------

/// The characters XML 1.0 excludes from a document entirely, one per class of the exclusion.
///
/// Not an exhaustive list of C0 — one from each end and each interesting middle is what a
/// per-character predicate can be wrong about. `U+FFFE` and `U+FFFF` are here because the
/// exclusion is not "control characters": it is a range, and the top two code points of the BMP
/// are outside it for reasons that have nothing to do with C0.
const FORBIDDEN: &[char] = &['\u{0}', '\u{1}', '\u{8}', '\u{b}', '\u{c}', '\u{1f}', '\u{fffe}', '\u{ffff}'];

/// The characters that look like they should be forbidden and are not.
///
/// Tab, newline and carriage return are the three C0 controls XML 1.0 admits. `U+007F` is the one
/// that catches an implementation written against XML 1.1, which requires DEL to be escaped;
/// XML 1.0, which is what S3 speaks, admits it raw. Measured against `expat`: `<v>a\u{7f}b</v>`
/// is well-formed and `<v>a\u{1}b</v>` is not.
const PERMITTED: &[char] = &[
    '\t',
    '\n',
    '\r',
    '\u{7f}',
    '\u{20}',
    '\u{d7ff}',
    '\u{e000}',
    '\u{fffd}',
    '\u{10000}',
];

/// Negative — the predicate answers the `Char` production of XML 1.0 and not "no control
/// characters".
#[test]
fn n_the_character_predicate_is_the_xml_range_and_not_a_control_blocklist() {
    for character in FORBIDDEN {
        assert!(
            !crate::is_xml_char(*character),
            "U+{:04X} is outside XML 1.0's Char production",
            *character as u32
        );
        let value = format!("a{character}b");
        assert!(!crate::is_xml_representable(&value), "U+{:04X}", *character as u32);
    }
    for character in PERMITTED {
        assert!(
            crate::is_xml_char(*character),
            "U+{:04X} is inside XML 1.0's Char production",
            *character as u32
        );
        let value = format!("a{character}b");
        assert!(crate::is_xml_representable(&value), "U+{:04X}", *character as u32);
    }
}

/// Negative — the reader refuses element text carrying a character XML 1.0 cannot represent.
///
/// This is the ingress. `quick-xml` does not validate the character range, so without this the
/// value is read, handed to a decoder as an ordinary string member, stored, and echoed into a
/// response no conforming parser will accept.
#[test]
fn n_refuses_element_text_carrying_a_character_xml_cannot_represent() {
    for character in FORBIDDEN {
        let body = format!("<Root><Value>a{character}b</Value></Root>");
        assert_eq!(
            parse(body.as_bytes()),
            Err(XmlError::ForbiddenCharacter),
            "U+{:04X} in element text",
            *character as u32
        );
    }
}

/// Negative — the three spellings of the same character are one refusal.
///
/// A reader that refused only the raw byte would be trivially bypassed: `&#1;` and `&#x1;` are
/// resolved by this crate, by name, and both produce the same `U+0001`. XML 1.0 makes a character
/// reference to a character outside the `Char` production a fatal error for exactly this reason.
/// CDATA is the fourth spelling and the one a blocklist over the escaped forms would miss.
#[test]
fn n_refuses_every_spelling_of_a_character_xml_cannot_represent() {
    for body in [
        "<Root><Value>a&#1;b</Value></Root>",
        "<Root><Value>a&#x1;b</Value></Root>",
        "<Root><Value>a&#xB;b</Value></Root>",
        "<Root><Value>a&#xFFFE;b</Value></Root>",
        "<Root><Value><![CDATA[a\u{1}b]]></Value></Root>",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::ForbiddenCharacter), "{body:?}");
    }
}

/// Negative — an attribute value and an element name are refused on the same rule.
///
/// The `<Grantee>` discriminator is read from an attribute, and a namespace binding is an
/// attribute value that this crate stores and shares. A rule applied to text alone would leave
/// three stored strings outside it.
#[test]
fn n_refuses_a_forbidden_character_in_an_attribute_value_or_a_name() {
    let attribute = "<Grantee xmlns:xsi=\"urn:x\" xsi:type=\"Grou\u{1}p\"></Grantee>";
    assert_eq!(parse(attribute.as_bytes()), Err(XmlError::ForbiddenCharacter));

    let declaration = "<Grantee xmlns:xsi=\"urn:\u{1}x\"></Grantee>";
    assert_eq!(parse(declaration.as_bytes()), Err(XmlError::ForbiddenCharacter));

    let name = "<Ro\u{1}ot></Ro\u{1}ot>";
    assert_eq!(parse(name.as_bytes()), Err(XmlError::ForbiddenCharacter));
}

/// Negative — an element or attribute name outside the XML `Name` production is refused whole,
/// before any decoder sees the tree (rustfs/gateway#743). The first is the fuzz finding: `quick-xml`
/// tokenises `<xmlns:p="urn:p" …/>` as an element named `xmlns:p="urn:p"`. The rest walk the
/// production's edges: a digit or `-` first, a `,` inside, and an empty part beside a colon on
/// either side.
#[test]
fn n_refuses_an_element_or_attribute_name_that_is_not_an_xml_name() {
    for body in [
        "<xmlns:p=\"urn:p\" p:x=\"1\" y=\"2\" z=\"3\"/>",
        "<1a></1a>",
        "<-a/>",
        "<a,b/>",
        "<Root><a,b>t</a,b></Root>",
        "<Root a,b=\"1\"></Root>",
        "<Root 1a=\"1\"/>",
        "<:a/>",
        "<a:/>",
        "<a::b/>",
        "<Root :k=\"1\"/>",
        "<Root xmlns:=\"urn:x\"/>",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::InvalidName), "{body}");
    }
}

/// Negative — a prefixed name whose parts are not each a `Name` is refused (rustfs/gateway#1077).
/// `a:2` is a `Name` as a whole, but this reader keeps only an element's local part and resolves an
/// attribute's prefix, so the part has to stand on its own: `<a:2/>` was accepted as the element
/// `2`, whose canonical spelling `<2/>` it then refused. The two fuzz reproducers are the first two
/// documents; the rest are the same shape on a prefix, a `-` and a `.`, a two-colon name, an
/// attribute under a bound prefix, and a namespace declaration.
#[test]
fn n_refuses_a_prefixed_name_whose_parts_are_not_each_a_name() {
    for body in [
        "<a:2 k=\"3456yyyyyyy&lt;y&lt;y{yyyy99\"/>",
        "<x3.66:66389 q=\"4\"/>",
        "<2:a/>",
        "<a:-x/>",
        "<a:.x/>",
        "<a:b:3/>",
        "<Root><a:9>t</a:9></Root>",
        "<Root xmlns:x=\"urn:x\" x:1=\"v\"/>",
        "<Root xmlns:1=\"urn:x\"/>",
    ] {
        assert_eq!(parse(body.as_bytes()), Err(XmlError::InvalidName), "{body}");
    }
}

/// Positive control for the rule above — a part may carry a digit, `-` or `.` after its first
/// character, and every accepted name is written back into a document this reader reads into the
/// same tree, which is the property rustfs/gateway#1077's input broke.
#[test]
fn a_prefixed_name_whose_parts_are_names_reads_and_round_trips() {
    for (body, name) in [
        ("<a:b2/>", "b2"),
        ("<a:b.c-d/>", "b.c-d"),
        ("<_:x/>", "x"),
        ("<x3.66:y66/>", "y66"),
    ] {
        let tree = parse(body.as_bytes()).unwrap_or_else(|error| panic!("{body}: {error}"));
        assert_eq!(tree.name, name, "{body}");
        let mut writer = XmlWriter::fragment();
        writer.open(&tree.name, None);
        writer.close();
        assert_eq!(parse(writer.finish().as_bytes()).as_ref(), Ok(&tree), "{body}");
    }
    let tree = parse(b"<Root xmlns:x=\"urn:x\" x:k1=\"v\"/>").expect("a prefixed attribute whose parts are names");
    assert_eq!(tree.attribute_ns("urn:x", "k1"), Some("v"));
}

/// Positive control for the rule above — every spelling the production admits still reads: the
/// colon-free names S3 uses, a prefixed name, a name with `.`, `-`, `_` and a digit after the
/// first character, a Latin-1 letter, a CJK name, and the two-colon name this crate has always
/// read by its last part.
#[test]
fn accepts_every_name_the_production_admits() {
    for (body, name) in [
        ("<Delete/>", "Delete"),
        ("<s3:Object xmlns:s3=\"urn:s3\"/>", "Object"),
        ("<a.b-c_d9/>", "a.b-c_d9"),
        ("<_leading/>", "_leading"),
        ("<caf\u{e9}/>", "caf\u{e9}"),
        ("<\u{540d}\u{524d}/>", "\u{540d}\u{524d}"),
        ("<x:y:z/>", "z"),
    ] {
        let tree = parse(body.as_bytes()).unwrap_or_else(|error| panic!("{body}: {error}"));
        assert_eq!(tree.name, name, "{body}");
    }
    let attribute = parse(b"<Root k.1=\"v\" _w-2=\"x\"/>").expect("Name attributes are read");
    assert_eq!(attribute.attribute("k.1"), Some("v"));
    assert_eq!(attribute.attribute("_w-2"), Some("x"));
}

/// The `Name` predicate at its edges, apart from any document: the first character is the
/// narrower set, `U+00B7` and the combining range continue but do not start, and a character
/// outside `Char` altogether is also outside `Name`.
#[test]
fn n_the_name_predicate_holds_the_production_edges() {
    use crate::chars::is_xml_name;
    for name in [
        "a",
        "_",
        ":",
        "A1",
        "a-b",
        "a.b",
        "a\u{b7}",
        "a\u{300}",
        "a\u{203f}",
        "\u{10000}a",
    ] {
        assert!(is_xml_name(name), "{name:?} is a Name");
    }
    for name in [
        "",
        "1",
        "-a",
        ".a",
        "\u{b7}a",
        "\u{300}a",
        "a b",
        "a\"",
        "a/b",
        "a\u{1}",
        "\u{2000}a",
        "a\u{fffe}",
    ] {
        assert!(!is_xml_name(name), "{name:?} is not a Name");
    }
}

/// Positive — XML 1.0 line-end normalisation happens before text reaches a decoder.
///
/// A literal CR and CRLF each become one LF, while a numeric character reference remains a CR.
/// The last direction keeps the normaliser from rewriting the decoded value rather than the
/// document's literal bytes. Tab and DEL keep the character guard from widening into "no control
/// characters".
#[test]
fn normalises_literal_line_ends_without_rewriting_a_character_reference() {
    let body = "<Root><Cr>a\rb</Cr><CrLf>c\r\nd</CrLf><CData><![CDATA[e\r\nf]]></CData><Reference>g&#13;h</Reference><Controls>i\tj\u{7f}k</Controls></Root>";
    let root = parse(body.as_bytes()).expect("the XML 1.0 characters are legal");
    assert_eq!(root.child_text("Cr"), Some("a\nb"));
    assert_eq!(root.child_text("CrLf"), Some("c\nd"));
    assert_eq!(root.child_text("CData"), Some("e\nf"));
    assert_eq!(root.child_text("Reference"), Some("g\rh"));
    assert_eq!(root.child_text("Controls"), Some("i\tj\u{7f}k"));
}

/// Negative — the writer cannot emit a character the reader refuses.
///
/// The two halves are one predicate, so the refused set and the un-writable set are the same set.
/// Without this the reader's refusal would be the only guard, and the reader never sees a value a
/// backend already held: `GetBucketLifecycleConfiguration` answers from the store, not from the
/// request, so a value written through some other channel would still produce a document that is
/// not well-formed.
#[test]
fn n_the_writer_cannot_emit_a_character_the_reader_refuses() {
    for character in FORBIDDEN {
        let mut writer = XmlWriter::fragment();
        writer.open("Root", None);
        writer.element("Value", &format!("a{character}b"));
        writer.open_with("Grantee", &[("type", &format!("a{character}b"))]);
        writer.close();
        writer.close();
        let document = writer.finish();

        assert!(
            !document.contains(*character),
            "the writer emitted U+{:04X}, which makes the whole document unparseable",
            *character as u32
        );
        assert!(
            document.contains(crate::UNREPRESENTABLE),
            "the substitute is visible, not a silent deletion"
        );
        // The bytes the writer produced are readable by the reader that refuses the input. A
        // writer whose output its own reader rejects is the round trip this crate exists to keep.
        parse(document.as_bytes()).expect("what the writer wrote is well-formed");
    }
}

/// Positive — a legal value is written byte for byte, escaping unchanged.
///
/// The two-directional half of the test above: without it, a writer that replaced *every*
/// character would satisfy "emits nothing forbidden" perfectly.
#[test]
fn a_representable_value_is_written_unchanged_by_the_character_guard() {
    let mut writer = XmlWriter::fragment();
    writer.open("Root", None);
    writer.element("Value", "a&b<c>d\"e\tf\ng\u{7f}h\u{e9}");
    writer.close();
    assert_eq!(writer.finish(), "<Root><Value>a&amp;b&lt;c&gt;d&quot;e\tf\ng\u{7f}h\u{e9}</Value></Root>");
}

/// Positive — raising the body ceiling admits a larger document and keeps every other bound.
#[test]
fn a_raised_body_ceiling_admits_a_larger_document_and_keeps_the_other_bounds() {
    let raised = XmlLimits::S3
        .with_max_body_bytes(4 * MAX_BODY_BYTES)
        .expect("a non-zero ceiling");
    assert_eq!(raised.max_body_bytes(), 4 * MAX_BODY_BYTES);
    assert_eq!(raised.max_depth(), MAX_DEPTH);
    assert_eq!(raised.max_elements(), MAX_ELEMENTS);
    assert_eq!(raised.max_attributes_per_element(), MAX_ATTRIBUTES_PER_ELEMENT);
    assert_eq!(raised.max_attribute_bytes(), MAX_ATTRIBUTE_BYTES);
    let body = format!("<Root>{}</Root>", " ".repeat(2 * MAX_BODY_BYTES));
    assert!(parse_with_limits(body.as_bytes(), raised).is_ok());
    assert_eq!(parse(body.as_bytes()), Err(XmlError::BodyTooLarge));
}

/// Negative — a zero ceiling is refused rather than read as unlimited.
#[test]
fn n_a_zero_body_ceiling_is_refused() {
    assert!(XmlLimits::S3.with_max_body_bytes(0).is_none());
}

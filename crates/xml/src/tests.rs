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
    MAX_ATTRIBUTE_BYTES, MAX_ATTRIBUTES_PER_ELEMENT, MAX_DEPTH, MAX_ELEMENTS, XmlLimits, parse, parse_with_limits,
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

#[test]
fn leaves_a_double_quote_alone_in_an_ordinary_text_node() {
    // Pinned rather than incidental: an object key carrying a quote comes back with the literal
    // byte (`c-list-0036`), so a writer that escaped every `"` would be wrong in that element as
    // surely as one that escapes none is wrong in an entity tag.
    let mut writer = XmlWriter::fragment();
    writer.element("Key", "a&b<c>d\"e.txt");
    assert_eq!(writer.finish(), "<Key>a&amp;b&lt;c&gt;d\"e.txt</Key>");
}

#[test]
fn escapes_a_double_quote_in_the_quoting_form() {
    let mut writer = XmlWriter::fragment();
    writer.element_quoting("ETag", "\"d41d8cd98f00b204e9800998ecf8427e\"");
    assert_eq!(writer.finish(), "<ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>");
}

#[test]
fn the_quoting_form_still_escapes_everything_the_ordinary_one_does() {
    let mut writer = XmlWriter::fragment();
    writer.element_quoting("ETag", "\"a&b<c>d\re\"");
    assert_eq!(writer.finish(), "<ETag>&quot;a&amp;b&lt;c&gt;d&#13;e&quot;</ETag>");
}

#[test]
fn n_the_quoting_form_drops_an_empty_value_under_the_omit_policy() {
    let mut writer = XmlWriter::fragment();
    writer.element_quoting_if_present("ETag", "");
    writer.element_quoting_if_present("ETag", "\"abc\"");
    assert_eq!(
        writer.finish(),
        "<ETag>&quot;abc&quot;</ETag>",
        "the omit policy is the same decision whichever escaping is in force"
    );
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

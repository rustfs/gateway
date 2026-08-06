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

//! Reader refusals and writer byte shapes.
//!
//! Every writer test compares whole bytes, because the properties this crate promises — no
//! whitespace, paired empty elements, escaping — are only observable that way.

use crate::error::XmlError;
use crate::read::parse;
use crate::write::{S3_XMLNS, XmlWriter};

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
fn n_refuses_an_external_entity_reference() {
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
fn n_refuses_a_body_that_nests_past_the_depth_ceiling() {
    let mut body = String::new();
    for _ in 0..64 {
        body.push_str("<A>");
    }
    for _ in 0..64 {
        body.push_str("</A>");
    }
    assert_eq!(parse(body.as_bytes()), Err(XmlError::TooDeep));
}

#[test]
fn n_refuses_a_body_with_more_elements_than_the_ceiling() {
    let mut body = String::from("<Delete>");
    for _ in 0..40_000 {
        body.push_str("<Object></Object>");
    }
    body.push_str("</Delete>");
    assert_eq!(parse(body.as_bytes()), Err(XmlError::TooManyElements));
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

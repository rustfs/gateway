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

//! Element-fragment validation at the response writer boundary.
//!
//! Responsible for: rejecting document declarations without changing the parent, and
//! preserving ordinary nested elements and declaration-looking character content.
//! NOT responsible for: changing request document acceptance or extension registration.
//! Upstream: `XmlWriter::append_fragment`. Downstream: the XML verification suite.

use crate::{DECLARATION, XmlError, XmlWriter};

fn refuses_without_changing_parent(fragment: &str) {
    let mut writer = XmlWriter::fragment();
    writer.legacy_layout(true);
    writer.open("Root", None);
    writer.order_children(&["After", "Before"]);
    writer.element("Before", "kept");
    let before = writer.len();
    assert_eq!(writer.append_fragment(fragment), Err(XmlError::Malformed));
    assert_eq!(writer.len(), before);
    writer.element("After", "kept");
    assert_eq!(writer.finish(), "<Root><After>kept</After><Before>kept</Before></Root>");
}

#[test]
fn n_fragment_refuses_a_leading_document_declaration() {
    refuses_without_changing_parent(&format!("{DECLARATION}<Child></Child>"));
}

#[test]
fn n_fragment_refuses_a_nested_document_declaration() {
    refuses_without_changing_parent("<Child><?xml version=\"1.0\"?><Leaf></Leaf></Child>");
}

#[test]
fn n_fragment_refuses_a_trailing_document_declaration() {
    refuses_without_changing_parent("<Child></Child><?xml version=\"1.0\"?>");
}

#[test]
fn n_fragment_refuses_case_variants_of_the_reserved_xml_target() {
    for target in ["XML", "xMl"] {
        refuses_without_changing_parent(&format!("<Child><?{target} version=\"1.0\"?></Child>"));
    }
}

#[test]
fn fragment_preserves_a_nested_element() {
    let mut writer = XmlWriter::fragment();
    writer.open("Root", None);
    writer.append_fragment("<Child><Leaf>a&amp;b</Leaf></Child>").unwrap();
    assert_eq!(writer.finish(), "<Root><Child><Leaf>a&amp;b</Leaf></Child></Root>");
}

#[test]
fn fragment_preserves_declaration_looking_character_content() {
    let mut writer = XmlWriter::fragment();
    writer.open("Root", None);
    let fragment = "<Child><![CDATA[<?xml version=\"1.0\"?>]]>&lt;?xml version=&quot;1.0&quot;?&gt;</Child>";
    writer.append_fragment(fragment).unwrap();
    assert_eq!(writer.finish(), format!("<Root>{fragment}</Root>"));
}

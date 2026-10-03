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

//! The writer's legacy layout (rustfs/gateway#1078): the compact declaration, declared child
//! orders, and the compact declaration's own stripping.
//!
//! Responsible for: `XmlWriter::legacy_layout`, `XmlWriter::order_children`,
//! `XmlWriter::entity_tag_element` and `strip_compact_declaration`, on and off.
//! NOT responsible for: the default writer and reader matrices (`tests.rs`).
//! Upstream: `crate::write`. Downstream: nothing.

use crate::write::{COMPACT_DECLARATION, DECLARATION, S3_XMLNS, XmlWriter, strip_compact_declaration, strip_declaration};

const RULE_ORDER: &[&str] = &["DelMarkerExpiration", "Expiration", "Filter", "ID", "Status", "Transition"];

/// A rule written in model order, its transitions repeated and one child no order names.
fn rule(writer: &mut XmlWriter) {
    writer.open("Rule", None);
    writer.order_children(RULE_ORDER);
    writer.open("Expiration", None);
    writer.element("Days", "30");
    writer.close();
    writer.element("ID", "r");
    writer.element("Extra", "x");
    writer.open("Filter", None);
    writer.order_children(&["And", "Prefix", "Tag"]);
    writer.open("Tag", None);
    writer.close();
    writer.element("Prefix", "logs/");
    writer.close();
    writer.element("Status", "Enabled");
    writer.element("Transition", "1");
    writer.element("DelMarkerExpiration", "7");
    writer.element("Transition", "2");
    writer.close();
}

/// Positive — under the legacy layout the declaration has no line end and every ordered element's
/// children are rearranged into their declared order, nested orders included, with repeated
/// children keeping their written order and a child no order names after all the named ones.
#[test]
fn the_legacy_layout_writes_the_compact_declaration_and_declared_orders() {
    let mut writer = XmlWriter::document();
    writer.legacy_layout(true);
    writer.open("LifecycleConfiguration", Some(S3_XMLNS));
    rule(&mut writer);
    writer.close();
    assert_eq!(
        writer.finish(),
        format!(
            "{COMPACT_DECLARATION}<LifecycleConfiguration xmlns=\"{S3_XMLNS}\"><Rule><DelMarkerExpiration>7</DelMarkerExpiration>\
             <Expiration><Days>30</Days></Expiration><Filter><Prefix>logs/</Prefix><Tag></Tag></Filter><ID>r</ID>\
             <Status>Enabled</Status><Transition>1</Transition><Transition>2</Transition><Extra>x</Extra></Rule>\
             </LifecycleConfiguration>"
        )
    );
}

/// Negative — by default a declared order changes nothing: the children stay in the order they
/// were written, and the declaration keeps its line end.
#[test]
fn n_the_default_layout_ignores_declared_orders() {
    let mut layout_off = XmlWriter::document();
    layout_off.legacy_layout(false);
    for mut writer in [XmlWriter::document(), layout_off] {
        writer.open("LifecycleConfiguration", None);
        rule(&mut writer);
        writer.close();
        assert_eq!(
            writer.finish(),
            format!(
                "{DECLARATION}<LifecycleConfiguration><Rule><Expiration><Days>30</Days></Expiration><ID>r</ID><Extra>x</Extra>\
                 <Filter><Tag></Tag><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Transition>1</Transition>\
                 <DelMarkerExpiration>7</DelMarkerExpiration><Transition>2</Transition></Rule></LifecycleConfiguration>"
            )
        );
    }
}

/// Negative — the layout is decided before the root: asked for once an element is open it changes
/// nothing, and a fragment writer, with no declaration, gains none.
#[test]
fn n_the_layout_is_fixed_once_the_root_is_open() {
    let mut late = XmlWriter::document();
    late.open("A", None);
    late.legacy_layout(true);
    late.order_children(&["C", "B"]);
    late.element("B", "b");
    late.element("C", "c");
    late.close();
    assert_eq!(late.finish(), format!("{DECLARATION}<A><B>b</B><C>c</C></A>"));

    let mut fragment = XmlWriter::fragment();
    fragment.legacy_layout(true);
    fragment.open("A", None);
    fragment.order_children(&["C", "B"]);
    fragment.element("B", "b");
    fragment.element("C", "c");
    fragment.close();
    assert_eq!(fragment.finish(), "<A><C>c</C><B>b</B></A>");
}

/// Negative — an appended fragment is a child no order names, so it follows every named child; an
/// element with no children is written unchanged.
#[test]
fn n_a_fragment_ranks_after_every_named_child() {
    let mut writer = XmlWriter::fragment();
    writer.legacy_layout(true);
    writer.open("A", None);
    writer.order_children(&["B", "C"]);
    writer.append_fragment("<Ext>e</Ext>").expect("a well-formed fragment");
    writer.element("C", "c");
    writer.element("B", "b");
    writer.open("Empty", None);
    writer.order_children(&["X"]);
    writer.close();
    writer.close();
    assert_eq!(writer.finish(), "<A><B>b</B><C>c</C><Ext>e</Ext><Empty></Empty></A>");
}

/// Negative — the compact declaration is removed only by its own function, and only at the front;
/// the default declaration's function leaves it, as it leaves every other form.
#[test]
fn n_the_compact_declaration_is_removed_only_by_its_own_function() {
    let compact = format!("{COMPACT_DECLARATION}<A></A>");
    assert_eq!(strip_compact_declaration(compact.as_bytes()), b"<A></A>");
    assert_eq!(strip_declaration(compact.as_bytes()), compact.as_bytes());
    let default = format!("{DECLARATION}<A></A>");
    assert_eq!(strip_compact_declaration(default.as_bytes()), default.as_bytes());
    assert_eq!(strip_compact_declaration(b"<A></A>"), b"<A></A>");
}

/// Positive — under the legacy layout an entity tag's quotes are written as they are, as legacy
/// RustFS writes them; the rest of the tag and every other text node stay escaped.
#[test]
fn the_legacy_layout_writes_an_entity_tags_quotes_as_they_are() {
    let mut writer = XmlWriter::document();
    writer.legacy_layout(true);
    writer.open("R", None);
    writer.entity_tag_element("ETag", "\"5d41&402\"");
    writer.entity_tag_element_if_present("ETag", "");
    writer.element("Key", "\"k\"");
    writer.close();
    assert_eq!(
        writer.finish(),
        format!("{COMPACT_DECLARATION}<R><ETag>\"5d41&amp;402\"</ETag><Key>&quot;k&quot;</Key></R>")
    );
}

/// Negative — outside the legacy layout an entity tag is element text like any other: both
/// quotes escaped, and an empty one written only by the unconditional call.
#[test]
fn n_the_default_layout_escapes_an_entity_tags_quotes() {
    let mut writer = XmlWriter::document();
    writer.open("R", None);
    writer.entity_tag_element("ETag", "\"v\"");
    writer.entity_tag_element_if_present("ETag", "");
    writer.entity_tag_element("Empty", "");
    writer.close();
    assert_eq!(writer.finish(), format!("{DECLARATION}<R><ETag>&quot;v&quot;</ETag><Empty></Empty></R>"));
}

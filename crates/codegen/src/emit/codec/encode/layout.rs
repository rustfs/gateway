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

//! The rest of the legacy RustFS response layout the encoders render (rustfs/gateway#1078): the
//! element an answer is rooted at, the call an entity tag is written with, and a list whose
//! presence is carried.
//!
//! Responsible for: [`LEGACY_ROOTS`]; the listing-entry members written as absent when the host does
//! not hold them ([`ABSENT_WHEN_UNHELD`]); the `XmlWriter` call a scalar member is written with; and
//! the iteration and guard of a list whose presence is carried (`emit::dto::presence`): its
//! wrapper written when the list is set, and when it is not only outside the RustFS response
//! layout, as the wrapper of every list is written today.
//! NOT responsible for: the member order (`super::order`), or honouring any of it at run time
//! (`rustfs_gateway_xml::XmlWriter` under its legacy layout).
//! Upstream: the IR. Downstream: the parent's encoders and shape writers, and
//! `super::order::open_root`.

use rustfs_gateway_model::ir::{EmptyValue, OperationIr, Type};

/// The operations whose answer the legacy stack roots at another element than the gateway's
/// `xml.response_root`, with that element: the legacy writer roots every output at its model
/// `xmlName`, and the gateway roots the attributes answer at the element AWS documents instead
/// (`q-attributes-root-0087`).
pub const LEGACY_ROOTS: &[(&str, &str)] = &[("GetObjectAttributes", "GetObjectAttributesResponse")];

/// The element the legacy stack roots `ir`'s answer at, when it is not the gateway's.
#[must_use]
pub fn legacy_root_name(ir: &OperationIr) -> Option<&'static str> {
    LEGACY_ROOTS
        .iter()
        .find(|(operation, _)| *operation == ir.operation)
        .map(|(_, root)| *root)
        .filter(|root| ir.xml.response_root.as_deref() != Some(*root))
}

/// The required listing-entry members a host may not hold, as `(shape, member)`
/// (rustfs/gateway#1613).
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS holds a listing entry's modification time and
/// storage class as optional and writes an entry without the one it lacks — an entry merged from
/// another system's listing, or a version record stored without either — where the model requires
/// both. Under the RustFS response layout such a member, left at its placeholder because the host
/// does not hold it, is written as no element; every other layout writes it as before, so a
/// placeholder timestamp still fails the encode. `Size` is not listed: the host always holds it.
/// The intended future behaviour is the core default, the model's required elements.
pub const ABSENT_WHEN_UNHELD: &[(&str, &str)] = &[
    ("DeleteMarkerEntry", "LastModified"),
    ("Object", "LastModified"),
    ("Object", "StorageClass"),
    ("ObjectVersion", "LastModified"),
    ("ObjectVersion", "StorageClass"),
];

/// The run-time condition, over the member bound to `v`, under which a member
/// [`ABSENT_WHEN_UNHELD`] lists is not written.
pub const UNHELD_UNDER_LEGACY_LAYOUT: &str =
    "(writer.writes_legacy_layout() && rustfs_gateway_types::WirePlaceholder::is_wire_placeholder(v))";

/// Whether `shape.member` is one [`ABSENT_WHEN_UNHELD`] lists.
#[must_use]
pub fn absent_when_unheld(shape: &str, member: &str) -> bool {
    ABSENT_WHEN_UNHELD.iter().any(|(s, m)| *s == shape && *m == member)
}

/// The `XmlWriter` method one scalar body member is written with.
///
/// `empty_value_policy` chooses between writing an empty value as a paired element and dropping
/// it. Escaping is one rule, S3's, which escapes both quotes in every text node (rustfs/gateway#13)
/// — with one exception the type decides: an entity tag is written with `entity_tag_element`,
/// which under the RustFS response layout writes the tag's quotes as they are, as legacy RustFS
/// writes them, and outside it escapes them as every other text node.
#[must_use]
pub fn element_call(ty: &Type, policy: EmptyValue) -> &'static str {
    match (ty, policy) {
        (Type::ETag(_), EmptyValue::Emit) => "entity_tag_element",
        (Type::ETag(_), EmptyValue::Omit) => "entity_tag_element_if_present",
        (_, EmptyValue::Emit) => "element",
        (_, EmptyValue::Omit) => "element_if_present",
    }
}

/// The loop header over a list member's entries at `pad`, each bound to `item`: over the list
/// itself, or over the list a member whose presence is carried holds when it is set.
#[must_use]
pub fn for_items(pad: &str, item: &str, source: &str, presence: bool) -> String {
    if presence {
        format!("{pad}for {item} in {source}.iter().flatten() {{\n")
    } else {
        format!("{pad}for {item} in &{source} {{\n")
    }
}

/// Guards the lines `out` holds for one list member whose presence is carried: they are written
/// when the list is set, and when it is not only outside the RustFS response layout — the legacy
/// stack writes no element for an unset list, and every other deployment writes the empty wrapper
/// it always has. Nothing changes for any other list.
pub fn guard(out: &mut String, pad: &str, source: &str, presence: bool) {
    if !presence {
        return;
    }
    let mut guarded = format!("{pad}if {source}.is_some() || !writer.writes_legacy_layout() {{\n");
    for line in out.lines() {
        if line.is_empty() {
            guarded.push('\n');
        } else {
            guarded.push_str("    ");
            guarded.push_str(line);
            guarded.push('\n');
        }
    }
    guarded.push_str(pad);
    guarded.push_str("}\n");
    *out = guarded;
}

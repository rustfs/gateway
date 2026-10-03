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

//! The order legacy RustFS writes a response document's children in (rustfs/gateway#1078).
//!
//! Responsible for: each response structure's legacy order — the order the legacy stack's
//! structure declares its fields in, which its serializer writes them in, read from the seam's
//! legacy facts — and the `rustfs_order` module of a codec file that carries every order differing
//! from the one the encoder writes.
//! NOT responsible for: writing in that order (`rustfs_gateway_xml::XmlWriter::order_children`,
//! honoured under the RustFS response layout), or which members are written at all (the parent).
//! Upstream: the IR, `emit::seam::legacy_facts`. Downstream: the parent's encoders and shape
//! writers.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Shape, ShapeKind, Type};

use super::super::carried_as_attribute;
use super::ordered_members;
use crate::emit::dto::naming;
use crate::emit::seam::facts::S3sType;

/// The module each codec file declares its legacy RustFS orders in.
pub const RUSTFS_ORDER: &str = "rustfs_order";

/// The legacy RustFS order of a response root's own children, in [`RUSTFS_ORDER`].
pub const RESPONSE_ORDER: &str = "RESPONSE";

/// The response root's body members, in the order the encoder writes them.
pub(super) fn written_members<'a>(ir: &OperationIr, members: &[&'a Field]) -> Vec<&'a Field> {
    ordered_members(ir, members)
        .iter()
        .filter_map(|name| members.iter().find(|field| &field.name == name).copied())
        .collect()
}

/// A structure's members as its writer writes them: in `xml.element_order` when one is declared,
/// and without the one carried as an attribute of the opening tag.
fn written_fields(shape: &Shape) -> Vec<&Field> {
    let order: Vec<&str> = if shape.xml.element_order.is_empty() {
        shape.fields.iter().map(|field| field.name.as_str()).collect()
    } else {
        shape.xml.element_order.iter().map(String::as_str).collect()
    };
    order
        .into_iter()
        .filter_map(|name| shape.fields.iter().find(|field| field.name == name))
        .filter(|field| !carried_as_attribute(shape, &field.name))
        .collect()
}

/// The element a member writes at its structure's own level: a wrapped list's wrapper, a
/// flattened list's entry, and every other member's own element.
fn written_element(field: &Field) -> Result<String, String> {
    let wire = field.wire_name.clone().unwrap_or_else(|| field.name.clone());
    match &field.ty {
        Type::List {
            flattened, member_name, ..
        } => {
            let names = super::super::list_elements(*flattened, member_name.as_deref(), &wire)?;
            Ok(names.wrapper.unwrap_or(names.entry))
        }
        _ => Ok(wire),
    }
}

/// The members of the legacy stack's structure `name`, in the order it declares — and writes —
/// them, or `None` for a structure the legacy stack does not have.
///
/// # Errors
///
/// The legacy facts do not parse.
fn legacy_members(name: &str) -> Result<Option<LegacyMembers>, String> {
    Ok(crate::emit::seam::legacy_facts()?.structs.get(name).map(Vec::as_slice))
}

/// The element names a structure's children are written with, in the order legacy RustFS writes
/// them — the order the legacy stack's structure declares its fields in (rustfs/gateway#1078) —
/// or `None` when that is already the order `written` gives them, or the legacy stack has no such
/// structure. A member the legacy structure lacks, which no answer the legacy stack built can
/// carry, follows every member it has.
///
/// # Errors
///
/// A list member with no XML element, as [`super::super::list_elements`].
pub fn rustfs_order(written: &[&Field], legacy: Option<&[(String, S3sType)]>) -> Result<Option<Vec<String>>, String> {
    let Some(legacy) = legacy else {
        return Ok(None);
    };
    let as_written = written
        .iter()
        .map(|field| written_element(field))
        .collect::<Result<Vec<_>, _>>()?;
    let rank = |field: &Field| {
        let name = naming::field_name(&field.name);
        legacy.iter().position(|(member, _)| *member == name).unwrap_or(legacy.len())
    };
    let mut ordered = written.to_vec();
    ordered.sort_by_key(|field| rank(field));
    let ordered = ordered
        .iter()
        .map(|field| written_element(field))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((ordered != as_written).then_some(ordered))
}

/// The `rustfs_order` module of one codec file: the legacy RustFS order of the response root's
/// children and of every response structure whose order differs from the one written, or `None`
/// when none does.
///
/// # Errors
///
/// As [`rustfs_order`].
pub fn rustfs_order_module(ir: &OperationIr, shapes: &[(&str, &Shape)]) -> Result<Option<String>, String> {
    let mut constants = Vec::new();
    let members: Vec<&Field> = ir.output.iter().filter(|field| field.binding == Binding::BodyXml).collect();
    if !members.is_empty()
        && !ir.xml.unwrapped_output
        && let Some(order) = root_order(ir, &members)?
    {
        constants.push((RESPONSE_ORDER.to_owned(), order));
    }
    for (name, shape) in shapes {
        if let Some(order) = shape_order(name, shape)? {
            constants.push((constant(name), order));
        }
    }
    if constants.is_empty() {
        return Ok(None);
    }
    let mut out = String::from(
        "\n/// The order legacy RustFS writes each response element's children in (rustfs/gateway#1078):\n\
         /// the order the legacy stack's structure declares its fields in.\n\
         /// Honoured under `MetaView::rustfs_response_layout`; generated from the IR.\n\
         #[rustfmt::skip]\n\
         mod rustfs_order {\n",
    );
    for (constant, order) in constants {
        let names = order.iter().map(|name| format!("{name:?}")).collect::<Vec<_>>().join(", ");
        let _ = writeln!(out, "    pub(super) const {constant}: &[&str] = &[{names}];");
    }
    out.push_str("}\n");
    Ok(Some(out))
}

/// The [`RUSTFS_ORDER`] constant of one response structure.
pub fn constant(name: &str) -> String {
    naming::module_name(name).to_ascii_uppercase()
}

/// A legacy structure's members, in declaration order.
type LegacyMembers = &'static [(String, S3sType)];

/// The members a response root is written from, and whether the S3 namespace is written on it.
type LegacyRoot = (LegacyMembers, bool);

/// The legacy structure an operation's response root is written from, and whether the legacy
/// stack writes the S3 namespace on it: an output whose body is one structure member — a copy's
/// result — is written through that structure, without the namespace; every other output is its
/// own root, with it. `None` for an operation the legacy stack does not have.
///
/// # Errors
///
/// The legacy facts do not parse.
fn legacy_root(ir: &OperationIr) -> Result<Option<LegacyRoot>, String> {
    let facts = crate::emit::seam::legacy_facts()?;
    let Some(output) = facts.structs.get(&format!("{}Output", ir.operation)) else {
        return Ok(None);
    };
    let root = ir.xml.response_root.as_deref().unwrap_or_default();
    let payload = output.iter().find_map(|(_, ty)| match ty.unwrap_option().0 {
        S3sType::Struct(name) if name == root => facts.structs.get(name),
        _ => None,
    });
    Ok(Some(match payload {
        Some(members) => (members.as_slice(), false),
        None => (output.as_slice(), true),
    }))
}

/// The legacy order of an operation's response root, or `None` when it is the order written.
///
/// # Errors
///
/// As [`rustfs_order`].
pub fn root_order(ir: &OperationIr, members: &[&Field]) -> Result<Option<Vec<String>>, String> {
    rustfs_order(&written_members(ir, members), legacy_root(ir)?.map(|(members, _)| members))
}

/// Renders the opening of an operation's own response root and its declared order: without the
/// S3 namespace under the RustFS response layout where the legacy stack writes the root from a
/// structure member (rustfs/gateway#1078); `xmlns` is the IR's choice for the default layout.
///
/// # Errors
///
/// As [`rustfs_order`].
pub fn open_root(out: &mut String, ir: &OperationIr, members: &[&Field], root: &str, xmlns: &str) -> Result<(), String> {
    let bare = legacy_root(ir)?.is_some_and(|(_, namespaced)| !namespaced);
    if let Some(legacy) = super::layout::legacy_root_name(ir) {
        let _ = writeln!(out, "        let root = if request.rustfs_response_layout() {{");
        let _ = writeln!(out, "            \"{legacy}\"");
        let _ = writeln!(out, "        }} else {{");
        let _ = writeln!(out, "            \"{root}\"");
        let _ = writeln!(out, "        }};");
        let _ = writeln!(out, "        writer.open(root, {xmlns});");
    } else if bare && xmlns != "None" {
        open_without_namespace(out, root, "        ");
    } else {
        let _ = writeln!(out, "        writer.open(\"{root}\", {xmlns});");
    }
    order_root(out, ir, members)
}

/// The legacy order of one response structure, or `None` when it is the order written.
///
/// # Errors
///
/// As [`rustfs_order`].
pub fn shape_order(name: &str, shape: &Shape) -> Result<Option<Vec<String>>, String> {
    if shape.kind == ShapeKind::Union {
        return Ok(None);
    }
    rustfs_order(&written_fields(shape), legacy_members(name)?)
}

/// Renders a new response document's writer, its layout read from the view: `indent` is the
/// statement's indentation.
pub fn new_document(out: &mut String, indent: &str) {
    let _ = writeln!(out, "{indent}let mut writer = rustfs_gateway_xml::XmlWriter::document();");
    let _ = writeln!(out, "{indent}writer.legacy_layout(request.rustfs_response_layout());");
}

/// Renders the declared order of an operation's own output root, when it has one.
///
/// # Errors
///
/// As [`rustfs_order`].
pub fn order_root(out: &mut String, ir: &OperationIr, members: &[&Field]) -> Result<(), String> {
    if root_order(ir, members)?.is_some() {
        let _ = writeln!(out, "        writer.order_children({RUSTFS_ORDER}::{RESPONSE_ORDER});");
    }
    Ok(())
}

/// Renders the declared order of one response structure's children, when it has one.
///
/// # Errors
///
/// As [`rustfs_order`].
pub fn order_shape(out: &mut String, name: &str, shape: &Shape) -> Result<(), String> {
    if shape_order(name, shape)?.is_some() {
        let _ = writeln!(out, "    writer.order_children({RUSTFS_ORDER}::{});", constant(name));
    }
    Ok(())
}

/// Renders the opening of a payload root, its writer included: under the RustFS response layout
/// without the S3 namespace, which legacy RustFS writes on an operation's own output root and not
/// on a payload structure's (rustfs/gateway#1078); `xmlns` is the IR's choice for the default
/// layout.
pub fn open_payload_root(out: &mut String, root: &str, xmlns: &str) {
    new_document(out, "            ");
    if xmlns == "None" {
        let _ = writeln!(out, "            writer.open(\"{root}\", None);");
        return;
    }
    open_without_namespace(out, root, "            ");
}

/// Renders `writer.open(root, …)` with the S3 namespace in the default layout and without it under
/// the RustFS response layout, at `indent`.
fn open_without_namespace(out: &mut String, root: &str, indent: &str) {
    let _ = writeln!(out, "{indent}let xmlns = if request.rustfs_response_layout() {{");
    let _ = writeln!(out, "{indent}    None");
    let _ = writeln!(out, "{indent}}} else {{");
    let _ = writeln!(out, "{indent}    Some(rustfs_gateway_xml::S3_XMLNS)");
    let _ = writeln!(out, "{indent}}};");
    let _ = writeln!(out, "{indent}writer.open(\"{root}\", xmlns);");
}

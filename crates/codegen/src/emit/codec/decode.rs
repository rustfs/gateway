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

//! The request half: one IR binding to the lines that read it.
//!
//! Responsible for: the body of every generated `decode`, plus the per-shape readers an XML
//! request body needs.
//! NOT responsible for: the conversions themselves ([`super::expr`]) or the response half
//! ([`super::encode`]).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: the generated codec files.
//!
//! # Where the error code for a missing member comes from
//!
//! From the IR, never from here. `PutObject.ContentLength` answers `MissingContentLength` and a
//! `411`, and every other missing member answers `InvalidArgument` and a `400`. The difference is
//! `missing_error` in the overlay, so a family that discovers a third answer records it there
//! rather than teaching this file a third branch.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Quirk, Shape, Type};

use super::{bounds, expr, forms};
use crate::emit::dto::naming;

/// The default code for a required member the request did not carry.
const DEFAULT_MISSING_CODE: &str = "InvalidArgument";

/// The node iterator one list-typed member reads its entries from.
///
/// A flattened list repeats its entry element directly under the parent; a wrapped one sits inside
/// an enclosing element. Which name is which comes from [`super::list_elements`] rather than from
/// here, so the reader and the writer cannot disagree about it — they did, and the disagreement
/// was invisible because both spellings compile.
fn list_source(flattened: bool, wrapper_name: Option<&str>, wire: &str) -> String {
    let names = super::list_elements(flattened, wrapper_name, wire);
    match &names.wrapper {
        None => format!("node.children_named(\"{}\")", names.entry),
        Some(wrapper) => format!(
            "node.child(\"{wrapper}\").into_iter().flat_map(|w| w.children_named(\"{}\"))",
            names.entry
        ),
    }
}

/// rustfmt's `max_width` for this repository.
const MAX_WIDTH: usize = 130;

/// One assignment, laid out the way rustfmt would lay it out.
///
/// `cargo fmt` follows `#[path]` into `generated/`, so an emitter that wrote a line past
/// `max_width` would make `cargo xtask spec verify` fail the moment somebody formatted the tree.
fn assign(indent: usize, target: &str, expression: &str) -> String {
    let pad = " ".repeat(indent);
    let single = format!("{pad}{target} = {expression};\n");
    if single.len().saturating_sub(1) <= MAX_WIDTH {
        return single;
    }
    let continuation = " ".repeat(indent.saturating_add(4));
    format!("{pad}{target} =\n{continuation}{expression};\n")
}

/// Renders the body of one operation's `decode`.
pub fn body(ir: &OperationIr) -> Result<String, String> {
    let mut out = String::new();
    // Functional-update syntax rather than `Input::default()`: the fields are filled in one at a
    // time from bindings that may or may not fire, and `clippy::field_reassign_with_default`
    // refuses the plain form. It is also the construction ADR-0004 P1 asks callers to use.
    out.push_str("        let mut input = Input { ..Default::default() };\n");

    // `checksum.http_checksum_required`, and nothing else, decides this. It is the first statement
    // of the decoder because the operations that carry it are the ones whose body must not be read
    // on an unverifiable request: `DeleteObjects` is a list of keys to destroy, so buffering it and
    // refusing afterwards has already paid for the attack.
    if ir.checksum.http_checksum_required {
        out.push_str("        // The IR declares this operation httpChecksumRequired.\n");
        out.push_str("        value::require_integrity(request)?;\n");
    }

    for field in &ir.input {
        out.push_str(&one_field(ir, field)?);
    }
    if !ir.input.iter().any(uses_body) {
        out.push_str("        let _ = body;\n");
    }
    out.push_str("        value::exit(input.check_required())?;\n        Ok(input)\n");
    Ok(out)
}

fn uses_body(field: &Field) -> bool {
    matches!(field.binding, Binding::Payload | Binding::BodyXml | Binding::FormField)
}

/// Renders the lines that read one input field.
fn one_field(ir: &OperationIr, field: &Field) -> Result<String, String> {
    let op = &ir.operation;
    let member = &field.name;
    let target = format!("input.{}", naming::field_name(member));
    let wire = field.wire_name.clone().unwrap_or_default();
    let mut out = String::new();

    match &field.binding {
        Binding::UriLabel { greedy } => {
            // The only greedy label in the S3 surface is the object key; a non-greedy one is the
            // bucket. Both were split and decoded once, at `MetaView::of`.
            let accessor = if *greedy { "require_key" } else { "require_bucket" };
            let _ = writeln!(out, "        // {member} — URI label, decoded once by `MetaView::of`.");
            out.push_str(&assign(8, &target, &format!("request.{accessor}()?")));
        }
        Binding::Header => {
            let conversion = expr::from_wire(
                &field.ty,
                member,
                op,
                false,
                bounds::of(field, &ir.quirks, op)?,
                forms::of(field, &ir.quirks, op)?,
            )?;
            let _ = writeln!(out, "        // {member} — header `{wire}`, repeated field lines joined.");
            let _ = writeln!(out, "        if let Some(raw) = request.header(\"{wire}\") {{");
            let _ = writeln!(out, "            let raw = raw.as_ref();");
            out.push_str(&assign(12, &target, &wrap(field, &conversion)));
            out.push_str(&otherwise(field, &target)?);
        }
        Binding::Query => {
            let conversion = expr::from_wire(
                &field.ty,
                member,
                op,
                false,
                bounds::of(field, &ir.quirks, op)?,
                forms::of(field, &ir.quirks, op)?,
            )?;
            let _ = writeln!(out, "        // {member} — query `{wire}`, percent-decoded once.");
            let _ = writeln!(out, "        if let Some(raw) = request.query(\"{wire}\") {{");
            let _ = writeln!(out, "            let raw = raw.as_ref();");
            out.push_str(&assign(12, &target, &wrap(field, &conversion)));
            out.push_str(&otherwise(field, &target)?);
        }
        Binding::PrefixHeaders => match &field.ty {
            Type::Map { .. } => {
                let _ = writeln!(out, "        // {member} — every header under `{wire}`.");
                out.push_str(&assign(8, &target, &format!("value::prefixed_map(request, \"{wire}\")")));
            }
            Type::ChecksumSpec => {
                let _ = writeln!(out, "        // {member} — the one checksum header under `{wire}`.");
                out.push_str(&assign(8, &target, &format!("value::checksum_spec(request, \"{wire}\", \"{member}\")?")));
            }
            _ => {
                return Err(expr::unsupported(
                    op,
                    member,
                    "a prefix-header binding carries either a map or a packed checksum",
                ));
            }
        },
        Binding::Payload => match &field.ty {
            Type::Blob { streaming: true } => {
                let _ = writeln!(out, "        // {member} — the streaming request body, never aggregated.");
                out.push_str(&assign(8, &target, "body.into_stream()"));
            }
            Type::Blob { streaming: false } => {
                let _ = writeln!(out, "        // {member} — the buffered request body.");
                out.push_str(&assign(8, &target, &wrap(field, "body.into_buffered()?")));
            }
            Type::Structure(shape) => {
                let root = if ir.xml.request_root.as_deref().unwrap_or("").is_empty() {
                    shape.clone()
                } else {
                    ir.xml.request_root.clone().unwrap_or_default()
                };
                let aliases: Vec<String> = ir.xml.request_root_aliases.clone();
                let reader = format!("read_{}", naming::module_name(shape));
                let _ = writeln!(out, "        // {member} — the XML request body, rooted at `{root}`.");
                out.push_str("        let raw_body = body.into_buffered()?;\n");
                out.push_str("        let root = rustfs_gateway_xml::parse(raw_body.as_ref())\n");
                out.push_str("            .map_err(|_| CodecError::malformed_xml(\"the request body is not the XML this operation accepts\"))?;\n");
                let mut accepted = vec![root];
                accepted.extend(aliases);
                let names = accepted.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(", ");
                let _ = writeln!(out, "        if ![{names}].contains(&root.name.as_str()) {{");
                let _ = writeln!(
                    out,
                    "            return Err(CodecError::malformed_xml(\"the request body has the wrong root element\").about(\"{member}\"));"
                );
                out.push_str("        }\n");
                out.push_str(&assign(8, &target, &wrap(field, &format!("{reader}(&root)?"))));
            }
            _ => {
                return Err(expr::unsupported(op, member, "a payload binding carries a blob or an XML structure"));
            }
        },
        Binding::BodyXml => {
            return Err(expr::unsupported(
                op,
                member,
                "an operation-level XML member is reached through its payload structure",
            ));
        }
        Binding::StatusCode => {
            return Err(expr::unsupported(op, member, "a status code is a response member"));
        }
        Binding::FormField => {
            return Err(expr::unsupported(op, member, "multipart form decoding has no family yet"));
        }
    }
    Ok(out)
}

/// The `else` arm of a header or query binding: a wire default, a refusal, or nothing.
fn otherwise(field: &Field, target: &str) -> Result<String, String> {
    let member = &field.name;
    let mut out = String::new();
    match (&field.default, field.required) {
        (Some(default), _) => {
            let literal = default_literal(field, default)?;
            out.push_str("        } else {\n");
            out.push_str(&assign(12, target, &wrap(field, &literal)));
            out.push_str("        }\n");
        }
        (None, true) => {
            let code = field.missing_error.as_deref().unwrap_or(DEFAULT_MISSING_CODE);
            out.push_str("        } else {\n");
            let _ = writeln!(out, "            return Err(value::missing(\"{code}\", \"{member}\"));");
            out.push_str("        }\n");
        }
        (None, false) => out.push_str("        }\n"),
    }
    Ok(out)
}

/// The Rust literal for a wire default.
fn default_literal(field: &Field, default: &rustfs_gateway_model::json::Value) -> Result<String, String> {
    use rustfs_gateway_model::json::Value;
    Ok(match (default, &field.ty) {
        (Value::Str(text), Type::String) => format!("\"{text}\".to_owned()"),
        (Value::Str(text), Type::OpaqueString) => format!("value::opaque(\"{text}\")"),
        (Value::Str(text), Type::StringEnum(_)) => {
            format!("dto::{}::from(\"{text}\")", naming::type_name(&field.name))
        }
        (Value::Int(number), Type::Integer) => format!("{number}i32"),
        (Value::Int(number), Type::Long) => format!("{number}i64"),
        (Value::Bool(flag), Type::Boolean) => flag.to_string(),
        _ => {
            return Err(format!("codec {}: the wire default has no literal form for this type", field.name));
        }
    })
}

/// Wraps a value in `Some` unless the field is stored bare.
fn wrap(field: &Field, inner: &str) -> String {
    // A container and a required member are both stored bare, and `Type::Range` already produces
    // an `Option` of its own — a `Range` that cannot be honoured is absent, not an error.
    let bare = field.required || matches!(field.ty, Type::List { .. } | Type::Map { .. } | Type::Range | Type::ChecksumSpec);
    if bare { inner.to_owned() } else { format!("Some({inner})") }
}

/// Renders the reader for one nested request shape.
///
/// Takes the operation's resolved quirks because a bounded integer is bounded wherever it is read:
/// `PartNumber` in a query and `PartNumber` in a completion body are the same wire contract, and a
/// reader that consulted only the operation's own fields would enforce it in one of the two.
pub fn shape_reader(operation: &str, name: &str, shape: &Shape, quirks: &[Quirk]) -> Result<String, String> {
    let type_name = naming::type_name(name);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "/// Reads one `{name}` element. Members are matched by local name, so a namespace-prefixed\n\
         /// body and a bare one decode identically."
    );
    let _ = writeln!(
        out,
        "fn read_{}(node: &rustfs_gateway_xml::XmlNode) -> Result<dto::{type_name}, CodecError> {{",
        naming::module_name(name)
    );
    let _ = writeln!(out, "    let mut shape = dto::{type_name} {{ ..Default::default() }};");

    for field in &shape.fields {
        let member = &field.name;
        let target = format!("shape.{}", naming::field_name(member));
        let wire = field.wire_name.clone().unwrap_or_else(|| member.clone());
        match &field.ty {
            Type::List {
                member: inner,
                flattened,
                wrapper_name,
            } if !matches!(inner.as_ref(), Type::Structure(_)) => {
                let conversion = expr::from_wire(
                    inner,
                    member,
                    operation,
                    true,
                    bounds::of(field, quirks, operation)?,
                    forms::of(field, quirks, operation)?,
                )?;
                let source = list_source(*flattened, wrapper_name.as_deref(), &wire);
                let _ = writeln!(out, "    for item in {source} {{");
                let _ = writeln!(out, "        let raw = item.text.as_str();");
                let _ = writeln!(out, "        {target}.push({conversion});");
                out.push_str("    }\n");
            }
            Type::List {
                member: inner,
                flattened,
                wrapper_name,
            } => {
                let Type::Structure(inner_name) = inner.as_ref() else {
                    return Err(expr::unsupported(
                        operation,
                        member,
                        "a request body list carries structures in the supported surface",
                    ));
                };
                let reader = format!("read_{}", naming::module_name(inner_name));
                let source = list_source(*flattened, wrapper_name.as_deref(), &wire);
                let _ = writeln!(out, "    for item in {source} {{");
                let _ = writeln!(out, "        {target}.push({reader}(item)?);");
                out.push_str("    }\n");
                if field.required {
                    let _ = writeln!(out, "    if {target}.is_empty() {{");
                    let _ = writeln!(
                        out,
                        "        return Err(CodecError::malformed_xml(\"the body carries no entry for a member that requires one\").about(\"{member}\"));"
                    );
                    out.push_str("    }\n");
                }
            }
            Type::Structure(inner_name) => {
                let reader = format!("read_{}", naming::module_name(inner_name));
                let _ = writeln!(out, "    if let Some(child) = node.child(\"{wire}\") {{");
                out.push_str(&assign(8, &target, &wrap(field, &format!("{reader}(child)?"))));
                out.push_str("    }\n");
            }
            other => {
                let conversion = expr::from_wire(
                    other,
                    member,
                    operation,
                    true,
                    bounds::of(field, quirks, operation)?,
                    forms::of(field, quirks, operation)?,
                )?;
                let _ = writeln!(out, "    if let Some(raw) = node.child_text(\"{wire}\") {{");
                out.push_str(&assign(8, &target, &wrap(field, &conversion)));
                out.push_str("    }\n");
            }
        }
    }
    out.push_str("    value::exit(shape.check_required())?;\n    Ok(shape)\n}\n");
    Ok(out)
}

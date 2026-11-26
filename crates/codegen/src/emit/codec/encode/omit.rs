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

//! Response-field suppression (`omit_when`) planning and rendering for headers and XML bodies.
//!
//! Responsible for: resolving `OmitWhen::RequestField` against an operation's input bindings,
//! computing which nested output shapes need `request: &MetaView<'_>` threaded through their
//! writers, and rendering suppression guards for both headers and XML elements.
//! NOT responsible for: URL-encoding plans ([`super::super::url`]), legacy member ordering
//! ([`super::order`]), or evaluating request values at run time (`crate::codec::value`).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: [`super`].

use std::collections::BTreeSet;
use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, Field, OmitWhen, OperationIr, Type};
use rustfs_gateway_model::json::Value;

use super::layout;

/// Which nested output shapes in one operation need `request: &MetaView<'_>` for `omit_when`.
#[derive(Debug, Default)]
pub(super) struct Plan {
    needs_request: BTreeSet<String>,
}

impl Plan {
    /// Computes which output shapes in `ir` directly or transitively read `request` for `omit_when`.
    pub(super) fn for_operation(ir: &OperationIr) -> Result<Self, String> {
        let mut needs_request = BTreeSet::new();
        for (name, shape) in &ir.shapes {
            for field in &shape.fields {
                if request_field_allow_expr(ir, field)?.is_some() {
                    needs_request.insert(name.clone());
                }
            }
        }
        loop {
            let mut grew = false;
            for (name, shape) in &ir.shapes {
                if needs_request.contains(name) {
                    continue;
                }
                if shape
                    .fields
                    .iter()
                    .filter_map(|field| nested_shape(&field.ty))
                    .any(|child| needs_request.contains(child))
                {
                    needs_request.insert(name.clone());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        Ok(Self { needs_request })
    }

    /// Whether `shape`'s generated writer needs `request: &MetaView<'_>`.
    #[must_use]
    pub(super) fn needs_request(&self, shape: &str) -> bool {
        self.needs_request.contains(shape)
    }
}

/// The shape a field type reaches, when it reaches one.
fn nested_shape(ty: &Type) -> Option<&str> {
    match ty {
        Type::Structure(name) | Type::Union(name) => Some(name.as_str()),
        Type::List { member, .. } => nested_shape(member),
        _ => None,
    }
}

/// Wraps a response header write in the suppression rule the IR recorded for the field.
pub(super) fn header_suppression(field: &Field, write: &str) -> Result<String, String> {
    Ok(match &field.omit_when {
        None => format!("            {write}\n"),
        Some(OmitWhen::Empty | OmitWhen::Default) => {
            format!("            if !rendered.is_empty() {{\n                {write}\n            }}\n")
        }
        Some(OmitWhen::ValueEquals(literal)) => {
            format!("            if rendered != \"{literal}\" {{\n                {write}\n            }}\n")
        }
        Some(OmitWhen::RequestField { .. }) => {
            return Err(format!(
                "codec {}: a request-field suppression is a body rule and has no header form",
                field.name
            ));
        }
    })
}

/// The boolean expression that permits emitting `field` when `field.omit_when` is
/// [`OmitWhen::RequestField`], or `None` when the field is not request-suppressed.
///
/// An absent request field on the current operation resolves to `None` ("do not suppress") rather
/// than an error: shared output shapes such as `Object.Owner` carry `FetchOwner` for
/// `ListObjectsV2` while `ListObjects` has no `FetchOwner` input and emits `<Owner>`
/// unconditionally (`q-owner-0065`).
pub(super) fn request_field_allow_expr(ir: &OperationIr, field: &Field) -> Result<Option<String>, String> {
    let Some(OmitWhen::RequestField {
        field: req_field,
        equals,
    }) = &field.omit_when
    else {
        return Ok(None);
    };
    let Some(input) = ir.input.iter().find(|candidate| candidate.name == *req_field) else {
        return Ok(None);
    };
    match &input.binding {
        Binding::Query => {
            let wire = input.wire_name.as_deref().unwrap_or(&input.name);
            if input.ty == Type::Boolean {
                let target = parse_bool_literal(&ir.operation, &field.name, equals)?;
                let default = match &input.default {
                    None => false,
                    Some(Value::Bool(value)) => *value,
                    Some(_) => {
                        return Err(format!(
                            "codec {}.{}: boolean request input `{req_field}` has a non-boolean default",
                            ir.operation, field.name
                        ));
                    }
                };
                Ok(Some(format!(
                    "!value::request_query_equals_bool(request, \"{wire}\", {default}, {target})"
                )))
            } else {
                let default = default_str_expr(&ir.operation, &field.name, req_field, &input.default)?;
                Ok(Some(format!("!value::request_query_equals(request, \"{wire}\", {default}, {equals:?})")))
            }
        }
        Binding::Header => {
            let wire = input.wire_name.as_deref().unwrap_or(&input.name).to_ascii_lowercase();
            let default = default_str_expr(&ir.operation, &field.name, req_field, &input.default)?;
            Ok(Some(format!("!value::request_header_equals(request, \"{wire}\", {default}, {equals:?})")))
        }
        other => Err(format!(
            "codec {}.{}: `omit_when` request field `{req_field}` has unsupported binding `{other:?}`",
            ir.operation, field.name
        )),
    }
}

/// The value-based allow expression over `rendered` for a scalar XML body member, if any.
pub(super) fn scalar_value_allow_expr(field: &Field) -> Option<String> {
    match &field.omit_when {
        Some(OmitWhen::Empty | OmitWhen::Default) => Some("!rendered.is_empty()".to_owned()),
        Some(OmitWhen::ValueEquals(literal)) => Some(format!("rendered != {literal:?}")),
        None | Some(OmitWhen::RequestField { .. }) => None,
    }
}

/// Validates that a non-scalar XML body member does not carry an unsupported value-based
/// `omit_when` variant, returning an allow expression for list `Empty`/`Default` when applicable.
pub(super) fn non_scalar_allow_expr(
    ir: &OperationIr,
    field: &Field,
    source: &str,
    presence: bool,
) -> Result<Option<String>, String> {
    match &field.omit_when {
        None => Ok(None),
        Some(OmitWhen::RequestField { .. }) => request_field_allow_expr(ir, field),
        Some(OmitWhen::Empty | OmitWhen::Default) if matches!(field.ty, Type::List { .. }) => {
            if presence {
                Ok(Some(format!("{source}.as_deref().is_some_and(|items| !items.is_empty())")))
            } else {
                Ok(Some(format!("!{source}.is_empty()")))
            }
        }
        Some(other) => Err(format!(
            "codec {}.{}: XML body member of this type does not support `omit_when = {other:?}`",
            ir.operation, field.name
        )),
    }
}

/// Renders the opening line(s) for an optional `if let Some(v) = {source}.as_ref() {` block,
/// folding an optional `allow` predicate into a rustfmt-formatted let-chain to avoid nested `if`s.
pub(super) fn open_optional(pad: &str, source: &str, allow: Option<&str>) -> String {
    match allow {
        None => format!("{pad}if let Some(v) = {source}.as_ref() {{\n"),
        Some(expr) => format!("{pad}if {expr}\n{pad}    && let Some(v) = {source}.as_ref()\n{pad}{{\n"),
    }
}

/// Renders the opening line for a required block, guarded by `allow` when present.
pub(super) fn open_required(pad: &str, source: &str, allow: Option<&str>) -> String {
    match allow {
        None => format!("{pad}{{\n{pad}    let v = &{source};\n"),
        Some(expr) => format!("{pad}if {expr} {{\n{pad}    let v = &{source};\n"),
    }
}

/// Emits one scalar `writer.{call}("{wire}", ...)` statement with optional legacy-unheld and
/// value-based `omit_when` guards.
pub(super) fn write_scalar_element(
    out: &mut String,
    pad: &str,
    call: &str,
    wire: &str,
    rendered: &str,
    unheld: bool,
    val_allow: Option<&str>,
) {
    match (unheld, val_allow) {
        (true, Some(cond)) => {
            let _ = writeln!(out, "{pad}if !{} {{", layout::UNHELD_UNDER_LEGACY_LAYOUT);
            let _ = writeln!(out, "{pad}    let rendered = {rendered};");
            let _ = writeln!(out, "{pad}    if {cond} {{");
            let _ = writeln!(out, "{pad}        writer.{call}(\"{wire}\", rendered);");
            let _ = writeln!(out, "{pad}    }}");
            let _ = writeln!(out, "{pad}}}");
        }
        (true, None) => {
            let _ = writeln!(out, "{pad}if !{} {{", layout::UNHELD_UNDER_LEGACY_LAYOUT);
            let _ = writeln!(out, "{pad}    writer.{call}(\"{wire}\", {rendered});");
            let _ = writeln!(out, "{pad}}}");
        }
        (false, Some(cond)) => {
            let _ = writeln!(out, "{pad}let rendered = {rendered};");
            let _ = writeln!(out, "{pad}if {cond} {{");
            let _ = writeln!(out, "{pad}    writer.{call}(\"{wire}\", rendered);");
            let _ = writeln!(out, "{pad}}}");
        }
        (false, None) => {
            let _ = writeln!(out, "{pad}writer.{call}(\"{wire}\", {rendered});");
        }
    }
}

/// Wraps an already-rendered block in `if {allow} { ... }` when `allow` is `Some`.
pub(super) fn wrap_block(out: &mut String, pad: &str, allow: Option<&str>) {
    let Some(expr) = allow else {
        return;
    };
    let mut guarded = format!("{pad}if {expr} {{\n");
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

fn parse_bool_literal(operation: &str, member: &str, raw: &str) -> Result<bool, String> {
    if raw.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if raw.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(format!(
            "codec {operation}.{member}: `omit_when_equals = {raw:?}` is not a boolean literal"
        ))
    }
}

fn default_str_expr(operation: &str, member: &str, req_field: &str, default: &Option<Value>) -> Result<String, String> {
    match default {
        None => Ok("None".to_owned()),
        Some(Value::Str(text)) => Ok(format!("Some({text:?})")),
        Some(Value::Bool(value)) => Ok(format!("Some(\"{value}\")")),
        Some(Value::Int(value)) => Ok(format!("Some(\"{value}\")")),
        Some(_) => Err(format!(
            "codec {operation}.{member}: request input `{req_field}` has an unsupported default value"
        )),
    }
}

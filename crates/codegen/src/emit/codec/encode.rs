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

//! The response half: one IR binding to the lines that write it.
//!
//! Responsible for: the body of every generated `encode`, the XML body writer that follows
//! `xml.element_order` and `xml.empty_value_policy`, and the per-shape writers a body needs.
//! NOT responsible for: the conversions ([`super::expr`]), the RFC 9110 invariants (one
//! hand-written function in `crate::codec::response`), or the `response-*` table (IR data).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: the generated codec files.
//!
//! # The three exceptions that are data here, not branches
//!
//! Entity-tag rendering is `Type::ETag(context)`, per field. An unwrapped body is
//! `xml.unwrapped_output`, per operation. Emit-or-omit for an empty member is
//! `xml.empty_value_policy`, per member. Each of them was a hand-written `if` somewhere upstream
//! and each of them was wrong in one of the two places it lived.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, EmptyValue, Field, OmitWhen, OperationIr, Shape, Type};

use super::expr;
use crate::emit::dto::naming;

/// Renders the body of one operation's `encode`.
pub fn body(ir: &OperationIr) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("        let mut response = EncodedResponse::of(status);\n");
    out.push_str("        response.status = status_code(status)?;\n");

    for field in &ir.output {
        out.push_str(&one_field(ir, field)?);
    }
    out.push_str(&xml_body(ir)?);

    out.push_str(
        "        // The `response-*` overrides are applied once, after every header this operation\n\
         \x20       // declares — so \"the override wins\" is true by construction and not by ordering.\n",
    );
    out.push_str("        response.apply_response_overrides(request, Self::RESPONSE_OVERRIDES);\n");
    out.push_str("        response.enforce_http_invariants(request.method());\n");
    out.push_str("        Ok(response)\n");
    Ok(out)
}

/// Renders the lines that write one output field.
fn one_field(ir: &OperationIr, field: &Field) -> Result<String, String> {
    let op = &ir.operation;
    let member = &field.name;
    let source = format!("output.{}", naming::field_name(member));
    let wire = field.wire_name.clone().unwrap_or_default();
    let mut out = String::new();

    match &field.binding {
        Binding::Header => {
            let rendered = expr::to_wire(&field.ty, member, op)?;
            let _ = writeln!(out, "        // {member} — header `{wire}`.");
            if field.required {
                let _ = writeln!(out, "        {{");
                let _ = writeln!(out, "            let v = &{source};");
            } else {
                let _ = writeln!(out, "        if let Some(v) = {source}.as_ref() {{");
            }
            let _ = writeln!(out, "            let rendered = {rendered};");
            out.push_str(&suppression(field, &format!("response.set_header(\"{wire}\", rendered);"))?);
            out.push_str("        }\n");
        }
        Binding::PrefixHeaders => match &field.ty {
            Type::Map { .. } => {
                let _ = writeln!(out, "        // {member} — one header per entry under `{wire}`.");
                let _ = writeln!(out, "        for (suffix, v) in &{source} {{");
                let _ = writeln!(out, "            response.set_prefixed_header(\"{wire}\", suffix, v);");
                out.push_str("        }\n");
            }
            Type::ChecksumSpec => {
                let _ = writeln!(out, "        // {member} — the algorithm decides the header name.");
                let _ = writeln!(out, "        if let Some(spec) = {source}.as_ref() {{");
                out.push_str("            let (name, digest) = value::checksum_header(spec);\n");
                out.push_str("            response.set_prefixed_header(\"\", name, digest);\n");
                out.push_str("        }\n");
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
                let _ = writeln!(out, "        // {member} — the streaming response body.");
                let _ = writeln!(out, "        if let Some(stream) = {source} {{");
                out.push_str("            response.body = ResponseBody::Stream(stream);\n        }\n");
            }
            Type::Blob { streaming: false } => {
                let _ = writeln!(out, "        // {member} — the complete response body.");
                let _ = writeln!(out, "        if let Some(bytes) = {source} {{");
                out.push_str("            response.body = ResponseBody::Complete(bytes.to_vec());\n        }\n");
            }
            _ => {
                return Err(expr::unsupported(op, member, "a payload binding carries a blob on the response side"));
            }
        },
        Binding::StatusCode => {
            let _ = writeln!(out, "        // {member} — the operation reports its own status.");
            let _ = writeln!(out, "        if let Some(code) = {source} {{");
            out.push_str("            response.status = status_code(u16::try_from(code).unwrap_or(status))?;\n        }\n");
        }
        // Body members are written together, in `xml.element_order`, after every header.
        Binding::BodyXml => {}
        Binding::UriLabel { .. } | Binding::Query | Binding::FormField => {
            return Err(expr::unsupported(op, member, "this binding has no response side"));
        }
    }
    Ok(out)
}

/// Wraps a write in the suppression rule the IR recorded for the field.
fn suppression(field: &Field, write: &str) -> Result<String, String> {
    Ok(match &field.omit_when {
        None => format!("            {write}\n"),
        Some(OmitWhen::Empty) => format!("            if !rendered.is_empty() {{\n                {write}\n            }}\n"),
        Some(OmitWhen::Default) => {
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

/// Renders the XML response body, when the operation has one.
fn xml_body(ir: &OperationIr) -> Result<String, String> {
    let members: Vec<&Field> = ir.output.iter().filter(|f| f.binding == Binding::BodyXml).collect();
    if members.is_empty() {
        return Ok(String::new());
    }
    let Some(root) = ir.xml.response_root.as_deref().filter(|name| !name.is_empty()) else {
        return Err(format!("codec {}: the operation has body members and no response root", ir.operation));
    };
    let xmlns = match ir.xml.xmlns {
        rustfs_gateway_model::ir::Xmlns::Emit => "Some(rustfs_gateway_xml::S3_XMLNS)",
        rustfs_gateway_model::ir::Xmlns::Suppress => "None",
    };

    let mut out = String::new();
    out.push_str("        let mut writer = rustfs_gateway_xml::XmlWriter::document();\n");

    if ir.xml.unwrapped_output {
        // The single body member *is* the root. A generic wrapper here is the shipped defect
        // `q-unwrapped-0001` records, which is why this is IR data and not a name comparison.
        let Some(field) = members.first() else {
            return Err(format!("codec {}: an unwrapped output needs exactly one body member", ir.operation));
        };
        let source = format!("output.{}", naming::field_name(&field.name));
        let rendered = expr::to_wire(&field.ty, &field.name, &ir.operation)?;
        let _ = writeln!(out, "        // {} — the unwrapped body: the member is the root.", field.name);
        let _ = writeln!(out, "        writer.open(\"{root}\", {xmlns});");
        let _ = writeln!(out, "        if let Some(v) = {source}.as_ref() {{");
        let _ = writeln!(out, "            writer.text({rendered});");
        out.push_str("        }\n        writer.close();\n");
    } else {
        let _ = writeln!(out, "        writer.open(\"{root}\", {xmlns});");
        for name in ordered_members(ir, &members) {
            let Some(field) = members.iter().find(|f| f.name == name) else {
                continue;
            };
            out.push_str(&body_member(ir, field, &format!("output.{}", naming::field_name(&field.name)), 8)?);
        }
        out.push_str("        writer.close();\n");
    }

    out.push_str("        response.body = ResponseBody::Complete(writer.finish().into_bytes());\n");
    out.push_str("        response.set_header(\"content-type\", \"application/xml\");\n");
    Ok(out)
}

/// The wire order of the response root's children.
///
/// `xml.element_order` when the overlay declared one — sibling order is part of the wire contract
/// and strict clients fail to parse when it changes (`q-order-0014`). Model order otherwise.
fn ordered_members(ir: &OperationIr, members: &[&Field]) -> Vec<String> {
    if ir.xml.element_order.is_empty() {
        return members.iter().map(|f| f.name.clone()).collect();
    }
    ir.xml.element_order.clone()
}

/// Renders one XML body member: a scalar element, a repeated structure, or a nested one.
fn body_member(ir: &OperationIr, field: &Field, source: &str, indent: usize) -> Result<String, String> {
    let pad = " ".repeat(indent);
    let member = &field.name;
    let wire = field.wire_name.clone().unwrap_or_else(|| member.clone());
    let policy = empty_policy(&ir.xml.empty_value_policy, member, field.required);
    let mut out = String::new();

    match &field.ty {
        Type::List {
            member: inner,
            flattened,
            wrapper_name,
        } if !matches!(inner.as_ref(), Type::Structure(_)) => {
            let rendered = expr::to_wire(inner, member, &ir.operation)?;
            let wrapper = if *flattened {
                None
            } else {
                Some(wrapper_name.clone().unwrap_or_else(|| wire.clone()))
            };
            if let Some(name) = &wrapper {
                let _ = writeln!(out, "{pad}writer.open(\"{name}\", None);");
            }
            let _ = writeln!(out, "{pad}for v in &{source} {{");
            let _ = writeln!(out, "{pad}    writer.element(\"{wire}\", {rendered});");
            let _ = writeln!(out, "{pad}}}");
            if wrapper.is_some() {
                let _ = writeln!(out, "{pad}writer.close();");
            }
        }
        Type::List {
            member: inner,
            flattened,
            wrapper_name,
        } => {
            let Type::Structure(inner_name) = inner.as_ref() else {
                return Err(expr::unsupported(
                    &ir.operation,
                    member,
                    "a response body list carries structures in the supported surface",
                ));
            };
            let writer_fn = format!("write_{}", naming::module_name(inner_name));
            if !*flattened {
                let wrapper = wrapper_name.clone().unwrap_or_else(|| wire.clone());
                let _ = writeln!(out, "{pad}writer.open(\"{wrapper}\", None);");
            }
            let _ = writeln!(out, "{pad}for item in &{source} {{");
            let _ = writeln!(out, "{pad}    writer.open(\"{wire}\", None);");
            let _ = writeln!(out, "{pad}    {writer_fn}(&mut writer, item)?;");
            let _ = writeln!(out, "{pad}    writer.close();");
            let _ = writeln!(out, "{pad}}}");
            if !*flattened {
                let _ = writeln!(out, "{pad}writer.close();");
            }
        }
        Type::Structure(inner_name) => {
            let writer_fn = format!("write_{}", naming::module_name(inner_name));
            let _ = writeln!(out, "{pad}if let Some(v) = {source}.as_ref() {{");
            let _ = writeln!(out, "{pad}    writer.open(\"{wire}\", None);");
            let _ = writeln!(out, "{pad}    {writer_fn}(&mut writer, v)?;");
            let _ = writeln!(out, "{pad}    writer.close();");
            let _ = writeln!(out, "{pad}}}");
        }
        other => {
            let rendered = expr::to_wire(other, member, &ir.operation)?;
            let call = match policy {
                EmptyValue::Emit => "element",
                EmptyValue::Omit => "element_if_present",
            };
            if field.required {
                let _ = writeln!(out, "{pad}{{");
                let _ = writeln!(out, "{pad}    let v = &{source};");
                let _ = writeln!(out, "{pad}    writer.{call}(\"{wire}\", {rendered});");
                let _ = writeln!(out, "{pad}}}");
            } else {
                let _ = writeln!(out, "{pad}if let Some(v) = {source}.as_ref() {{");
                let _ = writeln!(out, "{pad}    writer.{call}(\"{wire}\", {rendered});");
                let _ = writeln!(out, "{pad}}}");
            }
        }
    }
    Ok(out)
}

/// Emit or omit for an empty member.
///
/// The declared policy wins; otherwise the default is "a required member emits, an optional one is
/// omitted", which is the rule every `q-empty-*` quirk exists to override.
fn empty_policy(policy: &[(String, EmptyValue)], member: &str, required: bool) -> EmptyValue {
    policy
        .iter()
        .find(|(name, _)| name == member)
        .map(|(_, value)| *value)
        .unwrap_or(if required { EmptyValue::Emit } else { EmptyValue::Omit })
}

/// Renders the writer for one nested response shape.
pub fn shape_writer(ir: &OperationIr, name: &str, shape: &Shape) -> Result<String, String> {
    let type_name = naming::type_name(name);
    let order = if shape.xml.element_order.is_empty() {
        shape.fields.iter().map(|f| f.name.clone()).collect()
    } else {
        shape.xml.element_order.clone()
    };

    let mut out = String::new();
    let _ = writeln!(out, "/// Writes one `{name}` element's children, in the wire order the IR records.");
    let _ = writeln!(
        out,
        "fn write_{}(writer: &mut rustfs_gateway_xml::XmlWriter, value: &dto::{type_name}) -> Result<(), CodecError> {{",
        naming::module_name(name)
    );
    for member in order {
        let Some(field) = shape.fields.iter().find(|f| f.name == member) else {
            continue;
        };
        let source = format!("value.{}", naming::field_name(&field.name));
        let wire = field.wire_name.clone().unwrap_or_else(|| field.name.clone());
        let policy = empty_policy(&shape.xml.empty_value_policy, &field.name, field.required);
        match &field.ty {
            Type::Structure(_) | Type::List { .. } => {
                out.push_str(&shape_child(ir, field, &source, &wire)?);
            }
            other => {
                let rendered = expr::to_wire(other, &field.name, &ir.operation)?;
                let call = match policy {
                    EmptyValue::Emit => "element",
                    EmptyValue::Omit => "element_if_present",
                };
                if field.required {
                    let _ = writeln!(out, "    {{");
                    let _ = writeln!(out, "        let v = &{source};");
                    let _ = writeln!(out, "        writer.{call}(\"{wire}\", {rendered});");
                    let _ = writeln!(out, "    }}");
                } else {
                    let _ = writeln!(out, "    if let Some(v) = {source}.as_ref() {{");
                    let _ = writeln!(out, "        writer.{call}(\"{wire}\", {rendered});");
                    let _ = writeln!(out, "    }}");
                }
            }
        }
    }
    out.push_str("    Ok(())\n}\n");
    Ok(out)
}

/// A nested structure or list inside a shape.
fn shape_child(ir: &OperationIr, field: &Field, source: &str, wire: &str) -> Result<String, String> {
    let mut out = String::new();
    match &field.ty {
        Type::Structure(inner) => {
            let writer_fn = format!("write_{}", naming::module_name(inner));
            let _ = writeln!(out, "    if let Some(v) = {source}.as_ref() {{");
            let _ = writeln!(out, "        writer.open(\"{wire}\", None);");
            let _ = writeln!(out, "        {writer_fn}(writer, v)?;");
            let _ = writeln!(out, "        writer.close();");
            let _ = writeln!(out, "    }}");
        }
        Type::List { member: inner, .. } => match inner.as_ref() {
            Type::Structure(inner_name) => {
                let writer_fn = format!("write_{}", naming::module_name(inner_name));
                let _ = writeln!(out, "    for item in &{source} {{");
                let _ = writeln!(out, "        writer.open(\"{wire}\", None);");
                let _ = writeln!(out, "        {writer_fn}(writer, item)?;");
                let _ = writeln!(out, "        writer.close();");
                let _ = writeln!(out, "    }}");
            }
            // A list of scalars repeats the element with its text; the element name is the
            // member's wire name, which is what `flattened` means for a scalar list.
            scalar => {
                let rendered = expr::to_wire(scalar, &field.name, &ir.operation)?;
                let _ = writeln!(out, "    for v in &{source} {{");
                let _ = writeln!(out, "        writer.element(\"{wire}\", {rendered});");
                let _ = writeln!(out, "    }}");
            }
        },
        _ => {}
    }
    Ok(out)
}

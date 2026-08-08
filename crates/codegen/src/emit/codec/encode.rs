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
//! `xml.element_order`, `xml.empty_value_policy` and `xml.url_encoded_fields`, and the per-shape
//! writers a body needs.
//! NOT responsible for: the conversions ([`super::expr`]), the RFC 9110 invariants (one
//! hand-written function in `crate::codec::response`), or the `response-*` table (IR data).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: the generated codec files.
//!
//! # The four exceptions that are data here, not branches
//!
//! Entity-tag rendering is `Type::ETag(context)`, per field — and it decides the escaping of the
//! element as well as the text, because a quoted tag is the one text node S3 spells with
//! `&quot;`. An unwrapped body is `xml.unwrapped_output`, per operation. Emit-or-omit for an empty
//! member is `xml.empty_value_policy`, per member. Percent-encoding under `encoding-type=url` is
//! `xml.url_encoded_fields`, per member path, resolved by [`super::url`]. Each of them was a
//! hand-written `if` somewhere upstream and each of them was wrong in one of the two places it
//! lived.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{AttributeSource, Binding, ETagRender, EmptyValue, Field, OmitWhen, OperationIr, Shape, Type};

use super::{attribute_name, carried_as_attribute, expr, media, url};
use crate::emit::dto::naming;

/// Renders the body of one operation's `encode`.
pub fn body(ir: &OperationIr) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("        let mut response = EncodedResponse::of(status);\n");
    out.push_str("        response.status = status_code(status)?;\n");

    // An output with no members reads nothing off `output` — the delete family's `smithy.api#Unit`
    // shape — so the parameter is consumed explicitly, the same convention `decode` uses for a
    // request whose body no field reads. Generated code must compile warning-free.
    if ir.output.is_empty() {
        out.push_str("        let _ = output;\n");
    }
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
            // The payload structure *is* the document: its shape name (or the declared response
            // root) is the root element, and its writer renders the children — the mirror of the
            // structure-payload arm `decode` already has for the request side.
            Type::Structure(shape) => {
                let root = match ir.xml.response_root.as_deref().filter(|name| !name.is_empty()) {
                    Some(overridden) => overridden.to_owned(),
                    None => shape.clone(),
                };
                let xmlns = match ir.xml.xmlns {
                    rustfs_gateway_model::ir::Xmlns::Emit => "Some(rustfs_gateway_xml::S3_XMLNS)",
                    rustfs_gateway_model::ir::Xmlns::Suppress => "None",
                };
                let writer_fn = format!("write_{}", naming::module_name(shape));
                let argument = shape_writer_argument(&url::plan(ir)?, shape);
                if !argument.is_empty() {
                    // Nothing url-encodes inside a payload document today; the plan is consulted so
                    // the day something does, this fails loudly instead of emitting an unencoded body.
                    return Err(expr::unsupported(op, member, "a payload structure whose members url-encode"));
                }
                // Same reasoning for XML attributes: the root is opened with the S3 namespace and
                // nothing else, so a payload shape that declared attributes would lose them
                // silently. No shape does; the day one does, this says so.
                if ir.shapes.get(shape).is_some_and(|s| !s.xml.attributes.is_empty()) {
                    return Err(expr::unsupported(op, member, "a payload structure whose element carries XML attributes"));
                }
                let _ = writeln!(out, "        // {member} — the XML response body, rooted at `{root}`.");
                if field.required {
                    let _ = writeln!(out, "        {{");
                    let _ = writeln!(out, "            let v = &{source};");
                } else {
                    let _ = writeln!(out, "        if let Some(v) = {source}.as_ref() {{");
                }
                out.push_str("            let mut writer = rustfs_gateway_xml::XmlWriter::document();\n");
                let _ = writeln!(out, "            writer.open(\"{root}\", {xmlns});");
                let _ = writeln!(out, "            {writer_fn}(&mut writer, v)?;");
                out.push_str("            writer.close();\n");
                out.push_str("            response.body = ResponseBody::Complete(writer.finish().into_bytes());\n");
                out.push_str("            response.set_header(\"content-type\", \"application/xml\");\n");
                out.push_str("        }\n");
            }
            // A text payload is the body verbatim, with the content type the IR declares. The
            // only one today is a bucket policy, whose body is JSON while its *errors* stay XML
            // — so the header is written here, on the success path, and nowhere else.
            Type::String | Type::OpaqueString => {
                let media = media::required(field, &ir.quirks, op)?;
                let _ = writeln!(out, "        // {member} — the complete response body, `{media}`.");
                if field.required {
                    let _ = writeln!(out, "        {{");
                    let _ = writeln!(out, "            let v = &{source};");
                } else {
                    let _ = writeln!(out, "        if let Some(v) = {source}.as_ref() {{");
                }
                let rendered = expr::to_wire(&field.ty, member, op)?;
                let _ = writeln!(out, "            let rendered = {rendered};");
                out.push_str("            response.body = ResponseBody::Complete(rendered.as_bytes().to_vec());\n");
                let _ = writeln!(out, "            response.set_header(\"content-type\", \"{media}\");");
                out.push_str("        }\n");
            }
            _ => {
                return Err(expr::unsupported(
                    op,
                    member,
                    "a payload binding carries a blob, a text document or an XML structure",
                ));
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

    let plan = url::plan(ir)?;
    let mut out = String::new();
    if !plan.is_empty() {
        // Read once, before a byte is written: `encoding-type` covers the whole document, and a
        // member that consulted the request for itself could disagree with its siblings.
        out.push_str("        let url_encoding = value::url_encoding(request);\n");
    }
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
            out.push_str(&body_member(ir, &plan, field, &format!("output.{}", naming::field_name(&field.name)), 8)?);
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
fn body_member(ir: &OperationIr, plan: &url::Plan, field: &Field, source: &str, indent: usize) -> Result<String, String> {
    let pad = " ".repeat(indent);
    let member = &field.name;
    let wire = field.wire_name.clone().unwrap_or_else(|| member.clone());
    let policy = empty_policy(&ir.xml.empty_value_policy, member, field.required);
    let encoded = plan.encodes_root(member);
    let mut out = String::new();

    match &field.ty {
        Type::List {
            member: inner,
            flattened,
            wrapper_name,
        } if !matches!(inner.as_ref(), Type::Structure(_)) => {
            let rendered = wire_expr(inner, member, &ir.operation, encoded)?;
            let names = super::list_elements(*flattened, wrapper_name.as_deref(), &wire);
            if let Some(name) = &names.wrapper {
                let _ = writeln!(out, "{pad}writer.open(\"{name}\", None);");
            }
            let _ = writeln!(out, "{pad}for v in &{source} {{");
            let _ = writeln!(out, "{pad}    writer.element(\"{}\", {rendered});", names.entry);
            let _ = writeln!(out, "{pad}}}");
            if names.wrapper.is_some() {
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
            let argument = shape_writer_argument(plan, inner_name);
            let names = super::list_elements(*flattened, wrapper_name.as_deref(), &wire);
            let open = open_structure(ir, inner_name, &names.entry, "item", "&mut writer")?;
            if let Some(wrapper) = &names.wrapper {
                let _ = writeln!(out, "{pad}writer.open(\"{wrapper}\", None);");
            }
            let _ = writeln!(out, "{pad}for item in &{source} {{");
            let _ = writeln!(out, "{pad}    {open}");
            let _ = writeln!(out, "{pad}    {writer_fn}(&mut writer, item{argument})?;");
            let _ = writeln!(out, "{pad}    writer.close();");
            let _ = writeln!(out, "{pad}}}");
            if names.wrapper.is_some() {
                let _ = writeln!(out, "{pad}writer.close();");
            }
        }
        // A required nested structure is not an `Option` in the dto, so it is written
        // unconditionally. Emitting the `as_ref()` form regardless does not compile, which is the
        // good half of the failure; the bad half is that it would turn a member the overlay
        // declared unconditional into one the encoder is free to skip.
        Type::Structure(inner_name) => {
            let writer_fn = format!("write_{}", naming::module_name(inner_name));
            let argument = shape_writer_argument(plan, inner_name);
            let open = open_structure(ir, inner_name, &wire, "v", "&mut writer")?;
            if field.required {
                let _ = writeln!(out, "{pad}{{");
                let _ = writeln!(out, "{pad}    let v = &{source};");
            } else {
                let _ = writeln!(out, "{pad}if let Some(v) = {source}.as_ref() {{");
            }
            let _ = writeln!(out, "{pad}    {open}");
            let _ = writeln!(out, "{pad}    {writer_fn}(&mut writer, v{argument})?;");
            let _ = writeln!(out, "{pad}    writer.close();");
            let _ = writeln!(out, "{pad}}}");
        }
        other => {
            let rendered = wire_expr(other, member, &ir.operation, encoded)?;
            let call = element_call(other, policy);
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

/// The statement that opens the element one nested structure occupies.
///
/// `writer.open(…)` for the ordinary shape, and the shape's own `open_…` helper for a shape the
/// IR gives XML attributes. Resolved in one place because four call sites open a structure's
/// element, and a site that kept the plain form would drop the attributes on that one path only
/// — a document correct in three positions and wrong in the fourth.
/// `borrowed` is how the writer is spelled as a *function argument* at the call site: `writer`
/// inside a shape writer, which already holds a `&mut`, and `&mut writer` in the operation body,
/// which owns one.
fn open_structure(ir: &OperationIr, shape: &str, wire: &str, value: &str, borrowed: &str) -> Result<String, String> {
    let plain = format!("writer.open(\"{wire}\", None);");
    let Some(target) = ir.shapes.get(shape) else {
        return Ok(plain);
    };
    if target.xml.attributes.is_empty() {
        return Ok(plain);
    }
    for attribute in &target.xml.attributes {
        if attribute.element != wire {
            return Err(format!(
                "codec {}: shape `{shape}` declares attribute `{}` on element `{}`, but it is written into `{wire}`",
                ir.operation, attribute.name, attribute.element
            ));
        }
    }
    Ok(format!("open_{}({borrowed}, {value});", naming::module_name(shape)))
}

/// Renders the `open_…` helper for a shape whose element carries XML attributes.
///
/// Returns nothing for a shape that has none, which is every shape but one today.
fn shape_opener(name: &str, shape: &Shape) -> String {
    if shape.xml.attributes.is_empty() {
        return String::new();
    }
    let module = naming::module_name(name);
    let type_name = naming::type_name(name);
    let element = shape.xml.attributes.first().map(|a| a.element.clone()).unwrap_or_default();
    let mut out = String::new();
    let _ = writeln!(out, "/// Opens the `{element}` element with the XML attributes the IR records on it.");
    let _ = writeln!(
        out,
        "fn open_{module}(writer: &mut rustfs_gateway_xml::XmlWriter, value: &dto::{type_name}) {{"
    );
    let _ = writeln!(out, "    let mut attributes: Vec<(&str, &str)> = Vec::new();");
    for attribute in &shape.xml.attributes {
        match &attribute.source {
            AttributeSource::Constant(literal) => {
                let _ = writeln!(out, "    attributes.push((\"{}\", \"{literal}\"));", attribute.name);
            }
            AttributeSource::Field(member) => {
                let field = naming::field_name(member);
                let _ = writeln!(out, "    if let Some(v) = value.{field}.as_ref() {{");
                let _ = writeln!(out, "        attributes.push((\"{}\", v.as_str()));", attribute.name);
                let _ = writeln!(out, "    }}");
            }
        }
    }
    let _ = writeln!(out, "    writer.open_with(\"{element}\", &attributes);");
    out.push_str("}\n");
    out
}

/// The wire expression for one member, encoded or not.
///
/// One call rather than an `if` at each of the four sites that render a scalar: the two forms are
/// interchangeable everywhere a value is written, and a site that forgot the encoded one would
/// write the raw spelling into a document whose echo claims otherwise.
fn wire_expr(ty: &Type, member: &str, operation: &str, encoded: bool) -> Result<String, String> {
    if encoded {
        return expr::to_wire_url_encoded(ty, member, operation);
    }
    expr::to_wire(ty, member, operation)
}

/// The extra argument a nested shape's writer takes, when it encodes anything.
///
/// Empty for every shape that does not, so a writer never carries a parameter it does not read —
/// `-D warnings` would refuse the unused binding, and a `_`-prefixed one would hide the fact that
/// the shape opted out.
fn shape_writer_argument(plan: &url::Plan, shape: &str) -> &'static str {
    if plan.encodes_shape(shape) { ", url_encoding" } else { "" }
}

/// The `XmlWriter` method one scalar body member is written with.
///
/// Two independent IR facts choose it and neither is a name comparison: `empty_value_policy` says
/// whether an empty value is written as a paired element or dropped, and the type says whether the
/// value's own wire form carries quotation marks the writer has to escape. `ETag(XmlQuoted)` is
/// the only rendering that does — `ETag(XmlBare)` and every string are written with the ordinary
/// escaping, which is what leaves a `"` inside an object key literal.
fn element_call(ty: &Type, policy: EmptyValue) -> &'static str {
    let quoting = matches!(ty, Type::ETag(ETagRender::XmlQuoted));
    match (policy, quoting) {
        (EmptyValue::Emit, false) => "element",
        (EmptyValue::Omit, false) => "element_if_present",
        (EmptyValue::Emit, true) => "element_quoting",
        (EmptyValue::Omit, true) => "element_quoting_if_present",
    }
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
    let plan = url::plan(ir)?;
    let type_name = naming::type_name(name);
    let order = if shape.xml.element_order.is_empty() {
        shape.fields.iter().map(|f| f.name.clone()).collect()
    } else {
        shape.xml.element_order.clone()
    };

    let mut out = shape_opener(name, shape);
    if !out.is_empty() {
        out.push('\n');
    }
    let _ = writeln!(out, "/// Writes one `{name}` element's children, in the wire order the IR records.");
    out.push_str(&shape_writer_signature(&naming::module_name(name), &type_name, plan.encodes_shape(name)));
    // The mirror of the empty-shape arm in `decode::shape_reader`: a structure with no members
    // writes no children, so both parameters are consumed explicitly rather than renamed.
    if shape.fields.is_empty() {
        out.push_str("    let _ = writer;\n    let _ = value;\n");
    }
    for member in order {
        let Some(field) = shape.fields.iter().find(|f| f.name == member) else {
            continue;
        };
        // The attribute went into the opening tag; writing it again as a child element is the
        // `<xsi:type>` spelling no SDK reads.
        if carried_as_attribute(shape, &field.name) {
            let _ = writeln!(
                out,
                "    // {} — written as the `{}` attribute of the opening tag.",
                field.name,
                attribute_name(shape, &field.name)
            );
            continue;
        }
        let source = format!("value.{}", naming::field_name(&field.name));
        let wire = field.wire_name.clone().unwrap_or_else(|| field.name.clone());
        let policy = empty_policy(&shape.xml.empty_value_policy, &field.name, field.required);
        let encoded = plan.encodes_shape_member(name, &field.name);
        match &field.ty {
            Type::Structure(_) | Type::List { .. } => {
                out.push_str(&shape_child(ir, &plan, field, &source, &wire)?);
            }
            other => {
                let rendered = wire_expr(other, &field.name, &ir.operation, encoded)?;
                let call = element_call(other, policy);
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
fn shape_child(ir: &OperationIr, plan: &url::Plan, field: &Field, source: &str, wire: &str) -> Result<String, String> {
    let mut out = String::new();
    match &field.ty {
        Type::Structure(inner) => {
            let writer_fn = format!("write_{}", naming::module_name(inner));
            let argument = shape_writer_argument(plan, inner);
            let open = open_structure(ir, inner, wire, "v", "writer")?;
            if field.required {
                let _ = writeln!(out, "    {{");
                let _ = writeln!(out, "        let v = &{source};");
            } else {
                let _ = writeln!(out, "    if let Some(v) = {source}.as_ref() {{");
            }
            let _ = writeln!(out, "        {open}");
            let _ = writeln!(out, "        {writer_fn}(writer, v{argument})?;");
            let _ = writeln!(out, "        writer.close();");
            let _ = writeln!(out, "    }}");
        }
        // A list *inside a shape* obeys the same wrapped/flattened rule as one at the operation
        // level, and it has to read it from the same place: `list_elements` is where that rule
        // lives, and the reader in `super::decode` already consulted it here while this arm did
        // not. The disagreement was invisible for as long as every nested list happened to be
        // flattened — the first wrapped one, `LoggingEnabled.TargetGrants`, came back as repeated
        // `<TargetGrants>` elements with the `<Grant>` entry missing entirely, a document the
        // decoder beside it would refuse.
        Type::List {
            member: inner,
            flattened,
            wrapper_name,
        } => {
            let names = super::list_elements(*flattened, wrapper_name.as_deref(), wire);
            if let Some(wrapper) = &names.wrapper {
                let _ = writeln!(out, "    writer.open(\"{wrapper}\", None);");
            }
            match inner.as_ref() {
                Type::Structure(inner_name) => {
                    let writer_fn = format!("write_{}", naming::module_name(inner_name));
                    let argument = shape_writer_argument(plan, inner_name);
                    let open = open_structure(ir, inner_name, &names.entry, "item", "writer")?;
                    let _ = writeln!(out, "    for item in &{source} {{");
                    let _ = writeln!(out, "        {open}");
                    let _ = writeln!(out, "        {writer_fn}(writer, item{argument})?;");
                    let _ = writeln!(out, "        writer.close();");
                    let _ = writeln!(out, "    }}");
                }
                // A list of scalars repeats the element with its text.
                scalar => {
                    let rendered = expr::to_wire(scalar, &field.name, &ir.operation)?;
                    let _ = writeln!(out, "    for v in &{source} {{");
                    let _ = writeln!(out, "        writer.element(\"{}\", {rendered});", names.entry);
                    let _ = writeln!(out, "    }}");
                }
            }
            if names.wrapper.is_some() {
                let _ = writeln!(out, "    writer.close();");
            }
        }
        _ => {}
    }
    Ok(out)
}

/// rustfmt's `max_width` for this repository.
const MAX_WIDTH: usize = 130;

/// The signature of one shape writer, laid out the way rustfmt would lay it out.
///
/// `cargo fmt` follows `#[path]` into `generated/`, so a signature past `max_width` makes
/// `cargo xtask spec verify` fail the moment anybody formats the tree — and the shape names are
/// upstream's, so how long they get is not something this emitter controls.
///
/// `encodes` adds the url-encoding decision, for a shape that has a member to apply it to.
fn shape_writer_signature(module: &str, type_name: &str, encodes: bool) -> String {
    let encoding = if encodes { ", url_encoding: value::UrlEncoding" } else { "" };
    let single = format!(
        "fn write_{module}(writer: &mut rustfs_gateway_xml::XmlWriter, value: &dto::{type_name}{encoding}) -> Result<(), CodecError> {{\n"
    );
    if single.len().saturating_sub(1) <= MAX_WIDTH {
        return single;
    }
    let wrapped = if encodes {
        "\n    url_encoding: value::UrlEncoding,"
    } else {
        ""
    };
    format!(
        "fn write_{module}(\n    writer: &mut rustfs_gateway_xml::XmlWriter,\n    value: &dto::{type_name},{wrapped}\n) -> Result<(), CodecError> {{\n"
    )
}

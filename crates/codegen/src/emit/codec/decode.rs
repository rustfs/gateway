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
//!
//! # When a decoder may refuse an empty list, and where that permission comes from
//!
//! From `required` in the **model**, and from nowhere else — never from an overlay that wants a
//! refusal.
//!
//! Every list in the request surface is `xmlFlattened`, so its entries repeat directly under the
//! parent with no enclosing element. For such a list "the member is absent" and "the list has no
//! entries" are the same observation: there is nothing else on the wire to tell them apart. That
//! is what makes refusing an empty flattened list a reading of `required` rather than an opinion
//! about arity, and it is why `Delete.Objects` — `required` in the pinned model — is answered
//! `MalformedXML` here.
//!
//! The rule that had to be written down is the other half. `CompletedMultipartUpload.Parts` is
//! **not** required in the model; `model/overlays/ops/multipart.toml` had made it so, and the only
//! effect of that on a flattened list is this refusal. So an overlay had manufactured a wire
//! requirement in order to get an error out of the parser — and the error it got was the parser's
//! `MalformedXML`, where the operation owes `InvalidPart`. The backend was never called, and the
//! client read the wrong `<Code>` (issue #17, `c-mpu-0019`, `c-mpu-0034`).
//!
//! Stated so the next list member does not have to re-derive it: **a decoder may say "this is not
//! the document" and nothing else.** It has no way to name any other code — there is no parameter
//! here that could carry one — so a member whose emptiness has an operation-specific answer must
//! not be made `required` by an overlay to reach it. Requiredness is a fact about the wire that
//! the model states; wanting a particular error code is not a reason to assert one.
//!
//! A *wrapped* list would break the equivalence above, because `<Parts></Parts>` is present and
//! empty at the same time. None exists in the request surface today; the day one does, this
//! paragraph is the reason the check has to be re-derived rather than inherited.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Quirk, Shape, Type};

use super::{attribute_name, bounds, carried_as_attribute, expr, forms, media, tolerance};
use crate::emit::dto::naming;

/// The default code for a required member the request did not carry.
const DEFAULT_MISSING_CODE: &str = "InvalidArgument";

/// The node iterator one list-typed member reads its entries from.
///
/// A flattened list repeats its entry element directly under the parent; a wrapped one sits inside
/// an enclosing element. Which name is which comes from [`super::list_elements`] rather than from
/// here, so the reader and the writer cannot disagree about it — they did, and the disagreement
/// was invisible because both spellings compile.
///
/// Returned as the links of a method chain rather than as one string, because rustfmt breaks a
/// chain that is too long link by link and this emitter has to produce what rustfmt would.
fn list_source(flattened: bool, wrapper_name: Option<&str>, wire: &str) -> Vec<String> {
    let names = super::list_elements(flattened, wrapper_name, wire);
    match &names.wrapper {
        None => vec![format!("children_named(\"{}\")", names.entry)],
        Some(wrapper) => vec![
            format!("child(\"{wrapper}\")"),
            "into_iter()".to_owned(),
            format!("flat_map(|w| w.children_named(\"{}\"))", names.entry),
        ],
    }
}

/// The `for item in <chain> {` header, laid out the way rustfmt would lay it out.
///
/// rustfmt keeps a chain on one line while the links after the receiver fit `chain_width` and the
/// whole line fits `max_width`; past either it puts every link on its own line and the opening
/// brace on a line of its own. The wrapped `AccessControlList` list inside a restore's
/// `OutputLocation` is what first crossed it.
fn for_header(indent: usize, receiver: &str, links: &[String]) -> String {
    let pad = " ".repeat(indent);
    let chain: String = links.iter().map(|link| format!(".{link}")).collect();
    let single = format!("{pad}for item in {receiver}{chain} {{\n");
    if single.len().saturating_sub(1) <= MAX_WIDTH && chain.len() <= CHAIN_WIDTH {
        return single;
    }
    let continuation = " ".repeat(indent.saturating_add(4));
    let mut out = format!("{pad}for item in {receiver}\n");
    for link in links {
        out.push_str(&format!("{continuation}.{link}\n"));
    }
    out.push_str(&format!("{pad}{{\n"));
    out
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

/// rustfmt's default `chain_width`: sixty per cent of `max_width`, the budget a method chain has
/// before every link goes onto its own line.
const CHAIN_WIDTH: usize = MAX_WIDTH * 6 / 10;

/// One `target.push(expression)` inside a list loop, laid out the way rustfmt would lay it out.
///
/// The target is a field access on `shape` or `input`, so the statement is a two-link chain, and
/// rustfmt's rule for chains is `chain_width`, not `max_width`: the links past the receiver must
/// fit the chain budget or each goes onto its own line. A lifecycle rule's
/// `noncurrent_version_transitions` list is what made the budget observable.
fn push_stmt(indent: usize, target: &str, expression: &str) -> String {
    let pad = " ".repeat(indent);
    let single = format!("{pad}{target}.push({expression});\n");
    let receiver_len = target.split('.').next().map_or(0, str::len);
    let chain_len = target.len().saturating_sub(receiver_len) + ".push()".len() + expression.len();
    if single.len().saturating_sub(1) <= MAX_WIDTH && chain_len <= CHAIN_WIDTH {
        return single;
    }
    let continuation = " ".repeat(indent.saturating_add(4));
    let (receiver, links) = target.split_once('.').unwrap_or((target, ""));
    format!("{pad}{receiver}\n{continuation}.{links}\n{continuation}.push({expression});\n")
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

    // Where the XML document is opened, for an operation whose body members sit at operation
    // level rather than inside a payload structure. It is opened at the *first* such member and
    // not before, so a head binding declared ahead of it is still read ahead of it: an operation
    // that refuses on its head must not have buffered a body first.
    let first_body_member = ir.input.iter().position(|field| field.binding == Binding::BodyXml);
    for (index, field) in ir.input.iter().enumerate() {
        out.push_str(&one_field(ir, field, first_body_member == Some(index))?);
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
///
/// `open_document` is true for the first operation-level [`Binding::BodyXml`] member, which is
/// the one that parses the request body into the `root` node its siblings then read from.
fn one_field(ir: &OperationIr, field: &Field, open_document: bool) -> Result<String, String> {
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
            // A tolerated binding produces the stored `Option` itself, so it is emitted instead of
            // the conversion and never passed through `wrap`. That is the shape, not an
            // optimisation: the value it yields already distinguishes "arrived and unreadable"
            // from "did not arrive", and wrapping it in a second `Some` would put the two back
            // together — the `if-range` defect, one layer up.
            let tolerated = tolerance::of(field, &ir.quirks, op)?;
            let assignment = match tolerated {
                Some(reading) => reading
                    .call(&field.ty)
                    .ok_or_else(|| expr::unsupported(op, member, "this tolerance has no reading for the member's type"))?,
                None => wrap(
                    field,
                    &expr::from_wire(
                        &field.ty,
                        member,
                        op,
                        false,
                        bounds::of(field, &ir.quirks, op)?,
                        forms::of(field, &ir.quirks, op)?,
                    )?,
                ),
            };
            if tolerated.is_some() {
                let _ = writeln!(
                    out,
                    "        // {member} — header `{wire}`, read tolerantly: a value that is not a date is ignored."
                );
            } else {
                let _ = writeln!(out, "        // {member} — header `{wire}`, repeated field lines joined.");
            }
            let _ = writeln!(out, "        if let Some(raw) = request.header(\"{wire}\") {{");
            let _ = writeln!(out, "            let raw = raw.as_ref();");
            out.push_str(&assign(12, &target, &assignment));
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
                // An optional payload means the request may carry no body at all (CreateBucket):
                // zero bytes decode to the absent member, and anything else must still be the
                // declared document — an empty body is the one spelling that skips the parser.
                let (indent, close) = if field.required {
                    ("        ", "")
                } else {
                    let _ = writeln!(out, "        if raw_body.as_ref().is_empty() {{");
                    let _ = writeln!(out, "            {target} = None;");
                    out.push_str("        } else {\n");
                    ("            ", "        }\n")
                };
                let _ = writeln!(out, "{indent}let root = rustfs_gateway_xml::parse(raw_body.as_ref())");
                let _ = writeln!(
                    out,
                    "{indent}    .map_err(|_| CodecError::malformed_xml(\"the request body is not the XML this operation accepts\"))?;"
                );
                let mut accepted = vec![root];
                accepted.extend(aliases);
                let names = accepted.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(", ");
                let _ = writeln!(out, "{indent}if ![{names}].contains(&root.name.as_str()) {{");
                let base = "CodecError::malformed_xml(\"the request body has the wrong root element\")";
                let refusal = format!("{base}.about(\"{member}\")");
                let single = format!("{indent}    return Err({refusal});");
                if single.len() <= MAX_WIDTH {
                    let _ = writeln!(out, "{single}");
                } else if indent.len().saturating_add(8).saturating_add(refusal.len()) <= MAX_WIDTH {
                    // rustfmt's normal form for the over-long line: the argument on its own line.
                    let _ = writeln!(out, "{indent}    return Err(");
                    let _ = writeln!(out, "{indent}        {refusal}");
                    let _ = writeln!(out, "{indent}    );");
                } else {
                    // A shape name long enough that even the argument line overflows: rustfmt then
                    // breaks the method chain instead — the third form, learned from
                    // `ServerSideEncryptionConfiguration`.
                    let _ = writeln!(out, "{indent}    return Err({base}");
                    let _ = writeln!(out, "{indent}        .about(\"{member}\"));");
                }
                let _ = writeln!(out, "{indent}}}");
                let indent_len = indent.len();
                out.push_str(&assign(indent_len, &target, &wrap(field, &format!("{reader}(&root)?"))));
                out.push_str(close);
            }
            // A text payload is the body verbatim, once it is text at all. The decoder's whole
            // contribution is the UTF-8 refusal — whether the document *says* anything valid is
            // the operation's own question, asked after decoding, with the code that operation
            // owes. A bucket policy is the only member here today, and `MalformedPolicy` is not
            // a code any decoder can name.
            Type::String | Type::OpaqueString => {
                let media = media::required(field, &ir.quirks, op)?;
                let _ = writeln!(out, "        // {member} — the buffered request body, `{media}`.");
                out.push_str("        let raw_body = body.into_buffered()?;\n");
                let read = format!("value::text_payload(raw_body.as_ref(), \"{member}\")?");
                let read = match field.ty {
                    Type::OpaqueString => format!("value::opaque(&{read})"),
                    _ => read,
                };
                out.push_str(&assign(8, &target, &wrap(field, &read)));
            }
            _ => {
                return Err(expr::unsupported(
                    op,
                    member,
                    "a payload binding carries a blob, a text document or an XML structure",
                ));
            }
        },
        Binding::BodyXml => {
            if open_document {
                out.push_str(&open_request_document(ir)?);
            }
            out.push_str(&xml_member(op, field, &target, &ir.quirks, "root", 8)?);
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
    // A container and a required member are both stored bare. `Type::Range` is *not* on this list
    // any more: it used to produce an `Option` of its own, whose `None` conflated "no Range header"
    // with "a Range header we will not honour" and threw away the text a 416 has to echo. It now
    // yields a `RangeSpec` and is wrapped like any other optional binding, so absence is spelled
    // once and by the wrapper.
    let bare = field.required || matches!(field.ty, Type::List { .. } | Type::Map { .. } | Type::ChecksumSpec);
    if bare { inner.to_owned() } else { format!("Some({inner})") }
}

/// Opens the request document for an operation whose XML members sit at operation level.
///
/// The symmetric case of [`super::encode`]'s `xml_body`: a response has always been able to put
/// its body members directly under a root, and until `SelectObjectContent` no *request* in the
/// supported surface did. The alternative shape — one `httpPayload` structure holding the whole
/// document — is handled at the member itself, in [`one_field`], and reaches a different reader.
///
/// The root is parsed once and bound to `root`; every operation-level member then reads out of it
/// with exactly the lines a nested member of a shape reads with, because both go through
/// [`xml_member`]. No `.about(..)` rides the wrong-root refusal here: at operation level there is
/// no single member the root belongs to, and naming an arbitrary one of them would put a member
/// into an error that is about the document.
fn open_request_document(ir: &OperationIr) -> Result<String, String> {
    let root = ir
        .xml
        .request_root
        .as_deref()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("codec {}: the operation has body members and no request root", ir.operation))?;
    let mut aliases: Vec<String> = vec![root.to_owned()];
    aliases.extend(ir.xml.request_root_aliases.clone());
    let names = aliases
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = String::new();
    let _ = writeln!(out, "        // The XML request body, rooted at `{root}`.");
    out.push_str("        let raw_body = body.into_buffered()?;\n");
    out.push_str("        let root = rustfs_gateway_xml::parse(raw_body.as_ref())\n");
    out.push_str(
        "            .map_err(|_| CodecError::malformed_xml(\"the request body is not the XML this operation accepts\"))?;\n",
    );
    let _ = writeln!(out, "        if ![{names}].contains(&root.name.as_str()) {{");
    out.push_str("            return Err(CodecError::malformed_xml(\"the request body has the wrong root element\"));\n");
    out.push_str("        }\n");
    Ok(out)
}

/// Renders the lines that read one XML member out of `node`, wherever that member lives.
///
/// One copy, two callers: [`shape_reader`] reads a nested shape's members out of `node` at indent
/// four, and [`one_field`] reads an operation-level member out of `root` at indent eight. They
/// were two copies for exactly as long as only one of them existed; a second copy is how the
/// required-member refusal and the flattened-list rule would come to disagree.
fn xml_member(
    operation: &str,
    field: &Field,
    target: &str,
    quirks: &[Quirk],
    node: &str,
    indent: usize,
) -> Result<String, String> {
    let member = &field.name;
    let wire = field.wire_name.clone().unwrap_or_else(|| member.clone());
    let pad = " ".repeat(indent);
    let inner = indent.saturating_add(4);
    let mut out = String::new();
    match &field.ty {
        Type::List {
            member: entry,
            flattened,
            wrapper_name,
        } if !matches!(entry.as_ref(), Type::Structure(_)) => {
            let conversion = expr::from_wire(
                entry,
                member,
                operation,
                true,
                bounds::of(field, quirks, operation)?,
                forms::of(field, quirks, operation)?,
            )?;
            let links = list_source(*flattened, wrapper_name.as_deref(), &wire);
            out.push_str(&for_header(indent, node, &links));
            let _ = writeln!(out, "{}let raw = item.text.as_str();", " ".repeat(inner));
            out.push_str(&push_stmt(inner, target, &conversion));
            let _ = writeln!(out, "{pad}}}");
        }
        Type::List {
            member: entry,
            flattened,
            wrapper_name,
        } => {
            let Type::Structure(entry_name) = entry.as_ref() else {
                return Err(expr::unsupported(
                    operation,
                    member,
                    "a request body list carries structures in the supported surface",
                ));
            };
            let reader = format!("read_{}", naming::module_name(entry_name));
            let links = list_source(*flattened, wrapper_name.as_deref(), &wire);
            out.push_str(&for_header(indent, node, &links));
            out.push_str(&push_stmt(inner, target, &format!("{reader}(item)?")));
            let _ = writeln!(out, "{pad}}}");
            // Only the model's own `required` reaches here, and only `MalformedXML` can come
            // out of it. See the module documentation: an overlay that makes a list required in
            // order to reach an error code is taking the operation's answer, not stating a
            // wire fact.
            if field.required {
                let _ = writeln!(out, "{pad}if {target}.is_empty() {{");
                let _ = writeln!(
                    out,
                    "{}return Err(CodecError::malformed_xml(\"the body carries no entry for a member that requires one\").about(\"{member}\"));",
                    " ".repeat(inner)
                );
                let _ = writeln!(out, "{pad}}}");
            }
        }
        Type::Structure(entry_name) => {
            let reader = format!("read_{}", naming::module_name(entry_name));
            let _ = writeln!(out, "{pad}if let Some(child) = {node}.child(\"{wire}\") {{");
            out.push_str(&assign(inner, target, &wrap(field, &format!("{reader}(child)?"))));
            out.push_str(&required_member_refusal(field, member, indent));
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
            let _ = writeln!(out, "{pad}if let Some(raw) = {node}.child_text(\"{wire}\") {{");
            out.push_str(&assign(inner, target, &wrap(field, &conversion)));
            out.push_str(&required_member_refusal(field, member, indent));
        }
    }
    Ok(out)
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
    // A shape the model declares with no members at all — `ParquetInput` is the one, and it is
    // how a Select request says "Parquet" and nothing further. Its reader reads nothing, so both
    // the node and the mutability would be unused, and this workspace builds with warnings denied.
    let empty = shape.fields.is_empty();
    let node = if empty { "_node" } else { "node" };
    let construct = if empty {
        // `..Default::default()` over a struct with no fields is `clippy::needless_update`.
        format!("let shape = dto::{type_name} {{}};")
    } else {
        format!("let mut shape = dto::{type_name} {{ ..Default::default() }};")
    };
    // rustfmt's normal form: the signature stays on one line until it would cross `max_width`,
    // then the parameter gets its own line. A lifecycle shape name is what first crossed it.
    let single = format!(
        "fn read_{}({node}: &rustfs_gateway_xml::XmlNode) -> Result<dto::{type_name}, CodecError> {{",
        naming::module_name(name)
    );
    if single.len() <= MAX_WIDTH {
        let _ = writeln!(out, "{single}");
    } else {
        let _ = writeln!(
            out,
            "fn read_{}(\n    {node}: &rustfs_gateway_xml::XmlNode,\n) -> Result<dto::{type_name}, CodecError> {{",
            naming::module_name(name)
        );
    }
    let _ = writeln!(out, "    {construct}");

    for field in &shape.fields {
        // A member the IR carries as an XML attribute is not a child element, and the reader this
        // project ships hands attributes to nobody. Reading it as an element would accept a
        // spelling no AWS SDK sends and refuse the one they all do; the member is left at its
        // default and whichever shared contract owns the shape derives it. See `super`'s note on
        // the attribute mechanism.
        if carried_as_attribute(shape, &field.name) {
            let _ = writeln!(
                out,
                "    // {} — carried by the `{}` attribute, which the reader does not expose.",
                field.name,
                attribute_name(shape, &field.name)
            );
            continue;
        }
        let target = format!("shape.{}", naming::field_name(&field.name));
        out.push_str(&xml_member(operation, field, &target, quirks, "node", 4)?);
    }
    out.push_str("    value::exit(shape.check_required())?;\n    Ok(shape)\n}\n");
    Ok(out)
}

/// Closes a shape member's `if let`, refusing when the member is required and absent.
///
/// Only the model's own `required` reaches here — the same rule the required-list refusal above
/// states. Without the `else`, a missing required member sailed past its binding still holding
/// the placeholder default, and the decoder's exit check turned a client's malformed document
/// into this side's `500 InternalError`; the omission of a required element is a schema
/// violation and answers `MalformedXML` like every other one.
fn required_member_refusal(field: &Field, member: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    if !field.required {
        return format!("{pad}}}\n");
    }
    let mut out = String::new();
    let _ = writeln!(out, "{pad}}} else {{");
    let inner = " ".repeat(indent.saturating_add(4));
    let refusal = format!("CodecError::malformed_xml(\"the body omits a member the schema requires\").about(\"{member}\")");
    let single = format!("{inner}return Err({refusal});");
    if single.len() <= MAX_WIDTH {
        let _ = writeln!(out, "{single}");
    } else {
        // rustfmt's normal form once the statement crosses `max_width`: the argument gets its own
        // line. Reached only at the deeper indent an operation-level member is written at.
        let _ = writeln!(out, "{inner}return Err(");
        let _ = writeln!(out, "{inner}    {refusal}");
        let _ = writeln!(out, "{inner});");
    }
    let _ = writeln!(out, "{pad}}}");
    out
}

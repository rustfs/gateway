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
//! A *flattened* list repeats its entries directly under the parent with no enclosing element, so
//! "the member is absent" and "the list has no entries" are the same observation: there is nothing
//! else on the wire to tell them apart. That is what makes refusing an empty flattened list a
//! reading of `required` rather than an opinion about arity, and it is why `Delete.Objects` —
//! `required` in the pinned model — is answered `MalformedXML` here.
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
//! A *wrapped* list breaks that equivalence: `<TagSet></TagSet>` is present and empty at once, so
//! the refusal reads the **wrapper's absence** and never the entry count. The three wrapped request
//! readers are all the `Tagging` document's `TagSet`, and until rustfs/backlog#1717 they inherited
//! the flattened check rather than re-deriving it, so an empty `<TagSet/>` was `MalformedXML` — a
//! claim about arity `required` does not make, `TagSet` carries no `smithy.api#length` to support,
//! and AWS's user guide contradicts by documenting the empty tag set as *deleting* the existing
//! one. This gateway wrote those bytes itself (`q-tag-object-unconfigured-0090`) and refused them.

mod layout;
mod lists;

use std::fmt::Write as _;

use rustfs_gateway_model::UnknownElementPolicyValue;
use rustfs_gateway_model::ir::{AttributeSource, Binding, Field, OperationIr, Shape, ShapeKind, Type};

use super::{CodecRules, attribute_name, bounds, carried_as_attribute, expr, media, tolerance};
use crate::emit::dto::naming;
use crate::emit::error_status::Constants;

use self::layout::{MAX_WIDTH, assign, for_header, push_stmt};
use self::lists::{Presence, list_source};

/// The default code for a required member the request did not carry.
const DEFAULT_MISSING_CODE: &str = "InvalidArgument";

/// A flattened required list with no entries; the only way such a list can be absent.
const MISSING_LIST_ENTRIES: &str = "the body carries no entry for a member that requires one";
/// A wrapped required list whose wrapper is not on the wire at all.
const MISSING_MEMBER: &str = "the body omits a member the schema requires";

/// Opening the request document, the way the request's deployment reads one: as a tree, or as
/// legacy RustFS reads it against the operation's generated shape (`super::document`,
/// rustfs/gateway#1078). Either way a refused document is `MalformedXML` before any member is
/// read.
const OPEN_DOCUMENT: &str = "let root = crate::codec::request_document(request, raw_body.as_ref(), &document::DOCUMENT)?;";

/// Buffering the request body, and the one place a `Content-MD5` over it is settled.
///
/// The two lines are emitted together and never apart. A decoder that buffered a body without
/// verifying the digest declared over it would accept corrupted bytes at exactly the operations
/// AWS marks `httpChecksumRequired` — and the omission would be invisible, because a request whose
/// digest happens to be right decodes identically either way. `value::require_integrity` is the
/// other half and answers a different question: it asks whether a claim was *made*, before a byte
/// is read; this asks whether the claim was *true*, which cannot be asked any earlier.
const BUFFER_BODY: &str = concat!(
    "        let raw_body = body.into_buffered()?;\n",
    "        value::verify_body_digest(request, raw_body.as_ref())?;\n"
);

/// Renders the body of one operation's `decode`.
pub fn body(ir: &OperationIr, rules: &CodecRules, codes: &Constants) -> Result<String, String> {
    let mut out = String::new();
    let controlled_body = crate::emit::dto::controlled_required_body(&ir.input);
    let explicit_input = ir.input.iter().any(crate::emit::dto::requires_explicit_input_construction);
    if explicit_input {
        // ADR-0016: a required structural union has no honest Default. Decode into field-local
        // state and construct Input only after the union selected a real variant.
        for field in &ir.input {
            let name = naming::field_name(&field.name);
            if initializes_directly(field) {
                continue;
            }
            if field.required && !crate::emit::dto::registry::Registry::is_container(&field.ty) {
                let _ = writeln!(out, "        let {name};");
            } else {
                let _ = writeln!(out, "        let mut {name} = Default::default();");
            }
        }
    } else if controlled_body.is_none() {
        // Functional-update syntax rather than `Input::default()`: the fields are filled in one at
        // a time from bindings that may or may not fire, and `clippy::field_reassign_with_default`
        // refuses the plain form. It is also the construction ADR-0004 P1 asks callers to use.
        out.push_str("        let mut input = Input { ..Default::default() };\n");
    }
    // `checksum.http_checksum_required`, and nothing else, decides this. It is the first statement
    // of the decoder because the operations that carry it are the ones whose body must not be read
    // on an unverifiable request: `DeleteObjects` is a list of keys to destroy, so buffering it and
    // refusing afterwards has already paid for the attack.
    if ir.checksum.http_checksum_required {
        out.push_str("        // The IR declares this operation httpChecksumRequired.\n");
        out.push_str("        value::require_integrity(request)?;\n");
    }

    if controlled_body.is_some() {
        // A live producer has no truthful `Default`. The DTO constructor takes ownership of the
        // actual request body, so the required member is present before any other binding is read.
        out.push_str("        let mut input = Input::from_required_body(body.into_required_stream()?);\n");
    }

    // Where the XML document is opened, for an operation whose body members sit at operation
    // level rather than inside a payload structure. It is opened at the *first* such member and
    // not before, so a head binding declared ahead of it is still read ahead of it: an operation
    // that refuses on its head must not have buffered a body first.
    let first_body_member = ir.input.iter().position(|field| field.binding == Binding::BodyXml);
    for (index, field) in ir.input.iter().enumerate() {
        if controlled_body.is_some_and(|body| body.name == field.name) {
            continue;
        }
        let name = naming::field_name(&field.name);
        let target = if explicit_input {
            if initializes_directly(field) {
                format!("let {name}")
            } else {
                name
            }
        } else {
            format!("input.{name}")
        };
        out.push_str(&one_field(ir, field, &target, first_body_member == Some(index), rules, codes)?);
    }
    if !ir.input.iter().any(uses_body) {
        out.push_str("        let _ = body;\n");
    }
    if explicit_input {
        out.push_str("        let input = Input {\n");
        for field in &ir.input {
            let name = naming::field_name(&field.name);
            let _ = writeln!(out, "            {name},");
        }
        out.push_str("        };\n");
    }
    out.push_str("        value::exit(input.check_required())?;\n        Ok(input)\n");
    Ok(out)
}

fn uses_body(field: &Field) -> bool {
    matches!(field.binding, Binding::Payload | Binding::BodyXml | Binding::FormField)
}

/// Whether a required field is decoded on one unconditional straight-line binding.
///
/// Such fields can be declared at their assignment site. Conditional head bindings still need
/// field-local state before their `if`/`else`, while containers need mutable accumulation.
fn initializes_directly(field: &Field) -> bool {
    field.required
        && !crate::emit::dto::registry::Registry::is_container(&field.ty)
        && matches!(field.binding, Binding::UriLabel { .. } | Binding::Payload)
}

/// Renders the lines that read one input field.
///
/// `open_document` is true for the first operation-level [`Binding::BodyXml`] member, which is
/// the one that parses the request body into the `root` node its siblings then read from.
fn one_field(
    ir: &OperationIr,
    field: &Field,
    target: &str,
    open_document: bool,
    rules: &CodecRules,
    codes: &Constants,
) -> Result<String, String> {
    let op = &ir.operation;
    let member = &field.name;
    let wire = field.wire_name.clone().unwrap_or_default();
    let mut out = String::new();

    match &field.binding {
        Binding::UriLabel { greedy } => {
            // The only greedy label in the S3 surface is the object key; a non-greedy one is the
            // bucket. Both were split and decoded once, at `MetaView::of`.
            let accessor = if *greedy { "require_key" } else { "require_bucket" };
            let _ = writeln!(out, "        // {member} — URI label, decoded once by `MetaView::of`.");
            out.push_str(&assign(8, target, &format!("request.{accessor}()?")));
        }
        Binding::Header if matches!(field.ty, Type::List { .. }) => {
            let Type::List {
                member: entry,
                flattened: false,
                member_name: None,
            } = &field.ty
            else {
                return Err(expr::unsupported(
                    op,
                    member,
                    "a header list is comma-delimited; an XML list form has no header spelling",
                ));
            };
            let conversion = expr::from_wire(
                entry,
                member,
                op,
                false,
                bounds::of(field, rules, op)?,
                super::boolean::of(ir, field, rules)?,
                "request.names()",
            )?;
            let _ = writeln!(out, "        // {member} — header `{wire}`, a comma-delimited list.");
            let _ = writeln!(out, "        if let Some(raw) = request.header(\"{wire}\") {{");
            let _ = writeln!(out, "            for raw in value::header_list(raw.as_ref()) {{");
            out.push_str(&push_stmt(16, target, &conversion));
            out.push_str("            }\n");
            out.push_str(&otherwise(field, target, codes)?);
        }
        Binding::Header => {
            // A tolerated binding produces the stored `Option` itself, so it is emitted instead of
            // the conversion and never passed through `wrap`. That is the shape, not an
            // optimisation: the value it yields already distinguishes "arrived and unreadable"
            // from "did not arrive", and wrapping it in a second `Some` would put the two back
            // together — the `if-range` defect, one layer up.
            let tolerated = tolerance::of(field, rules, op)?;
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
                        bounds::of(field, rules, op)?,
                        super::boolean::of(ir, field, rules)?,
                        "request.names()",
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
            out.push_str(&assign(12, target, &assignment));
            out.push_str(&otherwise(field, target, codes)?);
        }
        Binding::Query => {
            let conversion = expr::from_wire(
                &field.ty,
                member,
                op,
                false,
                bounds::of(field, rules, op)?,
                super::boolean::of(ir, field, rules)?,
                "request.names()",
            )?;
            let _ = writeln!(out, "        // {member} — query `{wire}`, percent-decoded once.");
            let _ = writeln!(out, "        if let Some(raw) = request.query(\"{wire}\") {{");
            let _ = writeln!(out, "            let raw = raw.as_ref();");
            out.push_str(&assign(12, target, &wrap(field, &conversion)));
            out.push_str(&otherwise(field, target, codes)?);
        }
        Binding::PrefixHeaders => match &field.ty {
            Type::Map { .. } => {
                let _ = writeln!(out, "        // {member} — every header under `{wire}`.");
                out.push_str(&assign(8, target, &format!("value::metadata_map(request, \"{wire}\", \"{member}\")?")));
            }
            Type::ChecksumSpec => {
                let _ = writeln!(out, "        // {member} — the one checksum header under `{wire}`.");
                out.push_str(&assign(8, target, &format!("value::checksum_spec(request, \"{wire}\", \"{member}\")?")));
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
                out.push_str(&assign(8, target, "body.into_stream()"));
            }
            Type::Blob { streaming: false } => {
                let _ = writeln!(out, "        // {member} — the buffered request body.");
                out.push_str(BUFFER_BODY);
                out.push_str(&assign(8, target, &wrap(field, "raw_body")));
            }
            Type::Structure(shape) | Type::Union(shape) => {
                let root = if ir.xml.request_root.as_deref().unwrap_or("").is_empty() {
                    shape.clone()
                } else {
                    ir.xml.request_root.clone().unwrap_or_default()
                };
                let aliases: Vec<String> = ir.xml.request_root_aliases.clone();
                let reader = format!("read_{}", naming::module_name(shape));
                let _ = writeln!(out, "        // {member} — the XML request body, rooted at `{root}`.");
                out.push_str(BUFFER_BODY);
                if ir.xml.body_literal {
                    // After the digest check, which is over the bytes that arrived, and before the
                    // parse: a view the deployment marked reads MinIO's bare literal as the document
                    // it stands for; any other body, or an unmarked view, is handed on unchanged.
                    let _ = writeln!(out, "        let raw_body = value::body_literal(request, \"{root}\", raw_body);");
                }
                // An optional payload means the request may carry no body at all (CreateBucket):
                // zero bytes decode to the absent member, and anything else must still be the
                // declared document — an empty body is the one spelling that skips the parser.
                //
                // A required payload whose absence reads as the default document is never in the
                // lowered model; it is the mutation that violates a required body without changing
                // the member's type (`crate::mutate::plan`), and it takes the same branch shape.
                let (indent, close) = if crate::emit::reads_default_document(field) {
                    let _ = writeln!(out, "        if raw_body.as_ref().is_empty() {{");
                    let _ = writeln!(out, "            {target} = Default::default();");
                    out.push_str("        } else {\n");
                    ("            ", "        }\n")
                } else if field.required {
                    ("        ", "")
                } else {
                    let _ = writeln!(out, "        if raw_body.as_ref().is_empty() {{");
                    let _ = writeln!(out, "            {target} = None;");
                    out.push_str("        } else {\n");
                    ("            ", "        }\n")
                };
                out.push_str(&root_namespace_guard(&ir.operation, indent));
                let _ = writeln!(out, "{indent}{OPEN_DOCUMENT}");
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
                let read = super::name_policy::shape_reader_call(ir, shape, &reader, "&root", Some("request.names()"))?;
                out.push_str(&assign(indent_len, target, &wrap(field, &read)));
                out.push_str(close);
            }
            // A text payload is the body verbatim, once it is text at all. The decoder's whole
            // contribution is the UTF-8 refusal — whether the document *says* anything valid is
            // the operation's own question, asked after decoding, with the code that operation
            // owes. A bucket policy is the only member here today, and `MalformedPolicy` is not
            // a code any decoder can name.
            Type::String | Type::OpaqueString => {
                let media = media::required(field, rules, op)?;
                let _ = writeln!(out, "        // {member} — the buffered request body, `{media}`.");
                out.push_str(BUFFER_BODY);
                let read = format!("value::text_payload(raw_body.as_ref(), \"{member}\")?");
                let read = match field.ty {
                    Type::OpaqueString => format!("value::opaque(&{read})"),
                    _ => read,
                };
                out.push_str(&assign(8, target, &wrap(field, &read)));
            }
            _ => {
                return Err(expr::unsupported(
                    op,
                    member,
                    "a payload binding carries a blob, a text document, an XML structure or a structural union",
                ));
            }
        },
        Binding::BodyXml => {
            if open_document {
                out.push_str(&open_request_document(ir, super::unknown_element_policy(ir, rules)?)?);
            }
            let owner = format!("{}Input", naming::type_name(op));
            out.push_str(&xml_member(ir, (&owner, field), target, rules, "root", Some("request.names()"), 8)?);
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
fn otherwise(field: &Field, target: &str, codes: &Constants) -> Result<String, String> {
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
            let code = codes.path(field.missing_error.as_deref().unwrap_or(DEFAULT_MISSING_CODE))?;
            out.push_str("        } else {\n");
            let _ = writeln!(out, "            return Err(value::missing({code}, \"{member}\"));");
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
fn open_request_document(ir: &OperationIr, unknown_elements: UnknownElementPolicyValue) -> Result<String, String> {
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
    out.push_str(BUFFER_BODY);
    out.push_str(&root_namespace_guard(&ir.operation, "        "));
    let _ = writeln!(out, "        {OPEN_DOCUMENT}");
    let _ = writeln!(out, "        if ![{names}].contains(&root.name.as_str()) {{");
    out.push_str("            return Err(CodecError::malformed_xml(\"the request body has the wrong root element\"));\n");
    out.push_str("        }\n");
    if unknown_elements == UnknownElementPolicyValue::Reject {
        let names = ir.input.iter().filter(|field| field.binding == Binding::BodyXml);
        out.push_str(&super::unknown_child_guard(
            "root",
            names.map(|field| field.wire_name.as_deref().unwrap_or(&field.name)),
            "        ",
        ));
    }
    Ok(out)
}

fn root_namespace_guard(operation: &str, indent: &str) -> String {
    let policy = match operation {
        "RestoreObject" => {
            "crate::contracts::RESTORE_ROOT_NAMESPACE_POLICY, crate::contracts::RestoreRootNamespacePolicy::QualifiedName"
        }
        "SelectObjectContent" => {
            "crate::contracts::SELECT_ROOT_NAMESPACE_POLICY, crate::contracts::SelectRootNamespacePolicy::QualifiedName"
        }
        _ => return String::new(),
    };
    let policy = policy.replacen(", ", &format!(",\n{indent}    "), 1);
    format!(
        "{indent}if matches!(\n\
         {indent}    {policy}\n\
         {indent}) && raw_body\n\
         {indent}    .as_ref()\n\
         {indent}    .windows(6)\n\
         {indent}    .any(|part| part == b\"xmlns=\" || part == b\"xmlns:\")\n\
         {indent}{{\n\
         {indent}    return Err(CodecError::malformed_xml(\"the request body has the wrong root namespace\"));\n\
         {indent}}}\n"
    )
}

/// Renders the lines that read one XML member out of `node`, wherever that member lives.
///
/// One copy, two callers: [`shape_reader`] reads a nested shape's members out of `node` at indent
/// four, and [`one_field`] reads an operation-level member out of `root` at indent eight. They
/// were two copies for exactly as long as only one of them existed; a second copy is how the
/// required-member refusal and the flattened-list rule would come to disagree.
fn xml_member(
    ir: &OperationIr,
    (owner, field): (&str, &Field),
    target: &str,
    rules: &CodecRules,
    node: &str,
    name_policy: Option<&str>,
    indent: usize,
) -> Result<String, String> {
    let operation = &ir.operation;
    let member = &field.name;
    let wire = field.wire_name.clone().unwrap_or_else(|| member.clone());
    let pad = " ".repeat(indent);
    let inner = indent.saturating_add(4);
    let mut out = String::new();
    let presence = Presence::of(owner, field, target);
    out.push_str(&presence.prelude(&pad));
    match &field.ty {
        Type::List {
            member: entry,
            flattened,
            member_name,
        } if !matches!(entry.as_ref(), Type::Structure(_)) => {
            let conversion = expr::from_wire(
                entry,
                member,
                operation,
                true,
                bounds::of(field, rules, operation)?,
                super::boolean::of(ir, field, rules)?,
                name_policy.unwrap_or("names"),
            )?;
            let links = list_source(*flattened, member_name.as_deref(), &wire)?;
            out.push_str(&for_header(indent, node, &links));
            let _ = writeln!(out, "{}let raw = item.text.as_str();", " ".repeat(inner));
            out.push_str(&push_stmt(inner, presence.entries(), &conversion));
            let _ = writeln!(out, "{pad}}}");
            out.push_str(&presence.assign(indent, node, super::list_elements(*flattened, member_name.as_deref(), &wire)?)?);
        }
        Type::List {
            member: entry,
            flattened,
            member_name,
        } => {
            let Type::Structure(entry_name) = entry.as_ref() else {
                return Err(expr::unsupported(
                    operation,
                    member,
                    "a request body list carries structures in the supported surface",
                ));
            };
            let reader = format!("read_{}", naming::module_name(entry_name));
            let links = list_source(*flattened, member_name.as_deref(), &wire)?;
            out.push_str(&for_header(indent, node, &links));
            let read = super::name_policy::shape_reader_call(ir, entry_name, &reader, "item", name_policy)?;
            out.push_str(&push_stmt(inner, presence.entries(), &read));
            let _ = writeln!(out, "{pad}}}");
            out.push_str(&presence.assign(indent, node, super::list_elements(*flattened, member_name.as_deref(), &wire)?)?);
            // Only the model's own `required` reaches here, and only `MalformedXML` can come
            // out of it. See the module documentation: an overlay that makes a list required in
            // order to reach an error code is taking the operation's answer, not stating a
            // wire fact.
            //
            // What "absent" means depends on whether the list has an element of its own: a
            // flattened list *is* its entries, while a wrapped one has a wrapper whose absence
            // and whose emptiness are two different documents. Only the first is a missing
            // member; reading the entry count there refuses a document this shape's own encoder
            // writes.
            if field.required {
                let names = super::list_elements(*flattened, member_name.as_deref(), &wire)?;
                let (absent, reason) = match &names.wrapper {
                    None => (format!("{target}.is_empty()"), MISSING_LIST_ENTRIES),
                    Some(wrapper) => (format!("{node}.child(\"{wrapper}\").is_none()"), MISSING_MEMBER),
                };
                let _ = writeln!(out, "{pad}if {absent} {{");
                let _ = writeln!(
                    out,
                    "{}return Err(CodecError::malformed_xml(\"{reason}\").about(\"{member}\"));",
                    " ".repeat(inner)
                );
                let _ = writeln!(out, "{pad}}}");
            }
        }
        Type::Structure(entry_name) => {
            let reader = format!("read_{}", naming::module_name(entry_name));
            let _ = writeln!(out, "{pad}if let Some(child) = {node}.child(\"{wire}\") {{");
            out.push_str(&super::all_unknown::guard(ir, field, rules, entry_name, "child", inner)?);
            let read = super::name_policy::shape_reader_call(ir, entry_name, &reader, "child", name_policy)?;
            out.push_str(&assign(inner, target, &wrap(field, &read)));
            out.push_str(&required_member_refusal(field, member, indent));
        }
        other => {
            let conversion = expr::from_wire(
                other,
                member,
                operation,
                true,
                bounds::of(field, rules, operation)?,
                super::boolean::of(ir, field, rules)?,
                name_policy.unwrap_or("names"),
            )?;
            let _ = writeln!(out, "{pad}if let Some(raw) = {node}.child_text(\"{wire}\") {{");
            out.push_str(&assign(inner, target, &wrap(field, &conversion)));
            out.push_str(&required_member_refusal(field, &wire, indent));
        }
    }
    Ok(out)
}

/// Renders the lines that read one shape member the IR binds to an XML attribute.
///
/// The mirror image of [`super::encode`]'s `shape_opener`, and it must stay one: a member written
/// into the opening tag and read back out of a child element is the round trip nothing notices
/// until an SDK does.
fn xml_attribute_member(
    ir: &OperationIr,
    shape_name: &str,
    shape: &Shape,
    field: &Field,
    target: &str,
    rules: &CodecRules,
    name_policy: Option<&str>,
) -> Result<String, String> {
    let member = &field.name;
    let qualified = attribute_name(shape, member);
    let accessor = attribute_accessor(&ir.operation, shape_name, shape, &qualified)?;
    let conversion = expr::from_wire(
        &field.ty,
        member,
        &ir.operation,
        true,
        bounds::of(field, rules, &ir.operation)?,
        super::boolean::of(ir, field, rules)?,
        name_policy.unwrap_or("names"),
    )?;
    let mut out = String::new();
    let _ = writeln!(out, "    // {member} — the `{qualified}` attribute, not a child element.");
    let _ = writeln!(out, "    if let Some(raw) = node.{accessor} {{");
    out.push_str(&assign(8, target, &wrap(field, &conversion)));
    out.push_str(&required_member_refusal(field, &qualified, 4));
    Ok(out)
}

/// The reader call that fetches one attribute, resolved through the IR rather than through a
/// hard-coded namespace.
///
/// A prefixed attribute is looked up by the namespace its prefix is bound to, and the binding is
/// the shape's own constant `xmlns:<prefix>` attribute on the same element — which is the
/// declaration the encoder writes. Two spellings of the same fact would drift; this is one.
fn attribute_accessor(operation: &str, shape_name: &str, shape: &Shape, qualified: &str) -> Result<String, String> {
    let Some((prefix, local)) = qualified.split_once(':') else {
        return Ok(format!("attribute(\"{qualified}\")"));
    };
    let declaration = format!("xmlns:{prefix}");
    let namespace = shape
        .xml
        .attributes
        .iter()
        .find(|attribute| attribute.name == declaration)
        .and_then(|attribute| match &attribute.source {
            AttributeSource::Constant(literal) => Some(literal.clone()),
            AttributeSource::Field(_) => None,
        })
        .ok_or_else(|| {
            format!(
                "codec {operation}: shape `{shape_name}` reads the `{qualified}` attribute, but declares no constant `{declaration}` on the same element for its prefix to resolve through"
            )
        })?;
    Ok(format!("attribute_ns(\"{namespace}\", \"{local}\")"))
}

/// Renders the reader for one nested request shape.
///
/// Takes the operation's resolved quirks because a bounded integer is bounded wherever it is read:
/// `PartNumber` in a query and `PartNumber` in a completion body are the same wire contract, and a
/// reader that consulted only the operation's own fields would enforce it in one of the two.
pub fn shape_reader(
    ir: &OperationIr,
    name: &str,
    shape: &Shape,
    rules: &CodecRules,
    unknown_elements: UnknownElementPolicyValue,
) -> Result<String, String> {
    if shape.kind == ShapeKind::Union {
        return union_reader(ir, name, shape, rules);
    }
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
    let (signature, needs_names) = super::name_policy::shape_reader_signature(ir, name, node, &type_name, MAX_WIDTH);
    out.push_str(&signature);
    let _ = writeln!(out, "    {construct}");

    if unknown_elements == UnknownElementPolicyValue::Reject && !empty {
        let names = shape.fields.iter().filter(|field| !carried_as_attribute(shape, &field.name));
        out.push_str(&super::unknown_child_guard(
            "node",
            names.map(|field| field.wire_name.as_deref().unwrap_or(&field.name)),
            "    ",
        ));
    }

    for field in &shape.fields {
        let target = format!("shape.{}", naming::field_name(&field.name));
        // A member the IR carries as an XML attribute is not a child element. Reading it as one
        // would accept a spelling no AWS SDK sends and refuse the one they all do, so it is read
        // from the attribute — under the namespace the shape's own `xmlns:` constant binds, never
        // under the prefix, which is the sender's private alias.
        if carried_as_attribute(shape, &field.name) {
            out.push_str(&xml_attribute_member(
                ir,
                name,
                shape,
                field,
                &target,
                rules,
                needs_names.then_some("names"),
            )?);
            continue;
        }
        out.push_str(&xml_member(ir, (name, field), &target, rules, "node", needs_names.then_some("names"), 4)?);
    }
    out.push_str("    value::exit(shape.check_required())?;\n    Ok(shape)\n}\n");
    Ok(out)
}

/// Renders a request-side structural union reader.
///
/// A union is not a structure with optional fields: exactly one modeled child selects its enum
/// variant. Refusing zero, two or unknown children here prevents a required union from reaching
/// the handler as a fabricated default or an ambiguous projection.
fn union_reader(ir: &OperationIr, name: &str, shape: &Shape, rules: &CodecRules) -> Result<String, String> {
    let type_name = naming::type_name(name);
    let (signature, needs_names) = super::name_policy::shape_reader_signature(ir, name, "node", &type_name, MAX_WIDTH);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "/// Reads exactly one modeled `{name}` variant and refuses absent, ambiguous or unknown children."
    );
    out.push_str(&signature);
    let _ = writeln!(out, "    let mut selected: Option<dto::{type_name}> = None;");
    out.push_str("    for child in &node.children {\n");
    out.push_str("        let value = match child.name.as_str() {\n");
    for field in &shape.fields {
        let member = &field.name;
        let wire = field.wire_name.clone().unwrap_or_else(|| member.clone());
        let variant = naming::type_name(member);
        match &field.ty {
            Type::Structure(inner) | Type::Union(inner) => {
                let reader = format!("read_{}", naming::module_name(inner));
                let _ = writeln!(out, "            \"{wire}\" => {{");
                out.push_str(&super::all_unknown::guard(ir, field, rules, inner, "child", 16)?);
                let read = super::name_policy::shape_reader_call(ir, inner, &reader, "child", needs_names.then_some("names"))?;
                let _ = writeln!(out, "                let value = {read};");
                let _ = writeln!(out, "                dto::{type_name}::{variant}(value)");
                out.push_str("            }\n");
            }
            Type::List { .. } | Type::Map { .. } | Type::Blob { .. } | Type::Checksum(_) | Type::ChecksumSpec => {
                return Err(expr::unsupported(
                    &ir.operation,
                    member,
                    "a request structural-union variant must carry a scalar or nested shape",
                ));
            }
            scalar => {
                let conversion = expr::from_wire(
                    scalar,
                    member,
                    &ir.operation,
                    true,
                    bounds::of(field, rules, &ir.operation)?,
                    super::boolean::of(ir, field, rules)?,
                    "names",
                )?;
                let _ = writeln!(out, "            \"{wire}\" => {{");
                out.push_str("                let raw = child.text.as_str();\n");
                let _ = writeln!(out, "                dto::{type_name}::{variant}({conversion})");
                out.push_str("            }\n");
            }
        }
    }
    out.push_str(
        "            _ => {\n\
         \x20               return Err(CodecError::malformed_xml(\"the structural union contains an unknown variant\"));\n\
         \x20           }\n\
         \x20       };\n\
         \x20       if selected.replace(value).is_some() {\n\
         \x20           return Err(CodecError::malformed_xml(\"the structural union selects more than one variant\"));\n\
         \x20       }\n\
         \x20   }\n\
         \x20   selected.ok_or_else(|| CodecError::malformed_xml(\"the structural union selects no modeled variant\"))\n\
         }\n",
    );
    Ok(out)
}

/// Closes a shape member's `if let`, refusing when the member is required and absent.
///
/// Only the model's own `required` reaches here — the same rule the required-list refusal above
/// states. Without the `else`, a missing required member sailed past its binding still holding
/// the placeholder default, and the decoder's exit check turned a client's malformed document
/// into this side's `500 InternalError`; the omission of a required element is a schema
/// violation and answers `MalformedXML` like every other one.
///
/// A member whose absence reads as the default document is left holding that default instead:
/// that is the mutation violating the requirement without changing the member's type
/// (`crate::mutate::plan`), and the lowered model never carries it.
fn required_member_refusal(field: &Field, wire: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    if !field.required || crate::emit::reads_default_document(field) {
        return format!("{pad}}}\n");
    }
    let mut out = String::new();
    let _ = writeln!(out, "{pad}}} else {{");
    let inner = " ".repeat(indent.saturating_add(4));
    let refusal = format!("CodecError::malformed_xml(\"the body omits a member the schema requires\").about(\"{wire}\")");
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

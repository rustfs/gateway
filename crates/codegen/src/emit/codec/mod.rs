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

//! `generated/codec/ops/**`: one `impl OperationCodec` per operation.
//!
//! Responsible for: the file layout, the module facade, the `response-*` table, the shape
//! readers and writers each operation needs, and the one place that resolves a list's wrapper
//! element and its repeated entry element from the IR ([`list_elements`]).
//! NOT responsible for: the trait, the views, the RFC 9110 invariants or any scalar conversion.
//! All four are hand-written in `rustfs-gateway-core`'s `codec` module, and every generated line
//! calls into them.
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: `rustfs-gateway-core`, which mounts these
//! files with `#[path]`.
//!
//! # Why one file per operation
//!
//! The same reason `crate::ops` uses one file per operation and `model/overlays/ops` uses one file
//! per family: it is the unit of parallel edit conflict. A regenerated tree in which two families
//! moved touches two files and merges cleanly.
//!
//! # Why the operation is a `Payload` binding and not an `if`
//!
//! Everything this emitter branches on is IR data — the binding, the type, the entity-tag
//! rendering context, `xml.unwrapped_output`, `xml.empty_value_policy`, `xml.element_order`,
//! `omit_when`, `missing_error`. There is no operation name anywhere in the generated output
//! except as a comment and a type. That is the property that makes fifteen more families a matter
//! of writing overlay entries.

pub mod all_unknown;
pub mod boolean;
pub mod bounds;
pub mod decode;
pub mod document;
pub mod encode;
pub mod expr;
pub mod media;
pub mod name_policy;
pub mod tolerance;
pub mod url;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rustfs_gateway_model::ir::{AttributeSource, Binding, OperationIr, Shape, Type};
use rustfs_gateway_model::{CodecRule, CodecValue, UnknownElementPolicyValue};

use super::dto::{LICENSE, naming};
use super::error_status::Constants;

/// The query-parameter prefix that marks a response-header override.
///
/// The header a parameter overwrites is its own name with this prefix removed, so the table is
/// derived rather than listed. `response-content-type` overwrites `content-type`; there is no
/// second place for that pairing to be written down and get it wrong.
const RESPONSE_OVERRIDE_PREFIX: &str = "response-";

/// Typed overlay rules keyed by quirk id.
pub type CodecRules = BTreeMap<String, CodecRule>;

/// Renders every codec artefact.
///
/// # Errors
///
/// A string naming the operation and member whose binding the codec surface has no form for.
/// Failing is the point: an emitter that skipped the member would produce a codec that compiles,
/// runs, and silently drops a wire value.
pub fn emit(
    operations: &[OperationIr],
    rules: &CodecRules,
    codes: &Constants,
    generated_dir: &Path,
) -> Result<Vec<(PathBuf, String)>, String> {
    let mut ordered: Vec<&OperationIr> = operations.iter().collect();
    ordered.sort_by(|a, b| a.operation.cmp(&b.operation));

    let ops_dir = generated_dir.join("codec").join("ops");
    let payload_roots = document::payload_roots(&ordered);
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for ir in &ordered {
        files.push((
            ops_dir.join(format!("{}.rs", naming::module_name(&ir.operation))),
            operation(ir, rules, codes, &payload_roots)?,
        ));
    }
    files.push((ops_dir.join("mod.rs"), ops_mod(&ordered)));
    Ok(files)
}

/// Renders one operation's codec module.
fn operation(
    ir: &OperationIr,
    rules: &CodecRules,
    codes: &Constants,
    payload_roots: &BTreeSet<String>,
) -> Result<String, String> {
    let op = &ir.operation;
    let marker = naming::type_name(op);
    let module = naming::module_name(op);
    let mut out = String::from(LICENSE);

    let _ = write!(
        out,
        "\n//! `{op}` — the generated wire codec.\n\
         //!\n\
         //! Responsible for: reading a `{op}` request into its input, and writing its output back\n\
         //! as a status, a header set and a body. Every binding below is `generated/ir/{op}.json`;\n\
         //! nothing here is a decision.\n\
         //! NOT responsible for: any rule shared with another operation. The conversions, the\n\
         //! checksum-header rule and the RFC 9110 body invariants are hand-written in\n\
         //! `crate::codec` and called from here.\n\
         //! Upstream: `generated/ir/{op}.json`, `spec/operations/{op}.toml`. Downstream:\n\
         //! `crate::codec::ops`.\n\n"
    );

    // The bodies are rendered first: which imports a file needs is a fact about the code that was
    // generated, and `-D warnings` refuses an import the generated file does not use.
    let overrides = response_overrides(ir);
    let decoded = format!("{}{}", override_guard(&overrides), decode::body(ir, rules, codes)?);
    let encoded = encode::body(ir, rules)?;
    let uses = |needle: &str| decoded.contains(needle) || encoded.contains(needle);

    // rustfmt's order for one crate's imports, uppercase before lowercase. `cargo fmt` follows
    // `#[path]` into `generated/`, so an emitter that wrote them in any other order would make
    // `cargo xtask spec verify` fail the moment somebody formatted the tree.
    if uses("ErrorCode::") {
        out.push_str("use rustfs_gateway_types::ErrorCode;\n");
    }
    if needs_etag(ir) {
        out.push_str("use rustfs_gateway_types::EtagRender;\n");
    }
    if needs_timestamp(ir) {
        out.push_str("use rustfs_gateway_types::TimestampFormat;\n");
    }
    out.push_str("use rustfs_gateway_types::dto;\n");
    let _ = writeln!(out, "use rustfs_gateway_types::ops::{module}::Input;");
    out.push('\n');
    let mut response_names = vec!["EncodedResponse"];
    if uses("ResponseBody::") {
        response_names.push("ResponseBody");
    }
    if !overrides.is_empty() {
        response_names.push("ResponseOverride");
    }
    response_names.push("status_code");
    let _ = writeln!(out, "use crate::codec::response::{{{}}};", response_names.join(", "));
    out.push_str("use crate::codec::{CodecError, MetaView, OperationCodec, RequestBody, RequestBodyMode, value};\n\n");

    let _ = writeln!(out, "impl OperationCodec for dto::{marker} {{");
    let _ = writeln!(
        out,
        "    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::{};",
        ir.payload.request.buffering.as_str()
    );
    out.push('\n');
    out.push_str(&overrides);
    out.push_str("    fn decode(request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {\n");
    out.push_str(&decoded);
    out.push_str("    }\n\n");
    out.push_str(
        "    fn encode(output: Self::Output, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {\n",
    );
    out.push_str(&encoded);
    out.push_str("    }\n}\n");

    if ir.errors.allows_error_after_200 {
        let headers = response_binding_names(ir, Binding::Header);
        let prefixes = response_binding_names(ir, Binding::PrefixHeaders);
        let _ = write!(
            out,
            "\nimpl crate::handler::deferred_sealed::Sealed for dto::{marker} {{}}\n\n\
             impl crate::handler::DeferredOperation for dto::{marker} {{\n\
             \x20   const RESPONSE_HEADERS: &'static [&'static str] = {};\n\
             \x20   const RESPONSE_HEADER_PREFIXES: &'static [&'static str] = {};\n\
             }}\n",
            rust_string_slice(&headers),
            rust_string_slice(&prefixes),
        );
    }

    for (name, shape) in &ir.shapes {
        if reachable_from(ir, name, Side::Input) {
            out.push('\n');
            out.push_str(&decode::shape_reader(ir, name, shape, rules, unknown_element_policy(ir, rules)?)?);
        }
        if reachable_from(ir, name, Side::Output) {
            out.push('\n');
            out.push_str(&encode::shape_writer(ir, name, shape)?);
        }
    }
    if let Some(module) = document::module(ir, payload_roots)? {
        out.push_str(&module);
    }
    Ok(out)
}

fn response_binding_names(ir: &OperationIr, binding: Binding) -> Vec<String> {
    let mut names = ir
        .output
        .iter()
        .filter(|field| field.binding == binding)
        .filter_map(|field| field.wire_name.as_deref())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names
}

fn rust_string_slice(values: &[String]) -> String {
    if values.is_empty() {
        return "&[]".to_owned();
    }
    let entries = values
        .iter()
        .map(|value| format!("        \"{value}\","))
        .collect::<Vec<_>>()
        .join("\n");
    format!("&[\n{entries}\n    ]")
}

#[cfg(test)]
pub(crate) fn operation_for_test(ir: &OperationIr, rules: &CodecRules, codes: &Constants) -> Result<String, String> {
    operation(ir, rules, codes, &document::payload_roots(&[ir]))
}

fn unknown_element_policy(ir: &OperationIr, rules: &CodecRules) -> Result<UnknownElementPolicyValue, String> {
    let mut found = None;
    for quirk in &ir.quirks {
        let Some(rule) = rules.get(&quirk.id) else {
            continue;
        };
        let CodecValue::UnknownElementPolicy(policy) = rule.current else {
            continue;
        };
        if found.is_some_and(|current| current != policy) {
            return Err(format!("codec {}: unknown-element policies disagree", ir.operation));
        }
        found = Some(policy);
    }
    Ok(found.unwrap_or(UnknownElementPolicyValue::Skip))
}

/// The `allow-registered` guard: refuse any child element outside `names`.
///
/// Emitted already in rustfmt's layout, because the generated tree is both compared byte for byte
/// with a fresh run and checked by `cargo fmt`. The names are bound first so the `if` chain stays
/// under rustfmt's `chain_width` for every shape; the array itself is horizontal when it fits
/// rustfmt's `array_width` (sixty per cent of the repository's 130-column `max_width`) and one
/// name per line otherwise, which is rustfmt's layout for string literals longer than its
/// short-element threshold — every wire name a security configuration carries today.
fn unknown_child_guard<'a>(node: &str, names: impl Iterator<Item = &'a str>, indent: &str) -> String {
    const ARRAY_WIDTH: usize = 130 * 6 / 10;
    let names = names.map(|name| format!("\"{name}\"")).collect::<Vec<_>>();
    let horizontal = format!("[{}]", names.join(", "));
    let array = if horizontal.len() <= ARRAY_WIDTH {
        horizontal
    } else {
        let items = names.iter().map(|name| format!("{indent}    {name},\n")).collect::<String>();
        format!("[\n{items}{indent}]")
    };
    format!(
        "{indent}let known = {array};\n\
         {indent}if {node}.children.iter().any(|child| !known.contains(&child.name.as_str())) {{\n\
         {indent}    return Err(CodecError::malformed_xml(\"the body contains an unknown element\"));\n\
         {indent}}}\n"
    )
}

/// Whether a shape member is carried by an XML attribute rather than by a child element.
///
/// The two emitters ask this for opposite reasons and must agree: `decode` reads such a member out
/// of the opening tag instead of looking for a child element, and `encode` writes it into the
/// opening tag instead of emitting one. One answer, one place — a disagreement here is a member
/// written as an attribute and read back as an element, which is the round trip nothing would
/// notice until an SDK did.
#[must_use]
pub fn carried_as_attribute(shape: &Shape, member: &str) -> bool {
    shape
        .xml
        .attributes
        .iter()
        .any(|attribute| matches!(&attribute.source, AttributeSource::Field(name) if name == member))
}

/// The attribute name carrying a member, as the IR spells it — prefix included.
#[must_use]
pub fn attribute_name(shape: &Shape, member: &str) -> String {
    shape
        .xml
        .attributes
        .iter()
        .find(|attribute| matches!(&attribute.source, AttributeSource::Field(name) if name == member))
        .map(|attribute| attribute.name.clone())
        .unwrap_or_default()
}

/// The two element names a list is written and read through.
///
/// Resolved in one place because the two are easy to swap and a swap is invisible in a diff: the
/// shipped `ListBuckets` inversion — `<Bucket><Buckets>…</Buckets></Bucket>` where AWS writes
/// `<Buckets><Bucket>…</Bucket></Buckets>` — was one emitter reading `Type::List`'s then-misnamed
/// `wrapper_name` as the enclosing element on both the encode and the decode path. IR v3 renamed
/// the key to `member_name` (rustfs/gateway#11).
///
/// * `wrapper` is the enclosing element, and is always the field's own `wire_name`. `None` for a
///   flattened list, which has no enclosing element.
/// * `entry` is the repeated element. For a wrapped list it is `member_name`, the list member's
///   `xmlName`; for a flattened one it is the field's `wire_name`, which is what flattening means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListElements {
    /// The enclosing element, when the list has one.
    pub wrapper: Option<String>,
    /// The element each entry is written into.
    pub entry: String,
}

/// Resolves the wrapper and entry element names of one list-typed field.
///
/// `wire` is the field's wire name — the wrapper of a wrapped list, and the repeated element of a
/// flattened one.
///
/// # Errors
///
/// A list that is neither flattened nor names a member is the IR's comma-delimited header form,
/// which has no XML elements. Lowering writes Smithy's default `member` into every body list whose
/// model names none, so reaching here with that shape means a header list was routed into an XML
/// emitter; inventing an element name for it would put a fabricated wire form into safe code.
pub fn list_elements(flattened: bool, member_name: Option<&str>, wire: &str) -> Result<ListElements, String> {
    if flattened {
        return Ok(ListElements {
            wrapper: None,
            entry: wire.to_owned(),
        });
    }
    let entry = member_name
        .ok_or_else(|| format!("list `{wire}` is a comma-delimited header list and has no XML elements to read or write"))?;
    Ok(ListElements {
        wrapper: Some(wire.to_owned()),
        entry: entry.to_owned(),
    })
}

/// Which half of an operation a shape is reachable from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Input,
    Output,
}

/// Whether a nested shape is reachable from one half of the operation.
///
/// A shape reachable only from the request gets a reader and no writer, and the other way round.
/// Emitting both unconditionally would put dead code in every generated file, and `-D warnings`
/// would then be the thing that noticed.
fn reachable_from(ir: &OperationIr, shape: &str, side: Side) -> bool {
    let roots = match side {
        Side::Input => &ir.input,
        Side::Output => &ir.output,
    };
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut frontier: Vec<&Type> = roots.iter().map(|f| &f.ty).collect();
    while let Some(ty) = frontier.pop() {
        match ty {
            Type::Structure(name) | Type::Union(name) => {
                if name == shape {
                    return true;
                }
                if seen.insert(name.as_str())
                    && let Some(nested) = ir.shapes.get(name)
                {
                    frontier.extend(nested.fields.iter().map(|f| &f.ty));
                }
            }
            Type::List { member, .. } => frontier.push(member),
            Type::Map { key, value } => {
                frontier.push(key);
                frontier.push(value);
            }
            _ => {}
        }
    }
    false
}

/// Renders the `response-*` override table as an associated constant.
fn response_overrides(ir: &OperationIr) -> String {
    let entries: Vec<String> = ir
        .input
        .iter()
        .filter(|field| field.binding == Binding::Query)
        .filter_map(|field| field.wire_name.as_deref().map(|wire| (wire, field.name.as_str())))
        .filter_map(|(wire, member)| {
            wire.strip_prefix(RESPONSE_OVERRIDE_PREFIX)
                .map(|header| format!("        ResponseOverride::new(\"{wire}\", \"{header}\", \"{member}\"),"))
        })
        .collect();
    if entries.is_empty() {
        return String::new();
    }
    format!(
        "    const RESPONSE_OVERRIDES: &'static [ResponseOverride] = &[\n{}\n    ];\n\n",
        entries.join("\n")
    )
}

/// The first statement of a decoder whose operation declares `response-*` parameters.
///
/// Emitted from the same table the encoder writes those headers from, and emitted *before* any
/// binding is read, because the values are the caller's and they end up in the response head: a
/// CR or an LF in one of them terminates the header block early. The refusal is generated rather
/// than hand-written into the operations that have overrides for the same reason the table is —
/// an operation that gains a `response-*` parameter gains the check with it, and no author has to
/// remember that the two go together.
fn override_guard(overrides: &str) -> &'static str {
    if overrides.is_empty() {
        return "";
    }
    "        // The `response-*` values reach the response head, so a value no header can hold is\n\
     \x20       // refused before any other binding is read and before a handler sees the request.\n\
     \x20       value::verify_response_overrides(request, Self::RESPONSE_OVERRIDES)?;\n"
}

fn needs_timestamp(ir: &OperationIr) -> bool {
    walk_types(ir).any(|ty| matches!(ty, Type::Timestamp(_)))
}

fn needs_etag(ir: &OperationIr) -> bool {
    // Only the response side renders a tag: the request side parses one, and parsing carries the
    // context in the function name rather than in the enum. A shape reachable only from the
    // request therefore does not pull the import in.
    ir.output.iter().map(|f| &f.ty).any(|ty| matches!(ty, Type::ETag(_)))
        || ir
            .shapes
            .iter()
            .filter(|(name, _)| reachable_from(ir, name, Side::Output))
            .flat_map(|(_, shape)| shape.fields.iter().map(|f| &f.ty))
            .any(|ty| matches!(ty, Type::ETag(_)))
}

fn walk_types(ir: &OperationIr) -> impl Iterator<Item = &Type> {
    ir.input
        .iter()
        .chain(ir.output.iter())
        .map(|f| &f.ty)
        .chain(ir.shapes.values().flat_map(|shape| shape.fields.iter().map(|f| &f.ty)))
}

/// Renders `generated/codec/ops/mod.rs`.
fn ops_mod(operations: &[&OperationIr]) -> String {
    let mut out = String::from(LICENSE);
    out.push_str(
        "\n//! The generated per-operation codecs.\n\
         //!\n\
         //! Responsible for: mounting one module per generated operation. Each declares exactly one\n\
         //! `impl OperationCodec`, and no other module declares it.\n\
         //! NOT responsible for: the trait or anything shared, which are `crate::codec`.\n\
         //! Upstream: `cargo xtask codegen`. Downstream: `rustfs-gateway-core`.\n\n",
    );
    for ir in operations {
        let _ = writeln!(out, "mod {};", naming::module_name(&ir.operation));
    }
    out
}

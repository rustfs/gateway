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

//! Each XML request document's shape, as the RustFS profile reads it (rustfs/gateway#1078).
//!
//! Responsible for: rendering, into an operation's codec file, the `document` module whose static
//! `rustfs_gateway_xml::bound::Document` `rustfs_gateway_xml::bound::read` walks — the
//! document's roots and every structure it reaches, each member's element, arity, value kind and
//! requiredness — and the facts about legacy RustFS's reading that the model cannot state: which
//! structures skip an element they do not know, and the members legacy RustFS reads differently
//! from the model ([`OPTIONAL`], [`REQUIRED_ATTRIBUTES`], [`LEGACY_ONLY`]), and the
//! operations whose empty body legacy RustFS reads its own way ([`EMPTY_BODIES`]).
//! NOT responsible for: reading a document (the xml crate), the grammar of a value (the core
//! codec's scalar reading), MinIO's bare `Enabled` body (the decoder reads it as its document
//! before this shape sees the body, `value::body_literal`), or the tree reading every other
//! deployment uses.
//! Upstream: the IR. Downstream: the parent's `operation`, and the generated decoders' one call to
//! `crate::codec::request_document`.
//!
//! # Where the legacy facts come from, and what keeps them true
//!
//! From legacy RustFS's own reader, observed: a structure that is an operation's whole request
//! document skips an element it does not know, and every other structure refuses one; a member the
//! legacy stack has no field for is such an element. The tables below are the places the gateway
//! model and legacy RustFS disagree about members that the reading follows legacy RustFS in; the
//! one it does not follow is the Object Lock event hold, read so that the seam refuses it
//! (rd-put-0009). They are data rather than a derivation
//! so that they outlive the legacy stack's source; `rustfs-gateway-goldens`'
//! `request_documents` differential re-proves every one of them against the pinned legacy service,
//! and the tests beside this file pin the tables themselves.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rustfs_gateway_model::ir::{AttributeSource, Binding, Field, OperationIr, Shape, ShapeKind, TimestampFormat, Type};

use super::{carried_as_attribute, list_elements};

/// Members the model requires and legacy RustFS reads as optional. A document without one is
/// read; the generated decoder then refuses it, because the gateway's member cannot say "absent".
pub const OPTIONAL: &[(&str, &str)] = &[("Tag", "Key"), ("Tag", "Value"), ("CompletedPart", "PartNumber")];

/// Attribute members legacy RustFS requires where the model does not: a `Grantee` without a
/// literal `xsi:type` is refused.
pub const REQUIRED_ATTRIBUTES: &[(&str, &str)] = &[("Grantee", "Type")];

/// One member legacy RustFS reads that the model does not carry: read, validated, then left out
/// of the tree the decoder sees, as RustFS ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyOnly {
    /// The structure it belongs to.
    pub shape: &'static str,
    /// Its element.
    pub element: &'static str,
    /// The entry element, for a wrapped list.
    pub entry: Option<&'static str>,
    /// Its structure: a name in [`LEGACY_ONLY_SHAPES`].
    pub value: &'static str,
}

/// The members of [`LegacyOnly`]: `CreateBucketConfiguration`'s directory-bucket and tag members
/// of an AWS model revision the gateway model does not carry.
pub const LEGACY_ONLY: &[LegacyOnly] = &[
    LegacyOnly {
        shape: "CreateBucketConfiguration",
        element: "Location",
        entry: None,
        value: "LocationInfo",
    },
    LegacyOnly {
        shape: "CreateBucketConfiguration",
        element: "Bucket",
        entry: None,
        value: "BucketInfo",
    },
    LegacyOnly {
        shape: "CreateBucketConfiguration",
        element: "Tags",
        entry: Some("Tag"),
        value: "Tag",
    },
];

/// The structures [`LEGACY_ONLY`] reaches, each an unknown-refusing set of optional text members.
pub const LEGACY_ONLY_SHAPES: &[(&str, &[&str])] = &[
    ("LocationInfo", &["Name", "Type"]),
    ("BucketInfo", &["DataRedundancy", "Type"]),
    ("Tag", &["Key", "Value"]),
];

/// What an empty body is for the operations where legacy RustFS does not answer it as a missing
/// body, as `(operation, EmptyBody variant)`: a malformed document for the three its reader
/// refuses that way, and for the restore, whose document it reads as optional and whose handler
/// answers `MalformedXML` when handed none; an absent document for the object-lock configuration,
/// read as optional too, whose handler answers `InvalidArgument`. Every other document's empty
/// body is missing.
pub const EMPTY_BODIES: &[(&str, &str)] = &[
    ("CompleteMultipartUpload", "Refused"),
    ("PutObjectLegalHold", "Refused"),
    ("PutObjectLockConfiguration", "Absent"),
    ("PutObjectRetention", "Refused"),
    ("RestoreObject", "Refused"),
];

/// The structures that are some operation's whole request document: legacy RustFS skips an
/// unknown element inside these, wherever they appear, and refuses one everywhere else.
#[must_use]
pub fn payload_roots(operations: &[&OperationIr]) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    for ir in operations {
        for field in &ir.input {
            if field.binding == Binding::Payload
                && let Type::Structure(name) = &field.ty
            {
                roots.insert(name.clone());
            }
        }
    }
    roots
}

/// A structure the rendered document holds, by index.
enum Entry<'a> {
    /// The operation-level members of a document with no payload structure.
    Operation(Vec<&'a Field>),
    /// A structure of the model.
    Model(&'a str, &'a Shape),
    /// A structure only [`LEGACY_ONLY`] reaches.
    Legacy(&'static str, &'static [&'static str]),
}

struct Plan<'a> {
    entries: Vec<Entry<'a>>,
    index: BTreeMap<String, usize>,
}

impl<'a> Plan<'a> {
    fn shape(&mut self, ir: &'a OperationIr, name: &str) -> Result<usize, String> {
        if let Some(index) = self.index.get(name) {
            return Ok(*index);
        }
        let (key, shape) = ir
            .shapes
            .get_key_value(name)
            .ok_or_else(|| format!("document {}: shape `{name}` is not in the IR", ir.operation))?;
        let index = self.entries.len();
        self.index.insert(name.to_owned(), index);
        self.entries.push(Entry::Model(key, shape));
        Ok(index)
    }

    fn legacy(&mut self, name: &'static str) -> Result<usize, String> {
        let key = format!("legacy:{name}");
        if let Some(index) = self.index.get(&key) {
            return Ok(*index);
        }
        let members = LEGACY_ONLY_SHAPES
            .iter()
            .find(|(shape, _)| *shape == name)
            .map(|(_, members)| *members)
            .ok_or_else(|| format!("document: legacy-only structure `{name}` has no members recorded"))?;
        let index = self.entries.len();
        self.index.insert(key, index);
        self.entries.push(Entry::Legacy(name, members));
        Ok(index)
    }
}

fn scalar(ty: &Type, operation: &str, member: &str) -> Result<&'static str, String> {
    Ok(match ty {
        Type::String | Type::OpaqueString | Type::StringEnum(_) | Type::ObjectKey | Type::BucketName => "Text",
        Type::Integer => "Integer",
        Type::Long => "Long",
        Type::Boolean => "Boolean",
        Type::Timestamp(TimestampFormat::Iso8601) => "DateTime",
        Type::Timestamp(TimestampFormat::HttpDate) => "HttpDate",
        Type::ETag(_) => "EntityTag",
        _ => {
            return Err(format!(
                "document {operation}: member `{member}` has a type legacy RustFS's reading has no form for"
            ));
        }
    })
}

/// One member's `Member { .. }` literal.
///
/// Every member of the model is read, the Object Lock event hold of the 2026-09-17 model included,
/// though legacy RustFS knows none of it and skips it at a retention's root: the hold reaches the
/// seam, which refuses to hand RustFS a request naming it (rd-put-0009), rather than the document
/// being stored without a hold its client asked for.
fn member<'a>(ir: &'a OperationIr, plan: &mut Plan<'a>, owner: &str, field: &Field) -> Result<String, String> {
    let op = &ir.operation;
    let wire = field.wire_name.clone().unwrap_or_else(|| field.name.clone());
    let required = field.required && !OPTIONAL.contains(&(owner, field.name.as_str()));
    let (element, arity, value) = match &field.ty {
        Type::List {
            member: entry,
            flattened,
            member_name,
        } => {
            let names = list_elements(*flattened, member_name.as_deref(), &wire)?;
            let value = value(ir, plan, entry, &field.name)?;
            match names.wrapper {
                Some(wrapper) => (wrapper, format!("Arity::Wrapped({:?})", names.entry), value),
                None => (names.entry, "Arity::Repeated".to_owned(), value),
            }
        }
        other => (wire, "Arity::One".to_owned(), value(ir, plan, other, &field.name)?),
    };
    if element.is_empty() {
        return Err(format!("document {op}: member `{}` has no element name", field.name));
    }
    Ok(format!(
        "Member {{ element: {element:?}, arity: {arity}, value: {value}, required: {required}, kept: true }},"
    ))
}

fn value<'a>(ir: &'a OperationIr, plan: &mut Plan<'a>, ty: &Type, member: &str) -> Result<String, String> {
    match ty {
        Type::Structure(name) | Type::Union(name) => Ok(format!("Value::Shape({})", plan.shape(ir, name)?)),
        other => Ok(format!("Value::Text(Scalar::{})", scalar(other, &ir.operation, member)?)),
    }
}

/// The attribute literal of a structure that carries a member in one, resolved as the decoder
/// resolves it: the literal spelling, its local part, and the namespace the shape's own
/// `xmlns:` constant binds its prefix to.
fn attribute(ir: &OperationIr, name: &str, shape: &Shape) -> Result<String, String> {
    let Some(field) = shape.fields.iter().find(|field| carried_as_attribute(shape, &field.name)) else {
        return Ok("None".to_owned());
    };
    let key = super::attribute_name(shape, &field.name);
    let (prefix, local) = key
        .split_once(':')
        .ok_or_else(|| format!("document {}: attribute `{key}` of `{name}` has no prefix", ir.operation))?;
    let declaration = format!("xmlns:{prefix}");
    let namespace = shape
        .xml
        .attributes
        .iter()
        .find_map(|attribute| match &attribute.source {
            AttributeSource::Constant(value) if attribute.name == declaration => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| format!("document {}: `{name}` declares no `{declaration}` for `{key}`", ir.operation))?;
    let required = field.required || REQUIRED_ATTRIBUTES.contains(&(name, field.name.as_str()));
    Ok(format!(
        "Some(Attribute {{ key: {key:?}, name: {local:?}, namespace: {namespace:?}, required: {required} }})"
    ))
}

/// The `document` module of one operation's codec file, or `None` when it reads no XML document.
///
/// # Errors
///
/// A member whose type or shape the reading has no form for; failing is the point, as for every
/// other codec emitter.
pub fn module(ir: &OperationIr, payload_roots: &BTreeSet<String>) -> Result<Option<String>, String> {
    let payload = ir
        .input
        .iter()
        .find(|field| field.binding == Binding::Payload && matches!(field.ty, Type::Structure(_) | Type::Union(_)));
    let operation_members: Vec<&Field> = ir.input.iter().filter(|field| field.binding == Binding::BodyXml).collect();
    let mut plan = Plan {
        entries: Vec::new(),
        index: BTreeMap::new(),
    };
    let root_name = match payload {
        Some(field) => {
            let (Type::Structure(shape) | Type::Union(shape)) = &field.ty else {
                return Ok(None);
            };
            plan.shape(ir, shape)?;
            ir.xml
                .request_root
                .clone()
                .filter(|root| !root.is_empty())
                .unwrap_or_else(|| shape.clone())
        }
        None if !operation_members.is_empty() => {
            plan.entries.push(Entry::Operation(operation_members));
            ir.xml
                .request_root
                .clone()
                .filter(|root| !root.is_empty())
                .ok_or_else(|| format!("document {}: operation-level members and no request root", ir.operation))?
        }
        None => return Ok(None),
    };
    let mut roots = vec![root_name];
    roots.extend(ir.xml.request_root_aliases.iter().cloned());

    let mut rendered = Vec::new();
    let mut next = 0;
    while next < plan.entries.len() {
        let text = match &plan.entries[next] {
            Entry::Operation(fields) => {
                let fields = fields.clone();
                let mut members = String::new();
                for field in fields {
                    let line = member(ir, &mut plan, "", field)?;
                    let _ = writeln!(members, "            {line}");
                }
                format!(
                    "        Shape {{ name: {:?}, attribute: None, content: Content::Members {{ unknown: Unknown::Skip, members: &[\n{members}        ] }} }},\n",
                    ir.operation
                )
            }
            Entry::Model(name, shape) => {
                let (name, shape) = (*name, *shape);
                let mut members = String::new();
                for field in &shape.fields {
                    if carried_as_attribute(shape, &field.name) {
                        continue;
                    }
                    let line = member(ir, &mut plan, name, field)?;
                    let _ = writeln!(members, "            {line}");
                }
                for extra in LEGACY_ONLY.iter().filter(|extra| extra.shape == name) {
                    let index = plan.legacy(extra.value)?;
                    let arity = match extra.entry {
                        Some(entry) => format!("Arity::Wrapped({entry:?})"),
                        None => "Arity::One".to_owned(),
                    };
                    let _ = writeln!(
                        members,
                        "            Member {{ element: {:?}, arity: {arity}, value: Value::Shape({index}), required: false, kept: false }},",
                        extra.element
                    );
                }
                let attribute = attribute(ir, name, shape)?;
                if shape.kind == ShapeKind::Union {
                    format!(
                        "        Shape {{ name: {name:?}, attribute: {attribute}, content: Content::Choice(&[\n{members}        ]) }},\n"
                    )
                } else {
                    let unknown = if payload_roots.contains(name) { "Skip" } else { "Refuse" };
                    format!(
                        "        Shape {{ name: {name:?}, attribute: {attribute}, content: Content::Members {{ unknown: Unknown::{unknown}, members: &[\n{members}        ] }} }},\n"
                    )
                }
            }
            Entry::Legacy(name, members) => {
                let mut lines = String::new();
                for element in *members {
                    let _ = writeln!(
                        lines,
                        "            Member {{ element: {element:?}, arity: Arity::One, value: Value::Text(Scalar::Text), required: false, kept: true }},"
                    );
                }
                format!(
                    "        Shape {{ name: {name:?}, attribute: None, content: Content::Members {{ unknown: Unknown::Refuse, members: &[\n{lines}        ] }} }},\n"
                )
            }
        };
        rendered.push(text);
        next += 1;
    }

    let empty = EMPTY_BODIES
        .iter()
        .find(|(operation, _)| *operation == ir.operation)
        .map_or("Missing", |(_, empty)| *empty);
    let body = rendered.concat();
    let used = |needle: &str| body.contains(needle);
    let mut imports = vec!["Content", "Document", "EmptyBody", "Shape"];
    for (needle, name) in [
        ("Arity::", "Arity"),
        ("Attribute {", "Attribute"),
        ("Member {", "Member"),
        ("Scalar::", "Scalar"),
        ("Unknown::", "Unknown"),
        ("Value::", "Value"),
    ] {
        if used(needle) {
            imports.push(name);
        }
    }
    imports.sort_unstable();
    let roots = roots.iter().map(|root| format!("{root:?}")).collect::<Vec<_>>().join(", ");
    let mut out = String::new();
    out.push_str(
        "\n/// The request document's shape, as the RustFS profile reads it (`rustfs_gateway_xml::bound`,\n\
         /// rustfs/gateway#1078): its roots, every structure it reaches, and each member legacy\n\
         /// RustFS reads. Generated from the IR and the legacy facts in `emit::codec::document`.\n\
         #[rustfmt::skip]\n\
         mod document {\n",
    );
    let _ = writeln!(out, "    use rustfs_gateway_xml::bound::{{{}}};", imports.join(", "));
    out.push('\n');
    let _ = writeln!(
        out,
        "    pub(super) static DOCUMENT: Document = Document {{ roots: &[{roots}], empty: EmptyBody::{empty}, shapes: &["
    );
    out.push_str(&body);
    out.push_str("    ] };\n}\n");
    Ok(Some(out))
}

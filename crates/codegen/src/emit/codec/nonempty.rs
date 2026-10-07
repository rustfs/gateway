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

//! Required text constraints selected by field-level codec rules.
//!
//! Responsible for: emitting the tree reading's HTTP request refusal for explicitly bound nonempty
//! text members, and finding the nested reader shapes that need the deployment's document reading
//! to decide it. NOT responsible for: persisted XML or enum membership. Upstream: typed overlay
//! bindings. Downstream: the request shape reader emitter.
//!
//! # Why the refusal is the tree reading's alone
//!
//! The RustFS reading hands a member value to its handler exactly as legacy RustFS's decoder does,
//! and legacy RustFS's decoder hands an empty required `Status` over; its handlers then refuse it
//! with their own codes — `MalformedXML` for a lifecycle rule and `InvalidRequest` for every
//! replication position (`rustfs/src/app/bucket_usecase.rs:1272-1282`, `:688-704` at
//! rustfs/rustfs@95268a3b9). Refusing it in the decoder under that reading would answer a
//! replication write `MalformedXML` where legacy RustFS answers `InvalidRequest`.

use std::collections::BTreeSet;

use rustfs_gateway_model::CodecValue;
use rustfs_gateway_model::ir::{Field, OperationIr, Type};

use super::CodecRules;

/// The generated reader argument that carries the deployment's document reading.
pub(super) const READING: &str = "reading";

/// The expression an operation's top-level decoder passes for [`READING`].
pub(super) const REQUEST_READING: &str = "request.document_reading()";

/// Whether a member carries an active nonempty-text rule, or an error for a binding no reader
/// can enforce.
fn rejects_empty(field: &Field, rules: &CodecRules) -> Result<bool, String> {
    let mut found = None;
    for id in &field.quirk_refs {
        let Some(rule) = rules.get(id) else { continue };
        let CodecValue::NonEmptyText(reject) = rule.current else { continue };
        if !field.required || !matches!(field.ty, Type::String | Type::StringEnum(_)) {
            return Err(format!("codec {}: `{id}` requires a required text member", field.name));
        }
        if found.is_some_and(|current| current != reject) {
            return Err(format!("codec {}: nonempty text rules disagree", field.name));
        }
        found = Some(reject);
    }
    Ok(found == Some(true))
}

/// Whether the reader of shape `name` needs the deployment's document reading: true exactly when
/// a member with an active nonempty-text rule is reachable from it.
pub(super) fn shape_needs_reading(ir: &OperationIr, name: &str, rules: &CodecRules) -> bool {
    type_needs_reading(ir, &Type::Structure(name.to_owned()), rules, &mut BTreeSet::new())
}

fn type_needs_reading(ir: &OperationIr, ty: &Type, rules: &CodecRules, visiting: &mut BTreeSet<String>) -> bool {
    match ty {
        Type::List { member, .. } => type_needs_reading(ir, member, rules, visiting),
        Type::Map { key, value } => {
            type_needs_reading(ir, key, rules, visiting) || type_needs_reading(ir, value, rules, visiting)
        }
        Type::Structure(name) | Type::Union(name) => {
            if !visiting.insert(name.clone()) {
                return false;
            }
            let result = ir.shapes.get(name).is_some_and(|shape| {
                shape.fields.iter().any(|field| {
                    // A binding no reader can enforce still threads the reading; `guard` then
                    // refuses to render it, so the error names the member rather than a caller.
                    rejects_empty(field, rules).unwrap_or(true) || type_needs_reading(ir, &field.ty, rules, visiting)
                })
            });
            visiting.remove(name);
            result
        }
        _ => false,
    }
}

/// Renders the refusal of an empty bound member under the tree reading; `reading` is the
/// expression holding the deployment's document reading in the calling reader.
pub(super) fn guard(field: &Field, rules: &CodecRules, reading: &str, indent: usize) -> Result<String, String> {
    if !rejects_empty(field, rules)? {
        return Ok(String::new());
    }
    let pad = " ".repeat(indent);
    Ok(format!(
        "{pad}if raw.is_empty() && {reading} == crate::codec::DocumentReading::Tree {{\n{pad}    return Err(CodecError::malformed_xml(\"a required text member is empty\").about(\"{}\"));\n{pad}}}\n",
        field.name
    ))
}

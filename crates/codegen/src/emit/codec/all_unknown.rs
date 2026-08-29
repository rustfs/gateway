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

//! Field-level protection against losing every child of a non-empty structure element.
//!
//! Responsible for: resolving the typed member rule and emitting a guard whose recognized names
//! come from the referenced IR shape. NOT responsible for: the operation-wide unknown-element
//! policy or semantic validation after decoding. Upstream: field quirk references and shape IR.
//! Downstream: the XML structure-member decoder.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Type};
use rustfs_gateway_model::{AllUnknownChildrenValue, CodecValue};

use super::{CodecRules, carried_as_attribute};

/// Emits the guard selected for one structure member.
pub fn guard(
    ir: &OperationIr,
    field: &Field,
    rules: &CodecRules,
    shape_name: &str,
    node: &str,
    indent: usize,
) -> Result<String, String> {
    let Some(policy) = of(field, rules, &ir.operation)? else {
        return Ok(String::new());
    };
    if policy == AllUnknownChildrenValue::Allow {
        return Ok(String::new());
    }
    let shape = ir.shapes.get(shape_name).ok_or_else(|| {
        format!(
            "codec {}.{}: all-unknown-children rule references missing shape `{shape_name}`",
            ir.operation, field.name
        )
    })?;
    let mut names = shape
        .fields
        .iter()
        .filter(|nested| !carried_as_attribute(shape, &nested.name))
        .map(|nested| nested.wire_name.as_deref().unwrap_or(&nested.name))
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return Err(format!(
            "codec {}.{}: all-unknown-children rule has no recognized child names",
            ir.operation, field.name
        ));
    }

    let pad = " ".repeat(indent);
    let inner = " ".repeat(indent.saturating_add(4));
    let mut out = String::new();
    let names = names.iter().map(|name| format!("{name:?}")).collect::<Vec<_>>().join(", ");
    let _ = writeln!(out, "{pad}let recognized = [{names}];");
    let _ = writeln!(
        out,
        "{pad}if !{node}.children.is_empty() && !{node}.children.iter().any(|nested| recognized.contains(&nested.name.as_str())) {{"
    );
    let _ = writeln!(
        out,
        "{inner}return Err(CodecError::malformed_xml(\"a non-empty structure contains no recognized child element\").about({:?}));",
        field.name
    );
    let _ = writeln!(out, "{pad}}}");
    Ok(out)
}

fn of(field: &Field, rules: &CodecRules, operation: &str) -> Result<Option<AllUnknownChildrenValue>, String> {
    let mut found = None;
    for id in &field.quirk_refs {
        let Some(rule) = rules.get(id) else {
            continue;
        };
        let CodecValue::AllUnknownChildren(policy) = rule.current else {
            continue;
        };
        if !matches!(field.ty, Type::Structure(_)) || !matches!(field.binding, Binding::BodyXml) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` requires a body-XML structure member",
                field.name
            ));
        }
        if found.is_some_and(|current| current != policy) {
            return Err(format!("codec {operation}.{}: all-unknown-children rules disagree", field.name));
        }
        found = Some(policy);
    }
    Ok(found)
}

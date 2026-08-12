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

//! Field-level boolean spelling selected by typed codec quirks.
//!
//! Responsible for: resolving one boolean field's accepted wire spelling from a typed rule.
//! NOT responsible for: parsing the value or selecting a field by free-text metadata. Upstream:
//! operation and field quirk references. Downstream: the scalar expression emitter.

use rustfs_gateway_model::ir::{Field, OperationIr, Type};
use rustfs_gateway_model::{BooleanSpellingValue, CodecValue};

use super::CodecRules;

/// The boolean spelling selected for one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanSpelling {
    /// ASCII-case-insensitive `true` and `false`.
    AsciiCaseInsensitive,
    /// Lower-case `true` and `false` only.
    LowercaseOnly,
}

/// Resolves the typed spelling rule for one field.
///
/// An operation-level boolean rule is accepted only when the operation has exactly one boolean
/// input across its top-level fields and nested shapes. That makes the attachment mechanical and
/// fails code generation if a later model revision makes the target ambiguous.
pub fn of(ir: &OperationIr, field: &Field, rules: &CodecRules) -> Result<Option<BooleanSpelling>, String> {
    let direct = field.quirk_refs.iter().filter_map(|id| rules.get(id));
    let operation = ir.quirks.iter().filter_map(|quirk| rules.get(&quirk.id));
    let mut found = None;
    for rule in direct.chain(operation) {
        let policy = match rule.current {
            CodecValue::BooleanSpelling(BooleanSpellingValue::AsciiCaseInsensitive) => BooleanSpelling::AsciiCaseInsensitive,
            CodecValue::BooleanSpelling(BooleanSpellingValue::LowercaseOnly) => BooleanSpelling::LowercaseOnly,
            _ => continue,
        };
        if !matches!(field.ty, Type::Boolean) {
            continue;
        }
        if found.is_some_and(|current| current != policy) {
            return Err(format!("codec {}.{}: boolean spelling rules disagree", ir.operation, field.name));
        }
        found = Some(policy);
    }
    if found.is_some() && boolean_field_count(ir) != 1 {
        return Err(format!(
            "codec {}: an operation-level boolean spelling rule requires exactly one boolean field",
            ir.operation
        ));
    }
    Ok(found)
}

fn boolean_field_count(ir: &OperationIr) -> usize {
    ir.input
        .iter()
        .chain(ir.shapes.values().flat_map(|shape| &shape.fields))
        .filter(|field| matches!(field.ty, Type::Boolean))
        .count()
}

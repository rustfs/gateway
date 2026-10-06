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
//! Responsible for: emitting HTTP request refusals for explicitly bound nonempty text members.
//! NOT responsible for: persisted XML or enum membership. Upstream: typed overlay bindings.
//! Downstream: the request shape reader emitter.

use rustfs_gateway_model::CodecValue;
use rustfs_gateway_model::ir::{Field, Type};

use super::CodecRules;

pub(super) fn guard(field: &Field, rules: &CodecRules, indent: usize) -> Result<String, String> {
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
    if found != Some(true) {
        return Ok(String::new());
    }
    let pad = " ".repeat(indent);
    Ok(format!(
        "{pad}if raw.is_empty() {{\n{pad}    return Err(CodecError::malformed_xml(\"a required text member is empty\").about(\"{}\"));\n{pad}}}\n",
        field.name
    ))
}

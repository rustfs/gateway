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

//! The `default_document` mutation source: a required structure whose absence reads as default.
//!
//! Responsible for: reading and writing the one field property the optionality mutation of a
//! required structure member targets, and saying which `required` sources that plan applies to.
//! NOT responsible for: deciding to use it (that is [`super::plan`]) or the decoder lines it
//! produces (that is [`crate::emit::reads_default_document`] and the codec emitter).
//! Upstream: the lowered IR. Downstream: [`crate::emit::quirk_toml`] and [`super::apply`].
//!
//! # Why this property exists
//!
//! Flipping a required structure to optional turns its dto member from `T` into `Option<T>`, so
//! every consumer that reads it bare stops compiling and the mutation run reports
//! `KILLED_BY_COMPILE` without consulting a case (rustfs/backlog#1726). The rule those members
//! carry is about the wire — an absent document is refused, not read as a defaulted one — so this
//! property writes that violation instead and leaves the member's type alone.

use rustfs_gateway_model::ir::{Field, OperationIr, Type};
use rustfs_gateway_model::json::Value;

use super::DEFAULT_DOCUMENT_PROPERTY;
use crate::emit::quirk_toml::{SourceValue, resolve_at};

/// Whether `path` is the `required` flag of an input or shape structure member that this
/// property can violate without retyping it.
///
/// An output member is excluded: nothing on this side decodes it, so defaulting its absence would
/// be a mutation no request could reach.
#[must_use]
pub(crate) fn applies(operations: &[OperationIr], path: &str) -> bool {
    let Some(member) = path.strip_suffix(".required") else {
        return false;
    };
    member.split('.').nth(1) != Some("output") && resolve_at(operations, &format!("{member}.{DEFAULT_DOCUMENT_PROPERTY}")).is_ok()
}

/// Reads whether a required structure member's absence currently reads as its default.
///
/// # Errors
///
/// Returns the reason when the member is not a required structure.
pub(crate) fn read(field: &Field, path: &str) -> Result<SourceValue, String> {
    require_structure(field, path)?;
    Ok(SourceValue::Bool(crate::emit::reads_default_document(field)))
}

/// Writes whether a required structure member's absence reads as its default.
///
/// # Errors
///
/// Returns the reason when the member is not a required structure or the value is not boolean.
pub(crate) fn write(field: &mut Field, value: &SourceValue, path: &str) -> Result<(), String> {
    require_structure(field, path)?;
    let SourceValue::Bool(defaulted) = value else {
        return Err(format!("mutation source `{path}` needs a boolean, not {value:?}"));
    };
    field.default = defaulted.then(|| Value::Object(Vec::new()));
    Ok(())
}

fn require_structure(field: &Field, path: &str) -> Result<(), String> {
    if field.required && matches!(field.ty, Type::Structure(_)) {
        return Ok(());
    }
    Err(format!(
        "mutation source `{path}` is not a required structure, so it has no default document"
    ))
}

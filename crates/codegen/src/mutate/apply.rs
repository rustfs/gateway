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

//! The writer for the lowered-IR mutation-source path grammar.
//!
//! Responsible for: writing one planned value at one source path in a lowered operation document,
//! having first checked that the value found there is the one the plan says it replaces.
//! NOT responsible for: choosing the value (that is [`super::plan`]) or rendering anything.
//! Upstream: [`super::Mutation`]. Downstream: [`crate::generate_mutated`].
//!
//! # Why the current value is re-checked here
//!
//! [`crate::emit::quirk_toml::resolve_at`] is the reader for this grammar and this is its
//! writer, so the two can drift: a path that reads one field and writes another produces a mutation
//! run in which every mutant survives, which reads exactly like a corpus with no coverage. Refusing
//! to write unless the value found is the value the plan recorded turns that drift into an error
//! naming the path, and [`crate::generate_mutated`] re-reads afterwards to prove the write landed.

use rustfs_gateway_model::ir::{ETagRender, EmptyValue, Field, OperationIr, TimestampFormat, Type};
use rustfs_gateway_model::json::Value;

use crate::emit::quirk_toml::{SourceValue, resolve_at};

use super::Mutation;

/// Writes one planned mutation into the lowered IR.
///
/// # Errors
///
/// Returns the reason when the path names nothing, when the value found is not the one the plan
/// replaces, or when the path shape has no writer.
pub fn apply(operations: &mut [OperationIr], mutation: &Mutation) -> Result<(), String> {
    let found = resolve_at(operations, &mutation.path)?;
    if found != mutation.from {
        return Err(format!(
            "source `{}` carries {found:?}, but the mutation plan replaces {:?}; the ledger and the \
             lowered IR disagree",
            mutation.path, mutation.from
        ));
    }
    write(operations, &mutation.path, &mutation.to)
}

fn write(operations: &mut [OperationIr], path: &str, value: &SourceValue) -> Result<(), String> {
    let parts: Vec<&str> = path.split('.').collect();
    let operation_name = parts.first().copied().ok_or_else(|| "empty mutation source".to_owned())?;
    let operation = operations
        .iter_mut()
        .find(|operation| operation.operation == operation_name)
        .ok_or_else(|| format!("mutation source `{path}` names unknown operation `{operation_name}`"))?;
    match parts.as_slice() {
        [_, "http", "success_status"] => {
            let wanted = int(value, path)?;
            operation.http.success_status =
                u16::try_from(wanted).map_err(|_| format!("mutation source `{path}` cannot hold status {wanted}"))?;
        }
        [_, "errors", "not_configured"] => operation.errors.not_configured = optional_text(value, path)?,
        [_, "checksum", "http_checksum_required"] => operation.checksum.http_checksum_required = boolean(value, path)?,
        [_, "xml", "element_order"] => operation.xml.element_order = text_list(value, path)?,
        [_, "xml", "unwrapped_output"] => operation.xml.unwrapped_output = boolean(value, path)?,
        [_, "xml", "url_encoded_fields"] => operation.xml.url_encoded_fields = text_list(value, path)?,
        [_, "xml", "response_root"] => operation.xml.response_root = Some(text(value, path)?),
        [_, "xml", "request_root"] => operation.xml.request_root = Some(text(value, path)?),
        [_, "xml", "empty_value", field] => {
            write_empty_value(&mut operation.xml.empty_value_policy, field, value, path)?;
        }
        [_, side @ ("input" | "output"), name, property] => {
            let fields = if *side == "input" {
                &mut operation.input
            } else {
                &mut operation.output
            };
            let field = fields
                .iter_mut()
                .find(|candidate| candidate.name == *name)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown field"))?;
            write_field(field, property, value, path)?;
        }
        [_, "shapes", shape, "xml", "element_order"] => {
            shape_mut(operation, shape, path)?.xml.element_order = text_list(value, path)?;
        }
        [_, "shapes", shape, "xml", "empty_value", field] => {
            let policy = &mut shape_mut(operation, shape, path)?.xml.empty_value_policy;
            write_empty_value(policy, field, value, path)?;
        }
        [_, "shapes", shape, "xml", "attributes", index, "name"] => {
            let index = index
                .parse::<usize>()
                .map_err(|_| format!("mutation source `{path}` has a non-integer attribute index"))?;
            shape_mut(operation, shape, path)?
                .xml
                .attributes
                .get_mut(index)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown attribute"))?
                .name = text(value, path)?;
        }
        [_, "shapes", shape, "fields", name, property] => {
            let field = shape_mut(operation, shape, path)?
                .fields
                .iter_mut()
                .find(|candidate| candidate.name == *name)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown field"))?;
            write_field(field, property, value, path)?;
        }
        _ => return Err(format!("mutation source `{path}` has an unsupported path shape")),
    }
    Ok(())
}

fn shape_mut<'a>(
    operation: &'a mut OperationIr,
    shape: &str,
    path: &str,
) -> Result<&'a mut rustfs_gateway_model::ir::Shape, String> {
    operation
        .shapes
        .get_mut(shape)
        .ok_or_else(|| format!("mutation source `{path}` names an unknown shape"))
}

fn write_empty_value(policy: &mut [(String, EmptyValue)], field: &str, value: &SourceValue, path: &str) -> Result<(), String> {
    let entry = policy
        .iter_mut()
        .find(|(name, _)| name == field)
        .ok_or_else(|| format!("mutation source `{path}` has no empty-value policy"))?;
    let spelling = text(value, path)?;
    entry.1 = EmptyValue::parse(&spelling)
        .ok_or_else(|| format!("mutation source `{path}` cannot hold empty-value policy `{spelling}`"))?;
    Ok(())
}

fn write_field(field: &mut Field, property: &str, value: &SourceValue, path: &str) -> Result<(), String> {
    match property {
        "required" => field.required = boolean(value, path)?,
        "wire_name" => field.wire_name = Some(text(value, path)?),
        "omit_when" => {
            // Only the drop direction is written: reconstructing an `OmitWhen` from its rendered
            // spelling would be a second grammar, and the mutation that matters is that the value
            // is now always written.
            if optional_text(value, path)?.is_some() {
                return Err(format!("mutation source `{path}` can only be mutated by dropping its condition"));
            }
            field.omit_when = None;
        }
        "default_document" => super::default_document::write(field, value, path)?,
        "default_int" => field.default = Some(Value::Int(int(value, path)?)),
        "default_string" => field.default = Some(Value::Str(text(value, path)?)),
        "etag_render" => {
            let spelling = text(value, path)?;
            let render = ETagRender::parse(&spelling)
                .ok_or_else(|| format!("mutation source `{path}` cannot hold entity-tag rendering `{spelling}`"))?;
            field.ty = Type::ETag(render);
        }
        "timestamp_format" => {
            let spelling = text(value, path)?;
            let format = TimestampFormat::parse(&spelling)
                .ok_or_else(|| format!("mutation source `{path}` cannot hold timestamp format `{spelling}`"))?;
            field.ty = Type::Timestamp(format);
        }
        "wire_type" => {
            let spelling = text(value, path)?;
            if spelling != "String" {
                return Err(format!("mutation source `{path}` cannot hold wire type `{spelling}`"));
            }
            field.ty = Type::String;
        }
        "list_flattened" => {
            let flattened = boolean(value, path)?;
            let Type::List {
                member, wrapper_name, ..
            } = &field.ty
            else {
                return Err(format!("mutation source `{path}` is not a list"));
            };
            // The IR stores the entry name in `wire_name` when flattened, but the wrapper name
            // there when wrapped, so a strategy flip has to move both names with the boolean.
            let entry_name = field.wire_name.clone().unwrap_or_else(|| field.name.clone());
            let (wire_name, wrapper_name) = if flattened {
                (Some(wrapper_name.clone().unwrap_or_else(|| "member".to_owned())), None)
            } else {
                (Some(field.name.clone()), Some(entry_name))
            };
            field.wire_name = wire_name;
            field.ty = Type::List {
                member: member.clone(),
                flattened,
                wrapper_name,
            };
        }
        other => return Err(format!("mutation source `{path}` names unsupported field property `{other}`")),
    }
    Ok(())
}

fn boolean(value: &SourceValue, path: &str) -> Result<bool, String> {
    match value {
        SourceValue::Bool(value) => Ok(*value),
        other => Err(format!("mutation source `{path}` needs a boolean, not {other:?}")),
    }
}

fn text(value: &SourceValue, path: &str) -> Result<String, String> {
    match value {
        SourceValue::Text(value) => Ok(value.clone()),
        other => Err(format!("mutation source `{path}` needs a string, not {other:?}")),
    }
}

fn optional_text(value: &SourceValue, path: &str) -> Result<Option<String>, String> {
    match value {
        SourceValue::OptionalText(value) => Ok(value.clone()),
        other => Err(format!("mutation source `{path}` needs an optional string, not {other:?}")),
    }
}

fn text_list(value: &SourceValue, path: &str) -> Result<Vec<String>, String> {
    match value {
        SourceValue::TextList(values) => Ok(values.clone()),
        other => Err(format!("mutation source `{path}` needs a string list, not {other:?}")),
    }
}

fn int(value: &SourceValue, path: &str) -> Result<i64, String> {
    match value {
        SourceValue::Int(value) => Ok(*value),
        other => Err(format!("mutation source `{path}` needs an integer, not {other:?}")),
    }
}

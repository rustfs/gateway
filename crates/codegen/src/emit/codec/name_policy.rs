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

//! Deployment name-policy threading for generated XML input readers.
//!
//! Responsible for: finding nested input shapes that contain an `ObjectKey`, then rendering the
//! extra reader argument and matching function signature. NOT responsible for: decoding or
//! validating the key; generated readers delegate that to `rustfs-gateway-core`.
//! Upstream: the operation IR. Downstream: the request decoder emitter.

use std::collections::BTreeSet;

use rustfs_gateway_model::ir::{OperationIr, Type};

use super::expr;
use crate::emit::dto::naming;

fn shape_needs_name_policy(ir: &OperationIr, name: &str) -> bool {
    type_needs_name_policy(ir, &Type::Structure(name.to_owned()), &mut BTreeSet::new())
}

fn type_needs_name_policy(ir: &OperationIr, ty: &Type, visiting: &mut BTreeSet<String>) -> bool {
    match ty {
        Type::ObjectKey => true,
        Type::List { member, .. } => type_needs_name_policy(ir, member, visiting),
        Type::Map { key, value } => type_needs_name_policy(ir, key, visiting) || type_needs_name_policy(ir, value, visiting),
        Type::Structure(name) | Type::Union(name) => {
            if !visiting.insert(name.clone()) {
                return false;
            }
            let result = ir.shapes.get(name).is_some_and(|shape| {
                shape
                    .fields
                    .iter()
                    .any(|field| type_needs_name_policy(ir, &field.ty, visiting))
            });
            visiting.remove(name);
            result
        }
        _ => false,
    }
}

pub(super) fn shape_reader_call(
    ir: &OperationIr,
    shape: &str,
    reader: &str,
    node: &str,
    name_policy: Option<&str>,
) -> Result<String, String> {
    if !shape_needs_name_policy(ir, shape) {
        return Ok(format!("{reader}({node})?"));
    }
    let names = name_policy
        .ok_or_else(|| expr::unsupported(&ir.operation, shape, "an object-key body reader has no deployment naming policy"))?;
    Ok(format!("{reader}({node}, {names})?"))
}

pub(super) fn shape_reader_signature(
    ir: &OperationIr,
    name: &str,
    node: &str,
    type_name: &str,
    max_width: usize,
) -> (String, bool) {
    let needs_names = shape_needs_name_policy(ir, name);
    let module = naming::module_name(name);
    let names = if needs_names {
        ", names: &rustfs_gateway_types::NamePolicy"
    } else {
        ""
    };
    let single =
        format!("fn read_{module}({node}: &rustfs_gateway_xml::XmlNode{names}) -> Result<dto::{type_name}, CodecError> {{\n");
    if single.trim_end().len() <= max_width {
        return (single, needs_names);
    }
    let names = if needs_names {
        "    names: &rustfs_gateway_types::NamePolicy,\n"
    } else {
        ""
    };
    (
        format!(
            "fn read_{module}(\n    {node}: &rustfs_gateway_xml::XmlNode,\n{names}) -> Result<dto::{type_name}, CodecError> {{\n"
        ),
        needs_names,
    )
}

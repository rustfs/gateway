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
//! extra reader arguments — the name policy, and the document reading a nonempty-text member needs
//! (`nonempty`) — and the matching function signature. NOT responsible for: decoding or
//! validating the key; generated readers delegate that to `rustfs-gateway-core`.
//! Upstream: the operation IR. Downstream: the request decoder emitter.

use std::collections::BTreeSet;

use rustfs_gateway_model::ir::{OperationIr, Type};

use super::{CodecRules, expr, nonempty};
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

/// The extra arguments a generated reader call may pass on, as expressions in the calling scope.
#[derive(Clone, Copy)]
pub(super) struct ReaderArgs<'a> {
    /// The deployment name policy, where the calling scope holds one.
    pub(super) names: Option<&'a str>,
    /// The deployment's document reading (`nonempty`).
    pub(super) reading: &'a str,
}

impl ReaderArgs<'static> {
    /// An operation's top-level decoder: both come from the request view.
    pub(super) const TOP: Self = Self {
        names: Some("request.names()"),
        reading: nonempty::REQUEST_READING,
    };

    /// Inside a nested reader: its own parameters.
    pub(super) fn nested(needs_names: bool) -> Self {
        Self {
            names: needs_names.then_some("names"),
            reading: nonempty::READING,
        }
    }
}

pub(super) fn shape_reader_call(
    ir: &OperationIr,
    rules: &CodecRules,
    shape: &str,
    reader: &str,
    node: &str,
    args: ReaderArgs<'_>,
) -> Result<String, String> {
    let mut arguments = node.to_owned();
    if shape_needs_name_policy(ir, shape) {
        let names = args.names.ok_or_else(|| {
            expr::unsupported(&ir.operation, shape, "an object-key body reader has no deployment naming policy")
        })?;
        arguments.push_str(", ");
        arguments.push_str(names);
    }
    if nonempty::shape_needs_reading(ir, shape, rules) {
        arguments.push_str(", ");
        arguments.push_str(args.reading);
    }
    Ok(format!("{reader}({arguments})?"))
}

/// Renders a nested shape reader's signature, and whether the reader takes the name policy.
///
/// A reader takes the deployment's document reading too when a member it reaches carries a
/// nonempty-text rule (`nonempty`), so the tree reading can refuse an empty one.
pub(super) fn shape_reader_signature(
    ir: &OperationIr,
    rules: &CodecRules,
    name: &str,
    node: &str,
    type_name: &str,
    max_width: usize,
) -> (String, bool) {
    let needs_names = shape_needs_name_policy(ir, name);
    let needs_reading = nonempty::shape_needs_reading(ir, name, rules);
    let module = naming::module_name(name);
    let mut parameters = vec![format!("{node}: &rustfs_gateway_xml::XmlNode")];
    if needs_names {
        parameters.push("names: &rustfs_gateway_types::NamePolicy".to_owned());
    }
    if needs_reading {
        parameters.push(format!("{}: crate::codec::DocumentReading", nonempty::READING));
    }
    let single = format!("fn read_{module}({}) -> Result<dto::{type_name}, CodecError> {{\n", parameters.join(", "));
    if single.trim_end().len() <= max_width {
        return (single, needs_names);
    }
    let parameters: String = parameters.iter().map(|parameter| format!("    {parameter},\n")).collect();
    (
        format!("fn read_{module}(\n{parameters}) -> Result<dto::{type_name}, CodecError> {{\n"),
        needs_names,
    )
}

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

//! Validated field carriers shared by the DTO, codec and migration seam emitters.
//!
//! Responsible for: checking carrier annotations against their lowered XML bindings.
//! NOT responsible for: defining the runtime carrier behavior.
//! Upstream: the typed model overlay and wire IR. Downstream: the DTO, codec, and seam emitters.

use std::collections::BTreeMap;

use rustfs_gateway_model::Overlay;
use rustfs_gateway_model::ir::{Binding, OperationIr, ShapeKind, Type};
use rustfs_gateway_model::overlay::FieldCarrier;

use super::codec::{Side, reachable_from};

#[derive(Debug, Default)]
pub(crate) struct Carriers(BTreeMap<String, BTreeMap<String, FieldCarrier>>);

impl Carriers {
    #[cfg(test)]
    pub(crate) const EMPTY: Self = Self(BTreeMap::new());
    pub(crate) fn collect(operations: &[OperationIr], overlay: &Overlay) -> Result<Self, String> {
        let mut carriers = Self::default();
        for (owner, shape) in &overlay.shapes {
            for field in &shape.fields {
                let Some(carrier) = field.carrier else { continue };
                let (shape_name, member, side) = match carrier {
                    FieldCarrier::DeleteObjectKey => ("ObjectIdentifier", "Key", Side::Input),
                    FieldCarrier::DeleteObjectETag => ("ObjectIdentifier", "ETag", Side::Input),
                    FieldCarrier::DeleteKeyEcho => ("Error", "Key", Side::Output),
                };
                if owner != shape_name || field.name != member {
                    return Err(format!(
                        "carrier {carrier:?} only applies to {shape_name}.{member}, found {owner}.{}",
                        field.name
                    ));
                }
                if shape.fields.iter().filter(|entry| entry.name == field.name).count() != 1 {
                    return Err(format!("carrier {owner}.{member}: duplicate field override"));
                }
                let required = carrier == FieldCarrier::DeleteObjectKey;
                let mut uses = operations.iter().filter(|ir| ir.shapes.contains_key(owner));
                let valid = field.ty.as_deref() == Some("String")
                    && uses.next().is_some_and(|ir| {
                        let shape = &ir.shapes[owner];
                        let other_side = match side {
                            Side::Input => Side::Output,
                            Side::Output => Side::Input,
                        };
                        ir.operation == "DeleteObjects"
                            && reachable_from(ir, owner, side)
                            && !reachable_from(ir, owner, other_side)
                            && shape.kind == ShapeKind::Structure
                            && shape.fields.iter().any(|field| {
                                field.name == member
                                    && field.ty == Type::String
                                    && field.binding == Binding::BodyXml
                                    && field.required == required
                                    && !super::codec::carried_as_attribute(shape, &field.name)
                            })
                    })
                    && uses.next().is_none();
                if !valid {
                    return Err(format!(
                        "carrier {owner}.{member}: expected a DeleteObjects XML text member with required={required}"
                    ));
                }
                carriers
                    .0
                    .entry(owner.clone())
                    .or_default()
                    .insert(field.name.clone(), carrier);
            }
        }
        if operations.iter().any(|ir| ir.operation == "DeleteObjects")
            && carriers.0.values().map(BTreeMap::len).sum::<usize>() != 3
        {
            return Err("DeleteObjects requires all three carrier declarations".to_owned());
        }
        Ok(carriers)
    }

    pub(super) fn get(&self, owner: &str, member: &str) -> Option<FieldCarrier> {
        self.0.get(owner)?.get(member).copied()
    }

    pub(super) fn reads_delete_objects(&self, ir: &OperationIr) -> bool {
        ir.operation == "DeleteObjects" && self.get("ObjectIdentifier", "ETag") == Some(FieldCarrier::DeleteObjectETag)
    }
}

pub(super) fn rust_type(carrier: FieldCarrier) -> &'static str {
    match carrier {
        FieldCarrier::DeleteObjectKey => "crate::dto::DeleteObjectKey",
        FieldCarrier::DeleteObjectETag => "crate::dto::DeleteObjectETag",
        FieldCarrier::DeleteKeyEcho => "crate::dto::DeleteKeyEcho",
    }
}

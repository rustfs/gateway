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

//! Nested-shape members the model does not state: synthesized fields on a model shape, synthesized
//! shapes with no model shape behind them, and a shape's declared XML attributes.
//!
//! Responsible for: lowering `[[shape.<Shape>.field]] synthesize = true` entries into IR fields at
//! their declared position, lowering a `[shape.<Shape>] synthesize = true` shape entirely from its
//! overlay, and resolving `[[shape.<Shape>.attribute]]` against the members a shape has. The one
//! use today is the MinIO bucket-configuration extensions RustFS reads (rustfs/backlog#1752).
//! NOT responsible for: model members (`super::Ctx::collect_shapes`), or operation-level synthesized
//! fields (`super::Ctx::synthesize`).
//! Upstream: `crate::overlay`. Downstream: the IR shapes table.

use std::collections::BTreeMap;

use super::{Ctx, body_members, default_of, empty_value_policy, omit_when_of, sort_quirk_ids};
use crate::error::{Error, Result};
use crate::ir::*;
use crate::overlay::{AttributeOverlay, FieldOverlay, ShapeOverlay};

impl Ctx<'_> {
    /// Appends a model shape's synthesized fields, each after its `after` member or at the end.
    pub(super) fn append_synthesized_fields(&self, ov: &ShapeOverlay, fields: &mut Vec<Field>) -> Result<()> {
        for fov in ov.fields.iter().filter(|fov| fov.synthesize) {
            let field = self.synthesized_field(fov)?;
            match &fov.after {
                Some(after) => {
                    let at = fields
                        .iter()
                        .position(|f| f.name == *after)
                        .ok_or_else(|| Error::ir(self.operation, format!("`after = \"{after}\"` names no field")))?;
                    fields.insert(at + 1, field);
                }
                None => fields.push(field),
            }
        }
        Ok(())
    }

    /// Lowers a shape the model does not have, from a `[shape.<Shape>] synthesize = true` entry.
    pub(super) fn collect_synthesized_shape(&mut self, name: &str, out: &mut BTreeMap<String, Shape>) -> Result<()> {
        let ov = self
            .overlay
            .shapes
            .get(name)
            .filter(|ov| ov.synthesize)
            .ok_or_else(|| Error::ir(self.operation, format!("unknown nested shape `{name}`")))?;
        if let Some(field) = ov.fields.iter().find(|fov| !fov.synthesize) {
            return Err(Error::ir(
                self.operation,
                format!("shape `{name}` is synthesized, so field `{}` must be too", field.name),
            ));
        }
        if !ov.drop.is_empty() || !ov.required.is_empty() || !ov.hot.is_empty() {
            return Err(Error::ir(
                self.operation,
                format!("shape `{name}` is synthesized: state requirement and hotness on its fields"),
            ));
        }
        let mut fields = Vec::new();
        self.append_synthesized_fields(ov, &mut fields)?;
        if fields.is_empty() {
            return Err(Error::ir(self.operation, format!("synthesized shape `{name}` has no fields")));
        }
        let xml = ShapeXml {
            element_order: if ov.element_order.is_empty() {
                body_members(&fields)
            } else {
                ov.element_order.clone()
            },
            empty_value_policy: empty_value_policy(&fields, &ov.empty_value),
            attributes: shape_attributes(self.operation, name, &ov.attributes, &fields)?,
        };
        let nested: Vec<Type> = fields.iter().map(|f| f.ty.clone()).collect();
        out.insert(
            name.to_owned(),
            Shape {
                kind: ShapeKind::Structure,
                fields,
                xml,
            },
        );
        for ty in &nested {
            self.collect_shapes(ty, out)?;
        }
        Ok(())
    }

    /// One synthesized body member of a nested shape.
    fn synthesized_field(&self, fov: &FieldOverlay) -> Result<Field> {
        let spelling = fov
            .ty
            .as_deref()
            .ok_or_else(|| Error::ir(self.operation, format!("synthesized field `{}` needs a type", fov.name)))?;
        let binding = Binding::BodyXml;
        Ok(Field {
            name: fov.name.clone(),
            wire_name: Some(fov.wire_name.clone().unwrap_or_else(|| fov.name.clone())),
            required: fov.required.unwrap_or(false),
            ty: self.synthesized_type(spelling, &binding)?,
            binding,
            hot: fov.hot.unwrap_or(false),
            default: default_of(fov),
            omit_when: omit_when_of(fov)?,
            missing_error: fov.missing_error.clone(),
            quirk_refs: sort_quirk_ids(fov.quirks.clone()),
        })
    }

    /// A scalar spelling, or one of the three composite spellings a synthesized member needs:
    /// `Structure:<Shape>`, `FlattenedList:<Shape>` (the element repeats under the member's wire
    /// name with no wrapper), and `StringEnum:<A>|<B>`.
    fn synthesized_type(&self, spelling: &str, binding: &Binding) -> Result<Type> {
        let empty = || Error::ir(self.operation, format!("`{spelling}` names nothing"));
        Ok(match spelling.split_once(':') {
            Some(("Structure", shape)) if !shape.is_empty() => Type::Structure(shape.to_owned()),
            Some(("FlattenedList", shape)) if !shape.is_empty() => Type::List {
                member: Box::new(Type::Structure(shape.to_owned())),
                flattened: true,
                member_name: None,
            },
            Some(("StringEnum", values)) => {
                let values: Vec<String> = values.split('|').map(str::to_owned).collect();
                if values.iter().any(String::is_empty) {
                    return Err(empty());
                }
                Type::StringEnum(values)
            }
            Some(("Structure" | "FlattenedList", _)) => return Err(empty()),
            _ => self.scalar(spelling, binding)?,
        })
    }
}

/// Resolves one shape's declared XML attributes against the members it actually has.
///
/// A field source that names no member is the failure this exists to catch: the attribute would
/// silently disappear from the wire and the discriminator with it, which is the shape of the
/// defect `aws-java-sdk` hit against the legacy stack. A member carried as an attribute must also be
/// optional — the reader this project ships strips attributes, so a required member the decoder
/// can never populate would refuse every well-formed request body.
pub(super) fn shape_attributes(
    operation: &str,
    shape: &str,
    declared: &[AttributeOverlay],
    fields: &[Field],
) -> Result<Vec<XmlAttribute>> {
    let mut out = Vec::new();
    for attribute in declared {
        let element = attribute.element.clone().unwrap_or_else(|| shape.to_owned());
        let source = match (&attribute.field, &attribute.value) {
            (Some(member), _) => {
                let Some(field) = fields.iter().find(|f| &f.name == member) else {
                    return Err(Error::ir(
                        operation,
                        format!(
                            "shape `{shape}`: attribute `{}` names member `{member}`, which it does not have",
                            attribute.name
                        ),
                    ));
                };
                if field.required {
                    return Err(Error::ir(
                        operation,
                        format!(
                            "shape `{shape}`: attribute `{}` carries required member `{member}`; the XML reader drops attributes, so a required source can never be decoded",
                            attribute.name
                        ),
                    ));
                }
                AttributeSource::Field(member.clone())
            }
            (None, Some(value)) => AttributeSource::Constant(value.clone()),
            (None, None) => {
                return Err(Error::ir(
                    operation,
                    format!("shape `{shape}`: attribute `{}` has no source", attribute.name),
                ));
            }
        };
        out.push(XmlAttribute {
            element,
            name: attribute.name.clone(),
            source,
        });
    }
    Ok(out)
}

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

//! Which response members `encoding-type=url` applies to.
//!
//! Responsible for: turning `xml.url_encoded_fields` — a list of dotted paths — into the two
//! questions the response emitter asks, "does this operation's root encode this member?" and "does
//! this shape's writer encode this member, and therefore need the decision passed in?", and the
//! one line that narrows the decision to a named member (`member_binding`).
//! NOT responsible for: emitting the calls ([`super::encode`]) or performing the encoding
//! (`rustfs-gateway-core`'s `codec::value::url_encoded` and `url_encoded_key`).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: [`super::encode`].
//!
//! # Why an unresolvable path fails the run
//!
//! The defect this module closes was not a wrong path — it was that `url_encoded_fields` was
//! parsed, written into `spec/operations/*.toml`, printed in `OPERATIONS.md`, and read by nothing.
//! The parameter was accepted and echoed while every key came back raw, which is the worst of the
//! three possible states: a client that reads the echo decodes values that were never encoded.
//!
//! So a path this module cannot resolve to a member is an error rather than a skip. An overlay
//! that names `Contents.Etag` for a member spelled `ETag` would otherwise re-create exactly the
//! silence, one member at a time.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway_model::ir::{Binding, OperationIr, Type};

use crate::emit::dto::naming;

/// The resolved answer for one operation.
#[derive(Debug, Default)]
pub struct Plan {
    /// Members of the response root that are encoded.
    root: BTreeSet<String>,
    /// Per nested shape, the members of that shape that are encoded.
    shapes: BTreeMap<String, BTreeSet<String>>,
    /// Generated predicates that detect a returned value which forces URL encoding.
    force_checks: Vec<String>,
}

impl Plan {
    /// Whether the operation encodes anything at all, and therefore needs the decision read from
    /// the request once at the top of `encode`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.is_empty() && self.shapes.is_empty()
    }

    /// Whether a member of the response root is encoded.
    #[must_use]
    pub fn encodes_root(&self, member: &str) -> bool {
        self.root.contains(member)
    }

    /// Whether a nested shape's writer encodes anything, and so takes the decision as an argument.
    #[must_use]
    pub fn encodes_shape(&self, shape: &str) -> bool {
        self.shapes.contains_key(shape)
    }

    /// Whether one member of a nested shape is encoded.
    #[must_use]
    pub fn encodes_shape_member(&self, shape: &str, member: &str) -> bool {
        self.shapes.get(shape).is_some_and(|members| members.contains(member))
    }

    /// The generated predicates that detect whether an encoded member forces URL encoding.
    pub fn force_checks(&self) -> impl Iterator<Item = &str> {
        self.force_checks.iter().map(String::as_str)
    }
}

/// The shape a response member's type reaches, when it reaches one.
fn nested_shape(ty: &Type) -> Option<&str> {
    match ty {
        Type::Structure(name) | Type::Union(name) => Some(name.as_str()),
        Type::List { member, .. } => nested_shape(member),
        _ => None,
    }
}

/// Resolves one operation's `xml.url_encoded_fields`.
///
/// A path is either `Member` — a member of the response root — or `Member.Child`, where `Member`
/// is a response-root member whose type reaches a nested shape and `Child` is a member of it. Two
/// segments is the whole grammar the overlays use; a deeper one is refused rather than guessed at,
/// because the emitter would have to invent how to thread the decision down to it.
///
/// # Errors
///
/// A string naming the operation and the path, for a path with more than two segments, a path
/// whose first segment is not a body member of the response, a path whose first segment reaches no
/// nested shape, or a path whose second segment is not a member of that shape.
pub fn plan(ir: &OperationIr) -> Result<Plan, String> {
    let mut plan = Plan::default();
    let op = &ir.operation;
    for path in &ir.xml.url_encoded_fields {
        let mut segments = path.split('.');
        let (Some(head), tail) = (segments.next(), segments.next()) else {
            return Err(unresolved(op, path, "it is empty"));
        };
        if segments.next().is_some() {
            return Err(unresolved(op, path, "it names more than two segments"));
        }
        let Some(field) = ir.output.iter().find(|f| f.name == head && f.binding == Binding::BodyXml) else {
            return Err(unresolved(op, path, "its first segment is not a body member of the response"));
        };
        let Some(child) = tail else {
            plan.force_checks.push(scalar_force_check(
                &format!("output.{}", naming::field_name(&field.name)),
                &field.ty,
                op,
                path,
            )?);
            plan.root.insert(head.to_owned());
            continue;
        };
        let Some(shape_name) = nested_shape(&field.ty) else {
            return Err(unresolved(op, path, "its first segment reaches no nested shape"));
        };
        let Some(shape) = ir.shapes.get(shape_name) else {
            return Err(unresolved(op, path, "the shape its first segment names is not in the IR"));
        };
        let Some(child_field) = shape.fields.iter().find(|f| f.name == child) else {
            return Err(unresolved(op, path, "its second segment is not a member of that shape"));
        };
        let root_source = format!("output.{}", naming::field_name(&field.name));
        let child_source = format!("item.{}", naming::field_name(&child_field.name));
        let child_check = scalar_force_check(&child_source, &child_field.ty, op, path)?;
        let force_check = match &field.ty {
            Type::List { .. } => format!(
                "value::any_requires_url_encoding(&{root_source}, |item| &item.{})",
                naming::field_name(&child_field.name)
            ),
            Type::Structure(_) if field.required => scalar_force_check(
                &format!("{root_source}.{}", naming::field_name(&child_field.name)),
                &child_field.ty,
                op,
                path,
            )?,
            Type::Structure(_) => format!("{root_source}.as_ref().is_some_and(|item| {child_check})"),
            _ => return Err(unresolved(op, path, "its first segment has no scannable nested value")),
        };
        plan.force_checks.push(force_check);
        plan.shapes.entry(shape_name.to_owned()).or_default().insert(child.to_owned());
    }
    Ok(plan)
}

/// Renders the runtime predicate for one scalar that can be percent-encoded.
fn scalar_force_check(source: &str, ty: &Type, operation: &str, path: &str) -> Result<String, String> {
    if !matches!(ty, Type::String | Type::OpaqueString | Type::ObjectKey) {
        return Err(unresolved(operation, path, "its final member is not string-shaped"));
    }
    Ok(format!("value::requires_url_encoding(&{source})"))
}

/// The one failure shape, so every version of it reads the same way.
fn unresolved(operation: &str, path: &str, why: &str) -> String {
    format!(
        "codec {operation}: `url_encoded_fields` names `{path}` and {why}. A path that resolves to \
         no member would leave `encoding-type=url` accepted, echoed, and not applied to it, which \
         is the state this list exists to end."
    )
}

/// The binding that narrows the response-wide url-encoding decision to the one member at `path` —
/// `Prefix` at the root, `Object.Key` inside a shape — so a profile can encode some declared
/// members and not others (the RustFS profile, rustfs/gateway#1059). Empty for a member the plan
/// does not encode. Under the AWS-model decisions `UrlEncoding::member` is the identity.
pub(super) fn member_binding(pad: &str, path: &str, encoded: bool) -> String {
    if encoded {
        format!("{pad}let url_encoding = url_encoding.member(\"{path}\");\n")
    } else {
        String::new()
    }
}

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

//! The shared type vocabulary the per-operation dto modules point at.
//!
//! Responsible for: collecting every nested shape and every string enumeration reachable from the
//! selected operations, merging the duplicates the IR necessarily produces (the same `Owner` shape
//! is reachable from a dozen operations), and mapping an IR [`Type`] onto a Rust type spelling.
//! NOT responsible for: rendering (that is [`super::render`]) or naming rules
//! ([`super::naming`]).
//! Upstream: [`s3gate_model::ir`]. Downstream: [`super::render`].
//!
//! # Why the IR forces a name-based registry
//!
//! `Type::StringEnum` carries its values but not the Smithy shape name behind them, so the only
//! name available is the member's. Two operations therefore reach the same enumeration under the
//! same member name with value lists in different orders, and the registry merges them by first
//! appearance. Nested structures do carry a name, so a genuine disagreement between two
//! operations about one shape's members is a hard failure instead of a merge.

use std::collections::{BTreeMap, BTreeSet};

use s3gate_model::ir::{Field, OperationIr, ShapeKind, Type};

use super::naming;

/// One string enumeration, merged across every operation that reaches it.
#[derive(Debug, Clone)]
pub struct EnumDef {
    /// Rust type name.
    pub name: String,
    /// Wire values, in first-seen order.
    pub values: Vec<String>,
    /// Operations that reach it.
    pub sources: BTreeSet<String>,
}

/// One nested structure or union, merged across every operation that reaches it.
#[derive(Debug, Clone)]
pub struct ShapeDef {
    /// Rust type name.
    pub name: String,
    /// Structure or union.
    pub kind: ShapeKind,
    /// Members, in model order.
    pub fields: Vec<Field>,
    /// Operations that reach it.
    pub sources: BTreeSet<String>,
}

/// Everything the per-operation modules refer to by name.
#[derive(Debug, Default)]
pub struct Registry {
    /// String enumerations, by Rust type name.
    pub enums: BTreeMap<String, EnumDef>,
    /// Nested shapes, by Rust type name.
    pub shapes: BTreeMap<String, ShapeDef>,
}

impl Registry {
    /// Walks every selected operation and collects the shared vocabulary.
    ///
    /// # Errors
    ///
    /// Fails when two operations disagree about one nested shape's members, which means the
    /// overlays have to say which spelling is right.
    pub fn collect(operations: &[&OperationIr]) -> Result<Self, String> {
        let mut registry = Registry::default();
        for ir in operations {
            for field in ir.input.iter().chain(ir.output.iter()) {
                registry.walk(&field.ty, &field.name, ir)?;
            }
        }
        Ok(registry)
    }

    fn walk(&mut self, ty: &Type, member: &str, ir: &OperationIr) -> Result<(), String> {
        match ty {
            Type::StringEnum(values) => self.add_enum(member, values, ir),
            Type::Structure(name) | Type::Union(name) => self.add_shape(name, ir),
            Type::List { member: inner, .. } => self.walk(inner, member, ir),
            Type::Map { key, value } => {
                self.walk(key, member, ir)?;
                self.walk(value, member, ir)
            }
            _ => Ok(()),
        }
    }

    fn add_enum(&mut self, member: &str, values: &[String], ir: &OperationIr) -> Result<(), String> {
        let name = naming::type_name(member);
        let entry = self.enums.entry(name.clone()).or_insert_with(|| EnumDef {
            name,
            values: Vec::new(),
            sources: BTreeSet::new(),
        });
        entry.sources.insert(ir.operation.clone());
        for value in values {
            if !entry.values.contains(value) {
                entry.values.push(value.clone());
            }
        }
        let mut seen: BTreeMap<String, &str> = BTreeMap::new();
        for value in &entry.values {
            let constant = naming::const_name(value);
            if let Some(previous) = seen.insert(constant.clone(), value) {
                return Err(format!(
                    "dto: enumeration `{}` maps both `{previous}` and `{value}` onto the constant `{constant}`; \
                     add an overlay entry that renames one of them",
                    entry.name
                ));
            }
        }
        Ok(())
    }

    fn add_shape(&mut self, ir_name: &str, ir: &OperationIr) -> Result<(), String> {
        let Some(shape) = ir.shapes.get(ir_name) else {
            return Err(format!(
                "dto: operation `{}` references shape `{ir_name}`, which the IR document does not carry",
                ir.operation
            ));
        };
        let name = naming::type_name(ir_name);
        if let Some(existing) = self.shapes.get_mut(&name) {
            if existing.kind != shape.kind || !same_members(&existing.fields, &shape.fields) {
                return Err(format!(
                    "dto: shape `{name}` has two different shapes across {:?} and `{}`; the overlays must \
                     reconcile them before it can be a single Rust type",
                    existing.sources, ir.operation
                ));
            }
            existing.sources.insert(ir.operation.clone());
        } else {
            self.shapes.insert(
                name.clone(),
                ShapeDef {
                    name,
                    kind: shape.kind,
                    fields: shape.fields.clone(),
                    sources: BTreeSet::from([ir.operation.clone()]),
                },
            );
        }
        // Cloned so the borrow on `self.shapes` ends before the recursive walk.
        let fields: Vec<Field> = shape.fields.clone();
        for field in &fields {
            self.walk(&field.ty, &field.name, ir)?;
        }
        Ok(())
    }

    /// Whether a value of this type needs no wrapper because it has a `Default` of its own.
    ///
    /// Only the two containers qualify. Every scalar in the vocabulary is a validated newtype
    /// whose empty value would be invalid on the wire, which is the whole reason the generated
    /// fields are `Option` rather than bare — see ADR-0004 P1 and P2.
    #[must_use]
    pub fn is_container(ty: &Type) -> bool {
        matches!(ty, Type::List { .. } | Type::Map { .. })
    }

    /// The Rust spelling of an IR type.
    ///
    /// Paths are absolute (`crate::…`) rather than relative, because the same spelling is written
    /// into files at three different module depths under `generated/dto/`.
    #[must_use]
    pub fn rust_type(ty: &Type) -> String {
        match ty {
            Type::String => "String".to_owned(),
            Type::OpaqueString => "crate::OpaqueString".to_owned(),
            Type::Integer => "i32".to_owned(),
            Type::Long => "i64".to_owned(),
            Type::Boolean => "bool".to_owned(),
            Type::Timestamp(_) => "crate::Timestamp".to_owned(),
            Type::ETag(_) => "crate::ETag".to_owned(),
            Type::Checksum(_) => "crate::ChecksumDigest".to_owned(),
            Type::ChecksumSpec => "crate::ChecksumSpec".to_owned(),
            Type::ObjectKey => "crate::ObjectKey".to_owned(),
            Type::BucketName => "crate::BucketName".to_owned(),
            Type::Range => "crate::ByteRange".to_owned(),
            Type::Blob { streaming: true } => "s3gate_stream::ByteStream".to_owned(),
            Type::Blob { streaming: false } => "bytes::Bytes".to_owned(),
            Type::StringEnum(_) => unreachable!("string enumerations are named by their member, use `field_type`"),
            Type::Structure(name) | Type::Union(name) => format!("crate::ops::shapes::{}", naming::type_name(name)),
            Type::List { member, .. } => format!("Vec<{}>", Self::rust_type(member)),
            Type::Map { key, value } => {
                format!("std::collections::BTreeMap<{}, {}>", Self::rust_type(key), Self::rust_type(value))
            }
        }
    }

    /// The Rust spelling of one field's type, wrapper included.
    ///
    /// Containers stay bare — an empty `Vec` and an absent list are the same fact on the wire —
    /// and everything else is `Option`, required or not. ADR-0004 P1 needs every Input and Output
    /// to be `Default`, and none of the scalars has a `Default` that would be valid on the wire.
    #[must_use]
    pub fn field_type(field: &Field) -> String {
        let inner = Self::type_with_enums(&field.ty, &field.name);
        if Self::is_container(&field.ty) {
            inner
        } else {
            format!("Option<{inner}>")
        }
    }

    /// [`Self::rust_type`], with the member name available so a string enumeration can be named.
    #[must_use]
    pub fn type_with_enums(ty: &Type, member: &str) -> String {
        match ty {
            Type::StringEnum(_) => format!("crate::ops::enums::{}", naming::type_name(member)),
            Type::List { member: inner, .. } => format!("Vec<{}>", Self::type_with_enums(inner, member)),
            Type::Map { key, value } => format!(
                "std::collections::BTreeMap<{}, {}>",
                Self::type_with_enums(key, member),
                Self::type_with_enums(value, member)
            ),
            other => Self::rust_type(other),
        }
    }

    /// Whether a value of this type can be cloned.
    ///
    /// A streaming body cannot, and neither can anything reaching one. `PutObjectInput` is the
    /// first instance; the answer has to be transitive because a nested shape may hold one.
    #[must_use]
    pub fn is_clonable(&self, ty: &Type) -> bool {
        match ty {
            Type::Blob { streaming: true } => false,
            Type::List { member, .. } => self.is_clonable(member),
            Type::Map { key, value } => self.is_clonable(key) && self.is_clonable(value),
            Type::Structure(name) | Type::Union(name) => self
                .shapes
                .get(&naming::type_name(name))
                .is_none_or(|shape| shape.fields.iter().all(|f| self.is_clonable(&f.ty))),
            _ => true,
        }
    }
}

fn same_members(left: &[Field], right: &[Field]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.name == b.name && a.ty == b.ty)
}

/// Wire names whose value must never reach a log line, and therefore never a `Debug` output.
///
/// AGENTS.md forbids credentials and SSE-C key material in logs. A derived `Debug` on a struct
/// carrying one of these fields would put the secret one `{:?}` away from a log file, so the
/// emitter writes the `Debug` implementation by hand for those structs instead.
pub const REDACTED_WIRE_NAMES: &[&str] = &[
    "x-amz-server-side-encryption-customer-key",
    "x-amz-copy-source-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-context",
];

/// Whether a field's value is secret enough that `Debug` must not print it.
#[must_use]
pub fn is_redacted(field: &Field) -> bool {
    field
        .wire_name
        .as_deref()
        .is_some_and(|wire| REDACTED_WIRE_NAMES.contains(&wire))
}

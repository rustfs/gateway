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

//! Which integer bindings are bounded, and by what.
//!
//! Responsible for: resolving one field's inclusive integer range from the quirks it references.
//! NOT responsible for: emitting the check ([`super::decode`] does, through [`super::expr`]) or
//! performing it (`rustfs-gateway-core`'s `codec::value::integer_in_range` does).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: [`super::expr`].
//!
//! # Why the two numbers are here and not in the IR
//!
//! Because the IR cannot hold them. `spec/ir.schema.json` is frozen: `Type::Integer` carries no
//! range, `field` has no `min`/`max`, and the overlay reader has no key that could supply either.
//! A part number above ten thousand and a page size above a thousand are protocol refusals AWS
//! makes and the pinned Smithy model does not state, so today there is nowhere in the generated
//! IR to put them.
//!
//! What is data, and what is not:
//!
//! * **data** — *which* fields are bounded and the two inclusive bounds. The overlay attaches a
//!   typed codec rule to a field, and every field carrying it is bounded.
//! * **not data** — the range-checker implementation.
//!
//! That is the seam this module is: the smallest surface that keeps the branch out of the
//! handlers and out of the generated files, and the thing to delete the day the IR can express a
//! range. A typed range attached to a field that is not an integer fails the run. Free-text quirk
//! metadata is never consulted here.

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{Field, Type};
use rustfs_gateway_model::{CodecRule, CodecValue};

/// One inclusive integer range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    /// Smallest accepted value.
    pub min: i32,
    /// Largest accepted value.
    pub max: i32,
}

/// The range one field's quirks declare, if any.
///
/// # Errors
///
/// A string naming the operation and member when a typed range is attached to a field whose type
/// is not an integer, or when two typed range rules disagree on one member.
pub fn of(field: &Field, rules: &BTreeMap<String, CodecRule>, operation: &str) -> Result<Option<Bound>, String> {
    let mut found: Option<Bound> = None;
    for id in &field.quirk_refs {
        let Some(rule) = rules.get(id) else {
            continue;
        };
        let bound = match &rule.current {
            CodecValue::IntegerRange { min, max } => Bound { min: *min, max: *max },
            _ => continue,
        };
        if !matches!(scalar_of(&field.ty), Type::Integer) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` bounds an integer, and this member is not one.",
                field.name
            ));
        }
        if found.is_some_and(|existing| existing != bound) {
            return Err(format!(
                "codec {operation}.{}: two typed codec rules claim different ranges; one member has one range.",
                field.name
            ));
        }
        found = Some(bound);
    }
    Ok(found)
}

/// The scalar a field ultimately reads, looking through a list.
///
/// A list of bounded integers is bounded element by element — the range belongs to the value, not
/// to the container — so the type check has to see past the container or it would refuse the one
/// shape that needs it most.
fn scalar_of(ty: &Type) -> &Type {
    match ty {
        Type::List { member, .. } => scalar_of(member),
        other => other,
    }
}

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
//! * **data** — *which* fields are bounded. The overlay attaches a `bounded_range` quirk to a
//!   field, and every field carrying it is bounded, in every operation and every nested shape.
//!   Adding `CompletedPart.PartNumber` to the set is an overlay edit and nothing else.
//! * **not data** — the two numbers, which are the table below.
//!
//! That is the seam this module is: the smallest surface that keeps the branch out of the
//! handlers and out of the generated files, and the thing to delete the day the IR can express a
//! range. Two guards keep the table honest: a `bounded_range` quirk with no entry here fails the
//! run, and so does one attached to a field that is not an integer. Neither can be reached by a
//! silent drop.

use rustfs_gateway_model::ir::{Field, Quirk, Type};

/// The quirk category that marks a field as carrying an inclusive integer range.
pub const BOUNDED_KIND: &str = "bounded_range";

/// One inclusive integer range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    /// Smallest accepted value.
    pub min: i32,
    /// Largest accepted value.
    pub max: i32,
}

/// The ranges, by the quirk id that carries each one.
///
/// One row per quirk, never per field: `cargo xtask why <id>` resolves the row to its evidence and
/// to the conformance cases that would fail if it moved.
const RANGES: &[(&str, Bound)] = &[
    // Part numbers run from one to ten thousand inclusive. A part above the ceiling can never be
    // completed and no abort enumerates it, so accepting one stores bytes nobody reclaims.
    ("q-part-number-0072", Bound { min: 1, max: 10_000 }),
    // A listing page holds at most a thousand keys, and asking for none is a legitimate probe.
    ("q-max-keys-0073", Bound { min: 0, max: 1_000 }),
];

/// The range one field's quirks declare, if any.
///
/// # Errors
///
/// A string naming the operation and member when a `bounded_range` quirk has no row in `RANGES`,
/// or when one is attached to a field whose type is not an integer. Both are overlay mistakes that
/// would otherwise disable a refusal silently, which is the failure mode a hand-written file can
/// least afford.
pub fn of(field: &Field, quirks: &[Quirk], operation: &str) -> Result<Option<Bound>, String> {
    let mut found: Option<Bound> = None;
    for id in &field.quirk_refs {
        let Some(quirk) = quirks.iter().find(|q| &q.id == id) else {
            continue;
        };
        if quirk.kind != BOUNDED_KIND {
            continue;
        }
        let Some((_, bound)) = RANGES.iter().find(|(known, _)| known == id) else {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` is a `{BOUNDED_KIND}` with no range in \
                 `crates/codegen/src/emit/codec/bounds.rs`. Add the row rather than letting the \
                 quirk claim a refusal nothing performs.",
                field.name
            ));
        };
        if !matches!(scalar_of(&field.ty), Type::Integer) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` bounds an integer, and this member is not one.",
                field.name
            ));
        }
        if found.is_some_and(|existing| existing != *bound) {
            return Err(format!(
                "codec {operation}.{}: two `{BOUNDED_KIND}` quirks claim different ranges; one member has one range.",
                field.name
            ));
        }
        found = Some(*bound);
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

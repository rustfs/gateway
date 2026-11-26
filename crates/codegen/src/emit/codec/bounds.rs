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

/// One inclusive numeric range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// Inclusive 32-bit range, with an optional `ErrorCode::*` constant for out-of-range refusal.
    Int {
        /// Smallest accepted value.
        min: i32,
        /// Largest accepted value.
        max: i32,
        /// Error code constant when out-of-range uses a code other than `InvalidArgument`.
        code: Option<&'static str>,
    },
    /// Inclusive 32-bit range enforced under `DocumentReading::Tree` (deferred to legacy RustFS
    /// handlers under `DocumentReading::RustFs`).
    TreeInt {
        /// Smallest accepted value.
        min: i32,
        /// Largest accepted value.
        max: i32,
    },
    /// Inclusive 64-bit range.
    Long {
        /// Smallest accepted value.
        min: i64,
        /// Largest accepted value.
        max: i64,
    },
}

impl Bound {
    /// Inclusive 32-bit range using the default `InvalidArgument` refusal.
    #[must_use]
    pub const fn int(min: i32, max: i32) -> Self {
        Self::Int { min, max, code: None }
    }
}

/// The range one field's quirks or protocol contract declare, if any.
///
/// Typed codec rules in `rules` are consulted first so mutation tests over `q-part-number-0072`
/// and `q-max-keys-0073` control their exact members. Members without a typed codec rule fall back
/// to `protocol_bound`, which carries the remaining AWS S3 integer and long boundaries.
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
            CodecValue::IntegerRange { min, max } => Bound::int(*min, *max),
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
    if found.is_some() {
        return Ok(found);
    }
    Ok(protocol_bound(operation, field))
}

/// Whether `field` carries a `TreeInt` range check that needs `DocumentReading` threaded into its
/// enclosing XML reader.
#[must_use]
pub(super) fn uses_tree_reading(operation: &str, field: &Field) -> bool {
    matches!(protocol_bound(operation, field), Some(Bound::TreeInt { .. }))
}

/// Protocol ranges for bounded S3 integer/long members not already governed by a typed codec rule.
///
/// Intentionally excludes `UploadPart.PartNumber` (`q-part-number-0072`) and
/// `ListObjectsV2.MaxKeys` (`q-max-keys-0073`) so mutating either rule removes its bound.
fn protocol_bound(operation: &str, field: &Field) -> Option<Bound> {
    match (operation, field.name.as_str(), scalar_of(&field.ty)) {
        ("UploadPartCopy", "PartNumber", Type::Integer) => Some(Bound::int(1, 10_000)),
        // Under `DocumentReading::Tree` (standard AWS mode), out-of-range part numbers are refused
        // at decode; under `DocumentReading::RustFs`, legacy RustFS handlers enforce bucket
        // existence first and return `InvalidPart` ("Part number N must be between 1 and 10000").
        ("CompleteMultipartUpload", "PartNumber", Type::Integer) => Some(Bound::TreeInt { min: 1, max: 10_000 }),
        ("GetObject" | "HeadObject", "PartNumber", Type::Integer) => Some(Bound::Int {
            min: 1,
            max: 10_000,
            code: Some("INVALID_PART_NUMBER"),
        }),
        ("ListObjects" | "ListObjectVersions", "MaxKeys", Type::Integer) => Some(Bound::int(0, 1_000)),
        ("ListMultipartUploads", "MaxUploads", Type::Integer) => Some(Bound::int(1, 1_000)),
        // `c-mpu-0048` / `q-mpu-marker-0040`: `max-parts > 1000` is capped to 1000 by the handler,
        // while negative values are refused at decode.
        ("ListParts", "MaxParts", Type::Integer) => Some(Bound::int(0, i32::MAX)),
        ("ListBuckets", "MaxBuckets", Type::Integer) => Some(Bound::int(1, 10_000)),
        ("ListDirectoryBuckets", "MaxDirectoryBuckets", Type::Integer) => Some(Bound::int(1, 1_000)),
        ("PutObject", "WriteOffsetBytes", Type::Long)
        | ("CompleteMultipartUpload", "MpuObjectSize", Type::Long)
        | ("DeleteObject", "IfMatchSize", Type::Long) => Some(Bound::Long { min: 0, max: i64::MAX }),
        _ => None,
    }
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

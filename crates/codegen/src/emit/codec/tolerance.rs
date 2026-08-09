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

//! Which bindings are read tolerantly — a value the specification says to *ignore* rather than
//! refuse.
//!
//! Responsible for: resolving one field's tolerance from the quirks it references.
//! NOT responsible for: emitting the read ([`super::decode`] does) or performing it
//! (`rustfs-gateway-core`'s `codec::value::date_condition` does).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: [`super::decode`].
//!
//! # The third twin, and why it is not a decoder feature
//!
//! [`super::bounds`] and [`super::forms`] are the same shape as this module: the frozen IR cannot
//! say "this integer has a range" or "this string has a grammar", so *which* members carry the
//! rule is overlay data and the rule itself is a table here.
//!
//! This one exists for a rule the decoder is structurally unable to express. A decoder may say
//! "this is not the document" and nothing else — `MalformedXML` is the only code the parser owns,
//! and `CodecError` has no parameter that could carry a second one. A header the specification
//! says to **ignore** is not a decode failure at all: nothing about the document is wrong, and the
//! correct outcome is a `200` carrying the object. Expressing it as an error and then catching the
//! error somewhere would put a refusal on a path whose answer is a success.
//!
//! So it is expressed the only way that survives review: the binding reads the header into a value
//! that has a variant for "arrived and could not be read", and the collapse to the stored
//! `Option` is one named call. See `rustfs_gateway_core::codec::value::DateCondition` for why the
//! collapse is correct for a date condition and was the `if-range` defect for a range.
//!
//! Two guards keep the table honest: a `header_tolerance` quirk with no row here fails the run,
//! and so does one attached to a member whose type or binding the tolerance has no reading for.
//! Neither can be reached by a silent drop — which matters more here than in the twins, because
//! the failure mode of a *missing* tolerance is a refusal the RFC forbids, and it looks exactly
//! like ordinary strictness.

use rustfs_gateway_model::ir::{Binding, Field, Quirk, Type};

/// The quirk category that marks a binding as read tolerantly.
pub const TOLERANCE_KIND: &str = "header_tolerance";

/// One way of reading a value the specification says to ignore rather than refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tolerance {
    /// A modification-date condition: RFC 9110 §13.1.3 and §13.1.4 require a value that is not a
    /// valid HTTP-date to be ignored, and the request served as though it had not been sent.
    DateCondition,
}

impl Tolerance {
    /// Whether this reading has a meaning for the type and binding the member carries.
    fn accepts(self, ty: &Type, binding: &Binding) -> bool {
        match self {
            // A date condition is a timestamp read from a header. A query-bound or body-bound
            // timestamp is not a conditional header and has no RFC rule saying to ignore it.
            Self::DateCondition => matches!(ty, Type::Timestamp(_)) && matches!(binding, Binding::Header),
        }
    }

    /// The `crate::codec::value` call that reads `raw` into the value the member stores.
    ///
    /// The result is already the stored `Option`, so [`super::decode`] must not wrap it again —
    /// which is the whole distinction this reading carries: absence is spelled by the `if let` the
    /// binding is inside, and `honoured()` is the one place a dropped condition joins it.
    pub fn call(self, ty: &Type) -> Option<String> {
        match self {
            Self::DateCondition => {
                let Type::Timestamp(format) = ty else {
                    return None;
                };
                Some(format!(
                    "value::date_condition(raw, TimestampFormat::{}).honoured()",
                    super::expr::timestamp_format(*format)
                ))
            }
        }
    }

    /// The shape this reading expects, for the failure that names a mismatch.
    fn expects(self) -> &'static str {
        match self {
            Self::DateCondition => "a header-bound timestamp",
        }
    }
}

/// The tolerances, by the quirk id that carries each one.
///
/// One row per quirk, never per field: `cargo xtask why <id>` resolves the row to its evidence and
/// to the conformance cases that would fail if it moved.
const TOLERANCES: &[(&str, Tolerance)] = &[
    // A date condition that is not an HTTP-date is ignored and the object is served. Refusing it
    // answers 400 for a header that carries no requirement once it cannot be read, and the client
    // never learns its date format is the problem.
    ("q-cond-0050", Tolerance::DateCondition),
];

/// The tolerance one field's quirks declare, if any.
///
/// # Errors
///
/// A string naming the operation and member when a `header_tolerance` quirk has no row in
/// `TOLERANCES`, when one is attached to a member whose type or binding the reading has no form
/// for, or when two of them claim different readings for one member. All three are overlay
/// mistakes that would otherwise leave a member strict where the specification requires tolerance
/// — a failure indistinguishable, from the outside, from a decoder simply doing its job.
pub fn of(field: &Field, quirks: &[Quirk], operation: &str) -> Result<Option<Tolerance>, String> {
    let mut found: Option<Tolerance> = None;
    for id in &field.quirk_refs {
        let Some(quirk) = quirks.iter().find(|q| &q.id == id) else {
            continue;
        };
        if quirk.kind != TOLERANCE_KIND {
            continue;
        }
        let Some((_, tolerance)) = TOLERANCES.iter().find(|(known, _)| known == id) else {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` is a `{TOLERANCE_KIND}` with no reading in \
                 `crates/codegen/src/emit/codec/tolerance.rs`. Add the row rather than letting the \
                 quirk claim a tolerance nothing performs.",
                field.name
            ));
        };
        if !tolerance.accepts(&field.ty, &field.binding) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` reads {}, and this member is not one.",
                field.name,
                tolerance.expects()
            ));
        }
        if found.is_some_and(|existing| existing != *tolerance) {
            return Err(format!(
                "codec {operation}.{}: two `{TOLERANCE_KIND}` quirks claim different readings; one member has one.",
                field.name
            ));
        }
        found = Some(*tolerance);
    }
    Ok(found)
}

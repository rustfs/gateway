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

//! Which string bindings have a wire form stricter than the type they are stored in.
//!
//! Responsible for: resolving one field's wire form from the quirks it references.
//! NOT responsible for: emitting the check ([`super::decode`] does, through [`super::expr`]) or
//! performing it (`rustfs-gateway-core`'s `codec::value::etag_form` and
//! `codec::value::opaque_token` do).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: [`super::expr`].
//!
//! # Why this is the twin of [`super::bounds`] and not something new
//!
//! Same shape of problem, same seam. `spec/ir.schema.json` is frozen: `Type::String` and
//! `Type::OpaqueString` carry no grammar, `field` has no `pattern`, and the overlay reader has no
//! key that could supply one. "This header is spelled as an RFC 9110 entity tag" and "this query
//! value is a token this service minted" are protocol refusals AWS makes and the pinned Smithy
//! model does not state, so today there is nowhere in the generated IR to put them.
//!
//! What is data, and what is not:
//!
//! * **data** — *which* members carry a stricter wire form. The overlay attaches a `wire_form`
//!   quirk to a field, and every field carrying it is checked, in every operation. Adding
//!   `CopyObject.CopySourceIfMatch` to the set is an overlay edit and nothing else.
//! * **not data** — the grammar behind each form, which is the table below plus the two functions
//!   it names.
//!
//! # Why the type does not change instead
//!
//! Because the refusal and the storage are different questions, and answering both with one type
//! answers the second one badly. Moving `IfMatch` to `Type::ETag` would refuse the malformed tag
//! *and* hand every reader of that member a parsed `ETag` where a string used to be — a rewrite of
//! consumers this workspace does not need in order to stop accepting a broken value. The form is
//! the narrow half: it validates and hands the value back as it arrived.
//!
//! Two guards keep the table honest: a `wire_form` quirk with no entry here fails the run, and so
//! does one attached to a member whose type the form has no grammar for. Neither can be reached by
//! a silent drop.

use rustfs_gateway_model::ir::{Field, Quirk, Type};

/// The quirk category that marks a member as carrying a wire form stricter than its type.
pub const FORM_KIND: &str = "wire_form";

/// One wire grammar a string-typed member is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// An RFC 9110 entity tag: `"v"`, `W/"v"`, a bare `v`, or `*`.
    EntityTag,
    /// A token this service minted and handed to the caller in an earlier response.
    OpaqueToken,
}

impl Form {
    /// Whether this grammar has a meaning for the type the member is stored in.
    fn accepts(self, ty: &Type) -> bool {
        match self {
            // An entity tag arrives as a header string and stays one; the parse is the check.
            Self::EntityTag => matches!(ty, Type::String),
            // A cursor is round-tripped byte for byte, which is what `OpaqueString` says — but the
            // model spells several of them as plain strings, and the same value is the same wire
            // contract in both. A grammar that accepted only one of the two would enforce it on
            // `ListObjectsV2` and not on `ListMultipartUploads`.
            Self::OpaqueToken => matches!(ty, Type::String | Type::OpaqueString),
        }
    }

    /// The `crate::codec::value` call that performs this refusal on `raw` and produces the value
    /// the member stores.
    ///
    /// Every checker returns the validated `&str`, so the storage is composed here rather than
    /// duplicated as one checker per storage type.
    pub fn call(self, member: &str, ty: &Type) -> String {
        let checked = match self {
            Self::EntityTag => format!("value::etag_form(raw, \"{member}\")?"),
            Self::OpaqueToken => format!("value::token_form(raw, \"{member}\")?"),
        };
        match ty {
            Type::OpaqueString => format!("value::opaque({checked})"),
            _ => format!("{checked}.to_owned()"),
        }
    }

    /// The type this grammar reads, for the failure that names a mismatch.
    fn expects(self) -> &'static str {
        match self {
            Self::EntityTag => "a `String`",
            Self::OpaqueToken => "a `String` or an `OpaqueString`",
        }
    }
}

/// The forms, by the quirk id that carries each one.
///
/// One row per quirk, never per field: `cargo xtask why <id>` resolves the row to its evidence and
/// to the conformance cases that would fail if it moved.
const FORMS: &[(&str, Form)] = &[
    // A conditional header carries one entity tag. An unterminated one is not a tag, and two
    // field lines joined into one value are not a tag either.
    ("q-etag-form-0074", Form::EntityTag),
    // A listing cursor is a value this service produced, so bytes it could not have produced —
    // non-text, oversized, or spelling a path — are malformed input.
    ("q-token-form-0075", Form::OpaqueToken),
    // The upload-id cursor of a multipart listing, which is the same rule reached through a
    // different family's marker pair.
    ("q-marker-form-0076", Form::OpaqueToken),
];

/// The wire form one field's quirks declare, if any.
///
/// # Errors
///
/// A string naming the operation and member when a `wire_form` quirk has no row in `FORMS`, when
/// one is attached to a member whose type the form has no grammar for, or when two of them claim
/// different forms for one member. All three are overlay mistakes that would otherwise disable a
/// refusal silently, which is the failure a hand-written file can least afford.
pub fn of(field: &Field, quirks: &[Quirk], operation: &str) -> Result<Option<Form>, String> {
    let mut found: Option<Form> = None;
    for id in &field.quirk_refs {
        let Some(quirk) = quirks.iter().find(|q| &q.id == id) else {
            continue;
        };
        if quirk.kind != FORM_KIND {
            continue;
        }
        let Some((_, form)) = FORMS.iter().find(|(known, _)| known == id) else {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` is a `{FORM_KIND}` with no grammar in \
                 `crates/codegen/src/emit/codec/forms.rs`. Add the row rather than letting the \
                 quirk claim a refusal nothing performs.",
                field.name
            ));
        };
        if !form.accepts(&field.ty) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` reads {}, and this member is not one.",
                field.name,
                form.expects()
            ));
        }
        if found.is_some_and(|existing| existing != *form) {
            return Err(format!(
                "codec {operation}.{}: two `{FORM_KIND}` quirks claim different grammars; one member has one wire form.",
                field.name
            ));
        }
        found = Some(*form);
    }
    Ok(found)
}

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

//! Which payload members are a text document that is not XML, and what media type they carry.
//!
//! Responsible for: resolving one payload member's media type from the quirks it references.
//! NOT responsible for: emitting the read or the write ([`super::decode`] and [`super::encode`]
//! do) or performing them (`rustfs-gateway-core`'s `codec::value::text_payload` does).
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: [`super::decode`], [`super::encode`].
//!
//! # Why this is the third sibling of [`super::bounds`] and [`super::forms`]
//!
//! Same shape of problem, same seam. `spec/ir.schema.json` is frozen: `payload_spec.kind` is a
//! closed six-value enum with no `Json` member, `field` has no `media_type`, and the overlay
//! reader has no key that could supply one. The pinned model does carry Smithy's `@mediaType`,
//! but the lowering does not read it and widening the frozen IR to hold it is an IR-FREEZE
//! decision, not a codegen one.
//!
//! What is data, and what is not:
//!
//! * **data** — *which* members are a non-XML text payload. The overlay attaches a `media_type`
//!   quirk to a payload member, and every member carrying it is read and written as text with
//!   the declared `Content-Type`.
//! * **not data** — the media type behind each quirk, which is the table below.
//!
//! # Why the content type may not be inferred instead
//!
//! Because "a string payload" and "a JSON string payload" are different wire contracts, and the
//! difference is observable: Smithy's default for a bare string payload is `text/plain`, while a
//! bucket policy read answers `application/json`, and an SDK that branches on the header sees
//! the substitution immediately. Inferring one from the other would put a protocol exception in
//! the emitter, where `cargo xtask why` cannot reach it and no evidence URL is attached to it.
//!
//! Two guards keep the table honest: a `media_type` quirk with no entry here fails the run, and
//! so does one attached to a member that is not a string payload. A string payload with *no*
//! `media_type` quirk fails the run as well, in [`super::decode`] and [`super::encode`] — which
//! is the guard that matters most, because its absence is what would silently ship `text/plain`.

use rustfs_gateway_model::ir::{Binding, Field, Quirk, Type};

/// The quirk category that marks a payload member as a non-XML text document.
pub const MEDIA_KIND: &str = "media_type";

/// The media types, by the quirk id that carries each one.
///
/// One row per quirk, never per field: `cargo xtask why <id>` resolves the row to its evidence
/// and to the conformance cases that would fail if it moved.
const MEDIA_TYPES: &[(&str, &str)] = &[
    // A bucket policy is a JSON document on both the request and the response side — the one
    // place in the S3 surface where a success body is not XML. Error bodies stay XML.
    ("q-pol-0001", "application/json"),
];

/// Whether this member is a payload carried as text rather than as XML or bytes.
///
/// The two string types are both admitted for the same reason [`super::forms`] admits both: the
/// distinction between them is about round-tripping, and a document read as text round-trips
/// either way.
pub fn is_text_payload(field: &Field) -> bool {
    field.binding == Binding::Payload && matches!(field.ty, Type::String | Type::OpaqueString)
}

/// The media type one payload member's quirks declare, if any.
///
/// # Errors
///
/// A string naming the operation and member when a `media_type` quirk has no row in
/// `MEDIA_TYPES`, when one is attached to a member that is not a string payload, or when two of
/// them claim different types for one member. All three are overlay mistakes that would otherwise
/// put the wrong `Content-Type` on a body, which no test that reads only the body would catch.
pub fn of(field: &Field, quirks: &[Quirk], operation: &str) -> Result<Option<&'static str>, String> {
    let mut found: Option<&'static str> = None;
    for id in &field.quirk_refs {
        let Some(quirk) = quirks.iter().find(|q| &q.id == id) else {
            continue;
        };
        if quirk.kind != MEDIA_KIND {
            continue;
        }
        let Some((_, media)) = MEDIA_TYPES.iter().find(|(known, _)| known == id) else {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` is a `{MEDIA_KIND}` with no type in \
                 `crates/codegen/src/emit/codec/media.rs`. Add the row rather than letting the \
                 quirk claim a content type nothing emits.",
                field.name
            ));
        };
        if !is_text_payload(field) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` types a string payload, and this member is not one.",
                field.name
            ));
        }
        if found.is_some_and(|existing| existing != *media) {
            return Err(format!(
                "codec {operation}.{}: two `{MEDIA_KIND}` quirks claim different types; one body has one content type.",
                field.name
            ));
        }
        found = Some(media);
    }
    Ok(found)
}

/// The media type a string payload must declare, or the failure that says it declared none.
///
/// # Errors
///
/// A string naming the operation and member when the member is a string payload with no
/// `media_type` quirk. This is the guard the emitters call: without it a bare string payload
/// would be read and written with whatever content type the caller happened to send, which is
/// exactly the "compiles and is wrong" outcome the codec surface refuses to emit.
pub fn required(field: &Field, quirks: &[Quirk], operation: &str) -> Result<&'static str, String> {
    of(field, quirks, operation)?.ok_or_else(|| {
        format!(
            "codec {operation}.{}: a string payload carries a content type, and this member declares no \
             `{MEDIA_KIND}` quirk. Attach one in the overlay rather than defaulting the header.",
            field.name
        )
    })
}

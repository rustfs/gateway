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
//! * **data** — *which* members are a non-XML text payload and the media type they carry. The
//!   overlay attaches a typed codec rule to a payload member.
//! * **not data** — the text-payload reader and writer.
//!
//! # Why the content type may not be inferred instead
//!
//! Because "a string payload" and "a JSON string payload" are different wire contracts, and the
//! difference is observable: Smithy's default for a bare string payload is `text/plain`, while a
//! bucket policy read answers `application/json`, and an SDK that branches on the header sees
//! the substitution immediately. Inferring one from the other would put a protocol exception in
//! the emitter, where `cargo xtask why` cannot reach it and no evidence URL is attached to it.
//!
//! A typed media rule attached to a member that is not a string payload fails the run. A string
//! payload with *no* typed media rule fails the run as well, in [`super::decode`] and
//! [`super::encode`] — which
//! is the guard that matters most, because its absence is what would silently ship `text/plain`.

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{Binding, Field, Type};
use rustfs_gateway_model::{CodecRule, CodecValue};

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
/// A string naming the operation and member when a typed media rule is attached to a member that
/// is not a string payload, or when two typed media rules disagree on one member.
pub fn of<'a>(field: &Field, rules: &'a BTreeMap<String, CodecRule>, operation: &str) -> Result<Option<&'a str>, String> {
    let mut found: Option<&str> = None;
    for id in &field.quirk_refs {
        let Some(rule) = rules.get(id) else {
            continue;
        };
        let media = match &rule.current {
            CodecValue::MediaType(media) => media.as_str(),
            _ => continue,
        };
        if !is_text_payload(field) {
            return Err(format!(
                "codec {operation}.{}: quirk `{id}` types a string payload, and this member is not one.",
                field.name
            ));
        }
        if found.is_some_and(|existing| existing != media) {
            return Err(format!(
                "codec {operation}.{}: two typed codec rules claim different media types; one body has one content type.",
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
/// typed media rule. This is the guard the emitters call: without it a bare string payload
/// would be read and written with whatever content type the caller happened to send, which is
/// exactly the "compiles and is wrong" outcome the codec surface refuses to emit.
pub fn required<'a>(field: &Field, rules: &'a BTreeMap<String, CodecRule>, operation: &str) -> Result<&'a str, String> {
    of(field, rules, operation)?.ok_or_else(|| {
        format!(
            "codec {operation}.{}: a string payload carries a content type, and this member declares no \
             typed media rule. Attach one in the overlay rather than defaulting the header.",
            field.name
        )
    })
}

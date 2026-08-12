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

//! One IR type to one Rust expression, in each direction.
//!
//! Responsible for: the string-to-value and value-to-string half of every binding, and the
//! refusals for a type the codec surface cannot express yet.
//! NOT responsible for: where the string came from, or where the value goes. Both are
//! [`super::decode`] and [`super::encode`].
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: the generated codec files.
//!
//! Every conversion is a call into `crate::codec::value`, never inline logic. A rule rendered into
//! seventy-three files is a rule that can be fixed in seventy-two of them.

use rustfs_gateway_model::ir::{ETagRender, TimestampFormat, Type};

use super::boolean::BooleanSpelling;
use super::bounds::Bound;
use super::forms::Form;
use crate::emit::dto::naming;

/// Why one field cannot be given a codec.
///
/// Returned rather than guessed: a type the codec surface has no wire form for is a decision
/// somebody has to record, and a generator that invented one would put a fabricated wire value
/// into safe code.
pub fn unsupported(operation: &str, member: &str, reason: &str) -> String {
    format!(
        "codec {operation}.{member}: {reason}. The codec surface has no form for it, so the run \
         fails rather than emitting something that compiles and is wrong."
    )
}

/// The Rust spelling of an IR timestamp format.
pub fn timestamp_format(format: TimestampFormat) -> &'static str {
    match format {
        TimestampFormat::HttpDate => "HttpDate",
        TimestampFormat::Iso8601 => "Iso8601",
        TimestampFormat::Iso8601Basic => "Iso8601Basic",
        TimestampFormat::EpochSeconds => "EpochSeconds",
    }
}

/// The Rust spelling of an IR entity-tag rendering context.
pub fn etag_render(render: ETagRender) -> &'static str {
    match render {
        ETagRender::HeaderQuoted => "HeaderQuoted",
        ETagRender::XmlQuoted => "XmlQuoted",
        ETagRender::XmlBare => "XmlBare",
    }
}

/// Turns the wire string held in `raw` into the field's value.
///
/// `raw` is always a `&str`. The result is the bare value; the caller decides whether to wrap it
/// in `Some`.
///
/// `bound` is the inclusive range the field's quirks declare, resolved by [`super::bounds`]. It is
/// a parameter rather than something read from the type because the IR's `Integer` carries no
/// range — see that module for why the two numbers cannot live in the IR today.
///
/// `form` is the stricter wire grammar the field's quirks declare, resolved by [`super::forms`],
/// and it is a parameter for the same reason: the IR's `String` carries no pattern. It is applied
/// before the type is consulted at all, because [`super::forms::of`] has already refused a form
/// attached to a type it has no grammar for — so reaching this point means the form *is* the
/// conversion, and letting the type produce a second one would put the value through two readers.
pub fn from_wire(
    ty: &Type,
    member: &str,
    operation: &str,
    in_xml: bool,
    bound: Option<Bound>,
    form: Option<Form>,
    boolean_spelling: Option<BooleanSpelling>,
) -> Result<String, String> {
    if let Some(form) = form {
        return Ok(form.call(member, ty));
    }
    Ok(match ty {
        Type::String => "raw.to_owned()".to_owned(),
        Type::OpaqueString => "value::opaque(raw)".to_owned(),
        Type::Integer => match bound {
            Some(Bound { min, max }) => format!("value::integer_in_range(raw, \"{member}\", {min}, {max})?"),
            None => format!("value::integer(raw, \"{member}\")?"),
        },
        Type::Long => format!("value::long(raw, \"{member}\")?"),
        Type::Boolean => match boolean_spelling.unwrap_or(BooleanSpelling::AsciiCaseInsensitive) {
            BooleanSpelling::AsciiCaseInsensitive => format!("value::boolean(raw, \"{member}\")?"),
            BooleanSpelling::LowercaseOnly => format!("value::boolean_lowercase(raw, \"{member}\")?"),
        },
        Type::Timestamp(format) => {
            format!("value::timestamp(raw, TimestampFormat::{}, \"{member}\")?", timestamp_format(*format))
        }
        // The rendering context decides how a tag is read as well as how it is written: a header
        // tag is always quoted, an XML one is quoted in every body but `GetObjectAttributes`.
        Type::ETag(ETagRender::HeaderQuoted) => format!("value::etag_header(raw, \"{member}\")?"),
        Type::ETag(_) => format!("value::etag_xml(raw, \"{member}\")?"),
        Type::ObjectKey => format!("value::object_key(raw, \"{member}\")?"),
        Type::BucketName => format!("value::bucket_name(raw, \"{member}\")?"),
        Type::Range => "value::byte_range(raw)".to_owned(),
        Type::StringEnum(_) => format!("dto::{}::custom(raw.to_owned())", naming::type_name(member)),
        Type::ChecksumSpec => {
            return Err(unsupported(
                operation,
                member,
                "a packed checksum is read from its header prefix, not from one string",
            ));
        }
        Type::Structure(_) | Type::Union(_) | Type::List { .. } | Type::Map { .. } | Type::Blob { .. } | Type::Checksum(_) => {
            let what = if in_xml { "an XML element" } else { "a single wire string" };
            return Err(unsupported(operation, member, &format!("this type cannot be read from {what}")));
        }
    })
}

/// The wire string for a member the operation's `xml.url_encoded_fields` covers.
///
/// The decision itself is held in `url_encoding`, read once per response — the encoding is a
/// property of the request, not of the value, and a member that consulted the request for itself
/// could disagree with its siblings inside one document.
///
/// Only a key or a string has a form here. A url-encoded timestamp or integer would be a path the
/// overlay can name and this emitter cannot honour, so it fails the run rather than silently
/// writing the unencoded spelling.
pub fn to_wire_url_encoded(ty: &Type, member: &str, operation: &str) -> Result<String, String> {
    Ok(match ty {
        Type::ObjectKey => "&value::url_encoded_key(v, url_encoding)".to_owned(),
        Type::String | Type::OpaqueString | Type::BucketName => "&value::url_encoded(v.as_str(), url_encoding)".to_owned(),
        _ => {
            return Err(unsupported(
                operation,
                member,
                "url encoding has a wire form for an object key or a string and for nothing else",
            ));
        }
    })
}

/// Turns the field's value, held in `v`, into the wire string.
///
/// The result is an expression of type `&str` or `String`; the caller passes it straight to a
/// header or element writer, both of which take `&str`.
pub fn to_wire(ty: &Type, member: &str, operation: &str) -> Result<String, String> {
    Ok(match ty {
        Type::String => "v.as_str()".to_owned(),
        Type::OpaqueString => "v.as_str()".to_owned(),
        Type::Integer | Type::Long => "&v.to_string()".to_owned(),
        Type::Boolean => "if *v { \"true\" } else { \"false\" }".to_owned(),
        Type::Timestamp(format) => format!("&value::render_timestamp(v, TimestampFormat::{})?", timestamp_format(*format)),
        Type::ETag(render) => format!("&value::render_etag(v, EtagRender::{})", etag_render(*render)),
        Type::ObjectKey | Type::BucketName => "v.as_str()".to_owned(),
        Type::StringEnum(_) => "v.as_str()".to_owned(),
        _ => {
            return Err(unsupported(
                operation,
                member,
                "this type has no single-string wire form on the response side",
            ));
        }
    })
}

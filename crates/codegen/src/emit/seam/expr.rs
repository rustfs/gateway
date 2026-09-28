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

//! One conversion expression per (gateway IR type, s3s type) pair, in each direction.
//!
//! Responsible for: the pairing table — which gateway type converts into which s3s type and with
//! which hand-written leaf function (`compat/seam/leaf.rs`) — and recording which nested shapes the
//! expressions reach, so the generator emits exactly those shape conversions.
//! NOT responsible for: `Option` and container wrapping of a member (`super::member`), or naming
//! overrides (`super::overrides`).
//! Upstream: [`super::facts`] and the IR. Downstream: [`super`].
//!
//! A pair the table does not know is an error naming the member, never a guessed conversion: the
//! generator fails and the override table must say what the member means.

use std::cell::RefCell;
use std::collections::BTreeSet;

use rustfs_gateway_model::ir::Type;

use super::facts::{S3sFacts, S3sType};
use crate::emit::dto::naming;

/// What the expressions reached, so the generator emits exactly those shape conversions.
#[derive(Debug, Default)]
pub struct Reached {
    /// Raw Smithy shape names that need a gateway → s3s conversion.
    pub forward: BTreeSet<String>,
    /// Raw Smithy shape names that need an s3s → gateway conversion.
    pub backward: BTreeSet<String>,
}

/// The generator's view of both sides.
pub struct Ctx<'a> {
    /// The s3s release's facts.
    pub facts: &'a S3sFacts,
    /// Shapes reached so far.
    pub reached: RefCell<Reached>,
    /// Parameters the conversion being rendered takes besides its input (`Rule::Supplied`).
    pub supplied: RefCell<Vec<(String, String)>>,
}

/// The gateway enumeration type for a member name.
#[must_use]
pub fn gateway_enum(member: &str) -> String {
    format!("crate::ops::enums::{}", naming::type_name(member))
}

/// The gateway shape type for a raw Smithy shape name.
#[must_use]
pub fn gateway_shape(raw: &str) -> String {
    format!("crate::ops::shapes::{}", naming::type_name(raw))
}

/// The function converting one shape, in one direction.
#[must_use]
pub fn shape_fn(raw: &str, forward: bool) -> String {
    let module = naming::module_name(raw);
    format!("super::super::shapes::{module}::{module}_{}", if forward { "to_s3s" } else { "from_s3s" })
}

fn leaf(s3s: &S3sType) -> Option<&str> {
    match s3s {
        S3sType::Leaf(name) => Some(name.as_str()),
        _ => None,
    }
}

fn closure(body: &str) -> String {
    format!("|e| -> Result<_, ConversionError> {{ Ok({body}) }}")
}

impl Ctx<'_> {
    /// `v`, a gateway value of IR type `gw`, as the s3s value of `s3s`.
    /// `field` names the member in the generated code's `ConversionError`.
    ///
    /// # Errors
    ///
    /// A pair the table does not know.
    pub fn forward(&self, gw: &Type, s3s: &S3sType, v: &str, field: &str) -> Result<String, String> {
        let unknown = || Err(format!("no gateway → s3s conversion from {gw:?} to {s3s:?}"));
        Ok(match (gw, s3s) {
            (Type::String, S3sType::Leaf(l)) if l == "String" => v.to_owned(),
            (Type::String, S3sType::Enum(name)) => format!("s3s::dto::{name}::from({v})"),
            (Type::String, S3sType::Leaf(l)) if l == "CopySource" => format!("leaf::copy_source_to_s3s(\"{field}\", &{v})?"),
            (Type::String, S3sType::Leaf(l)) if l == "ETagCondition" => {
                format!("leaf::etag_condition_from_text(\"{field}\", &{v})?")
            }
            (Type::String, S3sType::Leaf(l)) if l == "i32" => format!("leaf::parse_i32(\"{field}\", &{v})?"),
            (Type::StringEnum(_), S3sType::Leaf(l)) if l == "Event" => format!("s3s::dto::Event::from({v}.as_str().to_owned())"),
            (Type::OpaqueString, S3sType::Leaf(l)) if l == "String" => format!("{v}.into_string()"),
            (Type::StringEnum(_), S3sType::Enum(name)) => format!("s3s::dto::{name}::from({v}.as_str().to_owned())"),
            (Type::StringEnum(_), S3sType::Leaf(l)) if l == "String" => format!("{v}.as_str().to_owned()"),
            (Type::Integer, S3sType::Leaf(l)) if l == "i32" => v.to_owned(),
            (Type::Integer, S3sType::Leaf(l)) if l == "i64" => format!("i64::from({v})"),
            (Type::Long, S3sType::Leaf(l)) if l == "i64" => v.to_owned(),
            (Type::Long, S3sType::Leaf(l)) if l == "i32" => format!("leaf::narrow(\"{field}\", {v})?"),
            (Type::Boolean, S3sType::Leaf(l)) if l == "bool" => v.to_owned(),
            (Type::Timestamp(_), S3sType::Leaf(l)) if l == "Timestamp" => format!("leaf::timestamp_to_s3s(\"{field}\", {v})?"),
            (Type::ETag(_), S3sType::Leaf(l)) if l == "ETag" => format!("leaf::etag_to_s3s(&{v})"),
            (Type::ETag(_), S3sType::Leaf(l)) if l == "ETagCondition" => {
                format!("leaf::etag_condition_to_s3s(\"{field}\", &{v})?")
            }
            (Type::ETag(_), S3sType::Leaf(l)) if l == "String" => format!("leaf::etag_to_text(&{v})"),
            (Type::Checksum(_), S3sType::Leaf(l)) if l == "String" => format!("leaf::digest_to_s3s(&{v})"),
            (Type::ObjectKey | Type::BucketName, S3sType::Leaf(l)) if l == "String" => format!("{v}.as_str().to_owned()"),
            (Type::Range, S3sType::Leaf(l)) if l == "Range" => format!("leaf::range_to_s3s(\"{field}\", &{v})?"),
            (Type::Capability { .. }, S3sType::Leaf(l)) if l == "String" => format!("leaf::upload_id_to_s3s(&{v})"),
            (Type::Blob { streaming: true }, S3sType::Leaf(l)) if l == "StreamingBlob" => format!("leaf::streaming_blob({v})"),
            (Type::Blob { streaming: false }, S3sType::Leaf(l)) if l == "Bytes" => v.to_owned(),
            (Type::Structure(raw), S3sType::Struct(name)) if raw == name => {
                self.reached.borrow_mut().forward.insert(raw.clone());
                format!("{}({v})?", shape_fn(raw, true))
            }
            (Type::Union(raw), S3sType::Union(name)) if raw == name => {
                self.reached.borrow_mut().forward.insert(raw.clone());
                format!("{}({v})?", shape_fn(raw, true))
            }
            (Type::List { member: inner, .. }, S3sType::Vec(s3s_inner)) => {
                let body = self.forward(inner, s3s_inner, "e", field)?;
                if body == "e" {
                    v.to_owned()
                } else {
                    format!("{v}.into_iter().map({}).collect::<Result<Vec<_>, ConversionError>>()?", closure(&body))
                }
            }
            (Type::Map { key, value }, S3sType::Map(s3s_key, s3s_value)) => {
                let k = self.forward(key, s3s_key, "k", field)?;
                let val = self.forward(value, s3s_value, "v", field)?;
                format!(
                    "{v}.into_iter().map(|(k, v)| -> Result<_, ConversionError> {{ Ok(({k}, {val})) }}).collect::<Result<std::collections::HashMap<_, _>, ConversionError>>()?"
                )
            }
            _ => return unknown(),
        })
    }

    /// `v`, an s3s value of `s3s`, as the gateway value of `gw` (the IR type of member `member`).
    ///
    /// # Errors
    ///
    /// A pair the table does not know.
    pub fn backward(&self, s3s: &S3sType, gw: &Type, member: &str, v: &str, field: &str) -> Result<String, String> {
        let unknown = || Err(format!("no s3s → gateway conversion from {s3s:?} to {gw:?}"));
        Ok(match (s3s, gw) {
            (S3sType::Leaf(l), Type::String) if l == "String" => v.to_owned(),
            (S3sType::Enum(_), Type::String) => format!("{v}.as_str().to_owned()"),
            (S3sType::Leaf(l), Type::String) if l == "i32" => format!("{v}.to_string()"),
            (S3sType::Leaf(l), Type::StringEnum(_)) if l == "Event" => {
                format!("{}::custom(String::from({v}))", gateway_enum(member))
            }
            (S3sType::Leaf(l), Type::OpaqueString) if l == "String" => format!("crate::OpaqueString::from({v})"),
            (S3sType::Enum(_), Type::StringEnum(_)) => format!("{}::custom({v}.as_str().to_owned())", gateway_enum(member)),
            (S3sType::Leaf(l), Type::StringEnum(_)) if l == "String" => format!("{}::custom({v})", gateway_enum(member)),
            (S3sType::Leaf(l), Type::Integer) if l == "i32" => v.to_owned(),
            (S3sType::Leaf(l), Type::Long) if l == "i64" => v.to_owned(),
            (S3sType::Leaf(l), Type::Long) if l == "i32" => format!("i64::from({v})"),
            (S3sType::Leaf(l), Type::Integer) if l == "i64" => format!("leaf::narrow(\"{field}\", {v})?"),
            (S3sType::Leaf(l), Type::Boolean) if l == "bool" => v.to_owned(),
            (S3sType::Leaf(l), Type::Timestamp(_)) if l == "Timestamp" => format!("leaf::timestamp_from_s3s(\"{field}\", &{v})?"),
            (S3sType::Leaf(l), Type::ETag(_)) if l == "ETag" => format!("leaf::etag_from_s3s(\"{field}\", {v})?"),
            (S3sType::Leaf(l), Type::ETag(_)) if l == "String" => format!("leaf::etag_from_text(\"{field}\", &{v})?"),
            (S3sType::Leaf(l), Type::Checksum(algo)) if l == "String" => {
                format!("leaf::digest_from_s3s(\"{field}\", crate::ChecksumAlgorithm::{algo:?}, &{v})?")
            }
            (S3sType::Leaf(l), Type::ObjectKey) if l == "String" => format!("leaf::object_key(\"{field}\", {v})?"),
            (S3sType::Leaf(l), Type::BucketName) if l == "String" => format!("leaf::bucket_name(\"{field}\", {v})?"),
            (S3sType::Leaf(l), Type::Capability { .. }) if l == "String" => format!("crate::UploadIdClaim::from_wire({v})"),
            (S3sType::Leaf(l), Type::Blob { streaming: true }) if l == "StreamingBlob" => format!("leaf::byte_stream({v})"),
            (S3sType::Leaf(l), Type::Blob { streaming: false }) if l == "Bytes" => v.to_owned(),
            (S3sType::Struct(name), Type::Structure(raw)) if raw == name => {
                self.reached.borrow_mut().backward.insert(raw.clone());
                format!("{}({v})?", shape_fn(raw, false))
            }
            (S3sType::Union(name), Type::Union(raw)) if raw == name => {
                self.reached.borrow_mut().backward.insert(raw.clone());
                format!("{}({v})?", shape_fn(raw, false))
            }
            (S3sType::Vec(s3s_inner), Type::List { member: inner, .. }) => {
                let body = self.backward(s3s_inner, inner, member, "e", field)?;
                if body == "e" {
                    v.to_owned()
                } else {
                    format!("{v}.into_iter().map({}).collect::<Result<Vec<_>, ConversionError>>()?", closure(&body))
                }
            }
            (S3sType::Map(s3s_key, s3s_value), Type::Map { key, value }) => {
                let k = self.backward(s3s_key, key, member, "k", field)?;
                let val = self.backward(s3s_value, value, member, "v", field)?;
                format!(
                    "{v}.into_iter().map(|(k, v)| -> Result<_, ConversionError> {{ Ok(({k}, {val})) }}).collect::<Result<std::collections::BTreeMap<_, _>, ConversionError>>()?"
                )
            }
            _ => return unknown(),
        })
    }
}

/// Whether an s3s leaf is the plain `String` (used to decide the checksum fan-out).
#[must_use]
pub fn is_string(s3s: &S3sType) -> bool {
    leaf(s3s.unwrap_option().0) == Some("String")
}
